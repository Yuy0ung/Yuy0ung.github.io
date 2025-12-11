---
title: "java安全基础-动态加载字节码"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java安全基础-动态加载字节码

## 字节码

严格来说，Java字节码（ByteCode）其实仅仅指的是Java虚拟机执行使用的一类指令，通常被存储在.class文件中，而.class文件可以在JVM中运行

本文中所说的“字节码”，可以理解的更广义一些——所有能够恢复成一个类并在JVM虚拟机里加载的字节序列，都在探讨范围内

## URLClassLoader

ClassLoader是来用来加载字节码文件最基础的方法，而这里的URLClassLoader可以用来远程加载字节码

正常情况下，Java会根据配置项 sun.boot.class.path 和 java.class.path 中列举到的基础路径（这些路径是经过处理后的 java.net.URL 类）来寻找.class文件来加载，而这个基础路径有分为三种情况：

* URL未以斜杠 / 结尾，则认为是一个JAR文件，使用 JarLoader 来寻找类，即为在Jar包中寻找.class文件

* URL以斜杠 / 结尾，且协议名是 file ，则使用 FileLoader 来寻找类，即为在本地文件系统中寻找.class文件
* URL以斜杠 / 结尾，且协议名不是 file ，则使用最基础的 Loader 来寻找类

这里关注第三种，远程加载的话，我们一般使用http://协议，看看下面这个demo：
首先写一个访问http://127.0.0.1:8000/test.class的程序：

~~~java
package com.yuy0ung.urlclassloader;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

public class loadertest {
    public static void main(String[] args) throws MalformedURLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        URL[] urls = {new URL("http://localhost:8000/")};
        URLClassLoader loader = URLClassLoader.newInstance(urls);
        Class c = loader.loadClass("test");
        c.newInstance();
    }
}
~~~

然后写一个有输出的test程序编译成class文件放在localhost:8000上：

```java
public class test {
    public test() {
        System.out.println("loader test");
    }
}
```

然后执行程序发现class加载成功：
![QQ_1761620537532](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761620537532.png)

那么，如果我们能够控制目标Java ClassLoader的基础路径为一个http服务器，则可以利用远程加载的方式执行任意代码了

## ClassLoader#defineClass

其实java的class加载都经历的是ClassLoader中这三个方法调用：

* loadClass：作用是从已加载的类缓存、父加载器等位置寻找类（这里实际上是双亲委派机制），在前面没有找到的情况下，执行findclass
* findClass 的作用是根据基础URL指定的方式来加载类的字节码，就像上一节中说到的，可能会在本地文件系统、jar包或远程http服务器上读取字节码，然后交给defineClass
* defineClass 的作用是处理前面传入的字节码，将其处理成真正的Java类

所以这里的核心其实是defineClass，Java默认的 ClassLoader#defineClass 是一个native方法，逻辑在JVM的C语言代码中，我们写个demo来直接加载字节码：
~~~java
package com.yuy0ung.urlclassloader;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;

public class TestDefineClass {
    public static void main(String[] args) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);

        byte[] b = Base64.getDecoder().decode("yv66vgAAADQAGwoABgANCQAOAA8IABAKABEAEgcAEwcAFAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApTb3VyY2VGaWxlAQAKSGVsbG8uamF2YQwABwAIBwAVDAAWABcBAAtIZWxsbyBXb3JsZAcAGAwAGQAaAQAFSGVsbG8BABBqYXZhL2xhbmcvT2JqZWN0AQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWACEABQAGAAAAAAABAAEABwAIAAEACQAAAC0AAgABAAAADSq3AAGyAAISA7YABLEAAAABAAoAAAAOAAMAAAACAAQABAAMAAUAAQALAAAAAgAM");
        Class hello = (Class)defineClass.invoke(ClassLoader.getSystemClassLoader(), "Hello", b, 0, b.length);
        hello.newInstance();
    }
}

~~~

> 注意一点，在 defineClass 被调用的时候，类对象是不会被初始化的，只有这个对象显式地调用其构造函数，初始化代码才能被执行。而且，即使我们将初始化代码放在类的static块中（在本系列文章第一篇中进行过说明），在 defineClass 时也无法被直接调用到。所以，如果我们要使用 defineClass 在目标机器上执行任意代码，需要想办法调用构造函数
>
> 另外，因为系统的 ClassLoader#defineClass 是一个保护属性，所以我们无法直接在外部访问，所以需要反射的形式来调用

运行后成功加载：

![image-20251028115226450](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251028115226450.png)

在实际场景中，因为defineClass方法作用域是不开放的，所以攻击者很少能直接利用到它，但它却是我们常用的一个攻击链 TemplatesImpl 的基石

## TemplatesImpl

`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`这个类中定义了一个内部类TransletClassLoader ：

![QQ_1761630885667](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761630885667.png)

这个类里重写了 defineClass 方法，并且这里没有显式地声明其定义域，所以这里的 defineClass 由其父类的protected类型变成了一个default类型的方法，可以被类外部调用

我们向前追溯一下调用链：

~~~java
TemplatesImpl#getOutputProperties()
  TemplatesImpl#newTransformer()
    TemplatesImpl#getTransletInstance()
      TemplatesImpl#defineTransletClasses()
        TransletClassLoader#defineClass()
~~~

这里最前面两个方法的作用域都是public，可以被外部调用，于是有了如下poc：
~~~java
package com.yuy0ung.urlclassloader;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.util.Base64;

public class TestTemplatesImpl {
    public static void main(String[] args) throws Exception {
// source: bytecodes/HelloTemplateImpl.java
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIQoABgASCQATABQIABUKABYAFwcAGAcAGQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgEAClNvdXJjZUZpbGUBABdIZWxsb1RlbXBsYXRlc0ltcGwuamF2YQwADgAPBwAbDAAcAB0BABNIZWxsbyBUZW1wbGF0ZXNJbXBsBwAeDAAfACABABJIZWxsb1RlbXBsYXRlc0ltcGwBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWACEABQAGAAAAAAADAAEABwAIAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAAIAAsAAAAEAAEADAABAAcADQACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAACgALAAAABAABAAwAAQAOAA8AAQAJAAAALQACAAEAAAANKrcAAbIAAhIDtgAEsQAAAAEACgAAAA4AAwAAAA0ABAAOAAwADwABABAAAAACABE=");
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][] {code});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        obj.newTransformer();
    }

    private static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        java.lang.reflect.Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
~~~

这里设置了三个属性： _bytecodes 、 _name和 _tfactory 。 _bytecodes 是由字节码组成的数组； _name 可以是任意字符串，只要不为null即可；_tfactory 需要是一个 TransformerFactoryImpl 对象，因为TemplatesImpl#defineTransletClasses() 方法里有调用到_tfactory.getExternalExtensionsMap() ，如果是null会出错

另外， TemplatesImpl 中加载的字节码对应的类必须是 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的子类，所以这里的字节码来自于我们构造的一个特殊的类：

~~~java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class HelloTemplatesImpl extends AbstractTranslet {
    public void transform(DOM document, SerializationHandler[] handlers)
        throws TransletException {
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler)
        throws TransletException {
    }

    public HelloTemplatesImpl() {
        super();
        System.out.println("Hello TemplatesImpl");
    }
}
~~~

将其编译成字节码，即可被TemplatesImpl 执行，运行即可加载字节码：
![image-20251028145007265](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251028145007265.png)

## BCEL ClassLoader

BCEL的全名应该是Apache Commons BCEL，属于Apache Commons项目下的一个子项目，但其因为被Apache Xalan所使用，而Apache Xalan又是Java内部对于JAXP的实现，所以BCEL也被包含在了JDK的原生库中

可以通过BCEL提供的两个类 Repository 和 Utility 来利用，Repository 用于将一个Java Class

先转换成原生字节码，当然这里也可以直接使用javac命令来编译java文件生成字节码； Utility 用于将原生的字节码转换成BCEL格式的字节码：
~~~java
package com.yuy0ung.urlclassloader;

import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.Repository;

public class BCELclassloaderTest {
    public static void main(String []args) throws Exception {
        JavaClass cls = Repository.lookupClass(evil.Hello.class);
        String code = Utility.encode(cls.getBytes(), true);
        System.out.println(code);
    }
}
~~~

运行生成BCEL字节码：
![image-20251028152117185](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251028152117185.png)

使用BCEL ClassLoader用于加载这串特殊的“字节码”即可执行：
~~~java
package com.yuy0ung.urlclassloader;

import com.sun.org.apache.bcel.internal.util.ClassLoader;

public class LoadBCEL {
    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        new ClassLoader().loadClass("$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmP$cbJ$DA$Q$acIv$b3$PW$T$T$e3$5b$83$H$n$f1$e0$5e$bc$rx$R$c4$c3$a2B$q$f7$c9$3a$c4$J$93$5d$d9L$C$7e$96$k$U$3c$f8$B$7e$94$d83$G$l$60$l$ba$e8$aa$ea$a2$e9$f7$8f$d77$A$th$85$a8$605$40$j$N$lk$n$9aX$f7$b0$e1a$93$a1$d2$93$99$d4$a7$M$e5vg$c0$e0$9c$e5$b7$82$a1$9a$c8L$5c$ce$sCQ$dc$f0$a1$o$a6$9e$e4$vW$D$5eH3$_HG$df$c9$vC$94$88$b9T$f1$85P$w$ef2$f8$bdT$zB$c3$7e$3e$xRq$$$8d$3b$b4$86$e31$9f$f3$I$k$7c$P$5b$R$b6$b1$c3$e0Z$c5$c3n$84$3d$ec$93$f3$t$8f$a1f$Wb$c5$b3Q$7c5$i$8bT$ff$a1$fa$PS$z$st$7e$3e$p$a1$99XE$e6$f1u$n3$dd$d7$85$e0$T$3a$a9$f1$P$cd$e0$dd$9bIe$b4$d7N$7eEj$a2G$dd$ce$A$Hp$e9q$a6J$60$e6d$ea$BM1$n$pt$8f$5e$c0$k$ad$iR$afX$b2$8c$r$ea$d1$97$81p$99$d0$c7$ca$f7$f2$n$b9M$FO$u$d5$cb$cfpL$A$b3$B$a1$95$5c$b2$9a$a8$aa$N$ae$7d$C$v$c1$91$B$c6$B$A$A").newInstance();
    }
}
~~~

运行成功加载BCEL字节码：

![image-20251028152958255](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251028152958255.png)