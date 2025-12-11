---
title: "java安全基础-Unsafe"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java安全基础-Unsafe

全限定名为sun.misc.Unsafe，是Java底层的API提供的一个类，它提供非常底层的内存、CAS、线程程度、类、对象等操作A，是一个可以直接操作内存，不用构造器、不需要任何访问权限检查就可以创建对象的类

### sun.mics.Unsafe

Unsafe源码如下:

~~~java
public final class Unsafe {
    private static final Unsafe theUnsafe;
    private Unsafe() {
    }
    @CallerSensitive
    public static Unsafe getUnsafe() {
        Class var0 = Reflection.getCallerClass();
        // 检查调用类的加载器是不是Bootstrap，也就是null
        if (!VM.isSystemDomainLoader(var0.getClassLoader())) {
            throw new SecurityException("Unsafe");
        } else {
            return theUnsafe;
        }
    }
 }

~~~

上述代码可以看出，Unsafe唯一的构造器也是private，没法通过new实例化

虽然getUnsafe()是一个public方法，但是它会检查调用getUsafe()类的加载器是不是Bootstrap类加载器，但是我们定义类的默认加载器是AppClassLoader，所以会直接抛出异常。
检查类加载器代码如下：

```java
// bootstrap加载器负责加载rt.jar，不是java编写，所以是null
public static boolean isSystemDomainLoader(ClassLoader var0) {
    return var0 == null;
}
```
### 获取Unsafe对象

虽然不能直接实例化获取Unsafe对象，但我们可以尝试通过反射从theUnsafe和构造器入手创建实例化对象：

* 方法一：反射获取字段即theUnsafe属性，就相当于获取到了Unsafe对象
* 方法二：反射获取构造器，再获取Unsafe实例

demo如下：

~~~java
import sun.misc.Unsafe;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

public class TemporaryFiles {
    public static void main(String[] args) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchFieldException {
        Class unsafeClass = Unsafe.class;
        // 第一种方式：通过构造器获取Unsafe实例
        Constructor constructor = Unsafe.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        Unsafe unsafe1 = (Unsafe) constructor.newInstance();
        System.out.println(unsafe1);

        // 第二种方法：通过字段获取Unsafe实例
        Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Unsafe unsafe2 = (Unsafe) theUnsafe.get(null);
        System.out.println(unsafe2);
    }
}
/*
输出:
sun.misc.Unsafe@4554617c
sun.misc.Unsafe@1540e19d
*/
~~~

### 利用Unsafe绕过JDK17+对反射的限制

##### 反射的限制

根据 [Oracle的文档](https://docs.oracle.com/en/java/javase/17/migrate/migrating-jdk-8-later-jdk-releases.html#GUID-7BB28E4D-99B3-4078-BDC4-FC24180CE82B)，为了安全性，从JDK 17开始对java本身代码使用强封装，原文叫 **Strong Encapsulation**。任何对 `java.*` 代码中的**非public**变量和方法进行反射会抛出InaccessibleObjectException异常

[JDK的文档](https://openjdk.org/jeps/403)解释了对java api进行封装的两个理由：

* 对java代码进行反射是不安全的，比如可以调用ClassLoader的defineClass方法，这样在运行时候可以给程序注入任意代码

* java的这些非公开的api本身就是非标准的，让开发者依赖使用这个api会给JDK的维护带来负担

所以从JDK 9开始就准备限制对java api的反射进行限制（会出现警告），直到JDK 17才正式禁用（会报错）

##### 利用Unsafe绕过限制

 官方文档描述，`java.*` 的非公共字段和方法都无法反射获取调用了，但原文中还提到:

"Note that the `sun.misc` and `sun.reflect` packages are available for reflection by tools and libraries in all JDK releases, including JDK 17."

即sun.misc和sun.reflect包下的我们是可以正常反射的，所以有个关键的类就可以拿来用来，就是 `Unsafe` 

[JDK17+反射限制绕过 (pankas.top)](https://pankas.top/2023/12/05/jdk17-反射限制绕过/)
