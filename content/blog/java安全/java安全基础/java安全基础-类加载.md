---
title: "java安全基础-类加载"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java安全基础-类加载

### 简介

Java程序在运行前需要先编译成`class文件`，java虚拟机（JVM）把描述类文件的数据从.class文件加载到内存，并对数据进行校验、转换、解析和类初始化，最终形成可以被JVM使用的java类型，上述过程中JVM的操作被称为JVM的类加载机制

### 类的生命周期

类的生命周期，是从加载到 JVM 内存开始，到卸载出 JVM 内存结束

整个生命周期包括：加载、验证、准备、解析、初始化、使用、卸载

而验证、准备、解析三个过程又称为连接

![image-20240609151828689](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240609151828689.png)

##### 加载

加载即查找并加载类的二进制数据，jvm做了三件事：

* 通过类的全限定名（包名 + 类名）来获取定义此类的二进制字节流
* 将该字节流所代表的静态存储结构转化为运行时的数据结构
* 在内存中生成一个代表这个类的`java.lang.Class`对象，作为方法区这个类的各种数据的访问入门

**注：** 连接阶段的部分行为会与加载阶段交叉进行，例如：在加载尚未结束时，就可以对加载成功的部分二进制流进行文件格式验证

##### 验证

确保被加载类的正确性，由于class文件是一个普通文件，可以被修改，验证阶段可以避免不规范的class被jvm使用，从而危害jvm安全，验证内容如下：

* 文件格式验证

  验证字节流是否符合Class文件格式规范

- 元数据验证

  对字节码描述的信息进行语义分析，以保证其描述的信息符合Java语言规范要求

- 字节码验证

  通过数据流和控制流分析，确定程序语义是否合法、符合逻辑

- 符号引用验证

  确保解析动作能正确执行

##### 准备

正式为类的静态变量分配内存，并将其初始化为默认值

* 这里的默认值是数据类型默认的零值（0、0L、null、false等）而不是代码中所初始化的值，比如：

  ~~~java
  public static int value = 123;
  ~~~

  准备阶段后类变量value的值是0而不是123，因为在准备阶段还没有任何java方法被执行，而给类变量赋值的操作是需要调用类构造器`<clinit>()`方法中的putstatic指令的

* 内存分配仅包括类静态变量，实例变量将会在对象实例化时随着对象一起分配到Java堆中
* 对于同时被`static`和`final`修饰的常量，必须在声明的时候就为其显示的赋值；只被`final`修饰的常量，在使用前必须为其显示的赋值，系统不会为其赋予默认零值，否则IDEA会提示未初始化

##### 解析

把类中的符号引用转换为直接引用。

* 符号引用：字符串，能根据这个字符串定位到指定的数据，比如java/lang/StringBuilder

* 直接引用：内存地址或指向对应内存地址的指针、句柄

符号引用就只是一个字面量，与内存结构无关，仅仅通过字面量无法确认该引用在jvm内存中的地址，也就无法使用它，所以必须要将符号引用转换为能够定位到内存地址的直接引用，比如我们要调用System.out.println方法，我们必须要找到println方法在内存中的起始地址，这样才能执行里面的字节码

##### 初始化

执行类构造器`<clinit>()`方法，对类变量以及类中各种静态代码块中的变量进行赋值操作（这里是类变量初始化，而不是实例初始化）

会调用`java.lang.ClassLoader`加载类字节码，`ClassLoader`会调用JVM的`native`方法（`defineClass0/1/2`）来定义一个`java.lang.Class` 实例

其中包括：

- 执行static语句块中的语句
- 完成static属性的赋值操作
- 当类的直接父类还没有被初始化，则先初始化其直接父类。

##### 使用

类访问方法区内的数据结构的接口， 对象是堆区上的的数据

##### 卸载

释放内存

JVM结束类生命周期的情况：

- 执行了`System.exit()`方法
- 程序正常执行结束
- 程序在执行过程中遇到了异常或错误而异常终止
- 由于操作系统出现错误而导致Java虚拟机进程终止

### 类的加载时机

JVM会在程序第一次主动引用类的时候加载该类，被动引用时并不会引用类加载的操作

主动引用：

- 遇到new、getstatic、putstatic、invokestatic

  字节码指令

  - `new`实例化对象
  - 读取设置类的静态属性（被`final`修饰，编译期把结果放入常量池中的静态字段除外）
  - 调用类的静态方法

- JVM启动，先初始化包含`main()`方法的主类

- 初始化一个类时，其父类还没初始化（需先初始化父类）

- 对类进行反射调用

- JDK 1.7动态语言支持：一个`java.lang.invoke.MethodHandle`的解析结果为 `REF_getStatic`、`REF_putStatic`、`REF_invokeStatic`。

被动引用：

- 通过子类引用父类的静态变量，不会导致子类初始化
- `Array[] arr = new Array[10];` 不会触发 Array 类初始化；
- `static final VAR` 在编译阶段会存入调用类的常量池，通过 `ClassName.VAR` 引用不会触发 ClassName 初始化。
- `Class.forName`加载指定类，但指定参数 initialize 为 false
- 通过类名获取Class对象

### 类加载器

Java把类加载阶段中的“通过一个类的全限名来获取描述此类的二进制字节流”这个动作放到JVM外部实现，以便让应用程序自己决定如何去获取所需要的类，实现这个动作的代码模块称为“类加载器”

##### **启动类加载器(Bootstrap ClassLoader):**

这个类加载器负责将\lib目录下的类库加载到虚拟机内存中，用来加载java的核心库,此类加载器并不继承于java.lang.ClassLoader，不能被java程序直接调用,代码是使用C++编写的.是虚拟机自身的一部分

##### **扩展类加载器(Extendsion ClassLoader):**

这个类加载器负责加载<JAVA_HOME>\lib\ext目录下的类库，或者被java.ext.dirs系统变量所指定的路径中的所有类库，用来加载java的扩展库，开发者可以直接使用这个类加载器

##### **应用程序类加载器(Application ClassLoader):**

这个类加载器负责加载用户类路径(CLASSPATH)下的类库，一般我们编写的java类都是由这个类加载器加载，这个类加载器是CLassLoader中的getSystemClassLoader()方法的返回值，所以也称为系统类加载器，一般情况下这就是系统默认的类加载器

##### 自定义类加载器

除此之外,我们还可以加入自己定义的类加载器,以满足特殊的需求,需要继承java.lang.ClassLoader类.

### 类加载器的核心方法

对应ClassLoader对象

* loadclass 加载指定的类
* findclass 查找指定的java类
* findLoadedClass 查找JVM已经加载过的类
* defineClass 定义一个java类
* resolveClass 链接指定的java类

### java类动态加载方式

Java类加载方式分为`显式`和`隐式`,`显式`即我们通常使用`Java反射`或者`ClassLoader`来动态加载一个类对象，而`隐式`指的是`类名.方法名()`或`new`类实例。`显式`类加载方式也可以理解为类动态加载，我们可以自定义类加载器去加载任意的类

上面两种类动态加载方式也有区别，LoadClass()方法只对类进行加载，不会对类进行初始化。Class.forName会默认对类进行初始化

`Class.forName("类名")`默认会初始化被加载类的静态属性和方法，因此可以注入恶意代码

```Java
public class Test {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

而`ClassLoader.loadClass`默认不会初始化类方法

```Java
public class MyTest {
    public  void abc() throws ClassNotFoundException {
        this.getClass().getClassLoader().loadClass("evil.Test");
    }
    public static void main(String[] args) throws Exception{
//        Class.forName("evil.Test");
        MyTest myTest = new MyTest();
        myTest.abc();

    }
}

```







![image-20240602223907193](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240602223907193.png)

看上图，在JVM类加载器中最顶层的是`Bootstrap ClassLoader（引导类加载器）`、`Extension ClassLoader（扩展类加载器）`、`App ClassLoader（系统类加载器）`，`AppClassLoader`是默认的类加载器，如果类加载时我们不指定类加载器的情况下，默认会使用`AppClassLoader`加载类，`ClassLoader.getSystemClassLoader()`返回的系统类加载器也是`AppClassLoader`

在获取一个类的类加载器的时候，可能会返回一个null对象，比如：java.io.File.class.getClassLoader()将返回一个null对象，因为java.io.File类在JVM初始化时会被引导类加载器加载（该加载器实现于JVM层，采用c++编写），在尝试获取被引导类加载器所加载的类时，都会返回null
