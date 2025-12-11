---
title: "java安全基础-反射"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java安全基础-反射

### 概念

Java反射机制是在运行状态时，对于任意一个类，都能够获取到这个类的所有属性和方法，对于任意一个对象，都能够调用它的任意一个方法和属性(包括私有的方法和属性)，这种动态获取的信息以及动态调用对象的方法的功能就称为java语言的反射机制。

P神是这样描述的：“反射是大多数语言里都必不可少的组成部分，对象可以通过反射获取他的类，类可以通过反射拿到所有方法（包括私有），拿到的方法可以调用，总之通过“反射”，我们可以将Java这种静态语言附加上动态特性。⼀段代码，改变其中的变量，将会导致这段代码产生功能性的变化，称之为动态特性。”

### 反射的实现

JVM为每个加载的`class`创建了对应的`Class`实例，并在实例中保存了该`class`的所有信息；因此，如果获取了某个`Class`实例，我们就可以通过这个`Class`实例获取到该实例对应的`class`的所有信息

### 与反射有关的包/类

#### 与反射有关的包

引入与反射有关的包

~~~java
import java.lang.reflect.*;
~~~

#### 反射中比较重要的类

- `java.lang.Class`

  这个类代表着字节码，整个类

- `java.lang.reflect.Method`

  代表字节码 (类) 中的成员方法

- `java.lang.reflect.Constructor`

  代表字节码 (类) 中的构造方法

- `java.lang.reflect.Field`

  代表字节码 (类) 中的成员变量

### 调用方法

欲要调用一个对象的任意方法，有三步：

* 获得该对象对应的Class类的实例
* 通过该Class类的实例来获取欲要调用的那个方法
* 拿到对应方法后，给该方法传入对应参数进行调用

接下来是具体的实现流程，以如下User类的setName()方法为例：

~~~java
public class User{
     private String name;
    private int age;

    @Override
    public String toString(){
        return "User{" + "name=" +name + ", age="+age+"}";
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}
~~~

#### 1.获得类实例

方法有三：

* 如果已经加载了某个类，可以直接访问该类的class属性，该属性就存储着该类对应的Class类的实例（使用.class来创建Class对象的引用时，不会自动初始化该Class对象）

  ~~~java
  public class test {
      public static void main(String[] args) {
  		Class cls = User.class;
          System.out.println(cls);
      }
  }
  ~~~

  ![image-20250310163720355](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310163720355.png)

* 如果上下文中存在某个类的实例，可以通过该实例变量提供的getClass()方法获取，也可以调用某实例化对象的getClass()方法获取:

  ~~~java
  User user = new User();
  Class cls = user.getClass();
  //或
  Class cls = (new User()).getClass();
  ~~~

  ![image-20250310163803191](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310163803191.png)

* 知道一个class的完整类名（例如java.lang.String），可以通过静态方法Class.forName()获取。(使用forName()会自动初始化该Class对象）

  ~~~java
  public class test {
      public static void main(String[] args) throws Exception {
  		Class cls = Class.forName("User");
          System.out.println(cls);
      }
  }
  ~~~
  
  ![image-20250310163840269](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310163840269.png)
  
  forName有两个函数重载
  
  * `Class<?> forName(String name)  `
  * `Class<?> forName(String name, **boolean** initialize, ClassLoader loader)`
  
  ```java
  Class.forName(className)
  // 等于
  Class.forName(className, true, currentLoader)
  ```
  
  第二个参数表示是否初始化，在 forName 的时候，构造函数并不会执⾏，而是执⾏类初始化。他会执行`static{}`静态块里面的内容
  
  ```java
  package com.yuy0ung.reflect02;
  
  public class TrainPrint {
      {
          System.out.printf("Empty block initial %s\n", this.getClass());
      }
      static {
          System.out.printf("Static initial %s\n", TrainPrint.class);
      }
      public TrainPrint() {
          System.out.printf("Initial %s\n", this.getClass());
      }
  }
  
  ```
  
  ~~~java
  public class TemporaryFiles {
      public static void main(String[] args) {
          TrainPrint t1 = new TrainPrint();//实例化TrainPrint
      }
  }
  ~~~
  
  ![image-20250310165053933](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310165053933.png)
  
  当实例化这个类时，⾸先调⽤的是`static {}`，其次是 `{}` ，最后是构造函数。其中`static {}`就是在类初始化的时候调用的
  
  由于`Class`实例在JVM中是唯一的，所以，上述方法获取的Class实例是同一个实例

#### 2.获取方法

方法如下：
~~~java
Method getMethod(name, Class...)：获取某个public的Method（包括父类）
Method getDeclaredMethod(name, Class...)：获取当前类的某个Method，modifiers不限（不包括父类）
Method[] getMethods()：获取所有public的Method（包括父类）
Method[] getDeclaredMethods()：获取当前类的所有Method，modifiers不限（不包括父类）
  
Class表示方法返回值类型，无返回值则为null
~~~

java中所有的方法都是Method类型，所以我们通过反射机制获取到某个对象的方法也是Method类型的：

~~~java
Method method = cls.getMethod("setName", String.class);
~~~

![image-20250310213131968](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310213131968.png)

![image-20250310214208910](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310214208910.png)

一个Method对象包含一个方法的所有信息:

- `getName()`：返回方法名称
- `getReturnType()`：返回方法返回值类型，也是一个Class实例
- `getParameterTypes()`：返回方法的参数类型，是一个Class数组
- `getModifiers()`：返回方法的修饰符

#### 3.调用方法

Method类中有一个invoke方法，就是用来调用特定方法的

`invoke`的作用是执行方法，它的第一个参数是调用该方法的对象：

- 如果这个方法是一个普通方法，那么第一个参数是类对象
- 如果这个方法是一个静态方法，那么第一个参数是类

比如正常执行方法是 [类/类对象].method([参数1], [参数2]...) ，其实在反射里就是method.invoke([类/类对象], [参数1], [参数2]...) 

第二个参数是一个可变长参数，是这个方法的需要传入的参数，这里与上文代码配合调用setName方法：

~~~java
Method method = cls.getMethod("setName", String.class);
method.invoke((new User()), "Yuy0ung");
//或
User user = new User();
Method method = cls.getMethod("setName", String.class);
method.invoke(user, "Yuy0ung");
~~~

如此可以成功调用setName方法，并设置name为“Yuy0ung”,demo如下：

~~~java
package com.yuy0ung.reflect01;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Test05 {
    public static void main(String[] args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class cls = User.class;
        User user = new User();
        Method method = cls.getMethod("setName", String.class);
        method.invoke(user, "Yuy0ung");

        Method method1 = cls.getMethod("getName");
        String name = (String) method1.invoke(user); //将object转换为
        System.out.println(name);
    }
}

~~~

![image-20250310215712484](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250310215712484.png)

如果方法并不是public属性，可以使用Method.setAccessible(true)允许其调用，demo如下：

~~~java
package Demo;

import java.lang.reflect.Method;

  public class TemporaryFiles{
    public static void main(String[] args) throws Exception{
        
        Class cls = Student.class;//获取Student类的实例
        Method m = cls.getDeclaredMethod("hello", String.class);//获取hello方法
        m.setAccessible(true);//允许调用private方法
        m.invoke(cls.newInstance(), "Yuy0ung");//调用hello输出"hello, Yuy0ung"

    }
}

class Student extends Person{
    public int score;
    private int grade;

    private void hello(String s){
        System.out.println("hello, " + s);
    }
}

class Person{
    public String name = "Yuy0ung";

}
//输出：hello, Yuy0ung
~~~

![image-20250311143656330](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250311143656330.png)

### 访问字段

利用反射除了可以获取并调用方法，还可以获取并修改字段

#### 1.获取字段

有如下方法获取字段：

* `Field getField(name)`：根据字段名获取某个public的field（包括父类）
* `Field getDeclaredField(name)`：根据字段名获取当前类的field，modifiers不限（不包括父类）
* `Field[] getFields()`：获取所有public的field（包括父类）
* `Field[] getDeclaredFields()`：获取当前类的所有field，modifiers不限（不包括父类）

而一个Field对象包含了一个字段的所有信息，可用如下方法查看：

- `getName()`：返回字段名称
- `getType()`：返回字段类型，也是一个Class实例
- `getModifiers()`：返回字段修饰符

demo如下：

~~~java
public class TemporaryFiles{
    public static void main(String[] args) throws Exception{
        Class stdClass = Student.class;//获取Student类实例
        System.out.println(stdClass.getField("score"));//获取该类的public字段"score"
        System.out.println(stdClass.getField("name"));//获取该类继承的字段"name"
        System.out.println(stdClass.getDeclaredField("grade"));//获取该类的private字段"grade"
        
    }
}

class Student extends Person{
    public int score = 100;
    private int grade = 6;
}

class Person{
    public String name = "Yuy0ung";
}
~~~

![image-20250311145440376](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250311145440376.png)

#### 2.获取字段值

* `get(obj)`:获取字段值，格式为`name.get(obj)`，参数是该类的对象（需要把类实例化）而不是.class

比如获取上文demo中Student类的name字段值：

创建Field需要导包：

~~~java
import java.lang.reflect.Field;		//创建Field需要导包
~~~

接下来获取并输出：

~~~java
Class stdClass = Student.class;//获取Student类实例
Field name = stdClass.getField("name");//创建field获得name值
System.out.println(name.get(stdClass.newInstance()));//输出
~~~

![image-20250312193508687](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312193508687.png)

也可以一次性直接输出（无需导包）：

~~~java
Class stdClass = Student.class;//获取Student类实例
System.out.println(stdClass.getField("name").get(stdClass.newInstance()));//直接输出
~~~

![image-20250312193610107](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312193610107.png)

直接获取private类型的grade字段会抛出一个IllegalAccessException的错误：

![image-20250312194253495](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312194253495.png)

需要先使用Field.setAccessible(true):

~~~java
Class stdClass = Student.class;//获取Student类实例
Field grade = stdClass.getDeclaredField("grade");
grade.setAccessible(true);
System.out.println(grade.get(stdClass.newInstance()));
~~~

![image-20250312194237016](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312194237016.png)

#### 3.修改/设置字段值

* `set`：修改/设置字段值

以设置上文demo中grade值为例：

~~~java
import java.lang.reflect.*;

public class TemporaryFiles{
    public static void main(String[] args) throws Exception{
        Class std = Student.class;//获取Student类实例
        Student student = new Student();//先实例化
        Field f = std.getDeclaredField("grade");//记得导包
        f.setAccessible(true);//修改非public字段，需要首先调用setAccessible(true)
        f.set(student,666);//将std的grade值设置为666
        System.out.println(f.get(student));//输出grade的值
    }
}

class Student extends Person {
    public int score;
    private int grade;
}

class Person{
    public String name = "Yuy0ung";
}
~~~

![image-20250312200422599](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312200422599.png)

#### 4.反射修改被final关键字修饰的成员变量

先修改modifiers

```Java
// 反射获取Field类的modifiers
Field modifiers = field.getClass().getDeclaredField("modifiers");

// 设置modifiers修改权限
modifiers.setAccessible(true);

// 修改成员变量的Field对象的modifiers值
modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);

// 修改成员变量值
field.set(类实例对象, 修改后的值);
```

比如下面的demo：

```Java
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public class TemporaryFiles {
    public static void main(String[] args) throws Exception {
        Class cls = Class.forName("Yuy0ung");
        Yuy0ung yuy0ung = new Yuy0ung();
        Field field = cls.getDeclaredField("team");

        Field modifiers = Field.class.getDeclaredField("modifiers");
        modifiers.setAccessible(true);//获取访问权限

        modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL); // 清除 final 修饰符
        field.setAccessible(true); // 添加此行以使私有字段可访问
        field.set(yuy0ung, "W4ntY0u");//修改team字段为"W4ntY0u"
        System.out.println(field.get(yuy0ung));//输出team字段
    }
}

class Yuy0ung {
    final String team = "D0g3";
}

```

![image-20250312210604829](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312210604829.png)

### 获取构造方法

Java的反射API提供了Constructor对象，它包含一个构造方法的所有信息，可以创建一个实例。

通过Class实例获取Constructor的方法和上面获取方法类似，如下：

- `getConstructor(Class...)`：获取某个`public`的`Constructor`；
- `getDeclaredConstructor(Class...)`：获取某个`Constructor`；
- `getConstructors()`：获取所有`public`的`Constructor`；
- `getDeclaredConstructors()`：获取所有`Constructor`。

调用非`public`的`Constructor`时，必须首先通过`setAccessible(true)`设置允许访问（`setAccessible(true)`可能会失败）

### 获取继承关系

获取父类

```java
Class.getSuperclass()
```

获取interface

```java
Class.getInterface()
```

### 利用反射命令执行

#### Runtime

首先了解正常情况的命令执行：

```java
public class cmd {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec("calc");
    }
}
//执行后，系统会打开计算机
```

java.lang.Runtime 因为有一个 exec 方法，所以可以执行本地命令:

![image-20250312212949415](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312212949415.png)

当我们直接尝试使用.newInstance()调用Runtime的构造函数进行实例化，会产生报错，newInstance()失败的原因通常有两种：

* 使用的类没有无参构造函数
* 使用的类构造函数是私有的

而这里的原因是 Runtime 类的构造方法是私有的

但`Runtime.exec`方法有六个重载，而这里使用`exec(String commmand)`方法即可实现命令执行比如`exec("calc")`

而`Runtime`类有一个`getRuntime`方法，且这个方法是公有的：

~~~java
public Static Runtime getRuntime() {
    return currentRuntime;
}
~~~

该方法可以获取Runtime对象

综上，我们可以得到一个反射实现命令执行的思路;

* 在获取Runtime类实例后，通过`getMethod("exec",String.Class)`获取exec方法
* 通过Runtime.getRuntime获取Runtime对象
* 执行Runtime.exec方法

实现的代码如下：

```java
import java.lang.reflect.*;

public class cmd {
    public static void main(String[] args) throws Exception {
        Class Runtime = Class.forName("java.lang.Runtime");//获得Runtime类实例
        Method exec = Runtime.getMethod("exec", String.class);//获得exec方法
        Method getRuntime = Runtime.getMethod("getRuntime");//获得getRuntime方法
        Object runtime = getRuntime.invoke(Runtime);//调用getRuntime方法获取Runtime实例对象
        exec.invoke(runtime, "calc");//调用exec方法
    }
}
```

![image-20250312213610808](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312213610808.png)

整合一下，可以不用导包

~~~java
public class cmd {
    public static void main(String[] args) throws Exception {
        Class Runtime = Class.forName("java.lang.Runtime");
        Runtime.getMethod("exec", String.class).invoke(Runtime.getMethod("getRuntime").invoke(Runtime), "calc");
    }
}
~~~

也可以利用getConstructor()获取构造函数，并使用newInstance()执行，实现实例化

demo如下，因为Runtime构造器是Private，所以需要setAccessible(true)实现暴力访问权限：

~~~java
import java.lang.reflect.Constructor;

public class cmd {
    public static void main(String[] args) throws Exception {
        Class Runtime = Class.forName("java.lang.Runtime");//获得Runtime类实例
        Constructor constructor = Runtime.getDeclaredConstructor();//获取构造器
        constructor.setAccessible(true);//暴力访问权限
        Runtime.getMethod("exec",String.class).invoke(constructor.newInstance(),"calc");//调用构造器的newInstance实现实例化
    }
}
//弹出计算机
~~~

![image-20250312214529089](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250312214529089.png)

#### ProcessBuilder

ProcessBuilder也是一种常用的命令执行方式

其有两个构造函数：

* ~~~java
  public ProcessBuilder(List<String> command) {
      if(command == null)
          throw new NullPointerException();
      this.command = command;
  }
  ~~~

* ~~~java
  public ProcessBuilder(String... command) {
      this.cammand = new ArrayList<>(command.length);
      for(String arg : command)
      	this.command.add(arg);
  }
  ~~~

##### 第一种构造函数的利用

可以使用反射来获取其第一种构造函数进行命令执行

在getConstructor传入List.class获取第一种构造函数，然后获取并调用start() 来执行命令：

~~~java
import java.util.Arrays;
import java.util.List;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class cmd {
    public static void main(String[] args) throws Exception {
        Class psb = Class.forName("java.lang.ProcessBuilder");
        Constructor constructor = psb.getConstructor(List.class);
        Object obj =  constructor.newInstance(Arrays.asList("calc"));//执行的命令是打开计算器
        Method start = psb.getMethod("start");//获取start用于启动进程
        start.invoke(obj);//调用start启动进程，即打开计算器
    }
}
~~~

整合一下：

~~~java
import java.util.Arrays;
import java.util.List;

public class cmd {
    public static void main(String[] args) throws Exception {
        Class psb = Class.forName("java.lang.ProcessBuilder");
        psb.getMethod("start").invoke(psb.getConstructor(List.class).newInstance(Arrays.asList("calc")));
    }
}
~~~

##### 第二种构造函数的利用

也可以利用第二种形式的构造函数，对于可变长参数，Java其实在编译的时候会编译成一个数组，也就是说，如下这两种写法在底层是等价的：

~~~java
public void hello(String[] names) {}
public void hello(String...names) {}
~~~

换句话说，对于反射而言，如果要获取的目标函数里包含可变长参数，其实我们认为它是数组就行了

可以将字符串数组的类String[].class传给getConstructor，获取ProcessBuilder的第二种构造函数，在调用 newInstance 的时候，因为这个构造函数本身接收的是一个可变长参数即数组，传给 ProcessBuilder的是一个`List<String>`类型，二者叠加为一个二维数组

搓搓payload：

~~~java
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class cmd {
    public static void main(String[] args) throws Exception {
        Class psb = Class.forName("java.lang.ProcessBuilder");
        Constructor constructor = psb.getConstructor(String[].class);
        Object obj = constructor.newInstance(new String[][]{{"calc"}});
        Method method = psb.getMethod("start");
        method.invoke(obj);
    }
}
~~~

整合一下：

~~~java
public class cmd {
    public static void main(String[] args) throws Exception {
        Class psb = Class.forName("java.lang.ProcessBuilder");
        psb.getMethod("start").invoke(psb.getConstructor(String[].class).newInstance(new String[][]{{"calc"}}));
    }
}
~~~

### 反射在反序列化中的运用

* 修改对象为我们需要的条件
* 通过invoke调用除了同名函数以外的函数
* 通过Class类创建对象，引入不能序列化的类
