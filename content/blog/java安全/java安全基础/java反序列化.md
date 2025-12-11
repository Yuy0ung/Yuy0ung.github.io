---
title: "java反序列化"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化

## 序列化与反序列化

方便对象传输，对象与序列化字符串的转换

## demo

person类

~~~java
package com.yuy0ung.fundamentals;

import java.io.Serializable;

public class Person implements Serializable {
    private String name;
    private int age;
    public Person() {

    }
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    @Override
    public String toString() {
        return "Person [name=" + name + ", age=" + age + "]";
    }
}
~~~

序列化：

~~~java
package com.yuy0ung.fundamentals;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class SerializationTest {
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static void main(String[] args) throws IOException {
        Person person = new Person("aa", 22);
//        System.out.println(person);
        serialize(person);
    }

}
~~~

反序列化：

~~~java
package com.yuy0ung.fundamentals;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class UnserializeTest {
    public static Object unserrialize(String fileName) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ser.bin"));
        Object obj = ois.readObject();
        return obj;
    }
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        Person person = (Person) unserrialize("ser.bin");
        System.out.println(person);
    }
}
~~~

为什么会有不安全的反序列化：

> 因为只要服务端反序列化数据，客户端传递类的readObject中代码会自动执行，攻击者就可以在服务器运行代码

1.入口类的readObject直接调用危险方法。
2.入口类参数中包含可控类，该类有危险方法，readObject时调用。
3.入口类参数中包含可控类，该类又调用其他有危险方法的类，readObject时调用。
比如类型定义为Object，
调用 Mequals/hashcode/toString
重点 相同类型 同名函数
4.构造函数/静态代码块等类加载时隐式执行。

**反序列化基础利用条件**：

* 继承serializable

* 入口点 source（重写readObject 参数类型宽泛 最好jdk自带）
* 调用链 gadget chain
* 执行类 sink （rce、ssrf、写文件等）

可以重写person类的readObject方法来验证:
~~~java
package com.yuy0ung.fundamentals;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Person implements Serializable {
    private String name;
    private int age;
    public Person() {

    }
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    @Override
    public String toString() {
        return "Person [name=" + name + ", age=" + age + "]";
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        Runtime.getRuntime().exec("open -a calculator");
    }
}
~~~

序列化然后反序列化就会弹计算器


