---
title: "java进阶 demo"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java进阶 demo

### JDBC

Java数据库连接的一套接口（规范）

需要在程序中引入驱动包：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250122094027369.png" alt="image-20250122094027369" style="zoom:33%;" />

#### 插入操作

~~~java
package fun.yuy0ung.test01;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class Test {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        int i = stmt.executeUpdate("insert into my_book (id,name,author,price) values (3,'test','Yuy0ung',49)");

        //处理结果
        if(i > 0) {
            System.out.println("success");
        }else {
            System.out.println("fail");
        }

        //关闭数据库资源
        stmt.close();
        conn.close();
    }
;}

~~~

运行结果：

![image-20250122110005664](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250122110005664.png)

数据库成功写入数据：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250122110044394.png" alt="image-20250122110044394" style="zoom:50%;" />

#### 删除

举一反三，数据更新的操作直接更改sql语句即可：

~~~java
package fun.yuy0ung.test01;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class Test {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        int i = stmt.executeUpdate("DELETE FROM my_book\n" + "WHERE id = 3 AND name = 'test' AND author = 'Yuy0ung' AND price = 49");

        //处理结果
        if(i > 0) {
            System.out.println("success");
        }else {
            System.out.println("fail");
        }

        //关闭数据库资源
        stmt.close();
        conn.close();
    }
;}
~~~

更新成功：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250122110539951.png" alt="image-20250122110539951" style="zoom: 50%;" />

#### 查询

查询不是数据更新操作，需要换一种方式executeQuery：

~~~java
package fun.yuy0ung.test01;

import java.sql.*;

public class Test2 {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        ResultSet resultSet = stmt.executeQuery("select * from my_book");
        //结果集合ResultSet

        //处理结果
        while (resultSet.next()) { //判断rs中是否有记录，类似链表指针
            System.out.println(resultSet.getInt("id")+"---"+resultSet.getString("name")+"---"+resultSet.getString("author")+"---"+resultSet.getDouble("price"));
        }

        //关闭数据库资源
        stmt.close();
        conn.close();
    }
;}

~~~

成功查询：

![image-20250122111854691](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250122111854691.png)

### 书店-JDBC应用

书店功能实现：

1.查询书籍
2.查看所有书籍
3.下架图书
4.上架图书
5.退出程序

书店demo：

~~~java
package fun.yuy0ung.test02;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.Scanner;

public class Test {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {

        //打印菜单
        while(true) {
            System.out.println("-----------------------------------");
            System.out.println("这里是Yuy0ung的书店");
            System.out.println("1.查询书籍");
            System.out.println("2.查看所有书籍");
            System.out.println("3.下架图书");
            System.out.println("4.上架图书");
            System.out.println("5.退出程序");
            System.out.println("请输入想要使用的功能序号");
            //键盘录入，使用scanner类
            Scanner scanner = new Scanner(System.in);
            //录入序号
            int choice = scanner.nextInt();
            if (choice == 1) {
                System.out.println("请输入想要查询的书籍编号");
                //键盘录入书籍NO.
                int bno = scanner.nextInt();

                //查询对应编号书籍方法调用
                Book b = findBookByBno(bno);
                //判断书籍是否存在
                if (b == null) {
                    System.out.println("书籍不存在");
                }else {
                    System.out.println("当前查询结果：《"+b.getbName()+'》');
                }

            } else if (choice == 2) {
                ArrayList allBooks = findBooks();
                if (allBooks.size() == 0) {
                    System.out.println("没有书籍！");
                }else {
                    for(int i=0; i<allBooks.size(); i++) {
                        Book b = (Book)(allBooks.get(i));
                        System.out.println(b.getbId()+"---"+b.getbName()+"---"+b.getbAuthor()+"---"+ b.getbPrice());
                    }
                }
            } else if (choice == 3) {
                System.out.println("请输入想要下架的书籍编号");
                int bno = scanner.nextInt();
                int n = deleteBookByBno(bno);
                if (n == 0) {
                    System.out.println("指定书籍不存在！");
                }else{
                    System.out.println("删除成功");
                }
            } else if (choice == 4) {
                String a = scanner.nextLine();
                System.out.println("请输入想要上架的书籍名称");
                String bna = scanner.nextLine();
                System.out.println("请输入想要上架的书籍作者");
                String bau = scanner.nextLine();
                System.out.println("请输入想要上架的书籍价格");
                double bpr = scanner.nextDouble();
                int n = updateBookByBno(bna,bau,bpr);

                if (n == 0) {
                    System.out.println("上架失败");
                }else {
                    System.out.println("上架成功");
                }
            } else if (choice == 5) {
                System.out.println("------退出");
                break;
            }
        }
    }

    //根据编号查询书籍
    public static Book findBookByBno(int bno) throws ClassNotFoundException, SQLException {
        Book b = null;

        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        ResultSet resultSet = stmt.executeQuery("select * FROM my_book WHERE id = " + bno);

        //处理结果
        if (resultSet.next()) { //不用while遍历，存在即可
            //获取数据
            int id = resultSet.getInt("id");
            String name = resultSet.getString("name");
            String author = resultSet.getString("author");
            double price = resultSet.getDouble("price");

            //封装
            b = new Book();
            b.setbId(id);
            b.setbName(name);
            b.setbAuthor(author);
            b.setbPrice(price);
        }
        //关闭数据库资源
        stmt.close();
        conn.close();

        return b;
    }

    public static ArrayList findBooks() throws ClassNotFoundException, SQLException {
        //使用集合
        ArrayList list = new ArrayList();

        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        ResultSet resultSet = stmt.executeQuery("select * FROM my_book");

        //处理结果
        while (resultSet.next()) { //不用while遍历，存在即可
            //获取数据
            int id = resultSet.getInt("id");
            String name = resultSet.getString("name");
            String author = resultSet.getString("author");
            double price = resultSet.getDouble("price");

            //封装
            Book b = new Book();
            b.setbId(id);
            b.setbName(name);
            b.setbAuthor(author);
            b.setbPrice(price);

            //将封装好的书籍加入集合
            list.add(b);
        }
        //关闭数据库资源
        stmt.close();
        conn.close();

        return list;
    }

    //根据编号查询书籍

    public static int deleteBookByBno(int bno) throws ClassNotFoundException, SQLException {

        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        int i = stmt.executeUpdate("delete  FROM my_book WHERE id = " + bno);

        //关闭数据库资源
        stmt.close();
        conn.close();

        return i;
    }

    public static int updateBookByBno(String bna,String bau, double bpr) throws ClassNotFoundException, SQLException {
        //反射加载driver驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //获取连接
        String url = "jdbc:mysql://localhost:3306/Yuy0ung_DB?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "Admin123456";
        Connection conn = DriverManager.getConnection(url,username,password);

        //创建会话
        Statement stmt = conn.createStatement();

        //发送sql命令
        int i = stmt.executeUpdate("INSERT INTO my_book (name, author, price) VALUES ('"+bna+"', '"+bau+"', "+bpr+");");

        //关闭数据库资源
        stmt.close();
        conn.close();
        return i;
    }
}

~~~

book类：

~~~java
package fun.yuy0ung.test02;

import java.io.Serializable;

public class Book implements Serializable {
    //属性
    private int bId;
    private String bName;
    private String bAuthor;
    private Double bPrice;

    public int getbId() {
        return bId;
    }

    public void setbId(int bId) {
        this.bId = bId;
    }

    public String getbName() {
        return bName;
    }

    public void setbName(String bName) {
        this.bName = bName;
    }

    public String getbAuthor() {
        return bAuthor;
    }

    public void setbAuthor(String bAuthor) {
        this.bAuthor = bAuthor;
    }

    public Double getbPrice() {
        return bPrice;
    }

    public void setbPrice(Double bPrice) {
        this.bPrice = bPrice;
    }

    public Book() {
    }
}
~~~

### Maven

项目管理工具

* jar包管理方便
* 版本控制方便

#### Maven项目创建

在project内创建module即可：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250123154220033.png" alt="image-20250123154220033" style="zoom:33%;" />

如果是创建不需要archetype的maven项目可以直接在java模块中选择maven创建基础的module

#### Maven加载外部库

test目录下可以创建测试代码：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250123161040571.png" alt="image-20250123161040571" style="zoom:33%;" />

### 框架

半成品，封装重要/重复代码，添加更多功能

#### 优点

* 好用
* 强大
* 开发周期短

#### 缺点

* 学习成本
* 错误概率
* 错误解决难度

#### 分类

* 持久层框架：mybatis、spring data、ibaties、hibernate
* MVC框架：spring MVC、struts1、strust2
* 项目管理框架：spring framwork、spring boot
* 微服务框架：spring cloud
* 权限管理框架：spring security、shiro

### mybatis

#### 持久层框架

分层开发中负责访问数据源的一层

#### ORM框架

对象/关系映射

#### 搭建

* 建表
* 创建项目
* 添加依赖（maven添加mybaties+mysql驱动）
