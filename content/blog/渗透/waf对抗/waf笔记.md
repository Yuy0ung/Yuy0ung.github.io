---
title: "waf笔记"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# waf笔记

记录一下攻防演练中waf相关见闻

## 常见漏洞通用bypass

常见漏洞中一些通用的值得尝试的方法

### shiro

一位师傅说的：

>一部分shiro相关waf有一个检测步骤：
>
>将rememberMe的值用最常见的默认key去尝试解密，然后查看是否有敏感参数比如命令执行语句
>
>所以默认key的shiro攻击很容易被waf

* 将请求包的method改为随机字符串，比如`GET`改为`xxxxT`
* method置空，比如直接删掉`GET`
* 脏数据，在cookie的`rememberMe=`后面增加一些特殊字符`.`或`（因为shiro处理点号、反引号等会直接去除）
  * 空白字段，在`rememberMe=`中添加"tab"锁进变为`rememberMe			=`
* Host头的域名改为IP能绕过一部分只防护域名的云waf

## 常见waf

由于一直试通用的bypass比较费时间，所以记住一些常见waf的特性肯定会事半功倍

### 电信云堤

打shiro遇到的：

![image-20250605171031177](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250605171031177.png)

师傅说这个waf和大部分云waf都有个特性就是有可能只防护了域名，对此的bypass手法就是在请求包host头中把域名改成真实IP

### 奇安信网站卫士

默认key打shiro偶遇的，拼尽全力无法战胜

![image-20250605172012851](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250605172012851.png)