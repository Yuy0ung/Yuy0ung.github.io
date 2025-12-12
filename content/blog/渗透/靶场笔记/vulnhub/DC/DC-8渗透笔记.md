---
title: "DC-8渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-8渗透笔记

靶场描述：

![image-20240723155111312](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723155111350-1542013783.png)

### 信息搜集

IP、端口、网页目录一条龙：

![image-20240723154405800](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723154406432-764470172.png)

* IP为192.168.111.191
* 端口开放了22、80
* 目录可以看到登陆后台

再看看网页：
![image-20240723155138488](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723155137948-874519673.png)

这次的cms是drupal 7

### 漏洞利用

#### sql注入获取密码哈希

翻翻各个页面：

![image-20240723155509329](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723155508733-401835021.png)

发现有的页面是使用nid参数进行控制的，看看有没有sql注入：

![image-20240723155607358](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723155606974-871969811.png)

还真有，直接sqlmap一把梭：

* 爆库名：

  ![image-20240723155923879](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723155923218-635417641.png)

  库名为d7db

* 爆表名：
  ![image-20240723160130253](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723160129872-1837485563.png)

  88张表，里面的users表值得关注

* 爆列名：

  ![image-20240723160351831](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723160351154-843048956.png)

  16列，主要关注其中的name和pass

* 爆字段：

  ![image-20240723160553549](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723160553107-1416067232.png)

  ok拿到两组密码哈希

#### john破解密码哈希

把获得的账密写入文档：

用john进行暴力破解：

![image-20240723165104712](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723165105131-222840877.png)

admin的密码无法破解但john的密码是turtle

#### 后台反弹shell

直接在/user/login登录，成功，接下来就是在后台看看有没有写文件之类能够用来getshell的点了：

![image-20240723170023205](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723170022989-959123157.png)

发现确实有个写php代码的位置，懒得连webshell再反弹了，直接写反弹shell代码：

![image-20240723170720274](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723170719934-2029780122.png)

确认页面后，填写信息，发送php代码：

![image-20240723170818119](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723170817435-1899728033.png)

成功反弹shell：

![image-20240723175434401](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723175435012-1614575436.png)

python获取pty：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723175529073-1615727724.png" alt="image-20240723175529833" style="zoom:150%;" />

进入提权阶段

### 权限提升

接下来就是针对提权的信息收集了，发现suid权限的配置有点问题：

![image-20240723180955112](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723180955060-1851463582.png)

这个exim4有点问题，看看：

![image-20240723181218053](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723181218154-456358045.png)

发现该版本存在权限提升的漏洞

cp一下脚本，并且编辑查看文件类型：set ff=unix，这样脚本才能再linux下执行

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723183337664-1331504732.png" alt="image-20240723183337904" style="zoom:150%;" />

将该脚本上传到靶机上并赋予执行权限：

![image-20240723182320320](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723182320106-196468743.png)

按照使用方法执行脚本：

![image-20240723183956070](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723183955859-775465713.png)

再在/root拿到flag：

![image-20240723184155302](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723184155146-1311014351.png)

### 总结

本次渗透过程中，我们遇到了如下漏洞或利用：

* drupal 7页面id存在sql注入
* john破解密码哈希
* 后台contact页面能以php代码编辑，实现反弹shell
* exim4.89 存在权限提升漏洞