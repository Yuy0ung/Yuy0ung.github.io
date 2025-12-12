---
title: "DC-9渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-9渗透笔记

### 信息搜集

IP、端口、目录一条龙：

![image-20240723215749893](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723215750025-193802802.png)

* IP为192.168.111.142
* 端口开放了22、80
* 目录只扫到一点点

再看看web页面：

![image-20240723225636482](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723225635884-1618970454.png)

并不是什么通用的cms，那就从功能点入手：
搜索功能点有个输入框，用万能密码试试：

![image-20240723230246708](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723230246642-1706289929.png)

直接爆出了所有员工信息：

![image-20240723230341051](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723230340311-48484347.png)

可知这里有SQL注入

### 漏洞利用

#### sql注入

sqlmap跑一下

* 爆库名：

  <img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723231014920-237618282.png" alt="image-20240723231015222" style="zoom:150%;" />

* 爆表名：

  ![image-20240723231143352](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723231142808-634555820.png)

* 打印表：

  ![image-20240723233703690](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723233703220-237900667.png)

获得了员工的账密，但是没有admin，再看看Staff库：

![image-20240723234000091](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723233959438-1688894244.png)

有俩表

* 爆俩表：

  StaffDetails：

  ![image-20240723234202150](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723234201725-1029927531.png)

  Users：

  ![image-20240723234920669](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723234919837-170453054.png)

  得到了admin的密码**transorbital1**

#### 文件包含

成功登录：

![image-20240723235444210](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723235443990-2083694630.png)

注意到页脚有“File does not exist”，一眼定真，存在文件包含，之前DC也遇到过，猜猜参数：

![image-20240723235748018](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240723235747422-1912561015.png)

哈哈还真是

接下来本来想尝试包含日志文件写马的，但是没有试出日志文件路径。。。

那么如何getshell？我们包含的时候可见passwd文件有很多用户，和数据库中用户一致，所以可以尝试一下ssh爆破：

~~~shell
hydra -L name.txt -P pass.txt ssh://192.168.111.142
~~~

![image-20240724005321921](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724005321374-2089920908.png)

不行，拒绝连接，这里应该是存在敲门服务：

>存在knockd服务。 该服务通过动态的添加iptables规则来隐藏系统开启的服务，使用自定义的一系列序列号来"敲门"，使系统开启需要访问的服务端口，才能对外访问。 不使用时，再使用自定义的序列号来"关门"，将端口关闭，不对外监听。进一步提升了服务和系统的安全 //配置文件路径 默认配置文件是：/etc/knockd.conf

所以先包含一下配置文件看看：

![image-20240724005718384](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724005717441-1043386151.png)

所以要依次对7469、8475、9842敲门，再连接ssh服务：

* 敲门：

  ![image-20240724010039783](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724010039225-405432143.png)

  可以看见ssh已开启：

  ![image-20240724010631697](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724010631089-752345795.png)

* 接下来再ssh爆破：

  ![image-20240724011604902](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724011605517-1402283747.png)

  获得了三组账户

#### ssh连接

三组用户都登陆试试，最后发现janitor的个人目录下有一个目录，看看：

![image-20240724012649351](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724012649026-1785542544.png)

发现几个密码，添加到原本的密码字典再ssh爆破一次：

![image-20240724013107052](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724013106663-2037828253.png)

发现多爆出一个fredf用户，登录

### 权限提升

信息搜集一下

![image-20240724013458434](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724013458170-333215704.png)

发现有个免密sudo，看看权限

![image-20240724020744490](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724020743787-271332876.png)

可执行，再看看其他的

![image-20240724014015142](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724014014832-196214702.png)

在/opt/devstuff目录下发现了一个test.py脚本文件，可以用来写文件，并且参数可控

那么就是一个很经典的sudo提权思路：构造一个拥有root权限的用户，并且通过脚本写入/etc/passwd文件中，即可登录

* 首先构造一个Yuy0ung用户的身份信息：

  ~~~shell
  openssl passwd -1 -salt Yuy0ung Yuy0ung
  //-1为MD5加密算法，-salt指定盐值，后面为密码
  ~~~

  构造出来：

  ~~~
  Yuy0ung:$1$Yuy0ung$9ETRQ.9iG7QgQQBI3xKu11:0:0:hack:/root:/bin/bash
  ~~~

* 把构造好的字符串写入文件：

  ![image-20240724022704413](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724022703384-98170602.png)

* 运行脚本写入/etc/passwd：

  ![image-20240724021951618](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724021950858-870152616.png)

* 直接su切换到Yuy0ung用户：

  ![image-20240724022641695](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724022641001-764406464.png)

  成功提权到root

在/root目录中拿到了flag：

![image-20240724022824593](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240724022824266-793501541.png)

### 总结

本次渗透过程中，遇到了以下漏洞或利用：

* 网站搜索框存在sql注入
* 网页后台存在文件包含
* 敲门开启ssh服务
* sudo脚本参数利用实现新增root用户提权