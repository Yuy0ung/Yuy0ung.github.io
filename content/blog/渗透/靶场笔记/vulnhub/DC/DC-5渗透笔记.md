---
title: "DC-5渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# 	DC-5渗透笔记

### 信息搜集

经过前面几个靶机的练习，已经轻车熟路了：

![image-20240719165439053](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719165440506-1265514191.png)

信息搜集一条龙，可知：

* IP为192.168.111.145
* 开放了80、111、47890三个端口
* 目录扫描到一点点可访问路径

接下来看看web服务：

![image-20240719170107740](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719170108696-1805610347.png)

并不是什么通用的cms，那么就只有先尝试从功能点入手了，翻一翻这里有哪些功能

![image-20240719170557993](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719170558580-1764687279.png)

我们发现contact功能点有留言功能，写点东西试试

![image-20240719170536916](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719170537599-1176214578.png)

提交后发现跳转了，并且网页底部的**Copyright**值从2019变成了2017

联想到我们在用dirsearch的时候，扫描到一个footer.php，看名字应该也是一个关于网页底部内容的文件，访问试试：

![image-20240719170914419](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719170914869-1286745330.png)

还真是，而且如果我们刷新，年份还会有变化：

![image-20240719171021710](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719171022097-293216287.png)

![image-20240719170956308](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719170956668-1833244195.png)

![image-20240719171006472](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719171006880-1474555334.png)

如果有搭建博客经历的话，其实就能想到，这个footer.php应该是被包含在了thankyou.php里的，我们可以尝试以此为立足点展开利用

### 漏洞利用

#### 文件包含漏洞

如果这里存在文件包含，我们可以用fuzz一下可能用于包含的参数

先试试get方法：

![image-20240719172220260](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719172220731-1651889598.png)

fuzz一手发现参数为file

![image-20240719172850016](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719172850469-1047640388.png)

再验证一下，包含`/etc/passwd`试试：

![image-20240719173015121](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719173015855-991786372.png)

确实是文件包含，那么这里想要getshell就有两种思路：

* 打php_filter_chain，但是filter链很长，会被GET传参限制，所以只能执行简单命令，但确实可以实现RCE：

  ![image-20240719173902420](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719173903438-1359853957.png)

* 包含日志文件写马，只要知道日志文件路径就能写，而我们已知中间件为Nginx，路径通常为`/var/log/nginx/access.log`，可以尝试一手

#### 包含日志文件写马

ok直接抓包写一个phpinfo试试：

![image-20240719174938855](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719174939789-654701500.png)

包含日志文件看看：

![image-20240719174926256](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719174927455-451503483.png)

出现了phpinfo界面，成功

接下来可以写个一句话木马：

![image-20240719174347892](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719174348619-288920858.png)

蚁剑连接试试：

![image-20240719175130432](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719175131031-542488280.png)

连上了，接下来就是反弹shell了

#### 获取交互式shell

![image-20240719175359080](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719175359635-605633148.png)

nc反弹shell

![image-20240719175450445](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719175451266-2057744534.png)

成功连上了

依然是python获取pty：
![image-20240719175703397](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719175704574-238664822.png)

我们当前的权限是www-data，接下来又是权限提升了

### 权限提升

先看看SUID权限的文件有没有什么可以利用的

![image-20240719180614279](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719180616020-543896218.png)

还真有一个Screen 4.5.0的漏洞可用于权限提升

将脚本复制一份放到web目录：

![image-20240719181225427](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719181226450-1013409552.png)

看看脚本内容：

![image-20240719181927338](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719181928460-1039659089.png)

如图，脚本内容分三段，前两段会构造出单独的脚本文件，还有一段会执行利用命令

接下来打开http服务准备上传文件：

~~~shell
python2 -m SimpleHTTPServer 8000
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719182550833-1953735478.png" alt="image-20240719182549940" style="zoom:150%;" />

在靶机上使用wget下载脚本文件到/tmp/目录，再赋予执行权限，即可运行提权脚本：

![image-20240719184355436](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719184356421-1502863059.png)

如图，提权成功，ez

接下来在/root目录拿到flag：

![image-20240719184524804](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719184525519-76934216.png)

### 总结

本次渗透过程中，有如下漏洞或利用：

* web网页文件包含参数可控
* 利用文件包含漏洞，包含日志文件写马
* getshell后利用screen的版本漏洞实现suid提权