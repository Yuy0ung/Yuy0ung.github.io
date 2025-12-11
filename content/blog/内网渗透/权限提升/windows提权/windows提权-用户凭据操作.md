---
title: "windows提权-用户凭据操作"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# windows提权-用户凭据操作

### 枚举Unattended凭据

无人值守（Unattended）安装允许应用程序在不需要管理员关注的情况下自动安装

但这样会导致系统中残留一些配置文件，其中可能包含本地管理员的用户名和密码，常见路径：

~~~
C:\sysprep.inf

C:\syspreg\sysprep.xml

C:\Windows\system32\sysprep.inf

C:\windows\system32\sysprep\sysprep.xml

C:\unattend.xml

C:\Windows\Panther\Unattend.xml

C:\Windows\Panther\Unattended.xml

C:\Windows\Panther\Unattend\Unattended.xml

C:\Windows\Panther\Unattend\Unattend.xml

C:\Windows\System32\Sysprep\Unattend.xml

C:\Windows\System32\Sysprep\Panther\Unattend.xml
~~~

我们可以全盘搜索这些文件

~~~cmd
dir /b /s c:\unattend.xml
~~~

当然，msf提供了enum_unattend模块，可以从unattend配置文件中自动化检索用户密码

### 获取组策略凭据

SYSVOL 是活动目录里的一个用于存储域公共文件服务器副本的共享文件夹，在域中的所有域控之间进行复制，SYSVOL 在所有经过身份验证的域用户或者域信任用户具有读权限的活动目录域范围内共享，所有的域策略均存放在 C:\Windows\SYSVOL\DOMAIN\Policies\ 目录中。

管理员在域中新建一个组策略后，系统会自动在 SYSVOL 目录中生成一个 XML 文件

该文件中保存了该组策略更新后的密码，该密码使用 AES-256 算法，但 2012 年微软公布了该密码的私钥，也就是说任何人都可以对其进行解密

在目录中搜索即可：

```cmd
findstr /s /i "cpassword" C:\Windows\SYSVOL\*.xml
```

然后找到cpassword的值解密

Gpprefdecrypt.py 下载地址：https://raw.githubusercontent.com/leonteale/pentestpackage/master/Gpprefdecrypt.py

~~~cmd
python2.7 Gpprefdecrypt.py Wdkeu1drbxqPJm7YAtPtwBtyzcqO88hJUBDD2eseoY0
~~~

使用 **msf **的 `post/windows/gather/credentials/gpp` 模块也可以搜索cpassword并解密

### HiveNightmare

和我之前看见的卷影拷贝获取ntds.dit原理相似，任何标准用户都可以从卷影副本中读取包括SAM、SYSTEM、SECURITY在内的多个系统文件，进而从SAM获取HTLM hash，破解后可以实现权限提升

低权限cmd检测是否存在漏洞：

~~~cmd
icacls c:\windows\system32\config\sam
~~~

若输出结果是：BUILTIN\USERS:(I)(RX)，表明存在漏洞（RX代表[READ/EXecute权限）

EXP下载地址：`https://github.com/GossiTheDog/HiveNightmare`
作者已经编译好的利用脚本下载地址：`https://github.com/GossiTheDog/HiveNightmare/releases/tag/0.6`

直接将作者编译好的 HiveNightmare.exe 拷贝到目标系统上执行即可

### 其他

其他的域内提权手法总结在我的另一篇文章