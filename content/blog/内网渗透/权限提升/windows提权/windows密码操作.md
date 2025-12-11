---
title: "windows密码操作"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 权限提升-windows密码操作

## 密码搜索

密码搜索属于信息搜集的一部分，很多用户喜欢将自己的网站、邮箱、应用程序设置同一个密码，可以执行各类命令来搜索系统内存储密码的配置文件，通过组合收集到的密码来尝试登陆高权限账户，可能达到权限提升或横向移动的目的

#### 文件中的密码搜索

##### 搜索文件内容

搜索文件内容里包括“password”字符串的txt文件：
~~~cmd
findstr /SI /M "password" *.txt
~~~

也可以增加其他文件的格式：

~~~cmd
findstr /SI /M "password" *.txt *.ini *.config
~~~

* 参数/SI：在当前目录和所有子目录中搜索指定文件， 指定搜索部分大小写
* 参数/M：如果搜索到相关的文件，则只列出文件的绝对路径

再使用`“type + 目标文件路径”`命令来获取文件内容

如果不添加参数`/M`，则会列出包含目标字符串的所有文件和内容，会显得比较杂乱

##### 搜索文件名

搜索当前目录及子目录中文件名包含字符串“password”的文件：

~~~cmd
dir /s *password*
~~~

powershell命令：

~~~powershell
Get-ChildItem <文件夹路径> -Include *password.txt* -recurse
~~~

cmd命令切换到其他目录并搜索文件名中包含web.config的文件：

~~~cmd
cd /d E: && dir /b /s web.config
~~~

用for命令查找某盘符内文件名包含password.txt:

~~~cmd
for /r <盘符> %i in (password.txt) do @echo %i
~~~

也可以使用where命令来查找这种类型的文件：

~~~cmd
where /r C:\ *password.txt
~~~

#### 在注册表中寻找密码

获取注册表根键HKCU下包含“password”字符串的全部内容：

~~~cmd
reg query HKCU /f password /t REG_SZ /s
~~~

为了方便查看，或当前在webshell中操作时，可以将结果保存在文本中，下载后再查看

~~~cmd
reg query HKCU /f password /t REG_SZ /s >temp.txt
~~~

正常情况下，每次登陆服务器都需要输入密码，但有些管理员为了方便，可能会设置自动登录，注册表中会保存自动登录的账号和密码，所以可以尝试命令获取自动登录密码：

~~~cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
~~~

#### 无人值守文件

无人值守文件（自动应答文件）可用于在安装系统前修改镜像中的windows设置

管理员在安装系统前修改镜像，能够把想要自定义的内容提前配置好，例如：

* 磁盘分区
* 系统磁盘安装位置
* 产品密钥
* 网络设置
* 应用程序安装等各种网络配置
* 账户名、密码（一般为明文或base64编码），甚至是浏览器收藏夹、

使用这种方法的一般都是大型内网，因为手动一个一个地安装操作系统再进行配置比较耗费时间和精力，使用无人值守文件方便部署

这个文件的扩展名通常为`.xml`，可以在不同的位置

执行命令查找系统中可能存在的无人值守文件，从该文件中搜索存在的密码、密钥等信息：

~~~cmd
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>null 
~~~

或执行powershell cmdlet命令

~~~powershell
Get-Childitem -Path C:\ -Include *unattend* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
~~~

在查找到的目标xml文件中，存在PlainText字段：

* 该字段的值为true时，表示密码为明文
* 该字段的值为false时，表示密码为经过base64编码

**metasploit**中的模块`post/windows/gather/enum_unattend`也是用于查找无人值守文件的，并会自动对密码进行解码

#### 安全账户数据库备份文件

SAM（Security Account Manager，安全账户管理）数据库（位置在%SystemRoot%\system32\config\SAM）是windows用户账户数据库，保存着windows系统用户的加密形式的登陆密码，在一些旧版本的windows系统中，如果使用修复功能修复过windows系统，那么权限配置不当安全账户数据库也是备份的，备份文件保存在`C:\WINDOWS\repair\`文件夹中

如果该文件夹权限配置不当，那么可以将SAM文件和SYSTEM文件下载到本地，复制到攻击机kai中，进行提取HASH和爆破HASH的操作

#### 便笺信息                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       

#### 应用中的密码

#### powershell历史命令记录

#### WIFI密码

#### 凭据管理器

#### WSL系统

#### 针对密码泄露的防御措施

## 密码窃取

#### 伪造锁屏

#### 伪造认证框

#### 肩窥

#### 针对密码窃取的防御措施

## 密码破解

#### 暴力破解

#### 字典组合

#### 撞库攻击

#### 喷射攻击

针对密码破解的防御措施