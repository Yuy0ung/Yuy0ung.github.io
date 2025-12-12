---
title: "权限提升-PEAS使用"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# 权限提升-PEAS使用

一个牛逼的针对权限提升的工具，适用于Windows/linux/unix*/macOS提权 

>这些工具搜索可能的**本地权限提升路径，您可以利用这些路径并将它们以漂亮的颜色**打印给您，以便您可以轻松识别错误配置

这里对其进行简单介绍，详细使用请前往github地址：https://github.com/carlospolop/PEASS-ng/

### WinPEAS

#### 介绍

直接命令行执行即可：

~~~cmd
winPEASany.exe
~~~

![image-20240924212949293](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240924212954653-1048033501.png)运行winpeas能搜索所有可能的提权路径，检查的信息如下

- 系统信息
  - 基本系统信息
  - 使用 Watson 搜索漏洞
  - 枚举 Microsoft 更新信息
  - PS、审计、WEF 和 LAPS 设置
  - LSA 保护
  - 凭据保护
  - WDigest
  - 缓存的信用数量
  - 环境变量
  - 互联网设置
  - 当前驱动器信息
  - 杀毒软件
  - Windows Defender
  - UAC 配置
  - NTLM 设置
  - 本地组策略
  - Applocker 配置和绕过建议
  - 打印机
  - 命名管道
  - AMSI 供应商
  - 系统监视器
  - .NET 版本
- 用户信息
  - 用户信息
  - 当前令牌特权
  - 剪贴板文本
  - 当前登录的用户
  - RDP 会话
  - 曾经登录过的用户
  - 自动登录凭据
  - 主文件夹
  - 密码策略
  - 本地用户详细信息
  - 登录会话
- 进程信息
  - 有趣的进程（非微软）
- 服务信息
  - 有趣的服务（非 Microsoft）信息
  - 可修改的服务
  - 可写服务注册表binpath
  - PATH DLL劫持
- 应用信息
  - 当前活动窗口
  - 安装的软件
  - 自动运行
  - 计划任务
  - 设备驱动程序
- 网络信息
  - 当前net share
  - 映射驱动器 (WMI)
  - 主机文件
  - 网络接口
  - 监听端口
  - 防火墙规则
  - DNS 缓存（限制 70）
  - 互联网设置
- Windows 凭据
  - Windows 保险库
  - 凭证管理器
  - 保存的 RDP 设置
  - 最近运行的命令
  - 默认 PS 成绩单文件
  - DPAPI 万能密钥
  - DPAPI 凭据文件
  - 远程桌面连接管理器凭据
  - Kerberos 门票
  - 无线上网
  - AppCmd.exe
  - SSClient.exe
  - SCCM
  - 安全包凭证
  - AlwaysInstallElevated
  - WSUS
- 浏览器信息
  - Firefox 数据库
  - Firefox 历史上的凭据
  - Chrome 数据库
  - chrome 历史上的凭据
  - 当前的 IE 选项卡
  - IE历史上的凭据
  - IE 收藏夹
  - **提取已保存的密码：Firefox、Chrome、Opera、Brave**
- 有趣的文件和注册表
  -  Putty会话
  -  Putty SSH 主机密钥
  -  SuperPutty信息
  -  OneDrive 同步的 Office365 端点
  -  注册表中的 SSH 密钥
  -  云凭证
  -  检查无人参与的文件
  -  检查 SAM 和 SYSTEM 备份
  -  检查缓存的 GPP 密码
  -  从 McAffe SiteList.xml 文件中检查并提取凭据
  -  可能的具有凭据的注册表
  -  用户家中可能的凭据文件
  -  **回收站中可能存在的密码文件**
  -  可能包含凭据的文件（这需要几分钟）
  -  用户文件（限制 100 个）
  -  Oracle SQL Developer 配置文件检查
  -  Slack文件搜索
  -  Outlook 下载
  -  机器和用户证书文件
  -  Office最近的文件
  -  隐藏的文件和文件夹
  -  具有写入权限的非默认文件夹中的可执行文件
  -  WSL 检查
- 活动信息
  - 登录 + 显式登录事件
  - 流程创建事件
  - PowerShell 事件
  - 电源开/关事件
- 附加（较慢）检查
  - LOLBAS 搜索
  - 在默认 WSL 分发中运行**[linpeas.sh](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh)**

#### 参数设置

`-h`可以查看所有参数：

~~~
[*] WinPEAS是一个二进制文件，它列举了本地升级特权的可能路径
        quiet                不要打印横幅
        notcolor             不要使用ansi颜色(全白)
        domain               列举域信息
        systeminfo           搜索系统信息
        userinfo             搜索用户信息
        processinfo          搜索处理信息
        servicesinfo         搜索服务信息
        applicationsinfo     搜索已安装应用程序信息
        networkinfo          搜索网络信息
        windowscreds         搜索windows的凭证
        browserinfo          搜索浏览器信息
        filesinfo            搜索可以包含凭据的通用文件
        fileanalysis         搜索可能包含凭据的特定文件
        eventsinfo           显示感兴趣的事件信息
        wait                 在两次检查之间等待用户输入
        debug                显示调试信息-内存使用，方法执行时间
        log[=logfile]        将所有输出记录到定义为logfile的文件中，如果没有指定，则记录到"out.txt"

        额外的检查(慢):
        -lolbas              运行额外的LOLBAS检查
        -linpeas=[url]       运行额外的linpeasen.sh检查默认的WSL分发，可选地提供自定义linpeasen.sh URL
                             (默认: https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)
~~~

### LinPEAS

#### 介绍

LinPEAS能搜索可能的**权限提升路径**（在 Debian、CentOS、FreeBSD、OpenBSD 和 MacOS 中测试）

>**这个脚本没有任何依赖。**
>
>它使用**/bin/sh**语法，因此可以在任何支持`sh`（以及使用的二进制文件和参数）中运行。
>
>默认情况下，**linpeas 不会向磁盘写入任何内容，也不会尝试以任何其他用户身份使用`su`**.

使用前赋予一下执行权限：

~~~shell
chmod+x linpeas.sh

./linpeas.sh -h
~~~

![image-20240924213930383](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240924213933143-689263829.png)

LinPEAS 使用颜色来指示每个部分的开始位置，也用来识别潜在的错误配置

红色/黄色用于识别导致 PE 的配置（99% 肯定）

红色用于识别可能导致 PE 的可疑配置：

- 可能的可利用内核版本
- 易受攻击的 sudo 版本
- **识别以 root 身份运行的进程**
- 未安装的设备
- 危险的 fstab 权限
- 有趣目录中的可写文件
- 具有某些易受攻击版本的 SUID/SGID 二进制文件（它还指定易受攻击的版本）
- 可用于在 sudo -l（无密码）中提升权限的 SUDO 二进制文件（https://gtfobins.github.io/）
- 检查 /etc/doas.conf
- 网络统计中的 127.0.0.1
- **可能包含密码的已知文件**
- 有趣的二进制文件中的功能
- 二进制文件的有趣功能
- 有关 cron 作业的信息中的可写文件夹和通配符
- PATH 中的可写文件夹
- 可能导致root的组
- 可能包含密码的文件
- 可疑的 cronjobs

绿色**用于**：

- 由 root 运行的常用进程
- 安装常见的不感兴趣的设备
- 不危险的 fstab 权限
- SUID/SGID 通用二进制文件（该 bin 已在其他机器中找到，并且 searchsploit 未识别任何易受攻击的版本）
- 路径中的常见 .sh 文件
- 执行进程的用户的通用名称
- 常见的 cronjobs

**蓝色**用于：

- 没有shell的用户
- 安装设备

**浅青色**用于：

- 有shell的用户

**浅洋红色**用于：

- 当前用户名

#### 参数设置

参数如下：

~~~
该工具将枚举并搜索主机内部可能的错误配置(已知的vulns、用户、进程和文件权限、特殊文件权限、可读/可写文件、暴力破解其他用户(top1000pwds)、密码……)，并用颜色突出显示可能的错误配置。
      -h 显示此帮助消息
      -q 不显示横幅
      -e 执行额外的枚举
      -s 超快(不检查一些耗时的检查)-潜行模式
      -a 所有检查(1分钟的进程和su)——噪声模式，主要用于CTFs
      -w 在大块检查之间等待执行
      -N 不要使用颜色
      -D 调试模式
      -P 指定用于运行'sudo -l'和通过'su'强制其他用户帐户的密码
      -o 只执行选定的检查(system_information、container、procs_crons_timers_srvcs_sockets、network_information、users_information、software_information、interesting_files)。选择逗号分隔的列表。
      -L 强制linpeas执行。
      -M 强制macpeas执行。
      -d <ip netmask="">使用fping或ping发现主机。</ip>例: -d 192.168.0.1/24
      -p <PORT(s)> -d <IP/NETMASK> 发现寻找TCP开放端口的主机(通过nc)。默认端口22、80,443,445、3389和您指定的另一个端口将被扫描(如果您不想添加更多端口，请选择22)。您也可以添加端口列表。例如:-d 192.168.0.1/24 -p 53,139
      -i <IP> [-p <PORT(s)>] 使用nc扫描IP。默认情况下(没有-p)，将扫描nmap的top1000，但您也可以选择一个端口列表。例如:-i 127.0.0.1 -p 53,80,443,8000,8080
      -t 自动网络扫描(主机发现和端口扫描)-此选项写入文件
         注意，如果指定一些网络扫描(options -d/-p/-i，但NOT -t)，将不会执行PE检查
~~~
