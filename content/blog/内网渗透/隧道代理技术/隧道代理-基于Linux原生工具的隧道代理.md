---
title: "隧道代理-基于Linux原生工具的隧道代理"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 隧道代理-基于Linux原生工具的隧道代理

文章的灵感来自于面试官的问题：“知道linux不上传任何工具怎么搭隧道代理吗”

由于平时习惯直接使用frp、venom、suo5等代理工具，或者是直接使用C2自带的代理，所以被问到的时候直接懵了，后面才发现我竟然在学习代理的时候是学过的：[隧道代理-端口转发相关工具](https://yuy0ung.github.io/blog/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F/%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86%E6%8A%80%E6%9C%AF/%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%E7%9B%B8%E5%85%B3%E5%B7%A5%E5%85%B7/)，但是当时没有上手实践所以根本没记住，特有此篇文章来记录相关操作

## 准备工作

我写了一个python脚本，用于在内网起一个web网页，通过是否可以访问来判断代理是否成功：

~~~python
import http.server
import socketserver

PORT = 8005
CONTENT = b"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Proxy Test</title>
</head>
<body>
    <h1>proxytest</h1>
    <h1>success</h1>
</body>
</html>
"""

class CustomHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)                     
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(CONTENT)

    def log_message(self, format, *args):
        return 

if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), CustomHandler) as httpd:
        print(f"[+] Serving on port {PORT} ...")
        httpd.serve_forever()
~~~

在被控服务器内网的8005端口运行（由于安全组等原因，不会开放到外网）：

![QQ_1750516993762](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750516993762.png)

可以看到现在是无法在外网访问的：
![QQ_1750516779223](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750516779223.png)

接下来开始进行代理操作

## SSH端口转发

首先是端口转发，一般都是选择正向转发：

~~~python
ssh -CfNg -L [本地端口]:[内网主机IP]:[内网主机端口] [外网主机IP]
~~~

这里的参数含义如下：

* -C：启用压缩（Compress），减少传输数据量，提高隧道效率，尤其在网络较差时
* -f：在验证成功后后台运行 SSH，否则会阻塞终端
* -N：不执行远程命令，仅用于端口转发
* -g：允许其他主机连接到你本地绑定的端口（否则默认只允许本机访问）
* -L：启用本地端口转发

首先将这个台被控主机反弹shell到我的控制端vps上：

![QQ_1750516969746](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750516969746.png)

然后python获取pty（一定要有一个交互式shell，我在测试的时候，反弹的shell不能直接输入ssh连接的密码），查看是否有ssh并端口转发，将内网8005端口转发到外网2333端口：

~~~sh
ssh -CfNg -L 2333:127.0.0.1:8005 [被控端服务器公网IP]
[回车后输入获取到的内网主机账户密码]
~~~

![QQ_1750518014388](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750518014388.png)

如此就实现了端口的转发，我们可以通过访问公网2333端口看到内网的8005端口web页面：

![QQ_1750518071186](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750518071186.png)

在测试完毕后，只需要kill掉相应进程即可：

![QQ_1750518339856](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750518339856.png)

## SSH动态转发

由于端口转发只能让我们可以访问固定的内网服务，这在一定程度上会限制我们的内网操作，所以可以考虑动态转发，这是一个类似socks5代理的方法：

~~~sh
ssh -N -D [本地监听IP]:[本地监听端口] [用户名]@[跳板机内网IP]
~~~

参数：

* -N：不执行远程命令，仅建立隧道（用于端口转发）
* -D：启动一个 SOCKS5 代理，监听在本地指定的 IP 和端口

所以前面的步骤和上面一样，只是ssh的使用命令变了：

~~~sh
ssh -N -D 0.0.0.0:2333 root@[被控服务器内网IP]
~~~

![QQ_1750520414629](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750520414629.png)

接下来我们在proxifier上配置socks5代理，实现对内网IP访问的转发：

![QQ_1750520516147](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750520516147.png)

接下来我们就可以随意的访问172.21.130.1/24段的内网服务了，比如浏览器直接访问上面内网的8005端口网页：

![QQ_1750520623505](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750520623505.png)

由于这里的动态转发并没有使用-f参数，所以不会在后台运行，在断开连接后，ssh进程就自动退出了，不需要kill进程来清楚痕迹：

![QQ_1750520819550](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1750520819550.png)

## 总结

这里我们记录了两种通过SSH在linux主机搭建隧道代理的方式，在不方便上传代理工具等特殊情况可以考虑使用，其实同样的在windows上也有netsh（只能用于端口转发），但由于windows的渗透通常都需要上线到C2，而C2的代理功能固然好用更多，所以就不记录了