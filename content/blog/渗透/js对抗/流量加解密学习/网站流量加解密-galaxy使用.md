---
title: "网站流量加解密-galaxy使用"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 网站流量加解密场景入门&Galaxy使用

这里使用的Galaxy开发者的网站demo做测试，场景比较简单，入门够用

## 网站加解密分析

可以看见网站有对于username的query功能：

![image-20250509170354251](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509170354251.png)

请求后查看request和response：

![image-20250509153942818](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509153942818.png)

发现请求和返回都加了密，可以看见这里是以POST方法请求`/api/des-cbc/getUserInfo`路由，所以在浏览控制台设置xhr断点拦截该路由的POST请求：

![image-20250509154219961](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509154219961.png)

再次点击query发现请求停在了断点处，且可以看到加解密的信息：

![image-20250509154426098](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509154426098.png)

加密代码如下，我们甚至可以看到data加密前的值：

![image-20250509154737203](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509154737203.png)

解密代码在请求之后：

![image-20250509154821594](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509154821594.png)

分析代码，可以得出结论：

* des加密
* key为12345678
* iv为12345678
* CBC模式

* padding为Pkcs7

## galaxy自动加解密

接下来是工具hook部分，我使用的是galaxy，当然autodecoder也可以试试（我还没学）：
我这里选择jython的hooker，模式即des_cbc，hooker中的参数按照上面分析出来的进行设置即可:

![image-20250509163344268](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509163344268.png)

配置好直接start，接下来我们就可以对加密的流量包进行解密了：

![image-20250509163552577](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509163552577.png)

例如选择decrypt request，即可得到明文请求：

![image-20250509163805931](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509163805931.png)

响应也是同理：
![image-20250509163738673](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509163738673.png)

此时，我们再将网页请求代理到burp即可发现请求和响应都已经被自动解密：

![image-20250509164003828](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250509164003828.png)

同理，在这个基础上可以将有加密的包send to sqlmap（galaxy自带的功能，此时galaxy是sqlmap和服务端的中间人，能够自动进行流量加解密），这个就不多介绍了