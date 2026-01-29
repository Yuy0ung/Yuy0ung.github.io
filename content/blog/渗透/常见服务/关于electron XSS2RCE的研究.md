---
title: "关于electron XSS2RCE的研究"
date: 2026-01-26T00:00:00+08:00
draft: false
---

# 关于electron XSS2RCE的研究

每次听见XSS2RCE，第一反应都是：客户端？electron？不过一直是知其然不知其所以然，于是现在来仔细了解一下其中的原理

## 多进程通信

Electron采用多进程架构，有两种进程：

* 主进程（Main Process）：拥有完整系统权限，负责窗口管理、原生API调用，它运行在Node.js环境中,拥有完整的系统访问权限,可以执行任意系统命令、访问文件系统

* 渲染进程（Renderer Process）：基于Chromium的网页环境，处理UI渲染，只有受限的权限

两者通过IPC（进程间通信） 机制交互，但默认配置下，这种通信缺乏严格的权限校验

到这里，我们其实可以简单理解其架构为浏览器内核+Node.js

## 安全配置项

一些错误的配置会导致漏洞风险的增加：

* `nodeIntegration: true`：直接在渲染进程中启用Node.js环境，即让渲染进程里的网页代码可以直接使用完整的 Node.js 环境，包括对文件、操作系统的控制功能

* `contextIsolation: false`：关闭上下文隔离，preload 脚本、网页脚本、Electron 内部扩展共享同一个 V8 全局上下文，互相可见可调用

* `enableRemoteModule: true`：该机制允许渲染进程通过 remote 调用主进程能力，已被官方明确标记为不推荐使用，并在新版本中逐步弃用

## XSS到RCE的利用

我们到这里已经大致能想到攻击链路了，即通过在渲染进程触发XSS，并尝试通过XSS来控制Node API，实现对系统的访问控制

我写了一个markdown文本编辑器来模拟electron应用，用户可以输入md语法格式的文本：

![image-20260126165859953](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20260126165859953.png)

点击preview可以预览解析md后的文本样式：

![image-20260126165940071](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20260126165940071.png)

### 最理想的情况

我在代码开启了危险配置：
![QQ_1769418012383](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769418012383.png)

由于这两个条件均开启，页面 JS 可以直接调用 Node.js 的 require，此时可以利用`child_process` 模块执行系统命令，实现 RCE，这里选择弹计算器的payload：

~~~html
<img src=x onerror="require('child_process').exec('open -a Calculator')">
~~~

![QQ_1769418059914](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769418059914.png)

点击预览，可以看到这里成功触发了XXS2RCE：

![QQ_1769418078357](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769418078357.png)

### 关闭nodeIntegration

接下来是关闭nodeIntegration的情况：

![QQ_1769418228221](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769418228221.png)

利用方法会比较苛刻一点，我们可以利用暴露的IPC接口，例如我在代码做了如下实现：

![QQ_1769418948547](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769418948547.png)

可以看到这里有一个用于读文件的IPC，而这个IPC又被暴露了出来：

![QQ_1769419367857](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769419367857.png)

那么我们可以通过XSS发送构造好的IPC消息来读文件，这里payload选择读取`/etc/passwd`文件：

~~~html
<img src=x style="display:none" onerror="ipcRenderer.send('read-file', '/etc/passwd')">
~~~

![QQ_1769419123387](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769419123387.png)

此时点击预览就会触发XSS，实现读文件操作：
![QQ_1769419234077](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769419234077.png)

### 启用contextIsolation

在此基础上，如果启用了contextIsolation呢？事实上，如果关闭了 sandbox 并且 Preload 脚本写得不安全，也会存在安全风险：

![QQ_1769419970024](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769419970024.png)

什么是sandbox选项？
>- 在较新的 Electron 版本中，默认开启了 Sandbox 。
>- 当 Sandbox 开启时，Preload 脚本只能访问极其有限的 Electron API（如 ipcRenderer ）， 无法访问 shell 模块 。

下面是不安全的preload脚本示例，直接暴露了shell模块：
![QQ_1769420316462](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769420316462.png)

在此情况下，我们可以直接调用`window.electron.shell.openExternal`，实现命令执行，这里我们仍然选择调用计算器：
~~~html
<img src=x style="display:none" onerror="window.electron.shell.openExternal('file:///System/Applications/Calculator.app')">
~~~

![QQ_1769420496378](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769420496378.png)

点击预览进行渲染，成功触发命令执行：

![QQ_1769420566763](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1769420566763.png)

## 总结

至此，我们了解了electron XSS2RCE的基本原理及其利用，其防御措施如下：

* 关闭nodeIntegration选项

* 开启contextIsolation选项

* 开启sandbox选项

* 关闭enableRemoteModule选项

* IPC 通信安全设计

* 使用CSP策略

  