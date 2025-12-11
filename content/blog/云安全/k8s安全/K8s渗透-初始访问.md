---
title: "K8s渗透-初始访问"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# K8s渗透-初始访问

> 文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

初始访问是攻防矩阵的第一步，可以简单理解为获取对k8s的访问权限

## APIServer未授权

### insecure-port开启

典中典的k8s相关漏洞，APIServer在集群中被用于提供API来控制集群内部，如果我们能控制API Server，就意味着我们可以通过它利用kubectl创建Pod并使用磁盘挂载技术获取Node节点控制权

如果目标主机将APISevrer非安全端口8080暴露出来，便可以利用此端口进行对集群的攻击：

直接访问8080端口，会返回可用的API列表：

![QQ_1751982848150](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751982848150.png)

接下来需要用到kubectl，安装教程见[官网](https://kubernetes.io/zh-cn/docs/tasks/tools/install-kubectl-linux/?spm=a2c6h.12873639.article-detail.17.27ea1f40XfNqrj#install-using-native-package-management)

使用kubectl可以获取集群信息：

~~~sh
kubectl -s [ip]:[port] get nodes
~~~

![QQ_1752384616909](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752384616909.png)

上面这个案例可以看到有4个节点，其中有一个节点status为ready，可以成为后续执行阶段的入口点，比如利用kubectl调用该apiserver来创建恶意pod

### secure-port开启匿名访问

即6443安全端口的未授权访问

若我们不带任何凭证的访问 API server的 secure-port端口，默认会被服务器标记为`system:anonymous`用户。

一般来说`system:anonymous`用户权限是很低的，但是如果运维人员管理失当，把`system:anonymous`用户绑定到了`cluster-admin`用户组，那么就意味着secure-port允许匿名用户以管理员权限向集群下达命令，这也算是变向的未授权了:

![QQ_1752426203178](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752426203178.png)

我们可以通过kubectl进行apiserver调用：

```
kubectl -s https://112.126.76.224:6443 --insecure-skip-tls-verify=true cluster-info
```

![QQ_1752426404993](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752426404993.png)

当然有可能会遇到这种情况：

![QQ_1752426467047](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752426467047.png)

这种时候可以使用浏览器curl去请求api接口查看响应的json都能达到类似效果：

![QQ_1752426612745](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752426612745.png)

当然有个很好用的工具叫**cdk**也可以实现，有个kcurl参数功能是连接K8s api-server发起自定义HTTP请求：

![QQ_1752426961861](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752426961861.png)

在匿名用户可以未授权访问6443端口的情况，，我们可以尝试访问`/api/v1/namespaces/default/secret`路由来尝试获取用户token：

![QQ_1754839911396](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754839911396.png)

我们将这里的token字段进行base64解码后可以到到kubectl的6443安全端口进行操作，比如获取当前的权限：

~~~sh
kubectl auth can-i --list --server=https://119.8.60.88:6443 --token="<token值>" --insecure-skip-tls-verify
~~~

![QQ_1752504397042](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752504397042.png)

这里可以看到权限非常高

打法和不安全端口8080未授权类似，这里不再细说

## kubectl proxy暴露

通过反向代理等方式进行端口转发将原本内网的未授权api server暴露到公网

所以利用方式和apiserver未授权类似，这里不再细说

## kubelet未授权

kubelet和kubectl的区别？

kubelet是在Node上用于管理本机Pod的，kubectl是用于管理集群的。kubectl向集群下达指令，Node上的kubelet收到指令后以此来管理本机Pod

每个节点都有一个kubelet服务，kubelet是在每个节点上运行的主要节点代理，监听了10250、10248、10255等端口，负责管理节点上的容器与master节点的通信，而10250端口就是kubelet与API Server进行通信的主要端口

如果kubeconfig文件中的配置不当，则会导致系统存在kubelet未授权访问，在该情况下，攻击者能够列出当前运行的pod，对任意pod执行命令等，实现进一步的利用

> 例如对服务账号绑定了cluster-admin权限的pod执行命令来读取服务账号的token，然后利用高权限token控制apiserver，创建恶意pod并逃逸

通过请求接口执行命令读取token：

~~~sh
curl -XPOST -k "https://${K8S}:10250/run/<namespace>/<pod>/<container>" -d "cmd=cat /var/run/secret/kubernetes.io/serviceaccount/token"
~~~

## etcd未授权

k8s使用etcd存储数据，默认监听2379端口，如果该端口暴露到公网且存在未授权访问，就可能导致信息泄漏，攻击者可以通过收集到的凭证来尝试接管集群，而由于本机可免认证访问2379端口，所以可以结合SSRF来打组合拳

etcd分为v2和v3两个大版本，打法也各不相同：

### etcd v2

Kubernetes ≤ 1.5的版本默认使用etcd v2，打法一般是直接通过网页访问来获取key-value的信息：

~~~
http://127.0.0.1:2379/v2/keys/?recursive=true
~~~

但感觉很少遇到有用的信息：

![QQ_1752764813479](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752764813479.png)

### etcd v3

从k8s v1.6 开始，就默认使用 etcd v3，一般使用etcdctl实现对etcd的访问

比如这里我们尝试读取etcd中存储的相关信息：

~~~
./etcdctl --endpoints=x.x.x.x:2379 get / --prefix --keys-only
~~~

![QQ_1753529396622](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1753529396622.png)

我们也可以通过匹配secrets关键字来寻找token相关信息：

~~~
./etcdctl --endpoints=x.x.x.x:2379 get / --prefix --keys-only | grep /secrets/
~~~

![QQ_1753529300887](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1753529300887.png)

可以看到这里就有很多token信息

比如我们读取bootstrap-token：

![QQ_1752770169058](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752770169058.png)

获得token后，我们可以在APIserver查看当前token权限：

~~~sh
./etcdctl --token=<token> --server=x.x.x.x:6443 --insecure-skip-tls-verify auth can-i --list
~~~

![QQ_1752769661978](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752769661978.png)

可见这里这个bootstrap-token的权限就比较低

## kubeconfig文件泄漏

kubeconfig文件是用于配制集群访问的文件，该文件用来组织有关集群、用户、命名空间和身份认证机制的信息，包括集群的apiserver地址和登录凭证，如果攻击者获取到该文件，就可以使用该凭证访问k8s集群

比如node节点上就存储了kubeconfig文件：
~~~sh
cat /root/.kube/config
# 或
cat /etc/kubernetes/kubelet.conf
~~~

![QQ_1753639624750](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1753639624750.png)

我们可以将config复制到我们自己的vps上，并且把这个config中server的值从本地url改为外网地址：
![QQ_1754241005724](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754241005724.png)

接下来可以通过kubect指定config文件来控制apiserver了：

~~~sh
kubectl --kubeconfig config get pods
~~~

![image-20250804011913966](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250804011913966.png)

## K8s Dashboard 未授权

k8s Dashboard是一个基于web的k8s用户界面，可以对k8s进行可视化管理

正常的k8s面板应该像这样，只允许使用bearer token登录：
![QQ_1754818190889](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754818190889.png)

或者还允许使用kubeconfig文件登录：

![QQ_1754818282686](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754818282686.png)

但如果用户配置错误，会导致可以跳过认证阶段：

![QQ_1754818442435](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754818442435.png)

只需要点击跳过，就能够进入dashboard的管理界面：

![QQ_1754818556792](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754818556792.png)

但我们这样使用的其实是dashboard默认服务账户：

![QQ_1754818889632](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754818889632.png)

该账户在默认情况下也不能达到控制集群的目的，但有些开发者会为了方便，将kubernets-dashboard账号绑定cluster-admin集群管理员角色，就这样就会使其拥有集群最高权限，那么我们就可以通过创建恶意pod来一步步接管集群：

![QQ_1754819546555](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1754819546555.png)

## 总结

可以看出，其实初始访问的入口都是配置不当导致的未授权，这些未授权存在于各个不同的端口，所以我们可以对这些端口多加留意
