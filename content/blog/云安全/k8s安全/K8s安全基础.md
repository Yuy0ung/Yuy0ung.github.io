---
title: "K8s安全基础"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Kubernetes安全基础

文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

## k8s基础

### k8s架构

Kubernetes 又称 k8s，是 Google 在 2014 年开源的一个用来管理容器的平台

k8s基本架构如下：
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

## K8s相关风险

基本面临5种风险：

### 容器基础设施相关风险

这个和docker的容器风险类似，这里就不详细记录了

### 组件接口相关风险

#### API Server

API Sevrer默认服务端口为8080和6443，8080端口提供了http服务，没有认证与授权机制，而6443提供http服务支持认证和授权服务

默认情况8080端口不会启动，但如果用户开启了该服务就会造成API Server的未授权访问，从而控制整个集群

#### Kubelet

Kubelet也运行API服务，默认服务端口为10250和10248

kubelet也存在未授权，若存在未授权访问，就可以控制所在的节点权限

#### Dashboard

Dashboard默认端口8001，从 1.10.1 版本起，Dashboard 默认禁用了跳过按钮，但如果用户为了方便或者其他原因，开启了相关功能，就会导致 Dashboard 的未授权访问

#### etcd

etcd默认监听两个端口：

* 2379：用于客户端连接
* 2380：用于多个etcd实例之间的通信

默认情况下，etcd 提供的两个端口都需要相应的证书才能访问，但如果攻击者窃取了证书或者用户将etcd设置了允许匿名访问，那么可以直接访问etcd并窃取相关数据

k8s集群内部的各种资源及其状态都存在etcd中，如果可以读取etcd的数据，就可能获取高权限，进而控制集群

### 集群网络相关风险

Pod是由一个或多个容器构成的集合，在没有其他网络隔离策略和和pod安全策略的默认情况下，不同pod之间可以联通，且Pod内的root用户具有CAP_NET_RAW权限（即允许使用原始套接字的权限，允许程序绕过常规的 TCP/UDP 协议栈，直接构造和发送自定义的 IP 包进行集群内网探测），因此集群内可能发生内网横向的风险

### 访问机制相关风险

Kubernetes 中的访问控制机制主要由三个部分组成：

* 认证机制
* 授权机制
* 准入机制

如果访问控制比较宽松或混乱或者允许 Kubernetes 的未授权访问，攻击人员可能借此直接获得集群管理员权限

一些Kubernetes 监控部署平台存在 "可能的验证缺失" 和 "对公网/外网开放" 的错误配置可能, 可以导致严重的集群接管的问题，并且利用这类平台即可实现k8s的权限维持

### K8s自身漏洞

自身的一些漏洞也是k8s相关风险

### k8s攻防矩阵

我接下来的笔记会按照下面这个攻防矩阵的每一步来进行

|      **初始访问**       | **权限提升**            | **防御绕过**             | **凭证窃取**                     | **权限维持**         |
| :---------------------: | ----------------------- | ------------------------ | -------------------------------- | -------------------- |
|      版本信息探测       | 特权容器逃逸            | 容器及宿主机日志清理     | Kubernetes secret窃取            | 后门Pod              |
| insecure-port未授权访问 | rolebinding添加用户权限 | Kubernetes audit日志清理 | Kubernetes ServiceAccount泄露    | Shadow-apiserver     |
|   Api-server匿名访问    | 目录挂载逃逸            | 利用系统Pod伪装          | 应用层Api凭据泄露                | cronjob持久化        |
|     Kubeconfig泄露      | 操作系统内核漏洞逃逸    | 通过代理访问Api-server   | 利用Kubernetes准入控制器获取信息 | 后门镜像             |
|    Kubelet未授权访问    | Docker漏洞逃逸          | 关闭安全产品平台容器     | Pod服务账户凭据窃取              | 修改核心组件访问权限 |
| Docker daemon未授权访问 | Kubernetes漏洞提权      | 创建超长Annotations      |                                  | 系统层后门           |
| 通过Nodeport访问Service | Docker.sock逃逸         | CVE-2019-1002101         |                                  | DaemonSets后门       |
|   Dashboard未授权访问   | Linux Capabilities逃逸  |                          |                                  |                      |
|     etcd未授权访问      | CVE-2018-1002105        |                          |                                  |                      |

来源：https://www.netstarsec.com/amulab/
