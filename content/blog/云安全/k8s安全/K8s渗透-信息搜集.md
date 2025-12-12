---
title: "K8s渗透-信息搜集"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# K8s渗透-信息搜集

>  文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

这一步发生在内网信息搜集的过程中，内网一般不会完全基于容器技术构建，所以内网搜集的起点一般可以分为权限受限的主机和物理主机内网

k8s内部集群网络主要依靠网络插件，目前使用比较多的是Flannel和Calico

而通信类型存在4种：

* 同一pod内的容器间通信
* 不同pod间的通信
* pod与service间的通信
* 集群外部的流量与service间的通信

## shell环境辨别

如果我们的起点是一个在k8s集群内部权限受限的容器，那么内网探测的过程依然遵循常规内网探测，可以先在搜集的时候判断当前是否是云环境，可以参考我的笔记：[快速识别虚拟主机、Docker和K8s集群环境](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/%E8%AF%86%E5%88%AB%E8%99%9A%E6%8B%9F%E4%B8%BB%E6%9C%BAdocker%E5%92%8Ck8s%E9%9B%86%E7%BE%A4%E7%8E%AF%E5%A2%83/)

一些常用命令：
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

## 特权相关搜集

另外`capsh --print`获取到信息也较为重要，可以打印出当前容器里已有的 Capabilities 权限：
![QQ_1751874769526](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751874769526.png)

那如果没有capsh命令且无法安装怎么办呢？

* 首先`cat /proc/1/status` 获取到 Capabilities hex 记录:

  ![QQ_1751875341210](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751875341210.png)

* 然后在我们自己安装了capsh的主机上进行decode：

  ![QQ_1751875475273](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1751875475273.png)

如此即可达到代替`capsh --print`的效果

## APIServer相关

有时候虽然获得了可以访问 APIServer 的网络权限和证书（又或者不需要证书）拥有了控制集群资源的权限，却无法下载或安装一个 kubectl 程序便捷的和 APIServer 通信，此时我们可以配置 kubectl 的 logging 登记，记录本地 kubectl 和测试 APIServer 的请求详情，并将相同的请求包发送给目标的 APIServer 以实现相同的效果

~~~sh
kubectl create -f cronjob.yaml -v=8
~~~

如果需要更详细的信息，也可以提高 logging level, 例如 kubectl -v=10 等，其他 Kubernetes 组件也能达到相同的目的

## 端口相关搜集

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



