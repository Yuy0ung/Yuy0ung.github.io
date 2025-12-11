---
title: "力扣leetcode刷题记录"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 力扣leetcode刷题记录

在一个上班摸鱼的下午，抱着练练算法和go语言基础的想法打开了力扣，并且决定坚持每天一题，于是有了这篇笔记

## 1.两数之和

> 给定一个整数数组 `nums` 和一个整数目标值 `target`，请你在该数组中找出 **和为目标值** *`target`* 的那 **两个** 整数，并返回它们的数组下标。
>
> 你可以假设每种输入只会对应一个答案，并且你不能使用两次相同的元素。
>
> 你可以按任意顺序返回答案。
>
> **示例 1：**
>
> ```
> 输入：nums = [2,7,11,15], target = 9
> 输出：[0,1]
> 解释：因为 nums[0] + nums[1] == 9 ，返回 [0, 1] 。
> ```
>
> **示例 2：**
>
> ```
> 输入：nums = [3,2,4], target = 6
> 输出：[1,2]
> ```
>
> **示例 3：**
>
> ```
> 输入：nums = [3,3], target = 6
> 输出：[0,1]
> ```

### 方法一：哈希表

开局第一题，啥都不会，问了kimi老师，知道了哈希表这个东西，那么思路清晰：

依次访问数组的元素并和目标数计算差值，然后查看哈希表中是否有这个差值，没有就将当前元素推入哈希表，然后判断下一个...

代码实现：

~~~go
func twoSum(nums []int, target int) []int {
    numMap := make(map[int]int)
    for i, num := range nums {
        cha := target - num 
        if j, ok := numMap[cha]; ok {
            return []int{j, i}
        }
        numMap[num] = i
    }
    return []int{}
}
~~~

时间复杂度o(n)，空间复杂度o(1)

## 9.回文数

>给你一个整数 `x` ，如果 `x` 是一个回文整数，返回 `true` ；否则，返回 `false` 。
>
>回文数是指正序（从左向右）和倒序（从右向左）读都是一样的整数。
>
>- 例如，`121` 是回文，而 `123` 不是。
>
>**示例 1：**
>
>```
>输入：x = 121
>输出：true
>```
>
>**示例 2：**
>
>```
>输入：x = -121
>输出：false
>解释：从左向右读, 为 -121 。 从右向左读, 为 121- 。因此它不是一个回文数。
>```
>
>**示例 3：**
>
>```
>输入：x = 10
>输出：false
>解释：从右向左读, 为 01 。因此它不是一个回文数。
>```

### 方法一：转字符串+双指针

这里首先想到的是转换为字符串再继续，那么双指针法是一个很好的选择，从两头到中间来判断，省去了反转字符串的环节，并且双指针的效率也更高，另外可以将特殊情况直接判断，比如负数、0、10的倍数，缺点是需要引入strconv，代码实现：

~~~go
import "strconv"
func isPalindrome(x int) bool {
    if x < 0 {
        return false
    }
    s := strconv.Itoa(x)
    left, right := 0, len(s)-1
    for left < right {
        if s[left] != s[right] {
            return false
        }
        left ++
        right --
    }
    return true
}
~~~

时间复杂度o(n)，空间复杂度o(1)

### 方法二：反转数字

不转换成字符串的条件下反转数字然后判断是否相等，很明显这种方法的时间复杂度更高，但可以拿来练练手：

~~~go
func isPalindrome(x int) bool {
    if x < 0 && x%10 == 0 {
        return false
    }
    if x == 0 {
        return true
    }
    renum := 0
    tmp := x
    for x > 0 {
        renum = renum*10 + x%10
        x /= 10
    }
    if renum == tmp {
        return true
    }
    return false
}
~~~

时间复杂度O(Log10(N))，空间复杂度o(1)

## 13.罗马数字转整数

> 罗马数字包含以下七种字符: `I`， `V`， `X`， `L`，`C`，`D` 和 `M`。
>
> ```
> 字符          数值
> I             1
> V             5
> X             10
> L             50
> C             100
> D             500
> M             1000
> ```
>
> 例如， 罗马数字 `2` 写做 `II` ，即为两个并列的 1 。`12` 写做 `XII` ，即为 `X` + `II` 。 `27` 写做 `XXVII`, 即为 `XX` + `V` + `II` 。
>
> 通常情况下，罗马数字中小的数字在大的数字的右边。但也存在特例，例如 4 不写做 `IIII`，而是 `IV`。数字 1 在数字 5 的左边，所表示的数等于大数 5 减小数 1 得到的数值 4 。同样地，数字 9 表示为 `IX`。这个特殊的规则只适用于以下六种情况：
>
> - `I` 可以放在 `V` (5) 和 `X` (10) 的左边，来表示 4 和 9。
> - `X` 可以放在 `L` (50) 和 `C` (100) 的左边，来表示 40 和 90。 
> - `C` 可以放在 `D` (500) 和 `M` (1000) 的左边，来表示 400 和 900。
>
> 给定一个罗马数字，将其转换成整数。

### 方法一：哈希表+正负判断

这里参考了0x3f师傅的思路，我们通过观察可以得出当左边的数小于右边则需要右减左，即相当于左边数字为负，右边数字为正，那么我们可以按照这个逻辑判断出每个罗马字符对应数字的正负，最后求和即可：

~~~go
func romanToInt(s string) int {
    rom := map[byte]int{
        'I':1,
        'V':5,
        'X':10,
        'L':50,
        'C':100,
        'D':500,
        'M':1000,
    }
    re := 0
    n := len(s)
    for i := 0; i+1 < n; i++ {
        if rom[s[i]] < rom[s[i+1]] {
            re -= rom[s[i]]
        } else {
            re += rom[s[i]]
        }
    }
    return re + rom[s[n-1]]
}
~~~

时间复杂度O(n)，空间复杂度O(1)

## 27.移除元素

> 给你一个数组 `nums` 和一个值 `val`，你需要原地移除所有数值等于 `val` 的元素。元素的顺序可能发生改变。然后返回 `nums` 中与 `val` 不同的元素的数量。
>
> 假设 `nums` 中不等于 `val` 的元素数量为 `k`，要通过此题，您需要执行以下操作：
>
> - 更改 `nums` 数组，使 `nums` 的前 `k` 个元素包含不等于 `val` 的元素。`nums` 的其余元素和 `nums` 的大小并不重要。
> - 返回 `k`。
>
> **用户评测：**
>
> 评测机将使用以下代码测试您的解决方案：
>
> ```
> int[] nums = [...]; // 输入数组
> int val = ...; // 要移除的值
> int[] expectedNums = [...]; // 长度正确的预期答案。
>                             // 它以不等于 val 的值排序。
> 
> int k = removeElement(nums, val); // 调用你的实现
> 
> assert k == expectedNums.length;
> sort(nums, 0, k); // 排序 nums 的前 k 个元素
> for (int i = 0; i < actualLength; i++) {
>     assert nums[i] == expectedNums[i];
> }
> ```
>
> 如果所有的断言都通过，你的解决方案将会 **通过**。
>
> **示例 1：**
>
> ```
> 输入：nums = [3,2,2,3], val = 3
> 输出：2, nums = [2,2,_,_]
> 解释：你的函数函数应该返回 k = 2, 并且 nums 中的前两个元素均为 2。
> 你在返回的 k 个元素之外留下了什么并不重要（因此它们并不计入评测）。
> ```
>
> **示例 2：**
>
> ```
> 输入：nums = [0,1,2,2,3,0,4,2], val = 2
> 输出：5, nums = [0,1,4,0,3,_,_,_]
> 解释：你的函数应该返回 k = 5，并且 nums 中的前五个元素为 0,0,1,3,4。
> 注意这五个元素可以任意顺序返回。
> 你在返回的 k 个元素之外留下了什么并不重要（因此它们并不计入评测）。
> ```

虽然因为找工作原因，很久没做题了，但一看到这题就能想到快慢指针：
~~~go
func removeElement(nums []int, val int) int {
    n1,n2 := 0,0
    for ;n1<len(nums);n1++ {
        if nums[n1]!=val {
            nums[n2] = nums[n1]
            n2++
        }
    }
    return n2
}
~~~

时间复杂度O(n)，空间复杂度O(1)

## 28.找出字符串中第一个匹配项的下标

>给你两个字符串 `haystack` 和 `needle` ，请你在 `haystack` 字符串中找出 `needle` 字符串的第一个匹配项的下标（下标从 0 开始）。如果 `needle` 不是 `haystack` 的一部分，则返回 `-1` 。 
>
>**示例 1：**
>
>```
>输入：haystack = "sadbutsad", needle = "sad"
>输出：0
>解释："sad" 在下标 0 和 6 处匹配。
>第一个匹配项的下标是 0 ，所以返回 0 。
>```
>
>**示例 2：**
>
>```
>输入：haystack = "leetcode", needle = "leeto"
>输出：-1
>解释："leeto" 没有在 "leetcode" 中出现，所以返回 -1 。
>```
>
>**提示：**
>
>- `1 <= haystack.length, needle.length <= 104`
>- `haystack` 和 `needle` 仅由小写英文字符组成

### 方法一：官方库

不讲码德的方法，直接使用官方的strings.Index(haystack, needle)，一句话解决：

~~~go
import "strings"
func strStr(haystack string, needle string) int {
    return strings.Index(haystack, needle)
}
~~~

时间复杂度O(n)，空间复杂度O(1)

### 方法二：暴力匹配

很基础的方法，遍历字符串，并逐个对比是否一致，值得注意的是，当起始位置到字符串结尾长度小于needle长度，则不可能存在，若needle是空字符串，则一定存在（另外注意循环边界）：

~~~go
func strStr(haystack string, needle string) int {
    lenh := len(haystack)
    lenn := len(needle)
    if lenn == 0 {
        return 0
    }
    if lenn > lenh {
        return -1
    }
    for i := 0; i <= lenh - lenn ; i++ {
        for j := 0;j < lenn; j++ {
            if haystack[i+j] != needle[j] {
                break
            }
            if j == lenn - 1 {
                return i
            }
        }
    }
    return -1
}
~~~

时间复杂度O(lenh∗lenn)，空间复杂度O(1)

### 方法三：KMP

这个是看官方题解学到的，coding思路一眼看过去已经晕了，这是我目前遇到最难的一个思路了：

>KMP 算法是一个快速查找匹配串的算法，它的作用其实就是本题问题：**如何快速在「原字符串」中找到「匹配字符串」**，放个链接https://www.zhihu.com/question/21923021/answer/281346746

~~~go
func strStr(haystack string, needle string) int {
    lenh, lenn := len(haystack), len(needle)
    if lenn == 0 {
        return 0
    }
    next := make([]int, lenn)
    next[0] = -1
    for i, j:= 0, -1; i < lenn - 1; {
        if j == -1 || needle[i] == needle[j] {
            i++
            j++
            next[i] = j 
        } else {
            j = next[j]
        }
    }
    for i, j := 0,0; i<lenh && j<lenn; {
        if j == -1 || haystack[i] == needle[j] {
            i++
            j++
        } else {
            j = next[j]
        }
        if j == lenn {
            return i - j
        }
    }
    return -1
}
~~~

时间复杂度O(lenh+lenn)，空间复杂度O(lenn)

## 58.最后一个单词的长度

> 给你一个字符串 `s`，由若干单词组成，单词前后用一些空格字符隔开。返回字符串中 **最后一个** 单词的长度。
>
> **单词** 是指仅由字母组成、不包含任何空格字符的最大。
>
> **示例 1：**
>
> ```
> 输入：s = "Hello World"
> 输出：5
> 解释：最后一个单词是“World”，长度为 5。
> ```
>
> **示例 2：**
>
> ```
> 输入：s = "   fly me   to   the moon  "
> 输出：4
> 解释：最后一个单词是“moon”，长度为 4。
> ```
>
> **示例 3：**
>
> ```
> 输入：s = "luffy is still joyboy"
> 输出：6
> 解释：最后一个单词是长度为 6 的“joyboy”。
> ```

### 方法一：反向遍历

可以从字符串最后一个字节开始判断，先遍历到不为空的字节，再开始遍历到为空的字节，中间的字节数就是长度：

~~~go
func lengthOfLastWord(s string) int {
    n, m := len(s) - 1, 0
    for s[n] == ' ' {
        n--
    }
    for n >= 0 && s[n] != ' ' {
        n--
        m++
    }
    return m
}
~~~

时间复杂度O(n)，空间复杂度O(1)

## 66.加一

> 给定一个表示 **大整数** 的整数数组 `digits`，其中 `digits[i]` 是整数的第 `i` 位数字。这些数字按从左到右，从最高位到最低位排列。这个大整数不包含任何前导 `0`。
>
> 将大整数加 1，并返回结果的数字数组。
>
> **示例 1：**
>
> ```
> 输入：digits = [1,2,3]
> 输出：[1,2,4]
> 解释：输入数组表示数字 123。
> 加 1 后得到 123 + 1 = 124。
> 因此，结果应该是 [1,2,4]。
> ```
>
> **示例 2：**
>
> ```
> 输入：digits = [4,3,2,1]
> 输出：[4,3,2,2]
> 解释：输入数组表示数字 4321。
> 加 1 后得到 4321 + 1 = 4322。
> 因此，结果应该是 [4,3,2,2]。
> ```
>
> **示例 3：**
>
> ```
> 输入：digits = [9]
> 输出：[1,0]
> 解释：输入数组表示数字 9。
> 加 1 得到了 9 + 1 = 10。
> 因此，结果应该是 [1,0]。
> ```

### 方法一：遍历+判断

重点在于考虑进位问题，那么可以设计一套逻辑：从最后一位向前判断是否为9，不为9就直接加一然后return结果，为9就继续判断下一位，如果均为9，则make一个第0位为1，其他为0的的新数组即可：

~~~go
func plusOne(digits []int) []int {
    n := len(digits)
    for i := n-1; i >= 0; i-- {
        if digits[i] != 9{
            digits[i]++
            return digits
        }
        digits[i] = 0
    }
    digits = make([]int, n+1)
    digits[0] = 1
    return digits
}
~~~

## 283.移动零

>给定一个数组 `nums`，编写一个函数将所有 `0` 移动到数组的末尾，同时保持非零元素的相对顺序。
>
>**请注意** ，必须在不复制数组的情况下原地对数组进行操作。
>
>**示例 1:**
>
>```
>输入: nums = [0,1,0,3,12]
>输出: [1,3,12,0,0]
>```
>
>**示例 2:**
>
>```
>输入: nums = [0]
>输出: [0]
>```

### 方法一：快慢指针

双指针法，使用快慢指针，均从左边出发，快指针遍历元素，如果非零，元素与慢指针位置交换，慢指针右移，为0则跳过继续遍历：

~~~go
func moveZeroes(nums []int)  {
    fast, slow, n:= 0, 0, len(nums)
    for ;fast < n;fast++ {
        if nums[fast] != 0 {
            nums[slow], nums[fast] = nums[fast], nums[slow]
            slow++
        }
    }
}
~~~

时间复杂度O(n)，空间复杂度O(1)

## 242.有效字母异位词

>给定两个字符串 `s` 和 `t` ，编写一个函数来判断 `t` 是否是 `s` 的  
>
>**示例 1:**
>
>```
>输入: s = "anagram", t = "nagaram"
>输出: true
>```
>
>**示例 2:**
>
>```
>输入: s = "rat", t = "car"
>输出: false
>```

### 方法一：哈希表

首先想到的是哈希表：

~~~go
func isAnagram(s string, t string) bool {
    count := make(map[byte]int)
    if  len(s)!=len(t) {
        return false
    }
    for i:= 0; i < len(s); i++ {
        count[s[i]]++
    }
    for j:= 0; j < len(t); j++ {
        if count[t[j]]==0 {
            return false
        }
        count[t[j]]--
    }
    return true
}
~~~

## 389.找不同

>给定两个字符串 `s` 和 `t` ，它们只包含小写字母。
>
>字符串 `t` 由字符串 `s` 随机重排，然后在随机位置添加一个字母。
>
>请找出在 `t` 中被添加的字母。
>
>**示例 1：**
>
>```
>输入：s = "abcd", t = "abcde"
>输出："e"
>解释：'e' 是那个被添加的字母。
>```
>
>**示例 2：**
>
>```
>输入：s = "", t = "y"
>输出："y"
>```

### 方法一：哈希表

这里第一个想到的是使用哈希表，遍历s存储每个字母出现次数，再便利t查询字母出现次数，只要存在则次数减一，为0则为被添加的字母：

~~~go
func findTheDifference(s string, t string) byte {
	charCount := make(map[byte]int)
    for i := 0; i < len(s); i++ {
        charCount[s[i]]++
    }
    for j := 0; j < len(t); j++ {
        if charCount[t[j]] == 0 {
            return t[j]
        }
        charCount[t[j]]--
    }
    return 0
}
~~~

时间复杂度O(n)，空间复杂度O(1)

### 方法二：ascii码计算

这个方法是问AI问出来的，也是第一次看见这个解法，惊为天人好吧，我怎么就没想到（其实因为题目说全小写，没考虑这个了，这个方法连分大小写的情况也能秒），直接转ascii求和，然后计算前后差值即可：

~~~go
func findTheDifference(s string, t string) byte {
    ascii1, ascii2 := 0,0
    for i:= 0; i < len(s); i++ {
        ascii1 += int(s[i])
    }
    for j:= 0; j < len(t); j++ {
        ascii2 += int(t[j])
    }
    res := ascii2 - ascii1
    return byte(res)
}
~~~

时间复杂度O(n)，空间复杂度O(1)

## 459.重复的子字符串

> 给定一个非空的字符串 `s` ，检查是否可以通过由它的一个子串重复多次构成。
>
> **示例 1:**
>
> ```
> 输入: s = "abab"
> 输出: true
> 解释: 可由子串 "ab" 重复两次构成。
> ```
>
> **示例 2:**
>
> ```
> 输入: s = "aba"
> 输出: false
> ```
>
> **示例 3:**
>
> ```
> 输入: s = "abcabcabcabc"
> 输出: true
> 解释: 可由子串 "abc" 重复四次构成。 (或子串 "abcabc" 重复两次构成。)
> ```

我一开始想到的是KMP但是很难想，然后AI给出了一个很不错的思路，把字符串重复两次拼接，然后去掉首尾字节，再在这个字符串中寻找是否有原字符串·，若存在则可以重复构成，那么代码实现很简单，一个Contains和一个切片就能搞定：

~~~go
func repeatedSubstringPattern(s string) bool {
    return strings.Contains((s+s)[1:len(s+s)-1], s)
}
~~~

时间复杂度O(n)，空间复杂度O(n)

## 709.转换成小写字母

> 给你一个字符串 `s` ，将该字符串中的大写字母转换成相同的小写字母，返回新的字符串。
>
> **示例 1：**
>
> ```
> 输入：s = "Hello"
> 输出："hello"
> ```
>
> **示例 2：**
>
> ```
> 输入：s = "here"
> 输出："here"
> ```
>
> **示例 3：**
>
> ```
> 输入：s = "LOVELY"
> 输出："lovely"
> ```

### 方法一：内置方法

直接用golang的内置函数即可

~~~go
func toLowerCase(s string) string {
    return strings.ToLower(s)
}
~~~

时间复杂度O(n)，空间复杂度O(n)

### 方法二：ASCII码

首先知道：

- 大写字母 A - Z 的 ASCII 码范围为 [65,90]
- 小写字母 a - z 的 ASCII 码范围为 [97,122]

所以大写字母的ascii码加32即为小写字母

~~~go
func toLowerCase(s string) string {
    runes := []rune(s)
    for i ,ch := range runes {
        if ch <='Z' && ch >= 'A' {
            runes[i] += 32
        }
    }
    return string(runes)
}
~~~

时间复杂度O(n)，空间复杂度O(n)

## 896.单调数列

> 如果数组是单调递增或单调递减的，那么它是 **单调** *的*。
>
> 如果对于所有 `i <= j`，`nums[i] <= nums[j]`，那么数组 `nums` 是单调递增的。 如果对于所有 `i <= j`，`nums[i] >= nums[j]`，那么数组 `nums` 是单调递减的。
>
> 当给定的数组 `nums` 是单调数组时返回 `true`，否则返回 `false`。
>
> **示例 1：**
>
> ```
> 输入：nums = [1,2,2,3]
> 输出：true
> ```
>
> **示例 2：**
>
> ```
> 输入：nums = [6,5,4,4]
> 输出：true
> ```
>
> **示例 3：**
>
> ```
> 输入：nums = [1,3,2]
> 输出：false
> ```

### 方法一：常规遍历

按照题目描述的方法来遍历判断即可：

~~~go
func isMonotonic(nums []int) bool {
    n := len(nums)
    if n < 3{
        return true
    }
    i := 0
    if nums[i] <= nums[n-1] {
        for ; i+1 < n;i++ {
            if nums[i] > nums[j] {
                return false
            }
        } 
    }
    if nums[i] > nums[n-1] {
        for ; i+1 < n;i++{
            if nums[i] < nums[j] {
                return false
            }
        } 
    }
    return true
}
~~~

时间复杂度O(n)，空间复杂度O(1)

## 1502.判断能否形成等差数列

> 给你一个数字数组 `arr` 。
>
> 如果一个数列中，任意相邻两项的差总等于同一个常数，那么这个数列就称为 **等差数列** 。
>
> 如果可以重新排列数组形成等差数列，请返回 `true` ；否则，返回 `false` 。
>
> **示例 1：**
>
> ```
> 输入：arr = [3,5,1]
> 输出：true
> 解释：对数组重新排序得到 [1,3,5] 或者 [5,3,1] ，任意相邻两项的差分别为 2 或 -2 ，可以形成等差数列。
> ```
>
> **示例 2：**
>
> ```
> 输入：arr = [1,2,4]
> 输出：false
> 解释：无法通过重新排序得到等差数列。
> ```

### 方法一：排序+差值判断

最简单的方法就是排序后用差来判断，另外当数组长度小于2时一定不为等差：

~~~go
func canMakeArithmeticProgression(arr []int) bool {
    if len(arr)<2{
        return false
    }
    sort.Ints(arr)
    complement := arr[1] - arr[0]
    for i := 1; i<len(arr)-1; i++ {
        if arr[i] + complement != arr[i+1] {
            return false
        }
    }
    return true
}
~~~

时间复杂度 O(nlog n)，空间复杂度 O(1)

### 方法二：算差值+哈希表

如果还想要更快，这个方法是个很好的思路，首先遍历得到极值和存储出现次数的哈希表，然后通过计算公差，不为整数就false，接下来通过最小值和公差来算元素并进入哈希表查询，查询不到则false（缺点是空间复杂度高）：

~~~go
func canMakeArithmeticProgression(arr []int) bool {
    n := len(arr)
    if n < 2 {
        return false
    }
    max, min := arr[0], arr[0]
    nums := make(map[int]int)
    for i:=0; i < n; i++ {
        if arr[i] > max {
            max = arr[i]
        }
        if arr[i] < min {
            min = arr[i]
        }
        nums[arr[i]]++
    }
    if (max - min)%(n-1) != 0 {
        return false
    }
    step := (max - min)/(n-1)
    for i:=0; i < n-1; i++{
        if nums[min] == 0 {
            return false
        }
        nums[min]--
        min += step
    }
    return true
}
~~~

时间复杂度O(n)，空间复杂度O(n)

## 1768.交替合并字符串

>给你两个字符串 `word1` 和 `word2` 。请你从 `word1` 开始，通过交替添加字母来合并字符串。如果一个字符串比另一个字符串长，就将多出来的字母追加到合并后字符串的末尾。
>
>返回 **合并后的字符串** 。
>
>**示例 1：**
>
>```
>输入：word1 = "abc", word2 = "pqr"
>输出："apbqcr"
>解释：字符串合并情况如下所示：
>word1：  a   b   c
>word2：    p   q   r
>合并后：  a p b q c r
>```
>
>**示例 2：**
>
>```
>输入：word1 = "ab", word2 = "pqrs"
>输出："apbqrs"
>解释：注意，word2 比 word1 长，"rs" 需要追加到合并后字符串的末尾。
>word1：  a   b 
>word2：    p   q   r   s
>合并后：  a p b q   r   s
>```
>
>**示例 3：**
>
>```
>输入：word1 = "abcd", word2 = "pq"
>输出："apbqcd"
>解释：注意，word1 比 word2 长，"cd" 需要追加到合并后字符串的末尾。
>word1：  a   b   c   d
>word2：    p   q 
>合并后：  a p b q c   d
>```

### 方法一：for循环

相当简单的一个题目了，首先想到的就是循环，然后用指针指定字符串的每个byte进行拼接，然后判断条件为指针不超过字符串长度：

~~~go
func mergeAlternately(word1 string, word2 string) string {
   s := 0
   res := ""
   for s < len(word1) || s < len(word2) {
    if s < len(word1) {
        res += string(word1[s])
    }
    if s < len(word2) {
        res += string(word2[s])
    }
    s++
   }
   return res
}
~~~

时间复杂度O(n)，空间复杂度O(len(word1) + len(word2))

## 1822.数组元素积的符号

> 已知函数 `signFunc(x)` 将会根据 `x` 的正负返回特定值：
>
> - 如果 `x` 是正数，返回 `1` 。
> - 如果 `x` 是负数，返回 `-1` 。
> - 如果 `x` 是等于 `0` ，返回 `0` 。
>
> 给你一个整数数组 `nums` 。令 `product` 为数组 `nums` 中所有元素值的乘积。
>
> 返回 `signFunc(product)` 。
>
>  
>
> **示例 1：**
>
> ```
> 输入：nums = [-1,-2,-3,-4,3,2,1]
> 输出：1
> 解释：数组中所有值的乘积是 144 ，且 signFunc(144) = 1
> ```
>
> **示例 2：**
>
> ```
> 输入：nums = [1,5,0,2,-3]
> 输出：0
> 解释：数组中所有值的乘积是 0 ，且 signFunc(0) = 0
> ```
>
> **示例 3：**
>
> ```
> 输入：nums = [-1,1,-1,1,-1]
> 输出：-1
> 解释：数组中所有值的乘积是 -1 ，且 signFunc(-1) = -1
> ```

也是一个很基础的逻辑判断：数组中有0就返回0，然后看负数的数量，为奇数则返回-1，否则返回1:

~~~go
func arraySign(nums []int) int {
    count := 0
    for i:= 0; i < len(nums); i++ {
        if nums[i] == 0 {
            return 0
        }
        if nums[i] < 0 {
            count++
        }
    }
    if count%2 == 0 {
        return 1
    }
    return -1
}
~~~

时间复杂度O(n)，空间复杂度O(1)



