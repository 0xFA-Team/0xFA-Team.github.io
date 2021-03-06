---
layout: post
title: "Bit flipping Attack 笔记"
description: "Hacking"
headline: 
modified: 2015-03-16
category: Hacking
tags: [Hacking]
imagefeature: 
mathjax: 
chart: 
author: Ricter
comments: true
featured: true
---

* 目录
{:toc}

##Bit flipping Attack 笔记

Bit-flippting attack 是针对于 CBC加密模式的一类攻击。攻击的意图也很直接：修改某一组密文的某个字节，导致另外一组解密出来的明文发生变化。

### Introduction

首先要理解 CBC（cipher-block chaining）加密模式是如何工作的。贴上高大上的维基百科：[http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

大体流程如下：

1.  首先将明文分组（比如 16 个字节一组），位数不足的时候加以填充；
2.  产生一个随机的初始化向量（叫做 IV）以及一个密钥；

3.  将 IV 和第一组明文进行异或操作（XOR）；
4.  用密钥将第 3 步中 XOR 后的密文进行加密；
5.  取第 4 步中加密后的密文，对第二组明文进行 XOR 操作；
6.  用密钥将第 5 步产生的的密文加密；
7.  重复 4-7，直到最后一组明文；
8.  将 IV 和加密后的密文块按顺序拼接，得到加密的最终结果。

![](http://ricter-blog.qiniudn.com/bit-flipping-attack/1.png)

解密的流程正相反：

1.  将 IV 从密文中取出，然后将密文进行分组；

2.  利用密钥将第一组密文解密，同时用 IV 进行 XOR 操作得到明文；

3.  利用密钥将第二组密文解密，同时用第 1 步中的密文进行 XOR 操作得到明文；

4.  重复 1-4，直到最后一组密文。

![](http://ricter-blog.qiniudn.com/bit-flipping-attack/2.png)

CBC 模式加密的一个主要特点是完全依靠前面的密码文段来译码后面的内容。因此，整个过程的正确性决定于前面的部分。

这里就牵扯到一个问题，当我们更改了 IV 后，我们得到的第一组的明文会发生怎样的变化？ 

### Example

我们首先来举个例子：

我们知道三个值，A、B，令`M = A XOR B`。由于`M = A XOR B`，所以`M XOR A = B`；

若让`X XOR M = C`，则 X 为`X = A XOR B XOR C`。

![](http://ricter-blog.qiniudn.com/bit-flipping-attack/3.png) 

这样，我们带入上述 CBC 模式加密中。我们可以更改初始化向量 IV 中某一个字节 A，导致解密出来的 XOR 异或后的密文中某一个字节 M，再经过和（更改过的）IV 异或操作后（原应该得到的明文的某一个字节 B）改变为 C。 

就是这么简单的样子。下面来具体实践一下：

    from Crypto.Cipher import AES
    from Crypto import Random
    import os

    SECRET_KEY = os.urandom(8).encode('hex').upper()
    IV = Random.new().read(16)
    plaintext = '0123456789ABCDEFRICTERISNOTBAKA!'

    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
    unpad = lambda s : s[0:-ord(s[-1])]
    `

    PS：这里利用了 Python 的 Crypto 库，可以用`pip install Crypto`安装喵。

    我们随机产生了一个密钥和一个初始化变量 IV，然后随便打了一段明文_(:3」∠)_。

    接下来我们对其进行 AES 加密，利用 CBC 加密模式：

    `aes = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    ciphertext = IV + aes.encrypt(pad(plaintext))
    `

    这里我产生的密文为（base64 编码后..不然不能看233）：

    `thcREg6a8a4hPGiz/kgTsr5hei07uot05ab0+ov3iwkj9zPobh9vs/KJZmrIj4XGsrv92mIpaVbh\n6DSuPDltcA==
    `

    然后我们来替换 IV 中某个字节，让我们的明文中第三个字节从 2 变成 R。

    经过上述公式`X = A XOR B XOR C`的计算，我们可以知道，要想让 2 变成 R，我们需要将 IV 中第三个字节从 0x17 变为 0x71。

    `chr(ord(ciphertext[2]) ^ ord(plaintext[2]) ^ ord('R'))
    `

    由于 Python 不能直接更改字符串的某个值，我们只能分割成数组更改完后再拼接：

    `ciphertext = list(ciphertext)
    ciphertext[2] = chr(ord(ciphertext[2]) ^ ord(plaintext[2]) ^ ord('R'))
    ciphertext = ''.join(ciphertext)
    `

    然后我们进行 AES 解密： 

    `IV = ciphertext[:BS]
    ciphertext = ciphertext[BS:]
    aes = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    plaintext = aes.decrypt(ciphertext)
    plaintext = unpad(plaintext)
    `

    这样得到的结果就为：  

    `01R3456789ABCDEFRICTERISNOTBAKA

值得注意的是，**我们更改 IV 的时候不会影响接下来其他密文块的解密，只会影响第一组密文的结果，但是如果我们想更改第二组密文的某个值的结果的时候，就需要改变第一组密文的值，会导致第一组密文的解密结果坏掉**。

我在 Github 上写了一段测试脚本如下，有兴趣可以看一看： 

  

最后，如有错误，欢迎指出。因为没学过密码学，所以很害怕误人子弟就对了.._(:3」∠)_

### References

1.  [http://resources.infosecinstitute.com/cbc-byte-flipping-attack-101-approach/](http://resources.infosecinstitute.com/cbc-byte-flipping-attack-101-approach/)

2.  [http://www.cnblogs.com/happyhippy/archive/2006/12/23/601353.html](http://www.cnblogs.com/happyhippy/archive/2006/12/23/601353.html)
