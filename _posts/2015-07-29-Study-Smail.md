---
layout: post
title: 简单分析一个smail文件
description: ""
modified: 2015-07-29
category: Android
tags: [Android]
imagefeature: 
comments: true
share: true
author: Croxy
---

#简单分析一个smail文件#

先看前面几行

    .class public Lcom/droider/crackme0201/MainActivity;  //定义类名
    .super Landroid/app/Activity;      //定义父类
    .source "MainActivity.java"        //java源


    # instance fields             //接口信息  实现了按钮 文本信息
    .field private btn_register:Landroid/widget/Button;
    .field private edit_sn:Landroid/widget/EditText;
    .field private edit_userName:Landroid/widget/EditText;

根据开头的几行可以构造出一个java的大体开头

    class MainAcctivity extends Activity {
        private EditText edit_userName;
        private EditText edit_sn;
        private Button btn_register; 

    }


我们可以根据正确 错误的提示

    <public type="string" name="registered" id="0x7f05000a" />
    <public type="string" name="unsuccessed" id="0x7f05000b" />
    <public type="string" name="successed" id="0x7f05000c" />


直接跳到关键的地方

    #getter for: Lcom/droider/crackme0201/MainActivity;->edit_userName:Landroid/widget/EditText;
    invoke-static {v1}, Lcom/droider/crackme0201/MainActivity;->access$0(Lcom/droider/crackme0201/MainActivity;)Landroid/widget/EditText; //调用静态edit_userName方法
    move-result-object v1  //将invoke操作结果付给v1
    invoke-virtual {v1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;//获得用户输入
    move-result-object v1 //将invoke操作结果付给v1
    invoke-interface {v1}, Landroid/text/Editable;->toString()Ljava/lang/String;//输入转回字符串
    move-result-object v1 //将invoke操作结果付给v1
    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String; //去掉空格
    move-result-object v1 //将invoke操作结果付给v1
    //v1 等于我们输入的username
    .line 33
    iget-object v2, p0, Lcom/droider/crackme0201/MainActivity$1;->this$0:Lcom/droider/crackme0201/MainActivity; //iget读取对象字段
    #getter for: Lcom/droider/crackme0201/MainActivity;->edit_sn:Landroid/widget/EditText; //先声明
    invoke-static {v2}, Lcom/droider/crackme0201/MainActivity;->access$1(Lcom/droider/crackme0201/MainActivity;)Landroid/widget/EditText; //调用静态edit_sn方法
    move-result-object v2 //将操作结果付给v2
    invoke-virtual {v2}, Landroid/widget/EditText;->getText()Landroid/text/Editable; //获得用户输入
    move-result-object v2 //将操作结果付给v2
    invoke-interface {v2}, Landroid/text/Editable;->toString()Ljava/lang/String; //将用户输入转回字符串
    move-result-object v2 //将操作结果付给v2
    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String; // 去空格
    move-result-object v2 //获得操作结果
    //v2 等于我们输入的sn
    .line 32
    #calls: Lcom/droider/crackme0201/MainActivity;->checkSN(Ljava/lang/String;Ljava/lang/String;)Z  //声明MainActivity的checkSN方法 结果返回为布尔值
    invoke-static {v0, v1, v2}, Lcom/droider/crackme0201/MainActivity;->access$2(Lcom/droider/crackme0201/MainActivity;Ljava/lang/String;Ljava/lang/String;)Z  //调用v1 v2作为参数带入checkSN 结果返回为布尔值
    move-result v0  //将布尔的结果付给v0
    .line 33
    if-nez v0, :cond_0  //如果v0不等于0 跳到cond_0
    .line 34
    iget-object v0, p0, Lcom/droider/crackme0201/MainActivity$1;->this$0:Lcom/droider/crackme0201/MainActivity; //读取字段
    .line 35
    const v1, 0x7f05000b //Error!
    .line 34
    invoke-static {v0, v1, v3}, Landroid/widget/Toast;->makeText(Landroid/content/Context;II)Landroid/widget/Toast; //调用Toast框
    move-result-object v0 //付给v0
    .line 35
    invoke-virtual {v0}, Landroid/widget/Toast;->show()V //调用v0显示出字符串
     (弹出注册失败)
    .line 42
    :goto_0
    return-void
    .line 37
    :cond_0
    iget-object v0, p0, Lcom/droider/crackme0201/MainActivity$1;->this$0:Lcom/droider/crackme0201/MainActivity;
    .line 38
    const v1, 0x7f05000c     //返回正确

Dalvik VM是基于寄存器的。也就是说，在smali里的所有操作都必须经过寄存器来进行：本地寄存器用v开头数字结尾的符号来表示，如v0、v1、v2、...参数寄存器则使用p开头数字结尾的符号来表示，如p0、p1、p2、...特别注意的是，p0不一定是函数中的第一个参数，在非static函数中，p0代指“this”，p1表示函数的第一个参数，p2代表函数中的第二个参数…而在static函数中p0才对应第一个参数（因为Java的static方法中没有this方法）。

我在想分析一段Dalvik源码 最需要看明白的就是 类 函数（方法） 变量(寄存器)

定义方法都是以
.method指令开始  根据方法类型不同可以有# virtual methods 表示虚方法  # direct methods 表示直接方法  最后以.end method结束  就等于一个函数体
这个small关键的整个判断过程就是 这个点击方法

    # virtual methods
    .method public onClick(Landroid/view/View;)V
        .locals 4
        .parameter "v"
        .prologue
        const/4 v3, 0x0
        
可以看出这个一个公共函数 返回的值是布尔值
.local 表示最少要用到的本地寄存器的个数(变量) (4个寄存器 分别为v0,v1,v2,v3)
.parameter 参数
const/4 v3, 0x0   定义v3的值为0x0

变量就是v0 v1 v2 v3了

破解方法就是改if-nez v0 把v0不等于0随便改一哈就好了～

之后就是无脑跟了 但是要熟记dalvik的smail语法  和关键的地址:)

[Dalvik指令集](http://c-chicken.cc/smail.html)


