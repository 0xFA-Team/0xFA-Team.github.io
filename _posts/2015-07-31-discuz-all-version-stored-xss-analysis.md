---
layout: post
title: "Discuz 全版本存储 XSS 分析"
author: Rickgray
tags: [web, security, xss]
---
* 目录
{:toc}

乌云上有人发了[《Discuz全版本存储型DOM XSS（可打管理员）附Discuz官方开发4大坑&验证脚本》](http://wooyun.org/bugs/wooyun-2010-099979)，借此文顺带练习了一下 JS 调试，下面是整个漏洞的分析。

Discuz在用户评论处设置了帖子管理员编辑评论的功能，由于前端JS代码处理不当导致了经过恶意构造的评论内容在经过交互后形成XSS。下面通过payload的调试过程来解释该漏洞的形成过程。

首先，在评论处提交评论内容：`[email=2"onmouseover="alert(2)]2[/email]`

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/1.png)

由于服务器对引号等有过滤，所以提交后，查看源码会发现引号已经被实体编码了。

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/2.png)

对于普通用户提交的评论，管理员或者版主都有权利对其发表的评论进行管理。

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/3.png)

当管理或版主对用户的评论点击管理时，前端JS代码就开始处理，弹出一个编辑框供管理或版主操作。在JS代码处理的过程中，首先获取用户评论的内容，代码位于当前页面中：

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/4.png)

而 $() 函数原型位于 /static/js/common.js 中：

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/5.png)

使用了原生的 `document.getElementById()` 函数来获取页面中的对应对象，此处获取的是标有`id=”e_textarea”`的对象，其对应的值为用户评论的内容。

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/6.png)

而由于JS原生函数的原因，被服务器后端转义的引号会被重新是渲染回引号：

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/7.png)

获取到`id=”e_textarea”`对象后，代码对浏览器进行了判断，并将结果赋值给变量 `var wysiwyg`。

在页面上另一处JS代码判断了变量`wysiwyg`的值，然后开始渲染编辑框：
	
![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/8.png)

这里使用了Firfox浏览器进行测试，在前面wysiwyg变量的值为1，所以会执行如下代码

	newEditor(1, bbcode2html(textobj.value))
	
其中textobj.value的值为：`[email=2"onmouseover="alert(2)]2[/email]`（经过document.getElementById()获取的对象解析了实体编码）

在进行`newEditor()`时，会对传入的内容使用函数bbcode2html()进行编码过滤，其函数原型位于/static/js/bbcode.js，下面是Discuz对程序所支持的shortcode进行处理的部分代码。

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/9.png)

程序匹配其支持的shortcode然后正则替换为相应的前端格式代码，因此次测试的payload为`[email=2”onmouseover=”alert(2)]2[/email]`，因此图中红色标注的代码会得到执行。

	str = str.replace(/\[email=(.[^\[]*)\](.*?)\[\/email\]/ig, '<a href="mailto:$1" target="_blank">$2</a>');
	
经过正则匹配替换后，str的值会变为：`<a href="mailto:2"onmouseover="alert(2)" target="_blank">2</a>`

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/10.png)

最终bbcode2html()函数会返回经过转换后的textobj.value，值为：`<a href="mailto:2"onmouseover="alert(2)" target="_blank">2</a>`

然后调用newEditor()函数进编辑框的渲染，其函数原型位于/static/js/editor.js

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/11.png)

从函数原型可以看到，代码再次判断浏览器类型然后开始渲染，由于wysiwyq变量的值为1，最终会执行

	writeEditorContents(isUndefined(initialtext) ? textobj.value: initialtext);

而调用newEditor()函数时，传递了initialtext参数，其值就为经过bbcode2html()函数处理后的textobj.value的值。
	
前端JS最终使用writeEditorContents()函数对页面进行渲染，其过程中会将initialtext变量的值直接写入到页面中，最终形成XSS。

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/12.png)

渲染成功后，查看页面源代码：

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/13.png)

当管理员或者版主对其进行交互时就会触发alert(2)。

![]({{ site.url }}/public/img/article/2015-07-31-discuz-all-version-stored-xss-analysis/14.png)

即使后段服务器对输入内容进行了过滤和转义，但是在前段渲染的时候依然有可能形成 XSS。
