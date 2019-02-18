 - 开发环境：
	本程序在 win7 32 位系统基于 WinPcap 开发，经测试也可在 win8 64 位和 win10 64
位系统运行。（注：测试前，须确保计算机上已经安装 WinPcap）
本程序是使用Visual C++开发的 MFC 程序，开发/编译环境为 Microsoft Visual Studio 2010。

 - 项目内容：
```
    |--WJ_firewall文件夹（应用层：使用Qt开发的用户界面）
    	|--……

    |--build-WJ_firewall-Desktop_Qt_5_9_0_GCC_64bit-Debug文件夹（Qt编译产生的可执行程序，sudo ./WJ_firewall 可运行）
        |--WJ_firewall（可执行程序）
        |--……

    |--my_mod文件夹（内核模块代码：在NF_INET_POST_ROUTING结点挂在钩子函数，接收规则并过滤报文）
    	|--WJ_firewall.c
        |--Makefile（sudo make 编译得到内核模块WJ_firewall.ko，并自动复制到bin文件夹）

    |--bin文件夹
        |--main.sh（在应用层代码中被调用，通过调用其他shell脚本进行内核模块的插入、检查、移除和报文过滤日志的采集）
        |--insmod.sh（内核模块插入）
        |--ckmod.sh（检查内核模块是否插入）
        |--rmmod.sh（内核模块移除）
        |--log.sh（报文过滤日志的采集）
    |--data文件夹
        |--rule.txt（保存正在运行的过滤规则）
        |--log.txt（保存报文过滤日志记录）
        |--rule_new（待导入的过滤规则，格式：SrcIP%DstIP%SPort%DPort%Time_Flag%Start_Hour%Start_Min%Stop_Hour%Stop_Min%Protocol）
        |--rule_out(导出的过滤规则)
    |--image文件夹（软件运行界面截图）
    	|--……
    |--doc文件夹（项目开发文档）
```

 - 说明：
```
 - 防火墙为黑名单模式，符合规则之一报文即被Reject
 - 对于所有被Reject的报文都自动进行日志记录
 - 对于一些新版本内核需要修改内核部分代码，WJ_firewall.c文件中：
    - nf_register_hook(&myhook)函数 需改为 nf_register_net_hook(&init_net,&myhook)
    - nf_unregister_hook(&myhook)函数 需改为 nf_unregister_net_hook(&init_net,&myhook)
 - 使用前需安装Qt5并配置好环境：
    - 修改/usr/lib/x86_64-linux-gnu/qt-default/qtchooser/default.conf文件为新安装Qt路径
    - 使用Qt前还需安装libGL库：sudo apt-get install libgl1-mesa-dev
```

 - 运行界面：
 	 - 主界面

 	![Image text](/image/MainWindow.png)
 	 - 添加规则

 	![Image text](/image/AddRule.png)
 	 - 修改规则

 	![Image text](/image/ModifyRule.png)
 	 - 删除规则

 	![Image text](/image/DeleteRule.png)
 	 - 导入规则

 	![Image text](/image/ImportRule.png)
 	 - 导出规则

 	![Image text](/image/ExportRule.png)
 	 - 过滤日志记录

 	![Image text](/image/Log.png)
 	 - 关于

 	![Image text](/image/About.png)


