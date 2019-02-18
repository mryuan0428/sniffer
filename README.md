 - 开发环境：
```
	本程序在 win7 32 位系统上基于 WinPcap 开发，经测试也可在 win8 64 位和 win10 64
位系统运行。（注：测试前，须确保计算机上已经安装 WinPcap）
	程序是使用Visual C++开发的 MFC 程序，开发/编译环境为 Microsoft Visual Studio 2010。
```

 - 项目内容：
```
    |--source文件夹（源代码）
    	|targetver.h, stdafx.h, stdafx.c, mcf6.h, mcf6.c, Resource.h 文档由VC++项目自动生成。
    	|mcf6Dlg.h, mcf6Dlg.c 文档主要实现 GUI 以及数据包的抓获。
		|Protocol.h 实现各协议头的数据结构及类型定义。
		|utilities.h, utilities.c 实现各协议头分析的功能函数。

    |--bin文件夹
        |--sniffer_wj.exe（打包好的sniffer程序，可直接运行）
        |--SavedData文件夹（自动保存的lix抓包文件）

    |--image文件夹（软件运行界面截图）
    	|--……

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


