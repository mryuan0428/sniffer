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

 - 运行流程：

    ![Image text](/image/流程图.png)

 - 主要算法：

     - 获取主机网卡设备：
     ```c++
    //调用 pcap_findalldevs()获得网卡接口信息。
    int Cmcf6Dlg::lixsniff_initCap()
      { devCount = 0;
        if(pcap_findalldevs(&alldev, errbuf) ==-1)
           return -1; 
        for(dev=alldev;dev;dev=dev->next) 
            devCount++;	//记录设备数return 0;
      }
    ```

     - 打开指定网卡
    ```
        调用 pcap_open_live()打开指定网卡接口，winpcap 将在此接口上侦听数据。
        然后调用 pcap_datalink()、pcap_compile()、pcap_setfilter()分别检查是否是以太网，并对过滤器进行设置。
        由于网络中过来的数据包是不同层次、不同协议的，过滤器的作用就是可以设定一些的规则来查看自己想要的数据包。
    ```

     - 创建临时文件存储数据
     ```
        调用 pcap_dump_open()先创建一个文件，捕获的数据将会存储到此文件中，后面捕获的数据包将会实时地写入临时文件。
        文件默认存储在 SaveData 文件中，文件名为存储时的时间，并且在捕获数据结束时，用户可以选择将此文件存储于指定路径。
     ```

    - 捕获、分析数据包
    ```
        因为主进程是一个对话框，它主要的任务是处理界面交互，而数据捕获是一项后台工作，所以调用CreateThread()创建一个新的线程，再调用 lixsinff_CapThread()函数在线程中完成数据包的捕获工作。
        在 lixsinff_CapThread()中调用 pcap_next_ex()函数进行数据包捕获，每到达一个数据包，调用自定义的包处理函数 analyze_frame()函数完成对捕获数据的解析。
    ```

    - 相关数据更新到 GUI

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


