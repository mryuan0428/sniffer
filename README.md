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

     - 获取主机网卡设备
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
    因为主进程是一个对话框，它主要的任务是处理界面交互，而数据捕获是一项后台工作，
    所以调用CreateThread()创建一个新的线程，再调用 lixsinff_CapThread()函数在线程中完成数据包的捕获工作。
    在 lixsinff_CapThread()中调用 pcap_next_ex()函数进行数据包捕获，每到达一个数据包，
    调用自定义的包处理函数 analyze_frame()函数完成对捕获数据的解析。
    ```

    - 相关数据更新到 GUI

 - 主要数据结构：

     - MAC 帧头信息
     ```c++
    //Mac 帧头
    typedef struct ethhdr
    { u_char dest[6];    //6 个字节 目标地址
      u_char src[6];    //6 个字节 源地址
      u_short type;     //2 个字节 类型
    };
     ```

     - ARP头信息
    ```c++
    //ARP 头
    typedef struct arphdr
    { u_short ar_hrd;	//硬件类型
      u_short ar_pro;	//协议类型
      u_char ar_hln;	//硬件地址长度
      u_char ar_pln;	//协议地址长度
      u_short ar_op;	//操作码，1 为请求 2 为回复
      u_char ar_srcmac[6];	//发送方 MAC 
      u_char ar_srcip[4];	//发送方 IP 
      u_char ar_destmac[6];	//接收方 MAC  
      u_char ar_destip[4];	//接收方 IP
    };
    ```
    
     - IP 头信息
    ```c++
    //定义 IP 头
    typedef struct iphdr
    { #if defined(LITTLE_ENDIAN) 
    	  u_char ihl:4;
          u_char version:4;
      #elif defined(BIG_ENDIAN) 
          u_char version:4;
          u_char	ihl:4; 
      #endif
      u_char tos;	//TOS 服务类型
      u_short tlen;	//包总长 u_short 占两个字节
      u_short id;	//标识
      u_short frag_off;	//片位移
      u_char ttl;	//生存时间
      u_char proto;	//协议
      u_short check;	//校验和
      u_int saddr;	//源地址
      u_int daddr;	//目的地址
      u_int op_pad;	//选项等
    };
    ```

     - TCP 头信息
     ```c++
    //TCP 头
    typedef struct tcphdr
    { u_short sport;	//源端口地址	16 位
      u_short dport;	//目的端口地址 16 位
      u_int seq;	//序列号 32 位
      u_int ack_seq;	//确认序列号
      u_short doff_flag;	//头大小、保留位、标志位u_short window;	//窗口大小 16 位
      u_short check;	//校验和 16 位
      u_short urg_ptr;	//紧急指针 16 位
      u_int opt;	//选项
    };
    ```

     - UDP 头信息
     ```c++
      //UDP 头
    typedef struct udphdr
    { u_short sport;	//源端口	16 位
      u_short dport;	//目的端口 16 位
      u_short len;	//数据报长度 16 位
      u_short check;	//校验和 16 位
    };
    ```

     - ICMP 头信息
     ```c++
    //ICMP 头
    typedef struct icmphdr
    { u_char type;	//8 位 类型
      u_char code;	//8 位 代码
      u_char seq;	//8 位序列号
      u_char chksum;	//8 位校验和
    };
    ```

     - IPv6 头信息
     ```c++
    //IPv6 头
    typedef struct iphdr6
    { u_int version:4,	//版本
            flowtype:8,	//流类型
            flowid:20;	//流标签
      u_short plen;	//有效载荷长度
      u_char nh;	//下一个头部
      u_char hlim;	//跳限制
      u_short saddr[8];	//源地址
      u_short daddr[8];	//目的地址
    };
    ```

     - ICMP6 头信息
     ```c++
    //ICMPv6 头
    typedef struct icmphdr6
    { u_char type;	//8 位 类型
      u_char code;	//8 位 代码
      u_char seq;	//序列号 8 位
      u_char chksum;	//8 位校验和
      u_char op_type;	//选项：类型
      u_char op_len;	// 选 项 ： 长 度 u_char op_ethaddr[6];	//选项：链路层地址
    };
    ```

     - 保存数据结构
     ```c++
    typedef struct datapkt
    { char	pktType[8];	//包类型
      int time[6];	//时间
      int len;	//长度
      struct ethhdr* ethh;	//链路层包头
      struct arphdr* arph;	//ARP 包头
      struct iphdr* iph;	//IP 包头
      struct iphdr6* iph6;	//IPV6
      struct icmphdr* icmph;	//ICMP 包头
      struct icmphdr6* icmph6;	//ICMPv6 包头
      struct udphdr* udph;	//UDP 包头
      struct tcphdr* tcph;	//TCP 包头
    };
    ```

 - 运行界面：
 	 - 安装 WinPcap

 	![Image text](/image/winpcap.png)
 	 - 主界面

 	![Image text](/image/主界面.png)
 	 - 抓包

 	![Image text](/image/抓包.png)
 	 - 选择过滤规则并且使用 ping 命令

 	![Image text](/image/ping.png)

 	![Image text](/image/ping2.png)
 	 - 数据包的保存（地址中不能带有汉字）

 	![Image text](/image/save.png)
 	 - 重新读取数据包

 	![Image text](/image/read.png)

 	![Image text](/image/read2.png)
 	 - 数据包解析

 	![Image text](/image/解析.png)



