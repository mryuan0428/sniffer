// mcf6Dlg.h : 头文件
//
#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"
#include "Protocol.h"
#include "utilities.h"

// Cmcf6Dlg 对话框
class Cmcf6Dlg : public CDialog
{
// 构造
public:
	Cmcf6Dlg(CWnd* pParent = NULL);	// 标准构造函数

	/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////
	int lixsniff_initCap();
	int lixsniff_startCap();
	int lixsniff_updateTree(int index);
	int lixsniff_updateEdit(int index);
	int lixsniff_updateNPacket();
	int lixsniff_saveFile();
	int lixsniff_readFile(CString path);
	
	//////////////////////////////////////////////［my data］/////////////////////////////////////////////
	int devCount;
	struct pktcount npacket;				//各类数据包计数
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	char filepath[512];							//	文件保存路径
	char filename[64];							//	文件名称							

	HANDLE m_ThreadHandle;			//线程

	CPtrList m_pktList;							//捕获包所存放的链表

// 对话框数据
	enum { IDD = IDD_MCF6_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listCtrl;
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
	CTreeCtrl m_treeCtrl;
	CEdit m_edit;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	CButton m_buttonStart;
	CButton m_buttonStop;
	CPtrList m_localDataList;				//保存被本地化后的数据包
	CPtrList m_netDataList;					//保存从网络中直接获取的数据包
	CBitmapButton m_bitButton	;		//图片按钮
	int npkt;
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	CEdit m_editNTcp;
	CEdit m_editNUdp;
	CEdit m_editNIcmp;
	CEdit m_editNIp;
	CEdit m_editNArp;
	CEdit m_editNHttp;
	CEdit m_editNOther;
	CEdit m_editNSum;
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton5();
	CButton m_buttonSave;
	CButton m_buttonRead;
	afx_msg void OnBnClickedButton4();
	CEdit m_editNIpv4;
	CEdit m_editIcmpv6;
	afx_msg void OnTvnSelchangedTree1(NMHDR *pNMHDR, LRESULT *pResult);
};
