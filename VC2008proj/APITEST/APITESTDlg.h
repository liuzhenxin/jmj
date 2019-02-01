// APITESTDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include <vector>
#include "Function.h"
#include "afxwin.h"


// CAPITESTDlg 对话框
class CAPITESTDlg : public CDialog
{
// 构造
public:
	CAPITESTDlg(CWnd* pParent = NULL);	// 标准构造函数

	void PrintLogInfo(CString logInfo,INT iColor);
	void AddHandle2Vector(std::vector<SGD_INT32> v,SGD_HANDLE h);
	void RefreshDeviceCombo();
	void RefreshSessionCombo();

	HINSTANCE hDll;

	CString m_strDllName;
	CString m_strMsg;
	CHARFORMAT  cf;

// 对话框数据
	enum { IDD = IDD_APITEST_DIALOG };

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
	CRichEditCtrl m_ConsoleLog;
	afx_msg void OnBnClickedBtnOpendevice();
	CComboBox m_DeviceComboBox;
	CComboBox m_SessionComboBox;
	afx_msg void OnBnClickedBtnClosedevice();


	afx_msg void OnBnClickedBtnOpensession();
	afx_msg void OnBnClickedBtnRandom();
	afx_msg void OnBnClickedBtnClosesession();
	afx_msg void OnBnClickedBtnGetdeviceinfo();
	afx_msg void OnBnClickedBtnGpkar();
	afx_msg void OnBnClickedBtnEspkrsa();
	afx_msg void OnBnClickedBtnEepkrrsa();
};
