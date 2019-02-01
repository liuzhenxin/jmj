// APITESTDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"
#include <vector>
#include "Function.h"
#include "afxwin.h"


// CAPITESTDlg �Ի���
class CAPITESTDlg : public CDialog
{
// ����
public:
	CAPITESTDlg(CWnd* pParent = NULL);	// ��׼���캯��

	void PrintLogInfo(CString logInfo,INT iColor);
	void AddHandle2Vector(std::vector<SGD_INT32> v,SGD_HANDLE h);
	void RefreshDeviceCombo();
	void RefreshSessionCombo();

	HINSTANCE hDll;

	CString m_strDllName;
	CString m_strMsg;
	CHARFORMAT  cf;

// �Ի�������
	enum { IDD = IDD_APITEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
