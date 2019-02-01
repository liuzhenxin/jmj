// APITESTDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "APITEST.h"
#include "APITESTDlg.h"
//#include "Function.h"
#include "IniFile.h"
#include "MsgDef.h"
#include <process.h>
//#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

std::vector<SGD_INT32> vhDev;
std::vector<SGD_INT32> vhSession;


CString m_strMsg;
CAPITESTDlg *m_pDlg;

SDF_OpenDevice_Fun   pSDF_OpenDevice_Fun;
SDF_CloseDevice_Fun  pSDF_CloseDevice_Fun;
SDF_OpenSession_Fun  pSDF_OpenSession_Fun;
SDF_CloseSession_Fun pSDF_CloseSession_Fun;

SDF_GenerateRandom_Fun pSDF_GenerateRandom_Fun;
SDF_GetDeviceInfo_Fun pSDF_GetDeviceInfo_Fun;

SDF_GetPrivateKeyAccessRight_Fun  pSDF_GetPrivateKeyAccessRight_Fun;
SDF_ReleasePrivateKeyAccessRight_Fun pSDF_ReleasePrivateKeyAccessRight_Fun;

SDF_ExportSignPublicKey_RSA_Fun pSDF_ExportSignPublicKey_RSA_Fun;
SDF_ExportEncPublicKey_RSA_Fun pSDF_ExportEncPublicKey_RSA_Fun;


void OpenDevice_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("OpenDevice");
	CString strMsgParam = _T("");
	SGD_RV  rv = 0;
	SGD_HANDLE hDev = NULL;
	SGD_INT32  hVal = 0;
		
	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

    rv = pSDF_OpenDevice_Fun(&hDev);

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	strMsgParam.Format(_T(",hDev = 0x%08x"),hDev);

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	memcpy(&hVal,&hDev,sizeof(SGD_INT32));
	vhDev.push_back(hVal);

	m_pDlg->RefreshDeviceCombo();
}

void OpenSession_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("OpenSession");
	CString strMsgParam = _T("");
	CString strDevice = _T("");
	SGD_RV  rv = 0;

	SGD_HANDLE hDev = NULL;
	SGD_INT32  hValDev = 0;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;

	m_pDlg->GetDlgItem(IDC_COMBO_DEVICE)->GetWindowText(strDevice);

	if (strDevice.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValDev = strtol(strDevice,NULL,16);

	memcpy(&hDev,&hValDev,sizeof(SGD_INT32));
	rv = pSDF_OpenSession_Fun(hDev,&hSession);

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	strMsgParam.Format(_T(",hSession = 0x%08x"),hSession);
	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

    memcpy(&hValSession,&hSession,sizeof(SGD_INT32));
	vhSession.push_back(hValSession);

	m_pDlg->RefreshSessionCombo();

}

void GetRandom_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("GenerateRandom");
	CString strMsgParam = _T("");
	//CString strSession = _T("");
	SGD_RV  rv = 0;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;
	CString    strSession = _T("");
	CString strHex = _T("");
	CString strRandom = _T("");

	SGD_UCHAR ucRandom[16] = {0};

	m_pDlg->GetDlgItem(IDC_COMBO_SESSION)->GetWindowText(strSession);

	if (strSession.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValSession = strtol(strSession,NULL,16);
	memcpy(&hSession,&hValSession,sizeof(SGD_INT32));
	
	rv = pSDF_GenerateRandom_Fun(hSession,16,ucRandom);

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	for(int i = 0;i != 16;i++){
       strHex.Format(_T("%02x"),ucRandom[i]);
	   strRandom += strHex;
	}

	strMsgParam.Format(_T(",Random = %s"),strRandom);
	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

}

void CloseDevice_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("CloseDevice");
	CString strMsgParam = _T("");
	CString strDevice = _T("");
	SGD_RV  rv = 0;

	SGD_HANDLE hDev = NULL;
	SGD_INT32  hValDevice = 0;

	m_pDlg->GetDlgItem(IDC_COMBO_DEVICE)->GetWindowText(strDevice);

	if (strDevice.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValDevice = strtol(strDevice,NULL,16);
	memcpy(&hDev,&hValDevice,sizeof(SGD_INT32));
	
	rv = pSDF_CloseDevice_Fun(hDev);

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);


	for(std::vector<SGD_INT32>::iterator it = vhDev.begin(); it != vhDev.end();it++)
	{
		if (*it == hValDevice)
		{
			vhDev.erase(it);
			break;
		}
	}

	m_pDlg->RefreshDeviceCombo();
}

void CloseSession_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("CloseSession");
	CString strMsgParam = _T("");
	CString strSession = _T("");
	SGD_RV  rv = 0;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;

	m_pDlg->GetDlgItem(IDC_COMBO_SESSION)->GetWindowText(strSession);

	if (strSession.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValSession = strtol(strSession,NULL,16);
	memcpy(&hSession,&hValSession,sizeof(SGD_INT32));

	rv = pSDF_CloseSession_Fun(hSession);

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	for(std::vector<SGD_INT32>::iterator it = vhSession.begin(); it != vhSession.end();it++)
	{
		if (*it == hValSession)
		{
			vhSession.erase(it);
			break;
		}
	}

	m_pDlg->RefreshSessionCombo();

}

void GetDeviceInfo_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("GetDeviceInfo");
	CString strMsgParam = _T("");
	CString strSession = _T("");
	SGD_RV  rv = 0;

	DEVICEINFO df;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;

	m_pDlg->GetDlgItem(IDC_COMBO_SESSION)->GetWindowText(strSession);

	if (strSession.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValSession = strtol(strSession,NULL,16);
	memcpy(&hSession,&hValSession,sizeof(SGD_INT32));

	memset(&df,0,sizeof(DEVICEINFO));

	rv = pSDF_GetDeviceInfo_Fun(hSession,&df);

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	m_strMsg.Format(MSG_DEV_INFO,df.IssuerName,df.DeviceName,df.DeviceSerial,\
		                         df.DeviceVersion,df.StandardVersion,df.AsymAlgAbility[0],\
								 df.AsymAlgAbility[1],df.SymAlgAbility,df.HashAlgAbility,df.BufferSize);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

}

void  GPKAR_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("GPKAR");
	CString strMsgParam = _T("");
	CString strSession = _T("");
	SGD_RV  rv = 0;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;

	m_pDlg->GetDlgItem(IDC_COMBO_SESSION)->GetWindowText(strSession);

	if (strSession.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValSession = strtol(strSession,NULL,16);
	memcpy(&hSession,&hValSession,sizeof(SGD_INT32));

	OutputDebugString("1111");

	//if (pSDF_GetPrivateKeyAccessRight_Fun == NULL)
	//{

	//	OutputDebugString("pSDF_GetPrivateKeyAccessRight_Fun is null");
	//	return;
	//}

	m_strMsg.Format(_T("hSession = 0x%08x"),hSession);
	OutputDebugString(m_strMsg);

	rv = pSDF_GetPrivateKeyAccessRight_Fun(hSession,1,(SGD_UCHAR*)"11111111",8);

	OutputDebugString("2222");

	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

}

void ESPKRSA_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("ESPKRSA");
	CString strMsgParam = _T("");
	CString strSession = _T("");
	SGD_RV  rv = 0;
	CString strHex = 0;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;

	RSArefPublicKey rsaArefPublicKey;
	memset(&rsaArefPublicKey,0,sizeof(RSArefPublicKey));

	m_pDlg->GetDlgItem(IDC_COMBO_SESSION)->GetWindowText(strSession);

	if (strSession.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValSession = strtol(strSession,NULL,16);
	memcpy(&hSession,&hValSession,sizeof(SGD_INT32));

	//memset(&rsaArefPublicKey,0,sizeof(RSArefPublicKey));

	int keyIndex = 1;
	int pukLen = 0;


	rv = pSDF_ExportSignPublicKey_RSA_Fun(hSession,keyIndex,&rsaArefPublicKey);


	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	if (rsaArefPublicKey.bits > 2048)
		pukLen = sizeof(RSArefPublicKeyEx);
	else
		pukLen = sizeof(RSArefPublicKeyLite);


	BYTE buf[4096] = {0};
	memcpy(buf,&rsaArefPublicKey,pukLen);

	for (int i = 0;i != pukLen;i++)
	{
		strHex.Format(_T("%02x "),buf[i]);
		m_strMsg += strHex;
	}
	
	//m_strMsg.Format(_T("签名公钥RSA:%s"),m_strMsg);
	m_pDlg->PrintLogInfo(_T("签名公钥RSA"),LOG_OK);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);
}

void EEPKRSA_ThreadFunc(LPVOID lpParam){

	CString strFuncName = _T("EEPKRSA");
	CString strMsgParam = _T("");
	CString strSession = _T("");
	SGD_RV  rv = 0;
	CString strHex = 0;

	SGD_HANDLE hSession = NULL;
	SGD_INT32  hValSession = 0;

	RSArefPublicKey rsaArefPublicKey;
	memset(&rsaArefPublicKey,0,sizeof(RSArefPublicKey));

	m_pDlg->GetDlgItem(IDC_COMBO_SESSION)->GetWindowText(strSession);

	if (strSession.Trim().GetLength() == 0)
	{
		m_strMsg.Format(MSG_FUNC_PARAM_EMPTY,strFuncName);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_FUNC_NAME,strFuncName);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	hValSession = strtol(strSession,NULL,16);
	memcpy(&hSession,&hValSession,sizeof(SGD_INT32));

	//memset(&rsaArefPublicKey,0,sizeof(RSArefPublicKey));

	int keyIndex = 1;
	int pukLen = 0;


	rv = pSDF_ExportEncPublicKey_RSA_Fun(hSession,keyIndex,&rsaArefPublicKey);


	if (rv != SDR_OK) 
	{
		m_strMsg.Format(MSG_ERROR,strFuncName,rv);
		m_pDlg->PrintLogInfo(m_strMsg,LOG_ERROR);
		return;
	}

	m_strMsg.Format(MSG_OK,strFuncName,strMsgParam);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

	if (rsaArefPublicKey.bits > 2048)
		pukLen = sizeof(RSArefPublicKeyEx);
	else
		pukLen = sizeof(RSArefPublicKeyLite);


	BYTE buf[4096] = {0};
	memcpy(buf,&rsaArefPublicKey,pukLen);

	for (int i = 0;i != pukLen;i++)
	{
		strHex.Format(_T("%02x "),buf[i]);
		m_strMsg += strHex;
	}

	//m_strMsg.Format(_T("加密公钥RSA:%s"),m_strMsg);
	m_pDlg->PrintLogInfo(_T("加密公钥RSA"),LOG_OK);
	m_pDlg->PrintLogInfo(m_strMsg,LOG_OK);

}


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CAPITESTDlg 对话框




CAPITESTDlg::CAPITESTDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAPITESTDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAPITESTDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_RICHEDIT21, m_ConsoleLog);
	DDX_Control(pDX, IDC_COMBO_DEVICE, m_DeviceComboBox);
	DDX_Control(pDX, IDC_COMBO_SESSION, m_SessionComboBox);
}

BEGIN_MESSAGE_MAP(CAPITESTDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BTN_OPENDEVICE, &CAPITESTDlg::OnBnClickedBtnOpendevice)
	ON_BN_CLICKED(IDC_BTN_CLOSEDEVICE, &CAPITESTDlg::OnBnClickedBtnClosedevice)
	ON_BN_CLICKED(IDC_BTN_OPENSESSION, &CAPITESTDlg::OnBnClickedBtnOpensession)
	ON_BN_CLICKED(IDC_BTN_RANDOM, &CAPITESTDlg::OnBnClickedBtnRandom)
	ON_BN_CLICKED(IDC_BTN_CLOSESESSION, &CAPITESTDlg::OnBnClickedBtnClosesession)
	ON_BN_CLICKED(IDC_BTN_GETDEVICEINFO, &CAPITESTDlg::OnBnClickedBtnGetdeviceinfo)
	ON_BN_CLICKED(IDC_BTN_GPKAR, &CAPITESTDlg::OnBnClickedBtnGpkar)
	ON_BN_CLICKED(IDC_BTN_ESPKRSA, &CAPITESTDlg::OnBnClickedBtnEspkrsa)
	ON_BN_CLICKED(IDC_BTN_EEPKRRSA, &CAPITESTDlg::OnBnClickedBtnEepkrrsa)
END_MESSAGE_MAP()


// CAPITESTDlg 消息处理程序

BOOL CAPITESTDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	m_pDlg = this;

	// TODO: 在此添加额外的初始化代码
	//获取配置文件信息
	BYTE bBuff[MAX_PATH] = {0};
	BYTE bCurrentDirectory[MAX_PATH] = {0};
	CString strCurrentDirectory = _T("");
	CString strFileName = _T(".\\config.ini");
	CString strSql = _T("");
	DWORD dwErrCode = 0;

	GetCurrentDirectory(MAX_PATH,(CHAR *)bCurrentDirectory);
	strCurrentDirectory.Format(_T("%s\\"),bCurrentDirectory);

	CIniFile Ini((CONST PCHAR)(strCurrentDirectory + strFileName).GetBuffer(0));

	memset(bBuff,0,MAX_PATH);
	Ini.GetString("DLL","NAME",NULL,(PCHAR)bBuff,MAX_PATH);
	m_strDllName.Format(_T("%s"),bBuff);


	hDll = LoadLibrary(m_strDllName);
	if (hDll == NULL)
	{
		CString strMsg = _T("加载") + m_strDllName  + _T("失败!");
		AfxMessageBox(strMsg);
		return FALSE;
	}

	pSDF_OpenDevice_Fun = (SDF_OpenDevice_Fun)GetProcAddress(hDll,"SDF_OpenDevice");
	pSDF_CloseDevice_Fun = (SDF_CloseDevice_Fun)GetProcAddress(hDll,"SDF_CloseDevice");
	pSDF_OpenSession_Fun = (SDF_OpenSession_Fun)GetProcAddress(hDll,"SDF_OpenSession");
	pSDF_CloseSession_Fun = (SDF_CloseSession_Fun)GetProcAddress(hDll,"SDF_CloseSession");

	pSDF_GenerateRandom_Fun = (SDF_GenerateRandom_Fun)GetProcAddress(hDll,"SDF_GenerateRandom");
	pSDF_GetDeviceInfo_Fun = (SDF_GetDeviceInfo_Fun)GetProcAddress(hDll,"SDF_GetDeviceInfo");

	pSDF_GetPrivateKeyAccessRight_Fun = (SDF_GetPrivateKeyAccessRight_Fun)GetProcAddress(hDll,"SDF_GetPrivateKeyAccessRight");
	pSDF_ReleasePrivateKeyAccessRight_Fun = (SDF_ReleasePrivateKeyAccessRight_Fun)GetProcAddress(hDll,"SDF_ReleasePrivateKeyAccessRight");

	pSDF_ExportSignPublicKey_RSA_Fun = (SDF_ExportSignPublicKey_RSA_Fun)GetProcAddress(hDll,"SDF_ExportSignPublicKey_RSA");
	pSDF_ExportEncPublicKey_RSA_Fun = (SDF_ExportEncPublicKey_RSA_Fun)GetProcAddress(hDll,"SDF_ExportEncPublicKey_RSA");


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAPITESTDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAPITESTDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAPITESTDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CAPITESTDlg::PrintLogInfo(CString logInfo,INT iColor){

	logInfo += "\n";

	if(!iColor)
	{

		m_ConsoleLog.SetSel(0xFFFF, 0xFFFF);
		m_ConsoleLog.ReplaceSel(logInfo);
		m_ConsoleLog.LineScroll(m_ConsoleLog.GetLineCount());

		m_ConsoleLog.UpdateData(TRUE);
	}else{

		CHARFORMAT cf;
		m_ConsoleLog.GetDefaultCharFormat(cf);
		cf.dwMask = CFM_COLOR;
		cf.dwEffects = 0;
		cf.crTextColor = RGB(255,0,0);

		// Set Focus to auto scroll the Richedit window and update it
		m_ConsoleLog.SetFocus();
		m_ConsoleLog.SetSel(0xFFFF, 0xFFFF);

		m_ConsoleLog.HideSelection(FALSE, TRUE);

		m_ConsoleLog.SetSelectionCharFormat(cf);

		m_ConsoleLog.ReplaceSel(logInfo);

		m_ConsoleLog.HideSelection(TRUE, TRUE);

	}
	return;
}

void CAPITESTDlg::AddHandle2Vector(std::vector<SGD_INT32> v,SGD_HANDLE h){
    
	SGD_INT32 hDev = 0;

	memcpy(&hDev,&h,sizeof(SGD_INT32));

	v.push_back(hDev);
	
}


void CAPITESTDlg::RefreshDeviceCombo(){
	
	CString strItem = _T("");

	m_DeviceComboBox.ResetContent();

	for (int i = 0;i != vhDev.size();i++)
	{
		strItem.Format(_T("%08x"),vhDev[i]);
		m_DeviceComboBox.AddString(strItem);
	}

	m_DeviceComboBox.SetCurSel(0);

}

void  CAPITESTDlg::RefreshSessionCombo(){

	CString strItem = _T("");
	
	m_SessionComboBox.ResetContent();

	for (int i = 0;i != vhSession.size();i++)
	{
		strItem.Format(_T("%08x"),vhSession[i]);
		m_SessionComboBox.AddString(strItem);
	}

	m_SessionComboBox.SetCurSel(0);

}

void CAPITESTDlg::OnBnClickedBtnOpendevice()
{
	_beginthread(OpenDevice_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnClosedevice()
{
	_beginthread(CloseDevice_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnOpensession()
{
	_beginthread(OpenSession_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnRandom()
{
	_beginthread(GetRandom_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnClosesession()
{
	_beginthread(CloseSession_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnGetdeviceinfo()
{
	_beginthread(GetDeviceInfo_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnGpkar()
{
	_beginthread(GPKAR_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnEspkrsa()
{
	_beginthread(ESPKRSA_ThreadFunc,0,0);
}

void CAPITESTDlg::OnBnClickedBtnEepkrrsa()
{
	// TODO: 在此添加控件通知处理程序代码	
	_beginthread(EEPKRSA_ThreadFunc,0,0);
}
