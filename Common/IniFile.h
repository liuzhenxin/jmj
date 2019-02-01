// IniFile.h: interface for the CIniFile class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_INIFILE_H__DD61AD07_F1FD_4293_A051_E0F81ED992FE__INCLUDED_)
#define AFX_INIFILE_H__DD61AD07_F1FD_4293_A051_E0F81ED992FE__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include <windows.h>

class CIniFile  
{
public:
	BOOL GetString( const PCHAR pSection,      
                    const PCHAR pKeyName, 
					const PCHAR pDefault,    //�����ȡʧ�ܣ��򷵻�ȱʡֵ��
					PCHAR pOutString, 
					int pOutBuffLength
				  );
	BOOL SetString( const PCHAR pSection,      
		            const PCHAR pKeyName, 		
		            PCHAR pInString 	
		          );
	BOOL GetInteger( const PCHAR pSection,      
					 const PCHAR pKeyName, 
					 const int   Default,    //�����ȡʧ�ܣ��򷵻�ȱʡֵ��
					 int   *OutData 					 
					);
	BOOL SetInteger( const PCHAR pSection,      
					 const PCHAR pKeyName, 
					 const int   Indata			
					);
	BOOL GetHex( const PCHAR pSection,      
					const PCHAR pKeyName, 
					const int   Default,    //�����ȡʧ�ܣ��򷵻�ȱʡֵ��
					int  &OutData 					 
					);
	BOOL SetHex( const PCHAR pSection,      
					const PCHAR pKeyName, 
					const int   Indata			
					);
	//������ת��Ϊʮ��������ʽ�Ŀ����ַ���
	void ByteToHexChar(PBYTE pData,  //����Ķ���������
						int DataLen, PCHAR  pChar);
	void HexCharToByte(PCHAR  pInBuff, PBYTE pOutBuff, int &RetLen);
	void SetIniFile(const PCHAR pIniFileName);
	CIniFile(const PCHAR pIniFileName);
	CIniFile();
	virtual ~CIniFile();

private:
	char         szIniFileName[MAX_PATH+1];

};
#endif // !defined(AFX_INIFILE_H__DD61AD07_F1FD_4293_A051_E0F81ED992FE__INCLUDED_)
