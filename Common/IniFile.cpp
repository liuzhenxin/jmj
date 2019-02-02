// IniFile.cpp: implementation of the CIniFile class.
//
//////////////////////////////////////////////////////////////////////
#include "IniFile.h"
#include <shlwapi.h>
#include <stdio.h>

#pragma comment (lib, "shlwapi.lib")

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CIniFile::CIniFile()
{
	memset(szIniFileName, 0, sizeof(szIniFileName));
}

CIniFile::~CIniFile()
{

}

CIniFile::CIniFile(const PCHAR pIniFileName)
{
	strcpy(szIniFileName, pIniFileName);
	SetFileAttributes(szIniFileName, FILE_ATTRIBUTE_NORMAL);  ////去掉文件的只读属性；
}

void CIniFile::SetIniFile(const PCHAR pIniFileName)
{
	strcpy(szIniFileName, pIniFileName);
	SetFileAttributes(szIniFileName, FILE_ATTRIBUTE_NORMAL);  ////去掉文件的只读属性；
}

BOOL CIniFile::GetString( const PCHAR pSection,      
						 const PCHAR pKeyName, 
						 const PCHAR pDefault,    //如果读取失败，则返回缺省值；
						 PCHAR pOutString, 
						 int pOutBuffLength
						 )
{
	pOutString[0] = '\0';
	return  GetPrivateProfileString(pSection, pKeyName, pDefault, 
					pOutString, pOutBuffLength, szIniFileName);	
}

BOOL CIniFile::SetString( const PCHAR pSection,      
						   const PCHAR pKeyName, 		
						   PCHAR pInString 	
						   )
{
	return WritePrivateProfileString(pSection, pKeyName, pInString, szIniFileName);
}

BOOL CIniFile::GetInteger( const PCHAR pSection,      
				const PCHAR pKeyName, 
				const int   Default,    //如果读取失败，则返回缺省值；
				int  *OutData 					 
				)
{
	char        szText[301] = "";
	
	if (GetString(pSection,pKeyName , NULL, szText, 300))
	{
		*OutData = StrToInt(szText); 
		return true;
	}
    *OutData = Default;
	return false;
}

BOOL CIniFile::SetInteger( const PCHAR pSection,      
				const PCHAR pKeyName, 
				const int   Indata			
				)
{
		char        szText[301] = "";
		sprintf(szText, "%d", Indata);
		return SetString(pSection, pKeyName, szText);
}

BOOL CIniFile::GetHex( const PCHAR pSection,      
			const PCHAR pKeyName, 
			const int   Default,    //如果读取失败，则返回缺省值；
			int   &OutData 					 
			)
{
	char        szText[301] = "";
	BYTE        Buff[300];
	int       Count = 0;
	
	memset(Buff, 0, 300);
	if (GetString(pSection,pKeyName , NULL, szText, 300))
	{
		HexCharToByte(szText, Buff, Count);
		OutData =0;
		for(int i=0; i< Count; i++)
		{
			OutData = (OutData << 8) + Buff[i];
		}
		return true;
	}
    OutData = Default;
	return false;
}

BOOL CIniFile::SetHex( const PCHAR pSection,      
			const PCHAR pKeyName, 
			const int   Indata			
					)
{
	char        szText[301] = "";
	sprintf(szText, "%X", Indata);
	return SetString(pSection, pKeyName, szText);
}

void CIniFile::HexCharToByte(PCHAR  pInBuff, PBYTE pOutBuff, int &RetLen)
{
	DWORD             i, x;
	char            *pBuff = new char [strlen(pInBuff)+1];
	
	ZeroMemory(pBuff, strlen(pInBuff)+1);	
	CharUpper(pInBuff);
	
	for(i=0, x=0; i<strlen(pInBuff); i++)
	{
		if (
			(  
			(pInBuff[i] >= 'A' ) 
			&& (pInBuff[i] <= 'F' )  
			)  
			||( 
			(pInBuff[i] >= '0') 
			&& (pInBuff[i] <= '9')
			)
			)
		{
			pBuff[x++] = pInBuff[i];
		}
	}
	
	for (i=0, x=0; i<strlen(pBuff); i+=2)
	{
		BYTE    y1, y2;
		if ( (pBuff[i] >= '0') && (pBuff[i] <= '9') )
			y1 = pBuff[i] - '0';
		else
			y1 = pBuff[i] - 'A'+10;
		
		if (0 == pBuff[i+1])
			pBuff[i+1] = '0';

		if ( (pBuff[i+1] >= '0') && (pBuff[i+1] <= '9') )
			y2 = pBuff[i+1] - '0';
		else
			y2 = pBuff[i+1] - 'A' +10;
		
		pOutBuff[x++] = (y1 << 4) + y2;
	}
	RetLen = x;
	
	if (NULL != pBuff)
	{
		delete [] pBuff;
		pBuff = NULL;
	}
}

//将数字转化为十六进制形式的可视字符；
void CIniFile::ByteToHexChar(PBYTE pData, int DataLen, PCHAR  pChar)
{
	for(int i=0; i<DataLen; i++)
	{
		char       ch;
		ch = (pData[i] >> 4) & 0xF;		
		if (ch > 9)
		{
			pChar[i*2] = ch -10 + 'A';
		}
		else
		{
			pChar[i*2] = ch + '0';
		}
		
		ch = pData[i] & 0xF;
		if (ch > 9)
		{
			pChar[i*2+1] = ch -10 + 'A';
		}
		else
		{
			pChar[i*2+1] = ch + '0';
		}
		
		pChar[i*2+2] = 0x00;
	}
}