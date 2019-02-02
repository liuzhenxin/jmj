#include "SessionObj.h"
#include <Windows.h>
#include <WinBase.h>
//#include "log.h"
#include<stdlib.h>
#include "ErrorCode.h"

#define random(x) (rand()%x)

CSessionObj::CSessionObj(string ip,int port)
{
	//this->nObj.ip = ip;
	//this->nObj.port = port;
	//this->pbObj = new CSDFB(this->nObj);
	//this->isBusy = false;
	//this->isAllocate = false;
}

CSessionObj::CSessionObj(CNetObj nObj)
{
	this->nObj = nObj;
	//this->isBusy = false;
	//this->isAllocate = false;
}
CSessionObj::CSessionObj(void)
{

}

CSessionObj::~CSessionObj(void)
{

}

bool CSessionObj::Init(SGD_UINT32 uiDeviceHandle){
	
	SessionHandle = (GetTickCount()  + (random(100) + random(89) + 1) * 100);
	DevcieHandle = uiDeviceHandle;
	SocketID = nObj.SocketID;
	PoolLock = 0;
	HashID = 0;
	Index = 0;

	return true;
}

SGD_RV CSessionObj::SDF_GetDeviceInfo(DEVICEINFO *pstDeviceInfo)
{
	SGD_RV rv = SDR_OK;
	SGD_UCHAR bCmd[64] = {0};
	SGD_UCHAR bRev[256] = {0};

	SGD_UINT32 uiTaskSN = GetTickCount();
	SGD_UINT32 uiCmdLen = 0;
	SGD_UINT32 uiRevLen = 0;
	SGD_UINT32 uiRet = 0;

	uiCmdLen = 0xc;

	memcpy(bCmd,&uiCmdLen,4);
	memcpy(bCmd + 4,&uiTaskSN,4);
	memcpy(bCmd + 4 + 4,"\x01\x00\x02\x00",4);
	
	nObj.SendCmd(bCmd,uiCmdLen,bRev,&uiRevLen,&uiRet);

	if (uiRet != 0)
	{
		rv = uiRet;

	}else{

		memcpy(pstDeviceInfo,bRev + 4,uiRevLen - 4);
	}

	return rv;
}

SGD_RV CSessionObj::SDF_GenerateRandom(SGD_UINT32 uiLength, SGD_UCHAR *pucRandom){

	SGD_RV rv = SDR_OK;
	SGD_UCHAR bCmd[64] = {0};
	SGD_UCHAR bRev[64] = {0};

	SGD_UINT32 uiTaskSN = GetTickCount();
	SGD_UINT32 uiCmdLen = 0;
	SGD_UINT32 uiRevLen = 0;
	SGD_UINT32 uiRet = 0;

	uiCmdLen = 0x10;

	memcpy(bCmd,&uiCmdLen,4);
	memcpy(bCmd + 4,&uiTaskSN,4);
	memcpy(bCmd + 4 + 4,"\x02\x00\x02\x00",4);
	memcpy(bCmd + 4 + 4 + 4,&uiLength,4);

	nObj.SendCmd(bCmd,uiCmdLen,bRev,&uiRevLen,&uiRet);

	if (uiRet != 0)
	{
		rv = uiRet;
	
	}else{
	
		memcpy(pucRandom,bRev + 4,uiLength);
	}

	return rv;
}


SGD_RV CSessionObj::SDF_GetPrivateKeyAccessRight(SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength){return 0;}
SGD_RV CSessionObj::SDF_ReleasePrivateKeyAccessRight(SGD_UINT32  uiKeyIndex){return 0;}

SGD_RV CSessionObj::SDF_GetKeyStatus(SGD_UINT32  uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount){return 0;}
SGD_RV CSessionObj::SDF_GetDeviceRunStatus(SGD_HANDLE hSessionHandle,DEVICE_RUN_STATUS *pstDeviceRunStatus){return 0;}

/*非对称密码RSA密钥管理、运算函数*/
SGD_RV CSessionObj::SDF_GenerateKeyPair_RSA(SGD_UINT32  uiKeyBits,RSArefPublicKey *pucPublicKey,RSArefPrivateKey *pucPrivateKey)
{
	return 0;
}
SGD_RV CSessionObj::SDF_ExportSignPublicKey_RSA(SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
{					
	SGD_RV rv = SDR_OK;
	SGD_UCHAR bCmd[64] = {0};
	SGD_UCHAR bRev[1024 + 32] = {0};

	SGD_UINT32 uiTaskSN = GetTickCount();
	SGD_UINT32 uiCmdLen = 0;
	SGD_UINT32 uiRevLen = 0;
	SGD_UINT32 uiRet = 0;

	uiCmdLen = 0x14;

	memcpy(bCmd,&uiCmdLen,4);
	memcpy(bCmd + 4,&uiTaskSN,4);
	memcpy(bCmd + 4 + 4,"\x01\x00\x04\x00",4);
	memcpy(bCmd + 4 + 4 + 4,&uiKeyIndex,4);
	memcpy(bCmd + 4 + 4 + 4 + 4,"\x00\x02\x01\x00",4);

	if (!nObj.SendCmd(bCmd,uiCmdLen,bRev,&uiRevLen,&uiRet))
	{
		rv = SWR_SOCKET_SEND_ERR;
		return rv;
	}

	if (uiRet != 0)
	{
		rv = uiRet;
	}else{
		memcpy(pucPublicKey,bRev + 4,uiRevLen - 4);
	}

	return rv;
}


SGD_RV CSessionObj::SDF_ExportEncPublicKey_RSA(SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
{
	SGD_RV rv = SDR_OK;
	SGD_UCHAR bCmd[64] = {0};
	SGD_UCHAR bRev[1024 + 32] = {0};

	SGD_UINT32 uiTaskSN = GetTickCount();
	SGD_UINT32 uiCmdLen = 0;
	SGD_UINT32 uiRevLen = 0;
	SGD_UINT32 uiRet = 0;

	uiCmdLen = 0x14;

	memcpy(bCmd,&uiCmdLen,4);
	memcpy(bCmd + 4,&uiTaskSN,4);
	memcpy(bCmd + 4 + 4,"\x01\x00\x04\x00",4);
	memcpy(bCmd + 4 + 4 + 4,&uiKeyIndex,4);
	memcpy(bCmd + 4 + 4 + 4 + 4,"\x00\x01\x01\x00",4);

	if (!nObj.SendCmd(bCmd,uiCmdLen,bRev,&uiRevLen,&uiRet))
	{
		rv = SWR_SOCKET_SEND_ERR;
		return rv;
	}
	

	if (uiRet != 0)
	{
		rv = uiRet;
	}else{
		memcpy(pucPublicKey,bRev + 4,uiRevLen - 4);
	}

	return rv;
}
SGD_RV CSessionObj::SDF_ExternalPublicKeyOperation_RSA(RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength){return 0;}
SGD_RV CSessionObj::SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength){return 0;}
SGD_RV CSessionObj::SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UINT32  uiKeyUsage,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength){return 0;}
SGD_RV CSessionObj::SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UINT32  uiKeyUsage,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength){return 0;}
SGD_RV CSessionObj::SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucDEInput,SGD_UINT32  uiDELength,SGD_UCHAR *pucDEOutput,SGD_UINT32  *puiDELength){return 0;}

/*非对称密码ECC密钥管理、运算函数*/
SGD_RV CSessionObj::SDF_GenerateKeyPair_ECC(SGD_UINT32  uiAlgID,SGD_UINT32  uiKeyBits,ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey){return 0;}
SGD_RV CSessionObj::SDF_ExportSignPublicKey_ECC(SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey){return 0;}
SGD_RV CSessionObj::SDF_ExportEncPublicKey_ECC(SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey){return 0;}
SGD_RV CSessionObj::SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature){return 0;}
SGD_RV CSessionObj::SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,ECCSignature *pucSignature){return 0;}
SGD_RV CSessionObj::SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature){return 0;}
SGD_RV CSessionObj::SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature){return 0;}
SGD_RV CSessionObj::SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData){return 0;}
SGD_RV CSessionObj::SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,SGD_UCHAR *pucData,SGD_UINT32  *puiDataLength){return 0;}
SGD_RV CSessionObj::SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData){return 0;}
SGD_RV CSessionObj::SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,ECCCipher *pucEncData,SGD_UCHAR *pucData,SGD_UINT32  *puiDataLength){return 0;}
SGD_RV CSessionObj::SDF_InternalSign_ECC_Ex(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature){return 0;}
SGD_RV CSessionObj::SDF_InternalVerify_ECC_Ex(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature){return 0;}

SGD_RV CSessionObj::SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey  *pucSponsorPublicKey,ECCrefPublicKey  *pucSponsorTmpPublicKey,SGD_HANDLE *phAgreementHandle){return 0;}
SGD_RV CSessionObj::SDF_GenerateKeyWithECC(SGD_UCHAR *pucResponseID,SGD_UINT32 uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucResponseID,SGD_UINT32 uiResponseIDLength,SGD_UCHAR *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey  *pucResponsePublicKey,ECCrefPublicKey  *pucResponseTmpPublicKey,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucEncDataIn,ECCCipher *pucEncDataOut){return 0;}

/*对称密钥管理、密码运算函数*/
SGD_RV CSessionObj::SDF_GenerateKeyWithIPK_RSA(SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_GenerateKeyWithEPK_RSA(SGD_UINT32 uiKeyBits,RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_GenerateKeyWithKEK(SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_GenerateKeyWithIPK_ECC (SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_GenerateKeyWithEPK_ECC (SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle){return 0;}

SGD_RV CSessionObj::SDF_ImportKeyWithISK_RSA(SGD_UINT32 uiISKIndex,SGD_UCHAR *pucKey,SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_ImportKeyWithKEK(SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_ImportKeyWithISK_ECC (SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_ImportKey(SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle){return 0;}

SGD_RV CSessionObj::SDF_DestroyKey(SGD_HANDLE hKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_GetSymmKeyHandle(SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle){return 0;}
SGD_RV CSessionObj::SDF_Encrypt(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR *pucEncData,SGD_UINT32  *puiEncDataLength){return 0;}
SGD_RV CSessionObj::SDF_Decrypt (SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucEncData,SGD_UINT32  uiEncDataLength,SGD_UCHAR *pucData,SGD_UINT32 *puiDataLength){return 0;}
SGD_RV CSessionObj::SDF_CalculateMAC(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR *pucMAC,SGD_UINT32  *puiMACLength){return 0;}

/*杂凑运算函数*/
SGD_RV CSessionObj::SDF_HashInit(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucID,SGD_UINT32 uiIDLength){return 0;}
SGD_RV CSessionObj::SDF_HashUpdate(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength){return 0;}
SGD_RV CSessionObj::SDF_HashFinal(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucHash,SGD_UINT32  *puiHashLength){return 0;}

/*用户文件操作函数*/
SGD_RV CSessionObj::SDF_CreateFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiFileSize){return 0;}
SGD_RV CSessionObj::SDF_ReadFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 *puiReadLength,SGD_UCHAR *pucBuffer){return 0;}
SGD_RV CSessionObj::SDF_WriteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 uiWriteLength,SGD_UCHAR *pucBuffer){return 0;}
SGD_RV CSessionObj::SDF_DeleteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen){return 0;}

/*自定义接口，总参PKCA扩展接口，仅总参专用密码机支持*/
SGD_RV	CSessionObj::SDF_ImportECCKeyPair(SGD_HANDLE		hSessionHandle, SGD_UINT32	uiKeyNumber,ECCrefPublicKey	*puxPublicKey,ECCrefPrivateKey	*pucPrivateKey){return 0;}
SGD_RV	CSessionObj::SDF_InternalSignEx_ECC(SGD_HANDLE	hSessionHandle,SGD_UINT32	uiKeyNumber,SGD_UCHAR	*pucData,SGD_UINT32	uiDataLength,ECCPoint	*P1,ECCSignatureEx	*sign){return 0;}
SGD_RV  CSessionObj::SDF_ECCMultAdd(SGD_HANDLE	hSessionHandle, SGD_UINT32	k,ECCrefPrivateKey	*e, ECCrefPublicKey	*A,ECCrefPublicKey	*B,ECCrefPublicKey	*C){return 0;}
SGD_RV  CSessionObj::SDF_ECCModMultAdd(SGD_HANDLE	hSessionHandle, ECCrefPrivateKey	*k,ECCrefPrivateKey	*a,ECCrefPrivateKey	*b,ECCrefPrivateKey	*c){return 0;}
SGD_RV  CSessionObj::SDF_ECCMultAdd2(SGD_HANDLE	hSessionHandle,ECCrefPrivateKey	*e1,ECCrefPublicKey	*A1,ECCrefPrivateKey	*e2,ECCrefPublicKey	*A2,ECCrefPublicKey	*B,ECCrefPublicKey	*C){return 0;}
SGD_RV  CSessionObj::SDF_InternalSignEx2_ECC(SGD_HANDLE	hSessionHandle,SGD_UINT32	uiISKIndex1,SGD_UINT32	uiISKIndex2,SGD_UCHAR	*pucData,SGD_UINT32	uiDataLength,ECCPoint	*P1,ECCSignatureEx	*sign){return 0;}