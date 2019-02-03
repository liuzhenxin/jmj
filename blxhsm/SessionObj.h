#ifndef _SESSIONOBJ_H_
#define _SESSIONOBJ_H_
#include "NetObj.h"
#include "sdf.h"



class CSessionObj
{
public:
	CNetObj nObj;
	//bool isBusy;       //繁忙
	//bool isAllocate;    //分配

	SGD_UINT32 SessionHandle;
	SGD_UINT32 Index;
	SGD_UINT32 DevcieHandle;
	SGD_BOOL PoolLock;
	SGD_UINT32 SocketID;
	SGD_UINT32 HashID; 
	


public:

	bool Init(SGD_UINT32 uiDeviceHandle);
	CSessionObj(void);
	CSessionObj(string ip,int port);
	CSessionObj(CNetObj nObj);
	~CSessionObj(void);

	// 关闭连接
	bool Finalize();
public:


	SGD_RV SDF_GetPrivateKeyAccessRight(SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength);
	SGD_RV SDF_ReleasePrivateKeyAccessRight(SGD_UINT32  uiKeyIndex);

	SGD_RV SDF_GetDeviceInfo(DEVICEINFO *pstDeviceInfo);
	SGD_RV SDF_GenerateRandom(SGD_UINT32  uiLength, SGD_UCHAR *pucRandom);
	SGD_RV SDF_GetKeyStatus(SGD_UINT32  uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount);
	SGD_RV SDF_GetDeviceRunStatus(SGD_HANDLE hSessionHandle,DEVICE_RUN_STATUS *pstDeviceRunStatus);

	/*非对称密码RSA密钥管理、运算函数*/
	SGD_RV SDF_GenerateKeyPair_RSA(SGD_UINT32  uiKeyBits,RSArefPublicKey *pucPublicKey,RSArefPrivateKey *pucPrivateKey);
	SGD_RV SDF_ExportSignPublicKey_RSA(SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey);
	SGD_RV SDF_ExportEncPublicKey_RSA(SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey);
	SGD_RV SDF_ExternalPublicKeyOperation_RSA(RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
	SGD_RV SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
	SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UINT32  uiKeyUsage,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
	SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UINT32  uiKeyUsage,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
	SGD_RV SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucDEInput,SGD_UINT32  uiDELength,SGD_UCHAR *pucDEOutput,SGD_UINT32  *puiDELength);

	/*非对称密码ECC密钥管理、运算函数*/
	SGD_RV SDF_GenerateKeyPair_ECC(SGD_UINT32  uiAlgID,SGD_UINT32  uiKeyBits,ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey);
	SGD_RV SDF_ExportSignPublicKey_ECC(SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey);
	SGD_RV SDF_ExportEncPublicKey_ECC(SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey);
	SGD_RV SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
	SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,ECCSignature *pucSignature);
	SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
	SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
	SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData);
	SGD_RV SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,SGD_UCHAR *pucData,SGD_UINT32  *puiDataLength);
	SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData);
	SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,ECCCipher *pucEncData,SGD_UCHAR *pucData,SGD_UINT32  *puiDataLength);
	SGD_RV SDF_InternalSign_ECC_Ex(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
	SGD_RV SDF_InternalVerify_ECC_Ex(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);

	SGD_RV SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey  *pucSponsorPublicKey,ECCrefPublicKey  *pucSponsorTmpPublicKey,SGD_HANDLE *phAgreementHandle);
	SGD_RV SDF_GenerateKeyWithECC(SGD_UCHAR *pucResponseID,SGD_UINT32 uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucResponseID,SGD_UINT32 uiResponseIDLength,SGD_UCHAR *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey  *pucResponsePublicKey,ECCrefPublicKey  *pucResponseTmpPublicKey,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucEncDataIn,ECCCipher *pucEncDataOut);

	/*对称密钥管理、密码运算函数*/
	SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_UINT32 uiKeyBits,RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_GenerateKeyWithKEK(SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_GenerateKeyWithIPK_ECC (SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_GenerateKeyWithEPK_ECC (SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle);

	SGD_RV SDF_ImportKeyWithISK_RSA(SGD_UINT32 uiISKIndex,SGD_UCHAR *pucKey,SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_ImportKeyWithKEK(SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_ImportKeyWithISK_ECC (SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_ImportKey(SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle);

	SGD_RV SDF_DestroyKey(SGD_HANDLE hKeyHandle);
	SGD_RV SDF_GetSymmKeyHandle(SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle);
	SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR *pucEncData,SGD_UINT32  *puiEncDataLength);
	SGD_RV SDF_Decrypt (SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucEncData,SGD_UINT32  uiEncDataLength,SGD_UCHAR *pucData,SGD_UINT32 *puiDataLength);
	SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR *pucMAC,SGD_UINT32  *puiMACLength);

	/*杂凑运算函数*/
	SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucID,SGD_UINT32 uiIDLength);
	SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength);
	SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucHash,SGD_UINT32  *puiHashLength);

	/*用户文件操作函数*/
	SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiFileSize);
	SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 *puiReadLength,SGD_UCHAR *pucBuffer);
	SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 uiWriteLength,SGD_UCHAR *pucBuffer);
	SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen);

	/*自定义接口，总参PKCA扩展接口，仅总参专用密码机支持*/
	SGD_RV	SDF_ImportECCKeyPair(SGD_HANDLE		hSessionHandle, SGD_UINT32	uiKeyNumber,ECCrefPublicKey	*puxPublicKey,ECCrefPrivateKey	*pucPrivateKey);
	SGD_RV	SDF_InternalSignEx_ECC(SGD_HANDLE	hSessionHandle,SGD_UINT32	uiKeyNumber,SGD_UCHAR	*pucData,SGD_UINT32	uiDataLength,ECCPoint	*P1,ECCSignatureEx	*sign);
	SGD_RV  SDF_ECCMultAdd(SGD_HANDLE	hSessionHandle, SGD_UINT32	k,ECCrefPrivateKey	*e, ECCrefPublicKey	*A,ECCrefPublicKey	*B,ECCrefPublicKey	*C);
	SGD_RV  SDF_ECCModMultAdd(SGD_HANDLE	hSessionHandle, ECCrefPrivateKey	*k,ECCrefPrivateKey	*a,ECCrefPrivateKey	*b,ECCrefPrivateKey	*c);
	SGD_RV  SDF_ECCMultAdd2(SGD_HANDLE	hSessionHandle,ECCrefPrivateKey	*e1,ECCrefPublicKey	*A1,ECCrefPrivateKey	*e2,ECCrefPublicKey	*A2,ECCrefPublicKey	*B,ECCrefPublicKey	*C);
	SGD_RV  SDF_InternalSignEx2_ECC(SGD_HANDLE	hSessionHandle,SGD_UINT32	uiISKIndex1,SGD_UINT32	uiISKIndex2,SGD_UCHAR	*pucData,SGD_UINT32	uiDataLength,ECCPoint	*P1,ECCSignatureEx	*sign);


};


#endif

