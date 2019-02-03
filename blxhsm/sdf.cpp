// blxhsm.cpp : 定义 DLL 应用程序的导出函数。
//
#include "sdf.h"
//#include "SessionObj.h"
#include <iostream>
#include <map>
#include "log.h"
#include "ConnectPool.h"
#include <Windows.h>
#include "typedef_exception.h"
#include "INIParser.h"
#include "ErrorCode.h"



//BOOL APIENTRY DllMain( HMODULE hModule,
//					  DWORD  ul_reason_for_call,
//					  LPVOID lpReserved
//					  )
//{
//	switch (ul_reason_for_call)
//	{
//	case DLL_PROCESS_ATTACH:
//	case DLL_THREAD_ATTACH:
//	case DLL_THREAD_DETACH:
//	case DLL_PROCESS_DETACH:
//		break;
//	}
//	return TRUE;
//}

CConnectPool CTP;
int poolsize;
int port;
string ip;
string passwd;

using namespace std;

typedef struct DeviceSessionInfo
{

    SGD_UINT16 uiSessionCount;
    CSessionObj *psObj;

} DeviceSessionInfo;


map<SGD_UINT32, DeviceSessionInfo> mDSI;

SGD_RV __cdecl SDF_OpenDevice(SGD_HANDLE *phDeviceHandle)
{

    SGD_RV rv = SDR_OK;
    INIParser ini_parser;

    ini_parser.ReadINI("config.ini");

    poolsize = ini_parser.GetInt("CONNECTPOOL", "poolsize");
    ip = ini_parser.GetValue("HSM", "ip");
    passwd = ini_parser.GetValue("HSM", "passwd");
    port = ini_parser.GetInt("HSM", "port");

    SGD_INT32 hDev = GetTickCount();

    //增加一个握手连接

    for (int i = 0 ; i != poolsize; i++)
    {
        SGD_UCHAR bCmd[64] = {0};
        SGD_UCHAR bRev[64] = {0};
        SGD_UINT32 uiRet = 0;
        SGD_UINT32 uiRevLen = 0;

        CNetObj nObj(ip, port, passwd);

        if (!nObj.Init())
        {
            rv = SWR_CONNECT_ERR;
            goto END;
        }

        CTP.CreateSession(nObj, hDev);

    }

    memcpy(phDeviceHandle, &hDev, 4);


END:
    return rv;
}
SGD_RV __cdecl SDF_CloseDevice(SGD_HANDLE hDeviceHandle)
{

    return 0;
}

SGD_RV __cdecl SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle)
{

    SGD_RV rv = SDR_OK;
    SGD_UINT32 uihDev = 0;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiRet = 0;
    SGD_UINT32 uiRevLen = 0;

GET:
    if (CTP.GetUnLockSession(hDeviceHandle, phSessionHandle))
    {
        CTP.LockSession(*phSessionHandle);

    }
    else
    {

        CNetObj nObj(ip, port, passwd);

        if (!nObj.Init())
        {
            rv = SWR_CONNECT_ERR;
            goto END;
        }

        memcpy(&uihDev, &hDeviceHandle, 4);
        CTP.CreateSession(nObj, uihDev);

        goto GET;
    }

END:
    return rv;
}

SGD_RV __cdecl SDF_CloseSession(SGD_HANDLE hSessionHandle)
{

    SGD_RV rv = SDR_OK;

    CTP.UnLockSession(hSessionHandle);

    return rv;
}


SGD_RV __cdecl SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength)
{

    SGD_RV rv = SDR_OK;

    try
    {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj)
        {
            rv = sObj->SDF_GetPrivateKeyAccessRight(uiKeyIndex, pucPassword, uiPwdLength);
        }
        else
        {
            rv = SWR_NO_AVAILABLE_HSM;
        }

    }
    catch (...)
    {
        LogMessage_tt("sdf.cpp", 1, 1, "SDF_GetPrivateKeyAccessRight");
    }

    return rv;
}

SGD_RV __cdecl SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex)
{
    return 0;
}

SGD_RV __cdecl SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
{

    SGD_RV rv = SDR_OK;

    try
    {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj)
        {
            rv = sObj->SDF_GetDeviceInfo(pstDeviceInfo);
        }
        else
        {
            rv = SWR_NO_AVAILABLE_HSM;
        }

    }
    catch (...)
    {
        LogMessage_tt("sdf.cpp", 1, 1, "SDF_GetDeviceInfo");
    }

    return rv;
}

SGD_RV __cdecl SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR *pucRandom)
{

    SGD_RV rv = SDR_OK;

    try
    {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj)
        {
            rv = sObj->SDF_GenerateRandom(uiLength, pucRandom);
        }
        else
        {
            rv = SWR_NO_AVAILABLE_HSM;
        }

    }
    catch (...)
    {
        LogMessage_tt("sdf.cpp", 1, 1, "SDF_GenerateRandom");
    }

    return rv;

}


//SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle){return 0;}
//SGD_RV SDF_CloseDevice(SGD_HANDLE hDeviceHandle){return 0;}

//SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle){return 0;}
//SGD_RV SDF_CloseSession(SGD_HANDLE hSessionHandle){return 0;}

//SGD_RV SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength){return 0;}
//SGD_RV SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex){return 0;}

//SGD_RV SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo){return 0;}
//SGD_RV SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR *pucRandom){return 0;}
SGD_RV SDF_GetKeyStatus(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount)
{
    return 0;
}
SGD_RV SDF_GetDeviceRunStatus(SGD_HANDLE hSessionHandle, DEVICE_RUN_STATUS *pstDeviceRunStatus)
{
    return 0;
}

/*非对称密码RSA密钥管理、运算函数*/
SGD_RV __cdecl SDF_GenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
    SGD_RV rv = SDR_OK;

    try
    {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj)
        {
            rv = sObj->SDF_GenerateKeyPair_RSA(uiKeyBits, pucPublicKey, pucPrivateKey);
        }
        else
        {
            rv = SWR_NO_AVAILABLE_HSM;
        }

    }
    catch (...)
    {
        LogMessage_tt("sdf.cpp", 1, 1, "SDF_GenerateKeyPair_RSA");
    }

    return rv;
}
SGD_RV __cdecl SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey)
//SGD_RV SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex)
{
    SGD_RV rv = SDR_OK;

    try
    {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj)
        {
            rv = sObj->SDF_ExportSignPublicKey_RSA(uiKeyIndex, pucPublicKey);
        }
        else
        {
            rv = SWR_NO_AVAILABLE_HSM;
        }

    }
    catch (...)
    {
        LogMessage_tt("sdf.cpp", 1, 1, "SDF_ExportSignPublicKey_RSA");
    }

    return rv;
}



SGD_RV __cdecl SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    SGD_RV rv = SDR_OK;

    try
    {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj)
        {
            rv = sObj->SDF_ExportEncPublicKey_RSA(uiKeyIndex, pucPublicKey);
        }
        else
        {
            rv = SWR_NO_AVAILABLE_HSM;
        }

    }
    catch (...)
    {
        LogMessage_tt("sdf.cpp", 1, 1, "SDF_ExportEncPublicKey_RSA");
    }

    return rv;
}
SGD_RV SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength)
{
    return 0;
}
SGD_RV SDF_ExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength)
{
    return 0;
}
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, SGD_UINT32  uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength)
{
    return 0;
}
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, SGD_UINT32  uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength)
{
    return 0;
}
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDEInput, SGD_UINT32  uiDELength, SGD_UCHAR *pucDEOutput, SGD_UINT32  *puiDELength)
{
    return 0;
}

/*非对称密码ECC密钥管理、运算函数*/
SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID, SGD_UINT32  uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    return 0;
}
SGD_RV SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    return 0;
}
SGD_RV SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    return 0;
}
SGD_RV SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}
SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, ECCSignature *pucSignature)
{
    return 0;
}
SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}
SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}
SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData)
{
    return 0;
}
SGD_RV SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32  *puiDataLength)
{
    return 0;
}
SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData)
{
    return 0;
}
SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32  *puiDataLength)
{
    return 0;
}
SGD_RV SDF_InternalSign_ECC_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}
SGD_RV SDF_InternalVerify_ECC_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}

SGD_RV SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey  *pucSponsorPublicKey, ECCrefPublicKey  *pucSponsorTmpPublicKey, SGD_HANDLE *phAgreementHandle)
{
    return 0;
}
SGD_RV SDF_GenerateKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey  *pucResponsePublicKey, ECCrefPublicKey  *pucResponseTmpPublicKey, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, SGD_UINT32  uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut)
{
    return 0;
}

/*对称密钥管理、密码运算函数*/
SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32  uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_GenerateKeyWithIPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_GenerateKeyWithEPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32  uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle)
{
    return 0;
}

SGD_RV SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_ImportKeyWithISK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle)
{
    return 0;
}

SGD_RV SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle)
{
    return 0;
}
SGD_RV SDF_GetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle)
{
    return 0;
}
SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, SGD_UINT32  *puiEncDataLength)
{
    return 0;
}
SGD_RV SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32  uiEncDataLength, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength)
{
    return 0;
}
SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, SGD_UINT32  *puiMACLength)
{
    return 0;
}

/*杂凑运算函数*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength)
{
    return 0;
}
SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength)
{
    return 0;
}
SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32  *puiHashLength)
{
    return 0;
}

/*用户文件操作函数*/
SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize)
{
    return 0;
}
SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 *puiReadLength, SGD_UCHAR *pucBuffer)
{
    return 0;
}
SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR *pucBuffer)
{
    return 0;
}
SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen)
{
    return 0;
}

/*自定义接口，总参PKCA扩展接口，仅总参专用密码机支持*/
SGD_RV	SDF_ImportECCKeyPair(SGD_HANDLE		hSessionHandle, SGD_UINT32	uiKeyNumber, ECCrefPublicKey	*puxPublicKey, ECCrefPrivateKey	*pucPrivateKey)
{
    return 0;
}
SGD_RV	SDF_InternalSignEx_ECC(SGD_HANDLE	hSessionHandle, SGD_UINT32	uiKeyNumber, SGD_UCHAR	*pucData, SGD_UINT32	uiDataLength, ECCPoint	*P1, ECCSignatureEx	*sign)
{
    return 0;
}
SGD_RV  SDF_ECCMultAdd(SGD_HANDLE	hSessionHandle, SGD_UINT32	k, ECCrefPrivateKey	*e, ECCrefPublicKey	*A, ECCrefPublicKey	*B, ECCrefPublicKey	*C)
{
    return 0;
}
SGD_RV  SDF_ECCModMultAdd(SGD_HANDLE	hSessionHandle, ECCrefPrivateKey	*k, ECCrefPrivateKey	*a, ECCrefPrivateKey	*b, ECCrefPrivateKey	*c)
{
    return 0;
}
SGD_RV  SDF_ECCMultAdd2(SGD_HANDLE	hSessionHandle, ECCrefPrivateKey	*e1, ECCrefPublicKey	*A1, ECCrefPrivateKey	*e2, ECCrefPublicKey	*A2, ECCrefPublicKey	*B, ECCrefPublicKey	*C)
{
    return 0;
}
SGD_RV  SDF_InternalSignEx2_ECC(SGD_HANDLE	hSessionHandle, SGD_UINT32	uiISKIndex1, SGD_UINT32	uiISKIndex2, SGD_UCHAR	*pucData, SGD_UINT32	uiDataLength, ECCPoint	*P1, ECCSignatureEx	*sign)
{
    return 0;
}

/**/
SGD_RV SWCSM_GenerateRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyBits)
{
    return 0;
}
SGD_RV SWCSM_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
    return 0;
}
SGD_RV SWCSM_SetPrivateKeyAccessPwd(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength)
{
    return 0;
}
SGD_RV SWMF_GenerateRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyBits)
{
    return 0;
}
SGD_RV SWMF_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
    return 0;
}
SGD_RV SWMF_SetPrivateKeyAccessPwd(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength)
{
    return 0;
}
SGD_RV SWMF_GenerateKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyLength)
{
    return 0;
}
SGD_RV SWMF_InputKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength)
{
    return 0;
}
SGD_RV SWCSM_GenerateRSAKeyPairEx(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyBits, SGD_UINT32 unPublicExponent, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
    return 0;
}
SGD_RV SDF_Encrypt_GCM(SGD_HANDLE hSessionHandle,
                       SGD_HANDLE hKeyHandle,
                       SGD_UINT32 uiAlgID,
                       SGD_UCHAR *pucIV,
                       SGD_UINT32 uiIVLength,
                       SGD_UCHAR *pucAAD,
                       SGD_UINT32 uiAADLength,
                       SGD_UCHAR *pucData,
                       SGD_UINT32 uiDataLength,
                       SGD_UCHAR *pucEncData,
                       SGD_UINT32  *puiEncDataLength,
                       SGD_UCHAR *pucTagData,
                       SGD_UINT32  *puiTagDataLength)
{
    return 0;
}
SGD_RV SDF_Decrypt_GCM(SGD_HANDLE hSessionHandle,
                       SGD_HANDLE hKeyHandle,
                       SGD_UINT32 uiAlgID,
                       SGD_UCHAR *pucIV,
                       SGD_UINT32 uiIVLength,
                       SGD_UCHAR *pucAAD,
                       SGD_UINT32 uiAADLength,
                       SGD_UCHAR *pucTag,              //输入，认证标签数据
                       SGD_UINT32 uiTagLength,         //输入，认证标签数据长度
                       SGD_UCHAR *pucEncData,          //输入，待解密的密文数据
                       SGD_UINT32 puiEncDataLength,    //输入，待解密的密文数据长度
                       SGD_UCHAR *pucData,             //输出，解密后的明文数据
                       SGD_UINT32  *uiDataLength,      //输出，解密后的明文数据长度
                       SGD_UINT32  *puiResult)
{
    return 0;   //输出，认证结果，1为认证通过，0为认证失败
}


SGD_RV SDF_ExportSignPublicKey_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, DSArefPublicKeyLite *pucPublicKey)
{
    return 0;
}
SGD_RV SDF_ExportEncPublicKey_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, DSArefPublicKeyLite *pucPublicKey)
{
    return 0;
}
SGD_RV SDF_InternalSign_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureDataLength)
{
    return 0;
}
SGD_RV SDF_InternalVerify_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureDataLength)
{
    return 0;
}
SGD_RV SDF_GenerateKeyPair_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID, SGD_UINT32  uiKeyBits, DSArefPublicKeyLite *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    return 0;
}
SGD_RV SDF_ExternalSign_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, DSArefPrivateKeyLite *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureLength)
{
    return 0;
}
SGD_RV SDF_ExternalVerify_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, DSArefPublicKeyLite *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureLength)
{
    return 0;
}