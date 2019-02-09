// blxhsm.cpp : 定义 DLL 应用程序的导出函数。
//
#include "sdf.h"
//#include "SessionObj.h"
#include <iostream>
#include <map>

#define GOOGLE_GLOG_DLL_DECL //glog静态链接库需要
#include "glog/logging.h"
#include "glog/log_severity.h"

#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif


#include "ConnectPool.h"
#include <Windows.h>
#include "typedef_exception.h"
#include "INIParser.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        char *fileName = getcwd(nullptr, 0);
        FLAGS_log_dir = fileName;
        google::InitGoogleLogging((std::string(fileName)+"\\blxhsm.dll").c_str());
        free(fileName);
    }
    break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        google::ShutdownGoogleLogging();
        break;
    }
    return TRUE;
}

CConnectPool CTP;
int poolsize;
int port;
string ip;
string passwd;

using namespace std;

typedef struct DeviceSessionInfo {

    SGD_UINT16 uiSessionCount;
    CSessionObj *psObj;

} DeviceSessionInfo;

map<SGD_UINT32, DeviceSessionInfo> mDSI;

SGD_RV __cdecl SDF_OpenDevice(SGD_HANDLE *phDeviceHandle) {

    SGD_RV rv = SDR_OK;
    INIParser ini_parser;

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *pChar = strrchr(path, '\\');
    if (pChar != NULL) {
        strcpy(pChar + 1, "config.ini");
    }

    ini_parser.ReadINI(path);

    poolsize = ini_parser.GetInt("CONNECTPOOL", "poolsize");
    ip = ini_parser.GetValue("HSM", "ip");
    passwd = ini_parser.GetValue("HSM", "passwd");
    port = ini_parser.GetInt("HSM", "port");

    SGD_INT32 hDev = GetTickCount();

    //增加一个握手连接

    for (int i = 0; i != poolsize; i++) {
        SGD_UCHAR bCmd[64] = {0};
        SGD_UCHAR bRev[64] = {0};
        SGD_UINT32 uiRet = 0;
        SGD_UINT32 uiRevLen = 0;

        CNetObj nObj(ip, port, passwd);

        rv = nObj.Init();
        if (rv != SDR_OK) {
            goto END;
        }

        LOG(INFO) << "session 连接创建成功";

        CTP.CreateSession(nObj, hDev);
    }

    memcpy(phDeviceHandle, &hDev, 4);

END:
    return rv;
}
SGD_RV __cdecl SDF_CloseDevice(SGD_HANDLE hDeviceHandle) {

    SGD_RV rv = SDR_OK;
    if(!CTP.DelDeviceSessions((SGD_UINT32)hDeviceHandle)) {
        rv = SDR_UNKNOWERR;
    }
    return rv;
}

SGD_RV __cdecl SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UINT32 uihDev = 0;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiRet = 0;
    SGD_UINT32 uiRevLen = 0;

GET:
    if (CTP.GetUnLockSession(hDeviceHandle, phSessionHandle)) {
        CTP.LockSession(*phSessionHandle);
    } else {

        CNetObj nObj(ip, port, passwd);

        rv = nObj.Init();
        if (rv != SDR_OK) {
            goto END;
        }

        memcpy(&uihDev, &hDeviceHandle, 4);
        CTP.CreateSession(nObj, uihDev);

        goto GET;
    }

END:
    return rv;
}

SGD_RV __cdecl SDF_CloseSession(SGD_HANDLE hSessionHandle) {

    SGD_RV rv = SDR_OK;

    CTP.UnLockSession(hSessionHandle);

    return rv;
}

SGD_RV __cdecl SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength) {

    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GetPrivateKeyAccessRight(uiKeyIndex, pucPassword, uiPwdLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GetPrivateKeyAccessRight exception";
    }

    return rv;
}

SGD_RV __cdecl SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ReleasePrivateKeyAccessRight(uiKeyIndex);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ReleasePrivateKeyAccessRight exception";
    }

    return rv;
}

SGD_RV __cdecl SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo) {

    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GetDeviceInfo(pstDeviceInfo);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GetDeviceInfo exception";
    }

    return rv;
}

SGD_RV __cdecl SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR *pucRandom) {

    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GenerateRandom(uiLength, pucRandom);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateRandom exception";
    }

    return rv;
}

SGD_RV SDF_GetKeyStatus(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount) {

    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GetKeyStatus(uiKeyType, puiKeyStatus, puiKeyCount);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GetKeyStatus exception";
    }

    return rv;
}

SGD_RV SDF_GetDeviceRunStatus(SGD_HANDLE hSessionHandle, DEVICE_RUN_STATUS *pstDeviceRunStatus) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GetDeviceRunStatus(pstDeviceRunStatus);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GetDeviceRunStatus exception";
    }

    return rv;
}

/*非对称密码RSA密钥管理、运算函数*/
SGD_RV __cdecl SDF_GenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,
                                       RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyPair_RSA(uiKeyBits, pucPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyPair_RSA exception";
    }

    return rv;
}

SGD_RV __cdecl SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey)
//SGD_RV SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex)
{
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExportSignPublicKey_RSA(uiKeyIndex, pucPublicKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExportSignPublicKey_RSA exception";
    }

    return rv;
}

SGD_RV __cdecl SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExportEncPublicKey_RSA(uiKeyIndex, pucPublicKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExportEncPublicKey_RSA exception";
    }

    return rv;
}

SGD_RV SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey,
        SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExternalPublicKeyOperation_RSA(pucPublicKey, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalPublicKeyOperation_RSA exception";
    }

    return rv;
}

SGD_RV SDF_ExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey,
        SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput,
        SGD_UINT32 *puiOutputLength) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExternalPrivateKeyOperation_RSA(pucPrivateKey, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalPrivateKeyOperation_RSA exception";
    }

    return rv;
}

SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage,
        SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_InternalPublicKeyOperation_RSA(uiKeyIndex, uiKeyUsage, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalPublicKeyOperation_RSA exception";
    }

    return rv;
}

SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,
        SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_InternalPrivateKeyOperation_RSA(uiKeyIndex, uiKeyUsage, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalPrivateKeyOperation_RSA exception";
    }

    return rv;
}

SGD_RV SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,
        RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDEInput, SGD_UINT32 uiDELength, SGD_UCHAR *pucDEOutput, SGD_UINT32 *puiDELength) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExchangeDigitEnvelopeBaseOnRSA(uiKeyIndex, pucPublicKey, pucDEInput, uiDELength, pucDEOutput, puiDELength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExchangeDigitEnvelopeBaseOnRSA exception";
    }

    return rv;
}

/*非对称密码ECC密钥管理、运算函数*/
SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,
                               SGD_UINT32 uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) {
    SGD_RV rv = SDR_OK;

    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyPair_ECC(uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyPair_ECC exception";
    }

    return rv;
}

SGD_RV SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExportSignPublicKey_ECC(uiKeyIndex, pucPublicKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExportSignPublicKey_ECC exception";
    }

    return rv;
}

SGD_RV SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);

        if (NULL != sObj) {
            rv = sObj->SDF_ExportEncPublicKey_ECC(uiKeyIndex, pucPublicKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExportEncPublicKey_ECC exception";
    }

    return rv;
}

SGD_RV SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,
                            ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExternalSign_ECC(uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalSign_ECC exception";
    }
    return rv;
}

SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,
                              ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, ECCSignature *pucSignature) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExternalVerify_ECC(uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucSignature);;
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalVerify_ECC exception";
    }
    return rv;
}

SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle,
                            SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalSign_ECC(uiISKIndex, pucData, uiDataLength, pucSignature);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalSign_ECC exception";
    }
    return rv;
}

SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle,
                              SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalVerify_ECC(uiISKIndex, pucData, uiDataLength, pucSignature);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalVerify_ECC exception";
    }
    return rv;
}

SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,
                               ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExternalEncrypt_ECC(uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalEncrypt_ECC exception";
    }
    return rv;
}

SGD_RV SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,
                               ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExternalDecrypt_ECC(uiAlgID, pucPrivateKey, pucEncData, pucData, puiDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalDecrypt_ECC exception";
    }
    return rv;
}

SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,
                               SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalEncrypt_ECC(uiISKIndex, uiAlgID, pucData, uiDataLength, pucEncData);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalEncrypt_ECC exception";
    }
    return rv;
}

SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,
                               SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalDecrypt_ECC(uiISKIndex, uiAlgID, pucEncData, pucData, puiDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalDecrypt_ECC exception";
    }
    return rv;
}

SGD_RV SDF_InternalSign_ECC_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,
                               SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalSign_ECC_Ex(uiISKIndex, uiAlgID, pucData, uiDataLength, pucSignature);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalSign_ECC_Ex exception";
    }
    return rv;
}

SGD_RV SDF_InternalVerify_ECC_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,
                                 SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalVerify_ECC_Ex(uiISKIndex, uiAlgID, pucData, uiDataLength, pucSignature);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalVerify_ECC_Ex exception";
    }
    return rv;
}

SGD_RV SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,
                                        SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength,
                                        ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
                                        SGD_HANDLE *phAgreementHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateAgreementDataWithECC(uiISKIndex, uiKeyBits, pucSponsorID, uiSponsorIDLength,
                    pucSponsorPublicKey, pucSponsorTmpPublicKey, phAgreementHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateAgreementDataWithECC exception";
    }
    return rv;
}

SGD_RV SDF_GenerateKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucResponseID,
                              SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
                              ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyWithECC(pucResponseID, uiResponseIDLength,
                                              pucResponsePublicKey,pucResponseTmpPublicKey, hAgreementHandle, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyWithECC exception";
    }
    return rv;
}

SGD_RV SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,
        SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, SGD_UCHAR *pucSponsorID,
        SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
        ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateAgreementDataAndKeyWithECC(uiISKIndex, uiKeyBits, pucResponseID, uiResponseIDLength,
                    pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey, pucResponsePublicKey,
                    pucResponseTmpPublicKey, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateAgreementDataAndKeyWithECC exception";
    }
    return rv;
}

SGD_RV SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,
        SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExchangeDigitEnvelopeBaseOnECC(uiKeyIndex, uiAlgID, pucPublicKey, pucEncDataIn, pucEncDataOut);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExchangeDigitEnvelopeBaseOnECC exception";
    }
    return rv;
}

/*对称密钥管理、密码运算函数*/
SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits,
                                  SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyWithIPK_RSA(uiIPKIndex, uiKeyBits, pucKey, puiKeyLength, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyWithIPK_RSA exception";
    }
    return rv;
}

SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey,
                                  SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyWithEPK_RSA(uiKeyBits, pucPublicKey, pucKey, puiKeyLength, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyWithEPK_RSA exception";
    }
    return rv;
}

SGD_RV SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID,
                              SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyWithKEK(uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyWithKEK exception";
    }
    return rv;
}

SGD_RV SDF_GenerateKeyWithIPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits,
                                  ECCCipher *pucKey, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyWithIPK_ECC(uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyWithIPK_ECC exception";
    }
    return rv;
}

SGD_RV SDF_GenerateKeyWithEPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID,
                                  ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyWithEPK_ECC(uiKeyBits, uiAlgID, pucPublicKey, pucKey, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyWithEPK_ECC exception";
    }
    return rv;
}

SGD_RV SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucKey,
                                SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ImportKeyWithISK_RSA(uiISKIndex, pucKey, uiKeyLength, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ImportKeyWithISK_RSA exception";
    }
    return rv;
}

SGD_RV SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex,
                            SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ImportKeyWithKEK(uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ImportKeyWithKEK exception";
    }
    return rv;
}

SGD_RV SDF_ImportKeyWithISK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ImportKeyWithISK_ECC(uiISKIndex, pucKey, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ImportKeyWithISK_ECC exception";
    }
    return rv;
}

SGD_RV SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ImportKey(pucKey, uiKeyLength, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ImportKey exception";
    }
    return rv;
}

SGD_RV SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_DestroyKey(hKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_DestroyKey exception";
    }
    return rv;
}

SGD_RV SDF_GetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GetSymmKeyHandle(uiKeyIndex, phKeyHandle);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GetSymmKeyHandle exception";
    }
    return rv;
}

SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID,
                   SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_Encrypt(hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, puiEncDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_Encrypt exception";
    }
    return rv;
}

SGD_RV SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID,
                   SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_Decrypt(hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucData, puiDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_Decrypt exception";
    }
    return rv;
}

SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID,
                        SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, SGD_UINT32 *puiMACLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_CalculateMAC(hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC, puiMACLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_CalculateMAC exception";
    }
    return rv;
}

/*凑运算函数*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_HashInit(uiAlgID, pucPublicKey, pucID, uiIDLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_HashInit exception";
    }
    return rv;
}

SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_HashUpdate(pucData, uiDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_HashUpdate exception";
    }
    return rv;
}

SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_HashFinal(pucHash, puiHashLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_HashFinal exception";
    }
    return rv;
}

/*用户文件操作函数*/
SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_CreateFile(pucFileName, uiNameLen, uiFileSize);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_CreateFile exception";
    }
    return rv;
}

SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen,
                    SGD_UINT32 uiOffset, SGD_UINT32 *puiReadLength, SGD_UCHAR *pucBuffer) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ReadFile(pucFileName, uiNameLen, uiOffset, puiReadLength, pucBuffer);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ReadFile exception";
    }
    return rv;
}

SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen,
                     SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR *pucBuffer) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_WriteFile(pucFileName, uiNameLen, uiOffset, uiWriteLength, pucBuffer);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_WriteFile exception";
    }
    return rv;
}

SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_DeleteFile(pucFileName, uiNameLen);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_DeleteFile exception";
    }
    return rv;
}

/*自定义接口，总参PKCA扩展接口，仅总参专用密码机支持*/
SGD_RV SDF_ImportECCKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, ECCrefPublicKey *puxPublicKey,
                            ECCrefPrivateKey *pucPrivateKey) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ImportECCKeyPair(uiKeyNumber, puxPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ImportECCKeyPair exception";
    }
    return rv;
}

SGD_RV SDF_InternalSignEx_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UCHAR *pucData,
                              SGD_UINT32 uiDataLength, ECCPoint *P1, ECCSignatureEx *sign) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalSignEx_ECC(uiKeyNumber, pucData, uiDataLength, P1, sign);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalSignEx_ECC exception";
    }
    return rv;
}

SGD_RV SDF_ECCMultAdd(SGD_HANDLE hSessionHandle, SGD_UINT32 k, ECCrefPrivateKey *e, ECCrefPublicKey *A, ECCrefPublicKey *B, ECCrefPublicKey *C) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ECCMultAdd(k, e, A, B, C);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ECCMultAdd exception";
    }
    return rv;
}

SGD_RV SDF_ECCModMultAdd(SGD_HANDLE hSessionHandle, ECCrefPrivateKey *k, ECCrefPrivateKey *a, ECCrefPrivateKey *b, ECCrefPrivateKey *c) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ECCModMultAdd(k, a, b, c);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ECCModMultAdd exception";
    }
    return rv;
}

SGD_RV SDF_ECCMultAdd2(SGD_HANDLE hSessionHandle, ECCrefPrivateKey *e1, ECCrefPublicKey *A1,
                       ECCrefPrivateKey *e2, ECCrefPublicKey *A2, ECCrefPublicKey *B, ECCrefPublicKey *C) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ECCMultAdd2(e1, A1, e2, A2, B, C);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ECCMultAdd2 exception";
    }
    return rv;
}

SGD_RV SDF_InternalSignEx2_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex1,
                               SGD_UINT32 uiISKIndex2, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCPoint *P1, ECCSignatureEx *sign) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalSignEx2_ECC(uiISKIndex1, uiISKIndex2, pucData, uiDataLength, P1, sign);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalSignEx2_ECC exception";
    }
    return rv;
}

/**/
SGD_RV SWCSM_GenerateRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyBits) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWCSM_GenerateRSAKeyPair(uiKeyNumber, uiKeyBits);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWCSM_GenerateRSAKeyPair exception";
    }
    return rv;
}

SGD_RV SWCSM_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWCSM_InputRSAKeyPair(uiKeyNumber, pucPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWCSM_InputRSAKeyPair exception";
    }
    return rv;
}

SGD_RV SWCSM_SetPrivateKeyAccessPwd(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWCSM_SetPrivateKeyAccessPwd(uiKeyIndex, pucPassword, uiPwdLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWCSM_SetPrivateKeyAccessPwd exception";
    }
    return rv;
}

SGD_RV SWMF_GenerateRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyBits) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWMF_GenerateRSAKeyPair(uiKeyNumber, uiKeyBits);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWMF_GenerateRSAKeyPair exception";
    }
    return rv;
}

SGD_RV SWMF_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWMF_InputRSAKeyPair(uiKeyNumber, pucPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWMF_InputRSAKeyPair exception";
    }
    return rv;
}

SGD_RV SWMF_SetPrivateKeyAccessPwd(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWMF_SetPrivateKeyAccessPwd(uiKeyIndex, pucPassword, uiPwdLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWMF_SetPrivateKeyAccessPwd exception";
    }
    return rv;
}

SGD_RV SWMF_GenerateKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWMF_GenerateKEK(uiKeyNumber, uiKeyLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWMF_GenerateKEK exception";
    }
    return rv;
}

SGD_RV SWMF_InputKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWMF_InputKEK(uiKeyNumber, pucKey, uiKeyLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWMF_InputKEK exception";
    }
    return rv;
}

SGD_RV SWCSM_GenerateRSAKeyPairEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyBits,
                                  SGD_UINT32 unPublicExponent, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SWCSM_GenerateRSAKeyPairEx(uiKeyNumber, uiKeyBits, unPublicExponent, pucPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SWCSM_GenerateRSAKeyPairEx exception";
    }
    return rv;
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
                       SGD_UINT32 *puiEncDataLength,
                       SGD_UCHAR *pucTagData,
                       SGD_UINT32 *puiTagDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_Encrypt_GCM(hKeyHandle, uiAlgID, pucIV, uiIVLength, pucAAD,
                                       uiAADLength, pucData, uiDataLength, pucEncData, puiEncDataLength, pucTagData, puiTagDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_Encrypt_GCM exception";
    }
    return rv;
}

SGD_RV SDF_Decrypt_GCM(SGD_HANDLE hSessionHandle,
                       SGD_HANDLE hKeyHandle,
                       SGD_UINT32 uiAlgID,
                       SGD_UCHAR *pucIV,
                       SGD_UINT32 uiIVLength,
                       SGD_UCHAR *pucAAD,
                       SGD_UINT32 uiAADLength,
                       SGD_UCHAR *pucTag,           //输入，认证标签数据
                       SGD_UINT32 uiTagLength,      //输入，认证标签数据长度
                       SGD_UCHAR *pucEncData,       //输入，待解密的密文数据
                       SGD_UINT32 puiEncDataLength, //输入，待解密的密文数据长度
                       SGD_UCHAR *pucData,          //输出，解密后的明文数据
                       SGD_UINT32 *uiDataLength,    //输出，解密后的明文数据长度
                       SGD_UINT32 *puiResult) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_Decrypt_GCM(hKeyHandle, uiAlgID, pucIV, uiIVLength, pucAAD, uiAADLength,
                                       pucTag, uiTagLength, pucEncData,
                                       puiEncDataLength, pucData, uiDataLength, puiResult);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_Decrypt_GCM exception";
    }
    return rv; //输出，认证结果，1为认证通过，0为认证失败
}

SGD_RV SDF_ExportSignPublicKey_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, DSArefPublicKeyLite *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExportSignPublicKey_DSA(uiKeyIndex, pucPublicKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExportSignPublicKey_DSA exception";
    }
    return rv;
}

SGD_RV SDF_ExportEncPublicKey_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, DSArefPublicKeyLite *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExportEncPublicKey_DSA(uiKeyIndex, pucPublicKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExportEncPublicKey_DSA exception";
    }
    return rv;
}

SGD_RV SDF_InternalSign_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData,
                            SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalSign_DSA(uiISKIndex, uiAlgID, pucData, uiDataLength, pucSignature, uiSignatureDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalSign_DSA exception";
    }
    return rv;
}

SGD_RV SDF_InternalVerify_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID,
                              SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureDataLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_InternalVerify_DSA(uiISKIndex, uiAlgID, pucData, uiDataLength, pucSignature, uiSignatureDataLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_InternalVerify_DSA exception";
    }
    return rv;
}

SGD_RV SDF_GenerateKeyPair_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits,
                               DSArefPublicKeyLite *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_GenerateKeyPair_DSA(uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_GenerateKeyPair_DSA exception";
    }
    return rv;
}

SGD_RV SDF_ExternalSign_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, DSArefPrivateKeyLite *pucPrivateKey,
                            SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExternalSign_DSA(uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature, uiSignatureLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalSign_DSA exception";
    }
    return rv;
}

SGD_RV SDF_ExternalVerify_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, DSArefPublicKeyLite *pucPublicKey,
                              SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureLength) {
    SGD_RV rv = SDR_OK;
    try {
        CSessionObj *sObj = CTP.GetLockSession(hSessionHandle);
        if (NULL != sObj) {
            rv = sObj->SDF_ExternalVerify_DSA(uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucSignature, uiSignatureLength);
        } else {
            rv = SWR_NO_AVAILABLE_HSM;
        }
    } catch (...) {
        LOG(ERROR) << "SDF_ExternalVerify_DSA exception";
    }
    return rv;
}