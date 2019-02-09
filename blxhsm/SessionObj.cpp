#include "SessionObj.h"

#include <stdlib.h>

#include <Windows.h>

#include "Protocal.h"

#define random(x) (rand() % x)

CSessionObj::CSessionObj(string ip, int port) {
    //this->nObj.ip = ip;
    //this->nObj.port = port;
    //this->pbObj = new CSDFB(this->nObj);
    //this->isBusy = false;
    //this->isAllocate = false;
}

CSessionObj::CSessionObj(CNetObj nObj) {
    this->nObj = nObj;
    //this->isBusy = false;
    //this->isAllocate = false;
}
CSessionObj::CSessionObj(void) {
}

CSessionObj::~CSessionObj(void) {
}

bool CSessionObj::Finalize() {
    return nObj.Finalize();
}

bool CSessionObj::Init(SGD_UINT32 uiDeviceHandle) {

    SessionHandle = (GetTickCount() + (random(100) + random(89) + 1) * 100);
    DevcieHandle = uiDeviceHandle;
    SocketID = nObj.SocketID;
    PoolLock = 0;
    HashID = 0;
    Index = 0;

    return true;
}

SGD_RV CSessionObj::SDF_GetDeviceInfo(DEVICEINFO *pstDeviceInfo) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[256] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiCmdLen = 0;
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;

    uiCmdLen = 0xc;

    memcpy(bCmd, &uiCmdLen, 4);
    memcpy(bCmd + 4, &uiTaskSN, 4);
    memcpy(bCmd + 4 + 4, "\x01\x00\x02\x00", 4);

    rv = nObj.SendCmd(bCmd, uiCmdLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    } else {

        memcpy(pstDeviceInfo, bRev + 4, uiRevLen - 4);
    }

    return rv;
}

SGD_RV CSessionObj::SDF_GenerateRandom(SGD_UINT32 uiLength, SGD_UCHAR *pucRandom) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiCmdLen = 0;
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;

    uiCmdLen = 0x10;

    memcpy(bCmd, &uiCmdLen, 4);
    memcpy(bCmd + 4, &uiTaskSN, 4);
    memcpy(bCmd + 4 + 4, "\x02\x00\x02\x00", 4);
    memcpy(bCmd + 4 + 4 + 4, &uiLength, 4);

    rv = nObj.SendCmd(bCmd, uiCmdLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    } else {

        memcpy(pucRandom, bRev + 4, uiLength);
    }

    return rv;
}

SGD_RV CSessionObj::SDF_GetPrivateKeyAccessRight(SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = htonl(0x02000200);
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ReleasePrivateKeyAccessRight(SGD_UINT32 uiKeyIndex) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_GetKeyStatus(SGD_UINT32 uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_GetDeviceRunStatus(DEVICE_RUN_STATUS *pstDeviceRunStatus) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

/*非对称密码RSA密钥管理、运算函数*/
SGD_RV CSessionObj::SDF_GenerateKeyPair_RSA(SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}
SGD_RV CSessionObj::SDF_ExportSignPublicKey_RSA(SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[1024 + 32] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiCmdLen = 0;
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;

    uiCmdLen = 0x14;

    memcpy(bCmd, &uiCmdLen, 4);
    memcpy(bCmd + 4, &uiTaskSN, 4);
    memcpy(bCmd + 4 + 4, "\x01\x00\x04\x00", 4);
    memcpy(bCmd + 4 + 4 + 4, &uiKeyIndex, 4);
    memcpy(bCmd + 4 + 4 + 4 + 4, "\x00\x02\x01\x00", 4);

    rv = nObj.SendCmd(bCmd, uiCmdLen, bRev, &uiRevLen, &uiRet);
    if (rv != SDR_OK) {
        return rv;
    }

    if (uiRet != 0) {
        rv = uiRet;
    } else {
        memcpy(pucPublicKey, bRev + 4, uiRevLen - 4);
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExportEncPublicKey_RSA(SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[1024 + 32] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiCmdLen = 0;
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;

    uiCmdLen = 0x14;

    memcpy(bCmd, &uiCmdLen, 4);
    memcpy(bCmd + 4, &uiTaskSN, 4);
    memcpy(bCmd + 4 + 4, "\x01\x00\x04\x00", 4);
    memcpy(bCmd + 4 + 4 + 4, &uiKeyIndex, 4);
    memcpy(bCmd + 4 + 4 + 4 + 4, "\x00\x01\x01\x00", 4);

    rv = nObj.SendCmd(bCmd, uiCmdLen, bRev, &uiRevLen, &uiRet);

    if (rv != SDR_OK) {
        return rv;
    }

    if (uiRet != 0) {
        rv = uiRet;
    } else {
        memcpy(pucPublicKey, bRev + 4, uiRevLen - 4);
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExternalPublicKeyOperation_RSA(RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_InternalPublicKeyOperation_RSA(SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_InternalPrivateKeyOperation_RSA(SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDEInput, SGD_UINT32 uiDELength, SGD_UCHAR *pucDEOutput, SGD_UINT32 *puiDELength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

/*非对称密码ECC密钥管理、运算函数*/
SGD_RV CSessionObj::SDF_GenerateKeyPair_ECC(SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExportSignPublicKey_ECC(SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExportEncPublicKey_ECC(SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};

    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};

    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;

    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);

    if (uiRet != 0) {
        rv = uiRet;
    }

    return rv;
}

SGD_RV CSessionObj::SDF_ExternalSign_ECC(SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExternalVerify_ECC(SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, ECCSignature *pucSignature) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalSign_ECC(SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalVerify_ECC(SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExternalEncrypt_ECC(SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExternalDecrypt_ECC(SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalEncrypt_ECC(SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalDecrypt_ECC(SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalSign_ECC_Ex(SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}
SGD_RV CSessionObj::SDF_InternalVerify_ECC_Ex(SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateAgreementDataWithECC(SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, SGD_HANDLE *phAgreementHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateKeyWithECC(SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateAgreementDataAndKeyWithECC(SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_UINT32 uiKeyIndex, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

/*对称密钥管理、密码运算函数*/
SGD_RV CSessionObj::SDF_GenerateKeyWithIPK_RSA(SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateKeyWithEPK_RSA(SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateKeyWithKEK(SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateKeyWithIPK_ECC(SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateKeyWithEPK_ECC(SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ImportKeyWithISK_RSA(SGD_UINT32 uiISKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ImportKeyWithKEK(SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ImportKeyWithISK_ECC(SGD_UINT32 uiISKIndex, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ImportKey(SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_DestroyKey(SGD_HANDLE hKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GetSymmKeyHandle(SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_Encrypt(SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_Decrypt(SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_CalculateMAC(SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, SGD_UINT32 *puiMACLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

/*杂凑运算函数*/
SGD_RV CSessionObj::SDF_HashInit(SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_HashUpdate(SGD_UCHAR *pucData, SGD_UINT32 uiDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_HashFinal(SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

/*用户文件操作函数*/
SGD_RV CSessionObj::SDF_CreateFile(SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ReadFile(SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 *puiReadLength, SGD_UCHAR *pucBuffer) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_WriteFile(SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR *pucBuffer) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_DeleteFile(SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

/*自定义接口，总参PKCA扩展接口，仅总参专用密码机支持*/
SGD_RV CSessionObj::SDF_ImportECCKeyPair(SGD_UINT32 uiKeyNumber, ECCrefPublicKey *puxPublicKey, ECCrefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalSignEx_ECC(SGD_UINT32 uiKeyNumber, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCPoint *P1, ECCSignatureEx *sign) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ECCMultAdd(SGD_UINT32 k, ECCrefPrivateKey *e, ECCrefPublicKey *A, ECCrefPublicKey *B, ECCrefPublicKey *C) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ECCModMultAdd(ECCrefPrivateKey *k, ECCrefPrivateKey *a, ECCrefPrivateKey *b, ECCrefPrivateKey *c) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ECCMultAdd2(ECCrefPrivateKey *e1, ECCrefPublicKey *A1, ECCrefPrivateKey *e2, ECCrefPublicKey *A2, ECCrefPublicKey *B, ECCrefPublicKey *C) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalSignEx2_ECC(SGD_UINT32 uiISKIndex1, SGD_UINT32 uiISKIndex2, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCPoint *P1, ECCSignatureEx *sign) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWCSM_GenerateRSAKeyPair(SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyBits) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWCSM_InputRSAKeyPair(SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWCSM_SetPrivateKeyAccessPwd(SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWMF_GenerateRSAKeyPair(SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyBits) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWMF_InputRSAKeyPair(SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWMF_SetPrivateKeyAccessPwd(SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWMF_GenerateKEK(SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWMF_InputKEK(SGD_UINT32 uiKeyNumber, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SWCSM_GenerateRSAKeyPairEx(SGD_UINT32 uiKeyNumber, SGD_UINT32 uiKeyBits, SGD_UINT32 unPublicExponent, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_Encrypt_GCM(SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UINT32 uiIVLength,
                                    SGD_UCHAR *pucAAD, SGD_UINT32 uiAADLength, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength,
                                    SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength, SGD_UCHAR *pucTagData, SGD_UINT32 *puiTagDataLength) {
    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_Decrypt_GCM(SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UINT32 uiIVLength,
                                    SGD_UCHAR *pucAAD, SGD_UINT32 uiAADLength, SGD_UCHAR *pucTag,
                                    SGD_UINT32 uiTagLength, SGD_UCHAR *pucEncData,
                                    SGD_UINT32 puiEncDataLength, SGD_UCHAR *pucData,
                                    SGD_UINT32 *uiDataLength, SGD_UINT32 *puiResult) {
    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExportSignPublicKey_DSA(SGD_UINT32 uiKeyIndex, DSArefPublicKeyLite *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExportEncPublicKey_DSA(SGD_UINT32 uiKeyIndex, DSArefPublicKeyLite *pucPublicKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalSign_DSA(SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_InternalVerify_DSA(SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureDataLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_GenerateKeyPair_DSA(SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits, DSArefPublicKeyLite *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExternalSign_DSA(SGD_UINT32 uiAlgID, DSArefPrivateKeyLite *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}

SGD_RV CSessionObj::SDF_ExternalVerify_DSA(SGD_UINT32 uiAlgID, DSArefPublicKeyLite *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureLength) {

    SGD_RV rv = SDR_OK;
    SGD_UCHAR bCmd[64] = {0};
    SGD_UCHAR bRev[64] = {0};
    SGD_UINT32 uiTaskSN = GetTickCount();
    SGD_UINT32 uiRevLen = 0;
    SGD_UINT32 uiRet = 0;
    Request req = {0};
    req.commandLen = 0x10;
    req.taskSN = uiTaskSN;
    req.command = 0x02000200;
    req;
    rv = nObj.SendCmd((unsigned char *)&req, req.commandLen, bRev, &uiRevLen, &uiRet);
    if (uiRet != 0) {
        rv = uiRet;
    }
    return rv;
}
