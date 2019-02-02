/*
* File: swsds.h
* Copyright (c) sansec 2015
*
*/

#ifndef _SW_SDS_H_
#define _SW_SDS_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

/*RSA最大模长定义*/
#define SGD_RSA_MAX_BITS    4096

/*数据类型定义*/
typedef char				SGD_CHAR;
typedef char				SGD_INT8;
typedef short				SGD_INT16;
typedef int					SGD_INT32;
typedef long long			SGD_INT64;
typedef unsigned char		SGD_UCHAR;
typedef unsigned char		SGD_UINT8;
typedef unsigned short		SGD_UINT16;
typedef unsigned int		SGD_UINT32;
typedef unsigned long long	SGD_UINT64;
typedef unsigned int        SGD_RV;
typedef void				*SGD_OBJ;
typedef int					SGD_BOOL;
typedef void				*SGD_HANDLE;

/*设备信息*/
typedef struct DeviceInfo_st
{
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int  DeviceVersion;
    unsigned int  StandardVersion;
    unsigned int  AsymAlgAbility[2];
    unsigned int  SymAlgAbility;
    unsigned int  HashAlgAbility;
    unsigned int  BufferSize;
} DEVICEINFO;

typedef struct st_DeviceRunStatus
{
    unsigned int onboot;		//服务是否开机自启动
    unsigned int service;		//当前服务状态，0-未启动，1-已启动，>1状态异常
    unsigned int concurrency;	//当前并发数
    unsigned int memtotal;		//内存大小
    unsigned int memfree;		//内存空闲
    unsigned int cpu;			//CPU占用率，不包含小数点部分
    unsigned int reserve1;
    unsigned int reserve2;
} DEVICE_RUN_STATUS;

/*RSA密钥*/
#define LiteRSAref_MAX_BITS    2048
#define LiteRSAref_MAX_LEN     ((LiteRSAref_MAX_BITS + 7) / 8)
#define LiteRSAref_MAX_PBITS   ((LiteRSAref_MAX_BITS + 1) / 2)
#define LiteRSAref_MAX_PLEN    ((LiteRSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKeyLite_st
{
    unsigned int  bits;
    unsigned char m[LiteRSAref_MAX_LEN];
    unsigned char e[LiteRSAref_MAX_LEN];
} RSArefPublicKeyLite;

typedef struct RSArefPrivateKeyLite_st
{
    unsigned int  bits;
    unsigned char m[LiteRSAref_MAX_LEN];
    unsigned char e[LiteRSAref_MAX_LEN];
    unsigned char d[LiteRSAref_MAX_LEN];
    unsigned char prime[2][LiteRSAref_MAX_PLEN];
    unsigned char pexp[2][LiteRSAref_MAX_PLEN];
    unsigned char coef[LiteRSAref_MAX_PLEN];
} RSArefPrivateKeyLite;

#define ExRSAref_MAX_BITS    4096
#define ExRSAref_MAX_LEN     ((ExRSAref_MAX_BITS + 7) / 8)
#define ExRSAref_MAX_PBITS   ((ExRSAref_MAX_BITS + 1) / 2)
#define ExRSAref_MAX_PLEN    ((ExRSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKeyEx_st
{
    unsigned int  bits;
    unsigned char m[ExRSAref_MAX_LEN];
    unsigned char e[ExRSAref_MAX_LEN];
} RSArefPublicKeyEx;

typedef struct RSArefPrivateKeyEx_st
{
    unsigned int  bits;
    unsigned char m[ExRSAref_MAX_LEN];
    unsigned char e[ExRSAref_MAX_LEN];
    unsigned char d[ExRSAref_MAX_LEN];
    unsigned char prime[2][ExRSAref_MAX_PLEN];
    unsigned char pexp[2][ExRSAref_MAX_PLEN];
    unsigned char coef[ExRSAref_MAX_PLEN];
} RSArefPrivateKeyEx;

#if defined(SGD_RSA_MAX_BITS) && (SGD_RSA_MAX_BITS > LiteRSAref_MAX_BITS)
#define RSAref_MAX_BITS    ExRSAref_MAX_BITS
#define RSAref_MAX_LEN     ExRSAref_MAX_LEN
#define RSAref_MAX_PBITS   ExRSAref_MAX_PBITS
#define RSAref_MAX_PLEN    ExRSAref_MAX_PLEN

typedef struct RSArefPublicKeyEx_st  RSArefPublicKey;
typedef struct RSArefPrivateKeyEx_st  RSArefPrivateKey;
#else
#define RSAref_MAX_BITS    LiteRSAref_MAX_BITS
#define RSAref_MAX_LEN     LiteRSAref_MAX_LEN
#define RSAref_MAX_PBITS   LiteRSAref_MAX_PBITS
#define RSAref_MAX_PLEN    LiteRSAref_MAX_PLEN

typedef struct RSArefPublicKeyLite_st  RSArefPublicKey;
typedef struct RSArefPrivateKeyLite_st  RSArefPrivateKey;
#endif

/*ECC密钥*/
#define ECCref_MAX_BITS			256
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN	136

typedef struct ECCrefPublicKey_st
{
    unsigned int  bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int  bits;
    unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st
{
    int clength;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char C[ECCref_MAX_CIPHER_LEN];
    unsigned char M[ECCref_MAX_LEN];
} ECCCipher;

typedef struct ECCSignature_st
{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

typedef struct ECCPoint_st
{
    unsigned char  x[ECCref_MAX_LEN];
    unsigned char  y[ECCref_MAX_LEN];
} ECCPoint;

// 扩展的签名结构定义
typedef  struct  ECCSignatureEx_st
{
    ECCPoint	R;
    unsigned char  	s[ECCref_MAX_LEN];
} ECCSignatureEx;

#define ECDSAref_MAX_BITS		640
#define ECDSAref_MAX_LEN			((ECDSAref_MAX_BITS+7) / 8)


typedef struct ECDSArefPublicKey_st
{
    unsigned int  bits;
    unsigned char x[ECDSAref_MAX_LEN];
    unsigned char y[ECDSAref_MAX_LEN];
} ECDSArefPublicKey;

typedef struct ECDSArefPrivateKey_st
{
    unsigned int  bits;
    unsigned char D[ECDSAref_MAX_LEN];
} ECDSArefPrivateKey;

typedef struct ECDSASignature_st
{
    unsigned char r[ECDSAref_MAX_LEN];
    unsigned char s[ECDSAref_MAX_LEN];
} ECDSASignature;

#define LiteDSAref_MAX_BITS    2048
#define LiteDSAref_MAX_LEN     ((LiteDSAref_MAX_BITS + 7) / 8)
#define LiteDSAref_MAX_QLEN   32

typedef struct DSArefPublicKeyLite_st
{
    unsigned int  bits;
    unsigned char p[LiteDSAref_MAX_LEN];
    unsigned char q[LiteDSAref_MAX_QLEN];
    unsigned char g[LiteDSAref_MAX_LEN];
    unsigned char pub_key[LiteDSAref_MAX_LEN];
} DSArefPublicKeyLite;

typedef struct DSArefPrivateKeyLite_st
{
    unsigned int  bits;
    unsigned char p[LiteDSAref_MAX_LEN];
    unsigned char q[LiteDSAref_MAX_QLEN];
    unsigned char g[LiteDSAref_MAX_LEN];
    unsigned char pub_key[LiteDSAref_MAX_LEN];
    unsigned char priv_key[LiteDSAref_MAX_QLEN];
} DSArefPrivateKeyLite;

typedef struct DSASignature_st
{
    unsigned char r[LiteDSAref_MAX_QLEN];
    unsigned char s[LiteDSAref_MAX_QLEN];
} DSASignature;
typedef struct KeyHandleInfo_st
{
    SGD_HANDLE hSessionHandle;
    unsigned int nKeyType;
    unsigned int nID;
    unsigned int nLength;
    unsigned char  pbKey[32];
} KEY_INFO, *KEY_HANDLE;

/*常量定义*/
#define SGD_TRUE	0x00000001
#define SGD_FALSE	0x00000000

/*算法标识*/
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_AES_ECB		0x00000401
#define SGD_AES_CBC		0x00000402
#define SGD_AES_CFB		0x00000404
#define SGD_AES_OFB		0x00000408
#define SGD_AES_MAC		0x00000410
#define SGD_AES_CTR		0x00000420
#define SGD_AES_GCM_256	0x00000440

#define SGD_3DES_ECB	0x00000801
#define SGD_3DES_CBC	0x00000802
#define SGD_3DES_CFB	0x00000804
#define SGD_3DES_OFB	0x00000808
#define SGD_3DES_MAC	0x00000810
#define SGD_3DES_CTR	0x00000820

#define SGD_SMS4_ECB	0x00002001
#define SGD_SMS4_CBC	0x00002002
#define SGD_SMS4_CFB	0x00002004
#define SGD_SMS4_OFB	0x00002008
#define SGD_SMS4_MAC	0x00002010
#define SGD_SMS4_CTR	0x00002020

#define SGD_SM7_ECB		0x00008001
#define SGD_SM7_CBC		0x00008002
#define SGD_SM7_CFB		0x00008004
#define SGD_SM7_OFB		0x00008008
#define SGD_SM7_MAC		0x00008010
#define SGD_SM7_CTR		0x00008020

#define SGD_IDEA_ECB		0x00001001
#define SGD_IDEA_ECB_MAC	0x00001002
#define SGD_RC4				0x00001004


#define SGD_RSA			0x00010000
#define SGD_RSA_SIGN	0x00010100
#define SGD_RSA_ENC		0x00010200

#define SGD_SM2 		0x00020000
#define SGD_SM2_1		0x00020100
#define SGD_SM2_2		0x00020200
#define SGD_SM2_3		0x00020400

#define SGD_ECDSA		0x00080000
#define SGD_ECDSA_SIGN		0x00080100
#define SGD_ECDSA_ENC		0x00080200
#define SGD_DSA			0x00040000
#define SGD_DSA_SIGN		0x00040100
#define SGD_DSA_ENC			0x00040200

#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
#define SGD_SHA512		0x00000008
#define SGD_SHA384		0x00000010
#define SGD_SHA224		0x00000020
#define SGD_MD5			0x00000080


/*设备管理类函数*/
SGD_RV __cdecl SDF_OpenDevice(SGD_HANDLE *phDeviceHandle);
SGD_RV __cdecl SDF_CloseDevice(SGD_HANDLE hDeviceHandle);

SGD_RV __cdecl SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);
SGD_RV __cdecl SDF_CloseSession(SGD_HANDLE hSessionHandle);

SGD_RV __cdecl SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength);
SGD_RV __cdecl SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex);

SGD_RV __cdecl SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
SGD_RV __cdecl SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR *pucRandom);
SGD_RV SDF_GetKeyStatus(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount);
SGD_RV SDF_GetDeviceRunStatus(SGD_HANDLE hSessionHandle, DEVICE_RUN_STATUS *pstDeviceRunStatus);

/*非对称密码RSA密钥管理、运算函数*/
SGD_RV __cdecl SDF_GenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
SGD_RV __cdecl SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
//SGD_RV SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex);
SGD_RV __cdecl SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
SGD_RV SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_ExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, SGD_UINT32  uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, SGD_UINT32  uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDEInput, SGD_UINT32  uiDELength, SGD_UCHAR *pucDEOutput, SGD_UINT32  *puiDELength);

/*非对称密码ECC密钥管理、运算函数*/
SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID, SGD_UINT32  uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
SGD_RV SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData);
SGD_RV SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32  *puiDataLength);
SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData);
SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32  *puiDataLength);
SGD_RV SDF_InternalSign_ECC_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalVerify_ECC_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, ECCSignature *pucSignature);

SGD_RV SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey  *pucSponsorPublicKey, ECCrefPublicKey  *pucSponsorTmpPublicKey, SGD_HANDLE *phAgreementHandle);
SGD_RV SDF_GenerateKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey  *pucResponsePublicKey, ECCrefPublicKey  *pucResponseTmpPublicKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, SGD_UINT32  uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut);

/*对称密钥管理、密码运算函数*/
SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32  uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithIPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32  uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);

SGD_RV SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);

SGD_RV SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle);
SGD_RV SDF_GetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, SGD_UINT32  *puiEncDataLength);
SGD_RV SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32  uiEncDataLength, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);
SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, SGD_UINT32  *puiMACLength);

/*杂凑运算函数*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);
SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength);
SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32  *puiHashLength);

/*用户文件操作函数*/
SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize);
SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 *puiReadLength, SGD_UCHAR *pucBuffer);
SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR *pucBuffer);
SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen);

/*自定义接口，总参PKCA扩展接口，仅总参专用密码机支持*/
SGD_RV	SDF_ImportECCKeyPair(SGD_HANDLE		hSessionHandle, SGD_UINT32	uiKeyNumber, ECCrefPublicKey	*puxPublicKey, ECCrefPrivateKey	*pucPrivateKey);
SGD_RV	SDF_InternalSignEx_ECC(SGD_HANDLE	hSessionHandle, SGD_UINT32	uiKeyNumber, SGD_UCHAR	*pucData, SGD_UINT32	uiDataLength, ECCPoint	*P1, ECCSignatureEx	*sign);
SGD_RV  SDF_ECCMultAdd(SGD_HANDLE	hSessionHandle, SGD_UINT32	k, ECCrefPrivateKey	*e, ECCrefPublicKey	*A, ECCrefPublicKey	*B, ECCrefPublicKey	*C);
SGD_RV  SDF_ECCModMultAdd(SGD_HANDLE	hSessionHandle, ECCrefPrivateKey	*k, ECCrefPrivateKey	*a, ECCrefPrivateKey	*b, ECCrefPrivateKey	*c);
SGD_RV  SDF_ECCMultAdd2(SGD_HANDLE	hSessionHandle, ECCrefPrivateKey	*e1, ECCrefPublicKey	*A1, ECCrefPrivateKey	*e2, ECCrefPublicKey	*A2, ECCrefPublicKey	*B, ECCrefPublicKey	*C);
SGD_RV  SDF_InternalSignEx2_ECC(SGD_HANDLE	hSessionHandle, SGD_UINT32	uiISKIndex1, SGD_UINT32	uiISKIndex2, SGD_UCHAR	*pucData, SGD_UINT32	uiDataLength, ECCPoint	*P1, ECCSignatureEx	*sign);

/**/
SGD_RV SWCSM_GenerateRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyBits);
SGD_RV SWCSM_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
SGD_RV SWCSM_SetPrivateKeyAccessPwd(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength);
SGD_RV SWMF_GenerateRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyBits);
SGD_RV SWMF_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
SGD_RV SWMF_SetPrivateKeyAccessPwd(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength);
SGD_RV SWMF_GenerateKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyLength);
SGD_RV SWMF_InputKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength);
SGD_RV SWCSM_GenerateRSAKeyPairEx(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyNumber, SGD_UINT32  uiKeyBits, SGD_UINT32 unPublicExponent, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
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
                       SGD_UINT32  *puiTagDataLength);
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
                       SGD_UINT32  *puiResult);				//输出，认证结果，1为认证通过，0为认证失败


SGD_RV SDF_ExportSignPublicKey_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, DSArefPublicKeyLite *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, DSArefPublicKeyLite *pucPublicKey);
SGD_RV SDF_InternalSign_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureDataLength);
SGD_RV SDF_InternalVerify_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureDataLength);
SGD_RV SDF_GenerateKeyPair_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID, SGD_UINT32  uiKeyBits, DSArefPublicKeyLite *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
SGD_RV SDF_ExternalSign_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, DSArefPrivateKeyLite *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *uiSignatureLength);
SGD_RV SDF_ExternalVerify_DSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, DSArefPublicKeyLite *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32  uiInputLength, SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureLength);

#ifdef __cplusplus
}
#endif

#endif
/*#ifndef _SW_SDS_H_*/