#ifndef _FUNCTION_H_
#define _FUNCTION_H_

#include "swsds.h"

typedef SGD_RV(__cdecl *SDF_OpenDevice_Fun)(SGD_HANDLE *phDeviceHandle);
typedef SGD_RV(__cdecl *SDF_CloseDevice_Fun)(SGD_HANDLE hDeviceHandle);
typedef SGD_RV(__cdecl *SDF_OpenSession_Fun)(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);
typedef SGD_RV(__cdecl *SDF_CloseSession_Fun)(SGD_HANDLE hSessionHandle);
typedef SGD_RV(__cdecl *SDF_GetPrivateKeyAccessRight_Fun)(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength);
typedef SGD_RV(__cdecl *SDF_ReleasePrivateKeyAccessRight_Fun)(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex);

typedef SGD_RV(__cdecl *SDF_GetDeviceInfo_Fun)(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
typedef SGD_RV(__cdecl *SDF_GenerateRandom_Fun)(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR *pucRandom);
typedef SGD_RV(__cdecl *SDF_GetKeyStatus_Fun)(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount);
typedef SGD_RV(__cdecl *SDF_GetDeviceRunStatus_Fun)(SGD_HANDLE hSessionHandle,DEVICE_RUN_STATUS *pstDeviceRunStatus);

typedef SGD_RV(__cdecl *SDF_ExportSignPublicKey_RSA_Fun)(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey);  //
typedef SGD_RV(__cdecl *SDF_ExportEncPublicKey_RSA_Fun)(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey);


extern SDF_OpenDevice_Fun   pSDF_OpenDevice_Fun;
extern SDF_CloseDevice_Fun  pSDF_CloseDevice_Fun;
extern SDF_OpenSession_Fun  pSDF_OpenSession_Fun;
extern SDF_CloseSession_Fun pSDF_CloseSession_Fun;
extern SDF_GetPrivateKeyAccessRight_Fun  pSDF_GetPrivateKeyAccessRight_Fun;
extern SDF_ReleasePrivateKeyAccessRight_Fun pSDF_ReleasePrivateKeyAccessRight_Fun;
extern SDF_GetDeviceInfo_Fun pSDF_GetDeviceInfo_Fun;
extern SDF_GenerateRandom_Fun pSDF_GenerateRandom_Fun;
extern SDF_GetKeyStatus_Fun pSDF_GetKeyStatus_Fun;
extern SDF_GetDeviceRunStatus_Fun pSDF_GetDeviceRunStatus_Fun;

extern SDF_ExportSignPublicKey_RSA_Fun pSDF_ExportSignPublicKey_RSA_Fun;
extern SDF_ExportEncPublicKey_RSA_Fun pSDF_ExportEncPublicKey_RSA_Fun;


#endif