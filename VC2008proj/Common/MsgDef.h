#ifndef _MSGDEF_H_
#define _MSGDEF_H_


#define LOG_OK    0
#define LOG_ERROR 1

#define MSG_ERROR				_T("[%s]调用失败，错误代码:0x%08x")
#define MSG_ERROR_LOG			_T("[%s]调用错误，%s")
#define MSG_OK					_T("[%s]调用成功%s")
#define MSG_FUNC_NAME			_T("[%s]...")
#define MSG_FUNC_PARAM_EMPTY	_T("[%s]参数为空")
#define MSG_DEV_INFO            _T("生产厂商:%s\n设备型号:%s\n设备序列号:%s\n设备版本:0x%08x\n支持标准版本:0x%08x\n支持公钥算法:0x%08x|%08x\n支持对称算法:0x%08x\n支持杂凑算法:0x%08x\n用户存储空间:0x%08x")
                             
								


//typedef struct DeviceInfo_st{
//	unsigned char IssuerName[40];
//	unsigned char DeviceName[16];
//	unsigned char DeviceSerial[16];
//	unsigned int  DeviceVersion;
//	unsigned int  StandardVersion;
//	unsigned int  AsymAlgAbility[2];
//	unsigned int  SymAlgAbility;
//	unsigned int  HashAlgAbility;
//	unsigned int  BufferSize;
//}DEVICEINFO;

#endif
