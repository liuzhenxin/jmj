#ifndef _MSGDEF_H_
#define _MSGDEF_H_


#define LOG_OK    0
#define LOG_ERROR 1

#define MSG_ERROR				_T("[%s]����ʧ�ܣ��������:0x%08x")
#define MSG_ERROR_LOG			_T("[%s]���ô���%s")
#define MSG_OK					_T("[%s]���óɹ�%s")
#define MSG_FUNC_NAME			_T("[%s]...")
#define MSG_FUNC_PARAM_EMPTY	_T("[%s]����Ϊ��")
#define MSG_DEV_INFO            _T("��������:%s\n�豸�ͺ�:%s\n�豸���к�:%s\n�豸�汾:0x%08x\n֧�ֱ�׼�汾:0x%08x\n֧�ֹ�Կ�㷨:0x%08x|%08x\n֧�ֶԳ��㷨:0x%08x\n֧���Ӵ��㷨:0x%08x\n�û��洢�ռ�:0x%08x")
                             
								


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
