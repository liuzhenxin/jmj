#ifndef ErrorCode_h__
#define ErrorCode_h__

/*��׼�����붨��*/
#define SDR_OK				0x0						   /*�ɹ�*/
#define SDR_BASE			0x01000000
#define SDR_UNKNOWERR		(SDR_BASE + 0x00000001)	   /*δ֪����*/
#define SDR_NOTSUPPORT		(SDR_BASE + 0x00000002)	   /*��֧��*/
#define SDR_COMMFAIL		(SDR_BASE + 0x00000003)    /*ͨ�Ŵ���*/
#define SDR_HARDFAIL		(SDR_BASE + 0x00000004)    /*Ӳ������*/
#define SDR_OPENDEVICE		(SDR_BASE + 0x00000005)    /*���豸����*/
#define SDR_OPENSESSION		(SDR_BASE + 0x00000006)    /*�򿪻Ự�������*/
#define SDR_PARDENY			(SDR_BASE + 0x00000007)    /*Ȩ�޲�����*/
#define SDR_KEYNOTEXIST		(SDR_BASE + 0x00000008)    /*��Կ������*/
#define SDR_ALGNOTSUPPORT	(SDR_BASE + 0x00000009)    /*��֧�ֵ��㷨*/
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A)   /*��֧�ֵ��㷨ģʽ*/
#define SDR_PKOPERR			(SDR_BASE + 0x0000000B)    /*��Կ�������*/
#define SDR_SKOPERR			(SDR_BASE + 0x0000000C)    /*˽Կ�������*/
#define SDR_SIGNERR			(SDR_BASE + 0x0000000D)    /*ǩ������*/
#define SDR_VERIFYERR		(SDR_BASE + 0x0000000E)    /*��֤����*/
#define SDR_SYMOPERR		(SDR_BASE + 0x0000000F)    /*�Գ��������*/
#define SDR_STEPERR			(SDR_BASE + 0x00000010)    /*�������*/
#define SDR_FILESIZEERR		(SDR_BASE + 0x00000011)    /*�ļ���С����*/
#define SDR_FILENOEXIST		(SDR_BASE + 0x00000012)    /*�ļ�������*/
#define SDR_FILEOFSERR		(SDR_BASE + 0x00000013)    /*�ļ�����ƫ��������*/
#define SDR_KEYTYPEERR		(SDR_BASE + 0x00000014)    /*��Կ���ʹ���*/
#define SDR_KEYERR			(SDR_BASE + 0x00000015)    /*��Կ����*/

/*��չ������*/
#define SWR_BASE				(SDR_BASE + 0x00010000)	/*�Զ�����������ֵ*/
#define SWR_INVALID_USER		(SWR_BASE + 0x00000001)	/*��Ч���û���*/
#define SWR_INVALID_AUTHENCODE	(SWR_BASE + 0x00000002)	/*��Ч����Ȩ��*/
#define SWR_PROTOCOL_VER_ERR	(SWR_BASE + 0x00000003)	/*��֧�ֵ�Э��汾*/
#define SWR_INVALID_COMMAND		(SWR_BASE + 0x00000004)	/*�����������*/
#define SWR_INVALID_PACKAGE		(SWR_BASE + 0x00000005)	/*��������ݰ���ʽ*/
#define SWR_FILE_ALREADY_EXIST	(SWR_BASE + 0x00000006)	/*�Ѵ���ͬ���ļ�*/

#define SWR_SOCKET_TIMEOUT		(SWR_BASE + 0x00000100)	/*��ʱ����*/
#define SWR_CONNECT_ERR			(SWR_BASE + 0x00000101)	/*���ӷ���������*/
#define SWR_SET_SOCKOPT_ERR		(SWR_BASE + 0x00000102)	/*����Socket��������*/
#define SWR_SOCKET_SEND_ERR		(SWR_BASE + 0x00000104)	/*����LOGINRequest����*/
#define SWR_SOCKET_RECV_ERR		(SWR_BASE + 0x00000105)	/*����LOGINRequest����*/
#define SWR_SOCKET_RECV_0		(SWR_BASE + 0x00000106)	/*����LOGINRequest����*/

#define SWR_NO_AVAILABLE_HSM	(SWR_BASE + 0x00000201)	/*û�п��õļ��ܻ�*/
#define SWR_NO_AVAILABLE_CSM	(SWR_BASE + 0x00000202)	/*���ܻ���û�п��õļ���ģ��*/
#define SWR_CONFIG_ERR			(SWR_BASE + 0x00000301)	/*�����ļ�����*/

#define SWR_CARD_BASE           (SDR_BASE + 0x00020000)		 /*���뿨������*/
#define SDR_BUFFER_TOO_SMALL	(SWR_CARD_BASE + 0x00000101) /*���ղ����Ļ�����̫С*/
#define SDR_DATA_PAD			(SWR_CARD_BASE + 0x00000102) /*����û�а���ȷ��ʽ��䣬����ܵõ����������ݲ���������ʽ*/
#define SDR_DATA_SIZE			(SWR_CARD_BASE + 0x00000103) /*���Ļ����ĳ��Ȳ�������Ӧ���㷨Ҫ��*/
#define SDR_CRYPTO_NOT_INIT		(SWR_CARD_BASE + 0x00000104) /*�������*/

#define SWR_MANAGEMENT_DENY		(SWR_CARD_BASE + 0x00001001)	//����Ȩ�޲�����
#define SWR_OPERATION_DENY		(SWR_CARD_BASE + 0x00001002)	//����Ȩ�޲�����
#define SWR_DEVICE_STATUS_ERR   (SWR_CARD_BASE + 0x00001003)	//��ǰ�豸״̬���������в���

#define SWR_LOGIN_ERR           (SWR_CARD_BASE + 0x00001011)	//��¼ʧ��
#define SWR_USERID_ERR          (SWR_CARD_BASE + 0x00001012)	//�û�ID��Ŀ/�������
#define SWR_PARAMENT_ERR        (SWR_CARD_BASE + 0x00001013)	//��������
#define SWR_KEYTYPEERR			(SWR_CARD_BASE + 0x00000020)	//��Կ���ʹ���

#endif // ErrorCode_h__