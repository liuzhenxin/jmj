#ifndef ErrorCode_h__
#define ErrorCode_h__

/*标准错误码定义*/
#define SDR_OK				0x0						   /*成功*/
#define SDR_BASE			0x01000000
#define SDR_UNKNOWERR		(SDR_BASE + 0x00000001)	   /*未知错误*/
#define SDR_NOTSUPPORT		(SDR_BASE + 0x00000002)	   /*不支持*/
#define SDR_COMMFAIL		(SDR_BASE + 0x00000003)    /*通信错误*/
#define SDR_HARDFAIL		(SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE		(SDR_BASE + 0x00000005)    /*打开设备错误*/
#define SDR_OPENSESSION		(SDR_BASE + 0x00000006)    /*打开会话句柄错误*/
#define SDR_PARDENY			(SDR_BASE + 0x00000007)    /*权限不满足*/
#define SDR_KEYNOTEXIST		(SDR_BASE + 0x00000008)    /*密钥不存在*/
#define SDR_ALGNOTSUPPORT	(SDR_BASE + 0x00000009)    /*不支持的算法*/
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A)   /*不支持的算法模式*/
#define SDR_PKOPERR			(SDR_BASE + 0x0000000B)    /*公钥运算错误*/
#define SDR_SKOPERR			(SDR_BASE + 0x0000000C)    /*私钥运算错误*/
#define SDR_SIGNERR			(SDR_BASE + 0x0000000D)    /*签名错误*/
#define SDR_VERIFYERR		(SDR_BASE + 0x0000000E)    /*验证错误*/
#define SDR_SYMOPERR		(SDR_BASE + 0x0000000F)    /*对称运算错误*/
#define SDR_STEPERR			(SDR_BASE + 0x00000010)    /*步骤错误*/
#define SDR_FILESIZEERR		(SDR_BASE + 0x00000011)    /*文件大小错误*/
#define SDR_FILENOEXIST		(SDR_BASE + 0x00000012)    /*文件不存在*/
#define SDR_FILEOFSERR		(SDR_BASE + 0x00000013)    /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR		(SDR_BASE + 0x00000014)    /*密钥类型错误*/
#define SDR_KEYERR			(SDR_BASE + 0x00000015)    /*密钥错误*/

/*扩展错误码*/
#define SWR_BASE				(SDR_BASE + 0x00010000)	/*自定义错误码基础值*/
#define SWR_INVALID_USER		(SWR_BASE + 0x00000001)	/*无效的用户名*/
#define SWR_INVALID_AUTHENCODE	(SWR_BASE + 0x00000002)	/*无效的授权码*/
#define SWR_PROTOCOL_VER_ERR	(SWR_BASE + 0x00000003)	/*不支持的协议版本*/
#define SWR_INVALID_COMMAND		(SWR_BASE + 0x00000004)	/*错误的命令字*/
#define SWR_INVALID_PACKAGE		(SWR_BASE + 0x00000005)	/*错误的数据包格式*/
#define SWR_FILE_ALREADY_EXIST	(SWR_BASE + 0x00000006)	/*已存在同名文件*/

#define SWR_SOCKET_TIMEOUT		(SWR_BASE + 0x00000100)	/*超时错误*/
#define SWR_CONNECT_ERR			(SWR_BASE + 0x00000101)	/*连接服务器错误*/
#define SWR_SET_SOCKOPT_ERR		(SWR_BASE + 0x00000102)	/*设置Socket参数错误*/
#define SWR_SOCKET_SEND_ERR		(SWR_BASE + 0x00000104)	/*发送LOGINRequest错误*/
#define SWR_SOCKET_RECV_ERR		(SWR_BASE + 0x00000105)	/*发送LOGINRequest错误*/
#define SWR_SOCKET_RECV_0		(SWR_BASE + 0x00000106)	/*发送LOGINRequest错误*/

#define SWR_NO_AVAILABLE_HSM	(SWR_BASE + 0x00000201)	/*没有可用的加密机*/
#define SWR_NO_AVAILABLE_CSM	(SWR_BASE + 0x00000202)	/*加密机内没有可用的加密模块*/
#define SWR_CONFIG_ERR			(SWR_BASE + 0x00000301)	/*配置文件错误*/

#define SWR_CARD_BASE           (SDR_BASE + 0x00020000)		 /*密码卡错误码*/
#define SDR_BUFFER_TOO_SMALL	(SWR_CARD_BASE + 0x00000101) /*接收参数的缓存区太小*/
#define SDR_DATA_PAD			(SWR_CARD_BASE + 0x00000102) /*数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式*/
#define SDR_DATA_SIZE			(SWR_CARD_BASE + 0x00000103) /*明文或密文长度不符合相应的算法要求*/
#define SDR_CRYPTO_NOT_INIT		(SWR_CARD_BASE + 0x00000104) /*步骤错误*/

#define SWR_MANAGEMENT_DENY		(SWR_CARD_BASE + 0x00001001)	//管理权限不满足
#define SWR_OPERATION_DENY		(SWR_CARD_BASE + 0x00001002)	//操作权限不满足
#define SWR_DEVICE_STATUS_ERR   (SWR_CARD_BASE + 0x00001003)	//当前设备状态不满足现有操作

#define SWR_LOGIN_ERR           (SWR_CARD_BASE + 0x00001011)	//登录失败
#define SWR_USERID_ERR          (SWR_CARD_BASE + 0x00001012)	//用户ID数目/号码错误
#define SWR_PARAMENT_ERR        (SWR_CARD_BASE + 0x00001013)	//参数错误
#define SWR_KEYTYPEERR			(SWR_CARD_BASE + 0x00000020)	//密钥类型错误

#endif // ErrorCode_h__