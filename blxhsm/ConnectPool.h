#ifndef _CONNECTPOOL_H_
#define _CONNECTPOOL_H_

#include "SessionObj.h"
#include "NetObj.h"
#include "sdf.h"
#include <vector>
using namespace std;

class CConnectPool{

private:
	vector<CSessionObj> vCSP; 

public:
	bool CreateSession(CNetObj nObj,SGD_UINT32 uiDevHandle);
	CSessionObj* GetLockSession(SGD_HANDLE hSession);
	bool GetUnLockSession(SGD_HANDLE hDev,SGD_HANDLE *phSession);

	bool DelSession(SGD_UINT32 uiSessionID);
	bool LockSession(SGD_HANDLE hSession);
	bool UnLockSession(SGD_HANDLE uiSessionID);
	// 关闭全部session连接
	void  ClearAllSessions();
private:
	bool AddSession(CSessionObj sObj);

		

};


#endif