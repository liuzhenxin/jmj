#include "ConnectPool.h"

bool CConnectPool::CreateSession(CNetObj nObj,SGD_UINT32 uiDevHandle){

	if (!nObj.IsInit()) return false;

    CSessionObj sObj(nObj);

	if (sObj.Init(uiDevHandle)) AddSession(sObj);
	else return false;

	return true;
}

CSessionObj* CConnectPool::GetLockSession(SGD_HANDLE hSession){

	CSessionObj *sObj = NULL;
	SGD_UINT32 uiSessionHandle = 0;

	memcpy(&uiSessionHandle,&hSession,4);

	for(int i = 0;i != vCSP.size();i++)
	{
		if (vCSP[i].SessionHandle == uiSessionHandle && vCSP[i].PoolLock == 1)
		{
			sObj = &vCSP[i];
			goto end;
		}
	}

end:
	return sObj;
}

bool CConnectPool::GetUnLockSession(SGD_HANDLE hDev,SGD_HANDLE *phSession){

	SGD_UINT32 uiDevHandle = 0;

	memcpy(&uiDevHandle,&hDev,4);

	for (int i = 0;i != vCSP.size();i++){

		if (vCSP[i].DevcieHandle == uiDevHandle && vCSP[i].PoolLock == 0)
		{
			memcpy(phSession,&vCSP[i].SessionHandle,4);
			return true;
		}
	}

	return false;
}

bool CConnectPool::LockSession(SGD_HANDLE hSession){

	SGD_UINT32 uiSessionHandle = 0;

	memcpy(&uiSessionHandle,&hSession,4);
	
	for (int i = 0;i != vCSP.size();i++){
		if (vCSP[i].SessionHandle == uiSessionHandle && vCSP[i].PoolLock == 0){
			vCSP[i].PoolLock = 1;
			return true;
		}
	}
	return false;
}

bool CConnectPool::UnLockSession(SGD_HANDLE hSession){
	
	SGD_UINT32 uiSessionHandle = 0;

	memcpy(&uiSessionHandle,&hSession,4);

	for (int i = 0;i != vCSP.size();i++){
		if (vCSP[i].SessionHandle == uiSessionHandle && vCSP[i].PoolLock == 1){
			vCSP[i].PoolLock = 0;
			return true;
		}
	}

	return false;
	
}

bool CConnectPool::DelSession(SGD_UINT32 uiSessionID){
	return true;
}

bool CConnectPool::AddSession(CSessionObj sObj){
	
	vCSP.push_back(sObj);
	
	return true;
}