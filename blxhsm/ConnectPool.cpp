#include "ConnectPool.h"
#include <algorithm>

//#include "log.h"

bool CConnectPool::CreateSession(CNetObj nObj,SGD_UINT32 uiDevHandle) {

    if (!nObj.IsInit()) return false;

    CSessionObj sObj(nObj);

    if (sObj.Init(uiDevHandle)) AddSession(sObj);
    else return false;

    return true;
}

CSessionObj* CConnectPool::GetLockSession(SGD_HANDLE hSession) {

    CSessionObj *sObj = NULL;
    SGD_UINT32 uiSessionHandle = 0;

    memcpy(&uiSessionHandle,&hSession,4);

    for(int i = 0; i != vCSP.size(); i++) {
        if (vCSP[i].SessionHandle == uiSessionHandle && vCSP[i].PoolLock == 1) {
            sObj = &vCSP[i];
            goto end;
        }
    }

end:
    return sObj;
}

bool CConnectPool::GetUnLockSession(SGD_HANDLE hDev,SGD_HANDLE *phSession) {

    SGD_UINT32 uiDevHandle = 0;

    memcpy(&uiDevHandle,&hDev,4);

    for (int i = 0; i != vCSP.size(); i++) {

        if (vCSP[i].DevcieHandle == uiDevHandle && vCSP[i].PoolLock == 0) {
            memcpy(phSession,&vCSP[i].SessionHandle,4);
            return true;
        }
    }

    return false;
}

bool CConnectPool::LockSession(SGD_HANDLE hSession) {

    SGD_UINT32 uiSessionHandle = 0;

    memcpy(&uiSessionHandle,&hSession,4);

    for (int i = 0; i != vCSP.size(); i++) {
        if (vCSP[i].SessionHandle == uiSessionHandle && vCSP[i].PoolLock == 0) {
            vCSP[i].PoolLock = 1;
            return true;
        }
    }
    return false;
}

bool CConnectPool::UnLockSession(SGD_HANDLE hSession) {

    SGD_UINT32 uiSessionHandle = 0;

    memcpy(&uiSessionHandle,&hSession,4);

    for (int i = 0; i != vCSP.size(); i++) {
        if (vCSP[i].SessionHandle == uiSessionHandle && vCSP[i].PoolLock == 1) {
            vCSP[i].PoolLock = 0;
            return true;
        }
    }

    return false;
}

bool CConnectPool::DelDeviceSessions(SGD_UINT32 uiDevHandle) {
    bool ret = false;
    for_each(vCSP.begin(), vCSP.end(),[uiDevHandle](CSessionObj obj) {
        if(obj.DevcieHandle == uiDevHandle) {
            if(obj.PoolLock == 0) { //������״̬
                obj.Finalize();
            } else {
                //LogMessage_tt("ConnectPool.cpp", __LINE__, 1, "����״̬��session������ɾ����");
            }
        }
    });

    return true;
}

void CConnectPool::ClearAllSessions() {
    for_each(vCSP.begin(), vCSP.end(), [](CSessionObj obj)->bool{ return obj.Finalize();});
}

bool CConnectPool::DelSession(SGD_UINT32 uiSessionID) {

    bool ret = false;
    auto iter = find_if(vCSP.begin(), vCSP.end(),[uiSessionID](CSessionObj obj)->bool {
        if(obj.SessionHandle == uiSessionID) {
            if(obj.PoolLock == 0) { //������״̬
                return true;
            } else {
                //LogMessage_tt("ConnectPool.cpp", __LINE__, 1, "����״̬��session������ɾ����");
                return false;
            }
        }
    });
    if(iter != vCSP.end()) {
        iter->Finalize(); //�ر�socket����
        vCSP.erase(iter);

        ret = true;
    } else {
        //LogMessage_tt("ConnectPool.cpp", __LINE__, 1, "û���ҵ�uiSessionID��Ӧ��Session����");
    }

    return true;
}

bool CConnectPool::AddSession(CSessionObj sObj) {

    vCSP.push_back(sObj);

    return true;
}