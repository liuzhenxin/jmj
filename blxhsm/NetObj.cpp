#include "NetObj.h"
#include "Protocal.h"
#include <tchar.h>



CNetObj::CNetObj(void) {

    SocketID = INVALID_SOCKET;
}

CNetObj::CNetObj(string ip, int port, string pwd) {

    this->ip = ip;
    this->port = port;
    this->pwd = pwd;
    this->isInit = false;
    SocketID = INVALID_SOCKET;
}

/*初始化socket连接*/
bool CNetObj::Init() {

    unsigned char bCmd[64] = {0};
    unsigned char bRev[64] = {0};
    unsigned int uiCmdLen = 0;
    unsigned int uiTaskSN = 0x01000000;
    unsigned int uiCmd = 0;
    unsigned int uiRevLen = 0;
    unsigned int uiRet = 0;

    WORD sockVersion = MAKEWORD(2, 2);

    WSADATA data;
    if (WSAStartup(sockVersion, &data) != 0) {
        return false;
    }

    SOCKET sc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sc == INVALID_SOCKET) {
        return false;
    }

    BOOL block = FALSE;
    ioctlsocket(sc, FIONBIO, (unsigned long *)&block);

    struct fd_set wfs;
    FD_ZERO(&wfs);
    FD_SET(sc, &wfs);

    sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(port);
    serAddr.sin_addr.S_un.S_addr = inet_addr(ip.c_str());
    connect(sc, (sockaddr *)&serAddr, sizeof(serAddr));

    //设置等待时间
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 5000000;

    int ret = select(0, NULL, &wfs, NULL, &tv);
    switch(ret) {
    case 0:
        OutputDebugString(_T("time out\n"));
        return false;
    case SOCKET_ERROR:
        OutputDebugString(_T("error\n"));
        return false;
    default:
        OutputDebugString(_T("connected\n"));
    }

    ////设置发送超时6秒
    //int timeOut = 6000;
    //if(setsockopt(sc,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeOut,sizeof(timeOut)) == SOCKET_ERROR) {
    //    return 0;
    //}

    ////设置接收超时6秒
    //timeOut = 6000;
    //if(setsockopt(sc,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeOut,sizeof(timeOut)) == SOCKET_ERROR) {
    //    return 0;
    //}

    SocketID = sc;

    Request reqest = {0};
    uiCmdLen = 0x3c;
    reqest.commandLen = uiCmdLen;
    reqest.taskSN = uiTaskSN;
    reqest.command = uiCmd;
    memcpy(reqest.commandData, pwd.c_str(), strlen(pwd.c_str()));


    //发送密码验证指令
    if (!SendCmd((unsigned char *)&reqest, uiCmdLen, bRev, &uiRevLen, &uiRet)) {
        return false;
    }

    if (uiRet != 0) {
        return false;
    }

    isInit = true;


    return true;
}

bool CNetObj::SendCmd(unsigned char *pcCmd, unsigned int uiCmdLen, unsigned char *pcRev, unsigned int *puiRevLen, unsigned int *puiRet) {

    unsigned char bRev[4096 + 32] = {0};

    if (send(SocketID, (const char *)pcCmd, uiCmdLen, 0) < 0)
        return false;

    int rLen = recv(SocketID, (char *)bRev, 4096 + 32, 0);

    if (rLen <= 0) {
        return false;
    }

    memcpy(puiRet, bRev + 8, 4);
    memcpy(pcRev, bRev + 12, rLen - 12);
    *puiRevLen = rLen - 12;

    return true;
}

bool CNetObj::IsInit() {
    return isInit;
}

bool CNetObj::Finalize() {
    bool retValue = false;

    if (SocketID != INVALID_SOCKET) {
        if (closesocket(SocketID) != SOCKET_ERROR) {
            SocketID = INVALID_SOCKET;
            isInit = false;

            retValue = true;
        }
    } else {
        retValue = true;
    }

    return retValue;
}
