#ifndef _NETOBJ_H_
#define _NETOBJ_H_
#include<WINSOCK2.H>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

class CNetObj {

  public:
    UINT_PTR SocketID;

  private:
    string ip;
    string pwd;
    int port;

    bool isInit;

  public:
    CNetObj(string ip,int port,string pwd);
    CNetObj(void);


  public:
    unsigned int SendCmd(unsigned char * pcCmd,unsigned int uiCmdLen,unsigned char *pcRev, unsigned int *puiRevLen,unsigned int *puiRet);
    unsigned int Init();
    bool IsInit();

    // 关闭socket连接
    bool Finalize();

};


#endif