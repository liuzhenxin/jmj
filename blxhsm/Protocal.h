#ifndef Protocal_h__
#define Protocal_h__

typedef struct Request_st 
{
	unsigned int commandLen;
	unsigned int taskSN;
	unsigned int command;
	unsigned char commandData[64];
} Request;

typedef struct  Response_st
{
	unsigned int r1;
	unsigned int r2;
	unsigned int errorCode;
	unsigned int dataLength;
} Response;

#endif // Protocal_h__
