#ifndef _LOG_H_
#define _LOG_H_

#include <time.h>
#include<stdlib.h>
/***************************************************************************************************/
#define random(x) (rand()%x)
#define DEFAULT_LOG_PATH "."
#define DEFAULT_LOG_FILE "tsds"
#define LOG_ERROR		1
#define LOG_WARNING		2
#define LOG_INFO		3
#define LOG_TRACE		4
unsigned int log_level = LOG_TRACE;

void LogMsg(int nLogLevel, char *sFile,int nLine,unsigned int unErrCode, char *sMessage);
#define LOG(lvl, rv, msg) \
	do { \
	if ((lvl) <= log_level) {\
	LogMsg(lvl, __FILE__, __LINE__, rv, msg);} \
	} while (0)


void LogMessage_tt(char *sFile,int nLine,unsigned int unErrCode, char *sMessage)
{

	FILE *fp;
	struct tm *newtime;
	time_t aclock;

	time( &aclock );                 
	newtime = localtime( &aclock ); 
#if defined(WIN32) || defined(WIN64)
	fp = fopen("test.log","a+");   
#else
	fp = fopen("/tmp/test.log","a+");   
#endif
	if(NULL == fp)		
		return;

	fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><Error>[0x%08x]%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,unErrCode, sMessage, sFile,nLine);

	fclose(fp);
}

int GetRandom(){
	srand((int)time(0));

	return random(10);
}

#endif