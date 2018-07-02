#pragma once
#include <Windows.h>
#include "Parser.h"
class CServerConfig
{
private :
	CServerConfig (void)
	{
		SetConfig ();
	}

	~CServerConfig ()
	{

	}


	void SetConfig (void);


	static CServerConfig *Config;
	Parser parser;
public :

	static void Initialize (void)
	{
		if ( Config == NULL )
		{
			Config = new CServerConfig ();
		}
		return;
	}


};


extern WCHAR _SERVER_NAME[11];

extern WCHAR _BIND_IP[11];
extern int _BIND_PORT;

extern WCHAR _LOGIN_SERVER_IP[11];
extern int _LOGIN_SERVER_PORT;

extern WCHAR _MONITORING_SERVER_IP[11];
extern int _MONITORING_SERVER_PORT;


extern int _WORKER_THREAD_NUM;

extern int _CLIENT_MAX;
extern int _PACKET_CODE;
extern int _PACKET_KEY1;
extern int _PACKET_KEY2;