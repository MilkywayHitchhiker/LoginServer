#include"stdafx.h"
#include"ServerConfig.h"
CServerConfig *CServerConfig::Config;


void CServerConfig::SetConfig (void)
{
	char SERVER_NAME[11];

	char BIND_IP[11];

	char LOGIN_SERVER_IP[11];

	char MONITORING_SERVER_IP[11];

	int Length = 11;
	parser.LoadFile ("_ChatServer.cnf");
	parser.SetArea ("NETWORK");
	parser.GetValue ("SERVER_NAME", SERVER_NAME, &Length);



	Length = 11;
	parser.GetValue ("BIND_IP", BIND_IP, &Length);
	parser.GetValue ("BIND_PORT", &_BIND_PORT);

	Length = 11;
	parser.GetValue ("LOGIN_SERVER_IP", LOGIN_SERVER_IP, &Length);
	parser.GetValue ("LOGIN_SERVER_PORT", &_LOGIN_SERVER_PORT);

	Length = 11;
	parser.GetValue ("MONITORING_SERVER_IP", MONITORING_SERVER_IP, &Length);
	parser.GetValue ("MONITORING_SERVER_PORT", &_MONITORING_SERVER_PORT);


	parser.GetValue ("WORKER_THREAD", &_WORKER_THREAD_NUM);


	parser.SetArea ("SYSTEM");
	parser.GetValue ("CLIENT_MAX", &_CLIENT_MAX);

	parser.GetValue ("PACKET_CODE", &_PACKET_CODE);
	parser.GetValue ("PACKET_KEY1", &_PACKET_KEY1);
	parser.GetValue ("PACKET_KEY2",&_PACKET_KEY2);




	MultiByteToWideChar (CP_ACP, 0, SERVER_NAME, -1, _SERVER_NAME, 11);
	MultiByteToWideChar (CP_ACP, 0, BIND_IP, -1, _BIND_IP, 11);
	MultiByteToWideChar (CP_ACP, 0, LOGIN_SERVER_IP, -1, _LOGIN_SERVER_IP, 11);
	MultiByteToWideChar (CP_ACP, 0, MONITORING_SERVER_IP, -1, _MONITORING_SERVER_IP, 11);
}


WCHAR _SERVER_NAME[11];

WCHAR _BIND_IP[11];
int _BIND_PORT;

WCHAR _LOGIN_SERVER_IP[11];
int _LOGIN_SERVER_PORT;

WCHAR _MONITORING_SERVER_IP[11];
int _MONITORING_SERVER_PORT;


int _WORKER_THREAD_NUM;

int _CLIENT_MAX;
int _PACKET_CODE;
int _PACKET_KEY1;
int _PACKET_KEY2;