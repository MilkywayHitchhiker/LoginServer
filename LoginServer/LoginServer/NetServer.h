#pragma once



#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

#include <process.h>
#include "lib\\Library.h"
#include "PacketPool.h"
#include "RingBuffer.h"
#include "LockFreeStack.h"
#include "LockFreeQueue.h"

/*======================================================================
//NET Server Module
//해당 클래스는 TCP모듈 클래스로 필요한 경우 상속받아서 사용할것.
======================================================================*/
class CNetServer
{
#define SendbufMax 100
protected:
	struct IOChk
	{
		int IOCount = 0;
		int UseFlag = false;
	};


	struct Session
	{
		IOChk p_IOChk;
		SOCKET sock;
		UINT64 SessionID;

		
		long SendFlag = FALSE;
		bool SendDisconnect = FALSE;
		CQueue_LF<Packet *> SendQ;
		OVERLAPPED SendOver;
		CStack_LF<Packet *> SendPack;

		CRingbuffer RecvQ;
		OVERLAPPED RecvOver;
		
	};

	HANDLE _IOCP;
	SOCKET _ListenSock;
	int _Session_Max;
	Session *Session_Array;
	CStack_LF<int> emptySession;

	char _SessionID_Count[6];

	UINT _RecvPacketTPS;
	UINT _SendPacketTPS;
	UINT _AcceptTotal;
	UINT _AcceptTPS;
	int _Use_Session_Cnt;

	HANDLE *Thread;
	int _WorkerThread_Num;

	bool bServerOn;

	/*======================================================================
	//생성자
	//인자 : 없음
	======================================================================*/
	CNetServer (void);
	
	/*======================================================================
	//파괴자
	//인자 : 없음
	======================================================================*/
	~CNetServer (void);

	/*======================================================================
	//AcceptThread
	//설명 : 실제 AcceptThread.
	//인자 : 없음
	//리턴 : 없음
	======================================================================*/
	void AcceptThread (void);


	/*======================================================================
	//WorkerThread
	//설명 : 실제 WorkerThread. GQCS로 Recv와 Send 완료통지를 받음.
	//인자 : 없음
	//리턴 : 없음
	======================================================================*/
	void WorkerThread (void);



	/*======================================================================
	//InitializeNetwork
	//설명 : Start로 서버 On시 Listen소켓 초기화 및 bind, listen 함수
	//인자 : WCHAR * IP, int 포트번호
	//리턴 : 성공여부
	======================================================================*/
	bool InitializeNetwork (WCHAR *IP,int PORT);



	/*======================================================================
	//FindLockSession
	//설명 : 세션검색 및 해당세션에 대한 IO카운트 증가로 락을 거는 작업.
	//인자 : UINT64 SessionID
	//리턴 : Session *, NULL리턴시 실패.
	======================================================================*/
	Session *FindLockSession (UINT64 SessionID);


	/*======================================================================
	//CreateSessionID
	//설명 : 인자로 받은 인덱스와 유니크값을 비트연산하여 세션ID생성.
	//인자 : short index, UINT64 Unique
	//리턴 : UINT64 SessionID
	======================================================================*/
	UINT64 CreateSessionID (short index, UINT64 Unique)
	{
			return ((UINT64)index << 48) | (Unique);
	}


	/*======================================================================
	//indexSessionID
	//설명 : 인자로 받은 세션ID에서 인덱스값 추출
	//인자 : UINT64 SessionID
	//리턴 : short INDEX
	======================================================================*/
	short indexSessionID (UINT64 SessionID)
	{
		return (short)(SessionID >> 48);
	}


	/*======================================================================
	//PostRecv
	//설명 : RecvQ를 WSARecv로 등록하는 작업.
	//인자 : Session *
	//리턴 : 없음
	======================================================================*/
	void PostRecv (Session *p);


	/*======================================================================
	//PostSend
	//설명 : SendQ에 있는 Packet을 WSASend로 POST
	//인자 : Session *
	//리턴 : 없음
	======================================================================*/
	void PostSend (Session *p,bool Disconnect = false);


	/*======================================================================
	//SessionRelease
	//설명 : IOCount가 0이면 진입. UseFlag가 false면 SessionRelease작업 진행.
	//인자 : Session *
	//리턴 : 없음
	======================================================================*/
	void SessionRelease (Session *p);


	/*======================================================================
	//IODeCrement
	//설명 : 인자로 들어온 해당 세션의 IOCount 차감 및 IOCount가 0일시 Session Release함수호출
	//인자 : Session *
	//리턴 : 없음
	======================================================================*/
	void IODecrement (Session *p);

public :
	/*======================================================================
	//OnStart
	//설명 : virtual 함수. NetServer가 Start될때 같이 호출된다.
	//인자 : 없음
	//리턴 : 없음
	======================================================================*/
	virtual void OnStart (void) = 0;
	/*======================================================================
	//OnStart
	//설명 : virtual 함수. NetServer가 Stop될때 같이 호출된다.
	//인자 : 없음
	//리턴 : 없음
	======================================================================*/
	virtual void OnStop (void) = 0;
	/*======================================================================
	//OnRecv
	//설명 : virtual 함수. 패킷이 Recv되면 해당 함수가 호출된다.
	//인자 : UINT64 SessionID, Packet *p
	//리턴 : 없음
	======================================================================*/
	virtual void OnRecv (UINT64 SessionID, Packet *p) = 0;


	/*======================================================================
	//OnSend
	//설명 : virtual 함수. Send가 완료되면 해당함수가 호출된다.
	//인자 : UINT64 SessionID, INT SendByte
	//리턴 : 없음
	======================================================================*/
	virtual void OnSend (UINT64 SessionID, INT SendByte) = 0;


	/*======================================================================
	//OnClientJoin
	//설명 : virtual 함수. 새로운 Client가 접속하면 해당함수가 호출된다.
	//인자 : UINT64 SessionID, WCHAR *IP, int PORT
	//리턴 : 없음
	======================================================================*/
	virtual bool OnClientJoin (UINT64 SessionID, WCHAR *IP, int PORT) = 0;

	/*======================================================================
	//OnClientLeave
	//설명 : virtual 함수. Client가 접속해제되면 해당함수가 호출된다.
	//인자 : UINT64 SessionID
	//리턴 : 없음
	======================================================================*/
	virtual void OnClientLeave (UINT64 SessionID) = 0;


	/*======================================================================
	//SendPacket
	//설명 : Packet을 SendQ에 넣고 WSASend함수 호출
	//인자 : UINT64 SessionID, Packet *
	//리턴 : 없음
	======================================================================*/
	void SendPacket (UINT64 SessionID, Packet *pack);


	/*======================================================================
	//Disconnect
	//설명 : 해당 세션의 TCP 연결 해제 요청 함수.
	//인자 : UINT64 SessionID
	//리턴 : 없음
	======================================================================*/
	void Disconnect (UINT64 SessionID);


	/*======================================================================
	//Start
	//설명 : NetworkServer On
	//인자 : WCHAR * 서버IP, int PORT번호, int 동시접속 Session수, int 워커스레드 최대숫자
	//리턴 : 서버 작동 여부. true false;
	======================================================================*/
	bool Start (WCHAR *ServerIP, int PORT, int Session_Max, int WorkerThread_Num);


	/*======================================================================
	//Stop
	//설명 : NetworkServer Off
	//인자 : 없음
	//리턴 : 서버 중지 여부. true false;
	======================================================================*/
	bool Stop (void);


	/*////////////////////////////////////////////////////////////////////////////////////////////////////
	//외부에서 확인 할 수 있는 수치 인터페이스모음.
	////////////////////////////////////////////////////////////////////////////////////////////////////*/
	/*======================================================================
	//RecvTPS
	//설명 : 초당 Recv수.
	//인자 : bool Reset여부. true일 경우 RecvTPS가 0으로 초기화됨.
	//리턴 : UINT
	======================================================================*/
	UINT RecvTPS (bool Reset)
	{
		UINT RecvTPS = _RecvPacketTPS;
		if ( Reset )
		{
			InterlockedExchange ((volatile LONG *)&_RecvPacketTPS, 0);
		}
		return RecvTPS;
	}

	/*======================================================================
	//SendTPS
	//설명 : 초당 Send수.
	//인자 : bool Reset여부. true일 경우 SendTPS가 0으로 초기화됨.
	//리턴 : UINT
	======================================================================*/
	UINT SendTPS (bool Reset)
	{
		UINT SendTPS = _SendPacketTPS;
		if ( Reset )
		{
			InterlockedExchange (( volatile LONG * )&_SendPacketTPS, 0);
		}
		return SendTPS;
	}


	/*======================================================================
	//AcceptTotal
	//설명 : 서버가 켜진뒤로 접속해온 클라이언트의 총 숫자
	//인자 : 없음
	//리턴 : UINT
	======================================================================*/
	UINT AcceptTotal (void)
	{
		return _AcceptTotal;
	}


	/*======================================================================
	//AcceptTPS
	//설명 : 초당 Accept수
	//인자 : bool Reset여부. true일 경우 AcceptTPS가 0으로 초기화됨.
	//리턴 : UINT
	======================================================================*/
	UINT AcceptTPS (bool Reset)
	{
		UINT AcceptTPS = _AcceptTPS;
		if ( Reset )
		{
			InterlockedExchange (( volatile LONG * )&_AcceptTPS, 0);
		}
		return AcceptTPS;
	}

	/*======================================================================
	//Use_SessionCnt
	//설명 : 현재 접속해있는 클라이언트의 숫자.
	//인자 : 없음
	//리턴 : UINT
	======================================================================*/
	int Use_SessionCnt (void)
	{
		return _Use_Session_Cnt;
	}

	/*======================================================================
	//Full_MemPoolCnt
	//설명 : 패킷풀의 총 사이즈
	//인자 : 없음
	//리턴 : double
	======================================================================*/
	int Full_MemPoolCnt (void)
	{
		return Packet::PacketPool->GetFullCount ();
	}

	/*======================================================================
	//Alloc_MemPoolCnt
	//설명 : 현재 Alloc중인 Packet의 총 사이즈
	//인자 : 없음
	//리턴 : double
	======================================================================*/
	int Alloc_MemPoolCnt (void)
	{
		return Packet::PacketPool->GetAllocCount ();
	}
protected:

	/*======================================================================
	//AcceptThread
	//설명 : AcceptThread() 함수 랩핑.
	//인자 : LPVOID pParam; = CLanServer this pointer 를 일로 넘겨받음.
	//리턴 : 0
	======================================================================*/
	static unsigned int WINAPI AcceptThread (LPVOID pParam);


	/*======================================================================
	//WorkerThread
	//설명 : WorkerThread() 함수 랩핑.
	//인자 : LPVOID pParam; = CLanServer this pointer 를 일로 넘겨받음.
	//리턴 : 0
	======================================================================*/
	static unsigned int WINAPI WorkerThread (LPVOID pParam);
};
