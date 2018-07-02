
#pragma once
#include <Windows.h>
#include "MemoryPool.h"

struct HEADER
{
	char Code;
	short Len;
	unsigned char RandXOR;
	unsigned char CheckSum;
};

struct ErrorAlloc
{
	int UseDataSize;
	int GetSize;
	int PutSize;
	int UseHeaderSize;

	int Flag;
};
enum ThrowCase
{
	Get_Error = 1,
	Put_Error = 2,
	PutHeader_Error = 3
};

class Packet
{
public:


	enum PACKET
	{
		BUFFER_DEFAULT			= 10000,		// 패킷의 기본 버퍼 사이즈.
		HEADERSIZE_DEFAULT		= 5
	};
	// 생성자, 파괴자.
			Packet();
			Packet(int iBufferSize);
			Packet(const Packet &SrcPacket);
			Packet (unsigned char PacketCode,char XOR_Code1,char XOR_Code2,int iBufferSize);

	virtual	~Packet();

	// 패킷 초기화.
	void	Initial(int iBufferSize = BUFFER_DEFAULT);

	//RefCnt를 1 증가시킴. 
	void	Add (void);

	// 패킷 비우기.
	void	Clear(void);


	// 버퍼 사이즈 얻기.
	int		GetBufferSize(void) { return _iBufferSize; }

	// 현재 사용중인 사이즈 얻기.
	int		GetDataSize(void) { return _iDataSize; }



	// 버퍼 포인터 얻기.
	char	*GetBufferPtr(void) { return HeaderStartPos; }

	// 버퍼 Pos 이동.
	int		MoveWritePos(int iSize);
	int		MoveReadPos(int iSize);






	// 연산자 오퍼레이터.
	Packet	&operator = (Packet &SrcPacket);

	//////////////////////////////////////////////////////////////////////////
	// 넣기.	각 변수 타입마다 모두 만듬.
	//////////////////////////////////////////////////////////////////////////
	Packet	&operator << (BYTE byValue);
	Packet	&operator << (char chValue);
	Packet &operator << (WCHAR &chValue);


	Packet	&operator << (short shValue);
	Packet	&operator << (WORD wValue);

	Packet	&operator << (int iValue);
	Packet	&operator << (DWORD dwValue);
	Packet	&operator << (float fValue);

	Packet	&operator << (__int64 iValue);
	Packet	&operator << (double dValue);

	//////////////////////////////////////////////////////////////////////////
	// 빼기.	각 변수 타입마다 모두 만듬.
	//////////////////////////////////////////////////////////////////////////
	Packet	&operator >> (BYTE &byValue);
	Packet	&operator >> (char &chValue);
	Packet &operator >> (WCHAR &chValue);

	Packet	&operator >> (short &shValue);
	Packet	&operator >> (WORD &wValue);

	Packet	&operator >> (int &iValue);
	Packet	&operator >> (DWORD &dwValue);
	Packet	&operator >> (float &fValue);

	Packet	&operator >> (__int64 &iValue);
	Packet	&operator >> (double &dValue);




	// 데이타 얻기.
	// Return 복사한 사이즈.
	int		GetData(char *chpDest, int iSize);

	// 데이타 삽입.
	// Return 복사한 사이즈.
	int		PutData(char *chpSrc, int iSrcSize);


protected:

	// RefCnt를 하나 차감시키고 REfCnt가 0이 되면 자기자신 delete하고 빠져나옴.
	void	Release (void);


	//------------------------------------------------------------
	// 패킷버퍼 / 버퍼 사이즈.
	//------------------------------------------------------------
	char	BufferDefault[BUFFER_DEFAULT];
	char	*BufferExpansion;

	char	*Buffer;
	int		_iBufferSize;
	//------------------------------------------------------------
	// 패킷버퍼 시작 위치.
	//------------------------------------------------------------
	char	*DataFieldStart;
	char	*DataFieldEnd;
	char	*HeaderStartPos;


	//------------------------------------------------------------
	// 버퍼의 읽을 위치, 넣을 위치.
	//------------------------------------------------------------
	char	*ReadPos;
	char	*WritePos;


	//------------------------------------------------------------
	// 현재 버퍼에 사용중인 사이즈.
	//------------------------------------------------------------
	int		_iDataSize;
	int		HeaderSize;
	//------------------------------------------------------------
	// 현재 Packet의 RefCnt
	//------------------------------------------------------------
	int iRefCnt;

private :
	static CMemoryPool<Packet> *PacketPool;

	int	PutHeader (char *chpSrc, int iSrcSize);

	unsigned char _PacketCode;
	char _XORCode1;
	char _XORCode2;
	bool _EnCodeFlag;


	bool EnCode (void);
	bool DeCode (HEADER *SrcHeader = NULL);

	void AcquireLOCK (void)
	{
		AcquireSRWLockExclusive (&_CS);
	}
	void ReleaseLOCK (void)
	{
		ReleaseSRWLockExclusive (&_CS);
	}
	SRWLOCK _CS;

public :
	
	static void Initialize (void)
	{
		if ( PacketPool == NULL )
		{
			PacketPool = new CMemoryPool<Packet> (0);
		}
		return;
	}
	

	static Packet *Alloc (void)
	{
		Packet *p = PacketPool->Alloc ();
		return p;
	}

	static bool Free (Packet *p)
	{
		bool flag;
		if ( InterlockedDecrement (( volatile long * )&p->iRefCnt) == 0 )
		{
			flag = PacketPool->Free (p);
			return flag;
		}
		return true;
	}
	friend class CNetServer;
	friend class CLanServer;

};
