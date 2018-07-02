#include "stdafx.h"
#include <windows.h>
#include "PacketPool.h"

#include"ServerConfig.h"

CMemoryPool<Packet> *Packet::PacketPool;


Packet::Packet() : Buffer (NULL),DataFieldStart (NULL),DataFieldEnd (NULL),ReadPos (NULL),WritePos (NULL)
{
	//버퍼 사이즈를 입력하지 않는다면, 기본치로 생성.
	Buffer = NULL;
	BufferExpansion = NULL;

	Initial();
	return;
}


Packet::Packet(int iBufferSize) : Buffer (NULL), DataFieldStart (NULL), DataFieldEnd (NULL), ReadPos (NULL), WritePos (NULL)
{
	Buffer = NULL;
	BufferExpansion = NULL;

	Initial(iBufferSize);
	return;
}

Packet::Packet(const Packet &SrcPacket) : Buffer (NULL),_iBufferSize (0), DataFieldStart (NULL), DataFieldEnd (NULL), ReadPos (NULL), WritePos (NULL)
{
	Buffer = NULL;
	BufferExpansion = NULL;
	Initial(SrcPacket._iBufferSize);
	
	/*-----------------------------------------------------------------
	원본 패킷 클래스에서 복사해온다.
	-------------------------------------------------------------------*/
	PutData(SrcPacket.ReadPos, SrcPacket._iDataSize);
	return;
}

Packet::Packet (unsigned char PacketCode, char XOR_Code1, char XOR_Code2, int iBufferSize = 0)
{

	Buffer = NULL;
	BufferExpansion = NULL;

	_PacketCode = PacketCode;
	_XORCode1 = XOR_Code1;
	_XORCode2 = XOR_Code2;
	srand (time (NULL));

	//버퍼 사이즈를 입력하지 않는다면, 기본사이즈로 생성.
	if ( iBufferSize == 0 )
	{
		Initial ();
	}
	else
	{
		Initial (iBufferSize);
	}

	return;
}



Packet::~Packet()
{
	Release();

	return;
}






// 패킷 초기화.
void Packet::Initial(int iBufferSize)
{
	_iBufferSize = iBufferSize;
	_EnCodeFlag = false;
	if ( NULL == Buffer )
	{
		if ( BUFFER_DEFAULT < _iBufferSize )
		{
			BufferExpansion = new char[_iBufferSize];
			Buffer = BufferExpansion;
		}
		else
		{
			BufferExpansion = NULL;
			Buffer = BufferDefault;
		}
	}

	DataFieldStart = Buffer+HEADERSIZE_DEFAULT;
	DataFieldEnd = Buffer + (_iBufferSize- HEADERSIZE_DEFAULT);
	ReadPos = WritePos = HeaderStartPos = DataFieldStart;

	InitializeSRWLock (&_CS);

	_PacketCode = _PACKET_CODE;
	_XORCode1 = _PACKET_KEY1;
	_XORCode2 = _PACKET_KEY2;
	srand (time (NULL));


	_iDataSize = 0;
	HeaderSize = 0;
	iRefCnt = 1;
	
	return;
}

//RefCnt를 1 증가시킴. 
void Packet::Add (void)
{
	InterlockedIncrement (( volatile long * )&iRefCnt);
	return;
}

// RefCnt를 하나 차감시키고 REfCnt가 0이 되면 자기자신 delete하고 빠져나옴.
void Packet::Release (void)
{
	if ( NULL != BufferExpansion )
	{
		delete[] BufferExpansion;
	}
	delete this;
	return;
}


// 패킷 초기화
void Packet::Clear(void)
{

	DataFieldStart = Buffer + HEADERSIZE_DEFAULT;
	DataFieldEnd = Buffer + (_iBufferSize - HEADERSIZE_DEFAULT);

	ReadPos = WritePos = HeaderStartPos = DataFieldStart;

	_iDataSize = 0;
}


// Wirtepos 이동. (음수이동은 안됨)
int Packet::MoveWritePos(int iSize)
{
	if ( 0 > iSize ) return 0;

	/*-----------------------------------------------------------------
	 이동할 자리가 부족하다면.
	-------------------------------------------------------------------*/
	if ( WritePos + iSize > DataFieldEnd )
		return 0;

	WritePos += iSize;
	_iDataSize += iSize;

	return iSize;
}

// 버퍼 ReadPos 이동.
int Packet::MoveReadPos(int iSize)
{
	if ( 0 > iSize ) return 0;

	// 이동할만큼 데이타가 없다면.
	if ( iSize > _iDataSize )
		return 0;

	ReadPos += iSize;
	_iDataSize -= iSize;

	return iSize;
}








//////////////////////////////////////////////////////////////////////////
// 연산자 오퍼레이터 시작
//////////////////////////////////////////////////////////////////////////
Packet &Packet::operator = (Packet &SrcPacket)
{
	ReadPos = Buffer;
	WritePos = Buffer;

	//원본 패킷 클래스에서 복사해온다.
	PutData(SrcPacket.ReadPos, SrcPacket._iDataSize);

	return *this;
}

// 넣기.	각 변수 타입마다 모두 만듬.
Packet &Packet::operator << (BYTE byValue)
{
	PutData(( char * )&byValue, sizeof(BYTE)); //캐스팅 기본(char *)&value
	return *this;
}

Packet &Packet::operator << (char chValue)
{
	PutData(&chValue, sizeof(char));
	return *this;
}

Packet &Packet::operator << (WCHAR &chValue)
{
	PutData (( char * )&chValue, sizeof (WCHAR));
	return *this;
}

Packet &Packet::operator << (short shValue)
{
	PutData(( char * )&shValue, sizeof(short));
	return *this;
}

Packet &Packet::operator << (WORD wValue)
{
	PutData(( char * )&wValue, sizeof(WORD));
	return *this;
}

Packet &Packet::operator << (int iValue)
{
	PutData(reinterpret_cast<char *>(&iValue), sizeof(int));

	return *this;
}

Packet &Packet::operator << (DWORD dwValue)
{
	PutData(( char * )&dwValue, sizeof(DWORD));
	return *this;
}

Packet &Packet::operator << (float fValue)
{
	PutData(( char * )&fValue, sizeof(float));
	return *this;
}

Packet &Packet::operator << (__int64 iValue)
{
	PutData(( char * )&iValue, sizeof(__int64));
	return *this;
}

Packet &Packet::operator << (double dValue)
{
	PutData((char *)&dValue, sizeof(double));
	return *this;
}

//////////////////////////////////////////////////////////////////////////
// 빼기.	각 변수 타입마다 모두 만듬.
//////////////////////////////////////////////////////////////////////////
Packet &Packet::operator >> (BYTE &byValue)
{
	GetData((char *)&byValue, sizeof(BYTE));
	return *this;
}

Packet &Packet::operator >> (char &chValue)
{
	GetData(&chValue, sizeof(char));
	return *this;
}

Packet &Packet::operator >> (WCHAR &chValue)
{
	GetData ((char *)&chValue, sizeof (WCHAR));
	return *this;
}

Packet &Packet::operator >> (short &shValue)
{
	GetData((char *)&shValue, sizeof(short));
	return *this;
}

Packet &Packet::operator >> (WORD &wValue)
{
	GetData((char *)&wValue, sizeof(WORD));
	return *this;
}

Packet &Packet::operator >> (int &iValue)
{
	GetData((char *)&iValue, sizeof(int));
	return *this;
}

Packet &Packet::operator >> (DWORD &dwValue)
{
	GetData((char *)&dwValue, sizeof(DWORD));
	return *this;
}

Packet &Packet::operator >> (float &fValue)
{
	GetData((char *)&fValue, sizeof(float));
	return *this;
}

Packet &Packet::operator >> (__int64 &iValue)
{
	GetData((char *)&iValue, sizeof(__int64));
	return *this;
}

Packet &Packet::operator >> (double &dValue)
{
	GetData((char *)&dValue, sizeof(double));
	return *this;
}







// 데이타 얻기.
int Packet::GetData(char *chpDest, int iSize)
{
	
	//얻고자 하는 만큼의 데이타가 없다면.
	if ( iSize > _iDataSize )
	{
		ErrorAlloc err;
		err.PutSize = 0;
		err.UseHeaderSize = 0;
		err.GetSize = iSize;
		err.UseDataSize = _iDataSize;
		err.Flag = Get_Error;
		throw err;
	}

	memcpy(chpDest, ReadPos, iSize);
	ReadPos += iSize;

	_iDataSize -= iSize;

	return iSize;

}


// 데이타 삽입.
int Packet::PutData(char *chpSrc, int iSrcSize)
{
	//넣을 자리가 없다면.
	if ( WritePos + iSrcSize > DataFieldEnd )
	{
			ErrorAlloc err;
			err.GetSize = 0;
			err.UseHeaderSize = 0;
			err.PutSize = iSrcSize;
			err.UseDataSize = _iDataSize;

			err.Flag = Put_Error;
			throw err;
	}

	memcpy(WritePos, chpSrc, iSrcSize);
	WritePos += iSrcSize;

	_iDataSize += iSrcSize;

	return iSrcSize;
}

// 헤더 삽입.
int	Packet::PutHeader (char *chpSrc, int iSrcSize)
{
	if ( iSrcSize > HEADERSIZE_DEFAULT - HeaderSize )
	{
		ErrorAlloc err;
		err.GetSize = 0;
		err.PutSize = 0;
		err.UseDataSize = _iDataSize;
		err.UseHeaderSize = HeaderSize;
		err.Flag = PutHeader_Error;
		throw err;
	}
		
	char *PrePos = HeaderStartPos - iSrcSize;
	memcpy (PrePos, chpSrc, iSrcSize);
	HeaderStartPos = PrePos;

	_iDataSize += iSrcSize;
	HeaderSize += iSrcSize;
	return  HeaderSize;
}



//===============================================================================================
//= 보내기 암호화 과정
//1. Rand XOR Code 생성
//2. Payload 의 checksum 계산
//3. Rand XOR Code 로[CheckSum, Payload] 바이트 단위 xor
//4. 고정 XOR Code 1 로[Rand XOR Code, CheckSum, Payload] 를 XOR
//5. 고정 XOR Code 2 로[Rand XOR Code, CheckSum, Payload] 를 XOR
//===============================================================================================
bool Packet::EnCode (void)
{
	char *ReadPosBuff;
	
	AcquireLOCK ();
	if ( _EnCodeFlag )
	{
		ReleaseLOCK ();
		return true;
	}
	_EnCodeFlag = true;

	int DataSize = _iDataSize;
	unsigned char XORCode1 = _XORCode1;
	unsigned char XORCode2 = _XORCode2;

	HEADER Header;

	Header.Code = _PACKET_CODE;
	Header.Len = DataSize;

	//1. Rand XOR Code 는 보내는 이가 랜덤하게 1byte 코드를 생성
	Header.RandXOR = rand () % 255;

	//2. CheckSum Payload 부분을 1byte 씩 모두 더해서 % 256 한 unsigned char 값
	ReadPosBuff = ReadPos;
	int CheckSum = 0;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		CheckSum += ReadPosBuff[Cnt];
	}
	Header.CheckSum = CheckSum % 256;

	//3. Rand XOR Code로 ChecSum, Payload 바이트 단위 xor
	ReadPosBuff = ReadPos;
	Header.CheckSum = Header.CheckSum ^ Header.RandXOR;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		ReadPosBuff[Cnt] = ReadPosBuff[Cnt] ^ Header.RandXOR;
	}

	//4. 고정 XOR Code 1 로[Rand XOR Code, CheckSum, Payload] 를 XOR
	ReadPosBuff = ReadPos;
	Header.RandXOR = Header.RandXOR ^ XORCode1;
	Header.CheckSum = Header.CheckSum ^ XORCode1;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		ReadPosBuff[Cnt] = ReadPosBuff[Cnt] ^ XORCode1;
	}

	//5. 고정 XOR Code 2 로[Rand XOR Code, CheckSum, Payload] 를 XOR
	ReadPosBuff = ReadPos;
	Header.RandXOR = Header.RandXOR ^ XORCode2;
	Header.CheckSum = Header.CheckSum ^ XORCode2;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		ReadPosBuff[Cnt] = ReadPosBuff[Cnt] ^ XORCode2;
	}

	//지역변수 Buff의 Data를 HeaderPos로 옮김.
	PutHeader ((char *)&Header.CheckSum, 1);
	PutHeader (( char * )&Header.RandXOR, 1);
	PutHeader (( char * )&Header.Len, 2);
	PutHeader (( char * )&Header.Code, 1);


	ReleaseLOCK ();

	return true;
}





//===============================================================================================
//= 받기 복호화 과정
//1. 고정 XOR Code 2 로[Rand XOR Code, CheckSum, Payload] 를 XOR
//2. 고정 XOR Code 1 로[Rand XOR Code, CheckSum, Payload] 를 XOR
//3. Rand XOR Code 를 파악.
//4. Rand XOR Code 로[CheckSum - Payload] 바이트 단위 xor
//5. Payload 를 checksum 공식으로 계산 후 패킷의 checksum 과 비교
//===============================================================================================
bool Packet::DeCode (HEADER *SrcHeader)
{
	HEADER Buff;
	if ( SrcHeader == NULL )
	{
		GetData (( char * )&Buff.Code, 1);
		GetData (( char * )&Buff.Len, 2);
		GetData (( char * )&Buff.RandXOR, 1);
		GetData (( char * )&Buff.CheckSum, 1);
	}
	else
	{
		Buff.CheckSum = SrcHeader->CheckSum;
		Buff.Code = SrcHeader->Code;
		Buff.Len = SrcHeader->Len;
		Buff.RandXOR = SrcHeader->RandXOR;
	}

	unsigned char XORCode1 = _XORCode1;
	unsigned char XORCode2 = _XORCode2;
	char *ReadPosBuff = ReadPos;
	int DataSize = _iDataSize;


	//1. 고정 XOR Code 2 로[Rand XOR Code, CheckSum, Payload] 를 XOR
	Buff.RandXOR = Buff.RandXOR ^ XORCode2;
	Buff.CheckSum = Buff.CheckSum ^ XORCode2;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		ReadPosBuff[Cnt] = ReadPosBuff[Cnt] ^ XORCode2;
	}


	//2. 고정 XOR Code 1 로[Rand XOR Code, CheckSum, Payload] 를 XOR
	ReadPosBuff = ReadPos;
	Buff.RandXOR = Buff.RandXOR ^ XORCode1;
	Buff.CheckSum = Buff.CheckSum ^ XORCode1;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		ReadPosBuff[Cnt] = ReadPosBuff[Cnt] ^ XORCode1;
	}


	//3. Rand XOR Code 를 파악.
	//4. Rand XOR Code 로[CheckSum - Payload] 바이트 단위 xor
	ReadPosBuff = ReadPos;
	Buff.CheckSum = Buff.CheckSum ^ Buff.RandXOR;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		ReadPosBuff[Cnt] = ReadPosBuff[Cnt] ^ Buff.RandXOR;
	}

	//5. Payload 를 checksum 공식으로 계산 후 패킷의 checksum 과 비교
	ReadPosBuff = ReadPos;
	int CheckSum = 0;
	for ( int Cnt = 0; Cnt < DataSize; Cnt++ )
	{
		CheckSum += ReadPosBuff[Cnt];
	}
	unsigned char Chk = ( unsigned char )CheckSum % 256;

	if ( Buff.CheckSum != Chk )
	{
		return false;
	}
	return true;
}