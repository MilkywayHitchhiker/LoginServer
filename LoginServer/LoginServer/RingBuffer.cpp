
#include"stdafx.h"
#include"RingBuffer.h"


//생성자
CRingbuffer::CRingbuffer (void)
{

	pBuffer = new char[dfBuffSize];
	BufferSize = dfBuffSize;
	Front = 0;
	Rear = 0;

	//크리티컬 섹션 초기화
	InitializeSRWLock (&cs);

	return;
}
CRingbuffer::CRingbuffer (int iBufferSize)
{

	pBuffer = new char[iBufferSize];
	BufferSize = iBufferSize;
	Front = 0;
	Rear = 0;

	//크리티컬 섹션 초기화
	InitializeSRWLock (&cs);

	return;
}

CRingbuffer::~CRingbuffer (void)
{
	delete[]pBuffer;
	return;
}

//초기화
void CRingbuffer::Initial (int iBufferSize)
{
	delete []pBuffer;

	pBuffer = new char[iBufferSize];
	BufferSize = iBufferSize;
	Front = 0;
	Rear = 0;

	return;
}


//크리티컬 섹션 락
void CRingbuffer::Lock (void)
{
	AcquireSRWLockExclusive (&cs);
	return;
}
//크리티컬 섹션 락 해제
void CRingbuffer::Free (void)
{
	ReleaseSRWLockExclusive (&cs);
	return;
}

//현재 버퍼 크기(사용 못하는 1byte제외) 반환.
int CRingbuffer::GetBufferSize (void)
{
	return BufferSize - 1;
}


//현재 사용중인 버퍼 크기 반환
int CRingbuffer::GetUseSize (void)
{
	int Size;
	//쓰기 위치가 읽기 위치보다 뒤에 있다면.
	if ( Rear > Front || Rear == Front)
	{
		Size = Rear - Front;
	}

	//읽기 위치가 쓰기 위치보다 뒤에 있다면.
	else if ( Front > Rear )
	{
		Size = (BufferSize - Front) + Rear;
	}
	else
	{
		Size = 0;
	}
	return Size;
}


//현재 사용가능한 버퍼 크기 반환
int CRingbuffer::GetFreeSize (void)
{
	int Size;
	//쓰기 위치가 읽기 위치보다 뒤에 있다면.
	if ( Rear > Front || Rear == Front )
	{
		//총크기에서 쓰기위치를 빼고 Front까지의 사이즈를 더한다. 링버퍼라서 총사이즈 -1;
		Size = (BufferSize - Rear) + (Front - 1);
	}
	//읽기 위치가 쓰기위치보다 뒤에 있다면
	else if ( Front > Rear )
	{
		Size = (Front - Rear) - 1;
	}
	else
	{
		Size = 0;
	}
	return Size;
}

//버퍼 포인터로 외부에서 한방에 읽을수 있는 길이
int CRingbuffer::GetNotBrokenGetSize (void)
{
	int Size;

	//쓰기 위치가 읽기 위치보다 뒤에 있다면
	//읽기 위치부터 쓰기위치까지 한방에 긁어올 수 있으므로
	//쓰기위치 - 읽기위치의 Size를 반환한다.
	if ( Rear > Front || Rear == Front)
	{
		Size = Rear - Front;
	}

	//읽기 위치가 쓰기 위치보다 뒤에 있다면
	//읽기 위치부터 링버퍼의 끝까지 갔다가 다시 처음부터 Rear까지 읽어야 되므로
	//읽기 위치부터 링버퍼 끝까지의 Size를 반환한다.
	else if ( Front > Rear )
	{
		Size =  BufferSize - Front;
	}
	else
	{
		Size = 0;
	}

	return Size;
}


//버퍼 포인터로 외부에서 한방에 쓸수 있는 길이
int CRingbuffer::GetNotBrokenPutSize (void)
{
	int Size;

	//쓰기 위치가 읽기 위치보다 뒤에 있다면
	//쓰기 위치부터 링버퍼의 끝까지 한번에 쓸 수 있으므로
	//쓰기위치부터 링버퍼 끝까지의 Size를 반환한다.
	if ( Rear > Front || Rear == Front)
	{
		Size = BufferSize - Rear;
	}

	//읽기 위치가 쓰기 위치보다 뒤에 있다면
	//쓰기위치부터 읽기 위치까지 한번에 쓸 수 있으므로
	//읽기 위치 - 쓰기위치 한 값에 링버퍼기때문에 Front Rear중복방지를 위한 -1
	else if ( Front > Rear )
	{
		Size = (Front - Rear) - 1;
	}

	return Size;
}


//WritePos에 데이타 넣음
int CRingbuffer::Put (char *chpData, int iSize)
{
	int PutSize = iSize;
	int CutSizeOne;
	int CutSizeTwo;
	int _Rear = Rear;	
	int _Front = Front;
	int ReturnSize = 0;


	//넣어야될 사이즈가 넣을 수 있는 사이즈보다 큰 경우.
	if ( iSize > GetFreeSize () )
	{
		PutSize = GetFreeSize ();
	}

	//쓰기위치가 읽기위치보다 뒤에 있을경우
	if ( _Rear > _Front || _Rear == _Front)
	{
		//쓰기위치 + Size가 링버퍼 사이즈보다 작을경우
		if ( _Rear + PutSize < BufferSize )
		{
			memcpy_s (&pBuffer[_Rear], PutSize, chpData, PutSize);
			_Rear = (_Rear + PutSize) % BufferSize;
			ReturnSize += PutSize;
		}
		//쓰기위치 + Size가 링버퍼 사이즈보다 클경우. = Front가 Rear보다 커질 경우.
		else if ( _Rear + PutSize >= BufferSize )
		{
			CutSizeOne = GetNotBrokenPutSize ();
			memcpy_s (&pBuffer[_Rear], CutSizeOne, chpData, CutSizeOne);
			_Rear = (_Rear + CutSizeOne) % BufferSize;
			ReturnSize += CutSizeOne;

			CutSizeTwo = PutSize - CutSizeOne;
			memcpy_s (&pBuffer[_Rear], CutSizeTwo, &chpData[CutSizeOne], CutSizeTwo);
			_Rear = (_Rear + CutSizeTwo) % BufferSize;
			ReturnSize += CutSizeTwo;

		}
	}

	//읽기 위치가 쓰기위치보다 뒤에 있을 경우
	else if ( _Rear < _Front )
	{
		memcpy_s (&pBuffer[_Rear], PutSize, chpData, PutSize);
		ReturnSize += PutSize;
		_Rear = (_Rear + PutSize) % BufferSize;
	}
	

	Rear = _Rear;
	return ReturnSize;
	
}

//ReadPos에서 데이터 가져옴. ReadPos이동.
int CRingbuffer::Get (char *chpDest, int iSize)
{
	int _Front = Front;
	int _Rear = Rear;
	int GetSize = iSize;
	int CutSizeOne,CutSizeTwo;
	int ReturnSize = 0;


	//읽어야될 사이즈가 읽을 수 있는 사이즈보다 클 경우
	if ( iSize > GetUseSize () )
	{
		GetSize = GetUseSize ();
	}

	//쓰기 위치가 읽기 위치보다 뒤에 있을 경우
	if ( _Rear > _Front || _Rear == _Front)
	{
		memcpy_s (chpDest, GetSize, &pBuffer[_Front], GetSize);
		_Front = (_Front + GetSize) % BufferSize;
		ReturnSize += GetSize;
	}

	//읽기 위치가 쓰기 위치보다 뒤에있을 경우

	else if ( _Front > _Rear )
	{
		//읽기위치 + GetSize가 BufferSize보다 작을 경우
		if ( _Front + GetSize <= BufferSize )
		{
			memcpy_s (chpDest, GetSize, &pBuffer[_Front], GetSize);
			_Front = (_Front + GetSize) % BufferSize;
			ReturnSize += GetSize;
		}
		//읽기 위치 + GetSize가 BufferSize와 같거나 클경우
		else if ( _Front + GetSize > BufferSize )
		{
			CutSizeOne = GetNotBrokenGetSize ();
			memcpy_s (chpDest, CutSizeOne, &pBuffer[_Front], CutSizeOne);
			_Front = (_Front + CutSizeOne) % BufferSize;
			ReturnSize += CutSizeOne;

			CutSizeTwo = GetSize - CutSizeOne;
			memcpy_s (&chpDest[CutSizeOne], CutSizeTwo, &pBuffer[_Front], CutSizeTwo);
			_Front = (_Front + CutSizeTwo) % BufferSize;
			ReturnSize += CutSizeTwo;
		}
	}
	
	Front = _Front;
	return ReturnSize;

}


//ReadPos에서 데이터 가져옴. ReadPos고정.
int CRingbuffer::Peek (char *chpDest, int iSize)
{
	int _Front = Front;
	int _Rear = Rear;
	int GetSize = iSize;
	int CutSizeOne, CutSizeTwo;
	int ReturnSize = 0;


	//읽어야될 사이즈가 읽을 수 있는 사이즈보다 클 경우
	if ( iSize > GetUseSize () )
	{
		GetSize = GetUseSize ();
	}

	//쓰기 위치가 읽기 위치보다 뒤에 있을 경우
	if ( _Rear > _Front || _Rear == _Front )
	{
		memcpy_s (chpDest, GetSize, &pBuffer[_Front], GetSize);
		_Front = (_Front + GetSize) % BufferSize;
		ReturnSize += GetSize;
	}

	//읽기 위치가 쓰기 위치보다 뒤에있을 경우

	else if ( _Front > _Rear )
	{
		//읽기위치 + GetSize가 BufferSize보다 작을 경우
		if ( _Front + GetSize <= BufferSize )
		{
			memcpy_s (chpDest, GetSize, &pBuffer[_Front], GetSize);
			_Front = (_Front + GetSize) % BufferSize;
			ReturnSize += GetSize;
		}
		//읽기 위치 + GetSize가 BufferSize와 같거나 클경우
		else if ( _Front + GetSize > BufferSize )
		{
			CutSizeOne = GetNotBrokenGetSize ();
			memcpy_s (chpDest, CutSizeOne, &pBuffer[_Front], CutSizeOne);
			_Front = (_Front + CutSizeOne) % BufferSize;
			ReturnSize += CutSizeOne;

			CutSizeTwo = GetSize - CutSizeOne;
			memcpy_s (&chpDest[CutSizeOne], CutSizeTwo, &pBuffer[_Front], CutSizeTwo);
			_Front = (_Front + CutSizeTwo) % BufferSize;
			ReturnSize += CutSizeTwo;
		}
	}

	return ReturnSize;
}


//원하는 길이만큼 읽기 위치에서 삭제/쓰기 위치 이동

void CRingbuffer::RemoveData (int iSize)
{
	if ( iSize > GetUseSize () )
	{
		iSize = GetUseSize ();
	}
	Front = (Front + iSize) % BufferSize;
	return;
}
int CRingbuffer::MoveWritePos (int iSize)
{
	if ( iSize > GetFreeSize () )
	{
		iSize = GetFreeSize ();
	}
	Rear = (Rear + iSize) % BufferSize;
	return iSize;
}

//버퍼의 모든 데이터 삭제
void CRingbuffer::ClearBuffer (void)
{
	Front = 0;
	Rear = 0;
	return;
}

//버퍼의 포인터 얻음.
char *CRingbuffer::GetBufferPtr (void)
{
	return pBuffer;
}

//버퍼의 ReadPos 포인터 얻음
char *CRingbuffer::GetReadBufferPtr (void)
{
	return &pBuffer[Front];
}

//버퍼의 WritePos 포인터 얻음
char *CRingbuffer::GetWriteBufferPtr (void)
{
	return &pBuffer[Rear];
}