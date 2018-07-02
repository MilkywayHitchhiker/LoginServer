#pragma once
#include<Windows.h>
#define dfBuffSize 4086
class CRingbuffer
{
protected:

	SRWLOCK cs;

	char *pBuffer;

	//버퍼 총 사이즈
	int BufferSize;

	//읽기위치
	int Front;

	//쓰기위치
	int Rear;
	

public : 
	
	//생성자
	CRingbuffer (void);
	CRingbuffer (int iBufferSize);

	//파괴자
	~CRingbuffer (void);

	//크리티컬 섹션 락
	void Lock (void);
	//크리티컬 섹션 락 해제
	void Free (void);

	//초기화
	void Initial (int iBufferSize);
	
	//현재 버퍼 크기(사용 못하는 1byte제외) 반환.
	int GetBufferSize (void);


	//현재 사용중인 버퍼 크기 반환
	int GetUseSize (void);

	
	//현재 사용가능한 버퍼 크기 반환
	int GetFreeSize (void);

	//버퍼 포인터로 외부에서 한방에 읽을수 있는 길이
	int GetNotBrokenGetSize (void);


	//버퍼 포인터로 외부에서 한방에 쓸수 있는 길이
	int GetNotBrokenPutSize (void);


	//WritePos에 데이타 넣음
	int Put (char *chpData, int iSize);

	//ReadPos에서 데이터 가져옴. ReadPos이동.
	int Get (char *chpDest, int iSize);


	//ReadPos에서 데이터 가져옴. ReadPos고정.
	int Peek (char *chpDest, int iSize);


	//원하는 길이만큼 읽기 위치에서 삭제/쓰기 위치 이동

	void RemoveData (int iSize);
	int MoveWritePos (int iSize);

	//버퍼의 모든 데이터 삭제
	void ClearBuffer (void);

	//버퍼의 포인터 얻음.
	char *GetBufferPtr (void);

	//버퍼의 ReadPos 포인터 얻음
	char *GetReadBufferPtr (void);

	//버퍼의 WritePos 포인터 얻음
	char *GetWriteBufferPtr (void);

};