/*---------------------------------------------------------------

	MemoryPool.

	메모리 풀 클래스.
	특정 데이타를 일정량 할당 후 나눠쓴다.

	- 사용법.

	CMemoryPool<DATA> MemPool(300);
	DATA *pData = MemPool.Alloc();

	pData 사용

	MemPool.Free(pData);

----------------------------------------------------------------*/
#ifndef  __MEMORYPOOL__H__
#define  __MEMORYPOOL__H__
#include <assert.h>
#include "lib\Library.h"
#include <Windows.h>
#include <new.h>

#define TLS_basicChunkSize 1000



template <class DATA>
class CMemoryPool
{
#define SafeLane 0xff77668888
private:

	/*========================================================================
	// 각 블럭 앞에 사용될 노드 구조체.
	========================================================================*/
	struct st_BLOCK_NODE
	{
		DATA Data;
		INT64 Safe;

		st_BLOCK_NODE ()
		{
			stpNextBlock = NULL;
		}

		st_BLOCK_NODE *stpNextBlock;
	};


	void LOCK ()
	{
		AcquireSRWLockExclusive (&_CS);
	}
	void Release ()
	{
		ReleaseSRWLockExclusive (&_CS);
	}

public:

	/*========================================================================
	// 생성자, 파괴자.
	//
	// Parameters:	(int) 최대 블럭 개수.
	// Return:		없음.
	========================================================================*/
	CMemoryPool (int iBlockNum)
	{
		st_BLOCK_NODE *pNode, *pPreNode;
		InitializeSRWLock (&_CS);
		/*========================================================================
		// TOP 노드 할당
		========================================================================*/
		_pTop = NULL;

		/*========================================================================
		// 메모리 풀 크기 설정
		========================================================================*/
		m_iBlockCount = iBlockNum;
		if ( iBlockNum < 0 )
		{
			CCrashDump::Crash ();
			return;	// Dump
		}
		else if ( iBlockNum == 0 )
		{
			m_bStoreFlag = true;
			_pTop = NULL;
		}

		/*========================================================================
		// DATA * 크기만 큼 메모리 할당 후 BLOCK 연결
		========================================================================*/
		else
		{
			m_bStoreFlag = false;

			pNode = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE));
			_pTop = pNode;
			pPreNode = pNode;

			for ( int iCnt = 1; iCnt < iBlockNum; iCnt++ )
			{
				pNode = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE));
				pPreNode->stpNextBlock = pNode;
				pPreNode = pNode;
			}
		}
	}

	virtual	~CMemoryPool ()
	{
		st_BLOCK_NODE *pNode;

		for ( int iCnt = 0; iCnt < m_iBlockCount; iCnt++ )
		{
			pNode = _pTop;
			_pTop = _pTop->stpNextBlock;
			free (pNode);
		}
	}

	/*========================================================================
	// 블럭 하나를 할당받는다.
	//
	// Parameters: PlacementNew여부.
	// Return:		(DATA *) 데이타 블럭 포인터.
	========================================================================*/
	DATA	*Alloc (bool bPlacementNew = true)
	{
		st_BLOCK_NODE *stpBlock;
		int iBlockCount = m_iBlockCount;


		InterlockedIncrement64 (( LONG64 * )&m_iAllocCount);

		if ( iBlockCount < m_iAllocCount )
		{
			if ( m_bStoreFlag )
			{
				stpBlock = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE));
				InterlockedIncrement64 (( LONG64 * )&m_iBlockCount);
			}

			else
				return nullptr;
		}

		else
		{
			LOCK ();

			stpBlock = _pTop;
			_pTop = _pTop->stpNextBlock;

			Release ();
		}

		if ( bPlacementNew )
		{
			new (( DATA * )&stpBlock->Data) DATA;
		}

		stpBlock->Safe = SafeLane;


		return &stpBlock->Data;
	}

	/*========================================================================
	// 사용중이던 블럭을 해제한다.
	//
	// Parameters:	(DATA *) 블럭 포인터.
	// Return:		(BOOL) TRUE, FALSE.
	========================================================================*/
	bool	Free (DATA *pData)
	{
		st_BLOCK_NODE *stpBlock;


		stpBlock = (( st_BLOCK_NODE * )pData);

		if ( stpBlock->Safe != SafeLane )
		{
			return false;
		}

		LOCK ();

		stpBlock->stpNextBlock = _pTop;
		_pTop = stpBlock;

		Release ();
		
		InterlockedDecrement64 (( LONG64 * )&m_iAllocCount);
		
		return true;
	}


	/*========================================================================
	// 현재 사용중인 블럭 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 사용중인 블럭 개수.
	========================================================================*/
	int		GetAllocCount (void)
	{
		return m_iAllocCount;
	}

	/*========================================================================
	// 메모리풀 블럭 전체 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 전체 블럭 개수.
	========================================================================*/
	int		GetFullCount (void)
	{
		return m_iBlockCount;
	}

	/*========================================================================
	// 현재 보관중인 블럭 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 보관중인 블럭 개수.
	========================================================================*/
	int		GetFreeCount (void)
	{
		return m_iBlockCount - m_iAllocCount;
	}

private:
	/*========================================================================
	// 블록 스택의 탑
	========================================================================*/
	st_BLOCK_NODE *_pTop;

	/*========================================================================
	// 메모리 동적 플래그, true면 없으면 동적할당 함
	========================================================================*/
	bool m_bStoreFlag;

	/*========================================================================
	// 현재 사용중인 블럭 개수
	========================================================================*/
	int m_iAllocCount;

	/*========================================================================
	// 전체 블럭 개수
	========================================================================*/
	int m_iBlockCount;

	SRWLOCK _CS;

};

template <class DATA>
class CMemoryPool_LF
{
private:

	/*========================================================================
	// 각 블럭 앞에 사용될 노드 구조체.
	========================================================================*/
	struct st_BLOCK_NODE
	{
		DATA Data;
		st_BLOCK_NODE ()
		{
			stpNextBlock = NULL;
		}
		st_BLOCK_NODE *stpNextBlock;
	};

	/*========================================================================
	// 락프리 메모리 풀의 탑 노드
	========================================================================*/
	struct st_TOP_NODE
	{
		st_BLOCK_NODE *pTopNode;
		__int64 iUniqueNum;
	};

public:

	/*========================================================================
	// 생성자, 파괴자.
	//
	// Parameters:	(int) 최대 블럭 개수.
	// Return:		없음.
	========================================================================*/
	CMemoryPool_LF (int iBlockNum)
	{
		st_BLOCK_NODE *pNode, *pPreNode;

		/*========================================================================
		// TOP 노드 할당
		========================================================================*/
		_pTop = ( st_TOP_NODE * )_aligned_malloc (sizeof (st_TOP_NODE), 16);
		_pTop->pTopNode = NULL;
		_pTop->iUniqueNum = 0;

		_iUniqueNum = 0;

		/*========================================================================
		// 메모리 풀 크기 설정
		========================================================================*/
		m_iBlockCount = iBlockNum;
		if ( iBlockNum < 0 )
		{
			CCrashDump::Crash ();
			return;	// Dump
		}
		else if ( iBlockNum == 0 )
		{
			m_bStoreFlag = true;
			_pTop->pTopNode = NULL;
		}

		/*========================================================================
		// DATA * 크기만 큼 메모리 할당 후 BLOCK 연결
		========================================================================*/
		else
		{
			m_bStoreFlag = false;

			pNode = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE));
			_pTop->pTopNode = pNode;
			pPreNode = pNode;

			for ( int iCnt = 1; iCnt < iBlockNum; iCnt++ )
			{
				pNode = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE));
				pPreNode->stpNextBlock = pNode;
				pPreNode = pNode;
			}
		}
	}

	virtual	~CMemoryPool_LF ()
	{
		st_BLOCK_NODE *pNode;

		for ( int iCnt = 0; iCnt < m_iBlockCount; iCnt++ )
		{
			pNode = _pTop->pTopNode;
			_pTop->pTopNode = _pTop->pTopNode->stpNextBlock;
			free (pNode);
		}
	}

	/*========================================================================
	// 블럭 하나를 할당받는다.
	//
	// Parameters: PlacementNew여부.
	// Return:		(DATA *) 데이타 블럭 포인터.
	========================================================================*/
	DATA	*Alloc (bool bPlacementNew = true)
	{
		st_BLOCK_NODE *stpBlock;
		st_TOP_NODE pPreTopNode;
		int iBlockCount = m_iBlockCount;
		InterlockedIncrement64 (( LONG64 * )&m_iAllocCount);

		if ( iBlockCount < m_iAllocCount )
		{
			if ( m_bStoreFlag )
			{
				stpBlock = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE));
				InterlockedIncrement64 (( LONG64 * )&m_iBlockCount);
			}

			else
				return nullptr;
		}

		else
		{
			__int64 iUniqueNum = InterlockedIncrement64 (&_iUniqueNum);

			do
			{
				pPreTopNode.iUniqueNum = _pTop->iUniqueNum;
				pPreTopNode.pTopNode = _pTop->pTopNode;

			} while ( !InterlockedCompareExchange128 (( volatile LONG64 * )_pTop,
				iUniqueNum,
				( LONG64 )_pTop->pTopNode->stpNextBlock,
				( LONG64 * )&pPreTopNode) );

			stpBlock = pPreTopNode.pTopNode;
		}

		if ( bPlacementNew )
		{
			new (( DATA * )&stpBlock->Data) DATA;
		}

		return &stpBlock->Data;
	}

	/*========================================================================
	// 사용중이던 블럭을 해제한다.
	//
	// Parameters:	(DATA *) 블럭 포인터.
	// Return:		(BOOL) TRUE, FALSE.
	========================================================================*/
	bool	Free (DATA *pData)
	{
		st_BLOCK_NODE *stpBlock;
		st_TOP_NODE pPreTopNode;

		__int64 iUniqueNum = InterlockedIncrement64 (&_iUniqueNum);

		do
		{
			pPreTopNode.iUniqueNum = _pTop->iUniqueNum;
			pPreTopNode.pTopNode = _pTop->pTopNode;

			stpBlock = (( st_BLOCK_NODE * )pData);
			stpBlock->stpNextBlock = _pTop->pTopNode;
		} while ( !InterlockedCompareExchange128 (( volatile LONG64 * )_pTop, iUniqueNum, ( LONG64 )stpBlock, ( LONG64 * )&pPreTopNode) );

		InterlockedDecrement64 (( LONG64 * )&m_iAllocCount);
		return true;
	}


	/*========================================================================
	// 현재 사용중인 블럭 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 사용중인 블럭 개수.
	========================================================================*/
	int		GetAllocCount (void)
	{
		return m_iAllocCount;
	}

	/*========================================================================
	// 메모리풀 블럭 전체 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 전체 블럭 개수.
	========================================================================*/
	int		GetFullCount (void)
	{
		return m_iBlockCount;
	}

	/*========================================================================
	// 현재 보관중인 블럭 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 보관중인 블럭 개수.
	========================================================================*/
	int		GetFreeCount (void)
	{
		return m_iBlockCount - m_iAllocCount;
	}

private:
	/*========================================================================
	// 블록 스택의 탑
	========================================================================*/
	st_TOP_NODE *_pTop;

	/*========================================================================
	// 탑의 Unique Number
	========================================================================*/
	__int64 _iUniqueNum;

	/*========================================================================
	// 메모리 동적 플래그, true면 없으면 동적할당 함
	========================================================================*/
	bool m_bStoreFlag;

	/*========================================================================
	// 현재 사용중인 블럭 개수
	========================================================================*/
	int m_iAllocCount;

	/*========================================================================
	// 전체 블럭 개수
	========================================================================*/
	int m_iBlockCount;


};

template <class DATA>
class CMemoryPool_TLS
{
private:
	/*========================================================================
	// 청크
	========================================================================*/
	template<class DATA>
	class Chunk
	{
	public:
#define SafeLane 0xff77668888
		struct st_BLOCK_NODE
		{
			DATA BLOCK;
			INT64 Safe;
			Chunk *pChunk_Main;
		};
	private :


		st_BLOCK_NODE *_pArray;
		CMemoryPool_TLS<DATA> *_pMain_Manager;

		int FullCnt;
		int _Top;
		int FreeCnt;
	public:
		////////////////////////////////////////////////////
		//Chunk 생성자
		////////////////////////////////////////////////////
		Chunk ()
		{

		}
		~Chunk ()
		{

		}

		bool ChunkSetting (int iBlockNum, CMemoryPool_TLS<DATA> *pManager)
		{
			if ( iBlockNum < 0 )
			{
				CCrashDump::Crash ();
			}
			else if ( iBlockNum == 0 )
			{
				iBlockNum = TLS_basicChunkSize;
			}

			_Top = 0;
			FreeCnt = 0;
			FullCnt = iBlockNum;
			_pMain_Manager = pManager;
			_pArray = ( st_BLOCK_NODE * )malloc (sizeof (st_BLOCK_NODE) * iBlockNum);


			for ( int Cnt = 0; Cnt < iBlockNum; Cnt++ )
			{
				_pArray[Cnt].pChunk_Main = this;
				_pArray[Cnt].Safe = SafeLane;
			}
			return true;
		}

		//////////////////////////////////////////////////////
		// 블럭 하나를 할당받는다.
		//
		// Parameters: PlacementNew여부.
		// Return:		(DATA *) 데이타 블럭 포인터.
		//////////////////////////////////////////////////////
		DATA	*Alloc (bool bPlacementNew = true)
		{
			int iBlockCount = InterlockedIncrement (( volatile long * )&_Top);
			st_BLOCK_NODE *stpBlock = &_pArray[iBlockCount - 1];

			if ( bPlacementNew )
			{
				new (( DATA * )&stpBlock->BLOCK) DATA;
			}

			if ( iBlockCount == FullCnt )
			{
				//메모리풀에 존재하는 청크 블록 지우고 새로운 블록으로 셋팅.
				_pMain_Manager->Chunk_Alloc ();
			}

			return &stpBlock->BLOCK;

		}

		bool Free (DATA *pData)
		{
			st_BLOCK_NODE *stpBlock;


			stpBlock = (( st_BLOCK_NODE * )pData);

			if ( stpBlock->Safe != SafeLane )
			{
				return false;
			}

			int Cnt = InterlockedIncrement (( volatile long * )&FreeCnt);

			if ( Cnt == FullCnt )
			{
				free (_pArray);
				free(this);
			}

			return true;

		}
	};

	struct st_Chunk_NODE
	{
		Chunk<DATA> *pChunk;
		DWORD ThreadID;
		st_Chunk_NODE *pNextNode;
	};

	st_Chunk_NODE *_pTopNode;
	int Chunk_in_BlockCnt;
	DWORD TlsNum;
	SRWLOCK _CS;
public:
	/*========================================================================
	// 생성자
	========================================================================*/
	CMemoryPool_TLS (int iBlockNum)
	{
		if ( iBlockNum == 0 )
		{
			iBlockNum = TLS_basicChunkSize;
		}


		_pTopNode = NULL;
		Chunk_in_BlockCnt = iBlockNum;
		TlsNum = TlsAlloc ();

		//TLS가 생성이 불가한 상태이므로 자기자신을 파괴하고 종료.
		if ( TlsNum == TLS_OUT_OF_INDEXES )
		{
			CCrashDump::Crash ();
			return;//Dump
		}
	}
	~CMemoryPool_TLS ()
	{
		st_Chunk_NODE *pPreTopNode = _pTopNode;
		st_Chunk_NODE *pdeleteTopNode = _pTopNode;
		while ( 1 )
		{
			pPreTopNode = pPreTopNode->pNextNode;

			free (pdeleteTopNode->pChunk);

			free (pdeleteTopNode);

			pdeleteTopNode = pPreTopNode;
			if ( pdeleteTopNode == NULL )
			{
				break;
			}
		}
		return;
	}

	/*========================================================================
	// 블럭 하나를 할당 받는다.
	//
	// Parameters:	PlacementNew 여부.
	// Return:		(DATA *) 블럭 포인터.
	========================================================================*/
	DATA *Alloc (bool bPlacemenenew = true)
	{
		//해당 스레드에서 최초 실행될때. 초기화 작업.
		st_Chunk_NODE *pChunkNode = ( st_Chunk_NODE  * )TlsGetValue (TlsNum);



		if ( pChunkNode == NULL )
		{


			pChunkNode = ( st_Chunk_NODE  * )malloc (sizeof (st_Chunk_NODE));
			pChunkNode->pChunk = (Chunk<DATA> *)malloc (sizeof (Chunk<DATA>));

			pChunkNode->ThreadID = GetCurrentThreadId ();
			pChunkNode->pChunk->ChunkSetting (Chunk_in_BlockCnt, this);

			TlsSetValue (TlsNum, pChunkNode);

			pChunkNode->pNextNode = _pTopNode;
			_pTopNode = pChunkNode;

			InterlockedAdd (( volatile long * )&m_iBlockCount, Chunk_in_BlockCnt);

		}


		DATA *pData = pChunkNode->pChunk->Alloc ();


		//InterlockedIncrement (( volatile long * )&m_iAllocCount);

		return pData;

	}
	
	/*========================================================================
	// 사용중이던 블럭을 해제한다.
	//
	// Parameters:	(DATA *) 블럭 포인터.
	// Return:		(BOOL) TRUE, FALSE.
	========================================================================*/
	bool Free (DATA *pDATA)
	{
		Chunk<DATA>::st_BLOCK_NODE *pNode = (Chunk<DATA>::st_BLOCK_NODE *) pDATA;

		bool chk = pNode->pChunk_Main->Free (pDATA);
	//		InterlockedDecrement (( volatile long * )&m_iAllocCount);
	//		InterlockedIncrement (( volatile long * )&m_iFreeCount);
		return chk;
	}
public:


	/*========================================================================
	// Alloc이 다된 Chunk블럭을 교체한다.
	//
	// Parameters:	없음
	// Return:		없음
	========================================================================*/
	void Chunk_Alloc ()
	{
		st_Chunk_NODE *pPreTopNode = _pTopNode;
		DWORD ThreadID = GetCurrentThreadId ();

		while ( 1 )
		{
			if ( pPreTopNode->ThreadID == ThreadID )
			{
				pPreTopNode->pChunk = (Chunk<DATA> *)malloc (sizeof (Chunk<DATA>));
				pPreTopNode->pChunk->ChunkSetting (Chunk_in_BlockCnt, this);
				break;
			}
			//청크 블록을 교체하는데 해당 스레드가 존재하지 않는 스레드라면 문제가 되므로 크래쉬를 유도시켜 덤프 남길것.
			else if ( pPreTopNode == NULL )
			{
				CCrashDump::Crash ();
				return;
			}
			pPreTopNode = pPreTopNode->pNextNode;
		}
		return;
	}


	/*========================================================================
	// 현재 사용중인 블럭 개수를 얻는다.
	//
	// ! 주의
	//	TLC의 성능상 한계로 인해 사용되지 않음.
	//
	// Parameters:	없음.
	// Return:		(int) 사용중인 블럭 개수.
	========================================================================*/
	int		GetAllocCount (void)
	{
	//	return m_iAllocCount;
		return 0;
	}

	/*========================================================================
	// 메모리풀 블럭 전체 개수를 얻는다.
	//
	// Parameters:	없음.
	// Return:		(int) 전체 블럭 개수.
	========================================================================*/
	int		GetFullCount (void)
	{
		return m_iBlockCount;
	}

	/*========================================================================
	// 현재 보관중인 블럭 개수를 얻는다.
	//
	// ! 주의
	//	TLC의 성능상 한계로 인해 사용되지 않음.
	//
	// Parameters:	없음.
	// Return:		(int) 보관중인 블럭 개수.
	========================================================================*/
	int		GetFreeCount (void)
	{
	//	return m_iFreeCount;
		return 0;
	}

private:

	int m_iBlockCount;
	int m_iAllocCount;
	int m_iFreeCount;
};


#endif