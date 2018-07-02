#pragma once
#include "MemoryPool.h"
#define MaxCnt 50000


/*
struct DATA
{
	int a;
};
*/


/*======================================================================================
//싱글 링크드 리스크 형식 락프리 Queue.
=======================================================================================*/
template<class DATA>
class CQueue_LF
{
private :
	SRWLOCK _CS;
	struct NODE
	{
		DATA Data;
		NODE *pNext;
	};
	struct _TOP_NODE
	{
		NODE *pNode;
		INT64 UNIQUEUE;
	};


	_TOP_NODE *_pHead;
	_TOP_NODE *_pTail;



	volatile __int64 _UniqueueNum;
	volatile __int64 _NodeCnt;
	volatile __int64 _MaxCnt;
public :
	CMemoryPool<NODE> *_pMemPool;
	/*//////////////////////////////////////////////////////////////////////
	//생성자.파괴자.
	//////////////////////////////////////////////////////////////////////*/
	CQueue_LF ()
	{
		_TOP_NODE *HNode = ( _TOP_NODE * )_aligned_malloc (sizeof (_TOP_NODE), 16);
		_TOP_NODE *TNode = ( _TOP_NODE * )_aligned_malloc (sizeof (_TOP_NODE), 16);
		_pMemPool = new CMemoryPool<NODE> (0);

		HNode->pNode = _pMemPool->Alloc ();
		HNode->pNode->pNext = NULL;
		HNode->UNIQUEUE = 0;
		
		TNode->pNode = HNode->pNode;
		TNode->UNIQUEUE = 0;
		_MaxCnt = MaxCnt;
		_NodeCnt = 0;

		
		_pHead = HNode;
		_pTail = TNode;
		InitializeSRWLock (&_CS);


	}
	~CQueue_LF ()
	{
		DATA p;
		while ( 1 )
		{
			
			if ( Dequeue(&p) == false )
			{
				return;
			}
		}
		_pMemPool->Free (_pHead->pNode);
	}


	/*//////////////////////////////////////////////////////////////////////
	//Enqueue
	//인자 : DATA
	//return : true,false
	//////////////////////////////////////////////////////////////////////*/

	bool Enqueue (DATA Data)
	{

		//Queue가 꽉찼으므로 return false.
		if ( _NodeCnt >= _MaxCnt )
		{
			return false;
		}

		_TOP_NODE PreNode;

		NODE *pNode = _pMemPool->Alloc ();
		pNode->Data = Data;

		INT64 Uniqueue;


		while ( 1 )
		{
			PreNode.pNode = _pTail->pNode;
			PreNode.UNIQUEUE = _pTail->UNIQUEUE;
			Uniqueue = InterlockedIncrement64 (&_UniqueueNum);
			//Tail의 next가 NULL이 아닐 경우 이미 누군가가 먼저 노드를 넣었으므로 Tail을 밀어줌.

			if ( PreNode.pNode->pNext != NULL )
			{
				InterlockedCompareExchange128 (( volatile LONG64 * )_pTail, Uniqueue, ( LONG64 )_pTail->pNode->pNext, ( LONG64 * )&PreNode);
				continue;
			}

			//Tail의 Next가 NULL일 경우 현재 노드 연결

			pNode->pNext = NULL;
			if ( InterlockedCompareExchangePointer (( volatile PVOID * )&_pTail->pNode->pNext, pNode, NULL) == NULL )
			{
				InterlockedCompareExchange128 (( volatile LONG64 * )_pTail, Uniqueue, ( LONG64 )_pTail->pNode->pNext, ( LONG64 * )&PreNode);
				InterlockedIncrement64 (&_NodeCnt);
				return true;
			}
		}
	}


	/*//////////////////////////////////////////////////////////////////////
	//Dequeue
	//인자 : 뽑을 데이터를 담을 버퍼.
	//return : true,false
	//////////////////////////////////////////////////////////////////////*/
	bool Dequeue (DATA *pOut)
	{
		_TOP_NODE PreNode;

		NODE *pNext;

		INT64 Uniqueue = InterlockedIncrement64 (&_UniqueueNum);


		while ( 1 )
		{
			PreNode.pNode = _pHead->pNode;
			PreNode.UNIQUEUE = _pHead->UNIQUEUE;

			pNext = _pHead->pNode->pNext;
			//헤드의 Next노드를 뽑는 것이므로 pNode가 NULL이라면 Dequeue 불가능.
			if ( pNext == NULL )
			{
				pOut = NULL;
				return false;
			}
			
			*pOut = pNext->Data;
			if ( InterlockedCompareExchange128 (( volatile LONG64 * )_pHead, Uniqueue, ( LONG64 )pNext, ( LONG64 * )&PreNode) )
			{
				_pMemPool->Free (PreNode.pNode);
				InterlockedDecrement64 (&_NodeCnt);
				
				return true;
			}
		}
	}



	/*//////////////////////////////////////////////////////////////////////
	//GetUseSize
	//인자 : 없음
	//return : 현재 Node갯수.
	//////////////////////////////////////////////////////////////////////*/
	INT64 GetUseSize (void)
	{
		return _NodeCnt;
	}
};






/*======================================================================================
//싱글 링크드 리스크 형식 Thread Safe SRW Lock버전 Queue
=======================================================================================*/
template<class DATA>
class CQueue_LOCK
{
private:
	struct NODE
	{
		DATA Data;
		NODE *pNext;
	};
	struct _TOP_NODE
	{
		NODE *pNode;
	};


	_TOP_NODE *_pHead;
	_TOP_NODE *_pTail;

	CMemoryPool<NODE> *_pMemPool;

	volatile __int64 _NodeCnt;
	volatile __int64 _MaxCnt;

	SRWLOCK _CS;
public:

	/*//////////////////////////////////////////////////////////////////////
	//생성자.파괴자.
	//////////////////////////////////////////////////////////////////////*/
	CQueue_LOCK ()
	{
		InitializeSRWLock (&_CS);

		_TOP_NODE *HNode = ( _TOP_NODE * )_aligned_malloc (sizeof (_TOP_NODE), 16);
		_TOP_NODE *TNode = ( _TOP_NODE * )_aligned_malloc (sizeof (_TOP_NODE), 16);
		HNode->pNode = ( NODE * )malloc (sizeof (NODE));
		HNode->pNode->pNext = NULL;

		TNode->pNode = HNode->pNode;
		_MaxCnt = MaxCnt;
		_NodeCnt = 0;


		_pHead = HNode;
		_pTail = TNode;

		_pMemPool = new CMemoryPool<NODE> (0);
	}
	~CQueue_LOCK ()
	{
		DATA p;
		while ( 1 )
		{
			
			if ( Dequeue (&p) == false )
			{
				return;
			}
		}
	}


	/*//////////////////////////////////////////////////////////////////////
	//Enqueue
	//인자 : DATA
	//return : true,false
	//////////////////////////////////////////////////////////////////////*/

	bool Enqueue (DATA Data)
	{

		//Queue가 꽉찼으므로 return false.
		if ( _NodeCnt >= _MaxCnt )
		{
			return false;
		}

		_TOP_NODE PreNode;


		NODE *pNode = _pMemPool->Alloc ();
		pNode->Data = Data;
		pNode->pNext = NULL;

		LOCK ();

		PreNode.pNode = _pTail->pNode;

		_pTail->pNode->pNext = pNode;
		_pTail->pNode = pNode;
		
		InterlockedIncrement64 (&_NodeCnt);

		Free ();
		return true;
	}


	/*//////////////////////////////////////////////////////////////////////
	//Dequeue
	//인자 : 뽑을 데이터를 담을 버퍼.
	//return : true,false
	//////////////////////////////////////////////////////////////////////*/
	bool Dequeue (DATA *pOut)
	{
		_TOP_NODE PreNode;
		NODE *pNode;
		LOCK ();

		PreNode.pNode = _pHead->pNode;

		pNode = PreNode.pNode->pNext;

		//헤드의 Next노드를 뽑는 것이므로 pNode가 NULL이라면 Dequeue 불가능.
		if ( pNode == NULL )
		{
			pOut = NULL;
			Free ();
			return false;
		}

		_pHead->pNode = pNode;

		*pOut = pNode->Data;
		_pMemPool->Free (PreNode.pNode);
		InterlockedDecrement64 (&_NodeCnt);

		Free ();

		return true;
	}



	/*//////////////////////////////////////////////////////////////////////
	//GetUseSize
	//인자 : 없음
	//return : 현재 Node갯수.
	//////////////////////////////////////////////////////////////////////*/
	INT64 GetUseSize (void)
	{
		return _NodeCnt;
	}


	void LOCK (void)
	{
		AcquireSRWLockExclusive (&_CS);
	}
	void Free (void)
	{
		ReleaseSRWLockExclusive (&_CS);
	}
};