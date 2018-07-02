#pragma once
#include "MemoryPool.h"

template <class DATA>
class CStack_LF
{
public:

	struct st_NODE
	{
		DATA	Data;
		st_NODE *pNext;
	};

	struct st_TOP_NODE
	{
		st_NODE *pTopNode;
		__int64 iUniqueNum;
	};

public:

	/////////////////////////////////////////////////////////////////////////
	// 생성자
	//
	// Parameters: 없음.
	// Return: 없음.
	/////////////////////////////////////////////////////////////////////////
	CStack_LF ()
	{
		_lUseSize = 0;
		_iUniqueNum = 0;

		_pTop = (st_TOP_NODE *)_aligned_malloc(sizeof(st_TOP_NODE), 16);
		_pTop->pTopNode = NULL;
		_pTop->iUniqueNum = 0;

		_pMemoryPool = new CMemoryPool<st_NODE>(0);
	}

	/////////////////////////////////////////////////////////////////////////
	// 파괴자
	//
	// Parameters: 없음.
	// Return: 없음.
	/////////////////////////////////////////////////////////////////////////
	virtual		~CStack_LF ()
	{
		st_NODE *pNode;
		while (_pTop->pTopNode != NULL)
		{
			pNode = _pTop->pTopNode;
			_pTop->pTopNode = _pTop->pTopNode->pNext;
			_pMemoryPool->Free(pNode);
		}
	}

	/////////////////////////////////////////////////////////////////////////
	// 현재 사용중인 용량 얻기.
	//
	// Parameters: 없음.
	// Return: (int)사용중인 용량.
	/////////////////////////////////////////////////////////////////////////
	long			GetUseSize(void){ return _lUseSize; }

	/////////////////////////////////////////////////////////////////////////
	// 데이터가 비었는가 ?
	//
	// Parameters: 없음.
	// Return: (bool)true, false
	/////////////////////////////////////////////////////////////////////////
	bool			isEmpty(void)
	{
		if (_pTop->pTopNode == NULL)
			return true;

		return false;
	}


	/////////////////////////////////////////////////////////////////////////
	// CPacket 포인터 데이타 넣음.
	//
	// Parameters: (DATA)데이타.
	// Return: (bool) true, false
	/////////////////////////////////////////////////////////////////////////
	bool			Push(DATA Data)
	{
		st_NODE *pNode = _pMemoryPool->Alloc();
		st_TOP_NODE pPreTopNode;
		__int64 iUniqueNum = InterlockedIncrement64(&_iUniqueNum);
		pNode->Data = Data;

		do {
			pPreTopNode.iUniqueNum = _pTop->iUniqueNum;
			pPreTopNode.pTopNode = _pTop->pTopNode;


			pNode->pNext = _pTop->pTopNode;
		} while (!InterlockedCompareExchange128((volatile LONG64 *)_pTop, iUniqueNum, (LONG64)pNode, (LONG64 *)&pPreTopNode));
		InterlockedIncrement ((volatile LONG * )&_lUseSize);
		return true;
	}

	/////////////////////////////////////////////////////////////////////////
	// 데이타 빼서 가져옴.
	//
	// Parameters: (DATA *) 뽑은 데이터 넣어줄 포인터
	// Return: (bool) true, false
	/////////////////////////////////////////////////////////////////////////
	bool			Pop(DATA *pOutData)
	{
		st_TOP_NODE pPreTopNode;
		st_NODE *pNode;
		__int64 iUniqueNum = InterlockedIncrement64(&_iUniqueNum);

		do
		{
			pPreTopNode.pTopNode = _pTop->pTopNode;
			pPreTopNode.iUniqueNum = _pTop->iUniqueNum;
			if ( pPreTopNode.pTopNode == NULL )
			{
				*pOutData = NULL;
				return false;
			}

			pNode = _pTop->pTopNode;
		} while (!InterlockedCompareExchange128((volatile LONG64 *)_pTop, iUniqueNum, (LONG64)pPreTopNode.pTopNode->pNext, (LONG64 *)&pPreTopNode));
		InterlockedDecrement (( LONG * )&_lUseSize);

		*pOutData = pPreTopNode.pTopNode->Data;
		_pMemoryPool->Free(pNode);
		return true;
	}

private:
	CMemoryPool<st_NODE>	*_pMemoryPool;
	st_TOP_NODE				*_pTop;

	__int64					_iUniqueNum;

	long						_lUseSize;
};