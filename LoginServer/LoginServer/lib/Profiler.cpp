#include "stdafx.h"
#include"Profiler.h"
#include <stdio.h>

/////////////////////////////////////////////////////////////////////////////////////
//프로파일 셋팅부
/////////////////////////////////////////////////////////////////////////////////////
bool ProfileStructher::Set_Profile (WCHAR *name, __int64 SetTime)
{
	int cnt;
	if ( pThread == NULL )
	{
		for ( int TCnt = 0; TCnt < ThreadMax; TCnt++ )
		{
			if ( Thread[TCnt].flag == false )
			{
				//인터락CompareExchange로 비교. false였다면 true로 바꾸고 다른 스레드에서 먼저 변경해서 true였다면 continue로 다음 배열 검색
				if ( InterlockedCompareExchange (( volatile long * )&Thread[TCnt].flag, 1, 0) == 1 )
				{
					continue;
				}
				
				//스레드 카운트가 false였을 경우 진행.
				Thread[TCnt].ThreadID = GetCurrentThreadId ();
				pThread = &Thread[TCnt];
				break;

			}
		}
	}


	ProfileThread *p = ( ProfileThread * )pThread;
	for ( cnt = 0; cnt < Max; cnt++ )
	{
		//배열을 돌면서 false를 만났다면 해당 프로파일이 존재하지 않으므로 새로 셋팅해 주어야 된다.
		if ( false == p->profile_Array[cnt].flag )
		{
			break;
		}
		//배열을 돌면서 같은 이름의 프로파일를 만나게 되면은 해당 프로파일의 시작시간이 0으로 초기화 되어있는지 확인. 
		else if ( 0 == lstrcmpW (p->profile_Array[cnt].Name, name) )
		{
			//해당 프로파일의 beginflag가 true라면 종료되지 않은 프로파일 이므로 false를 리턴
			if ( true == p->profile_Array[cnt].Beginflag )
			{
				return false;
			}
			break;
		}
	}

	//배열을 오버하여 저장하지 못한것은 false로 리턴.
	if ( cnt >= Max )
	{
		return false;
	}
	else
	{
		p->profile_Array[cnt].flag = true;
		lstrcpynW (p->profile_Array[cnt].Name, name, sizeof (p->profile_Array[cnt].Name));
		p->profile_Array[cnt].Start_Time = SetTime;
		p->profile_Array[cnt].Beginflag = true;
		return true;
	}

}

/////////////////////////////////////////////////////////////////////////////////////
//프로파일 종료부
////////////////////////////////////////////////////////////////////////////////////
bool ProfileStructher::End_Profile (WCHAR *name, __int64 EndTime)
{
	int cnt;
	__int64 Time;
	ProfileThread *p = ( ProfileThread * )pThread;

	for ( cnt = 0; cnt < Max; cnt++ )
	{
		//배열의 flag가 false라면 해당 프로파일이 존재하지 않는것이므로 false를 리턴한다.
		if ( false == p->profile_Array[cnt].flag )
		{
			return false;
		}
		//배열의 해당 프로파일이 존재한다면 Beginflag로 프로파일의 시작여부를 확인.
		else if ( 0 == lstrcmpW (p->profile_Array[cnt].Name, name) )
		{
			//Beginflag가 true라면 해당 프로파일이 시작되어있으므로 종료처리 false라면 시작되지 않은 프로파일이므로 false를 리턴한다.
			if ( true == p->profile_Array[cnt].Beginflag )
			{
				p->profile_Array[cnt].Beginflag = false;
				p->profile_Array[cnt].CallCNT++;
				Time = EndTime - p->profile_Array[cnt].Start_Time;

				//최대 시간값보다 클 경우 최대 시간값에 저장하고 현재 최대 시간값은 실질 최대 시간값에 저장한다.
				if ( Time > p->profile_Array[cnt].Max_Time[0] )
				{
					p->profile_Array[cnt].Max_Time[1] = p->profile_Array[cnt].Max_Time[0];
					p->profile_Array[cnt].Max_Time[0] = Time;
				}
				//최대 시간값보다 작고 실질 최대 시간값보다 큰경우 실질 최대 시간값은 TotalTime에 포함하고 실질 최대 시간값에 저장한다.
				else if ( Time > p->profile_Array[cnt].Max_Time[1] )
				{
					//처음 한번은 초기화로 인한 변수가 들어가 있으므로 버린다.
					if ( p->profile_Array[cnt].Max_Time[1] != 0 )
					{
						p->profile_Array[cnt].TotalTime += p->profile_Array[cnt].Max_Time[1];
					}
					p->profile_Array[cnt].Max_Time[1] = Time;
				}

				if ( Time < p->profile_Array[cnt].Min_Time[0] )
				{
					p->profile_Array[cnt].Min_Time[1] = p->profile_Array[cnt].Min_Time[0];
					p->profile_Array[cnt].Min_Time[0] = Time;
				}

				else if ( Time < p->profile_Array[cnt].Min_Time[1] )
				{
					//초기화는 저장안함.
					if ( p->profile_Array[cnt].Min_Time[1] != 0x7fffffffffffffff )
					{
						p->profile_Array[cnt].TotalTime += p->profile_Array[cnt].Min_Time[1];
					}
					p->profile_Array[cnt].Min_Time[1] = Time;
				}


				//현재 시간이 최대값보다 작고 최소값보다 클 경우 토탈타임에 합침.
				if ( Time > p->profile_Array[cnt].Min_Time[1] && Time < p->profile_Array[cnt].Max_Time[1] )
				{
					p->profile_Array[cnt].TotalTime += Time;
				}

				return true;

			}
			return false;

		}
	}
	return false;
}

///////////////////////////////////////////////////////////////////////////////////
//프로파일 출력부
///////////////////////////////////////////////////////////////////////////////////
void ProfileStructher::Print_Profile (void)
{
	int cnt;
	FILE *fp;
	double Average;
	__int64 i_Average;
	double MinTime;
	double MaxTime;


	_wfopen_s (&fp,L"Profile.txt",L"w+t,ccs=UNICODE");

	fwprintf_s (fp, L"%-13s l %-25s l %18s   l %18s   l %18s   l %20s l\n", L"ThreadID", L"Name", L"Average", L"MinTime", L"MaxTime", L"TotalCaLL");
	fwprintf_s (fp, L"ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ\n");

	for ( int TCnt = 0; TCnt < ThreadMax; TCnt++ )
	{
		//쓰레드에서 뽑아가는 순서는 맨 앞 배열부터 순서대로 이므로 flag가 false인 경우는 그 뒤로 빈배열이므로 빠져 나온다.
		if ( Thread[TCnt].flag == false )
		{
			break;
		}
		for ( cnt = 0; cnt < Max; cnt++ )
		{
			if ( Thread[TCnt].profile_Array[cnt].CallCNT >= 1 )
			{
				Thread[TCnt].profile_Array[cnt].TotalTime += Thread[TCnt].profile_Array[cnt].Min_Time[1];
				Thread[TCnt].profile_Array[cnt].TotalTime += Thread[TCnt].profile_Array[cnt].Max_Time[1];

				i_Average = Thread[TCnt].profile_Array[cnt].TotalTime / Thread[TCnt].profile_Array[cnt].CallCNT;
				Average = ( double )i_Average / NanoSecond;
				MinTime = ( double )Thread[TCnt].profile_Array[cnt].Min_Time[1] / NanoSecond;
				MaxTime = ( double )Thread[TCnt].profile_Array[cnt].Max_Time[1] / NanoSecond;

				fwprintf_s (fp, L" %-13d l %-24ls l %-18.2fµs l %-18.2fµs l %-18.2fµs l %-19lld  l\n", Thread[TCnt].ThreadID,Thread[TCnt].profile_Array[cnt].Name, Average, MinTime, MaxTime, Thread[TCnt].profile_Array[cnt].CallCNT);
			//	fwprintf_s (fp, L" %-13d l %-24ls l %-18.2fms l %-18.2fms l %-18.2fms l %-20lld  l\n", Thread[TCnt].ThreadID, Thread[TCnt].profile_Array[cnt].Name, Average, MinTime, MaxTime, Thread[TCnt].profile_Array[cnt].CallCNT);
			}
		}
	}

	fclose (fp);
}
void ProfileStructher::ClearProfile (void)		//모든 프로파일을 초기화 시켜버린다.
{
	int cnt;
	for ( int TCnt = 0; TCnt < ThreadMax; TCnt++ )
	{
		//쓰레드에서 뽑아가는 순서는 맨 앞 배열부터 순서대로 이므로 flag가 false인 경우는 그 뒤로 빈배열이므로 빠져 나온다.
		if ( Thread[TCnt].flag == false )
		{
			break;
		}
		for ( cnt = 0; cnt < Max; cnt++ )
		{
			Thread[TCnt].profile_Array[cnt].flag = false;
			Thread[TCnt].profile_Array[cnt].Name[0] = NULL;
			Thread[TCnt].profile_Array[cnt].TotalTime = 0;
			Thread[TCnt].profile_Array[cnt].Min_Time[0] = 0x7fffffffffffffff;		//최소 걸린 시간이므로 최대값으로 밀어준다.
			Thread[TCnt].profile_Array[cnt].Min_Time[1] = 0x7fffffffffffffff;
			Thread[TCnt].profile_Array[cnt].Max_Time[0] = 0;		//최대 걸린 시간이므로 최소값으로 밀어준다.
			Thread[TCnt].profile_Array[cnt].Max_Time[1] = 0;
			Thread[TCnt].profile_Array[cnt].CallCNT = 0;		//호출횟수 초기화
		}
	}
}

ProfileStructher Profile;
 
void Profile_Begin (WCHAR *name)
{
	LARGE_INTEGER StartTime;
	QueryPerformanceCounter (&StartTime);
	if ( false == Profile.Set_Profile (name, StartTime.QuadPart) )
	{
		/*
		int *p = nullptr;
		*p = 0;
		*/
	}
	return;
}

void Profile_End (WCHAR *name)
{
	LARGE_INTEGER EndTime;
	QueryPerformanceCounter (&EndTime);
	if ( false == Profile.End_Profile (name, EndTime.QuadPart) )
	{
		/*
		int *p = nullptr;
		*p = 0;
		*/
	}
	return;
}

void PROFILE_KeyProc (void)
{
	INT64 Time;
	/*
	//p
	if ( GetAsyncKeyState (0x50) & 0x8001 )
	{
		Profile.Print_Profile ();
	}

	*/
	
	//5분 에 한번씩 저장.
	Time = GetTickCount64 ();

	if ( Time - Profile._CStartTime > 60000 )
	{
		Profile._CStartTime = Time;
		Profile.Print_Profile ();
	}

	//o
	if ( GetAsyncKeyState (0x4f) & 0x8001 )
	{
		Profile._CStartTime = Time;
		Profile.ClearProfile ();
	}

	
	return;
}
