#pragma once
#include <Windows.h>
#include <locale.h>

__declspec (thread) static void *pThread = NULL;

class ProfileStructher
{
#define Max 50		//여기에서만 쓸 용도 이므로 class내부에서 정의해 준다.
#define ThreadMax 10

private:
	struct Profile
	{
		bool flag;
		WCHAR Name[64];
		
		bool Beginflag;		//프로파일 시작여부
		__int64 Start_Time;	//시작시간
		__int64 TotalTime;	//모든 시간의 합계
		__int64 Min_Time[2];	//0번은 최소 걸린시간. 너무 작은값. 1번이 그 다음값
		__int64 Max_Time[2];	//0번은 최대 걸린 시간. 너무 큰 값. 1번은 그 다음 큰값.
		unsigned __int64 CallCNT;	//call한 횟수.
	};
	struct ProfileThread
	{
		bool flag;
			
		DWORD ThreadID;
		Profile profile_Array[Max];
	};
	ProfileThread Thread[ThreadMax];

	LARGE_INTEGER SecondFrequency;
	double NanoSecond;

public:
	ProfileStructher(void)
	{
		int cnt;
		for ( int TCnt = 0; TCnt < ThreadMax; TCnt++ )
		{
			Thread[TCnt].ThreadID = 0;
			Thread[TCnt].flag = false;
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

		QueryPerformanceFrequency (&SecondFrequency);
		NanoSecond = (double) SecondFrequency.QuadPart / 1000000000;
		setlocale (LC_ALL, "");

		_CStartTime = GetTickCount64 ();
	}
	~ProfileStructher (void)
	{

	}
	bool Set_Profile (WCHAR *name, __int64 SetTime);	//종료안된 프로파일 일 경우 false 리턴
	bool End_Profile (WCHAR *name, __int64 EndTime);	//없거나 시작되지 않은 프로파일 일경우 false 리턴.
	void Print_Profile (void);		//저장된 프로파일들을 파일로 출력함.
	void ClearProfile (void);		//모든 프로파일을 초기화 시켜버린다.




	INT64 _CStartTime;
};

void Profile_Begin (WCHAR *name);
void Profile_End (WCHAR *name);
void PROFILE_KeyProc (void);


//선언부
//#define PROFILE_CHECK

#ifdef PROFILE_CHECK
#define PROFILE_BEGIN(X)	Profile_Begin(X)
#define PROFILE_END(X)		Profile_End(X)
#define PROFILE_KEYPROC()		PROFILE_KeyProc()

#else
#define PROFILE_BEGIN(X)
#define PROFILE_END(X)
#define PROFILE_KEYPROC()

#endif