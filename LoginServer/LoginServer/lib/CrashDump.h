#pragma once

//상단에 APIHOOK에 대한 Header를 붙여넣어놨음.
//#ifndef __CCrashDump_LIB__ 부터가 Dump lib 시작.

class CToolhelp
{
private:
	HANDLE m_hSnapshot;

public:
	CToolhelp (DWORD dwFlags = 0, DWORD dwProcessID = 0);
	~CToolhelp ();

	BOOL CreateSnapshot (DWORD dwFlags, DWORD dwProcessID = 0);

	BOOL ProcessFirst (PPROCESSENTRY32 ppe) const;
	BOOL ProcessNext (PPROCESSENTRY32 ppe) const;
	BOOL ProcessFind (DWORD dwProcessId, PPROCESSENTRY32 ppe) const;

	BOOL ModuleFirst (PMODULEENTRY32 pme) const;
	BOOL ModuleNext (PMODULEENTRY32 pme) const;
	BOOL ModuleFind (PVOID pvBaseAddr, PMODULEENTRY32 pme) const;
	BOOL ModuleFind (PTSTR pszModName, PMODULEENTRY32 pme) const;

	BOOL ThreadFirst (PTHREADENTRY32 pte) const;
	BOOL ThreadNext (PTHREADENTRY32 pte) const;

	BOOL HeapListFirst (PHEAPLIST32 phl) const;
	BOOL HeapListNext (PHEAPLIST32 phl) const;
	int  HowManyHeaps () const;

	// Note: The heap block functions do not reference a snapshot and
	// just walk the process's heap from the beginning each time. Infinite 
	// loops can occur if the target process changes its heap while the
	// functions below are enumerating the blocks in the heap.
	BOOL HeapFirst (PHEAPENTRY32 phe, DWORD dwProcessID,
		UINT_PTR dwHeapID) const;
	BOOL HeapNext (PHEAPENTRY32 phe) const;
	int  HowManyBlocksInHeap (DWORD dwProcessID, DWORD dwHeapId) const;
	BOOL IsAHeap (HANDLE hProcess, PVOID pvBlock, PDWORD pdwFlags) const;

public:
	static BOOL EnablePrivilege (PCTSTR szPrivilege, BOOL fEnable = TRUE);
	static BOOL ReadProcessMemory (DWORD dwProcessID, LPCVOID pvBaseAddress,
		PVOID pvBuffer, SIZE_T cbRead, SIZE_T* pNumberOfBytesRead = NULL);
};

inline CToolhelp::CToolhelp (DWORD dwFlags, DWORD dwProcessID)
{
	m_hSnapshot = INVALID_HANDLE_VALUE;
	CreateSnapshot (dwFlags, dwProcessID);
}

inline CToolhelp::~CToolhelp ()
{
	if ( m_hSnapshot != INVALID_HANDLE_VALUE )
		CloseHandle (m_hSnapshot);
}

inline BOOL CToolhelp::CreateSnapshot (DWORD dwFlags, DWORD dwProcessID)
{

	if ( m_hSnapshot != INVALID_HANDLE_VALUE )
		CloseHandle (m_hSnapshot);

	if ( dwFlags == 0 )
	{
		m_hSnapshot = INVALID_HANDLE_VALUE;
	}
	else
	{
		m_hSnapshot = CreateToolhelp32Snapshot (dwFlags, dwProcessID);
	}

	return(m_hSnapshot != INVALID_HANDLE_VALUE);
}

inline BOOL CToolhelp::EnablePrivilege (PCTSTR szPrivilege, BOOL fEnable)
{

	// Enabling the debug privilege allows the application to see
	// information about service applications
	BOOL fOk = FALSE;    // Assume function fails
	HANDLE hToken;

	// Try to open this process's access token
	if ( OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES, &hToken) )
	{
		// Attempt to modify the given privilege
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue (NULL, szPrivilege, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges (hToken, FALSE, &tp, sizeof (tp), NULL, NULL);
		fOk = (GetLastError () == ERROR_SUCCESS);

		// Don't forget to close the token handle
		CloseHandle (hToken);
	}
	return(fOk);
}

inline BOOL CToolhelp::ReadProcessMemory (DWORD dwProcessID, LPCVOID pvBaseAddress, PVOID pvBuffer, SIZE_T cbRead, SIZE_T* pNumberOfBytesRead)
{
	return(Toolhelp32ReadProcessMemory (dwProcessID, pvBaseAddress, pvBuffer, cbRead, pNumberOfBytesRead));
}

inline BOOL CToolhelp::ProcessFirst (PPROCESSENTRY32 ppe) const
{
	BOOL fOk = Process32First (m_hSnapshot, ppe);
	if ( fOk && (ppe->th32ProcessID == 0) )
		fOk = ProcessNext (ppe); // Remove the "[System Process]" (PID = 0)

	return(fOk);
}


inline BOOL CToolhelp::ProcessNext (PPROCESSENTRY32 ppe) const
{
	BOOL fOk = Process32Next (m_hSnapshot, ppe);
	if ( fOk && (ppe->th32ProcessID == 0) )
		fOk = ProcessNext (ppe); // Remove the "[System Process]" (PID = 0)

	return(fOk);
}


inline BOOL CToolhelp::ProcessFind (DWORD dwProcessId, PPROCESSENTRY32 ppe) const
{
	BOOL fFound = FALSE;
	for ( BOOL fOk = ProcessFirst (ppe); fOk; fOk = ProcessNext (ppe) )
	{
		fFound = (ppe->th32ProcessID == dwProcessId);
		if ( fFound ) break;
	}

	return(fFound);
}

inline BOOL CToolhelp::ModuleFirst (PMODULEENTRY32 pme) const
{
	return(Module32First (m_hSnapshot, pme));
}


inline BOOL CToolhelp::ModuleNext (PMODULEENTRY32 pme) const
{
	return(Module32Next (m_hSnapshot, pme));
}

inline BOOL CToolhelp::ModuleFind (PVOID pvBaseAddr, PMODULEENTRY32 pme) const
{
	BOOL fFound = FALSE;
	for ( BOOL fOk = ModuleFirst (pme); fOk; fOk = ModuleNext (pme) )
	{
		fFound = (pme->modBaseAddr == pvBaseAddr);
		if ( fFound ) break;
	}

	return(fFound);
}

inline BOOL CToolhelp::ModuleFind (PTSTR pszModName, PMODULEENTRY32 pme) const
{
	BOOL fFound = FALSE;
	for ( BOOL fOk = ModuleFirst (pme); fOk; fOk = ModuleNext (pme) )
	{
		fFound = (lstrcmpi (pme->szModule, pszModName) == 0) ||
			(lstrcmpi (pme->szExePath, pszModName) == 0);
		if ( fFound )
			break;
	}
	return(fFound);
}

inline BOOL CToolhelp::ThreadFirst (PTHREADENTRY32 pte) const
{
	return(Thread32First (m_hSnapshot, pte));
}


inline BOOL CToolhelp::ThreadNext (PTHREADENTRY32 pte) const
{
	return(Thread32Next (m_hSnapshot, pte));
}

inline int CToolhelp::HowManyHeaps () const
{
	int nHowManyHeaps = 0;
	HEAPLIST32 hl = { sizeof (hl) };
	for ( BOOL fOk = HeapListFirst (&hl); fOk; fOk = HeapListNext (&hl) )
		nHowManyHeaps++;
	return(nHowManyHeaps);
}


inline int CToolhelp::HowManyBlocksInHeap (DWORD dwProcessID, DWORD dwHeapID) const
{
	int nHowManyBlocksInHeap = 0;
	HEAPENTRY32 he = { sizeof (he) };
	BOOL fOk = HeapFirst (&he, dwProcessID, dwHeapID);
	for ( ; fOk; fOk = HeapNext (&he) )
		nHowManyBlocksInHeap++;

	return(nHowManyBlocksInHeap);
}


inline BOOL CToolhelp::HeapListFirst (PHEAPLIST32 phl) const
{
	return(Heap32ListFirst (m_hSnapshot, phl));
}


inline BOOL CToolhelp::HeapListNext (PHEAPLIST32 phl) const
{
	return(Heap32ListNext (m_hSnapshot, phl));
}


inline BOOL CToolhelp::HeapFirst (PHEAPENTRY32 phe, DWORD dwProcessID, UINT_PTR dwHeapID) const
{
	return(Heap32First (phe, dwProcessID, dwHeapID));
}


inline BOOL CToolhelp::HeapNext (PHEAPENTRY32 phe) const
{
	return(Heap32Next (phe));
}


inline BOOL CToolhelp::IsAHeap (HANDLE hProcess, PVOID pvBlock, PDWORD pdwFlags) const
{
	HEAPLIST32 hl = { sizeof (hl) };
	for ( BOOL fOkHL = HeapListFirst (&hl); fOkHL; fOkHL = HeapListNext (&hl) )
	{
		HEAPENTRY32 he = { sizeof (he) };
		BOOL fOkHE = HeapFirst (&he, hl.th32ProcessID, hl.th32HeapID);
		for ( ; fOkHE; fOkHE = HeapNext (&he) )
		{
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQueryEx (hProcess, ( PVOID )he.dwAddress, &mbi, sizeof (mbi));
			if ( chINRANGE (mbi.AllocationBase, pvBlock, ( PBYTE )mbi.AllocationBase + mbi.RegionSize) )
			{
				*pdwFlags = hl.dwFlags;
				return(TRUE);
			}
		}
	}
	return(FALSE);
}




class CAPIHook
{
public:
	// Hook a function in all modules
	CAPIHook (PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook, bool bThisMod = false);

	// Unhook a function from all modules
	~CAPIHook ();

	// Returns the original address of the hooked function
	operator PROC()
	{
		return(m_pfnOrig);
	}

	// Hook module w/CAPIHook implementation?
	// I have to make it static because I need to use it 
	// in ReplaceIATEntryInAllMods
	static BOOL ExcludeAPIHookMod;


public:
	// Calls the real GetProcAddress 
	static FARPROC WINAPI GetProcAddressRaw (HMODULE hmod, PCSTR pszProcName);

private:
	static PVOID sm_pvMaxAppAddr; // Maximum private memory address
	static CAPIHook* sm_pHead;    // Address of first object
	CAPIHook* m_pNext;            // Address of next  object

	PCSTR m_pszCalleeModName;     // Module containing the function (ANSI)
	PCSTR m_pszFuncName;          // Function name in callee (ANSI)
	PROC  m_pfnOrig;              // Original function address in callee
	PROC  m_pfnHook;              // Hook function address

private:
	// Replaces a symbol's address in a module's import section
	static void WINAPI ReplaceIATEntryInAllMods (PCSTR pszCalleeModName, PROC pfnOrig, PROC pfnHook, bool bThisMod = false);

	// Replaces a symbol's address in all modules' import sections
	static void WINAPI ReplaceIATEntryInOneMod (PCSTR pszCalleeModName,
		PROC pfnOrig, PROC pfnHook, HMODULE hmodCaller);

	// Replaces a symbol's address in a module's export sections
	static void ReplaceEATEntryInOneMod (HMODULE hmod, PCSTR pszFunctionName, PROC pfnNew);

private:
	// Used when a DLL is newly loaded after hooking a function
	static void    WINAPI FixupNewlyLoadedModule (HMODULE hmod, DWORD dwFlags);

	// Used to trap when DLLs are newly loaded
	static HMODULE WINAPI LoadLibraryA (PCSTR pszModulePath);
	static HMODULE WINAPI LoadLibraryW (PCWSTR pszModulePath);
	static HMODULE WINAPI LoadLibraryExA (PCSTR pszModulePath,
		HANDLE hFile, DWORD dwFlags);
	static HMODULE WINAPI LoadLibraryExW (PCWSTR pszModulePath,
		HANDLE hFile, DWORD dwFlags);

	// Returns address of replacement function if hooked function is requested
	static FARPROC WINAPI GetProcAddress (HMODULE hmod, PCSTR pszProcName);

private:
	// Instantiates hooks on these functions
	static CAPIHook sm_LoadLibraryA;
	static CAPIHook sm_LoadLibraryW;
	static CAPIHook sm_LoadLibraryExA;
	static CAPIHook sm_LoadLibraryExW;
	static CAPIHook sm_GetProcAddress;
};






#ifndef __CCrashDump_LIB__
#define __CCrashDump_LIB__

#include <signal.h>

class CCrashDump
{
public :

	static long _DumpCount;

	CCrashDump ()
	{
		_DumpCount = 0;
		_invalid_parameter_handler oldHandler;
		_invalid_parameter_handler newHandler;

		newHandler = myInvalidParameterHandler;

		oldHandler = _set_invalid_parameter_handler (newHandler);
		_CrtSetReportMode (_CRT_WARN, 0);
		_CrtSetReportMode (_CRT_ASSERT, 0);
		_CrtSetReportMode (_CRT_ERROR, 0);

		_CrtSetReportHook (_custom_Report_hook);


		//pure virtual function called 에러 핸들러를 사용자 정의 함수로 우회시킨다.
		_set_purecall_handler (myPurecallHandler);

		_set_abort_behavior (0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
		signal (SIGABRT, signalHandler);
		signal (SIGINT, signalHandler);
		signal (SIGILL, signalHandler);
		signal (SIGFPE, signalHandler);
		signal (SIGSEGV, signalHandler);
		signal (SIGTERM, signalHandler);

		SetHandlerDump ();
	}

	static void Crash (void)
	{
		int *p = nullptr;
		*p = 0;

	}

	static LONG WINAPI MyExceptionFilter (__in PEXCEPTION_POINTERS pExceptionPointer)
	{
		int iWorkingMemory = 0;
		SYSTEMTIME stNowTime;

		long DumpCount = InterlockedIncrement (&_DumpCount);

		//현재 프로세스의 메모리 사용량을 얻어온다.
		HANDLE hProcess = 0;
		PROCESS_MEMORY_COUNTERS pmc;

		hProcess = GetCurrentProcess ();

		if ( NULL == hProcess )
		{
			return 0;
		}
		if ( GetProcessMemoryInfo (hProcess, &pmc, sizeof (pmc)))
		{
			iWorkingMemory = ( int )(pmc.WorkingSetSize / 1024 / 1024);
		}
		CloseHandle (hProcess);


		//현재 날짜와 시간을 알아온다
		WCHAR filename[MAX_PATH];

		GetLocalTime (&stNowTime);
		wsprintf (filename, L"Dump_%d%02d%02d_%02d.%02d.%02d_%d.dmp", stNowTime.wYear, stNowTime.wMonth, stNowTime.wDay, stNowTime.wHour, stNowTime.wMinute, stNowTime.wSecond, DumpCount);
		wprintf (L"\n\n!!! Crash Error !!! %d.%d.%d / %d : %d : %d  Count=%d\n", stNowTime.wYear, stNowTime.wMonth, stNowTime.wDay, stNowTime.wHour, stNowTime.wMinute, stNowTime.wSecond, DumpCount);
		wprintf (L"Now Save dump file...\n");

		HANDLE hDumpFile = ::CreateFile (filename, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if ( hDumpFile != INVALID_HANDLE_VALUE )
		{
			_MINIDUMP_EXCEPTION_INFORMATION MinidumpExceptionImformation;

			MinidumpExceptionImformation.ThreadId = ::GetCurrentThreadId ();
			MinidumpExceptionImformation.ExceptionPointers = pExceptionPointer;
			MinidumpExceptionImformation.ClientPointers = TRUE;

			MiniDumpWriteDump (GetCurrentProcess (), GetCurrentProcessId (), hDumpFile, MiniDumpWithFullMemory, &MinidumpExceptionImformation, NULL, NULL);

			CloseHandle (hDumpFile);

			wprintf (L"Crash Dump Save Finish !");
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	static LONG WINAPI RedirectedSetUnhandledExceptionFilter (EXCEPTION_POINTERS *exceptionInfo)
	{
		MyExceptionFilter (exceptionInfo);
		return EXCEPTION_EXECUTE_HANDLER;
	}


	static void SetHandlerDump ()
	{
		SetUnhandledExceptionFilter (MyExceptionFilter);

		// C 런타임 라이브러리 내부의 예외 핸들러 등록을 막기 위해서 API 후킹사용.
		static CAPIHook apiHook ("kernel32.dll", "SetUnhandledExceptionFilter", ( PROC )RedirectedSetUnhandledExceptionFilter, true);
	}


	//Invalid Parameter handler
	static void myInvalidParameterHandler (const wchar_t *expression, const wchar_t *function, const wchar_t *filfile, unsigned int line, uintptr_t pReserved)
	{
		Crash ();
	}
	
	static int _custom_Report_hook (int ireposttype, char *message, int *returnvalue)
	{
		Crash ();
		return true;
	}

	static void myPurecallHandler (void)
	{
		Crash ();
	}

	static void signalHandler (int Error)
	{
		Crash ();
	}

};

#endif