#pragma once
#ifndef __Library_Header__
#define __Library_Header__

#include <Windows.h>
#include <tchar.h>
#include <locale.h>
#include <process.h>
#include <Strsafe.h>
#include <time.h>
#include <psapi.h>
#include <dbghelp.h>
#include <crtdbg.h>
#include <StrSafe.h>
#include <tlhelp32.h>

#pragma comment(lib, "DbgHelp.Lib")
#pragma comment(lib, "ImageHlp")
#pragma comment(lib, "psapi")

#define chINRANGE(low, Num, High) (((low) <= (Num)) && ((Num) <= (High)))

#include "CrashDump.h"
#include "Profiler.h"
#include "System_Log.h"


#endif