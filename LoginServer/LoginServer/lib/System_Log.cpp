#include "stdafx.h"
#include "System_Log.h"


hiker::CSystemLog *hiker::CSystemLog::pLog = nullptr;
hiker::CSystemLog *Log = hiker::CSystemLog::GetInstance (LOG_DEBUG);