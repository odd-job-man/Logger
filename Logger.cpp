#define LOGGERAPI extern "C" __declspec(dllexport)
#include"Logger.h"
#include <strsafe.h>
#include "LOG_BUF_INFO.h"



DWORD g_dwLogCount = 0;
LOG_LEVEL g_logLevel = (LOG_LEVEL)DEBUG;
#define LOCAL_LOG_BUF_SIZE 3000

HANDLE g_hHeapHandle;
__declspec(thread) WCHAR* g_pszFolderPath;
__declspec(thread) LOG_BUF_INFO g_logBufInfo;

SRWLOCK g_srwForFILEIO;
SRWLOCK g_srwForLogLevel;

void GetParentDir(WCHAR* szTargetPath)
{
	WCHAR* lastSlash = wcsrchr(szTargetPath, L'\\');
	if (lastSlash)
		*lastSlash = L'\0';
}

void SYSLOG_DIRECTORY(CONST WCHAR* szPath)
{
	WCHAR exePath[MAX_PATH];
	WCHAR ParentDir[MAX_PATH];

	// �������� �̸� ������
	GetModuleFileName(NULL, exePath, MAX_PATH);
	StringCchCopy(ParentDir, MAX_PATH, exePath);

	// �δܰ� ����� ������
	GetParentDir(ParentDir);
	GetParentDir(ParentDir);

	// �����̸� �����
	StringCchPrintf(g_pszFolderPath, MAX_PATH, L"%s\\%s", ParentDir, szPath);

	// ���������ϸ� �Ѿ�� ������ �����
	DWORD dwAttr = GetFileAttributes(g_pszFolderPath);
	if (dwAttr == INVALID_FILE_ATTRIBUTES)
	{
		if (!CreateDirectory(g_pszFolderPath, NULL))
		{
			DWORD dwErrCode = GetLastError();
			__debugbreak();
		}
	}
}

void LOG(CONST WCHAR* szHead, LOG_LEVEL LogLevel, CHAR OUTPUT, CONST WCHAR* szStringFormat, ...);


__forceinline void GetLogLevel(WCHAR* pOutLogLevelStr, LOG_LEVEL LogLevel)
{
	switch (LogLevel)
	{
	case DEBUG:
		memcpy(pOutLogLevelStr, L"DEBUG", sizeof(L"DEBUG"));
		break;
	case SYSTEM:
		memcpy(pOutLogLevelStr, L"SYSTEM", sizeof(L"SYSTEM"));
		break;
	case ERR:
		memcpy(pOutLogLevelStr, L"ERROR", sizeof(L"ERROR"));
		break;
	default:
		__debugbreak();
		break;
	}
}

__forceinline BOOL CheckLogLevel(LOG_LEVEL LogLevel)
{
	LOG_LEVEL level;
	AcquireSRWLockShared(&g_srwForLogLevel);
	level = g_logLevel;
	ReleaseSRWLockShared(&g_srwForLogLevel);
	if (level > LogLevel)
		return FALSE;
	else
		return TRUE;
}

// EX : [2024 - 08 - 15 01:30 : 50 /
__forceinline HRESULT MakeStringYearMonthDayHourMinuteSecond(SYSTEMTIME* pSt)
{
	GetLocalTime(pSt);

	// �����Ͻú��� / 
	SIZE_T len = wcslen(g_logBufInfo.pLogBuf);
	HRESULT hResult = StringCchPrintf(g_logBufInfo.pLogBuf + len, (g_logBufInfo.iCurrentSize / 2) - len, L"[%04d-%02d-%02d %02d:%02d:%02d / ", pSt->wYear, pSt->wMonth, pSt->wDay, pSt->wHour, pSt->wMinute, pSt->wSecond);

	return hResult;
}

// EX : ERROR  / 000000001]  
// ���Ͷ����� �α�ī��Ʈ �ø�
__forceinline HRESULT MakeLogLevelAndCount(LOG_LEVEL LogLevel)
{
	// �α׷��� ���ϱ�
	SIZE_T len;
	WCHAR LogLevelStr[10];
	HRESULT hResult;
	GetLogLevel(LogLevelStr, LogLevel);

	len = wcslen(g_logBufInfo.pLogBuf);
	// �αװ� ���� ������ ��Ƽ������ �������հ� �ľ��ϱ� ���ؼ� ����
	DWORD dwLogCount = InterlockedIncrement((LONG*)&g_dwLogCount);

	hResult = StringCchPrintf(g_logBufInfo.pLogBuf + len, (g_logBufInfo.iCurrentSize / 2) - len, L"%-6s / %09d]  ", LogLevelStr, dwLogCount);
	return hResult;
}

// ���Ͽ��� ���ݱ��� ������ �α�����.
// g_srwFILEIO�� ������ ���Լ� ȣ�� �յڿ� ���� �Ǵ�.
__forceinline void OpenFileAndLog(CONST WCHAR* pFilePath)
{
	FILE* pFile;
	_wfopen_s(&pFile, pFilePath, L"a");
	fputws(g_logBufInfo.pLogBuf, pFile);
	fputc(L'\n', pFile);
	fclose(pFile);
}

// �α� ��ٰ� ���� �����Ҷ� ����ó���Լ�
// ���� ���Ҵ���  ���Ҵ��ϱ� ���� ����Ʈ�� -> ���Ҵ��� ����Ʈ���� �α׷� ��� ��.
// ȣ���� �Լ������� �� �Լ�ȣ������ �ٽ� ��ó������ �α׸� �����Ѵ�.
void ExceptLogBufInSuf(CONST WCHAR* pszType, LOG_LEVEL LogLevel, DWORD dwCurBufSize)
{
	while (1)
	{
		HeapFree(g_hHeapHandle, 0, g_logBufInfo.pLogBuf);
		g_logBufInfo.iCurrentSize *= 2;
		g_logBufInfo.pLogBuf = (WCHAR*)HeapAlloc(g_hHeapHandle, HEAP_GENERATE_EXCEPTIONS, g_logBufInfo.iCurrentSize);
		StringCchPrintf(g_logBufInfo.pLogBuf, g_logBufInfo.iCurrentSize / 2, L"[%s]  ", pszType);
		SYSTEMTIME st;
		HRESULT hResult = MakeStringYearMonthDayHourMinuteSecond(&st);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType, ERR, g_logBufInfo.iCurrentSize);
			continue;
		}

		// �α׷��� ���ϱ�
		// �αװ� ���� ������ ��Ƽ������ �������հ� �ľ��ϱ� ���ؼ� ����
		MakeLogLevelAndCount(LogLevel);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType, ERR, g_logBufInfo.iCurrentSize);
			continue;
		}

		// ��¥ �α��ϰ��� �ϴ°� �������ڷ� �ֱ�
		SIZE_T len = wcslen(g_logBufInfo.pLogBuf);
		hResult = StringCchPrintfW(g_logBufInfo.pLogBuf + len, (g_logBufInfo.iCurrentSize / 2) - len, L"LOG BUFSIZE INSUFFICIENT ALLOCATE % d -> % dBytes", dwCurBufSize, g_logBufInfo.iCurrentSize);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			continue;
		}

		// ���� �� ����
		WCHAR FilePath[MAX_PATH];
		StringCchPrintf(FilePath, MAX_PATH, L"%s\\%04d%02d_%s.txt", g_pszFolderPath, st.wYear, st.wMonth, pszType);

		// ���� ���� ������ �ݱ�
		// �������� ��������� ���ÿ� �������Ͽ� �����ϸ� ���Ͽ��⿡ �����Ҽ�������
		AcquireSRWLockExclusive(&g_srwForFILEIO);
		OpenFileAndLog(FilePath);
		ReleaseSRWLockExclusive(&g_srwForFILEIO);
		break;
	}
}

LOGGERAPI void LOG(const WCHAR* pszType, LOG_LEVEL LogLevel, CHAR OUTPUT, CONST WCHAR* pszStringFormat, ...)
{
	if (!CheckLogLevel(LogLevel))
		return;

	while (1)
	{
		//[BATTLE]  ���� ���ڿ� ���̱�
		StringCchPrintf(g_logBufInfo.pLogBuf, g_logBufInfo.iCurrentSize / 2, L"[%s]  ", pszType);


		SYSTEMTIME st;
		HRESULT hResult = MakeStringYearMonthDayHourMinuteSecond(&st);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType,ERR,g_logBufInfo.iCurrentSize);
			continue;
		}

		// �α׷��� ���ϱ�
		// �αװ� ���� ������ ��Ƽ������ �������հ� �ľ��ϱ� ���ؼ� ����
		MakeLogLevelAndCount(LogLevel);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType,ERR,g_logBufInfo.iCurrentSize);
			continue;
		}

		// ��¥ �α��ϰ��� �ϴ°� �������ڷ� �ֱ�
		SIZE_T len = wcslen(g_logBufInfo.pLogBuf);
		va_list va;
		va_start(va, pszStringFormat);
		hResult = StringCchVPrintf(g_logBufInfo.pLogBuf + len, (g_logBufInfo.iCurrentSize / 2) - len, pszStringFormat, va);
		va_end(va);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType,ERR,g_logBufInfo.iCurrentSize);
			continue;
		}
		if (OUTPUT == CONSOLE)
		{
			wprintf(L"%s\n", g_logBufInfo.pLogBuf);
		}
		else
		{
			// ���� �� ����
			WCHAR FilePath[MAX_PATH];
			StringCchPrintf(FilePath, MAX_PATH, L"%s\\%04d%02d_%s.txt", g_pszFolderPath, st.wYear, st.wMonth, pszType);

			// ���� ���� ������ �ݱ�
			// �������� ��������� ���ÿ� �������Ͽ� �����ϸ� ���Ͽ��⿡ �����Ҽ�������
			AcquireSRWLockExclusive(&g_srwForFILEIO);
			OpenFileAndLog(FilePath);
			ReleaseSRWLockExclusive(&g_srwForFILEIO);
		}
		break;
	}
}

#define ADDRESS 16
#define BYTESTRING 2
#define SPACEBAR 1
#define NULL_TERMINATOR 1
#define ENTER 1
#define LinePlaceHolderInterval (dwAlign + 1)


//swprintf_s�� 2��° �Ű����� BufferCount�� NULL Terminator�� �� ������ �����ؼ� �־���Ѵ�.
//dwNumOfChar�� NULL Terminator���� �����ؼ� ����� ���ۻ������̱� ������ dwNumOfChar - 1 - dwWrittenWcharNum�� �ƴ� 1ū���� �����.
void MAKE_BINARY_LOG(BYTE* pBuffer, DWORD dwBufferLen, DWORD dwAlign, CONST WCHAR* pFilePath)
{
	DWORD dwLineNumber;
	DWORD dwLastLineByteNum;
	DWORD dwNumOfWChar;
	WCHAR* pTempFileBuf;
	DWORD dwBinaryBufCnt;
	DWORD dwWrittenWcharNum;
	DWORD dwLineCounter;

	dwLineNumber = dwBufferLen / dwAlign; // ���� �ټ� ���� 1���۴�, ������ ������ ���ܵ�.
	dwLastLineByteNum = dwBufferLen % dwAlign;


	// �ټ� * (�ּ� + (�����̽��� ~ ����Ʈ�� * �ٴ� ����Ʈ�� ����) * �ټ� + �ι���)
	dwNumOfWChar = dwLineNumber * (ADDRESS + ((BYTESTRING + SPACEBAR) * dwAlign + ENTER)) + 
		ADDRESS + dwLastLineByteNum * (BYTESTRING + SPACEBAR) + NULL_TERMINATOR; // ��������
	pTempFileBuf = (WCHAR*)HeapAlloc(g_hHeapHandle, HEAP_GENERATE_EXCEPTIONS, dwNumOfWChar * sizeof(WCHAR));

	dwBinaryBufCnt = 0;
	dwWrittenWcharNum = 0;
	dwLineCounter = 0;

	while (dwLineCounter < dwLineNumber)
	{
		swprintf_s(pTempFileBuf + dwWrittenWcharNum, dwNumOfWChar - dwWrittenWcharNum, L"%p", pBuffer + dwBinaryBufCnt);
		dwWrittenWcharNum += ADDRESS;
		for (DWORD i = 0; i < dwAlign; ++i)
		{
			swprintf_s(pTempFileBuf + dwWrittenWcharNum, dwNumOfWChar  - dwWrittenWcharNum, L" %02x", pBuffer[dwBinaryBufCnt]);
			dwWrittenWcharNum += (BYTESTRING + SPACEBAR);
			++dwBinaryBufCnt;
		}
		pTempFileBuf[dwWrittenWcharNum] = L'\n';
		++dwWrittenWcharNum;
		++dwLineCounter;
	}

	if (dwLastLineByteNum == 0)
		goto lb_logging;

	// �������� ó��
	swprintf_s(pTempFileBuf + dwWrittenWcharNum, dwNumOfWChar  - dwWrittenWcharNum, L"%p", pBuffer + dwBinaryBufCnt);
	dwWrittenWcharNum += ADDRESS;
	for (DWORD i = 0; dwBinaryBufCnt < dwBufferLen; ++i)
	{
		swprintf_s(pTempFileBuf + dwWrittenWcharNum, dwNumOfWChar - dwWrittenWcharNum, L" %02x", pBuffer[dwBinaryBufCnt]);
		dwWrittenWcharNum += (BYTESTRING + SPACEBAR);
		++dwBinaryBufCnt;
	}

	lb_logging:
	FILE* pFile;
	_wfopen_s(&pFile, pFilePath, L"a");
	fputws(pTempFileBuf, pFile);
	fputc(L'\n', pFile);
	fclose(pFile);

	HeapFree(g_hHeapHandle, 0, pTempFileBuf);
}

LOGGERAPI void LOG_MEMORY_VIEW(CONST WCHAR* pszType, LOG_LEVEL LogLevel, CHAR OUTPUT, BYTE* pBuffer, DWORD dwBufferLen, DWORD dwAlign, CONST WCHAR* pszStringFormat, ...)
{
	if (!CheckLogLevel(LogLevel))
		return;

	while (1)
	{
		//[BATTLE]  ���� ���ڿ� ���̱�
		StringCchPrintf(g_logBufInfo.pLogBuf, g_logBufInfo.iCurrentSize / 2, L"[%s]  ", pszType);


		SYSTEMTIME st;
		HRESULT hResult = MakeStringYearMonthDayHourMinuteSecond(&st);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType, ERR, g_logBufInfo.iCurrentSize);
			continue;
		}

		// �α׷��� ���ϱ�
		// �αװ� ���� ������ ��Ƽ������ �������հ� �ľ��ϱ� ���ؼ� ����
		MakeLogLevelAndCount(LogLevel);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType, ERR, g_logBufInfo.iCurrentSize);
			continue;
		}

		// ��¥ �α��ϰ��� �ϴ°� �������ڷ� �ֱ�
		SIZE_T len = wcslen(g_logBufInfo.pLogBuf);
		va_list va;
		va_start(va, pszStringFormat);
		hResult = StringCchVPrintf(g_logBufInfo.pLogBuf + len, (g_logBufInfo.iCurrentSize / 2) - len, pszStringFormat, va);
		va_end(va);
		if (hResult == STRSAFE_E_INSUFFICIENT_BUFFER)
		{
			ExceptLogBufInSuf(pszType, ERR, g_logBufInfo.iCurrentSize);
			continue;
		}


		if (OUTPUT == CONSOLE)
		{
			wprintf(L"%s\n", g_logBufInfo.pLogBuf);
		}
		else
		{
			// ���� �� ����
			WCHAR FilePath[MAX_PATH];
			StringCchPrintf(FilePath, MAX_PATH, L"%s\\%04d%02d_%s.txt", g_pszFolderPath, st.wYear, st.wMonth, pszType);

			// ���� ���� ������ �ݱ�
			// �������� ��������� ���ÿ� �������Ͽ� �����ϸ� ���Ͽ��⿡ �����Ҽ�������
			AcquireSRWLockExclusive(&g_srwForFILEIO);
			OpenFileAndLog(FilePath);
			MAKE_BINARY_LOG(pBuffer, dwBufferLen, dwAlign, FilePath);
			ReleaseSRWLockExclusive(&g_srwForFILEIO);
		}
		break;
	}
}


LOGGERAPI void SET_LOG_LEVEL(LOG_LEVEL level)
{
	AcquireSRWLockExclusive(&g_srwForLogLevel);
	if (level >= DEBUG && level <= ERR)
		g_logLevel = level;
	ReleaseSRWLockExclusive(&g_srwForLogLevel);
}

LOGGERAPI LOG_LEVEL INCREASE_LOG_LEVEL()
{
	LOG_LEVEL Ret;
	AcquireSRWLockExclusive(&g_srwForLogLevel);
	if (g_logLevel >= DEBUG && g_logLevel <= SYSTEM)
	{
		++*(DWORD*)(&g_logLevel);
		Ret = g_logLevel;
	}
	else
	{
		Ret = g_logLevel;
	}
	ReleaseSRWLockExclusive(&g_srwForLogLevel);
	return Ret;
}

LOGGERAPI LOG_LEVEL DECREASE_LOG_LEVEL()
{
	LOG_LEVEL Ret;
	AcquireSRWLockExclusive(&g_srwForLogLevel);
	if (g_logLevel >= SYSTEM && g_logLevel <= ERR)
	{
		--*(DWORD*)(&g_logLevel);
		Ret = g_logLevel;
	}
	else
	{
		Ret = g_logLevel;
	}
	ReleaseSRWLockExclusive(&g_srwForLogLevel);
	return Ret;
}


