#pragma once

#include "stdafx.h"

struct GLOBAL_CONFIG
{
	UINT CodePage;
	UINT LCID;
	long Bias;
	bool HookIME;
	bool SingleLCID;
	bool UseFontSubstitution;
	bool SubstituteAllFonts;
	LPCWSTR SubstituteFontName;
	std::vector<std::wstring> FontsToSubstitute;
	std::vector<std::wstring> ExcludedProcesses;
};

struct INITIAL_STATE
{
	HMODULE hModule = NULL;
	HANDLE hHeap = NULL;
	UINT CodePage = CP_ACP;
	UINT Charset = 0;
	UINT LCID = 0;
	char DllPath[MAX_PATH] = { 0 };
	const char* lpDefaultChar = " ";
	BOOL lpUsedDefaultChar = TRUE;
};

static int (WINAPI* OriginalMultiByteToWideChar)(
	UINT CodePage,
	DWORD dwFlags,
	LPCSTR lpMultiByteStr,
	int cbMultiByte,
	LPWSTR lpWideCharStr,
	int cchWideChar
	) = MultiByteToWideChar;

static int (WINAPI* OriginalWideCharToMultiByte)(
	UINT CodePage,
	DWORD dwFlags,
	LPCWSTR lpWideCharStr,
	int cchWideChar,
	LPSTR lpMultiByteStr,
	int cbMultiByte,
	LPCSTR lpDefaultChar,
	LPBOOL lpUsedDefaultChar
	) = WideCharToMultiByte;

// Sandboxie function pointer types
typedef LONG(WINAPI* SbieApi_QueryConf_t)(const WCHAR*, const WCHAR*, ULONG, WCHAR*, ULONG);
typedef BOOLEAN(WINAPI* SbieApi_QueryConfBool_t)(const WCHAR*, const WCHAR*, BOOLEAN);
typedef LONG(WINAPI* SbieApi_QueryProcess_t)(HANDLE, WCHAR*, WCHAR*, WCHAR*, ULONG*);
typedef LONG(WINAPI* SbieApi_Log_t)(ULONG, const WCHAR*, ...);

inline LPVOID AllocateZeroedMemory(SIZE_T size);
inline VOID FreeStringInternal(LPVOID pBuffer);
LPWSTR MultiByteToWideCharInternal(LPCSTR lstr, UINT CodePage);
LPSTR WideCharToMultiByteInternal(LPCWSTR wstr, UINT CodePage);

extern inline void DebugLog(const char* format, ...);
extern inline void DebugLog(const wchar_t* format, ...);
