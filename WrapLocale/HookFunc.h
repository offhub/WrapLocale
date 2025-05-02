#pragma once

#include "stdafx.h"
#include "User32Hook.h"
#include "CommonLibrary.h"

extern GLOBAL_CONFIG settings;
extern INITIAL_STATE Initial;

inline LPVOID AllocateZeroedMemory(SIZE_T size /*eax*/);
VOID FreeStringInternal(LPVOID pBuffer /*ecx*/);
inline LPWSTR MultiByteToWideCharInternal(LPCSTR lstr, UINT CodePage = settings.CodePage);
inline LPSTR WideCharToMultiByteInternal(LPCWSTR wstr, UINT CodePage = settings.CodePage);

void EnableApiHooks();
void DisableApiHooks();

UINT WINAPI HookGetACP(void);
UINT WINAPI HookGetOEMCP(void);
BOOL WINAPI HookGetCPInfo(UINT CodePage, LPCPINFO lpCPInfo);

LCID WINAPI HookGetLocaleID(void);
LCID WINAPI HookGetThreadLocale(void);
LANGID WINAPI HookGetSystemDefaultUILanguage(void);
LANGID WINAPI HookGetUserDefaultUILanguage(void);
LCID WINAPI HookGetSystemDefaultLCID(void);
LCID WINAPI HookGetUserDefaultLCID(void);
LANGID WINAPI HookGetSystemDefaultLangID(void);
LANGID WINAPI HookGetUserDefaultLangID(void);

HWND WINAPI HookCreateWindowExA(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCSTR lpClassName,
	_In_opt_ LPCSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam
);

LRESULT WINAPI HookSendMessageA(
	_In_ HWND hWnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

LRESULT WINAPI HookCallWindowProcA(
	_In_ WNDPROC lpPrevWndFunc,
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

int WINAPI HookMultiByteToWideChar(UINT CodePage, DWORD dwFlags,
	LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

int WINAPI HookWideCharToMultiByte(UINT CodePage, DWORD dwFlags,
	LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);

UINT WINAPI HookWinExec(
	_In_ LPSTR lpCmdLine,
	_In_ UINT uCmdShow);


BOOL WINAPI HookCreateProcessA(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
);

HINSTANCE WINAPI HookShellExecuteA(
	_In_opt_ HWND hwnd,
	_In_opt_ LPSTR lpOperation,
	_In_ LPSTR lpFile,
	_In_opt_ LPSTR lpParameters,
	_In_opt_ LPSTR lpDirectory,
	_In_ INT nShowCmd);

HINSTANCE WINAPI HookShellExecuteW(
	_In_opt_ HWND hwnd,
	_In_opt_ LPWSTR lpOperation,
	_In_ LPWSTR lpFile,
	_In_opt_ LPWSTR lpParameters,
	_In_opt_ LPWSTR lpDirectory,
	_In_ INT nShowCmd
);

BOOL WINAPI HookShellExecuteExA(
_Inout_ SHELLEXECUTEINFOA* pExecInfo
);

BOOL WINAPI HookShellExecuteExW(
_Inout_ SHELLEXECUTEINFOW* pExecInfo
);

int WINAPI HookMessageBoxA(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType
);

BOOL WINAPI HookSetWindowTextA(
	_In_ HWND hWnd,
	_In_opt_ LPCSTR lpString
);

int WINAPI HookGetWindowTextA(
	_In_ HWND hWnd,
	_Out_writes_(nMaxCount) LPSTR lpString,
	_In_ int nMaxCount);

LONG WINAPI HookImmGetCompositionStringA(
	HIMC hIMC,
	DWORD dwIndex,
	LPSTR lpBuf,
	DWORD  dwBufLen
);

LONG WINAPI HookImmGetCompositionStringA_WM(
	HIMC hIMC,
	DWORD dwIndex,
	LPSTR lpBuf,
	DWORD  dwBufLen
);

DWORD WINAPI HookImmGetCandidateListA(
	HIMC            hIMC,
	DWORD           deIndex,
	LPCANDIDATELIST lpCandList,
	DWORD           dwBufLen
);

DWORD WINAPI HookImmGetCandidateListA_WM(
	HIMC            hIMC,
	DWORD           deIndex,
	LPCANDIDATELIST lpCandList,
	DWORD           dwBufLen
);

HFONT WINAPI HookCreateFontA(
	_In_ int cHeight,
	_In_ int cWidth,
	_In_ int cEscapement,
	_In_ int cOrientation,
	_In_ int cWeight,
	_In_ DWORD bItalic,
	_In_ DWORD bUnderline,
	_In_ DWORD bStrikeOut,
	_In_ DWORD iCharSet,
	_In_ DWORD iOutPrecision,
	_In_ DWORD iClipPrecision,
	_In_ DWORD iQuality,
	_In_ DWORD iPitchAndFamily,
	_In_opt_ LPCSTR pszFaceName
);

HFONT WINAPI HookCreateFontW(
	_In_ int cHeight,
	_In_ int cWidth,
	_In_ int cEscapement,
	_In_ int cOrientation,
	_In_ int cWeight,
	_In_ DWORD bItalic,
	_In_ DWORD bUnderline,
	_In_ DWORD bStrikeOut,
	_In_ DWORD iCharSet,
	_In_ DWORD iOutPrecision,
	_In_ DWORD iClipPrecision,
	_In_ DWORD iQuality,
	_In_ DWORD iPitchAndFamily,
	_In_opt_ LPCWSTR pszFaceName
);

HFONT WINAPI HookCreateFontIndirectA(
	LOGFONTA* lplf
);

HFONT WINAPI HookCreateFontIndirectW(
	LOGFONTW* lplf
);

HFONT WINAPI HookCreateFontIndirectExA(
	ENUMLOGFONTEXDVA*
);

HFONT WINAPI HookCreateFontIndirectExW(
	ENUMLOGFONTEXDVW*
);

BOOL WINAPI HookTextOutA(
	HDC    hdc,
	int    x,
	int    y,
	LPSTR lpString,
	int    c
);

int WINAPI HookDrawTextExA(
	_In_ HDC hdc,
	LPSTR lpchText,
	_In_ int cchText,
	_Inout_ LPRECT lprc,
	_In_ UINT format,
	_In_opt_ LPDRAWTEXTPARAMS lpdtp
);

HANDLE WINAPI HookGetClipboardData(
	UINT uFormat
);

HANDLE WINAPI HookSetClipboardData(
	UINT uFormat,
	HANDLE hMem
);

HRESULT WINAPI HookDirectSoundEnumerateA(
	_In_ LPDSENUMCALLBACKA pDSEnumCallback,
	_In_opt_ LPVOID pContext
);

LPSTR WINAPI HookCharPrevExA(
	_In_ WORD CodePage,
	_In_ LPCSTR lpStart,
	_In_ LPCSTR lpCurrentChar,
	_In_ DWORD dwFlags
);

LPSTR WINAPI HookCharNextExA(
	_In_ WORD CodePage,
	_In_ LPCSTR lpCurrentChar,
	_In_ DWORD dwFlags
);

BOOL WINAPI HookIsDBCSLeadByteEx(
	_In_ UINT  CodePage,
	_In_ BYTE  TestChar
);

/*
INT_PTR WINAPI HookDialogBoxParamA(
	_In_opt_ HINSTANCE hInstance,
	_In_ LPCSTR lpTemplateName,
	_In_opt_ HWND hWndParent,
	_In_opt_ DLGPROC lpDialogFunc,
	_In_ LPARAM dwInitParam
);
*/

HWND WINAPI HookCreateDialogIndirectParamA(
	_In_opt_ HINSTANCE hInstance,
	_In_ LPCDLGTEMPLATEA lpTemplate,
	_In_opt_ HWND hWndParent,
	_In_opt_ DLGPROC lpDialogFunc,
	_In_ LPARAM dwInitParam
);

ATOM WINAPI HookRegisterClassA(
	_In_ CONST WNDCLASSA* lpWndClass
);

ATOM WINAPI HookRegisterClassExA(
	_In_ CONST WNDCLASSEXA* lpWndClass
);

LRESULT CALLBACK HookDefWindowProcA(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

DWORD WINAPI HookGetTimeZoneInformation(
	_Out_ LPTIME_ZONE_INFORMATION lpTimeZoneInformation
); 

BOOL WINAPI HookCreateDirectoryA(
	_In_ LPCSTR lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

HANDLE WINAPI HookCreateFileA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

int WINAPI HookGetLocaleInfoA(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPSTR lpLCData,
	_In_ int cchData
);

int WINAPI HookGetLocaleInfoW(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPWSTR lpLCData,
	_In_ int cchData
);

/*
DWORD WINAPI HookGetNumberFormatW(
	_In_ LCID Locale,
	_In_ DWORD dwFlags,
	_In_ LPCWSTR lpValue,
	_In_opt_ CONST NUMBERFMTW* lpFormat,
	_Out_writes_opt_(cchNumber) LPWSTR lpNumberStr,
	_In_ int cchNumber);

DWORD WINAPI HookGetNumberFormatA(
	_In_ LCID Locale,
	_In_ DWORD dwFlags,
	_In_ LPCSTR lpValue,
	_In_opt_ CONST NUMBERFMTA* lpFormat,
	_Out_writes_opt_(cchNumber) LPSTR lpNumberStr,
	_In_ int cchNumber);
*/

// File operation hooks
HANDLE WINAPI HookCreateFileA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

BOOL WINAPI HookCreateDirectoryA(
	_In_ LPCSTR lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

HANDLE WINAPI HookFindFirstFileA(
	_In_ LPCSTR lpFileName,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
);

BOOL WINAPI HookFindNextFileA(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
);

DWORD WINAPI HookGetFileAttributesA(
	_In_ LPCSTR lpFileName
);

BOOL WINAPI HookDeleteFileA(
	_In_ LPCSTR lpFileName
);

BOOL WINAPI HookCopyFileA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName,
	_In_ BOOL bFailIfExists
);

BOOL WINAPI HookMoveFileA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName
);

DWORD WINAPI HookGetFullPathNameA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD nBufferLength,
	_Out_opt_ LPSTR lpBuffer,
	_Outptr_opt_ LPSTR* lpFilePart
);

HANDLE WINAPI HookCreateFileMappingA(
	_In_ HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_ DWORD flProtect,
	_In_ DWORD dwMaximumSizeHigh,
	_In_ DWORD dwMaximumSizeLow,
	_In_opt_ LPCSTR lpName
);

HMODULE WINAPI HookLoadLibraryA(
	_In_ LPCSTR lpLibFileName
);

DWORD WINAPI HookGetModuleFileNameA(
	_In_opt_ HMODULE hModule,
	_Out_writes_(MAX_PATH) LPSTR lpFilename,
	_In_ DWORD nSize
);

DWORD WINAPI HookGetTempPathA(
	_In_ DWORD nBufferLength,
	_Out_ LPSTR lpBuffer
);

UINT WINAPI HookGetTempFileNameA(
	_In_ LPCSTR lpPathName,
	_In_ LPCSTR lpPrefixString,
	_In_ UINT uUnique,
	_Out_writes_(MAX_PATH) LPSTR lpTempFileName
);

BOOL WINAPI HookGetFileVersionInfoA(
	_In_ LPCSTR lptstrFilename,
	_Reserved_ DWORD dwHandle,
	_In_ DWORD dwLen,
	_Out_writes_bytes_(dwLen) LPVOID lpData
);

BOOL WINAPI HookRemoveDirectoryA(
	_In_ LPCSTR lpPathName
);

BOOL WINAPI HookSetCurrentDirectoryA(
	_In_ LPCSTR lpPathName
);

DWORD WINAPI HookGetCurrentDirectoryA(
	_In_ DWORD nBufferLength,
	_Out_writes_opt_(nBufferLength) LPSTR lpBuffer
);

HANDLE WINAPI HookFindFirstFileExA(
	_In_ LPCSTR lpFileName,
	_In_ FINDEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FIND_DATAA)) LPVOID lpFindFileData,
	_In_ FINDEX_SEARCH_OPS fSearchOp,
	_Reserved_ LPVOID lpSearchFilter,
	_In_ DWORD dwAdditionalFlags
);
DWORD WINAPI HookGetLongPathNameA(
	_In_ LPCSTR lpszShortPath,
	_Out_writes_(cchBuffer) LPSTR lpszLongPath,
	_In_ DWORD cchBuffer
);
DWORD WINAPI HookGetShortPathNameA(
	_In_ LPCSTR lpszLongPath,
	_Out_writes_(cchBuffer) LPSTR lpszShortPath,
	_In_ DWORD cchBuffer
);
BOOL WINAPI HookSetFileAttributesA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwFileAttributes
);
UINT WINAPI HookGetDriveTypeA(
	_In_opt_ LPCSTR lpRootPathName
);
BOOL WINAPI HookGetVolumeInformationA(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_writes_opt_(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
	_In_ DWORD nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_writes_opt_(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
	_In_ DWORD nFileSystemNameSize
);
BOOL WINAPI HookGetDiskFreeSpaceA(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_opt_ LPDWORD lpSectorsPerCluster,
	_Out_opt_ LPDWORD lpBytesPerSector,
	_Out_opt_ LPDWORD lpNumberOfFreeClusters,
	_Out_opt_ LPDWORD lpTotalNumberOfClusters
);
BOOL WINAPI HookGetDiskFreeSpaceExA(
	_In_opt_ LPCSTR lpDirectoryName,
	_Out_opt_ PULARGE_INTEGER lpFreeBytesAvailableToCaller,
	_Out_opt_ PULARGE_INTEGER lpTotalNumberOfBytes,
	_Out_opt_ PULARGE_INTEGER lpTotalNumberOfFreeBytes
);
DWORD WINAPI HookGetLogicalDrives(VOID);
DWORD WINAPI HookGetLogicalDriveStringsA(
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer
);
BOOL WINAPI HookReadFile(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);
BOOL WINAPI HookWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);
BOOL WINAPI HookSetEndOfFile(
	_In_ HANDLE hFile
);
DWORD WINAPI HookGetFileSize(
	_In_ HANDLE hFile,
	_Out_opt_ LPDWORD lpFileSizeHigh
);
BOOL WINAPI HookGetFileSizeEx(
	_In_ HANDLE hFile,
	_Out_ PLARGE_INTEGER lpFileSize
);
DWORD WINAPI HookSetFilePointer(
	_In_ HANDLE hFile,
	_In_ LONG lDistanceToMove,
	_Inout_opt_ PLONG lpDistanceToMoveHigh,
	_In_ DWORD dwMoveMethod
);
BOOL WINAPI HookSetFilePointerEx(
	_In_ HANDLE hFile,
	_In_ LARGE_INTEGER liDistanceToMove,
	_Out_opt_ PLARGE_INTEGER lpNewFilePointer,
	_In_ DWORD dwMoveMethod
);
BOOL WINAPI HookCreateHardLinkA(
	_In_ LPCSTR lpFileName,
	_In_ LPCSTR lpExistingFileName,
	_Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
BOOLEAN WINAPI HookCreateSymbolicLinkA(
	_In_ LPCSTR lpSymlinkFileName,
	_In_ LPCSTR lpTargetFileName,
	_In_ DWORD dwFlags
);
LSTATUS WINAPI HookRegOpenKeyExA(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpSubKey,
	_In_opt_ DWORD ulOptions,
	_In_ REGSAM samDesired,
	_Out_ PHKEY phkResult
);
LSTATUS WINAPI HookRegCreateKeyExA(
	_In_ HKEY hKey,
	_In_ LPCSTR lpSubKey,
	_Reserved_ DWORD Reserved,
	_In_opt_ LPSTR lpClass,
	_In_ DWORD dwOptions,
	_In_ REGSAM samDesired,
	_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_ PHKEY phkResult,
	_Out_opt_ LPDWORD lpdwDisposition
);
LSTATUS WINAPI HookRegQueryValueExA(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ LPDWORD lpReserved,
	_Out_opt_ LPDWORD lpType,
	_Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) LPBYTE lpData,
	_Inout_opt_ LPDWORD lpcbData
);
LSTATUS WINAPI HookRegSetValueExA(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ DWORD Reserved,
	_In_ DWORD dwType,
	_In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
	_In_ DWORD cbData
);
HMODULE WINAPI HookLoadLibraryExA(
	_In_ LPCSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
);
HMODULE WINAPI HookGetModuleHandleA(
	_In_opt_ LPCSTR lpModuleName
);
BOOL WINAPI HookGetModuleHandleExA(
	_In_ DWORD dwFlags,
	_In_opt_ LPCSTR lpModuleName,
	_Out_ HMODULE* phModule
);
LPSTR WINAPI HookGetCommandLineA(VOID);
VOID WINAPI HookGetStartupInfoA(
	_Out_ LPSTARTUPINFOA lpStartupInfo
);
DWORD WINAPI HookGetEnvironmentVariableA(
	_In_opt_ LPCSTR lpName,
	_Out_writes_to_opt_(nSize, return + 1) LPSTR lpBuffer,
	_In_ DWORD nSize
);
BOOL WINAPI HookSetEnvironmentVariableA(
	_In_opt_ LPCSTR lpName,
	_In_opt_ LPCSTR lpValue
);
DWORD WINAPI HookExpandEnvironmentStringsA(
	_In_ LPCSTR lpSrc,
	_Out_writes_to_opt_(nSize, return) LPSTR lpDst,
	_In_ DWORD nSize
);

typedef struct {
    FONTENUMPROCA lpOriginalProc;
    LPARAM lOriginalParam;
} ENUMFONTS_CB_DATA;

DWORD CALLBACK EnumFontsCallbackWrapper(
	CONST LOGFONTW* lpelfw,
	CONST TEXTMETRICW* lpntmw,
	DWORD FontType,
	LPARAM lParam
);

int WINAPI HookEnumFontsA(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam
);

int WINAPI HookEnumFontFamiliesA(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam
);