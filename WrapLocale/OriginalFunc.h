#pragma once

#include "stdafx.h"

static UINT(WINAPI* OriginalGetACP)(void) = GetACP;
static UINT(WINAPI* OriginalGetOEMCP)(void) = GetOEMCP;
static BOOL(WINAPI* OriginalGetCPInfo)(
	UINT	   CodePage,
	LPCPINFO  lpCPInfo
	) = GetCPInfo;

static HWND(WINAPI* OriginalCreateWindowExA)(
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
	) = CreateWindowExA;

static LRESULT(WINAPI* OriginalSendMessageA)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_Pre_maybenull_ _Post_valid_ WPARAM wParam,
	_Pre_maybenull_ _Post_valid_ LPARAM lParam
	) = SendMessageA;

static UINT(WINAPI* OriginalWinExec)(
	_In_ LPCSTR lpCmdLine,
	_In_ UINT uCmdShow
	) = WinExec;

static BOOL(WINAPI* OriginalCreateProcessA)(
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
	) = CreateProcessA;

static BOOL(WINAPI* OriginalCreateProcessW)(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessW;

static HINSTANCE(WINAPI* OriginalShellExecuteA)(
	_In_opt_ HWND hwnd, 
	_In_opt_ LPCSTR lpOperation, 
	_In_ LPCSTR lpFile, 
	_In_opt_ LPCSTR lpParameters,
	_In_opt_ LPCSTR lpDirectory, 
	_In_ INT nShowCmd
	)= ShellExecuteA;

static HINSTANCE(WINAPI* OriginalShellExecuteW)(
	_In_opt_ HWND hwnd,
	_In_opt_ LPCWSTR lpOperation,
	_In_ LPCWSTR lpFile,
	_In_opt_ LPCWSTR lpParameters,
	_In_opt_ LPCWSTR lpDirectory,
	_In_ INT nShowCmd
	) = ShellExecuteW;

static BOOL(WINAPI* OriginalShellExecuteExA)(
	_Inout_ SHELLEXECUTEINFOA* pExecInfo
	) = ShellExecuteExA;

static BOOL(WINAPI* OriginalShellExecuteExW)(
	_Inout_ SHELLEXECUTEINFOW* pExecInfo
	) = ShellExecuteExW;

static int(WINAPI* OriginalMessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType
	) = MessageBoxA;

static BOOL(WINAPI* OriginalSetWindowTextA)(
	_In_ HWND hWnd,
	_In_opt_ LPCSTR lpString
	) = SetWindowTextA;

static int(WINAPI* OriginalGetWindowTextA)(
	_In_ HWND hWnd,
	_Out_writes_(nMaxCount) LPSTR lpString,
	_In_ int nMaxCount
	) = GetWindowTextA;

static LONG(WINAPI* OriginalImmGetCompositionStringA)(
	HIMC hIMC,
	DWORD dwIndex,
	LPVOID lpBuf,
	DWORD  dwBufLen
	) = ImmGetCompositionStringA;

static DWORD(WINAPI* OriginalImmGetCandidateListA)(
	HIMC			hIMC,
	DWORD		   deIndex,
	LPCANDIDATELIST lpCandList,
	DWORD		   dwBufLen
	) = ImmGetCandidateListA;

static HFONT(WINAPI* OriginalCreateFontA)(
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
	) = CreateFontA;

static HFONT(WINAPI* OriginalCreateFontW)(
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
	) = CreateFontW;

static HFONT(WINAPI* OriginalCreateFontIndirectA)(
	const LOGFONTA* lplf
	) = CreateFontIndirectA;

static HFONT(WINAPI* OriginalCreateFontIndirectW)(
	_In_ CONST LOGFONTW* lplf
	) = CreateFontIndirectW;

static HFONT(WINAPI* OriginalCreateFontIndirectExA)(
	_In_ CONST ENUMLOGFONTEXDVA*
	) = CreateFontIndirectExA;

static HFONT(WINAPI* OriginalCreateFontIndirectExW)(
	_In_ CONST ENUMLOGFONTEXDVW*
	) = CreateFontIndirectExW;

static BOOL(WINAPI* OriginalTextOutA)(
	HDC	hdc,
	int	x,
	int	y,
	LPCSTR lpString,
	int	c
	) = TextOutA;

static int(WINAPI* OriginalDrawTextExA)(
	_In_ HDC hdc,
	LPSTR lpchText,
	_In_ int cchText,
	_Inout_ LPRECT lprc,
	_In_ UINT format,
	_In_opt_ LPDRAWTEXTPARAMS lpdtp
	) = DrawTextExA;

static HANDLE(WINAPI* OriginalGetClipboardData)(
	_In_ UINT uFormat
	) = GetClipboardData;

static HANDLE(WINAPI* OriginalSetClipboardData)(
	_In_ UINT uFormat,
	_In_opt_ HANDLE hMem
	) = SetClipboardData;

static HRESULT(WINAPI* OriginalDirectSoundEnumerateA)(
	_In_ LPDSENUMCALLBACKA pDSEnumCallback,
	_In_opt_ LPVOID pContext
	) = DirectSoundEnumerateA;

static LPSTR(WINAPI* OriginalCharPrevExA)(
	_In_ WORD CodePage,
	_In_ LPCSTR lpStart,
	_In_ LPCSTR lpCurrentChar,
	_In_ DWORD dwFlags
	) = CharPrevExA;

static LPSTR(WINAPI* OriginalCharNextExA)(
	_In_ WORD CodePage,
	_In_ LPCSTR lpCurrentChar,
	_In_ DWORD dwFlags
	) = CharNextExA;

static BOOL(WINAPI* OriginalIsDBCSLeadByteEx)(
	_In_ UINT  CodePage,
	_In_ BYTE  TestChar
	) = IsDBCSLeadByteEx;

static INT_PTR(WINAPI* OriginalDialogBoxParamA)(
	_In_opt_ HINSTANCE hInstance,
	_In_ LPCSTR lpTemplateName,
	_In_opt_ HWND hWndParent,
	_In_opt_ DLGPROC lpDialogFunc,
	_In_ LPARAM dwInitParam
	) = DialogBoxParamA;

static HWND(WINAPI* OriginalCreateDialogIndirectParamA)(
	_In_opt_ HINSTANCE hInstance,
	_In_ LPCDLGTEMPLATEA lpTemplate,
	_In_opt_ HWND hWndParent,
	_In_opt_ DLGPROC lpDialogFunc,
	_In_ LPARAM dwInitParam
	) = CreateDialogIndirectParamA;

static ATOM(WINAPI* OriginalRegisterClassA)(
	_In_ CONST WNDCLASSA* lpWndClass
	) = RegisterClassA;

static ATOM(WINAPI* OriginalRegisterClassExA)(
	_In_ CONST WNDCLASSEXA* lpWndClass
	) = RegisterClassExA;

static LRESULT(WINAPI* OriginalDefWindowProcA)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	) = DefWindowProcA;

static LRESULT(WINAPI* OriginalCallWindowProcA)(
	_In_ WNDPROC lpPrevWndFunc,
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	) = CallWindowProcA;

static LCID(WINAPI* OriginalGetThreadLocale)() = GetThreadLocale;
static LANGID(WINAPI* OriginalGetSystemDefaultUILanguage)() = GetSystemDefaultUILanguage;
static LANGID(WINAPI* OriginalGetUserDefaultUILanguage)() = GetUserDefaultUILanguage;
static LCID(WINAPI* OriginalGetSystemDefaultLCID)() = GetSystemDefaultLCID;
static LCID(WINAPI* OriginalGetUserDefaultLCID)() = GetUserDefaultLCID;
static LANGID(WINAPI* OriginalGetSystemDefaultLangID)() = GetSystemDefaultLangID;
static LANGID(WINAPI* OriginalGetUserDefaultLangID)() = GetUserDefaultLangID;

static DWORD(WINAPI* OriginalGetTimeZoneInformation)(
	_Out_ LPTIME_ZONE_INFORMATION lpTimeZoneInformation
	) = GetTimeZoneInformation;

static BOOL(WINAPI* OriginalCreateDirectoryA)(
	_In_ LPCSTR lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
) = CreateDirectoryA;

static HANDLE(WINAPI* OriginalCreateFileA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	) = CreateFileA;

static int(WINAPI* OriginalGetLocaleInfoA)(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPSTR lpLCData,
	_In_ int cchData
	) = GetLocaleInfoA;

static int(WINAPI* OriginalGetLocaleInfoW)(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPWSTR lpLCData,
	_In_ int cchData
) = GetLocaleInfoW;

static BOOL(WINAPI* OriginalGetUserDefaultLocaleName)(
	_Out_writes_(cchLocaleName) LPWSTR lpLocaleName,
	_In_ int cchLocaleName
	) = GetUserDefaultLocaleName;

static BOOL(WINAPI* OriginalGetSystemDefaultLocaleName)(
	_Out_writes_(cchLocaleName) LPWSTR lpLocaleName,
	_In_ int cchLocaleName
	) = GetSystemDefaultLocaleName;

/*static DWORD(WINAPI* OriginalGetNumberFormatW)(
	_In_ LCID Locale,
	_In_ DWORD dwFlags,
	_In_ LPCWSTR lpValue,
	_In_opt_ CONST NUMBERFMTW* lpFormat,
	_Out_writes_opt_(cchNumber) LPWSTR lpNumberStr,
	_In_ int cchNumber
) = GetNumberFormatW;

static DWORD(WINAPI* OriginalGetNumberFormatA)(
	_In_ LCID Locale,
	_In_ DWORD dwFlags,
	_In_ LPCSTR lpValue,
	_In_opt_ CONST NUMBERFMTA* lpFormat,
	_Out_writes_opt_(cchNumber) LPSTR lpNumberStr,
	_In_ int cchNumber
) = GetNumberFormatA;

static HWND(WINAPI* OriginalNtUserCreateWindowEx)(
	_In_ DWORD dwExStyle,
	_In_opt_ UNICODE_STRING* lpClassName,
	_In_opt_ UNICODE_STRING* lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam,
	_In_ DWORD dwFlags,
	_In_ PVOID lpCreateParams
	) = NtUserCreateWindowEx;

static LRESULT(WINAPI* OriginalNtUserMessageCall)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam,
	_In_ ULONG_PTR ResultInfo,
	_In_ DWORD dwType,
	_In_ BOOL bAnsi
	) = NtUserMessageCall;
*/


// Original function pointers
static HANDLE(WINAPI* OriginalFindFirstFileA)(
	_In_ LPCSTR lpFileName,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
) = FindFirstFileA;

static BOOL(WINAPI* OriginalFindNextFileA)(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
) = FindNextFileA;

static DWORD(WINAPI* OriginalGetFileAttributesA)(
	_In_ LPCSTR lpFileName
) = GetFileAttributesA;

static BOOL(WINAPI* OriginalDeleteFileA)(
	_In_ LPCSTR lpFileName
) = DeleteFileA;

static BOOL(WINAPI* OriginalCopyFileA)(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName,
	_In_ BOOL bFailIfExists
) = CopyFileA;

static BOOL(WINAPI* OriginalMoveFileA)(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName
) = MoveFileA;

static DWORD(WINAPI* OriginalGetFullPathNameA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD nBufferLength,
	_Out_opt_ LPSTR lpBuffer,
	_Outptr_opt_ LPSTR* lpFilePart
) = GetFullPathNameA;

static HANDLE(WINAPI* OriginalCreateFileMappingA)(
	_In_opt_ HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_ DWORD flProtect,
	_In_ DWORD dwMaximumSizeHigh,
	_In_ DWORD dwMaximumSizeLow,
	_In_opt_ LPCSTR lpName
	) = CreateFileMappingA;

static HMODULE(WINAPI* OriginalLoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	) = LoadLibraryA;

static DWORD(WINAPI* OriginalGetModuleFileNameA)(
	_In_opt_ HMODULE hModule,
	_Out_writes_(MAX_PATH) LPSTR lpFilename,
	_In_ DWORD nSize
	) = GetModuleFileNameA;

static DWORD(WINAPI * OriginalGetTempPathA)(
	_In_ DWORD nBufferLength,
	_Out_ LPSTR lpBuffer
	) = GetTempPathA;

static UINT(WINAPI * OriginalGetTempFileNameA)(
	_In_ LPCSTR lpPathName,
	_In_ LPCSTR lpPrefixString,
	_In_ UINT uUnique,
	_Out_writes_(MAX_PATH) LPSTR lpTempFileName
	) = GetTempFileNameA;

static BOOL(WINAPI * OriginalGetFileVersionInfoA)(
	_In_ LPCSTR lptstrFilename,
	_Reserved_ DWORD dwHandle,
	_In_ DWORD dwLen,
	_Out_writes_bytes_(dwLen) LPVOID lpData
	) = GetFileVersionInfoA;

static BOOL(WINAPI * OriginalRemoveDirectoryA)(
	_In_ LPCSTR lpPathName
	) = RemoveDirectoryA;

static BOOL(WINAPI * OriginalSetCurrentDirectoryA)(
	_In_ LPCSTR lpPathName
	) = SetCurrentDirectoryA;

static DWORD(WINAPI * OriginalGetCurrentDirectoryA)(
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer
	) = GetCurrentDirectoryA;

// Original function pointers
static BOOL (WINAPI* OriginalFindClose)(
	_In_ HANDLE hFindFile
) = FindClose;

static HANDLE (WINAPI* OriginalFindFirstFileExA)(
	_In_ LPCSTR lpFileName,
	_In_ FINDEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FIND_DATAA)) LPVOID lpFindFileData,
	_In_ FINDEX_SEARCH_OPS fSearchOp,
	_Reserved_ LPVOID lpSearchFilter,
	_In_ DWORD dwAdditionalFlags
) = FindFirstFileExA;

static DWORD (WINAPI* OriginalGetLongPathNameA)(
	_In_ LPCSTR lpszShortPath,
	_Out_writes_(cchBuffer) LPSTR lpszLongPath,
	_In_ DWORD cchBuffer
) = GetLongPathNameA;

static DWORD (WINAPI* OriginalGetShortPathNameA)(
	_In_ LPCSTR lpszLongPath,
	_Out_writes_(cchBuffer) LPSTR lpszShortPath,
	_In_ DWORD cchBuffer
) = GetShortPathNameA;

static BOOL (WINAPI* OriginalSetFileAttributesA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwFileAttributes
) = SetFileAttributesA;

static UINT (WINAPI* OriginalGetDriveTypeA)(
	_In_opt_ LPCSTR lpRootPathName
) = GetDriveTypeA;

static BOOL (WINAPI* OriginalGetVolumeInformationA)(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_writes_opt_(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
	_In_ DWORD nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_writes_opt_(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
	_In_ DWORD nFileSystemNameSize
) = GetVolumeInformationA;

static BOOL (WINAPI* OriginalGetDiskFreeSpaceA)(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_opt_ LPDWORD lpSectorsPerCluster,
	_Out_opt_ LPDWORD lpBytesPerSector,
	_Out_opt_ LPDWORD lpNumberOfFreeClusters,
	_Out_opt_ LPDWORD lpTotalNumberOfClusters
) = GetDiskFreeSpaceA;

static BOOL (WINAPI* OriginalGetDiskFreeSpaceExA)(
	_In_opt_ LPCSTR lpDirectoryName,
	_Out_opt_ PULARGE_INTEGER lpFreeBytesAvailableToCaller,
	_Out_opt_ PULARGE_INTEGER lpTotalNumberOfBytes,
	_Out_opt_ PULARGE_INTEGER lpTotalNumberOfFreeBytes
) = GetDiskFreeSpaceExA;

static DWORD (WINAPI* OriginalGetLogicalDrives)(VOID) = GetLogicalDrives;

static DWORD (WINAPI* OriginalGetLogicalDriveStringsA)(
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer
) = GetLogicalDriveStringsA;

static BOOL (WINAPI* OriginalReadFile)(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
) = ReadFile;

static BOOL (WINAPI* OriginalWriteFile)(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
) = WriteFile;

static BOOL (WINAPI* OriginalSetEndOfFile)(
	_In_ HANDLE hFile
) = SetEndOfFile;

static DWORD (WINAPI* OriginalGetFileSize)(
	_In_ HANDLE hFile,
	_Out_opt_ LPDWORD lpFileSizeHigh
) = GetFileSize;

static BOOL (WINAPI* OriginalGetFileSizeEx)(
	_In_ HANDLE hFile,
	_Out_ PLARGE_INTEGER lpFileSize
) = GetFileSizeEx;

static DWORD (WINAPI* OriginalSetFilePointer)(
	_In_ HANDLE hFile,
	_In_ LONG lDistanceToMove,
	_Inout_opt_ PLONG lpDistanceToMoveHigh,
	_In_ DWORD dwMoveMethod
) = SetFilePointer;

static BOOL (WINAPI* OriginalSetFilePointerEx)(
	_In_ HANDLE hFile,
	_In_ LARGE_INTEGER liDistanceToMove,
	_Out_opt_ PLARGE_INTEGER lpNewFilePointer,
	_In_ DWORD dwMoveMethod
) = SetFilePointerEx;

static BOOL (WINAPI* OriginalCreateHardLinkA)(
	_In_ LPCSTR lpFileName,
	_In_ LPCSTR lpExistingFileName,
	_Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
) = CreateHardLinkA;

static BOOLEAN (WINAPI* OriginalCreateSymbolicLinkA)(
	_In_ LPCSTR lpSymlinkFileName,
	_In_ LPCSTR lpTargetFileName,
	_In_ DWORD dwFlags
) = CreateSymbolicLinkA;

static LSTATUS (WINAPI* OriginalRegOpenKeyExA)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpSubKey,
	_In_opt_ DWORD ulOptions,
	_In_ REGSAM samDesired,
	_Out_ PHKEY phkResult
) = RegOpenKeyExA;

static LSTATUS (WINAPI* OriginalRegCreateKeyExA)(
	_In_ HKEY hKey,
	_In_ LPCSTR lpSubKey,
	_Reserved_ DWORD Reserved,
	_In_opt_ LPSTR lpClass,
	_In_ DWORD dwOptions,
	_In_ REGSAM samDesired,
	_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_ PHKEY phkResult,
	_Out_opt_ LPDWORD lpdwDisposition
) = RegCreateKeyExA;

static LSTATUS (WINAPI* OriginalRegQueryValueExA)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ LPDWORD lpReserved,
	_Out_opt_ LPDWORD lpType,
	_Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) LPBYTE lpData,
	_Inout_opt_ LPDWORD lpcbData
) = RegQueryValueExA;

static LSTATUS (WINAPI* OriginalRegSetValueExA)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ DWORD Reserved,
	_In_ DWORD dwType,
	_In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
	_In_ DWORD cbData
) = RegSetValueExA;

static HMODULE (WINAPI* OriginalLoadLibraryExA)(
	_In_ LPCSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
) = LoadLibraryExA;

static HMODULE (WINAPI* OriginalGetModuleHandleA)(
	_In_opt_ LPCSTR lpModuleName
) = GetModuleHandleA;

static BOOL (WINAPI* OriginalGetModuleHandleExA)(
	_In_ DWORD dwFlags,
	_In_opt_ LPCSTR lpModuleName,
	_Out_ HMODULE* phModule
) = GetModuleHandleExA;

static LPSTR (WINAPI* OriginalGetCommandLineA)(VOID) = GetCommandLineA;

static VOID (WINAPI* OriginalGetStartupInfoA)(
	_Out_ LPSTARTUPINFOA lpStartupInfo
) = GetStartupInfoA;

static DWORD (WINAPI* OriginalGetEnvironmentVariableA)(
	_In_opt_ LPCSTR lpName,
	_Out_writes_to_opt_(nSize, return + 1) LPSTR lpBuffer,
	_In_ DWORD nSize
) = GetEnvironmentVariableA;

static BOOL (WINAPI* OriginalSetEnvironmentVariableA)(
	_In_opt_ LPCSTR lpName,
	_In_opt_ LPCSTR lpValue
) = SetEnvironmentVariableA;

static DWORD (WINAPI* OriginalExpandEnvironmentStringsA)(
	_In_ LPCSTR lpSrc,
	_Out_writes_to_opt_(nSize, return) LPSTR lpDst,
	_In_ DWORD nSize
) = ExpandEnvironmentStringsA;

static int(WINAPI* OriginalEnumFontsA)(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam
) = EnumFontsA;

static int(WINAPI* OriginalEnumFontFamiliesA)(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam
) = EnumFontFamiliesA;