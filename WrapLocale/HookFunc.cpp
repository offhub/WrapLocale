#include <windows.h>

#include "MinHook\include\MinHook.h"
#include "MINT.h"

#include "OriginalFunc.h"
#include "HookFunc.h"
#include "User32Hook.h"

#ifdef ENABLE_HIDING
#include "HideProcessInformation.h"
#endif

// MAIN API HOOKS

#ifdef _DEBUG
#define DEBUG_FUNCTION_TRACE() \
    OutputDebugStringA(__FUNCTION__)
#else
#define DEBUG_FUNCTION_TRACE() 
#endif

LPWSTR ConvertEnvironmentBlockToUnicode(LPCSTR lpEnvA, UINT codePage)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpEnvA) return NULL;

	// Calculate length of environment block (double null terminated)
	LPCSTR p = lpEnvA;
	SIZE_T len = 0;
	while (*p) {
		SIZE_T entryLen = strlen(p) + 1;
		len += entryLen;
		p += entryLen;
	}
	len++; // include final null

	// Convert whole block
	int wlen = MultiByteToWideChar(codePage, 0, lpEnvA, (int)len, NULL, 0);
	if (wlen <= 0) return NULL;

	LPWSTR lpEnvW = (LPWSTR)AllocateZeroedMemory(wlen * sizeof(WCHAR));
	if (!lpEnvW) return NULL;

	if (!MultiByteToWideChar(codePage, 0, lpEnvA, (int)len, lpEnvW, wlen)) {
		FreeStringInternal(lpEnvW);
		return NULL;
	}

	return lpEnvW;
}

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
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpStartupInfo || !lpProcessInformation) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR wApplicationName = NULL;
	LPWSTR wCommandLine = NULL;
	LPWSTR wCurrentDirectory = NULL;
	LPWSTR wEnvironment = NULL;

	if (lpApplicationName)
		wApplicationName = MultiByteToWideCharInternal(lpApplicationName, settings.CodePage);

	if (lpCommandLine)
		wCommandLine = MultiByteToWideCharInternal(lpCommandLine, settings.CodePage);

	if (lpCurrentDirectory)
		wCurrentDirectory = MultiByteToWideCharInternal(lpCurrentDirectory, settings.CodePage);

	/*if (lpEnvironment) {
		// Convert environment block from ANSI to Unicode
		wEnvironment = ConvertEnvironmentBlockToUnicode((LPCSTR)lpEnvironment, settings.CodePage);
		if (!wEnvironment) {
			FreeStringInternal(wApplicationName);
			FreeStringInternal(wCommandLine);
			FreeStringInternal(wCurrentDirectory);
			SetLastError(ERROR_OUTOFMEMORY);
			return FALSE;
		}
	}*/

	STARTUPINFOW siW = { 0 };
	siW.cb = sizeof(STARTUPINFOW);
	siW.dwFlags = lpStartupInfo->dwFlags;
	siW.wShowWindow = lpStartupInfo->wShowWindow;
	siW.dwX = lpStartupInfo->dwX;
	siW.dwY = lpStartupInfo->dwY;
	siW.dwXSize = lpStartupInfo->dwXSize;
	siW.dwYSize = lpStartupInfo->dwYSize;
	siW.dwXCountChars = lpStartupInfo->dwXCountChars;
	siW.dwYCountChars = lpStartupInfo->dwYCountChars;
	siW.dwFillAttribute = lpStartupInfo->dwFillAttribute;
	siW.hStdInput = lpStartupInfo->hStdInput;
	siW.hStdOutput = lpStartupInfo->hStdOutput;
	siW.hStdError = lpStartupInfo->hStdError;
	siW.cbReserved2 = lpStartupInfo->cbReserved2;
	siW.lpReserved2 = lpStartupInfo->lpReserved2;

	if (lpStartupInfo->lpDesktop)
		siW.lpDesktop = MultiByteToWideCharInternal(lpStartupInfo->lpDesktop, settings.CodePage);

	if (lpStartupInfo->lpTitle)
		siW.lpTitle = MultiByteToWideCharInternal(lpStartupInfo->lpTitle, settings.CodePage);

	BOOL result = OriginalCreateProcessW(
		wApplicationName,
		wCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		/*wEnvironment ? (LPVOID)wEnvironment :*/ lpEnvironment,
		wCurrentDirectory,
		&siW,
		lpProcessInformation
	);

	FreeStringInternal(wApplicationName);
	FreeStringInternal(wCommandLine);
	FreeStringInternal(wCurrentDirectory);
	FreeStringInternal(wEnvironment);
	FreeStringInternal(siW.lpDesktop);
	FreeStringInternal(siW.lpTitle);

	return result;
}

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
)
{
	DEBUG_FUNCTION_TRACE();
	// Convert class name to Unicode if it's not NULL and not an atom
	LPCWSTR wstrlpClassName = NULL;
	LPCWSTR wstrlpWindowName = NULL;
	BOOL freeClassName = FALSE;
	BOOL freeWindowName = FALSE;

	// Convert class name if not an atom
	if (lpClassName && !IS_INTRESOURCE(lpClassName)) {
		wstrlpClassName = MultiByteToWideCharInternal(lpClassName, settings.CodePage);
		if (!wstrlpClassName) {
			return OriginalCreateWindowExA(
				dwExStyle, lpClassName, lpWindowName, dwStyle,
				X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam
			);
		}
		freeClassName = TRUE;
	}
	else
		wstrlpClassName = (LPCWSTR)lpClassName; // Atom or NULL

	if (lpWindowName) {
		wstrlpWindowName = MultiByteToWideCharInternal(lpWindowName, settings.CodePage);
		if (!wstrlpWindowName) {
			if (freeClassName)
				FreeStringInternal((LPWSTR)wstrlpClassName);

			return OriginalCreateWindowExA(
				dwExStyle, lpClassName, lpWindowName, dwStyle,
				X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam
			);
		}
		freeWindowName = TRUE;
	}

	HWND ret = CreateWindowExW(
		dwExStyle,
		wstrlpClassName,
		wstrlpWindowName,
		dwStyle,
		X, Y, nWidth, nHeight,
		hWndParent, hMenu, hInstance, lpParam
	);

	if (freeClassName)
		FreeStringInternal((LPWSTR)wstrlpClassName);
	if (freeWindowName)
		FreeStringInternal((LPWSTR)wstrlpWindowName);

	return ret;
}

int WINAPI HookMessageBoxA(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType)
{
	DEBUG_FUNCTION_TRACE();
	// Convert text to Unicode
	LPCWSTR wlpText = lpText ? MultiByteToWideCharInternal(lpText, settings.CodePage) : NULL;
	if (lpText && !wlpText)
		return OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);

	// Convert caption to Unicode
	LPCWSTR wlpCaption = lpCaption ? MultiByteToWideCharInternal(lpCaption, settings.CodePage) : NULL;
	if (lpCaption && !wlpCaption) {
		FreeStringInternal((LPWSTR)wlpText);
		return OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
	}

	int ret = MessageBoxW(hWnd, wlpText, wlpCaption, uType);

	FreeStringInternal((LPWSTR)wlpText);
	FreeStringInternal((LPWSTR)wlpCaption);

	return ret;
}

UINT WINAPI HookGetACP(void)
{
	//DEBUG_FUNCTION_TRACE();
	return settings.CodePage;
}

UINT WINAPI HookGetOEMCP(void)
{
	//DEBUG_FUNCTION_TRACE();
	return settings.CodePage;
}

BOOL WINAPI HookGetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
{
	//DEBUG_FUNCTION_TRACE();
	if (!lpCPInfo)
		return FALSE;

	// If the application is asking for the system code page or the 
	// code page we're pretending to be, give it our settings code page
	if (CodePage == CP_ACP || CodePage == GetACP() || CodePage == settings.CodePage)
		return OriginalGetCPInfo(settings.CodePage, lpCPInfo);

	return OriginalGetCPInfo(CodePage, lpCPInfo);
}

LRESULT WINAPI HookSendMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//DEBUG_FUNCTION_TRACE();
	// Handle window creation messages
	switch (uMsg)
	{
		case WM_CREATE:
		case WM_NCCREATE:
			return ANSI_INLPCREATESTRUCT(hWnd, uMsg, wParam, lParam);
		case WM_MDICREATE:
			return ANSI_INLPMDICREATESTRUCT(hWnd, uMsg, wParam, lParam);
		case WM_SETTEXT:
		case WM_SETTINGCHANGE:
		case EM_REPLACESEL:
		case WM_DEVMODECHANGE:
		case CB_DIR:
		case LB_DIR:
		case LB_ADDFILE:
		case CB_ADDSTRING:
		case CB_INSERTSTRING:
		case CB_FINDSTRING:
		case CB_SELECTSTRING:
		case CB_FINDSTRINGEXACT:
		case LB_ADDSTRING:
		case LB_INSERTSTRING:
		case LB_SELECTSTRING:
		case LB_FINDSTRING:
		case LB_FINDSTRINGEXACT:
		// Additional string input messages
		//case EM_SETWORDBREAKPROC:
		//case LB_SETTABSTOPS:
			return ANSI_INSTRING(hWnd, uMsg, wParam, lParam);
		// Handle messages that retrieve text from a list
		case CB_GETLBTEXT:
		case LB_GETTEXT:
			return ANSI_GETTEXT(hWnd, uMsg, wParam, lParam);
		// Handle messages that get text length
		case WM_GETTEXTLENGTH: // LN327
		case CB_GETLBTEXTLEN:
		case LB_GETTEXTLEN:
			return ANSI_GETTEXTLENGTH(hWnd, uMsg, wParam, lParam);
		// Handle messages that output strings
		case WM_GETTEXT:
		case WM_ASKCBFORMATNAME:
			return ANSI_OUTSTRING(hWnd, uMsg, wParam, lParam);
		// Handle edit control line retrieval
		case EM_GETLINE:
			return ANSI_GETLINE(hWnd, uMsg, wParam, lParam);
		// For all other messages, pass through to the original function
		default:
			return OriginalSendMessageA(hWnd, uMsg, wParam, lParam);
	}
}

//CodePage == CP_ACP || CodePage == CP_OEMCP ||

#define CODEPAGE_IS_ANY_NOT_UTF CodePage >= 0 && CodePage < CP_UTF7

int WINAPI HookMultiByteToWideChar(UINT CodePage, DWORD dwFlags,
	LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
{
	//DEBUG_FUNCTION_TRACE();
	// CP_ACP (0) is the default ANSI code page
	// CP_OEMCP (1) is the default OEM code page
	// Replace only standard Windows code pages with our settings code page
	if (CODEPAGE_IS_ANY_NOT_UTF)
		CodePage = settings.CodePage;

	return OriginalMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

int WINAPI HookWideCharToMultiByte(UINT CodePage, DWORD dwFlags,
	LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
	//DEBUG_FUNCTION_TRACE();
	if (CODEPAGE_IS_ANY_NOT_UTF) {
		CodePage = settings.CodePage;

		// If code page changed and default character handling is specified,
		// we might need to use our custom default character
		//if (originalCodePage != CodePage && lpDefaultChar != NULL && settings.UseCustomDefaultChar) {
			//lpDefaultChar = &settings.DefaultChar;
		//}
	}
	return OriginalWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

UINT WINAPI HookWinExec(
	_In_ LPSTR lpCmdLine,
	_In_ UINT uCmdShow
)
{
	DEBUG_FUNCTION_TRACE();
	// Prepare startup info with the provided show command
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFOA));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = (WORD)uCmdShow;

	// Attempt to create the process
	BOOL ret = HookCreateProcessA(
		NULL,		   // No application name
		lpCmdLine,	  // Command line
		NULL,		   // Process security attributes
		NULL,		   // Thread security attributes
		FALSE,		  // Don't inherit handles
		CREATE_DEFAULT_ERROR_MODE,  // Creation flags
		NULL,		   // Use parent's environment
		NULL,		   // Use parent's current directory
		&si,			// Startup info
		&pi			 // Process information
	);

	// Handle the result properly
	UINT result;
	if (ret == TRUE) {
		// Process created successfully
		result = 32; // SUCCESS value for WinExec (>31 means success)

		// Wait for process to initialize (optional)
		// WaitForInputIdle(pi.hProcess, 1000);

		// Close process and thread handles to prevent leaks
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	} else {
		// Process creation failed, get the specific error
		DWORD error = GetLastError();

		// Map Windows error codes to WinExec error codes
		switch (error) {
			case ERROR_BAD_FORMAT:
				result = 11; // ERROR_BAD_FORMAT
				break;
			case ERROR_FILE_NOT_FOUND:
				result = 2;  // FILE_NOT_FOUND
				break;
			case ERROR_PATH_NOT_FOUND:
				result = 3;  // PATH_NOT_FOUND
				break;
			case ERROR_ACCESS_DENIED:
				result = 5;  // ACCESS_DENIED
				break;
			case ERROR_NOT_ENOUGH_MEMORY:
				result = 8;  // OUT_OF_MEMORY
				break;
			default:
				result = 0;  // UNKNOWN_ERROR
		}
	}

	return result;
}

HINSTANCE WINAPI HookShellExecuteA(
	_In_opt_ HWND hwnd,
	_In_opt_ LPSTR lpOperation,
	_In_ LPSTR lpFile,
	_In_opt_ LPSTR lpParameters,
	_In_opt_ LPSTR lpDirectory,
	_In_ INT nShowCmd
)
{
	DEBUG_FUNCTION_TRACE();
	// Validate input parameters
	if (!lpFile || !*lpFile) {
		return (HINSTANCE)SE_ERR_FNF; // File not found error
	}

	// Prepare startup info with the provided show command
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFOA));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = (WORD)nShowCmd;

	// Build command line: "file" + " " + parameters
	char cmdLine[MAX_PATH * 2] = {0};

	// Add quotes around the file path if it contains spaces
	if (strchr(lpFile, ' ') != NULL)
		sprintf_s(cmdLine, sizeof(cmdLine), "\"%s\"", lpFile);
	else
		strcpy_s(cmdLine, sizeof(cmdLine), lpFile);

	// Append parameters if provided
	if (lpParameters && *lpParameters) {
		strcat_s(cmdLine, sizeof(cmdLine), " ");
		strcat_s(cmdLine, sizeof(cmdLine), lpParameters);
	}

	// Create process using standard CreateProcessA
	// The environment will handle DLL injection automatically
	BOOL ret = HookCreateProcessA(
		NULL,		   // No application name (use command line)
		cmdLine,		// Command line
		NULL,		   // Process security attributes
		NULL,		   // Thread security attributes
		FALSE,		  // Don't inherit handles
		CREATE_DEFAULT_ERROR_MODE,  // Creation flags
		NULL,		   // Use parent's environment
		lpDirectory,	// Working directory
		&si,			// Startup info
		&pi			 // Process information
	);

	// Handle the result properly
	HINSTANCE result;
	if (ret) {
		// Process created successfully

		// Return process handle as HINSTANCE > 32
		result = (HINSTANCE)pi.hProcess;

		// Close thread handle to prevent leak
		CloseHandle(pi.hThread);
	} else {
		// Process creation failed, get the specific error
		DWORD error = GetLastError();

		// Map Windows error codes to ShellExecute error codes
		switch (error) {
			case ERROR_FILE_NOT_FOUND:
				result = (HINSTANCE)SE_ERR_FNF;  // File not found
				break;
			case ERROR_PATH_NOT_FOUND:
				result = (HINSTANCE)SE_ERR_PNF;  // Path not found
				break;
			case ERROR_ACCESS_DENIED:
				result = (HINSTANCE)SE_ERR_ACCESSDENIED;  // Access denied
				break;
			case ERROR_NOT_ENOUGH_MEMORY:
				result = (HINSTANCE)SE_ERR_OOM;  // Out of memory
				break;
			case ERROR_SHARING_VIOLATION:
				result = (HINSTANCE)SE_ERR_SHARE;  // Sharing violation
				break;
			default:
				result = (HINSTANCE)SE_ERR_NOASSOC;  // No association
				break;
		}
	}

	return result;
}

HINSTANCE WINAPI HookShellExecuteW(
	_In_opt_ HWND hwnd,
	_In_opt_ LPWSTR lpOperation,
	_In_ LPWSTR lpFile,
	_In_opt_ LPWSTR lpParameters,
	_In_opt_ LPWSTR lpDirectory,
	_In_ INT nShowCmd
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFile || !*lpFile)
		return (HINSTANCE)SE_ERR_FNF;

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFOW));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = (WORD)nShowCmd;

	// Build command line: "file" + " " + parameters
	WCHAR cmdLine[MAX_PATH * 2] = {0};

	// Add quotes around the file path if it contains spaces
	if (wcschr(lpFile, L' ') != NULL)
		swprintf_s(cmdLine, _countof(cmdLine), L"\"%s\"", lpFile);
	else
		wcscpy_s(cmdLine, _countof(cmdLine), lpFile);

	// Append parameters if provided
	if (lpParameters && *lpParameters) {
		wcscat_s(cmdLine, _countof(cmdLine), L" ");
		wcscat_s(cmdLine, _countof(cmdLine), lpParameters);
	}

	// Create process using standard CreateProcessW
	// Sandboxie will handle the DLL injection
	BOOL ret = CreateProcessW(
		NULL,		   // No application name (use command line)
		cmdLine,		// Command line
		NULL,		   // Process security attributes
		NULL,		   // Thread security attributes
		FALSE,		  // Don't inherit handles
		CREATE_DEFAULT_ERROR_MODE,  // Creation flags
		NULL,		   // Use parent's environment
		lpDirectory,	// Working directory
		&si,			// Startup info
		&pi			 // Process information
	);

	HINSTANCE result;
	if (ret) {
		// Process created successfully
		// Return process handle as HINSTANCE > 32
		result = (HINSTANCE)pi.hProcess;

		// Close thread handle to prevent leak
		CloseHandle(pi.hThread);
	} else {
		DWORD error = GetLastError();
		switch (error) {
			case ERROR_FILE_NOT_FOUND:
				result = (HINSTANCE)SE_ERR_FNF;  // File not found
				break;
			case ERROR_PATH_NOT_FOUND:
				result = (HINSTANCE)SE_ERR_PNF;  // Path not found
				break;
			case ERROR_ACCESS_DENIED:
				result = (HINSTANCE)SE_ERR_ACCESSDENIED;  // Access denied
				break;
			case ERROR_NOT_ENOUGH_MEMORY:
				result = (HINSTANCE)SE_ERR_OOM;  // Out of memory
				break;
			case ERROR_SHARING_VIOLATION:
				result = (HINSTANCE)SE_ERR_SHARE;  // Sharing violation
				break;
			default:
				result = (HINSTANCE)SE_ERR_NOASSOC;  // No association
				break;
		}
	}
	return result;
}

BOOL WINAPI HookShellExecuteExA(
	_Inout_ SHELLEXECUTEINFOA* pExecInfo
)
{
	DEBUG_FUNCTION_TRACE();
	return OriginalShellExecuteExA(pExecInfo);
}

BOOL WINAPI HookShellExecuteExW(
	_Inout_ SHELLEXECUTEINFOW* pExecInfo
)
{
	DEBUG_FUNCTION_TRACE();
	return OriginalShellExecuteExW(pExecInfo);
}

BOOL WINAPI HookSetWindowTextA(
	_In_ HWND hWnd,
	_In_opt_ LPCSTR lpString
)
{
	//DEBUG_FUNCTION_TRACE();

	// Option 2: Convert text
	/*
	LPCWSTR wstr = lpString ? MultiByteToWideCharInternal(lpString, settings.CodePage) : NULL;
	BOOL ret = FALSE;
	if (lpString == NULL || wstr != NULL)
		ret = SetWindowTextW(hWnd, wstr);
	else
		ret = OriginalSetWindowTextA(hWnd, lpString);

	if (wstr)
		FreeStringInternal((LPWSTR)wstr);

	return ret;
	*/

	// Option 2: Use modded SendMessageA
	return OriginalSendMessageA(hWnd, WM_SETTEXT, 0, (LPARAM)lpString);
}

int WINAPI HookGetWindowTextA(
	_In_ HWND hWnd, 
	_Out_writes_(nMaxCount) LPSTR lpString, 
	_In_ int nMaxCount
)
{
	//DEBUG_FUNCTION_TRACE();

	if (!lpString || nMaxCount <= 0)
		return 0;

	// Option 1: convert text
	int wlen = GetWindowTextLengthW(hWnd);
	if (wlen <= 0) { // No text or error
		if (nMaxCount > 0) lpString[0] = '\0';
		return 0;
	}

	LPWSTR lpStringW = (LPWSTR)AllocateZeroedMemory((wlen + 1) * sizeof(WCHAR));
	if (!lpStringW) {
		if (nMaxCount > 0) lpString[0] = '\0';
		return 0;
	}

	int wsize = GetWindowTextW(hWnd, lpStringW, wlen + 1);
	int lsize = 0;
	if (wsize > 0) {
		lsize = WideCharToMultiByte(
			settings.CodePage,  // Use our settings code page
			0,				  // No flags
			lpStringW,		  // Unicode string
			wsize,			  // Unicode string length
			lpString,		   // Output ANSI buffer
			nMaxCount,		  // Size of ANSI buffer
			NULL,			   // Default char
			NULL				// Used default char
		);
		if (lsize > 0 && lsize < nMaxCount) 
			lpString[lsize] = '\0';
		else if (nMaxCount > 0) 
			lpString[nMaxCount - 1] = '\0';
	} else {
		// No text or error
		if (nMaxCount > 0)
			lpString[0] = '\0';
	}

	FreeStringInternal(lpStringW);

	return lsize;

	// Option 2: use SendMessageA
	// return SendMessageA(hWnd, WM_GETTEXT, nMaxCount, (LPARAM)lpString);
}

LONG WINAPI HookImmGetCompositionStringA(
	HIMC hIMC, 
	DWORD dwIndex,
	LPSTR lpBuf,
	DWORD dwBufLen
)
{
	DEBUG_FUNCTION_TRACE();
	// Call original function to get composition string
	LONG ret = OriginalImmGetCompositionStringA(hIMC, dwIndex, lpBuf, dwBufLen);

	// Only process if we got data and have a buffer
	if (ret > 0 && lpBuf && dwBufLen > 0) {
		// Ensure the string is null-terminated for conversion
		if (ret < (LONG)dwBufLen) {
			lpBuf[ret] = '\0';
		} else {
			// Buffer is full, create a temporary null-terminated copy
			LPSTR tempBuf = (LPSTR)AllocateZeroedMemory(ret + 1);
			if (!tempBuf)
				return ret;

			memcpy(tempBuf, lpBuf, ret);
			tempBuf[ret] = '\0';
			LPWSTR wstr = MultiByteToWideCharInternal(tempBuf, Initial.CodePage);
			FreeStringInternal(tempBuf);

			if (wstr) {
				// Convert back to multibyte using settings code page
				int wsize = lstrlenW(wstr);
				int requiredSize = WideCharToMultiByte(
					settings.CodePage, 0, wstr, wsize, NULL, 0, NULL, NULL);

				// Only proceed if we can fit the result
				if (requiredSize > 0 && requiredSize <= (LONG)dwBufLen) {
					int convertedSize = WideCharToMultiByte(
						settings.CodePage, 0, wstr, wsize, 
						lpBuf, dwBufLen, NULL, NULL);

					if (convertedSize > 0) {
						// Update return value to reflect new size
						ret = convertedSize;

						if (convertedSize < (LONG)dwBufLen)
							lpBuf[convertedSize] = '\0';
					}
				}
				FreeStringInternal(wstr);
			}

			return ret;
		}

		// Convert to Unicode using original code page
		LPWSTR wstr = MultiByteToWideCharInternal(lpBuf, Initial.CodePage);
		if (wstr) {
			int wsize = lstrlenW(wstr);

			// Get required buffer size
			int requiredSize = WideCharToMultiByte(
				settings.CodePage, 0, wstr, wsize, NULL, 0, NULL, NULL);

			// Only proceed if we can fit the result
			if (requiredSize > 0 && requiredSize <= (LONG)dwBufLen) {
				int convertedSize = WideCharToMultiByte(
					settings.CodePage, 0, wstr, wsize, 
					lpBuf, dwBufLen, NULL, NULL);

				if (convertedSize > 0) {
					// Update return value to reflect new size
					ret = convertedSize;

					if (convertedSize < (LONG)dwBufLen)
						lpBuf[convertedSize] = '\0';
				}
			}


			FreeStringInternal(wstr);
		}
	}

	return ret;
}

LONG WINAPI HookImmGetCompositionStringA_WM(
	HIMC  hIMC,
	DWORD dwIndex,
	LPSTR lpBuf,
	DWORD dwBufLen
)
{
	DEBUG_FUNCTION_TRACE();
	// Get the size of Unicode composition string (in bytes)
	LONG wsize = ImmGetCompositionStringW(hIMC, dwIndex, NULL, 0);
	if (wsize <= 0)
		return wsize;

	LPWSTR wstr = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wsize + sizeof(WCHAR)); // +2 for null terminator
	if (!wstr)
		return -1;

	// Get the Unicode composition string
	LONG result = ImmGetCompositionStringW(hIMC, dwIndex, wstr, wsize);
	if (result < 0) {
		FreeStringInternal(wstr);
		return result; // Return the error code
	}

	// wsize is in bytes
	int wchars = wsize / sizeof(WCHAR);
	wstr[wchars] = L'\0';

	LONG requiredSize = WideCharToMultiByte(
		settings.CodePage, 
		0, 
		wstr, 
		wchars, 
		NULL, 
		0, 
		Initial.lpDefaultChar, 
		&Initial.lpUsedDefaultChar
	);

	if (!lpBuf || dwBufLen == 0) {
		FreeStringInternal(wstr);
		return requiredSize;
	}

	LONG lsize = WideCharToMultiByte(
		settings.CodePage, 
		0, 
		wstr, 
		wchars, 
		lpBuf, 
		dwBufLen, 
		Initial.lpDefaultChar, 
		&Initial.lpUsedDefaultChar
	);

	FreeStringInternal(wstr);

	if (lsize <= 0)
		return -1;


	if ((DWORD)lsize < dwBufLen)
		lpBuf[lsize] = '\0'; // make tail ! 

	return lsize;
}

DWORD WINAPI HookImmGetCandidateListA(
	HIMC			hIMC,
	DWORD		   deIndex,
	LPCANDIDATELIST lpCandList,
	DWORD		   dwBufLen
)
{
	DEBUG_FUNCTION_TRACE();
	// Get the original candidate list
	DWORD ret = OriginalImmGetCandidateListA(hIMC, deIndex, lpCandList, dwBufLen);

	// If we got data and have a buffer, process it
	if (ret > 0 && lpCandList && dwBufLen >= sizeof(CANDIDATELIST)) {
		// Calculate how much space we have for strings
		DWORD availableSpace = dwBufLen - sizeof(CANDIDATELIST);

		// Process each candidate string
		for (DWORD i = 0; i < lpCandList->dwCount; i++) {
			// Get pointer to the current string
			LPSTR lstr = (LPSTR)lpCandList + lpCandList->dwOffset[i];

			// Calculate remaining space after this string
			DWORD stringOffset = lpCandList->dwOffset[i];
			if (stringOffset >= dwBufLen) {
				break; // Invalid offset, stop processing
			}

			// Calculate maximum string length we can safely modify
			DWORD maxStringLen = 0;

			// If this is the last string, space extends to end of buffer
			if (i == lpCandList->dwCount - 1) {
				maxStringLen = dwBufLen - stringOffset;
			} else {
				// Otherwise, space extends to the next string
				if (lpCandList->dwOffset[i+1] > stringOffset && 
					lpCandList->dwOffset[i+1] <= dwBufLen) {
					maxStringLen = lpCandList->dwOffset[i+1] - stringOffset;
				} else {
					break; // Invalid offset, stop processing
				}
			}

			// Get the length of the current string
			size_t currentLen = strlen(lstr);

			// Only process if we have a valid string
			if (currentLen > 0 && currentLen < maxStringLen) {
				// Convert to Unicode using original code page
				LPWSTR wstr = MultiByteToWideCharInternal(lstr, Initial.CodePage);
				if (wstr) {
					int wlen = lstrlenW(wstr);

					// Calculate required buffer size for converted string
					int requiredSize = WideCharToMultiByte(
						settings.CodePage, 0, wstr, wlen, NULL, 0, NULL, NULL);

					// Only convert if it will fit in the available space
					if (requiredSize > 0 && requiredSize < (int)maxStringLen) {
						// Convert back to multibyte using settings code page
						int convertedSize = WideCharToMultiByte(
							settings.CodePage, 0, wstr, wlen, 
							lstr, maxStringLen - 1, NULL, NULL);


						if (convertedSize > 0)
							lstr[convertedSize] = '\0';
					}


					FreeStringInternal(wstr);
				}
			}
		}
	}
	return ret;
}

DWORD WINAPI HookImmGetCandidateListA_WM(
	HIMC            hIMC,
	DWORD           deIndex,
	LPCANDIDATELIST lpCandList,
	DWORD           dwBufLen
)
{
	DEBUG_FUNCTION_TRACE();
	// Check if we're just querying the required size
	if (!lpCandList || dwBufLen == 0) {
		// Get the size required for the Unicode candidate list
		DWORD dwBufLenW = ImmGetCandidateListW(hIMC, deIndex, NULL, 0);
		if (dwBufLenW == 0) // If Unicode method fails, fall back to original function
			return OriginalImmGetCandidateListA(hIMC, deIndex, NULL, 0);

		// Estimate the size required for ANSI candidate list
		// This is an approximation - actual size depends on string content
		// We multiply by 2 to ensure enough space for DBCS characters
		return dwBufLenW * 2;
	}

	// Get the Unicode candidate list size
	DWORD dwBufLenW = ImmGetCandidateListW(hIMC, deIndex, NULL, 0);
	if (dwBufLenW == 0)
		return OriginalImmGetCandidateListA(hIMC, deIndex, lpCandList, dwBufLen);

	LPCANDIDATELIST lpCandListW = (LPCANDIDATELIST)AllocateZeroedMemory(dwBufLenW);

	if (!lpCandListW) 
		return OriginalImmGetCandidateListA(hIMC, deIndex, lpCandList, dwBufLen);

	// Get the Unicode candidate list
	DWORD retW = ImmGetCandidateListW(hIMC, deIndex, lpCandListW, dwBufLenW);
	if (retW == 0) { // Failed to get Unicode list, clean up and fall back
		FreeStringInternal((LPVOID)lpCandListW);
		return OriginalImmGetCandidateListA(hIMC, deIndex, lpCandList, dwBufLen);
	}

	// Copy the structure header
	lpCandList->dwSize = sizeof(CANDIDATELIST);
	lpCandList->dwStyle = lpCandListW->dwStyle;
	lpCandList->dwCount = lpCandListW->dwCount;
	lpCandList->dwSelection = lpCandListW->dwSelection;
	lpCandList->dwPageStart = lpCandListW->dwPageStart;
	lpCandList->dwPageSize = lpCandListW->dwPageSize;

	// Calculate available space for strings
	DWORD headerSize = sizeof(CANDIDATELIST);
	DWORD availableSpace = (dwBufLen > headerSize) ? (dwBufLen - headerSize) : 0;
	DWORD currentOffset = headerSize;

	// Process each candidate string
	for (DWORD i = 0; i < lpCandListW->dwCount && i < 64; i++) { // Limit to 64 for safety
		// Set the offset for this string
		lpCandList->dwOffset[i] = currentOffset;

		// Get pointer to the Unicode string
		LPWSTR wstr = (LPWSTR)((BYTE*)lpCandListW + lpCandListW->dwOffset[i]);

		// Get pointer to where we'll write the ANSI string
		LPSTR lstr = (LPSTR)((BYTE*)lpCandList + currentOffset);

		DWORD remainingSpace = (currentOffset < dwBufLen) ? (dwBufLen - currentOffset) : 0;

		if (remainingSpace > 0) {
			// Convert to ANSI with our settings code page
			int wlen = lstrlenW(wstr);
			int convertedSize = WideCharToMultiByte(
				settings.CodePage, 0, wstr, wlen, 
				lstr, remainingSpace - 1, NULL, NULL);


			if (convertedSize > 0 && convertedSize < (int)remainingSpace) {
				lstr[convertedSize] = '\0';
				// Update offset for next string
				currentOffset += convertedSize + 1;
			} else {
				// Not enough space, mark end of list
				lpCandList->dwCount = i;
				break;
			}
		} else {
			// Out of space, mark end of list
			lpCandList->dwCount = i;
			break;
		}
	}

	// Update the structure size
	lpCandList->dwSize = currentOffset;

	FreeStringInternal((LPVOID)lpCandListW);

	return currentOffset; // Return the actual size used
}

#define IS_REPLACEABLE_CHARSET(name)\
	name == ANSI_CHARSET || \
	name == DEFAULT_CHARSET || \
	name == Initial.Charset 

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
)
{
	DEBUG_FUNCTION_TRACE();
	// Convert face name to Unicode if not NULL
	LPWSTR pszFaceNameW = NULL;
	if (pszFaceName) {
		pszFaceNameW = MultiByteToWideCharInternal(pszFaceName, settings.CodePage);
		if (!pszFaceNameW) {
			// Conversion failed, fall back to original function
			return OriginalCreateFontA(
				cHeight, cWidth, cEscapement, cOrientation,
				cWeight, bItalic, bUnderline, bStrikeOut,
				iCharSet, iOutPrecision, iClipPrecision,
				iQuality, iPitchAndFamily, pszFaceName
			);
		}
	}

	// Adjust character set based on code page if needed
	DWORD adjustedCharSet = iCharSet;
	if (IS_REPLACEABLE_CHARSET(iCharSet)) {
		// Map code page to charset
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, adjustedCharSet)
	}

	// Create font with Unicode name and adjusted charset
	HFONT ret = HookCreateFontW(
		cHeight, cWidth, cEscapement, cOrientation,
		cWeight, bItalic, bUnderline, bStrikeOut,
		adjustedCharSet, iOutPrecision, iClipPrecision,
		iQuality, iPitchAndFamily, pszFaceNameW
	);

	FreeStringInternal(pszFaceNameW);

	return ret;
}

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
)
{
	DEBUG_FUNCTION_TRACE();
	DWORD adjustedCharSet = iCharSet;

	if (IS_REPLACEABLE_CHARSET(iCharSet)) {
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, adjustedCharSet)
	}

	// If settings specify a custom font substitution, replace face name
	LPCWSTR adjustedFaceName = pszFaceName;
	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		bool applySubstitution = false;

		if (!pszFaceName || pszFaceName[0] == L'\0')
			applySubstitution = true;
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName : settings.FontsToSubstitute) {
				if (wcscmp(pszFaceName, fontName.c_str()) == 0) {
					applySubstitution = true;
					break;
				}
			}
		}

		if (applySubstitution)
			adjustedFaceName = settings.SubstituteFontName;
	}

	return OriginalCreateFontW(
		cHeight,
		cWidth,
		cEscapement,
		cOrientation,
		cWeight,
		bItalic,
		bUnderline,
		bStrikeOut,
		adjustedCharSet,
		iOutPrecision,
		iClipPrecision,
		iQuality,
		iPitchAndFamily,
		adjustedFaceName
	);
}

HFONT WINAPI HookCreateFontIndirectA(
	LOGFONTA* lplf
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lplf)
		return NULL;

	LOGFONTW logfontW;
	ZeroMemory(&logfontW, sizeof(LOGFONTW));

	logfontW.lfHeight = lplf->lfHeight;
	logfontW.lfWidth = lplf->lfWidth;
	logfontW.lfEscapement = lplf->lfEscapement;
	logfontW.lfOrientation = lplf->lfOrientation;
	logfontW.lfWeight = lplf->lfWeight;
	logfontW.lfItalic = lplf->lfItalic;
	logfontW.lfUnderline = lplf->lfUnderline;
	logfontW.lfStrikeOut = lplf->lfStrikeOut;
	logfontW.lfOutPrecision = lplf->lfOutPrecision;
	logfontW.lfClipPrecision = lplf->lfClipPrecision;
	logfontW.lfQuality = lplf->lfQuality;
	logfontW.lfPitchAndFamily = lplf->lfPitchAndFamily;

	BYTE adjustedCharSet = lplf->lfCharSet;

	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (IS_REPLACEABLE_CHARSET(lplf->lfCharSet)) {
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, adjustedCharSet)
	}

	logfontW.lfCharSet = adjustedCharSet;

	// Convert font face name from ANSI to Unicode using our settings code page
	if (lplf->lfFaceName[0] != '\0') {
		MultiByteToWideChar(
			settings.CodePage, 
			0, 
			lplf->lfFaceName, 
			-1, 
			logfontW.lfFaceName, 
			LF_FACESIZE
		);
	}

	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		bool applySubstitution = false;

		// If original font is empty, substitute
		if (logfontW.lfFaceName[0] == L'\0')
			applySubstitution = true;
		else if (settings.SubstituteAllFonts)
			applySubstitution = true;
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName: settings.FontsToSubstitute) {
				if (wcscmp(logfontW.lfFaceName, fontName.c_str()) == 0) {
					applySubstitution = true;
					break;
				}
			}
		}

		if (applySubstitution) {
			wcsncpy(logfontW.lfFaceName, settings.SubstituteFontName, LF_FACESIZE - 1);
			logfontW.lfFaceName[LF_FACESIZE - 1] = L'\0';
		}
	}

	return CreateFontIndirectW(&logfontW);
}

HFONT WINAPI HookCreateFontIndirectW(
	LOGFONTW* lplf
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lplf)
		return NULL;

	LOGFONTW logfontW = *lplf;

	// Adjust character set based on code page if needed
	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (IS_REPLACEABLE_CHARSET(logfontW.lfCharSet)) {
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, logfontW.lfCharSet)
	}

	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		bool applySubstitution = false;

		// If original font is empty, substitute
		if (logfontW.lfFaceName[0] == L'\0')
			applySubstitution = true;
		else if (settings.SubstituteAllFonts)
			applySubstitution = true;
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName : settings.FontsToSubstitute) {
				if (wcscmp(logfontW.lfFaceName, fontName.c_str()) == 0) {
					applySubstitution = true;
					break;
				}
			}
		}

		if (applySubstitution) {
			DebugLog(L"Substituting font %s->%s", logfontW.lfFaceName, settings.SubstituteFontName);
			wcsncpy(logfontW.lfFaceName, settings.SubstituteFontName, LF_FACESIZE - 1);
			logfontW.lfFaceName[LF_FACESIZE - 1] = L'\0';
		}
	}

	return OriginalCreateFontIndirectW(&logfontW);
}

HFONT WINAPI HookCreateFontIndirectExA(
	ENUMLOGFONTEXDVA* lplf
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lplf)
		return NULL;

	// Initialize the Unicode structure
	ENUMLOGFONTEXDVW lplfW;
	ZeroMemory(&lplfW, sizeof(ENUMLOGFONTEXDVW));

	// Copy numeric values from ANSI structure to Unicode structure
	lplfW.elfEnumLogfontEx.elfLogFont.lfHeight = lplf->elfEnumLogfontEx.elfLogFont.lfHeight;
	lplfW.elfEnumLogfontEx.elfLogFont.lfWidth = lplf->elfEnumLogfontEx.elfLogFont.lfWidth;
	lplfW.elfEnumLogfontEx.elfLogFont.lfEscapement = lplf->elfEnumLogfontEx.elfLogFont.lfEscapement;
	lplfW.elfEnumLogfontEx.elfLogFont.lfOrientation = lplf->elfEnumLogfontEx.elfLogFont.lfOrientation;
	lplfW.elfEnumLogfontEx.elfLogFont.lfWeight = lplf->elfEnumLogfontEx.elfLogFont.lfWeight;
	lplfW.elfEnumLogfontEx.elfLogFont.lfItalic = lplf->elfEnumLogfontEx.elfLogFont.lfItalic;
	lplfW.elfEnumLogfontEx.elfLogFont.lfUnderline = lplf->elfEnumLogfontEx.elfLogFont.lfUnderline;
	lplfW.elfEnumLogfontEx.elfLogFont.lfStrikeOut = lplf->elfEnumLogfontEx.elfLogFont.lfStrikeOut;
	lplfW.elfEnumLogfontEx.elfLogFont.lfOutPrecision = lplf->elfEnumLogfontEx.elfLogFont.lfOutPrecision;
	lplfW.elfEnumLogfontEx.elfLogFont.lfClipPrecision = lplf->elfEnumLogfontEx.elfLogFont.lfClipPrecision;
	lplfW.elfEnumLogfontEx.elfLogFont.lfQuality = lplf->elfEnumLogfontEx.elfLogFont.lfQuality;
	lplfW.elfEnumLogfontEx.elfLogFont.lfPitchAndFamily = lplf->elfEnumLogfontEx.elfLogFont.lfPitchAndFamily;

	// Adjust character set based on code page if needed
	BYTE adjustedCharSet = lplf->elfEnumLogfontEx.elfLogFont.lfCharSet;

	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (IS_REPLACEABLE_CHARSET(lplf->elfEnumLogfontEx.elfLogFont.lfCharSet)) {
		// Map code page to charset
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, adjustedCharSet)
	}

	lplfW.elfEnumLogfontEx.elfLogFont.lfCharSet = adjustedCharSet;

	// Convert font face name
	MultiByteToWideChar(settings.CodePage, 0, 
						lplf->elfEnumLogfontEx.elfLogFont.lfFaceName, -1, 
						lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName, LF_FACESIZE);

	// Apply font substitution if configured
	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		// Check if we should apply substitution
		bool applySubstitution = false;

		// If original font is empty, substitute
		if (lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName[0] == L'\0')
			applySubstitution = true;
		// If we're forcing substitution for all fonts
		else if (settings.SubstituteAllFonts)
			applySubstitution = true;
		// If this font is in our substitution list
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName : settings.FontsToSubstitute) {
				if (wcscmp(lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName, fontName.c_str()) == 0) {
					applySubstitution = true;
					break;
				}
			}
		}

		if (applySubstitution) {
			wcsncpy(lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName, settings.SubstituteFontName, LF_FACESIZE - 1);
			lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName[LF_FACESIZE - 1] = L'\0';
		}
	}

	// Convert additional string fields
	MultiByteToWideChar(settings.CodePage, 0, 
		(LPCCH)lplf->elfEnumLogfontEx.elfFullName, -1, 
		lplfW.elfEnumLogfontEx.elfFullName, LF_FULLFACESIZE);

	MultiByteToWideChar(settings.CodePage, 0, 
		(LPCCH)lplf->elfEnumLogfontEx.elfStyle, -1,
		lplfW.elfEnumLogfontEx.elfStyle, LF_FACESIZE);

	MultiByteToWideChar(settings.CodePage, 0, 
		(LPCCH)lplf->elfEnumLogfontEx.elfScript, -1,
		lplfW.elfEnumLogfontEx.elfScript, LF_FACESIZE);

	// Copy the design vector part
	lplfW.elfDesignVector = lplf->elfDesignVector;

	// Call the Unicode version
	return OriginalCreateFontIndirectExW(&lplfW);
}

HFONT WINAPI HookCreateFontIndirectExW(
	ENUMLOGFONTEXDVW* lplf
)
{
	DEBUG_FUNCTION_TRACE();

	if (!lplf)
		return NULL;

	// Create a copy of the structure that we can modify
	ENUMLOGFONTEXDVW lplfW = *lplf;

	// Adjust character set based on code page if needed
	if (IS_REPLACEABLE_CHARSET(lplfW.elfEnumLogfontEx.elfLogFont.lfCharSet)) {
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, lplfW.elfEnumLogfontEx.elfLogFont.lfCharSet)
	}

	// Apply font substitution if configured
	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		// Check if we should apply substitution
		bool applySubstitution = false;

		// If original font is empty, substitute
		if (lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName[0] == L'\0') {
			applySubstitution = true;
		}
		// If we're forcing substitution for all fonts
		else if (settings.SubstituteAllFonts) {
			applySubstitution = true;
		}
		// If this font is in our substitution list
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName : settings.FontsToSubstitute) {
				if (wcscmp(lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName, fontName.c_str()) == 0) {
					applySubstitution = true;
					break;
				}
			}
		}

		if (applySubstitution) {
			wcsncpy(lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName, settings.SubstituteFontName, LF_FACESIZE - 1);
			lplfW.elfEnumLogfontEx.elfLogFont.lfFaceName[LF_FACESIZE - 1] = L'\0';
		}
	}

	// Call original function with potentially modified structure
	return OriginalCreateFontIndirectExW(&lplfW);
}

BOOL WINAPI HookTextOutA(
	HDC	hdc,
	int	x,
	int	y,
	LPSTR  lpString,
	int	c
)
{
	DEBUG_FUNCTION_TRACE();
	// Handle NULL string case
	if (!lpString) {
		return OriginalTextOutA(hdc, x, y, lpString, c);
	}

	// Determine actual string length if not specified
	int actualLength = c;
	if (c == -1) {
		actualLength = lstrlenA(lpString);
	}

	// Convert text to Unicode with specific code page
	LPWSTR wstr = MultiByteToWideCharInternal(lpString, settings.CodePage);
	if (wstr)
	{
		// For TextOut, we need to calculate character count, not byte count
		int wlen;
		if (c == -1) {
			// If original length was -1, use the full converted string
			wlen = lstrlenW(wstr);
		} else {
			// Otherwise, we need to determine how many Unicode characters
			// correspond to the specified number of ANSI characters
			// This is complex due to potential multi-byte characters
			// For simplicity and safety, we'll use the full string length
			// but limit it to the original count if it's smaller
			wlen = lstrlenW(wstr);
			if (wlen > c) {
				wlen = c;
			}
		}

		// Call Unicode version with correct length
		BOOL ret = TextOutW(hdc, x, y, wstr, wlen);


		FreeStringInternal(wstr);

		return ret;
	}

	// Fall back to original function if conversion fails
	return OriginalTextOutA(hdc, x, y, lpString, c);
}

int WINAPI HookDrawTextExA(
	_In_ HDC hdc,
	LPSTR lpchText,
	_In_ int cchText,
	_Inout_ LPRECT lprc,
	_In_ UINT format,
	_In_opt_ LPDRAWTEXTPARAMS lpdtp
)
{
	DEBUG_FUNCTION_TRACE();
	// Handle NULL text case
	if (!lpchText) {
		return OriginalDrawTextExA(hdc, lpchText, cchText, lprc, format, lpdtp);
	}

	// Convert text to Unicode with specific code page
	LPWSTR wstr = MultiByteToWideCharInternal(lpchText, settings.CodePage);
	if (wstr)
	{
		// Determine the appropriate length for the Unicode string
		int wsize;
		if (cchText == -1) {
			// If original length was -1, use the full converted string
			wsize = -1;
		} else {
			// Otherwise, we need to determine how many Unicode characters
			// correspond to the specified number of ANSI characters
			// For DrawTextExW, we can pass -1 to use the entire string,
			// or limit it to the original count if needed
			wsize = lstrlenW(wstr);
			if (wsize > cchText) {
				wsize = cchText;
			}
		}

		// Call Unicode version of the function
		int ret = DrawTextExW(hdc, wstr, wsize, lprc, format, lpdtp);


		FreeStringInternal(wstr);

		return ret;
	}

	// Fall back to original function if conversion fails
	return OriginalDrawTextExA(
		hdc,
		lpchText,
		cchText,
		lprc,
		format,
		lpdtp
	);
}

HANDLE WINAPI HookGetClipboardData(UINT uFormat)
{
	DEBUG_FUNCTION_TRACE();
	if (uFormat == CF_TEXT)
	{
		// Try to get Unicode text from clipboard
		HANDLE hClipMemory = OriginalGetClipboardData(CF_UNICODETEXT);
		if (hClipMemory)
		{
			LPWSTR wstr = (LPWSTR)GlobalLock(hClipMemory);
			if (wstr)
			{
				int wsize = lstrlenW(wstr);

				// Get the required buffer size for conversion
				int lsize = WideCharToMultiByte(settings.CodePage, 0, wstr, wsize, NULL, 0, NULL, NULL);
				if (lsize > 0)
				{
					// Allocate memory for converted text plus null terminator
					HANDLE hGlobalMemory = GlobalAlloc(GHND, lsize + 1);
					if (hGlobalMemory)
					{
						LPSTR lstr = (LPSTR)GlobalLock(hGlobalMemory);
						if (lstr)
						{
							// Convert the Unicode text to multibyte
							lsize = OriginalWideCharToMultiByte(settings.CodePage, 0, 
									wstr, wsize, lstr, lsize, NULL, NULL);
							if (lsize > 0)
							{
								lstr[lsize] = '\0';
								GlobalUnlock(hGlobalMemory);
								GlobalUnlock(hClipMemory);
								return hGlobalMemory;
							}
							else
							{
								// Conversion failed
								GlobalUnlock(hGlobalMemory);
								GlobalFree(hGlobalMemory);
							}
						}
						else // Lock failed
							GlobalFree(hGlobalMemory);
					}
				}

				GlobalUnlock(hClipMemory);
			}
		}
		// If Unicode conversion failed or wasn't available, try to get original text
		return OriginalGetClipboardData(uFormat);
	}

	// For non-text formats, just pass through
	return OriginalGetClipboardData(uFormat);
}

HANDLE WINAPI HookSetClipboardData(UINT uFormat, HANDLE hMem)
{
	DEBUG_FUNCTION_TRACE();
	// Only intercept text format
	if (uFormat == CF_TEXT)
	{
		HANDLE hGlobalMemory = NULL;
		LPSTR lstr = (LPSTR)GlobalLock(hMem);

		if (lstr)
		{
			int lsize = lstrlenA(lstr);
			int wsize = MultiByteToWideChar(settings.CodePage, 0, lstr, lsize, NULL, 0);
			if (wsize > 0)
			{
				// Allocate memory for converted text plus null terminator
				hGlobalMemory = GlobalAlloc(GHND, (wsize + 1) * sizeof(WCHAR));
				if (hGlobalMemory)
				{
					LPWSTR wstr = (LPWSTR)GlobalLock(hGlobalMemory);
					if (wstr)
					{
						// Convert the text
						wsize = OriginalMultiByteToWideChar(settings.CodePage, 0, lstr, lsize, wstr, wsize);
						if (wsize > 0)
						{
							wstr[wsize] = L'\0';
							GlobalUnlock(hGlobalMemory);

							// Set both the original and Unicode text
							OriginalSetClipboardData(uFormat, hMem);
							return OriginalSetClipboardData(CF_UNICODETEXT, hGlobalMemory);
						}
						else
						{
							// Conversion failed
							GlobalUnlock(hGlobalMemory);
							GlobalFree(hGlobalMemory);
						}
					}
					else
						GlobalFree(hGlobalMemory);
				}
			}

			GlobalUnlock(hMem);
		}
	}
	return OriginalSetClipboardData(uFormat, hMem);
}

// Define a global structure to store the original callback and context
typedef struct {
	LPDSENUMCALLBACKA pOriginalCallback;
	LPVOID pOriginalContext;
} DS_ENUM_CONTEXT;

// This is our Unicode callback that will convert strings back to ANSI
BOOL CALLBACK DSEnumCallbackWrapperW(LPGUID lpGuid, LPCWSTR lpstrDescription, 
									 LPCWSTR lpstrModule, LPVOID lpContext)
{
	DEBUG_FUNCTION_TRACE();
	// Retrieve our context with the original callback and context
	DS_ENUM_CONTEXT* pEnumContext = (DS_ENUM_CONTEXT*)lpContext;
	if (!pEnumContext || !pEnumContext->pOriginalCallback) {
		return FALSE; // Safety check
	}

	// Convert the Unicode strings to ANSI
	char szDescription[MAX_PATH] = {0};
	char szModule[MAX_PATH] = {0};

	WideCharToMultiByte(
		settings.CodePage, 0, 
		lpstrDescription, -1, 
		szDescription, MAX_PATH, 
		NULL, NULL
	);

	WideCharToMultiByte(
		settings.CodePage, 0, 
		lpstrModule, -1, 
		szModule, MAX_PATH, 
		NULL, NULL
	);

	// Call the original ANSI callback with converted strings
	return pEnumContext->pOriginalCallback(
		lpGuid, 
		szDescription, 
		szModule, 
		pEnumContext->pOriginalContext
	);
}

HRESULT WINAPI HookDirectSoundEnumerateA(
	_In_ LPDSENUMCALLBACKA pDSEnumCallback,
	_In_opt_ LPVOID pContext
){
	// Validate parameters
	if (!pDSEnumCallback) {
		return DSERR_INVALIDPARAM;
	}

	// Create a context to pass the original callback and context
	DS_ENUM_CONTEXT enumContext;
	enumContext.pOriginalCallback = pDSEnumCallback;
	enumContext.pOriginalContext = pContext;

	// Call the Unicode version with our wrapper callback
	return DirectSoundEnumerateW(
		DSEnumCallbackWrapperW,
		&enumContext
	);
}

LPSTR WINAPI HookCharPrevExA(
	_In_ WORD CodePage,
	_In_ LPCSTR lpStart,
	_In_ LPCSTR lpCurrentChar,
	_In_ DWORD dwFlags
){
	// Only replace standard Windows code pages with our settings code page
	// Preserve special code pages like UTF-7 (CP_UTF7=65000), UTF-8 (CP_UTF8=65001)
	if (CodePage == CP_ACP || CodePage == CP_OEMCP || 
		(CodePage > 2 && CodePage < CP_UTF7)) {
		CodePage = settings.CodePage;
	}

	return OriginalCharPrevExA(CodePage, lpStart, lpCurrentChar, dwFlags);
}

LPSTR WINAPI HookCharNextExA(
	_In_ WORD CodePage,
	_In_ LPCSTR lpCurrentChar,
	_In_ DWORD dwFlags
){

	if (CodePage == CP_ACP || CodePage == CP_OEMCP || 
		(CodePage > 2 && CodePage < CP_UTF7)) {
		CodePage = settings.CodePage;
	}

	return OriginalCharNextExA(CodePage, lpCurrentChar, dwFlags);
}

BOOL WINAPI HookIsDBCSLeadByteEx(
	_In_ UINT  CodePage,
	_In_ BYTE  TestChar
){
	if (CodePage == CP_ACP || CodePage == CP_OEMCP || 
		(CodePage > 2 && CodePage < CP_UTF7)) {
		CodePage = settings.CodePage;
	}

	return OriginalIsDBCSLeadByteEx(CodePage, TestChar);
}


HWND WINAPI HookCreateDialogIndirectParamA(
	_In_opt_ HINSTANCE hInstance,
	_In_ LPCDLGTEMPLATEA lpTemplate,
	_In_opt_ HWND hWndParent,
	_In_opt_ DLGPROC lpDialogFunc,
	_In_ LPARAM dwInitParam
){
	if (!lpTemplate) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	return CreateDialogIndirectParamW(
		hInstance,
		(LPCDLGTEMPLATEW)lpTemplate,
		hWndParent,
		lpDialogFunc,
		dwInitParam
	);;
}

ATOM WINAPI HookRegisterClassA(_In_ CONST WNDCLASSA* lpWndClass)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpWndClass) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Allocate memory for the WNDCLASSW structure
	WNDCLASSW* wcW = (WNDCLASSW*)AllocateZeroedMemory(sizeof(WNDCLASSW));
	if (!wcW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Copy non-string members directly
	wcW->style = lpWndClass->style;
	wcW->lpfnWndProc = lpWndClass->lpfnWndProc;
	wcW->cbClsExtra = lpWndClass->cbClsExtra;
	wcW->cbWndExtra = lpWndClass->cbWndExtra;
	wcW->hInstance = lpWndClass->hInstance;
	wcW->hIcon = lpWndClass->hIcon;
	wcW->hCursor = lpWndClass->hCursor;
	wcW->hbrBackground = lpWndClass->hbrBackground;
	wcW->lpszMenuName = NULL;
	wcW->lpszClassName = NULL;

	// Convert menu name if not NULL and not a resource ID
	if (lpWndClass->lpszMenuName && !IS_INTRESOURCE(lpWndClass->lpszMenuName)) {
		wcW->lpszMenuName = MultiByteToWideCharInternal(lpWndClass->lpszMenuName, settings.CodePage);
		if (!wcW->lpszMenuName)
			return OriginalRegisterClassA(lpWndClass);
	}
	else {
		wcW->lpszMenuName = (LPCWSTR)lpWndClass->lpszMenuName;
	}

	// Convert class name (must not be NULL)
	if (lpWndClass->lpszClassName && !IS_INTRESOURCE(lpWndClass->lpszClassName)) {
		wcW->lpszClassName = MultiByteToWideCharInternal(lpWndClass->lpszClassName, settings.CodePage);
		if (!wcW->lpszClassName) {
			if (wcW->lpszMenuName && !IS_INTRESOURCE(lpWndClass->lpszMenuName))
				FreeStringInternal((LPWSTR)wcW->lpszMenuName);
			return OriginalRegisterClassA(lpWndClass);
		}
	}
	else {
		wcW->lpszClassName = (LPCWSTR)lpWndClass->lpszClassName;
	}

	// Register the Unicode window class
	ATOM atom = RegisterClassW(wcW);

	// Clean up allocated strings
	if (lpWndClass->lpszMenuName && !IS_INTRESOURCE(lpWndClass->lpszMenuName))
		FreeStringInternal((LPWSTR)wcW->lpszMenuName);

	if (lpWndClass->lpszClassName && !IS_INTRESOURCE(lpWndClass->lpszClassName))
		FreeStringInternal((LPWSTR)wcW->lpszClassName);

	return atom;
}

ATOM WINAPI HookRegisterClassExA(_In_ CONST WNDCLASSEXA* lpWndClassEx)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpWndClassEx) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Allocate memory for the WNDCLASSEXW structure
	WNDCLASSEXW* wcExW = (WNDCLASSEXW*)AllocateZeroedMemory(sizeof(WNDCLASSEXW));
	if (!wcExW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Copy non-string members directly
	wcExW->cbSize = sizeof(WNDCLASSEXW);
	wcExW->style = lpWndClassEx->style;
	wcExW->lpfnWndProc = lpWndClassEx->lpfnWndProc;
	wcExW->cbClsExtra = lpWndClassEx->cbClsExtra;
	wcExW->cbWndExtra = lpWndClassEx->cbWndExtra;
	wcExW->hInstance = lpWndClassEx->hInstance;
	wcExW->hIcon = lpWndClassEx->hIcon;
	wcExW->hCursor = lpWndClassEx->hCursor;
	wcExW->hbrBackground = lpWndClassEx->hbrBackground;
	wcExW->hIconSm = lpWndClassEx->hIconSm;
	wcExW->lpszMenuName = NULL;
	wcExW->lpszClassName = NULL;

	// Convert menu name if not NULL and not a resource ID
	if (lpWndClassEx->lpszMenuName && !IS_INTRESOURCE(lpWndClassEx->lpszMenuName)) {
		wcExW->lpszMenuName = MultiByteToWideCharInternal(lpWndClassEx->lpszMenuName, settings.CodePage);
		if (!wcExW->lpszMenuName)
			return OriginalRegisterClassExA(lpWndClassEx);
	}
	else
		wcExW->lpszMenuName = (LPCWSTR)lpWndClassEx->lpszMenuName;

	// Convert class name (must not be NULL)
	if (lpWndClassEx->lpszClassName && !IS_INTRESOURCE(lpWndClassEx->lpszClassName)) {
		wcExW->lpszClassName = MultiByteToWideCharInternal(lpWndClassEx->lpszClassName, settings.CodePage);
		if (!wcExW->lpszClassName) {
			if (wcExW->lpszMenuName && !IS_INTRESOURCE(lpWndClassEx->lpszMenuName))
				FreeStringInternal((LPWSTR)wcExW->lpszMenuName);
			return OriginalRegisterClassExA(lpWndClassEx);
		}
	}
	else
		wcExW->lpszClassName = (LPCWSTR)lpWndClassEx->lpszClassName;

	// Register the Unicode window class
	ATOM ret = RegisterClassExW(wcExW);

	if (!IS_INTRESOURCE(lpWndClassEx->lpszMenuName))
		FreeStringInternal((LPWSTR)wcExW->lpszMenuName);

	if (!IS_INTRESOURCE(lpWndClassEx->lpszClassName))
		FreeStringInternal((LPWSTR)wcExW->lpszClassName);

	return ret;
}

inline LRESULT CallProcAddress(
	LPVOID lpProcAddress, 
	HWND hWnd, 
	HWND hMDIClient,
	BOOL bMDIClientEnabled, 
	UINT uMsg, 
	WPARAM wParam, 
	LPARAM lParam)
{
	DEBUG_FUNCTION_TRACE();
	// Define function pointer types for normal and MDI window procedures
	typedef LRESULT (WINAPI *WNDPROC_TYPE)(HWND, UINT, WPARAM, LPARAM);
	typedef LRESULT (WINAPI *MDIPROC_TYPE)(HWND, HWND, UINT, WPARAM, LPARAM);

	if (bMDIClientEnabled) {
		// Call MDI window procedure
		MDIPROC_TYPE pfnMDIProc = (MDIPROC_TYPE)lpProcAddress;
		return pfnMDIProc(hWnd, hMDIClient, uMsg, wParam, lParam);
	} else {
		// Call regular window procedure
		WNDPROC_TYPE pfnWndProc = (WNDPROC_TYPE)lpProcAddress;
		return pfnWndProc(hWnd, uMsg, wParam, lParam);
	}
}

LRESULT CALLBACK HookDefWindowProcA(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	DEBUG_FUNCTION_TRACE();
	if (IsWindowUnicode(hWnd))
		return DefWindowProcW(hWnd, Msg, wParam, lParam);
	else
		return OriginalDefWindowProcA(hWnd, Msg, wParam, lParam);
}

DWORD WINAPI HookGetTimeZoneInformation(
	_Out_ LPTIME_ZONE_INFORMATION lpTimeZoneInformation
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpTimeZoneInformation) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return TIME_ZONE_ID_INVALID;
	}

	DWORD ret = OriginalGetTimeZoneInformation(lpTimeZoneInformation);

	// If successful, override with our custom time zone settings if enabled
	if (ret != TIME_ZONE_ID_INVALID) {
		// Copy our custom time zone information
		lpTimeZoneInformation->Bias = -settings.Bias; // bias becomes negative here
		//lpTimeZoneInformation->StandardBias = settings.StandardBias;
		//lpTimeZoneInformation->DaylightBias = settings.DaylightBias;

		/*
		if (settings.StandardName[0] != L'\0') {
			wcsncpy(lpTimeZoneInformation->StandardName, 
					settings.StandardName, 
					sizeof(lpTimeZoneInformation->StandardName) / sizeof(WCHAR));
		}

		if (settings.DaylightName[0] != L'\0') {
			wcsncpy(lpTimeZoneInformation->DaylightName, 
					settings.DaylightName, 
					sizeof(lpTimeZoneInformation->DaylightName) / sizeof(WCHAR));
		}

		if (settings.TimeZoneID != TIME_ZONE_ID_UNKNOWN)
			result = settings.TimeZoneID;
		*/
	}
	return ret;
}

BOOL WINAPI HookCreateDirectoryA(
	_In_ LPCSTR lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpPathName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpPathNameW = MultiByteToWideCharInternal(lpPathName, settings.CodePage);
	if (!lpPathNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = CreateDirectoryW(lpPathNameW, lpSecurityAttributes);

	FreeStringInternal(lpPathNameW);

	return ret;
}

HANDLE WINAPI HookCreateFileA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE_VALUE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return INVALID_HANDLE_VALUE;
	}

	HANDLE ret = CreateFileW(
		lpFileNameW,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);


	FreeStringInternal(lpFileNameW);

	return ret;
}

int WINAPI HookGetLocaleInfoW(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPWSTR lpLCData,
	_In_ int cchData)
{
	DEBUG_FUNCTION_TRACE();
	// Override only if it's a default locale
	if (Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)
		Locale = settings.LCID;

	if (cchData <= 0 || !lpLCData)
		return OriginalGetLocaleInfoW(Locale, LCType, lpLCData, cchData);

	/*switch (LCType) {
		case LOCALE_SDECIMAL:  // Decimal separator
			if (settings.UseCustomDecimalSeparator && cchData >= 2) {
				lpLCData[0] = settings.DecimalSeparator;
				lpLCData[1] = L'\0';
				return 2;
			}
			break;

		case LOCALE_STHOUSAND:  // Thousands separator
			if (settings.UseCustomThousandSeparator && cchData >= 2) {
				lpLCData[0] = settings.ThousandSeparator;
				lpLCData[1] = L'\0';
				return 2;
			}
			break;

		case LOCALE_SGROUPING:  // Digit grouping
			if (settings.UseCustomGrouping && settings.CustomGrouping[0] != L'\0') {
				wcscpy_s(lpLCData, cchData, settings.CustomGrouping);
				return (int)wcslen(settings.CustomGrouping) + 1;
			}
			break;

		case LOCALE_SCURRENCY:  // Currency symbol
			if (settings.UseCustomCurrencySymbol && settings.CustomCurrencySymbol[0] != L'\0') {
				wcscpy_s(lpLCData, cchData, settings.CustomCurrencySymbol);
				return (int)wcslen(settings.CustomCurrencySymbol) + 1;
			}
			break;

		case LOCALE_SDATE:  // Date separator
			if (settings.UseCustomDateSeparator && cchData >= 2) {
				lpLCData[0] = settings.DateSeparator;
				lpLCData[1] = L'\0';
				return 2;
			}
			break;

		case LOCALE_STIME:  // Time separator
			if (settings.UseCustomTimeSeparator && cchData >= 2) {
				lpLCData[0] = settings.TimeSeparator;
				lpLCData[1] = L'\0';
				return 2;
			}
			break;

		case LOCALE_SSHORTDATE:  // Short date format
			if (settings.UseCustomShortDateFormat && settings.CustomShortDateFormat[0] != L'\0') {
				wcscpy_s(lpLCData, cchData, settings.CustomShortDateFormat);
				return (int)wcslen(settings.CustomShortDateFormat) + 1;
			}
			break;
	}*/

	return OriginalGetLocaleInfoW(Locale, LCType, lpLCData, cchData);
}

int WINAPI HookGetLocaleInfoA(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPSTR lpLCData,
	_In_ int cchData)
{
	DEBUG_FUNCTION_TRACE();
	if (Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)
		Locale = settings.LCID;

	if (cchData <= 0 || !lpLCData)
		return OriginalGetLocaleInfoA(Locale, LCType, lpLCData, cchData);

	WCHAR wBuffer[256] = {0};
	int wResult = HookGetLocaleInfoW(Locale, LCType, wBuffer, 256);

	if (wResult > 0) {
		int result = WideCharToMultiByte(
			settings.CodePage, 0, wBuffer, -1,
			lpLCData, cchData, NULL, NULL);

		if (result > 0)
			return result;
	}

	return OriginalGetLocaleInfoA(Locale, LCType, lpLCData, cchData);
}

DWORD WINAPI HookGetFileVersionInfoSizeA(
	_In_ LPCSTR lptstrFilename,
	_Out_opt_ LPDWORD lpdwHandle
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lptstrFilename) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	LPWSTR lpwFilename = MultiByteToWideCharInternal(lptstrFilename);
	if (!lpwFilename) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD result = GetFileVersionInfoSizeW(lpwFilename, lpdwHandle);

	FreeStringInternal(lpwFilename);

	return result;
}

LANGID WINAPI HookGetUserDefaultUILanguage(void)
{
	DEBUG_FUNCTION_TRACE();
	if (settings.LCID > 0)
		return settings.LCID;

	if (settings.CodePage > 0) {
		// Map CodePage to LANGID in case it's not provided
		switch (settings.CodePage) {
			case 932:   return 0x0411; // Japanese
			case 936:   return 0x0804; // Chinese (Simplified)
			case 950:   return 0x0404; // Chinese (Traditional)
			case 949:   return 0x0412; // Korean
			case 1250:  return 0x0415; // Polish (example for Central European)
			case 1251:  return 0x0419; // Russian
			case 1252:  return 0x0409; // English (US) for Western European
			case 1253:  return 0x0408; // Greek
			case 1254:  return 0x041F; // Turkish
			case 1255:  return 0x040D; // Hebrew
			case 1256:  return 0x0401; // Arabic
			case 1258:  return 0x042A; // Vietnamese
			// Add more mappings as needed
			default:
				break;
		}
	}
	// Fallback to original function if no mapping is found
	return OriginalGetUserDefaultUILanguage();
}

LCID WINAPI HookGetLocaleID(void) { 
	return MAKELCID(HookGetUserDefaultUILanguage(), SORT_DEFAULT); 
}

LCID WINAPI HookGetThreadLocale(void) { 
	return MAKELCID(HookGetUserDefaultUILanguage(), SORT_DEFAULT); 
}

LCID WINAPI HookGetUserDefaultLCID(void)
{
	DEBUG_FUNCTION_TRACE();
	return MAKELCID(HookGetUserDefaultUILanguage(), SORT_DEFAULT);
}

LCID WINAPI HookGetSystemDefaultLCID(void)
{
	DEBUG_FUNCTION_TRACE();
	return MAKELCID(HookGetUserDefaultUILanguage(), SORT_DEFAULT); 
}

LANGID WINAPI HookGetUserDefaultLangID(void)
{
	DEBUG_FUNCTION_TRACE();
	return HookGetUserDefaultUILanguage();
}

LANGID WINAPI HookGetSystemDefaultLangID(void)
{
	DEBUG_FUNCTION_TRACE();
	return HookGetSystemDefaultUILanguage();
}

LANGID WINAPI HookGetSystemDefaultUILanguage(void)
{
	DEBUG_FUNCTION_TRACE();
	return HookGetUserDefaultUILanguage();
}

BOOL WINAPI HookGetUserDefaultLocaleName(
	_Out_writes_(cchLocaleName) LPWSTR lpLocaleName,
	_In_ int cchLocaleName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpLocaleName || cchLocaleName <= 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	LANGID langID = HookGetUserDefaultUILanguage();

	// Use LCIDToLocaleName if available (Windows Vista and later)
	LCID lcid = MAKELCID(langID, SORT_DEFAULT);
	return LCIDToLocaleName(lcid, lpLocaleName, cchLocaleName, 0);
}

BOOL WINAPI HookGetSystemDefaultLocaleName(
	_Out_writes_(cchLocaleName) LPWSTR lpLocaleName,
	_In_ int cchLocaleName
)
{
	DEBUG_FUNCTION_TRACE();
	return HookGetUserDefaultLocaleName(lpLocaleName, cchLocaleName);
}
/*DWORD WINAPI HookGetNumberFormatW(
	_In_ LCID Locale,
	_In_ DWORD dwFlags,
	_In_ LPCWSTR lpValue,
	_In_opt_ CONST NUMBERFMTW* lpFormat,
	_Out_writes_opt_(cchNumber) LPWSTR lpNumberStr,
	_In_ int cchNumber)
{
	DEBUG_FUNCTION_TRACE();
	// Override locale if it's a default locale
	if (Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)
		Locale = settings.LCID;

	// Create a custom NUMBERFMT if needed
	NUMBERFMTW customFormat;
	BOOL useCustomFormat = FALSE;

	if (settings.UseCustomDecimalSeparator || 
		settings.UseCustomThousandSeparator || 
		settings.UseCustomGrouping) {

		// Start with the provided format or get the default for the locale
		if (lpFormat) {
			memcpy(&customFormat, lpFormat, sizeof(NUMBERFMTW));
		} else {
			ZeroMemory(&customFormat, sizeof(NUMBERFMTW));
			customFormat.NumDigits = 2;
			customFormat.LeadingZero = 1;
			customFormat.Grouping = 3;
			customFormat.lpDecimalSep = L".";
			customFormat.lpThousandSep = L",";
			customFormat.NegativeOrder = 1;

			// Get default format values from locale
			int len;
			WCHAR buffer[10];

			len = OriginalGetLocaleInfoW(Locale, LOCALE_IDIGITS, buffer, 10);
			if (len > 0) customFormat.NumDigits = _wtoi(buffer);

			len = OriginalGetLocaleInfoW(Locale, LOCALE_ILZERO, buffer, 10);
			if (len > 0) customFormat.LeadingZero = _wtoi(buffer);

			len = OriginalGetLocaleInfoW(Locale, LOCALE_INEGNUMBER, buffer, 10);
			if (len > 0) customFormat.NegativeOrder = _wtoi(buffer);
		}

		// Apply our custom settings
		static WCHAR decimalSep[2] = {0};
		static WCHAR thousandSep[2] = {0};
		static WCHAR grouping[16] = {0};

		if (settings.UseCustomDecimalSeparator) {
			decimalSep[0] = settings.DecimalSeparator;
			decimalSep[1] = L'\0';
			customFormat.lpDecimalSep = decimalSep;
		}

		if (settings.UseCustomThousandSeparator) {
			thousandSep[0] = settings.ThousandSeparator;
			thousandSep[1] = L'\0';
			customFormat.lpThousandSep = thousandSep;
		}

		if (settings.UseCustomGrouping && settings.CustomGrouping[0] != L'\0') {
			customFormat.Grouping = _wtoi(settings.CustomGrouping);
		}

		useCustomFormat = TRUE;
	}

	// Call the original function with our potentially modified format
	return OriginalGetNumberFormatW(Locale, dwFlags, lpValue, 
								   useCustomFormat ? &customFormat : lpFormat, 
								   lpNumberStr, cchNumber);
}

DWORD WINAPI HookGetNumberFormatA(
	_In_ LCID Locale,
	_In_ DWORD dwFlags,
	_In_ LPCSTR lpValue,
	_In_opt_ CONST NUMBERFMTA* lpFormat,
	_Out_writes_opt_(cchNumber) LPSTR lpNumberStr,
	_In_ int cchNumber)
{
	DEBUG_FUNCTION_TRACE();
	// Override locale if it's a default locale
	if (Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)
		Locale = settings.LCID;

	// Convert value to Unicode
	LPWSTR wValue = NULL;
	if (lpValue) {
		int len = MultiByteToWideChar(CP_ACP, 0, lpValue, -1, NULL, 0);
		wValue = (LPWSTR)malloc(len * sizeof(WCHAR));
		if (!wValue) return 0;
		MultiByteToWideChar(CP_ACP, 0, lpValue, -1, wValue, len);
	}

	// Convert format to Unicode if provided
	NUMBERFMTW wFormat;
	LPWSTR wDecimalSep = NULL;
	LPWSTR wThousandSep = NULL;

	if (lpFormat) {
		wFormat.NumDigits = lpFormat->NumDigits;
		wFormat.LeadingZero = lpFormat->LeadingZero;
		wFormat.Grouping = lpFormat->Grouping;
		wFormat.NegativeOrder = lpFormat->NegativeOrder;

		if (lpFormat->lpDecimalSep) {
			int len = MultiByteToWideChar(CP_ACP, 0, lpFormat->lpDecimalSep, -1, NULL, 0);
			wDecimalSep = (LPWSTR)malloc(len * sizeof(WCHAR));
			if (wDecimalSep) {
				MultiByteToWideChar(CP_ACP, 0, lpFormat->lpDecimalSep, -1, wDecimalSep, len);
				wFormat.lpDecimalSep = wDecimalSep;
			}
		} else {
			wFormat.lpDecimalSep = NULL;
		}

		if (lpFormat->lpThousandSep) {
			int len = MultiByteToWideChar(CP_ACP, 0, lpFormat->lpThousandSep, -1, NULL, 0);
			wThousandSep = (LPWSTR)malloc(len * sizeof(WCHAR));
			if (wThousandSep) {
				MultiByteToWideChar(CP_ACP, 0, lpFormat->lpThousandSep, -1, wThousandSep, len);
				wFormat.lpThousandSep = wThousandSep;
			}
		} else {
			wFormat.lpThousandSep = NULL;
		}
	}

	// Use a temporary Unicode buffer for the result
	LPWSTR wNumberStr = NULL;
	DWORD result = 0;

	if (lpNumberStr && cchNumber > 0) {
		wNumberStr = (LPWSTR)malloc(cchNumber * sizeof(WCHAR));
		if (wNumberStr) {
			// Get the number format in Unicode
			result = HookGetNumberFormatW(Locale, dwFlags, wValue, 
										lpFormat ? &wFormat : NULL, 
										wNumberStr, cchNumber);

			if (result > 0) {
				// Convert back to ANSI
				WideCharToMultiByte(settings.CodePage, 0, wNumberStr, -1, 
									lpNumberStr, cchNumber, NULL, NULL);
				result = strlen(lpNumberStr);
			}

			free(wNumberStr);
		}
	}

	// Clean up
	if (wValue) free(wValue);
	if (wDecimalSep) free(wDecimalSep);
	if (wThousandSep) free(wThousandSep);

	// If our approach failed, fall back to original
	if (result == 0 && lpNumberStr)
	  return OriginalGetNumberFormatA(Locale, dwFlags, lpValue, lpFormat, lpNumberStr, cchNumber);


	return result;
}
*/

// Additional file operation function hooks
HANDLE WINAPI HookFindFirstFileA(
	_In_ LPCSTR lpFileName,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE_VALUE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return INVALID_HANDLE_VALUE;
	}

	WIN32_FIND_DATAW findDataW;
	HANDLE hFind = FindFirstFileW(lpFileNameW, &findDataW);

	if (hFind != INVALID_HANDLE_VALUE && lpFindFileData) {
		// Convert the DATAW structure to DATAA
		lpFindFileData->dwFileAttributes = findDataW.dwFileAttributes;
		lpFindFileData->ftCreationTime = findDataW.ftCreationTime;
		lpFindFileData->ftLastAccessTime = findDataW.ftLastAccessTime;
		lpFindFileData->ftLastWriteTime = findDataW.ftLastWriteTime;
		lpFindFileData->nFileSizeHigh = findDataW.nFileSizeHigh;
		lpFindFileData->nFileSizeLow = findDataW.nFileSizeLow;
		lpFindFileData->dwReserved0 = findDataW.dwReserved0;
		lpFindFileData->dwReserved1 = findDataW.dwReserved1;

		// Convert filename back to ANSI
		LPSTR cFileName = WideCharToMultiByteInternal(findDataW.cFileName, settings.CodePage);
		if (cFileName) {
			strncpy(lpFindFileData->cFileName, cFileName, MAX_PATH - 1);
			lpFindFileData->cFileName[MAX_PATH - 1] = '\0';
			FreeStringInternal(cFileName);
		}

		// Convert alternate filename back to ANSI
		LPSTR cAlternateFileName = WideCharToMultiByteInternal(findDataW.cAlternateFileName, settings.CodePage);
		if (cAlternateFileName) {
			strncpy(lpFindFileData->cAlternateFileName, cAlternateFileName, 14);
			lpFindFileData->cAlternateFileName[14] = '\0';
			FreeStringInternal(cAlternateFileName);
		}
	}

	FreeStringInternal(lpFileNameW);
	return hFind;
}

BOOL WINAPI HookFindNextFileA(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
)
{
	DEBUG_FUNCTION_TRACE();
	if (!hFindFile || hFindFile == INVALID_HANDLE_VALUE || !lpFindFileData) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	WIN32_FIND_DATAW findDataW;
	BOOL result = FindNextFileW(hFindFile, &findDataW);

	if (result) {
		// Convert the DATAW structure to DATAA
		lpFindFileData->dwFileAttributes = findDataW.dwFileAttributes;
		lpFindFileData->ftCreationTime = findDataW.ftCreationTime;
		lpFindFileData->ftLastAccessTime = findDataW.ftLastAccessTime;
		lpFindFileData->ftLastWriteTime = findDataW.ftLastWriteTime;
		lpFindFileData->nFileSizeHigh = findDataW.nFileSizeHigh;
		lpFindFileData->nFileSizeLow = findDataW.nFileSizeLow;
		lpFindFileData->dwReserved0 = findDataW.dwReserved0;
		lpFindFileData->dwReserved1 = findDataW.dwReserved1;

		// Convert filename back to ANSI
		LPSTR cFileName = WideCharToMultiByteInternal(findDataW.cFileName, settings.CodePage);
		if (cFileName) {
			strncpy(lpFindFileData->cFileName, cFileName, MAX_PATH - 1);
			lpFindFileData->cFileName[MAX_PATH - 1] = '\0';
			FreeStringInternal(cFileName);
		}

		// Convert alternate filename back to ANSI
		LPSTR cAlternateFileName = WideCharToMultiByteInternal(findDataW.cAlternateFileName, settings.CodePage);
		if (cAlternateFileName) {
			strncpy(lpFindFileData->cAlternateFileName, cAlternateFileName, 14);
			lpFindFileData->cAlternateFileName[13] = '\0';
			FreeStringInternal(cAlternateFileName);
		}
	}

	return result;
}

DWORD WINAPI HookGetFileAttributesA(
	_In_ LPCSTR lpFileName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_FILE_ATTRIBUTES;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return INVALID_FILE_ATTRIBUTES;
	}

	DWORD ret = GetFileAttributesW(lpFileNameW);

	FreeStringInternal(lpFileNameW);

	return ret;
}

BOOL WINAPI HookDeleteFileA(
	_In_ LPCSTR lpFileName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = DeleteFileW(lpFileNameW);

	FreeStringInternal(lpFileNameW);

	return ret;
}

BOOL WINAPI HookCopyFileA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName,
	_In_ BOOL bFailIfExists
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpExistingFileName || !lpNewFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpExistingFileNameW = MultiByteToWideCharInternal(lpExistingFileName, settings.CodePage);
	if (!lpExistingFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	LPWSTR lpNewFileNameW = MultiByteToWideCharInternal(lpNewFileName, settings.CodePage);
	if (!lpNewFileNameW) {
		FreeStringInternal(lpExistingFileNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = CopyFileW(lpExistingFileNameW, lpNewFileNameW, bFailIfExists);

	FreeStringInternal(lpExistingFileNameW);
	FreeStringInternal(lpNewFileNameW);

	return ret;
}

BOOL WINAPI HookMoveFileA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpExistingFileName || !lpNewFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpExistingFileNameW = MultiByteToWideCharInternal(lpExistingFileName, settings.CodePage);
	if (!lpExistingFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	LPWSTR lpNewFileNameW = MultiByteToWideCharInternal(lpNewFileName, settings.CodePage);
	if (!lpNewFileNameW) {
		FreeStringInternal(lpExistingFileNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = MoveFileW(lpExistingFileNameW, lpNewFileNameW);

	FreeStringInternal(lpExistingFileNameW);
	FreeStringInternal(lpNewFileNameW);

	return ret;
}

DWORD WINAPI HookGetFullPathNameA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD nBufferLength,
	_Out_opt_ LPSTR lpBuffer,
	_Outptr_opt_ LPSTR* lpFilePart
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (lpBuffer)
		*lpBuffer = '\0'; // Initialize output buffer

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD requiredSizeW = GetFullPathNameW(lpFileNameW, 0, NULL, NULL);
	if (requiredSizeW == 0) {
		FreeStringInternal(lpFileNameW);
		return 0;
	}

	LPWSTR lpBufferW = (LPWSTR)AllocateZeroedMemory(requiredSizeW * sizeof(WCHAR));
	if (!lpBufferW) {
		FreeStringInternal(lpFileNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	LPWSTR lpFilePartW = NULL;
	DWORD resultW = GetFullPathNameW(lpFileNameW, requiredSizeW, lpBufferW, lpFilePartW ? &lpFilePartW : NULL);

	if (resultW == 0) {
		FreeStringInternal(lpFileNameW);
		FreeStringInternal(lpBufferW);
		return 0;
	}

	LPSTR fullPathA = WideCharToMultiByteInternal(lpBufferW, settings.CodePage);
	if (!fullPathA) {
		FreeStringInternal(lpFileNameW);
		FreeStringInternal(lpBufferW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD requiredSizeA = strlen(fullPathA) + 1;

	// If buffer is provided, copy the result
	if (lpBuffer && nBufferLength > 0) {
		strncpy(lpBuffer, fullPathA, nBufferLength - 1);
		lpBuffer[nBufferLength - 1] = '\0';

		// Set the file part pointer if requested
		if (lpFilePart) {
			if (lpFilePartW) {
				// Calculate offset in wide string and map to ANSI string
				ptrdiff_t offset = lpFilePartW - lpBufferW;
				// Apply the same offset to the ANSI string
				*lpFilePart = lpBuffer + offset;
			} else {
				*lpFilePart = NULL;
			}
		}
	}

	FreeStringInternal(lpFileNameW);
	FreeStringInternal(lpBufferW);
	FreeStringInternal(fullPathA);

	return requiredSizeA;
}

HANDLE WINAPI HookCreateFileMappingA(
	_In_ HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_ DWORD flProtect,
	_In_ DWORD dwMaximumSizeHigh,
	_In_ DWORD dwMaximumSizeLow,
	_In_opt_ LPCSTR lpName
)
{
	//DEBUG_FUNCTION_TRACE();
	LPWSTR lpNameW = nullptr;

	if (lpName) {
		lpNameW = MultiByteToWideCharInternal(lpName, settings.CodePage);
		if (!lpNameW) {
			SetLastError(ERROR_OUTOFMEMORY);
			return NULL;
		}
	}

	HANDLE ret = CreateFileMappingW(
		hFile,
		lpFileMappingAttributes,
		flProtect,
		dwMaximumSizeHigh,
		dwMaximumSizeLow,
		lpNameW
	);

	FreeStringInternal(lpNameW);

	return ret;
}

HMODULE WINAPI HookLoadLibraryA(
	_In_ LPCSTR lpLibFileName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpLibFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	LPWSTR lpLibFileNameW = MultiByteToWideCharInternal(lpLibFileName, settings.CodePage);
	if (!lpLibFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}

	HMODULE ret = LoadLibraryW(lpLibFileNameW);

	FreeStringInternal(lpLibFileNameW);

	return ret;
}

DWORD WINAPI HookGetModuleFileNameA(
	_In_opt_ HMODULE hModule,
	_Out_writes_(MAX_PATH) LPSTR lpFilename,
	_In_ DWORD nSize
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFilename || nSize == 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Buffer for wide char path - doubling the size to be safe
	LPWSTR lpFileNameW = (LPWSTR)AllocateZeroedMemory(nSize * sizeof(WCHAR));
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD result = GetModuleFileNameW(hModule, lpFileNameW, nSize);

	if (result == 0) {
		FreeStringInternal(lpFileNameW);
		return 0;
	}

	// Convert back to ANSI
	LPSTR ansiPath = WideCharToMultiByteInternal(lpFileNameW, settings.CodePage);
	if (!ansiPath) {
		FreeStringInternal(lpFileNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Copy to output buffer
	size_t len = strlen(ansiPath);
	if (len > nSize - 1) 
		len = nSize - 1;
	strncpy(lpFilename, ansiPath, len);
	lpFilename[len] = '\0';

	FreeStringInternal(lpFileNameW);
	FreeStringInternal(ansiPath);

	// If the buffer was too small, return nSize
	if (len >= nSize) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return nSize;
	}

	return len;
}

DWORD WINAPI HookGetTempPathA(
	_In_ DWORD nBufferLength,
	_Out_writes_(MAX_PATH) LPSTR lpBuffer
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpBuffer && nBufferLength > 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Get the temp path in wide chars first
	WCHAR wideBuffer[MAX_PATH + 1];
	DWORD result = GetTempPathW(MAX_PATH, wideBuffer);

	if (result == 0) {
		return 0;
	}

	// Convert to ANSI
	LPSTR ansiPath = WideCharToMultiByteInternal(wideBuffer, settings.CodePage);
	if (!ansiPath) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD requiredLength = strlen(ansiPath) + 1;

	// If buffer is provided and large enough, copy the result
	if (lpBuffer && nBufferLength >= requiredLength) {
		strcpy(lpBuffer, ansiPath);
	}

	FreeStringInternal(ansiPath);

	return requiredLength - 1; // Return length without null terminator
}

UINT WINAPI HookGetTempFileNameA(
	_In_ LPCSTR lpPathName,
	_In_ LPCSTR lpPrefixString,
	_In_ UINT uUnique,
	_Out_writes_(MAX_PATH) LPSTR lpTempFileName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpPathName || !lpPrefixString || !lpTempFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	LPWSTR lpPathNameW = MultiByteToWideCharInternal(lpPathName, settings.CodePage);
	if (!lpPathNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	LPWSTR lpPrefixStringW = MultiByteToWideCharInternal(lpPrefixString, settings.CodePage);
	if (!lpPrefixStringW) {
		FreeStringInternal(lpPathNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	WCHAR tempFileNameW[MAX_PATH];
	UINT result = GetTempFileNameW(lpPathNameW, lpPrefixStringW, uUnique, tempFileNameW);

	if (result != 0) {
		LPSTR ansiTempFileName = WideCharToMultiByteInternal(tempFileNameW, settings.CodePage);
		if (ansiTempFileName) {
			strcpy(lpTempFileName, ansiTempFileName);
			FreeStringInternal(ansiTempFileName);
		} else {
			result = 0;
			SetLastError(ERROR_OUTOFMEMORY);
		}
	}

	FreeStringInternal(lpPathNameW);
	FreeStringInternal(lpPrefixStringW);

	return result;
}

BOOL WINAPI HookGetFileVersionInfoA(
	_In_ LPCSTR lptstrFilename,
	_Reserved_ DWORD dwHandle,
	_In_ DWORD dwLen,
	_Out_writes_bytes_(dwLen) LPVOID lpData
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lptstrFilename || !lpData) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lptstrFilename, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL result = GetFileVersionInfoW(lpFileNameW, dwHandle, dwLen, lpData);

	FreeStringInternal(lpFileNameW);

	return result;
}

BOOL WINAPI HookRemoveDirectoryA(
	_In_ LPCSTR lpPathName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpPathName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpPathNameW = MultiByteToWideCharInternal(lpPathName, settings.CodePage);
	if (!lpPathNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL result = RemoveDirectoryW(lpPathNameW);

	FreeStringInternal(lpPathNameW);

	return result;
}

BOOL WINAPI HookSetCurrentDirectoryA(
	_In_ LPCSTR lpPathName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpPathName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpPathNameW = MultiByteToWideCharInternal(lpPathName, settings.CodePage);
	if (!lpPathNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL result = SetCurrentDirectoryW(lpPathNameW);

	FreeStringInternal(lpPathNameW);

	return result;
}

DWORD WINAPI HookGetCurrentDirectoryA(
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpBuffer && nBufferLength > 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Get the current directory in wide chars
	DWORD requiredSizeW = GetCurrentDirectoryW(0, NULL);
	if (requiredSizeW == 0) {
		return 0;
	}

	LPWSTR currentDirW = (LPWSTR)AllocateZeroedMemory(requiredSizeW * sizeof(WCHAR));
	if (!currentDirW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD result = GetCurrentDirectoryW(requiredSizeW, currentDirW);
	if (result == 0) {
		FreeStringInternal(currentDirW);
		return 0;
	}

	// Convert to ANSI
	LPSTR currentDirA = WideCharToMultiByteInternal(currentDirW, settings.CodePage);
	if (!currentDirA) {
		FreeStringInternal(currentDirW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD requiredSizeA = strlen(currentDirA) + 1;

	// If buffer is provided and large enough, copy the result
	if (lpBuffer && nBufferLength >= requiredSizeA) {
		strcpy(lpBuffer, currentDirA);
	}

	FreeStringInternal(currentDirW);
	FreeStringInternal(currentDirA);

	return requiredSizeA - 1; // Return length without null terminator
}


HANDLE WINAPI HookFindFirstFileExA(
	_In_ LPCSTR lpFileName,
	_In_ FINDEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FIND_DATAA)) LPVOID lpFindFileData,
	_In_ FINDEX_SEARCH_OPS fSearchOp,
	_Reserved_ LPVOID lpSearchFilter,
	_In_ DWORD dwAdditionalFlags
)
{
	//DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE_VALUE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return INVALID_HANDLE_VALUE;
	}

	// Need to convert it to the A format
	WIN32_FIND_DATAW findDataW = { 0 };
	HANDLE ret = FindFirstFileExW(
		lpFileNameW,
		fInfoLevelId,
		(fInfoLevelId == FindExInfoStandard || fInfoLevelId == FindExInfoBasic) ? &findDataW : lpFindFileData,
		fSearchOp,
		lpSearchFilter,
		dwAdditionalFlags
	);

	// If successful and we need to convert the data back
	if (ret != INVALID_HANDLE_VALUE && 
		(fInfoLevelId == FindExInfoStandard || fInfoLevelId == FindExInfoBasic)) {
		WIN32_FIND_DATAA* findDataA = (WIN32_FIND_DATAA*)lpFindFileData;

		// Copy non-string data
		findDataA->dwFileAttributes = findDataW.dwFileAttributes;
		findDataA->ftCreationTime = findDataW.ftCreationTime;
		findDataA->ftLastAccessTime = findDataW.ftLastAccessTime;
		findDataA->ftLastWriteTime = findDataW.ftLastWriteTime;
		findDataA->nFileSizeHigh = findDataW.nFileSizeHigh;
		findDataA->nFileSizeLow = findDataW.nFileSizeLow;
		findDataA->dwReserved0 = findDataW.dwReserved0;
		findDataA->dwReserved1 = findDataW.dwReserved1;

		// Convert file name
		WideCharToMultiByte(settings.CodePage, 0, findDataW.cFileName, -1, 
							findDataA->cFileName, MAX_PATH, NULL, NULL);

		// Convert alternate file name
		WideCharToMultiByte(settings.CodePage, 0, findDataW.cAlternateFileName, -1, 
							findDataA->cAlternateFileName, 14, NULL, NULL);
	}

	FreeStringInternal(lpFileNameW);
	return ret;
}

DWORD WINAPI HookGetLongPathNameA(
	_In_ LPCSTR lpszShortPath,
	_Out_writes_(cchBuffer) LPSTR lpszLongPath,
	_In_ DWORD cchBuffer
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpszShortPath) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	LPWSTR lpszShortPathW = MultiByteToWideCharInternal(lpszShortPath, settings.CodePage);
	if (!lpszShortPathW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Allocate buffer for wide result
	DWORD requiredSize = GetLongPathNameW(lpszShortPathW, NULL, 0);
	if (requiredSize == 0) {
		DWORD error = GetLastError();
		FreeStringInternal(lpszShortPathW);
		SetLastError(error);
		return 0;
	}

	LPWSTR lpszLongPathW = (LPWSTR)AllocateZeroedMemory(requiredSize * sizeof(WCHAR));
	if (!lpszLongPathW) {
		FreeStringInternal(lpszShortPathW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD result = GetLongPathNameW(lpszShortPathW, lpszLongPathW, requiredSize);
	FreeStringInternal(lpszShortPathW);

	if (result == 0) {
		DWORD error = GetLastError();
		FreeStringInternal(lpszLongPathW);
		SetLastError(error);
		return 0;
	}

	// Convert result back to ANSI
	DWORD ansiLength = WideCharToMultiByte(settings.CodePage, 0,lpszLongPathW, -1, NULL, 0, NULL, NULL);

	if (lpszLongPath && cchBuffer > 0) {
		if (ansiLength <= cchBuffer) {
			WideCharToMultiByte(settings.CodePage, 0, lpszLongPathW, -1, 
							   lpszLongPath, cchBuffer, NULL, NULL);
			result = ansiLength - 1; // Don't count null terminator
		} else {
			// Buffer too small, return required size
			result = ansiLength - 1;
		}
	} else {
		// Just return required buffer size
		result = ansiLength - 1;
	}

	FreeStringInternal(lpszLongPathW);
	return result;
}

DWORD WINAPI HookGetShortPathNameA(
	_In_ LPCSTR lpszLongPath,
	_Out_writes_(cchBuffer) LPSTR lpszShortPath,
	_In_ DWORD cchBuffer
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpszLongPath) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	LPWSTR lpszLongPathW = MultiByteToWideCharInternal(lpszLongPath, settings.CodePage);
	if (!lpszLongPathW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Allocate buffer for wide result
	DWORD requiredSize = GetShortPathNameW(lpszLongPathW, NULL, 0);
	if (requiredSize == 0) {
		DWORD error = GetLastError();
		FreeStringInternal(lpszLongPathW);
		SetLastError(error);
		return 0;
	}

	LPWSTR lpszShortPathW = (LPWSTR)AllocateZeroedMemory(requiredSize * sizeof(WCHAR));
	if (!lpszShortPathW) {
		FreeStringInternal(lpszLongPathW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD result = GetShortPathNameW(lpszLongPathW, lpszShortPathW, requiredSize);
	FreeStringInternal(lpszLongPathW);

	if (result == 0) {
		DWORD error = GetLastError();
		FreeStringInternal(lpszShortPathW);
		SetLastError(error);
		return 0;
	}

	// Convert result back to ANSI
	DWORD ansiLength = WideCharToMultiByte(settings.CodePage, 0, 
										  lpszShortPathW, -1, NULL, 0, NULL, NULL);

	if (lpszShortPath && cchBuffer > 0) {
		if (ansiLength <= cchBuffer) {
			WideCharToMultiByte(settings.CodePage, 0, lpszShortPathW, -1, 
							   lpszShortPath, cchBuffer, NULL, NULL);
			result = ansiLength - 1; // Don't count null terminator
		} else {
			// Buffer too small, return required size
			result = ansiLength - 1;
		}
	} else {
		// Just return required buffer size
		result = ansiLength - 1;
	}

	FreeStringInternal(lpszShortPathW);
	return result;
}

BOOL WINAPI HookSetFileAttributesA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwFileAttributes
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = SetFileAttributesW(lpFileNameW, dwFileAttributes);

	FreeStringInternal(lpFileNameW);
	return ret;
}

UINT WINAPI HookGetDriveTypeA(
	_In_opt_ LPCSTR lpRootPathName
)
{
	DEBUG_FUNCTION_TRACE();
	// Handle NULL path
	if (!lpRootPathName) {
		return GetDriveTypeW(NULL);
	}

	LPWSTR lpRootPathNameW = MultiByteToWideCharInternal(lpRootPathName, settings.CodePage);
	if (!lpRootPathNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return DRIVE_UNKNOWN;
	}

	UINT ret = GetDriveTypeW(lpRootPathNameW);

	FreeStringInternal(lpRootPathNameW);
	return ret;
}

BOOL WINAPI HookGetVolumeInformationA(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_writes_opt_(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
	_In_ DWORD nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_writes_opt_(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
	_In_ DWORD nFileSystemNameSize
)
{
	DEBUG_FUNCTION_TRACE();
	LPWSTR lpRootPathNameW = NULL;
	LPWSTR lpVolumeNameBufferW = NULL;
	LPWSTR lpFileSystemNameBufferW = NULL;
	BOOL ret = FALSE;

	// Convert root path if provided
	if (lpRootPathName) {
		lpRootPathNameW = MultiByteToWideCharInternal(lpRootPathName, settings.CodePage);
		if (!lpRootPathNameW) {
			SetLastError(ERROR_OUTOFMEMORY);
			goto cleanup;
		}
	}

	// Allocate buffers for wide char results if needed
	if (lpVolumeNameBuffer && nVolumeNameSize > 0) {
		lpVolumeNameBufferW = (LPWSTR)AllocateZeroedMemory(nVolumeNameSize * sizeof(WCHAR));
		if (!lpVolumeNameBufferW) {
			SetLastError(ERROR_OUTOFMEMORY);
			goto cleanup;
		}
	}

	if (lpFileSystemNameBuffer && nFileSystemNameSize > 0) {
		lpFileSystemNameBufferW = (LPWSTR)AllocateZeroedMemory(nFileSystemNameSize * sizeof(WCHAR));
		if (!lpFileSystemNameBufferW) {
			SetLastError(ERROR_OUTOFMEMORY);
			goto cleanup;
		}
	}

	// Call the wide version
	ret = GetVolumeInformationW(
		lpRootPathNameW,
		lpVolumeNameBufferW,
		lpVolumeNameBuffer ? nVolumeNameSize : 0,
		lpVolumeSerialNumber,
		lpMaximumComponentLength,
		lpFileSystemFlags,
		lpFileSystemNameBufferW,
		lpFileSystemNameBuffer ? nFileSystemNameSize : 0
	);

	if (ret) {
		// Convert results back to ANSI if needed
		if (lpVolumeNameBuffer && nVolumeNameSize > 0) {
			WideCharToMultiByte(settings.CodePage, 0, lpVolumeNameBufferW, -1,
							   lpVolumeNameBuffer, nVolumeNameSize, NULL, NULL);
		}

		if (lpFileSystemNameBuffer && nFileSystemNameSize > 0) {
			WideCharToMultiByte(settings.CodePage, 0, lpFileSystemNameBufferW, -1,
							   lpFileSystemNameBuffer, nFileSystemNameSize, NULL, NULL);
		}
	}

cleanup:
	if (lpRootPathNameW) FreeStringInternal(lpRootPathNameW);
	if (lpVolumeNameBufferW) FreeStringInternal(lpVolumeNameBufferW);
	if (lpFileSystemNameBufferW) FreeStringInternal(lpFileSystemNameBufferW);

	return ret;
}

BOOL WINAPI HookGetDiskFreeSpaceA(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_opt_ LPDWORD lpSectorsPerCluster,
	_Out_opt_ LPDWORD lpBytesPerSector,
	_Out_opt_ LPDWORD lpNumberOfFreeClusters,
	_Out_opt_ LPDWORD lpTotalNumberOfClusters
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpRootPathName) {
		return GetDiskFreeSpaceW(NULL, lpSectorsPerCluster, lpBytesPerSector,
								lpNumberOfFreeClusters, lpTotalNumberOfClusters);
	}

	LPWSTR lpRootPathNameW = MultiByteToWideCharInternal(lpRootPathName, settings.CodePage);
	if (!lpRootPathNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = GetDiskFreeSpaceW(lpRootPathNameW, lpSectorsPerCluster, lpBytesPerSector,
								lpNumberOfFreeClusters, lpTotalNumberOfClusters);

	FreeStringInternal(lpRootPathNameW);
	return ret;
}

BOOL WINAPI HookGetDiskFreeSpaceExA(
	_In_opt_ LPCSTR lpDirectoryName,
	_Out_opt_ PULARGE_INTEGER lpFreeBytesAvailableToCaller,
	_Out_opt_ PULARGE_INTEGER lpTotalNumberOfBytes,
	_Out_opt_ PULARGE_INTEGER lpTotalNumberOfFreeBytes
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpDirectoryName) {
		return GetDiskFreeSpaceExW(NULL, lpFreeBytesAvailableToCaller,
								  lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
	}

	LPWSTR lpDirectoryNameW = MultiByteToWideCharInternal(lpDirectoryName, settings.CodePage);
	if (!lpDirectoryNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = GetDiskFreeSpaceExW(lpDirectoryNameW, lpFreeBytesAvailableToCaller,
								  lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);

	FreeStringInternal(lpDirectoryNameW);
	return ret;
}

DWORD WINAPI HookGetLogicalDrives(VOID)
{
	DEBUG_FUNCTION_TRACE();
	// No string conversion needed
	return OriginalGetLogicalDrives();
}

DWORD WINAPI HookGetLogicalDriveStringsA(
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer
)
{
	DEBUG_FUNCTION_TRACE();
	// Get the required buffer size for wide char result
	DWORD wideLength = GetLogicalDriveStringsW(0, NULL);
	if (wideLength == 0) {
		return 0;
	}

	// Allocate buffer for wide result
	LPWSTR lpBufferW = (LPWSTR)AllocateZeroedMemory(wideLength * sizeof(WCHAR));
	if (!lpBufferW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Get the wide char result
	DWORD result = GetLogicalDriveStringsW(wideLength, lpBufferW);
	if (result == 0) {
		DWORD error = GetLastError();
		FreeStringInternal(lpBufferW);
		SetLastError(error);
		return 0;
	}

	// Calculate required buffer size for ANSI result
	DWORD ansiLength = 0;
	LPWSTR tempPtr = lpBufferW;
	while (*tempPtr) {
		int len = lstrlenW(tempPtr) + 1;
		ansiLength += WideCharToMultiByte(settings.CodePage, 0, tempPtr, len, NULL, 0, NULL, NULL);
		tempPtr += len;
	}

	// If buffer is provided, convert the result
	if (lpBuffer && nBufferLength > 0) {
		if (ansiLength <= nBufferLength) {
			LPSTR ansiPtr = lpBuffer;
			DWORD remainingLength = nBufferLength;
			tempPtr = lpBufferW;

			while (*tempPtr && remainingLength > 0) {
				int wideLen = lstrlenW(tempPtr) + 1;
				int ansiLen = WideCharToMultiByte(settings.CodePage, 0, tempPtr, wideLen,
												ansiPtr, remainingLength, NULL, NULL);

				ansiPtr += ansiLen;
				remainingLength -= ansiLen;
				tempPtr += wideLen;
			}

			// Ensure double null-termination
			if (remainingLength > 0) {
				*ansiPtr = '\0';
			}

			result = ansiLength - 1; // Don't count the final null terminator
		} else {
			// Buffer too small
			result = ansiLength;
		}
	} else {
		// Just return the required buffer size
		result = ansiLength;
	}

	FreeStringInternal(lpBufferW);
	return result;
}

BOOL WINAPI HookCreateHardLinkA(
	_In_ LPCSTR lpFileName,
	_In_ LPCSTR lpExistingFileName,
	_Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpFileName || !lpExistingFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	LPWSTR lpExistingFileNameW = MultiByteToWideCharInternal(lpExistingFileName, settings.CodePage);
	if (!lpExistingFileNameW) {
		FreeStringInternal(lpFileNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = CreateHardLinkW(lpFileNameW, lpExistingFileNameW, lpSecurityAttributes);

	FreeStringInternal(lpFileNameW);
	FreeStringInternal(lpExistingFileNameW);

	return ret;
}

BOOLEAN WINAPI HookCreateSymbolicLinkA(
	_In_ LPCSTR lpSymlinkFileName,
	_In_ LPCSTR lpTargetFileName,
	_In_ DWORD dwFlags
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpSymlinkFileName || !lpTargetFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpSymlinkFileNameW = MultiByteToWideCharInternal(lpSymlinkFileName, settings.CodePage);
	if (!lpSymlinkFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	LPWSTR lpTargetFileNameW = MultiByteToWideCharInternal(lpTargetFileName, settings.CodePage);
	if (!lpTargetFileNameW) {
		FreeStringInternal(lpSymlinkFileNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOLEAN ret = CreateSymbolicLinkW(lpSymlinkFileNameW, lpTargetFileNameW, dwFlags);

	FreeStringInternal(lpSymlinkFileNameW);
	FreeStringInternal(lpTargetFileNameW);

	return ret;
}

LSTATUS WINAPI HookRegOpenKeyExA(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpSubKey,
	_In_opt_ DWORD ulOptions,
	_In_ REGSAM samDesired,
	_Out_ PHKEY phkResult
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpSubKey) {
		return RegOpenKeyExW(hKey, NULL, ulOptions, samDesired, phkResult);
	}

	LPWSTR lpSubKeyW = MultiByteToWideCharInternal(lpSubKey, settings.CodePage);
	if (!lpSubKeyW) {
		return ERROR_OUTOFMEMORY;
	}

	LSTATUS ret = RegOpenKeyExW(hKey, lpSubKeyW, ulOptions, samDesired, phkResult);

	FreeStringInternal(lpSubKeyW);

	return ret;
}

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
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpSubKey) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return ERROR_INVALID_PARAMETER;
	}

	LPWSTR lpSubKeyW = MultiByteToWideCharInternal(lpSubKey, settings.CodePage);
	if (!lpSubKeyW) {
		return ERROR_OUTOFMEMORY;
	}

	LPWSTR lpClassW = NULL;
	if (lpClass) {
		lpClassW = MultiByteToWideCharInternal(lpClass, settings.CodePage);
		if (!lpClassW) {
			FreeStringInternal(lpSubKeyW);
			return ERROR_OUTOFMEMORY;
		}
	}

	LSTATUS ret = RegCreateKeyExW(
		hKey,
		lpSubKeyW,
		Reserved,
		lpClassW,
		dwOptions,
		samDesired,
		lpSecurityAttributes,
		phkResult,
		lpdwDisposition
	);

	FreeStringInternal(lpSubKeyW);
	if (lpClassW) FreeStringInternal(lpClassW);

	return ret;
}

LSTATUS WINAPI HookRegQueryValueExA(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ LPDWORD lpReserved,
	_Out_opt_ LPDWORD lpType,
	_Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) LPBYTE lpData,
	_Inout_opt_ LPDWORD lpcbData
)
{
	DEBUG_FUNCTION_TRACE();
	LPWSTR lpValueNameW = NULL;
	LSTATUS ret = ERROR_SUCCESS;
	DWORD dataType = 0;
	LPBYTE lpDataW = NULL;
	DWORD cbDataW = 0;

	// Convert value name if provided
	if (lpValueName) {
		lpValueNameW = MultiByteToWideCharInternal(lpValueName, settings.CodePage);
		if (!lpValueNameW) {
			return ERROR_OUTOFMEMORY;
		}
	}

	// First query to get the type and size
	ret = RegQueryValueExW(hKey, lpValueNameW, lpReserved, &dataType, NULL, &cbDataW);
	if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) {
		if (lpValueNameW) FreeStringInternal(lpValueNameW);
		return ret;
	}

	// If caller only wanted the size or type
	if (!lpData || !lpcbData || *lpcbData == 0) {
		if (lpType) *lpType = dataType;
		if (lpcbData) {
			// For string values, we need to adjust the size for ANSI
			if (dataType == REG_SZ || dataType == REG_EXPAND_SZ || dataType == REG_MULTI_SZ) {
				// Allocate buffer for wide data
				lpDataW = (LPBYTE)AllocateZeroedMemory(cbDataW);
				if (!lpDataW) {
					if (lpValueNameW) FreeStringInternal(lpValueNameW);
					return ERROR_OUTOFMEMORY;
				}

				// Get the wide string data
				ret = RegQueryValueExW(hKey, lpValueNameW, lpReserved, NULL, lpDataW, &cbDataW);
				if (ret != ERROR_SUCCESS) {
					FreeStringInternal(lpDataW);
					if (lpValueNameW) FreeStringInternal(lpValueNameW);
					return ret;
				}

				DWORD ansiSize = 0;  
				if (dataType == REG_MULTI_SZ) {
					// For REG_MULTI_SZ, we need to process each string
					LPWSTR strPtr = (LPWSTR)lpDataW;
					while (*strPtr) {
						DWORD strLen = WideCharToMultiByte(settings.CodePage, 0, strPtr, -1, 
														 NULL, 0, NULL, NULL);
						ansiSize += strLen;
						strPtr += wcslen(strPtr) + 1;
					}
					// Add final null terminator
					ansiSize++;
				} else {
					// For REG_SZ and REG_EXPAND_SZ
					ansiSize = WideCharToMultiByte(settings.CodePage, 0, (LPCWSTR)lpDataW, -1, 
												 NULL, 0, NULL, NULL);
				}

				*lpcbData = ansiSize;
				FreeStringInternal(lpDataW);
			} else {
				// For non-string data, size is the same
				*lpcbData = cbDataW;
			}
		}

		if (lpValueNameW) FreeStringInternal(lpValueNameW);
		return ret;
	}

	// If we're retrieving actual data
	if (dataType == REG_SZ || dataType == REG_EXPAND_SZ || dataType == REG_MULTI_SZ) {
		lpDataW = (LPBYTE)AllocateZeroedMemory(cbDataW);
		if (!lpDataW) {
			if (lpValueNameW) FreeStringInternal(lpValueNameW);
			return ERROR_OUTOFMEMORY;
		}

		// Get the wide string data
		ret = RegQueryValueExW(hKey, lpValueNameW, lpReserved, NULL, lpDataW, &cbDataW);
		if (ret != ERROR_SUCCESS) {
			FreeStringInternal(lpDataW);
			if (lpValueNameW) FreeStringInternal(lpValueNameW);
			return ret;
		}

		// Convert to ANSI
		if (dataType == REG_MULTI_SZ) {
			// For REG_MULTI_SZ, we need to process each string
			LPWSTR widePtr = (LPWSTR)lpDataW;
			LPSTR ansiPtr = (LPSTR)lpData;
			DWORD remainingSpace = *lpcbData;
			DWORD totalSize = 0;

			while (*widePtr && remainingSpace > 0) {
				DWORD strLen = WideCharToMultiByte(settings.CodePage, 0, widePtr, -1, 
												 ansiPtr, remainingSpace, NULL, NULL);
				if (strLen == 0) {
					// Buffer too small
					ret = ERROR_MORE_DATA;
					break;
				}

				totalSize += strLen;
				remainingSpace -= strLen;
				ansiPtr += strLen;
				widePtr += wcslen(widePtr) + 1;
			}

			// Add final null terminator if there's room
			if (remainingSpace > 0 && ret == ERROR_SUCCESS) {
				*ansiPtr = '\0';
				totalSize++;
			} else if (ret == ERROR_SUCCESS)
				ret = ERROR_MORE_DATA;

			*lpcbData = totalSize;
		} else {
			// For REG_SZ and REG_EXPAND_SZ
			DWORD convertedSize = WideCharToMultiByte(settings.CodePage, 0, (LPCWSTR)lpDataW, -1, 
													(LPSTR)lpData, *lpcbData, NULL, NULL);
			if (convertedSize == 0)
				ret = ERROR_MORE_DATA;
			else
				*lpcbData = convertedSize;
		}
	} else {
		// For non-string data, just pass through
		ret = RegQueryValueExW(hKey, lpValueNameW, lpReserved, NULL, lpData, lpcbData);
	}

	if (lpType) *lpType = dataType;
	if (lpDataW) FreeStringInternal(lpDataW);
	if (lpValueNameW) FreeStringInternal(lpValueNameW);

	return ret;
}

LSTATUS WINAPI HookRegSetValueExA(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ DWORD Reserved,
	_In_ DWORD dwType,
	_In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
	_In_ DWORD cbData
)
{
	DEBUG_FUNCTION_TRACE();
	LPWSTR lpValueNameW = NULL;
	LPBYTE lpDataW = NULL;
	DWORD cbDataW = 0;
	LSTATUS ret = ERROR_SUCCESS;

	if (lpValueName) {
		lpValueNameW = MultiByteToWideCharInternal(lpValueName, settings.CodePage);
		if (!lpValueNameW)
			return ERROR_OUTOFMEMORY;
	}

	// For string types, convert the data
	if ((dwType == REG_SZ || dwType == REG_EXPAND_SZ) && lpData && cbData > 0) {
		cbDataW = MultiByteToWideChar(settings.CodePage, 0, (LPCSTR)lpData, -1, NULL, 0) * sizeof(WCHAR);
		lpDataW = (LPBYTE)AllocateZeroedMemory(cbDataW);
		if (!lpDataW) {
			if (lpValueNameW) FreeStringInternal(lpValueNameW);
			return ERROR_OUTOFMEMORY;
		}

		MultiByteToWideChar(settings.CodePage, 0, (LPCSTR)lpData, -1, (LPWSTR)lpDataW, cbDataW / sizeof(WCHAR));

		ret = RegSetValueExW(hKey, lpValueNameW, Reserved, dwType, lpDataW, cbDataW);
	} else if (dwType == REG_MULTI_SZ && lpData && cbData > 0) {
		// For REG_MULTI_SZ, we need to convert each string
		// First, calculate the size needed for wide strings
		LPCSTR ansiPtr = (LPCSTR)lpData;
		DWORD totalWideSize = 0;

		while (*ansiPtr) {
			DWORD strLen = MultiByteToWideChar(settings.CodePage, 0, ansiPtr, -1, NULL, 0);
			totalWideSize += strLen;
			ansiPtr += strlen(ansiPtr) + 1;
		}

		// Add final null terminator
		totalWideSize++;

		// Allocate buffer for wide data
		cbDataW = totalWideSize * sizeof(WCHAR);
		lpDataW = (LPBYTE)AllocateZeroedMemory(cbDataW);
		if (!lpDataW) {
			if (lpValueNameW) FreeStringInternal(lpValueNameW);
			return ERROR_OUTOFMEMORY;
		}

		// Convert each string
		ansiPtr = (LPCSTR)lpData;
		LPWSTR widePtr = (LPWSTR)lpDataW;

		while (*ansiPtr) {
			DWORD strLen = MultiByteToWideChar(settings.CodePage, 0, ansiPtr, -1, widePtr, totalWideSize);
			widePtr += strLen;
			totalWideSize -= strLen;
			ansiPtr += strlen(ansiPtr) + 1;
		}

		*widePtr = L'\0';

		ret = RegSetValueExW(hKey, lpValueNameW, Reserved, dwType, lpDataW, cbDataW);
	} else {
		// For non-string data, just pass through
		ret = RegSetValueExW(hKey, lpValueNameW, Reserved, dwType, lpData, cbData);
	}

	if (lpValueNameW) FreeStringInternal(lpValueNameW);
	if (lpDataW) FreeStringInternal(lpDataW);

	return ret;
}

HMODULE WINAPI HookLoadLibraryExA(
	_In_ LPCSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpLibFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	LPWSTR lpLibFileNameW = MultiByteToWideCharInternal(lpLibFileName, settings.CodePage);
	if (!lpLibFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}

	HMODULE ret = LoadLibraryExW(lpLibFileNameW, hFile, dwFlags);

	FreeStringInternal(lpLibFileNameW);

	return ret;
}

HMODULE WINAPI HookGetModuleHandleA(
	_In_opt_ LPCSTR lpModuleName
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpModuleName)
		return GetModuleHandleW(NULL);

	LPWSTR lpModuleNameW = MultiByteToWideCharInternal(lpModuleName, settings.CodePage);
	if (!lpModuleNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}

	HMODULE ret = GetModuleHandleW(lpModuleNameW);

	FreeStringInternal(lpModuleNameW);

	return ret;
}

BOOL WINAPI HookGetModuleHandleExA(
	_In_ DWORD dwFlags,
	_In_opt_ LPCSTR lpModuleName,
	_Out_ HMODULE* phModule
)
{
	DEBUG_FUNCTION_TRACE();
	if (!phModule) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (!lpModuleName)
		return GetModuleHandleExW(dwFlags, NULL, phModule);

	LPWSTR lpModuleNameW = MultiByteToWideCharInternal(lpModuleName, settings.CodePage);
	if (!lpModuleNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	BOOL ret = GetModuleHandleExW(dwFlags, lpModuleNameW, phModule);

	FreeStringInternal(lpModuleNameW);

	return ret;
}

LPSTR WINAPI HookGetCommandLineA(VOID)
{
	DEBUG_FUNCTION_TRACE();
	static LPSTR cachedCommandLineA = nullptr;

	if (cachedCommandLineA) {
		FreeStringInternal(cachedCommandLineA);
		cachedCommandLineA = nullptr;
	}

	LPCWSTR cmdLineW = GetCommandLineW();
	if (!cmdLineW)
		return nullptr;

	cachedCommandLineA = WideCharToMultiByteInternal(cmdLineW, settings.CodePage);
	return cachedCommandLineA;
}

VOID WINAPI HookGetStartupInfoA(
	_Out_ LPSTARTUPINFOA lpStartupInfo
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpStartupInfo)
		return;

	// Get the wide version
	STARTUPINFOW siW;
	ZeroMemory(&siW, sizeof(STARTUPINFOW));
	siW.cb = sizeof(STARTUPINFOW);

	GetStartupInfoW(&siW);

	// Copy non-string data
	lpStartupInfo->cb = sizeof(STARTUPINFOA);
	lpStartupInfo->lpReserved = nullptr;
	lpStartupInfo->dwFlags = siW.dwFlags;
	lpStartupInfo->wShowWindow = siW.wShowWindow;
	lpStartupInfo->dwX = siW.dwX;
	lpStartupInfo->dwY = siW.dwY;
	lpStartupInfo->dwXSize = siW.dwXSize;
	lpStartupInfo->dwYSize = siW.dwYSize;
	lpStartupInfo->dwXCountChars = siW.dwXCountChars;
	lpStartupInfo->dwYCountChars = siW.dwYCountChars;
	lpStartupInfo->dwFillAttribute = siW.dwFillAttribute;
	lpStartupInfo->dwFlags = siW.dwFlags;
	lpStartupInfo->wShowWindow = siW.wShowWindow;
	lpStartupInfo->cbReserved2 = siW.cbReserved2;
	lpStartupInfo->lpReserved2 = siW.lpReserved2;
	lpStartupInfo->hStdInput = siW.hStdInput;
	lpStartupInfo->hStdOutput = siW.hStdOutput;
	lpStartupInfo->hStdError = siW.hStdError;

	if (siW.lpDesktop)
		lpStartupInfo->lpDesktop = WideCharToMultiByteInternal(siW.lpDesktop, settings.CodePage);
	else
		lpStartupInfo->lpDesktop = nullptr;

	if (siW.lpTitle)
		lpStartupInfo->lpTitle = WideCharToMultiByteInternal(siW.lpTitle, settings.CodePage);
	else
		lpStartupInfo->lpTitle = nullptr;

	// Note: We're not freeing these strings because the application is expected to use them
	// This may cause a memory leak, but it's necessary for the API to work correctly
}

DWORD WINAPI HookGetEnvironmentVariableA(
	_In_opt_ LPCSTR lpName,
	_Out_opt_ LPSTR lpBuffer,
	_In_ DWORD nSize
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	LPWSTR lpNameW = MultiByteToWideCharInternal(lpName, settings.CodePage);
	if (!lpNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD requiredSize = GetEnvironmentVariableW(lpNameW, NULL, 0);
	if (requiredSize == 0) {
		FreeStringInternal(lpNameW);
		return 0; // Variable doesn't exist or error occurred
	}

	LPWSTR lpBufferW = (LPWSTR)AllocateZeroedMemory(requiredSize * sizeof(WCHAR));
	if (!lpBufferW) {
		FreeStringInternal(lpNameW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Get the actual value
	DWORD result = GetEnvironmentVariableW(lpNameW, lpBufferW, requiredSize);
	FreeStringInternal(lpNameW);

	if (result == 0) {
		FreeStringInternal(lpBufferW);
		return 0;
	}

	// Convert back to ANSI if buffer is provided
	if (lpBuffer && nSize > 0) {
		LPSTR ansiResult = WideCharToMultiByteInternal(lpBufferW, settings.CodePage);
		if (!ansiResult) {
			FreeStringInternal(lpBufferW);
			SetLastError(ERROR_OUTOFMEMORY);
			return 0;
		}

		SIZE_T ansiLen = strlen(ansiResult);
		if (ansiLen >= nSize) {
			// Buffer too small
			memcpy(lpBuffer, ansiResult, (nSize - 1) * sizeof(CHAR));
			lpBuffer[nSize - 1] = '\0';
			FreeStringInternal(ansiResult);
			FreeStringInternal(lpBufferW);
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return ansiLen + 1;
		} else {
			strcpy(lpBuffer, ansiResult);
			FreeStringInternal(ansiResult);
			FreeStringInternal(lpBufferW);
			return ansiLen;
		}
	}

	// If no buffer provided, just return required size
	LPSTR tempAnsi = WideCharToMultiByteInternal(lpBufferW, settings.CodePage);
	DWORD ansiLen = tempAnsi ? strlen(tempAnsi) : 0;

	if (tempAnsi) {
		FreeStringInternal(tempAnsi);
	}

	FreeStringInternal(lpBufferW);
	return ansiLen + 1; // Size including null terminator
}

BOOL WINAPI HookSetEnvironmentVariableA(
	_In_ LPCSTR lpName,
	_In_opt_ LPCSTR lpValue
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	LPWSTR lpNameW = MultiByteToWideCharInternal(lpName, settings.CodePage);
	if (!lpNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}

	LPWSTR lpValueW = NULL;
	if (lpValue) {
		lpValueW = MultiByteToWideCharInternal(lpValue, settings.CodePage);
		if (!lpValueW) {
			FreeStringInternal(lpNameW);
			SetLastError(ERROR_OUTOFMEMORY);
			return FALSE;
		}
	}

	BOOL ret = SetEnvironmentVariableW(lpNameW, lpValueW);

	FreeStringInternal(lpNameW);
	FreeStringInternal(lpValueW);

	return ret;
}

DWORD WINAPI HookExpandEnvironmentStringsA(
	_In_ LPCSTR lpSrc,
	_Out_opt_ LPSTR lpDst,
	_In_ DWORD nSize
)
{
	DEBUG_FUNCTION_TRACE();
	if (!lpSrc) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	LPWSTR lpSrcW = MultiByteToWideCharInternal(lpSrc, settings.CodePage);
	if (!lpSrcW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Get required buffer size
	DWORD requiredSizeW = ExpandEnvironmentStringsW(lpSrcW, NULL, 0);
	if (requiredSizeW == 0) {
		FreeStringInternal(lpSrcW);
		return 0;
	}

	// Allocate buffer for wide char result
	LPWSTR lpDstW = (LPWSTR)AllocateZeroedMemory(requiredSizeW * sizeof(WCHAR));
	if (!lpDstW) {
		FreeStringInternal(lpSrcW);
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Expand the environment strings
	DWORD resultW = ExpandEnvironmentStringsW(lpSrcW, lpDstW, requiredSizeW);
	FreeStringInternal(lpSrcW);

	if (resultW == 0) {
		FreeStringInternal(lpDstW);
		return 0;
	}

	// Convert back to ANSI
	LPSTR ansiResult = WideCharToMultiByteInternal(lpDstW, settings.CodePage);
	FreeStringInternal(lpDstW);

	if (!ansiResult) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	DWORD ansiLen = strlen(ansiResult) + 1; // Include null terminator

	// Copy to output buffer if provided
	if (lpDst && nSize > 0) {
		if (ansiLen > nSize) {
			// Buffer too small
			memcpy(lpDst, ansiResult, (nSize - 1) * sizeof(CHAR));
			lpDst[nSize - 1] = '\0';
			FreeStringInternal(ansiResult);
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return ansiLen; // Return required size
		} else {
			strcpy(lpDst, ansiResult);
			FreeStringInternal(ansiResult);
			return ansiLen;
		}
	}

	FreeStringInternal(ansiResult);
	return ansiLen;
}

#define CREATE_HOOK(name) \
	MH_CreateHook(name, Hook##name, reinterpret_cast<LPVOID*>(&Original##name));

#ifdef ENABLE_HIDING
extern NtQueryVirtualMemoryType OriginalNtQueryVirtualMemory;
extern NtQueryObjectType OriginalNtQueryObject;
extern NtQueryInformationFileType OriginalNtQueryInformationFile;
extern NtQuerySectionType OriginalNtQuerySection;
#endif

#ifdef TEST_MESSAGES
extern NtUserCreateWindowExType OriginalNtUserCreateWindowEx;
extern NtUserMessageCallType OriginalNtUserMessageCall;
#endif

void EnableApiHooks()
{
	DEBUG_FUNCTION_TRACE();
	MH_Initialize();

	// Process hiding
#ifdef ENABLE_HIDING
	CREATE_HOOK(NtQueryVirtualMemory)
	CREATE_HOOK(NtQueryVirtualMemory)
	CREATE_HOOK(NtQueryObject)
	CREATE_HOOK(NtQueryInformationFile)
	CREATE_HOOK(NtQuerySection)
#endif

	// Create hooks for the message-related functions
#ifdef TEST_MESSAGES
	CREATE_HOOK(NtUserCreateWindowEx)
	CREATE_HOOK(NtUserMessageCall)
#endif

	// Locale emulation
	CREATE_HOOK(GetACP)
	CREATE_HOOK(GetOEMCP)
	CREATE_HOOK(GetCPInfo)
	CREATE_HOOK(GetThreadLocale)
	CREATE_HOOK(GetSystemDefaultUILanguage)
	CREATE_HOOK(GetUserDefaultUILanguage)
	CREATE_HOOK(GetSystemDefaultLCID)
	CREATE_HOOK(GetUserDefaultLCID)
	CREATE_HOOK(GetSystemDefaultLangID)
	CREATE_HOOK(GetUserDefaultLangID)
	CREATE_HOOK(GetUserDefaultLocaleName);
	CREATE_HOOK(GetSystemDefaultLocaleName);

	CREATE_HOOK(MultiByteToWideChar)
	CREATE_HOOK(WideCharToMultiByte)

	CREATE_HOOK(CreateWindowExA)
	//CREATE_HOOK(DefWindowProcA)
	//CREATE_HOOK(CallWindowProcA)
	CREATE_HOOK(MessageBoxA)

	CREATE_HOOK(CharPrevExA)
	CREATE_HOOK(CharNextExA)
	CREATE_HOOK(IsDBCSLeadByteEx)
	CREATE_HOOK(SendMessageA)

	//CREATE_HOOK(NtCreateUserProcess)
	CREATE_HOOK(CreateProcessA)

	CREATE_HOOK(WinExec)
	//CREATE_HOOK(ShellExecuteA)
	//CREATE_HOOK(ShellExecuteW)
	//CREATE_HOOK(ShellExecuteExA)
	//CREATE_HOOK(ShellExecuteExW)

	CREATE_HOOK(SetWindowTextA)
	CREATE_HOOK(GetWindowTextA)
	CREATE_HOOK(DirectSoundEnumerateA)
	CREATE_HOOK(CreateFontA)
	CREATE_HOOK(CreateFontW)
	CREATE_HOOK(CreateFontIndirectA)
	CREATE_HOOK(CreateFontIndirectW)
	CREATE_HOOK(CreateFontIndirectExA)
	CREATE_HOOK(CreateFontIndirectExW)
	//CREATE_HOOK(TextOutA)
	CREATE_HOOK(DrawTextExA)
	CREATE_HOOK(GetClipboardData)
	CREATE_HOOK(SetClipboardData)

	//CREATE_HOOK(DialogBoxParamA)
	CREATE_HOOK(CreateDialogIndirectParamA)

	CREATE_HOOK(GetTimeZoneInformation)
	CREATE_HOOK(CreateDirectoryA)
	CREATE_HOOK(CreateFileA)

	CREATE_HOOK(GetLocaleInfoA)
	CREATE_HOOK(GetLocaleInfoW)

	//CREATE_HOOK(GetNumberFormatA);
	//CREATE_HOOK(GetNumberFormatW);

	// Filesystem functions
	CREATE_HOOK(CreateFileA)
	CREATE_HOOK(CreateDirectoryA)
	CREATE_HOOK(FindFirstFileA)
	CREATE_HOOK(FindNextFileA)
	CREATE_HOOK(FindFirstFileExA)
	CREATE_HOOK(GetFileAttributesA)
	CREATE_HOOK(DeleteFileA)
	CREATE_HOOK(CopyFileA)
	CREATE_HOOK(MoveFileA)
	CREATE_HOOK(GetFullPathNameA)
	CREATE_HOOK(CreateFileMappingA)
	CREATE_HOOK(LoadLibraryA)
	CREATE_HOOK(GetModuleFileNameA)
	CREATE_HOOK(GetTempPathA)
	CREATE_HOOK(GetTempFileNameA)
	CREATE_HOOK(GetFileVersionInfoA)
	CREATE_HOOK(RemoveDirectoryA)
	CREATE_HOOK(SetCurrentDirectoryA)
	CREATE_HOOK(GetCurrentDirectoryA)

	CREATE_HOOK(GetLongPathNameA)
	CREATE_HOOK(GetShortPathNameA)
	CREATE_HOOK(SetFileAttributesA)
	CREATE_HOOK(GetDriveTypeA)
	CREATE_HOOK(GetVolumeInformationA)
	CREATE_HOOK(GetDiskFreeSpaceA)
	CREATE_HOOK(GetDiskFreeSpaceExA)
	CREATE_HOOK(GetLogicalDrives)
	CREATE_HOOK(GetLogicalDriveStringsA)

	CREATE_HOOK(CreateHardLinkA)
	CREATE_HOOK(CreateSymbolicLinkA)

	// Registry functions (often used for file paths)
	CREATE_HOOK(RegOpenKeyExA)
	CREATE_HOOK(RegCreateKeyExA)
	CREATE_HOOK(RegQueryValueExA)
	CREATE_HOOK(RegSetValueExA)

	// Additional process/module functions
	CREATE_HOOK(LoadLibraryExA)
	CREATE_HOOK(GetModuleHandleA)
	CREATE_HOOK(GetModuleHandleExA)
	CREATE_HOOK(GetCommandLineA)
	CREATE_HOOK(GetStartupInfoA)
	CREATE_HOOK(GetEnvironmentVariableA)
	CREATE_HOOK(SetEnvironmentVariableA)
	CREATE_HOOK(ExpandEnvironmentStringsA)

	//if (settings.SingleLCID)
	//{
		//CREATE_HOOK(RegisterClassA)
		//CREATE_HOOK(RegisterClassExA)
	//}

	if (settings.HookIME)
	{
		if (Initial.CodePage == 936 && (settings.CodePage == 932 || settings.CodePage == 950))
		{
			CREATE_HOOK(ImmGetCompositionStringA)
			CREATE_HOOK(ImmGetCandidateListA)
		}
		else
		{
			CREATE_HOOK(ImmGetCompositionStringA)
			//CREATE_HOOK(ImmGetCandidateListA)
		}
	}

	MH_EnableHook(MH_ALL_HOOKS);
}

void DisableApiHooks()
{
	DEBUG_FUNCTION_TRACE();
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}