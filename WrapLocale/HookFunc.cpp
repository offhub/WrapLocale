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
	// Convert ANSI strings to wide character strings
	LPWSTR wApplicationName = NULL;
	LPWSTR wCommandLine = NULL;
	LPWSTR wCurrentDirectory = NULL;

	if (lpApplicationName)
		wApplicationName = MultiByteToWideCharInternal(lpApplicationName, CP_ACP);

	if (lpCommandLine)
		wCommandLine = MultiByteToWideCharInternal(lpCommandLine, CP_ACP);

	if (lpCurrentDirectory)
		wCurrentDirectory = MultiByteToWideCharInternal(lpCurrentDirectory, CP_ACP);

	// Convert STARTUPINFOA to STARTUPINFOW
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

	if (lpStartupInfo->lpDesktop)
		siW.lpDesktop = MultiByteToWideCharInternal(lpStartupInfo->lpDesktop, CP_ACP);

	if (lpStartupInfo->lpTitle)
		siW.lpTitle = MultiByteToWideCharInternal(lpStartupInfo->lpTitle, CP_ACP);

	// Call the original CreateProcessW
	BOOL result = OriginalCreateProcessW(
		wApplicationName,
		wCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		wCurrentDirectory,
		&siW,
		lpProcessInformation
	);

	// Free allocated memory
	if (wApplicationName)
		FreeStringInternal(wApplicationName);
	if (wCommandLine)
		FreeStringInternal(wCommandLine);
	if (wCurrentDirectory)
		FreeStringInternal(wCurrentDirectory);
	if (siW.lpDesktop)
		FreeStringInternal(siW.lpDesktop);
	if (siW.lpTitle)
		FreeStringInternal(siW.lpTitle);

	return result;
}


HWND WINAPI HookCreateWindowExA(
	DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
	int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	// Convert class name to Unicode if it's not NULL and not an atom
	LPCWSTR wstrlpClassName = NULL;
	if (lpClassName && !IS_INTRESOURCE(lpClassName)) {
		wstrlpClassName = MultiByteToWideCharInternal(lpClassName, settings.CodePage);
		// If conversion fails, fall back to original function
		if (!wstrlpClassName && lpClassName) {
			return OriginalCreateWindowExA(
				dwExStyle, lpClassName, lpWindowName, dwStyle,
				X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam
			);
		}
	} else {
		// Handle atom or NULL case
		wstrlpClassName = (LPCWSTR)lpClassName;
	}
	
	// Convert window name to Unicode
	LPCWSTR wstrlpWindowName = NULL;
	if (lpWindowName) {
		wstrlpWindowName = MultiByteToWideCharInternal(lpWindowName, settings.CodePage);
		// If conversion fails, fall back to original function
		if (!wstrlpWindowName) {
			if (wstrlpClassName && !IS_INTRESOURCE(lpClassName)) {
				FreeStringInternal((LPWSTR)wstrlpClassName);
			}
			return OriginalCreateWindowExA(
				dwExStyle, lpClassName, lpWindowName, dwStyle,
				X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam
			);
		}
	}
	
	// Call Unicode version of CreateWindowEx
	HWND ret = CreateWindowExW(
		dwExStyle,
		wstrlpClassName,
		wstrlpWindowName,
		dwStyle,
		X, Y, nWidth, nHeight,
		hWndParent, hMenu, hInstance, lpParam
	);

	if (wstrlpClassName && !IS_INTRESOURCE(lpClassName))
		FreeStringInternal((LPWSTR)wstrlpClassName);
	
	if (wstrlpWindowName)
		FreeStringInternal((LPWSTR)wstrlpWindowName);
	
	return ret;
}

int WINAPI HookMessageBoxA(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType)
{
	// Convert text to Unicode if not NULL
	LPCWSTR wlpText = NULL;
	if (lpText) {
		wlpText = MultiByteToWideCharInternal(lpText, settings.CodePage);
		if (!wlpText)
			return OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
	}
	
	// Convert caption to Unicode if not NULL
	LPCWSTR wlpCaption = NULL;
	if (lpCaption) {
		wlpCaption = MultiByteToWideCharInternal(lpCaption, settings.CodePage);
		if (!wlpCaption) {
			if (wlpText)
				FreeStringInternal((LPWSTR)wlpText);
			return OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
		}
	}

	// Call Unicode version of MessageBox
	int ret = MessageBoxW(hWnd, wlpText, wlpCaption, uType);

	if (wlpText)
		FreeStringInternal((LPWSTR)wlpText);
	
	if (wlpCaption)
		FreeStringInternal((LPWSTR)wlpCaption);
	
	return ret;
}

UINT WINAPI HookGetACP(void)
{
	return settings.CodePage;
}

UINT WINAPI HookGetOEMCP(void)
{
	return settings.CodePage;
}

BOOL WINAPI HookGetCPInfo(UINT CodePage,LPCPINFO lpCPInfo)
{
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
	// Handle window creation messages
	if (uMsg == WM_CREATE || uMsg == WM_NCCREATE)
		return ANSI_INLPCREATESTRUCT(hWnd, uMsg, wParam, lParam);

	// Handle MDI window creation
	if (uMsg == WM_MDICREATE)
		return ANSI_INLPMDICREATESTRUCT(hWnd, uMsg, wParam, lParam);

	// Handle messages where string is passed as input parameter
	switch (uMsg) {
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
	}
	// For all other messages, pass through to original function
	return OriginalSendMessageA(hWnd, uMsg, wParam, lParam);
}

int WINAPI HookMultiByteToWideChar(UINT CodePage, DWORD dwFlags,
	LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
{
	// CP_ACP (0) is the default ANSI code page
	// CP_OEMCP (1) is the default OEM code page
	// Replace only standard Windows code pages with our settings code page
	if (CodePage == CP_ACP || CodePage == CP_OEMCP || 
		(CodePage > 2 && CodePage < CP_UTF7)) {
		CodePage = settings.CodePage;
	}

	return OriginalMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

int WINAPI HookWideCharToMultiByte(UINT CodePage, DWORD dwFlags,
	LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
	if (CodePage == CP_ACP || CodePage == CP_OEMCP || 
		(CodePage > 2 && CodePage < CP_UTF7)) {
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
	// Prepare startup info with the provided show command
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFOA));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = (WORD)uCmdShow;
	
	// Attempt to create the process
	BOOL ret = CreateProcessA(
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
	BOOL ret = CreateProcessA(
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
	// Validate input parameters
	if (!lpFile || !*lpFile)
		return (HINSTANCE)SE_ERR_FNF; // File not found error
	
	// Prepare startup info with the provided show command
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
	// The environment will handle DLL injection automatically
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

BOOL WINAPI HookShellExecuteExA(
	_Inout_ SHELLEXECUTEINFOA* pExecInfo
)
{
	//MessageBoxA(NULL, pExecInfo->lpFile, "ShellExecuteExA", NULL);

	return OriginalShellExecuteExA(pExecInfo);
}

BOOL WINAPI HookShellExecuteExW(
	_Inout_ SHELLEXECUTEINFOW* pExecInfo
)
{
	//MessageBoxW(NULL, L"ShellExecuteExW", L"ShellExecuteExW", NULL);

	return OriginalShellExecuteExW(pExecInfo);
}

BOOL WINAPI HookSetWindowTextA(
	_In_ HWND hWnd,
	_In_opt_ LPCSTR lpString
)
{
	LPCWSTR wstr = lpString ? MultiByteToWideCharInternal(lpString, settings.CodePage) : NULL;
	BOOL ret = FALSE;
	if (lpString == NULL || wstr != NULL)
		ret = SetWindowTextW(hWnd, wstr);
	else
		ret = OriginalSetWindowTextA(hWnd, lpString);

	if (wstr)
		FreeStringInternal((LPWSTR)wstr);
	
	return ret;
	
	// Option 2: Use SendMessageA (commented out as alternative)
	// return SendMessageA(hWnd, WM_SETTEXT, 0, (LPARAM)lpString);
}

int WINAPI HookGetWindowTextA(
	_In_ HWND hWnd, 
	_Out_writes_(nMaxCount) LPSTR lpString, 
	_In_ int nMaxCount
)
{
	if (!lpString || nMaxCount <= 0)
		return 0;
	
	// Get the text length first
	int wlen = GetWindowTextLengthW(hWnd);
	if (wlen <= 0) { // No text or error
		if (nMaxCount > 0) lpString[0] = '\0';
		return 0;
	}
	
	// Allocate buffer for Unicode text (add space for null terminator)
	LPWSTR lpStringW = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (wlen + 1) * sizeof(WCHAR));
	if (!lpStringW) {
		if (nMaxCount > 0) lpString[0] = '\0';
		return 0;
	}
	
	// Get the Unicode text
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
		
	   
		if (lsize > 0 && lsize < nMaxCount) lpString[lsize] = '\0';
		else if (nMaxCount > 0) lpString[nMaxCount - 1] = '\0';
	} else {
		// No text or error
		if (nMaxCount > 0)
			lpString[0] = '\0';
	}

	HeapFree(GetProcessHeap(), 0, lpStringW);
	
	return lsize;
	
	// Alternative approach using SendMessageA (commented out)
	// return SendMessageA(hWnd, WM_GETTEXT, nMaxCount, (LPARAM)lpString);
}

LONG WINAPI HookImmGetCompositionStringA(
	HIMC hIMC, 
	DWORD dwIndex,
	LPSTR lpBuf,
	DWORD dwBufLen
)
{
	// Call original function to get composition string
	LONG ret = OriginalImmGetCompositionStringA(hIMC, dwIndex, lpBuf, dwBufLen);
	
	// Only process if we got data and have a buffer
	if (ret > 0 && lpBuf && dwBufLen > 0) {
		// Ensure the string is null-terminated for conversion
		if (ret < (LONG)dwBufLen) {
			lpBuf[ret] = '\0';
		} else {
			// Buffer is full, create a temporary null-terminated copy
			LPSTR tempBuf = (LPSTR)HeapAlloc(GetProcessHeap(), 0, ret + 1);
			if (!tempBuf)
				return ret; // Memory allocation failed
			
			memcpy(tempBuf, lpBuf, ret);
			tempBuf[ret] = '\0';
			
			// Convert to Unicode using original code page
			LPWSTR wstr = MultiByteToWideCharInternal(tempBuf, Initial.CodePage);
			HeapFree(GetProcessHeap(), 0, tempBuf);
		
			if (wstr) {
				// Convert back to multibyte using settings code page
				int wsize = lstrlenW(wstr);
				
				// Get required buffer size
				int requiredSize = WideCharToMultiByte(
					settings.CodePage, 0, wstr, wsize, NULL, 0, NULL, NULL);
				
				// Only proceed if we can fit the result
				if (requiredSize > 0 && requiredSize <= (LONG)dwBufLen) {
					// Convert to target code page
					int convertedSize = WideCharToMultiByte(
						settings.CodePage, 0, wstr, wsize, 
						lpBuf, dwBufLen, NULL, NULL);
					
					if (convertedSize > 0) {
						// Update return value to reflect new size
						ret = convertedSize;
						
						// Null-terminate if there's room
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
				// Convert to target code page
				int convertedSize = WideCharToMultiByte(
					settings.CodePage, 0, wstr, wsize, 
					lpBuf, dwBufLen, NULL, NULL);
				
				if (convertedSize > 0) {
					// Update return value to reflect new size
					ret = convertedSize;
					
					// Null-terminate if there's room
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
	HIMC hIMC,
	DWORD dwIndex,
	LPSTR lpBuf,
	DWORD dwBufLen
)
{
	// Get the size of Unicode composition string (in bytes)
	LONG wsize = ImmGetCompositionStringW(hIMC, dwIndex, NULL, 0);
	
	// Check for errors
	if (wsize <= 0)
		return wsize;
	
	// Allocate buffer for Unicode string
	LPWSTR wstr = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wsize + sizeof(WCHAR)); // +2 for null terminator
	if (!wstr)
		return -1; // Memory allocation failed
	
	// Get the Unicode composition string
	LONG result = ImmGetCompositionStringW(hIMC, dwIndex, wstr, wsize);
	if (result < 0) {
		HeapFree(GetProcessHeap(), 0, wstr);
		return result; // Return the error code
	}
	
	// wsize is in bytes
	int wchars = wsize / sizeof(WCHAR);
	wstr[wchars] = L'\0';
	
	// Get required buffer size for ANSI string
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
		HeapFree(GetProcessHeap(), 0, wstr);
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
	
	HeapFree(GetProcessHeap(), 0, wstr);
	
	if (lsize <= 0)
		return -1; // Conversion failed

	
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
	HIMC			hIMC,
	DWORD		   deIndex,
	LPCANDIDATELIST lpCandList,
	DWORD		   dwBufLen
)
{
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
	
	// Allocate buffer for Unicode candidate list
	LPCANDIDATELIST lpCandListW = (LPCANDIDATELIST)HeapAlloc(
		GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufLenW);
	
	if (!lpCandListW) 
		return OriginalImmGetCandidateListA(hIMC, deIndex, lpCandList, dwBufLen);
	
	// Get the Unicode candidate list
	DWORD retW = ImmGetCandidateListW(hIMC, deIndex, lpCandListW, dwBufLenW);
	if (retW == 0) { // Failed to get Unicode list, clean up and fall back
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpCandListW);
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
	for (DWORD i = 0; i < lpCandListW->dwCount && i < 32; i++) { // Limit to 32 for safety
		// Set the offset for this string
		lpCandList->dwOffset[i] = currentOffset;
		
		// Get pointer to the Unicode string
		LPWSTR wstr = (LPWSTR)((BYTE*)lpCandListW + lpCandListW->dwOffset[i]);
		
		// Get pointer to where we'll write the ANSI string
		LPSTR lstr = (LPSTR)((BYTE*)lpCandList + currentOffset);
		
		// Calculate remaining space
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
	

	HeapFree(GetProcessHeap(), 0, (LPVOID)lpCandListW);
	
	return currentOffset; // Return the actual size used
}

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
	if (iCharSet == DEFAULT_CHARSET) {
		// Map code page to charset
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, adjustedCharSet)
	}
	
	// Create font with Unicode name and adjusted charset
	HFONT ret = CreateFontW(
		cHeight, cWidth, cEscapement, cOrientation,
		cWeight, bItalic, bUnderline, bStrikeOut,
		adjustedCharSet, iOutPrecision, iClipPrecision,
		iQuality, iPitchAndFamily, pszFaceNameW
	);
	

	if (pszFaceNameW)
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
	// Adjust character set based on code page if needed
	DWORD adjustedCharSet = iCharSet;
	
	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (iCharSet == DEFAULT_CHARSET) {
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, adjustedCharSet)
	}
	
	// If settings specify a custom font substitution, replace face name
	LPCWSTR adjustedFaceName = pszFaceName;
	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		// Check if we should apply substitution
		bool applySubstitution = false;
		
		// If original font is NULL or empty, substitute
		if (!pszFaceName || pszFaceName[0] == L'\0') {
			applySubstitution = true;
		}
		// If this font is in our substitution list
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName : settings.FontsToSubstitute) {
				if (wcscmp(pszFaceName, fontName.c_str()) == 0) {
					applySubstitution = true;
					break;
				}
			}
		}
		
		if (applySubstitution) {
			adjustedFaceName = settings.SubstituteFontName;
		}
	}
	
	// Create font with potentially adjusted charset and face name
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

//set font characters set
HFONT WINAPI HookCreateFontIndirectA(
	LOGFONTA* lplf
)
{
	// Check for NULL input
	if (!lplf) {
		return NULL;
	}
	
	// Create a Unicode LOGFONTW structure
	LOGFONTW logfontW;
	ZeroMemory(&logfontW, sizeof(LOGFONTW));
	
	// Copy numeric values from ANSI structure to Unicode structure
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
	
	// Adjust character set based on code page if needed
	BYTE adjustedCharSet = lplf->lfCharSet;
	
	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (lplf->lfCharSet == DEFAULT_CHARSET) {
		// Map code page to charset
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
	
	// Apply font substitution if configured
	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		// Check if we should apply substitution
		bool applySubstitution = false;
		
		// If original font is empty, substitute
		if (logfontW.lfFaceName[0] == L'\0') {
			applySubstitution = true;
		}
		// If we're forcing substitution for all fonts
		else if (settings.SubstituteAllFonts) {
			applySubstitution = true;
		}
		// If this font is in our substitution list
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
	
	// Create font with Unicode structure
	return CreateFontIndirectW(&logfontW);
}

HFONT WINAPI HookCreateFontIndirectW(
	LOGFONTW* lplf
)
{
	// Check for NULL input
	if (!lplf)
		return NULL;

	
	// Create a copy of the LOGFONTW structure that we can modify
	LOGFONTW logfontW = *lplf;
	
	// Adjust character set based on code page if needed
	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (logfontW.lfCharSet == DEFAULT_CHARSET) {
		// Map code page to charset
		MAP_CODEPAGE_TO_CHARSET(settings.CodePage, logfontW.lfCharSet)
	}
	
	// Apply font substitution if configured
	if (settings.UseFontSubstitution && settings.SubstituteFontName[0] != L'\0') {
		// Check if we should apply substitution
		bool applySubstitution = false;
		
		// If original font is empty, substitute
		if (logfontW.lfFaceName[0] == L'\0') {
			applySubstitution = true;
		}
		// If we're forcing substitution for all fonts
		else if (settings.SubstituteAllFonts) {
			applySubstitution = true;
		}
		// If this font is in our substitution list
		else if (settings.FontsToSubstitute.size() > 0) {
			for (std::wstring fontName : settings.FontsToSubstitute) {
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
	
	// Call original function with potentially modified structure
	return OriginalCreateFontIndirectW(&logfontW);
}

HFONT WINAPI HookCreateFontIndirectExA(
	ENUMLOGFONTEXDVA* lplf
)
{
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
	if (lplf->elfEnumLogfontEx.elfLogFont.lfCharSet == DEFAULT_CHARSET) {
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
	// Check for NULL input
	if (!lplf) {
		return NULL;
	}
	
	// Create a copy of the structure that we can modify
	ENUMLOGFONTEXDVW lplfW = *lplf;
	
	// Adjust character set based on code page if needed
	// Only adjust if DEFAULT_CHARSET is specified or if settings force charset override
	if (lplfW.elfEnumLogfontEx.elfLogFont.lfCharSet == DEFAULT_CHARSET) {
		// Map code page to charset
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
	if (!lpWndClass) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Allocate memory for the WNDCLASSW structure
	WNDCLASSW* lpWndClassW = (WNDCLASSW*)AllocateZeroedMemory(sizeof(WNDCLASSW));
	if (!lpWndClassW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Copy structure fields
	lpWndClassW->style = lpWndClass->style;
	lpWndClassW->lpfnWndProc = lpWndClass->lpfnWndProc;
	lpWndClassW->cbClsExtra = lpWndClass->cbClsExtra;
	lpWndClassW->cbWndExtra = lpWndClass->cbWndExtra;
	lpWndClassW->hInstance = lpWndClass->hInstance;
	lpWndClassW->hIcon = lpWndClass->hIcon;
	lpWndClassW->hCursor = lpWndClass->hCursor;
	lpWndClassW->hbrBackground = lpWndClass->hbrBackground;

	// Convert strings
	lpWndClassW->lpszMenuName = MultiByteToWideCharInternal(lpWndClass->lpszMenuName);
	lpWndClassW->lpszClassName = MultiByteToWideCharInternal(lpWndClass->lpszClassName);

	// Register the class
	ATOM atom = RegisterClassW(lpWndClassW);

	// Free allocated memory
	if (lpWndClassW->lpszMenuName)
		FreeStringInternal((LPVOID)lpWndClassW->lpszMenuName);
	if (lpWndClassW->lpszClassName)
		FreeStringInternal((LPVOID)lpWndClassW->lpszClassName);

	FreeStringInternal(lpWndClassW);

	return atom;
}

ATOM WINAPI HookRegisterClassExA(_In_ CONST WNDCLASSEXA* lpWndClass)
{
	if (!lpWndClass) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	// Allocate memory for the WNDCLASSEXW structure
	WNDCLASSEXW* lpWndClassW = (WNDCLASSEXW*)AllocateZeroedMemory(sizeof(WNDCLASSEXW));
	if (!lpWndClassW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return 0;
	}

	// Copy structure fields
	lpWndClassW->cbSize = sizeof(WNDCLASSEXW);  // Use correct size for W version
	lpWndClassW->style = lpWndClass->style;
	lpWndClassW->lpfnWndProc = lpWndClass->lpfnWndProc;
	lpWndClassW->cbClsExtra = lpWndClass->cbClsExtra;
	lpWndClassW->cbWndExtra = lpWndClass->cbWndExtra;
	lpWndClassW->hInstance = lpWndClass->hInstance;
	lpWndClassW->hIcon = lpWndClass->hIcon;
	lpWndClassW->hCursor = lpWndClass->hCursor;
	lpWndClassW->hbrBackground = lpWndClass->hbrBackground;
	lpWndClassW->hIconSm = lpWndClass->hIconSm;

	// Convert strings
	lpWndClassW->lpszMenuName = MultiByteToWideCharInternal(lpWndClass->lpszMenuName);
	lpWndClassW->lpszClassName = MultiByteToWideCharInternal(lpWndClass->lpszClassName);

	// Register the class
	ATOM atom = RegisterClassExW(lpWndClassW);

	// Free allocated memory
	if (lpWndClassW->lpszMenuName)
		FreeStringInternal((LPVOID)lpWndClassW->lpszMenuName);
	if (lpWndClassW->lpszClassName)
		FreeStringInternal((LPVOID)lpWndClassW->lpszClassName);

	FreeStringInternal(lpWndClassW);

	return atom;
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
	if (IsWindowUnicode(hWnd))
		return DefWindowProcW(hWnd, Msg, wParam, lParam);
	else
		return OriginalDefWindowProcA(hWnd, Msg, wParam, lParam);
}

DWORD WINAPI HookGetTimeZoneInformation(
	_Out_ LPTIME_ZONE_INFORMATION lpTimeZoneInformation
)
{
	DWORD ret = OriginalGetTimeZoneInformation(lpTimeZoneInformation);
	if (ret != TIME_ZONE_ID_INVALID) 
		lpTimeZoneInformation->Bias = -settings.Bias; // bias becomes negative here

	return ret;
}

BOOL WINAPI HookCreateDirectoryA(
	_In_ LPCSTR lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
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
	if (!lpFileName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE_VALUE;
	}

	// Convert filename to Unicode using the specified code page
	LPWSTR lpFileNameW = MultiByteToWideCharInternal(lpFileName, settings.CodePage);
	if (!lpFileNameW) {
		SetLastError(ERROR_OUTOFMEMORY);
		return INVALID_HANDLE_VALUE;
	}

	// Call the Unicode version of the function
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

int WINAPI HookGetLocaleInfoA(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPSTR lpLCData,
	_In_ int cchData
)
{
	// Only replace the system default user locale (LOCALE_USER_DEFAULT)
	// and system default locale (LOCALE_SYSTEM_DEFAULT)
	if (Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)
		Locale = settings.LCID;
	
	return OriginalGetLocaleInfoA(Locale, LCType, lpLCData, cchData);
}

int WINAPI HookGetLocaleInfoW(
	_In_ LCID Locale,
	_In_ LCTYPE LCType,
	_Out_writes_opt_(cchData) LPWSTR lpLCData,
	_In_ int cchData
)
{
	if (Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)
		Locale = settings.LCID;

	return OriginalGetLocaleInfoW(Locale, LCType,lpLCData,cchData);
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
	CREATE_HOOK(MultiByteToWideChar)
	CREATE_HOOK(WideCharToMultiByte)

	CREATE_HOOK(CreateWindowExA)
	//CREATE_HOOK(DefWindowProcA)
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

	/*if (settings.SingleLCID)
	{
		CREATE_HOOK(RegisterClassA)
		CREATE_HOOK(RegisterClassExA)
	}*/

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
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}