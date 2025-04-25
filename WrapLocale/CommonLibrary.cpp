#include "CommonLibrary.h"

extern GLOBAL_CONFIG settings;
extern INITIAL_STATE Initial;

inline LPVOID AllocateZeroedMemory(SIZE_T size/*eax*/) {
	return HeapAlloc(Initial.hHeap, HEAP_ZERO_MEMORY, size);
}

inline VOID FreeStringInternal(LPVOID pBuffer/*ecx*/)
{
	if (pBuffer != nullptr)
		HeapFree(Initial.hHeap, 0, pBuffer);
}

LPWSTR MultiByteToWideCharInternal(LPCSTR lstr, UINT CodePage)
{
	if (lstr == nullptr)
		return nullptr;

	UINT usedCodePage = CodePage ? CodePage : settings.CodePage;

	int wsize = OriginalMultiByteToWideChar(usedCodePage, 0, lstr, -1, NULL, 0);
	if (wsize == 0)
		return nullptr;

	LPWSTR wstr = (LPWSTR)AllocateZeroedMemory(wsize * sizeof(WCHAR));
	if (!wstr)
		return nullptr;

	int n = OriginalMultiByteToWideChar(usedCodePage, 0, lstr, -1, wstr, wsize);
	if (n <= 0) {
		FreeStringInternal(wstr);
		return nullptr;
	}

	return wstr;
}

LPSTR WideCharToMultiByteInternal(LPCWSTR wstr, UINT CodePage)
{
	if (wstr == nullptr)
		return nullptr;

	int lsize = WideCharToMultiByte(CodePage, 0, wstr, -1, NULL, 0, NULL, NULL);
	 if (lsize == 0) 
		return nullptr;

	LPSTR lstr = (LPSTR)AllocateZeroedMemory(lsize);
	if (!lstr)
		return nullptr;

	int n = 0;
	UINT usedCodePage = CodePage ? CodePage : settings.CodePage;
	n = OriginalWideCharToMultiByte(usedCodePage, 0, wstr, -1, lstr, lsize, NULL, NULL);
	if (n <= 0) {
		FreeStringInternal(lstr);
		return nullptr;
	}

	return lstr;
}

/*
LPWSTR MultiByteToWideCharInternal(LPCSTR lstr, UINT CodePage)
{
	if (lstr == nullptr)
		return nullptr;

	UINT usedCodePage = CodePage ? CodePage : settings.CodePage;

	SIZE_T lsize = strlen(lstr);

	UNICODE_STRING unicodeString;
	ULONG unicodeSize = 0;
	ULONG bytesUsed = 0;
	NTSTATUS status = RtlCustomCPToUnicodeN(
		usedCodePage,
		&unicodeString,
		0,
		&unicodeSize,
		lstr,
		(ULONG)lsize);

	if (!NT_SUCCESS(status))
		return nullptr;

	// Allocate buffer for Unicode string (adding space for null terminator)
	unicodeSize += sizeof(WCHAR);
	LPWSTR wstr = (LPWSTR)AllocateZeroedMemory(unicodeSize);
	if (!wstr)
		return nullptr;

	// Convert the string
	unicodeString.Buffer = wstr;
	unicodeString.Length = 0;
	unicodeString.MaximumLength = (USHORT)unicodeSize;

	status = RtlCustomCPToUnicodeN(
		usedCodePage,
		&unicodeString,
		unicodeSize,
		&bytesUsed,
		lstr,
		(ULONG)lsize);

	if (!NT_SUCCESS(status)) {
		FreeStringInternal(wstr);
		return nullptr;
	}

	// Ensure null termination
	wstr[unicodeString.Length / sizeof(WCHAR)] = L'\0';

	return wstr;
}

LPSTR WideCharToMultiByteInternal(LPCWSTR wstr, UINT CodePage)
{
	if (wstr == nullptr)
		return nullptr;

	UINT usedCodePage = CodePage ? CodePage : settings.CodePage;

	SIZE_T wsize = wcslen(wstr);

	ANSI_STRING ansiString;
	ULONG ansiSize = 0;
	ULONG bytesUsed = 0;
	NTSTATUS status = RtlUnicodeToCustomCPN(
		usedCodePage,
		&ansiString,
		0,
		&ansiSize,
		wstr,
		(ULONG)(wsize * sizeof(WCHAR)));

	if (!NT_SUCCESS(status))
		return nullptr;

	// Allocate buffer for ANSI string (adding space for null terminator)
	ansiSize += sizeof(CHAR);
	LPSTR lstr = (LPSTR)AllocateZeroedMemory(ansiSize);
	if (!lstr)
		return nullptr;

	// Convert the string
	ansiString.Buffer = lstr;
	ansiString.Length = 0;
	ansiString.MaximumLength = (USHORT)ansiSize;

	status = RtlUnicodeToCustomCPN(
		usedCodePage,
		&ansiString,
		ansiSize,
		&bytesUsed,
		wstr,
		(ULONG)(wsize * sizeof(WCHAR)));

	if (!NT_SUCCESS(status)) {
		FreeStringInternal(lstr);
		return nullptr;
	}

	// Ensure null termination
	lstr[ansiString.Length] = '\0';

	return lstr;
}
*/

inline void DebugLog(const char* format, ...)
{
	char buffer[1024] = "\0";
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	buffer[1023] = '\0';
	va_end(args);
	OutputDebugStringA(buffer);
}

inline void DebugLog(const wchar_t* format, ...)
{
	wchar_t buffer[1024] = L"\0";
	va_list args;
	va_start(args, format);
	_vsnwprintf(buffer, sizeof(buffer), format, args);
	buffer[1023] = L'\0';
	va_end(args);
	OutputDebugStringW(buffer);
}