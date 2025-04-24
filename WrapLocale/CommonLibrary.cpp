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
	int lsize = lstrlenA(lstr); // size without '\0'
	int wsize = (lsize + 1) << 1;
	LPWSTR wstr = (LPWSTR)AllocateZeroedMemory(wsize);
	if (!wstr)
		return nullptr;
	int n = 0;
	if (CodePage)
		n = OriginalMultiByteToWideChar(CodePage, 0, lstr, lsize, wstr, wsize);
	else
		n = MultiByteToWideChar(settings.CodePage, 0, lstr, lsize, wstr, wsize);
	if (n <= 0) {
		FreeStringInternal(wstr);
		return nullptr;
	}
	wstr[n] = L'\0'; // make tail ! 
	return wstr;
}

LPSTR WideCharToMultiByteInternal(LPCWSTR wstr, UINT CodePage)
{
	if (wstr == nullptr)
		return nullptr;
	int wsize = lstrlenW(wstr); // size without '\0'
	int lsize = (wsize + 1) << 1;
	LPSTR lstr = (LPSTR)AllocateZeroedMemory(lsize);
	if (!lstr)
		return lstr;
	int n = 0;
	if (CodePage)
		n = OriginalWideCharToMultiByte(CodePage, 0, wstr, wsize, lstr, lsize, NULL, NULL);
	else
		n = WideCharToMultiByte(settings.CodePage, 0, wstr, wsize, lstr, lsize, NULL, NULL);
	lstr[n] = '\0'; // make tail ! 
	return lstr;
}

void DebugLog(const char* format, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	OutputDebugStringA(buffer);
}