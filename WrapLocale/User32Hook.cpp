#include "User32Hook.h"

/****************************************/
/* Ansi to Unicode KernelCall Functions */
/****************************************/
LRESULT NTAPI ANSI_INLPCREATESTRUCT(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	LRESULT			Result;
	LPCREATESTRUCTA CreateStructA;
	CREATESTRUCTW   CreateStructW;

	CreateStructA = (LPCREATESTRUCTA)lParam;
	CreateStructW.lpszClass = nullptr;
	CreateStructW.lpszName = nullptr;

	if (CreateStructA)
	{
		CreateStructW = *(LPCREATESTRUCTW)CreateStructA;
		CreateStructW.lpszClass = MultiByteToWideCharInternal(CreateStructA->lpszClass, settings.CodePage);
		CreateStructW.lpszName = MultiByteToWideCharInternal(CreateStructA->lpszName, settings.CodePage);
		lParam = (LPARAM)&CreateStructW;
	}
	Result = SendMessageW(Window, Message, wParam, lParam);
	FreeStringInternal((LPVOID)CreateStructW.lpszClass);
	FreeStringInternal((LPVOID)CreateStructW.lpszName);

	return Result;
}

LRESULT NTAPI ANSI_INLPMDICREATESTRUCT(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	LRESULT				Result;
	LPMDICREATESTRUCTA  MdiCreateStructA;
	MDICREATESTRUCTW    MdiCreateStructW;

	MdiCreateStructA = (LPMDICREATESTRUCTA)lParam;
	MdiCreateStructW.szClass = nullptr;
	MdiCreateStructW.szTitle = nullptr;

	if (MdiCreateStructA)
	{
		MdiCreateStructW = *(LPMDICREATESTRUCTW)MdiCreateStructA;
		MdiCreateStructW.szClass = MultiByteToWideCharInternal(MdiCreateStructA->szClass, settings.CodePage);
		MdiCreateStructW.szTitle = MultiByteToWideCharInternal(MdiCreateStructA->szTitle, settings.CodePage);

		lParam = (LPARAM)&MdiCreateStructW;
	}

	Result = SendMessageW(Window, Message, wParam, lParam);

	FreeStringInternal((LPVOID)MdiCreateStructW.szClass);
	FreeStringInternal((LPVOID)MdiCreateStructW.szTitle);

	return Result;
}

LRESULT NTAPI ANSI_INSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	LRESULT	Result;
	LPSTR	Ansi;
	LPWSTR	Unicode;

	Ansi = (LPSTR)lParam;
	Unicode = nullptr;

	if (Ansi)
	{
		Unicode = MultiByteToWideCharInternal(Ansi, settings.CodePage);
		lParam = (LPARAM)Unicode;
	}

	Result = SendMessageW(Window, Message, wParam, lParam);
	FreeStringInternal(Unicode);
	return Result;
}


LRESULT NTAPI ANSI_GETTEXTLENGTH(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{

	int cchUnicode = (int)SendMessageW(Window, Message, wParam, lParam);
	if (cchUnicode < 0) 
		return cchUnicode;

	cchUnicode++;
	LPWSTR UnicodeParam = (LPWSTR)AllocateZeroedMemory(cchUnicode * 2);
	if (UnicodeParam == nullptr) 
		return 0;

	wParam = Message == WM_GETTEXTLENGTH ? cchUnicode : wParam;

	cchUnicode = (int)SendMessageW(Window, Message - 1, wParam, (LPARAM)UnicodeParam);
	if (cchUnicode > 0)
		cchUnicode = HookWideCharToMultiByte(settings.CodePage, 0, UnicodeParam, cchUnicode * 2, NULL, 0, NULL, NULL);

	FreeStringInternal(UnicodeParam);

	return cchUnicode;
}

LRESULT NTAPI ANSI_OUTSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{

	LPSTR AnsiBuffer = (LPSTR)lParam;
	int AnsiSize = (int)wParam;

	int UnicodeSize = (int)SendMessageW(Window, WM_GETTEXTLENGTH, (WPARAM)wParam, lParam);
	if (UnicodeSize == 0)
		return 0;

	UnicodeSize++;
	LPWSTR UnicodeBuffer = (LPWSTR)AllocateZeroedMemory(UnicodeSize * 2);
	if (UnicodeBuffer == nullptr)
		return 0;

	AnsiSize = (int)SendMessageW(Window, Message, UnicodeSize, (LPARAM)UnicodeBuffer);
	AnsiSize = WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, UnicodeSize, AnsiBuffer, AnsiSize, NULL, NULL);

	FreeStringInternal(UnicodeBuffer);

	return AnsiSize;
}

LRESULT NTAPI ANSI_GETTEXT(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{

	LPSTR AnsiBuffer = (LPSTR)lParam;

	int Length = (int)SendMessageW(Window, Message + 1, wParam, lParam);
	if (Length < 0)
		return Length;

	Length++;
	LPWSTR UnicodeBuffer = (LPWSTR)AllocateZeroedMemory(Length * 2);
	if (UnicodeBuffer == nullptr)
		return 0;

	Length = (int)SendMessageW(Window, Message, wParam, (LPARAM)UnicodeBuffer);
	if (Length > 0)
		Length = WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, Length, AnsiBuffer, Length * 2, NULL, NULL);

	FreeStringInternal(UnicodeBuffer);

	return Length;
}

LRESULT NTAPI ANSI_GETLINE(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    if (!lParam)
        return 0;

	typedef union
	{
		USHORT  BufferSize;
		WCHAR   UnicodeBuffer[1];
		CHAR    AnsiBuffer[1];

	} MSG_INPUT_COUNT_OUPUT_STRING, * PMSG_INPUT_COUNT_OUPUT_STRING;


	PMSG_INPUT_COUNT_OUPUT_STRING ParamA = (PMSG_INPUT_COUNT_OUPUT_STRING)lParam;

	// Get the ANSI buffer size and pointer
	USHORT AnsiSize = ParamA->BufferSize;
	LPSTR AnsiBuffer = ParamA->AnsiBuffer;
    if (AnsiSize == 0)
        return 0;

	LPWSTR UnicodeBuffer = (LPWSTR)AllocateZeroedMemory(AnsiSize);
	if (UnicodeBuffer == nullptr)
		return 0;

	PMSG_INPUT_COUNT_OUPUT_STRING ParamW = (PMSG_INPUT_COUNT_OUPUT_STRING)UnicodeBuffer;
	ParamW->BufferSize = AnsiSize;

	int Length = (int)SendMessageW(Window, Message, wParam, lParam);

	if (Length != 0)
		Length = WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, Length, AnsiBuffer, AnsiSize, NULL, NULL);

	FreeStringInternal(UnicodeBuffer);

	return Length;
}

