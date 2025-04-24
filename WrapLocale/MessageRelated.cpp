#include "MessageRelated.h"

#include "OriginalFunc.h"
#include "CommonLibrary.h"


extern GLOBAL_CONFIG settings;

NtUserCreateWindowExType OriginalNtUserCreateWindowEx = nullptr;
NtUserMessageCallType OriginalNtUserMessageCall = nullptr;

VOID InitEmptyLargeString(PLARGE_UNICODE_STRING String) 
{
	ZeroMemory(String, sizeof(*String));
}

VOID InitStringFromLargeString(
    PUNICODE_STRING UnicodeString, 
    PLARGE_UNICODE_STRING LargeString
) {
	UnicodeString->Length = (USHORT)LargeString->Length;
	UnicodeString->MaximumLength = (USHORT)LargeString->MaximumLength;
	UnicodeString->Buffer = LargeString->UnicodeBuffer;
}

NTSTATUS WINAPI HookRtlDuplicateUnicodeString(
    ULONG Flags,
    PUNICODE_STRING StringIn,
    PUNICODE_STRING StringOut
){
	if (!StringIn || !StringOut ||
		StringIn->Length > StringIn->MaximumLength ||
		(StringIn->Length == 0 && StringIn->MaximumLength > 0 && !StringIn->Buffer) ||
		Flags == 2 || Flags >= 4 || Flags < 0) {
		return STATUS_INVALID_PARAMETER;
	}

	if (StringIn->Length == 0 && Flags != 3) {
		StringOut->Length = 0;
		StringOut->MaximumLength = 0;
		StringOut->Buffer = NULL;
		return STATUS_SUCCESS;
	}

	USHORT StringOutMaxLen = StringIn->Length;
	if (Flags)
		StringOutMaxLen += sizeof(WCHAR);

	StringOut->Buffer = (LPWSTR)AllocateZeroedMemory(StringOutMaxLen);
	if (!StringOut->Buffer)
		return STATUS_NO_MEMORY;

	memcpy(StringOut->Buffer, StringIn->Buffer, StringIn->Length);
	StringOut->Length = StringIn->Length;
	StringOut->MaximumLength = StringIn->Length;

	if (Flags) {
		StringOut->MaximumLength = StringOutMaxLen;
		StringOut->Buffer[StringOut->Length / sizeof(WCHAR)] = 0;
	}

	return STATUS_SUCCESS;
}

PLARGE_UNICODE_STRING LargeStringDuplicate(
    PLARGE_UNICODE_STRING LargeString, 
    PLARGE_UNICODE_STRING Destination
) {
	UNICODE_STRING Unicode;
	UNICODE_STRING NewUnicode;

	if (LargeString->Ansi)
		return NULL;

	InitStringFromLargeString(&Unicode, LargeString);
	if (HookRtlDuplicateUnicodeString(RTL_DUPSTR_ADD_NULL, &Unicode, &NewUnicode) != STATUS_SUCCESS)
		return NULL;

	Destination->Ansi = FALSE;
	Destination->Length = NewUnicode.Length;
	Destination->MaximumLength = NewUnicode.MaximumLength;
	Destination->UnicodeBuffer = NewUnicode.Buffer;

	return Destination;
}

ULONG WINAPI HookRtlAnsiStringToUnicodeSize(PCANSI_STRING AnsiString) {
	ULONG ret = (AnsiString->Length + 1) * sizeof(WCHAR);
	return ret;
}

NTSTATUS WINAPI HookRtlAnsiStringToUnicodeString( 
    PUNICODE_STRING DestinationString, /* [I/O] Destination for the unicode string */
    PANSI_STRING SourceString,         /* [I]   Ansi string to be converted */
    BOOLEAN AllocateDestinationString  /* [I]   TRUE=Allocate new buffer for uni, FALSE=Use existing buffer */
){
	DWORD total = HookRtlAnsiStringToUnicodeSize(SourceString);
	if (total > 0xffff)
		return STATUS_INVALID_PARAMETER_2;

	DestinationString->Length = total - sizeof(WCHAR);

	if (AllocateDestinationString) {
		DestinationString->MaximumLength = total;
		DestinationString->Buffer = (LPWSTR)AllocateZeroedMemory(total);
		if (!DestinationString->Buffer)
			return STATUS_NO_MEMORY;
	}
	else if (total > DestinationString->MaximumLength)
		return STATUS_BUFFER_OVERFLOW;

	MultiByteToWideChar(
		settings.CodePage, 
		0, SourceString->Buffer, 
		SourceString->Length, 
		DestinationString->Buffer, 
		DestinationString->Length / sizeof(WCHAR)
	);

	DestinationString->Buffer[DestinationString->Length / sizeof(WCHAR)] = 0;

	return STATUS_SUCCESS;
}

PLARGE_UNICODE_STRING LargeStringAnsiToUnicode(
    PLARGE_UNICODE_STRING LargeAnsiString, 
    PLARGE_UNICODE_STRING LargeUnicodeString
) {
	if (!LargeAnsiString)
		return NULL;

	if (!LargeAnsiString->Ansi)
		return LargeStringDuplicate(LargeAnsiString, LargeUnicodeString);

	ANSI_STRING AnsiString;
	UNICODE_STRING UnicodeString = { 0 };

	AnsiString.Buffer = LargeAnsiString->AnsiBuffer;
	AnsiString.Length = LargeAnsiString->Length;
	AnsiString.MaximumLength = LargeAnsiString->MaximumLength;

	if (RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE) != STATUS_SUCCESS)
		return NULL;

	LargeUnicodeString->Ansi = FALSE;
	LargeUnicodeString->Length = UnicodeString.Length;
	LargeUnicodeString->MaximumLength = UnicodeString.MaximumLength;
	LargeUnicodeString->Buffer = (ULONG64)UnicodeString.Buffer;

	return LargeUnicodeString;
}

PLARGE_UNICODE_STRING CaptureAnsiWindowName(
    PLARGE_UNICODE_STRING WindowName, 
    PLARGE_UNICODE_STRING UnicodeWindowName
) {
	InitEmptyLargeString(UnicodeWindowName);

	if (!WindowName || WindowName->Buffer == 0)
		return NULL;

	if (WindowName->UnicodeBuffer[0] == 0xFFFF) {
		WCHAR Buffer[0x10];
		ULONG_PTR Length;
		LARGE_UNICODE_STRING TitleAsResourceId;

		TitleAsResourceId.Ansi = FALSE;
		Length = WindowName->Ansi ? 3 : 4;

		CopyMemory(Buffer, WindowName->AnsiBuffer + WindowName->Ansi, Length);

		TitleAsResourceId.Length = Length;
		TitleAsResourceId.MaximumLength = Length;
		TitleAsResourceId.Buffer = (ULONG64)Buffer;

		return LargeStringDuplicate(&TitleAsResourceId, UnicodeWindowName);
	}

	return LargeStringAnsiToUnicode(WindowName, UnicodeWindowName);
}

/*************************************/
/* Unicde to Ansi UserCall Functions */
/*************************************/
LRESULT NTAPI UNICODE_EMPTY(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_INLPCREATESTRUCT(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	CREATESTRUCTA	CreateStructA = nullptr;
	LPCREATESTRUCTW CreateStructW = (LPCREATESTRUCTW)lParam;

	if (CreateStructW)
	{
		CreateStructA = *(LPCREATESTRUCTA)CreateStructW; // technically we can even if buffers don't match
		CreateStructA.lpszClass = WideCharToMultiByteInternal(CreateStructW->lpszClass, settings.CodePage);
		CreateStructA.lpszName = WideCharToMultiByteInternal(CreateStructW->lpszName, settings.CodePage);

		lParam = (LPARAM)&CreateStructA;
	}

	LRESULT Result = CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

	if (CreateStructW)
	{
		FreeStringInternal((LPVOID)CreateStructA.lpszClass);
		FreeStringInternal((LPVOID)CreateStructA.lpszName);
	}

	return Result;
}

LRESULT NTAPI UNICODE_INLPMDICREATESTRUCT(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	MDICREATESTRUCTA	MdiCreateStructA = nullptr;
	LPMDICREATESTRUCTW  MdiCreateStructW = (LPMDICREATESTRUCTW)lParam;

	if (MdiCreateStructW)
	{
		MdiCreateStructA = *(LPMDICREATESTRUCTA)MdiCreateStructW;
		MdiCreateStructA.szClass = WideCharToMultiByteInternal(MdiCreateStructW->szClass, settings.CodePage);
		MdiCreateStructA.szTitle = WideCharToMultiByteInternal(MdiCreateStructW->szTitle, settings.CodePage);

		lParam = (LPARAM)&MdiCreateStructA;
	}

	LRESULT Result = CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

	if (MdiCreateStructW) {
		FreeStringInternal((LPVOID)MdiCreateStructA.szClass);
		FreeStringInternal((LPVOID)MdiCreateStructA.szTitle);
	}


	return Result;
}

LRESULT NTAPI UNICODE_INSTRINGNULL(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	LPWSTR Unicode = (LPWSTR)lParam;
	LPSTR Ansi = nullptr;

	DebugLog(L"UNICODE_INSTRINGNULL=%s", Unicode);
	if (Unicode)
	{
		Ansi = WideCharToMultiByteInternal(Unicode, settings.CodePage);
		lParam = (LPARAM)Ansi;
	}

	LRESULT Result = CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

	FreeStringInternal(Ansi);

	return Result;
}

LRESULT NTAPI UNICODE_OUTSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	UINT UnicodeSize = (UINT)wParam;
	LPWSTR UnicodeBuffer = (LPWSTR)lParam;

	DebugLog(L"UNICODE_INSTRINGNULL=%s", UnicodeBuffer);

	UINT AnsiSize = UnicodeSize * sizeof(WCHAR);
	LPSTR AnsiBuffer = (LPSTR)AllocateZeroedMemory(AnsiSize);
	if (AnsiBuffer == nullptr)
		return 0;

	wParam = AnsiSize;
	lParam = (LPARAM)AnsiBuffer;

	AnsiSize = CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

	if (AnsiSize != 0)
		WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, UnicodeSize, AnsiBuffer, AnsiSize, NULL, NULL);

	FreeStringInternal(AnsiBuffer);

	return AnsiSize / sizeof(WCHAR);
}

LRESULT NTAPI UNICODE_INSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_INCNTOUTSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	DebugLog(L"UNICODE_INCNTOUTSTRING");
	return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_INCBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_OUTCBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	DebugLog(L"UNICODE_OUTCBOXSTRING");
	return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_INLBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_OUTLBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_INCNTOUTSTRINGNULL(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_GETDBCSTEXTLENGTHS(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	DebugLog(L"UNICODE_GETDBCSTEXTLENGTHS");
	return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);
}

/****************************************/
/* Ansi to Unicode KernelCall Functions */
/****************************************/

LRESULT NTAPI ANSI_EMPTY(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return OriginalNtUserMessageCall(
		Window,
		Message,
		wParam,
		lParam,
		xParam,
		xpfnProc,
		Flags
	);
}


LRESULT NTAPI ANSI_INLPCREATESTRUCT(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	CREATESTRUCTW   CreateStructW = nullptr;
	LPCREATESTRUCTA CreateStructA = (LPCREATESTRUCTA)lParam;

	if (CreateStructA)
	{
		CreateStructW = *(LPCREATESTRUCTW)CreateStructA;
		CreateStructW.lpszClass = MultiByteToWideCharInternal(CreateStructA->lpszClass, settings.CodePage);
		if (CreateStructA->lpszClass != nullptr)
		{
			CreateStructW.lpszName = MultiByteToWideCharInternal(CreateStructA->lpszName, settings.CodePage);
			CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
		}
		lParam = (LPARAM)&CreateStructW;
	}

	LRESULT Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);

	if (CreateStructA) {
		FreeStringInternal((LPVOID)CreateStructW.lpszClass);
		FreeStringInternal((LPVOID)CreateStructW.lpszName);
	}

	return Result;
}

LRESULT NTAPI ANSI_INLPMDICREATESTRUCT(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	MDICREATESTRUCTW   MdiCreateStructW = nullptr;
	LPMDICREATESTRUCTA MdiCreateStructA = (LPMDICREATESTRUCTA)lParam;

	if (MdiCreateStructA)
	{
		MdiCreateStructW = *(LPMDICREATESTRUCTW)MdiCreateStructA;
		MdiCreateStructW.szClass = MultiByteToWideCharInternal(MdiCreateStructA->szClass, settings.CodePage);
		MdiCreateStructW.szTitle = MultiByteToWideCharInternal(MdiCreateStructA->szTitle, settings.CodePage);

		CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
		lParam = (LPARAM)&MdiCreateStructW;
	}

	LRESULT Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);

	if (MdiCreateStructA) {
		FreeStringInternal((LPVOID)MdiCreateStructW.szClass);
		FreeStringInternal((LPVOID)MdiCreateStructW.szTitle);
	}

	return Result;
}

LRESULT NTAPI ANSI_INSTRINGNULL(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	LPWSTR Unicode = nullptr;
	LPSTR Ansi = (LPSTR)lParam;

	if (Ansi)
	{
		Unicode = MultiByteToWideCharInternal(Ansi, settings.CodePage);
		lParam = (LPARAM)Unicode;
		CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
	}

	LRESULT Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);

	FreeStringInternal(Unicode);

	return Result;
}

LRESULT NTAPI ANSI_OUTSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	LRESULT Result;
	DebugLog(L"ANSI_OUTSTRING");
	Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
	return Result;
}

LRESULT NTAPI ANSI_INSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return ANSI_INSTRINGNULL(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}

LRESULT NTAPI ANSI_INCNTOUTSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	LRESULT Result;
	DebugLog(L"ANSI_INCNTOUTSTRING");
	Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
	return Result;
}

LRESULT NTAPI ANSI_INCBOXSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return ANSI_INSTRINGNULL(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}

LRESULT NTAPI ANSI_OUTCBOXSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	LRESULT Result;
	DebugLog(L"ANSI_OUTCBOXSTRING");
	Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
	return Result;
}

LRESULT NTAPI ANSI_INLBOXSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return ANSI_INSTRINGNULL(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}

LRESULT NTAPI ANSI_OUTLBOXSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return ANSI_INSTRINGNULL(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}

LRESULT NTAPI ANSI_INCNTOUTSTRINGNULL(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return ANSI_INSTRINGNULL(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}

LRESULT NTAPI ANSI_GETDBCSTEXTLENGTHS(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	LRESULT Result;
	DebugLog(L"ANSI_GETDBCSTEXTLENGTHS");
	Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
	return Result;
}



HHOOK CbtHook = nullptr;

HWND WINAPI HookNtUserCreateWindowEx(
	ULONG                   ExStyle,
	PLARGE_UNICODE_STRING   ClassName,
	PLARGE_UNICODE_STRING   ClassVersion,
	PLARGE_UNICODE_STRING   WindowName,
	ULONG                   Style,
	LONG                    X,
	LONG                    Y,
	LONG                    Width,
	LONG                    Height,
	HWND                    ParentWnd,
	HMENU                   Menu,
	PVOID                   Instance,
	LPVOID                  Param,
	ULONG                   ShowMode,
	ULONG                   Unknown1,
	ULONG                   Unknown2,
	ULONG                   Unknown3
)
{
	LARGE_UNICODE_STRING UnicodeWindowName;

	InitEmptyLargeString(&UnicodeWindowName);

	LOOP_ONCE
	{
		if (!FLAG_ON(ExStyle, WS_EX_ANSI))
			break;

		if (WindowName != nullptr && CaptureAnsiWindowName(WindowName, &UnicodeWindowName) == nullptr)
			break;

		WindowName = &UnicodeWindowName;
		CbtHook = SetWindowsHookExA(WH_CBT, CBTProc, nullptr, GetCurrentThreadId());
	}

		HWND ret = OriginalNtUserCreateWindowEx(
			ExStyle,
			(PLARGE_UNICODE_STRING)ClassName,
			(PLARGE_UNICODE_STRING)ClassVersion,
			(PLARGE_UNICODE_STRING)WindowName,
			Style,
			X,
			Y,
			Width,
			Height,
			ParentWnd,
			Menu,
			Instance,
			Param,
			ShowMode,
			Unknown1,
			Unknown2,
			Unknown3
		);

	if (CbtHook)
		UnhookWindowsHookEx(CbtHook);

	return ret;
}

LRESULT NTAPI WindowProcW(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC	PrevProc = (WNDPROC)GetPropW(Window, L"OriginalProcA");

	if (Message < MessageSize)
		return MessageTable[Message].UnicodeCall(PrevProc, Window, Message, wParam, lParam);

	return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);
}

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	HWND hWnd = (HWND)wParam;
	WNDPROC OriginalProcA = (WNDPROC)GetWindowLongA(hWnd, GWLP_WNDPROC);

	if (nCode == HCBT_CREATEWND)
	{
		SetPropW(hWnd, L"OriginalProcA", OriginalProcA);
		SetWindowLongW(hWnd, GWLP_WNDPROC, (LONG)WindowProcW);
	}

	return CallNextHookEx(CbtHook, nCode, wParam, lParam);
}

LRESULT WINAPI HookNtUserMessageCall(
	HWND         Window,
	UINT         Message,
	WPARAM       wParam,
	LPARAM       lParam,
	ULONG_PTR    xParam,
	ULONG        xpfnProc,
	ULONG        Flags
)
{
	LOOP_ONCE
	{
		if (Message >= MessageSize)
			break;

		if (!FLAG_ON(Flags, WINDOW_FLAG_ANSI))
			break;

		return MessageTable[Message].AnsiCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
	}
	return OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}
