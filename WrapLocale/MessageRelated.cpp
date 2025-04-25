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
    if (!DestinationString || !SourceString)
        return STATUS_INVALID_PARAMETER;

    // Calculate required buffer size with the specified code page
    int RequiredSize = MultiByteToWideChar(
        settings.CodePage, 
        0, 
        SourceString->Buffer, 
        SourceString->Length, 
        NULL, 
        0
    );

    if (RequiredSize == 0)
        return STATUS_INVALID_PARAMETER_2;

    // Add space for null terminator
    DWORD total = (RequiredSize + 1) * sizeof(WCHAR);
    if (total > 0xffff)
        return STATUS_INVALID_PARAMETER_2;

    DestinationString->Length = RequiredSize * sizeof(WCHAR);

    if (AllocateDestinationString) {
        DestinationString->MaximumLength = total;
        DestinationString->Buffer = (LPWSTR)AllocateZeroedMemory(total);
        if (!DestinationString->Buffer)
            return STATUS_NO_MEMORY;
    }
    else if (total > DestinationString->MaximumLength)
        return STATUS_BUFFER_OVERFLOW;

    // Perform the actual conversion
    if (!MultiByteToWideChar(
        settings.CodePage, 
        0, 
        SourceString->Buffer, 
        SourceString->Length, 
        DestinationString->Buffer, 
        RequiredSize
    )) {
        if (AllocateDestinationString) {
            FreeStringInternal(DestinationString->Buffer);
            DestinationString->Buffer = NULL;
        }
        return STATUS_INVALID_PARAMETER_2;
    }

    // Add null terminator
    DestinationString->Buffer[RequiredSize] = 0;

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
        return UnicodeWindowName;
    
    // Special case: Resource ID (indicated by 0xFFFF marker)
    if ((!WindowName->Ansi && WindowName->UnicodeBuffer[0] == 0xFFFF) ||
        (WindowName->Ansi && ((WORD*)WindowName->AnsiBuffer)[0] == 0xFFFF)) {
        PWCHAR Buffer = (PWCHAR)AllocateZeroedMemory(sizeof(WCHAR) * 0x10);
        if (!Buffer)
            return UnicodeWindowName;
        
        ZeroMemory(Buffer, sizeof(WCHAR) * 0x10);
        LARGE_UNICODE_STRING TitleAsResourceId = {0};
        ULONG_PTR Length;
        
        TitleAsResourceId.Ansi = FALSE;

        Length = 4;
        if (WindowName->Ansi) {
            MultiByteToWideChar(CP_ACP, 0, WindowName->AnsiBuffer, Length/2, Buffer, 0x10);
        } else {
            CopyMemory(Buffer, WindowName->UnicodeBuffer, Length);
        }

        TitleAsResourceId.Length = Length;
        TitleAsResourceId.MaximumLength = sizeof(WCHAR) * 0x10;
        TitleAsResourceId.Buffer = (ULONG64)Buffer;
        
        PLARGE_UNICODE_STRING result = LargeStringDuplicate(&TitleAsResourceId, UnicodeWindowName);
        FreeMemory(Buffer);

        return result;
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

    if (!UnicodeBuffer || UnicodeSize == 0)
        return 0;

    // Calculate required buffer size for ANSI conversion
    int AnsiSize = WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, UnicodeSize, 
                                      NULL, 0, NULL, NULL);
    if (AnsiSize == 0)
        return 0;

    LPSTR AnsiBuffer = (LPSTR)AllocateZeroedMemory(AnsiSize);
    if (AnsiBuffer == nullptr)
        return 0;

    // Convert Unicode to ANSI
    if (!WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, UnicodeSize, 
                            AnsiBuffer, AnsiSize, NULL, NULL)) {
        FreeStringInternal(AnsiBuffer);
        return 0;
    }

    // Call the ANSI window procedure
    LRESULT Result = CallWindowProcA(PrevProc, Window, Message, AnsiSize, (LPARAM)AnsiBuffer);

    // If the call succeeded and we need to copy data back
    if (Result > 0 && Result <= UnicodeSize) {
        // Convert the result back to Unicode
        MultiByteToWideChar(settings.CodePage, 0, AnsiBuffer, Result, 
                           UnicodeBuffer, UnicodeSize);
    }

    FreeStringInternal(AnsiBuffer);
    return Result;
}

LRESULT NTAPI UNICODE_INSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_INCNTOUTSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    UINT UnicodeCount = (UINT)wParam;
    LPWSTR UnicodeInput = (LPWSTR)lParam;

    if (!UnicodeInput || UnicodeCount == 0)
        return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

    // Convert Unicode to ANSI for input
    int AnsiSize = WideCharToMultiByte(settings.CodePage, 0, UnicodeInput, UnicodeCount, 
                                      NULL, 0, NULL, NULL);
    if (AnsiSize == 0)
        return 0;

LPSTR AnsiBuffer = (LPSTR)AllocateZeroedMemory(AnsiSize);
    if (AnsiBuffer == nullptr)
        return 0;

    if (!WideCharToMultiByte(settings.CodePage, 0, UnicodeInput, UnicodeCount, 
                            AnsiBuffer, AnsiSize, NULL, NULL)) {
        FreeStringInternal(AnsiBuffer);
        return 0;
    }

    // Call the ANSI procedure
    LRESULT Result = CallWindowProcA(PrevProc, Window, Message, AnsiSize, (LPARAM)AnsiBuffer);

    // If output is expected in the same buffer, convert back to Unicode
    if (Result > 0) {
        MultiByteToWideChar(settings.CodePage, 0, AnsiBuffer, Result, 
                           UnicodeInput, UnicodeCount);
    }

    FreeStringInternal(AnsiBuffer);
    return Result;
}

LRESULT NTAPI UNICODE_INCBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_OUTCBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    UINT UnicodeSize = (UINT)wParam;
    LPWSTR UnicodeBuffer = (LPWSTR)lParam;

    if (!UnicodeBuffer || UnicodeSize == 0)
        return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

    // Calculate required buffer size for ANSI conversion
    int AnsiSize = WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, UnicodeSize, 
                                      NULL, 0, NULL, NULL);
    if (AnsiSize == 0)
        return 0;

    LPSTR AnsiBuffer = (LPSTR)AllocateZeroedMemory(AnsiSize);
    if (AnsiBuffer == nullptr)
        return 0;

    // Call the ANSI procedure with a buffer to receive the result
    LRESULT Result = CallWindowProcA(PrevProc, Window, Message, AnsiSize, (LPARAM)AnsiBuffer);

    // If the call succeeded, convert the result back to Unicode
    if (Result > 0) {
        MultiByteToWideChar(settings.CodePage, 0, AnsiBuffer, Result, 
                           UnicodeBuffer, UnicodeSize);
    }

    FreeStringInternal(AnsiBuffer);
    return Result;
}
LRESULT NTAPI UNICODE_INLBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_OUTLBOXSTRING(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    UINT UnicodeSize = (UINT)wParam;
    LPWSTR UnicodeBuffer = (LPWSTR)lParam;

    if (!UnicodeBuffer || UnicodeSize == 0)
        return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

    // Calculate required buffer size for ANSI conversion
    int AnsiSize = WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, UnicodeSize, 
                                      NULL, 0, NULL, NULL);
    if (AnsiSize == 0)
        return 0;

    LPSTR AnsiBuffer = (LPSTR)AllocateZeroedMemory(AnsiSize);
    if (AnsiBuffer == nullptr)
        return 0;

    // Call the ANSI procedure
    LRESULT Result = CallWindowProcA(PrevProc, Window, Message, AnsiSize, (LPARAM)AnsiBuffer);

    // If the call succeeded, convert the result back to Unicode
    if (Result > 0) {
        MultiByteToWideChar(settings.CodePage, 0, AnsiBuffer, Result, 
                           UnicodeBuffer, UnicodeSize);
    }

    FreeStringInternal(AnsiBuffer);
    return Result;
}

LRESULT NTAPI UNICODE_INCNTOUTSTRINGNULL(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
	return UNICODE_INSTRINGNULL(PrevProc, Window, Message, wParam, lParam);
}

LRESULT NTAPI UNICODE_GETDBCSTEXTLENGTHS(WNDPROC PrevProc, HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    LPWSTR UnicodeText = (LPWSTR)lParam;

    if (!UnicodeText)
        return CallWindowProcA(PrevProc, Window, Message, wParam, lParam);

    // Convert to ANSI for proper DBCS length calculation
    LPSTR AnsiText = WideCharToMultiByteInternal(UnicodeText, settings.CodePage);
    if (!AnsiText)
        return 0;

    // Call with ANSI text
    LRESULT Result = CallWindowProcA(PrevProc, Window, Message, wParam, (LPARAM)AnsiText);

    FreeStringInternal(AnsiText);
    return Result;
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
    CREATESTRUCTW CreateStructW = {0};
    LPCREATESTRUCTA CreateStructA = (LPCREATESTRUCTA)lParam;

    if (CreateStructA)
    {
        CreateStructW = *(LPCREATESTRUCTW)CreateStructA;

        // Always convert class name if it exists
        if (CreateStructA->lpszClass != nullptr) {
            CreateStructW.lpszClass = MultiByteToWideCharInternal(CreateStructA->lpszClass, settings.CodePage);
        }

        // Always convert window name if it exists
        if (CreateStructA->lpszName != nullptr) {
            CreateStructW.lpszName = MultiByteToWideCharInternal(CreateStructA->lpszName, settings.CodePage);
        }

        // Only clear the ANSI flag if we successfully converted all strings
        if ((CreateStructA->lpszClass == nullptr || CreateStructW.lpszClass != nullptr) &&
            (CreateStructA->lpszName == nullptr || CreateStructW.lpszName != nullptr)) {
            CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
            lParam = (LPARAM)&CreateStructW;
        }
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
        if (Unicode) {
            lParam = (LPARAM)Unicode;
            CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
        }
    }

    LRESULT Result = OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
    FreeStringInternal(Unicode);

    return Result;
}

LRESULT NTAPI ANSI_OUTSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
    UINT AnsiSize = (UINT)wParam;
    LPSTR AnsiBuffer = (LPSTR)lParam;

    if (!AnsiBuffer || AnsiSize == 0)
        return OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);

    // Calculate required buffer size for Unicode conversion
    int UnicodeSize = MultiByteToWideChar(settings.CodePage, 0, AnsiBuffer, AnsiSize, NULL, 0);
    if (UnicodeSize == 0)
        return 0;

    LPWSTR UnicodeBuffer = (LPWSTR)AllocateZeroedMemory(UnicodeSize * sizeof(WCHAR));
    if (UnicodeBuffer == nullptr)
        return 0;

    // Convert ANSI to Unicode
    if (!MultiByteToWideChar(settings.CodePage, 0, AnsiBuffer, AnsiSize, 
                            UnicodeBuffer, UnicodeSize)) {
        FreeStringInternal(UnicodeBuffer);
        return 0;
    }

    CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
    LRESULT Result = OriginalNtUserMessageCall(Window, Message, UnicodeSize, 
                                              (LPARAM)UnicodeBuffer, xParam, xpfnProc, Flags);

    if (Result > 0 && Result <= AnsiSize) {
        WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, Result, 
                           AnsiBuffer, AnsiSize, NULL, NULL);
    }

    FreeStringInternal(UnicodeBuffer);
    return Result;
}

LRESULT NTAPI ANSI_INSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
	return ANSI_INSTRINGNULL(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);
}

LRESULT NTAPI ANSI_INCNTOUTSTRING(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam, ULONG_PTR xParam, ULONG xpfnProc, ULONG Flags)
{
    // This handles messages where input is a count and string, output is a string
    UINT AnsiCount = (UINT)wParam;
    LPSTR AnsiInput = (LPSTR)lParam;

    if (!AnsiInput || AnsiCount == 0)
        return OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);

    // Convert input string to Unicode
    int UnicodeSize = MultiByteToWideChar(settings.CodePage, 0, AnsiInput, AnsiCount, NULL, 0);
    if (UnicodeSize == 0)
        return 0;
    LPWSTR UnicodeBuffer = (LPWSTR)AllocateZeroedMemory(UnicodeSize * sizeof(WCHAR));
    if (UnicodeBuffer == nullptr)
        return 0;
    if (!MultiByteToWideChar(settings.CodePage, 0, AnsiInput, AnsiCount, UnicodeBuffer, UnicodeSize)) {
        FreeStringInternal(UnicodeBuffer);
        return 0;
    }

    CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
    LRESULT Result = OriginalNtUserMessageCall(Window, Message, UnicodeSize, 
                                              (LPARAM)UnicodeBuffer, xParam, xpfnProc, Flags);
    if (Result > 0) {
        WideCharToMultiByte(settings.CodePage, 0, UnicodeBuffer, Result, 
                           AnsiInput, AnsiCount, NULL, NULL);
    }

    FreeStringInternal(UnicodeBuffer);
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
    // Handle DBCS text length calculation
    LPSTR AnsiText = (LPSTR)lParam;
    if (!AnsiText)
        return OriginalNtUserMessageCall(Window, Message, wParam, lParam, xParam, xpfnProc, Flags);

    LPWSTR UnicodeText = MultiByteToWideCharInternal(AnsiText, settings.CodePage);
    if (!UnicodeText)
        return 0;

    CLEAR_FLAG(Flags, WINDOW_FLAG_ANSI);
    LRESULT Result = OriginalNtUserMessageCall(Window, Message, wParam, 
                                              (LPARAM)UnicodeText, xParam, xpfnProc, Flags);

    FreeStringInternal(UnicodeText);
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
    if (nCode == HCBT_CREATEWND)
    {
        HWND hWnd = (HWND)wParam;

        // Check if this is an ANSI window before hooking
        BOOL isAnsi = GetWindowLongA(hWnd, GWL_STYLE) & WS_EX_ANSI;

        if (isAnsi) {
            WNDPROC OriginalProcA = (WNDPROC)GetWindowLongA(hWnd, GWLP_WNDPROC);

            // Only set the hook if we found a valid procedure
            if (OriginalProcA) {
                SetPropW(hWnd, L"OriginalProcA", OriginalProcA);
                SetWindowLongW(hWnd, GWLP_WNDPROC, (LONG)WindowProcW);
            }
        }
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
