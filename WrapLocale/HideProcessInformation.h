#pragma once

#include "MINT.h"

typedef NTSTATUS(NTAPI* NtQueryVirtualMemoryType)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

typedef NTSTATUS(NTAPI* NtQueryObjectType)(
	_In_opt_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* NtQueryInformationFileType)(
	_In_ HANDLE FileHandle,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* NtQuerySectionType)(
	_In_ HANDLE SectionHandle,
	_In_ SECTION_INFORMATION_CLASS SectionInformationClass,
	_Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
	_In_ SIZE_T SectionInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

struct MemoryImageHideInformation {
	ULONG_PTR ImageStartAddress;
	ULONG_PTR ImageEndAddress;

	MemoryImageHideInformation(ULONG_PTR Start, ULONG_PTR End) {
		ImageStartAddress = Start;
		ImageEndAddress = End;
	}
};

VOID EraseModuleNameFromPeb();

BOOLEAN InitMemoryImageHideInformation();
BOOLEAN IsAddressShouldHide(ULONG_PTR Address);
BOOLEAN IsAddressShouldHide(PVOID Address);

