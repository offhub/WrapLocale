#include "HideProcessInformation.h"
#include <list>
#include <string>

std::list<MemoryImageHideInformation> g_MemoryImageHideInformationList;
std::string                           g_CurrentModuleName;

NtQueryVirtualMemoryType OriginalNtQueryVirtualMemory = nullptr;
NtQueryObjectType OriginalNtQueryObject = nullptr;
NtQueryInformationFileType OriginalNtQueryInformationFile = nullptr;
NtQuerySectionType OriginalNtQuerySection = nullptr;

#define THIS_BASE reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase)

#define IF_HIDDEN_NAME(name) (wcsstr(name, L"SBIEDLL") != 0) || (wcsstr(name, L"WRAPLOCALE") != 0)

VOID EraseModuleNameFromPeb() {
    PPEB ProcessEnvironmentBlock = nullptr;
    PLIST_ENTRY FirstEntry = nullptr;
    PLIST_ENTRY CurrentEntry = nullptr;
    PLIST_ENTRY NextEntry = nullptr;
    PLDR_DATA_TABLE_ENTRY CurrentEntryData = nullptr;

    // Acquire the PEB lock to prevent concurrent modifications
    RtlAcquirePebLock();

    ProcessEnvironmentBlock = NtCurrentPeb();
    if (!ProcessEnvironmentBlock || !ProcessEnvironmentBlock->Ldr) {
        RtlReleasePebLock();
        return;
    }

    FirstEntry = CurrentEntry = ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink;
    
    // Safety check to prevent infinite loops
    if (!FirstEntry) {
        RtlReleasePebLock();
        return;
    }

    do {
        // Get the LDR_DATA_TABLE_ENTRY that contains this list entry
        CurrentEntryData = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        // Get the next entry before potentially modifying the list
        NextEntry = CurrentEntry->Flink;
        
        if (IsAddressShouldHide(CurrentEntryData->DllBase)) {
            // Update FirstEntry if we're removing the first entry
            if (FirstEntry == CurrentEntry) {
                FirstEntry = NextEntry;
            }
            
            // Remove from HashLinks list
            if (CurrentEntryData->HashLinks.Blink && CurrentEntryData->HashLinks.Flink) {
                CurrentEntryData->HashLinks.Blink->Flink = CurrentEntryData->HashLinks.Flink;
                CurrentEntryData->HashLinks.Flink->Blink = CurrentEntryData->HashLinks.Blink;
            }

            // Remove from InLoadOrderLinks list
            if (CurrentEntryData->InLoadOrderLinks.Blink && CurrentEntryData->InLoadOrderLinks.Flink) {
                CurrentEntryData->InLoadOrderLinks.Blink->Flink = CurrentEntryData->InLoadOrderLinks.Flink;
                CurrentEntryData->InLoadOrderLinks.Flink->Blink = CurrentEntryData->InLoadOrderLinks.Blink;
            }

            // Remove from InMemoryOrderLinks list
            if (CurrentEntryData->InMemoryOrderLinks.Blink && CurrentEntryData->InMemoryOrderLinks.Flink) {
                CurrentEntryData->InMemoryOrderLinks.Blink->Flink = CurrentEntryData->InMemoryOrderLinks.Flink;
                CurrentEntryData->InMemoryOrderLinks.Flink->Blink = CurrentEntryData->InMemoryOrderLinks.Blink;
            }

            // Remove from InInitializationOrderLinks list
            if (CurrentEntryData->InInitializationOrderLinks.Blink && CurrentEntryData->InInitializationOrderLinks.Flink) {
                CurrentEntryData->InInitializationOrderLinks.Blink->Flink = CurrentEntryData->InInitializationOrderLinks.Flink;
                CurrentEntryData->InInitializationOrderLinks.Flink->Blink = CurrentEntryData->InInitializationOrderLinks.Blink;
            }

            // Remove from NodeModuleLink list (if available - check structure definition)
            if (CurrentEntryData->NodeModuleLink.Blink && CurrentEntryData->NodeModuleLink.Flink) {
                CurrentEntryData->NodeModuleLink.Blink->Flink = CurrentEntryData->NodeModuleLink.Flink;
                CurrentEntryData->NodeModuleLink.Flink->Blink = CurrentEntryData->NodeModuleLink.Blink;
            }

            // Clear module name information
            if (CurrentEntryData->BaseDllName.Buffer && CurrentEntryData->BaseDllName.MaximumLength > 0) {
                RtlZeroMemory(CurrentEntryData->BaseDllName.Buffer, CurrentEntryData->BaseDllName.MaximumLength);
            }
            
            if (CurrentEntryData->FullDllName.Buffer && CurrentEntryData->FullDllName.MaximumLength > 0) {
                RtlZeroMemory(CurrentEntryData->FullDllName.Buffer, CurrentEntryData->FullDllName.MaximumLength);
            }
        }

        CurrentEntry = NextEntry;
    } while (CurrentEntry != FirstEntry && CurrentEntry != nullptr);

    RtlReleasePebLock();
}

NTSTATUS NTAPI HookNtQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
	if (IsAddressShouldHide(BaseAddress)) {
		switch (MemoryInformationClass) {
		case MemoryBasicInformation:
		case MemoryMappedFilenameInformation:
		case MemoryRegionInformation:
		case MemoryImageInformation:
		case MemoryRegionInformationEx:
		case MemoryEnclaveImageInformation:
		case MemoryBasicInformationCapped:
			return STATUS_ACCESS_DENIED;
		default:
			break;
		}
	}
	return OriginalNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookNtQueryObject(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength) {
	NTSTATUS Status = STATUS_SUCCESS;

	Status = OriginalNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

	if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation != nullptr) {
		UNICODE_STRING ObjectName = {};

		if (!NT_SUCCESS(RtlUpcaseUnicodeString(&ObjectName, &reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name, TRUE))) {
			return Status;
		}

		if (ObjectName.Buffer == NULL || ObjectName.Length == 0) {
			RtlFreeUnicodeString(&ObjectName);
			return Status;
		}

		if (ObjectName.Length < 7) {
			RtlFreeUnicodeString(&ObjectName);
			return Status;
		}

		if (IF_HIDDEN_NAME(ObjectName.Buffer)) {
			RtlZeroMemory(reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Buffer, reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.MaximumLength);
			reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Length = 0;
			RtlFreeUnicodeString(&ObjectName);
			return STATUS_ACCESS_DENIED;
		}

		RtlFreeUnicodeString(&ObjectName);
	}

	return Status;
}

NTSTATUS NTAPI HookNtQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {
	NTSTATUS			   Status = STATUS_SUCCESS;
	UNICODE_STRING		 FileName = {};
	UNICODE_STRING		 UpperFileName = {};
	PFILE_ALL_INFORMATION  AllInformation = {};
	PFILE_NAME_INFORMATION NameInformation = {};

	Status = OriginalNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

	if (NT_SUCCESS(Status) && FileInformation != nullptr) {
		switch (FileInformationClass) {
		case FileNameInformation:
			NameInformation = reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation);

			FileName.Buffer = NameInformation->FileName;
			FileName.Length = static_cast<USHORT>(NameInformation->FileNameLength);
			FileName.MaximumLength = static_cast<USHORT>(NameInformation->FileNameLength);

			if (!NT_SUCCESS(RtlUpcaseUnicodeString(&UpperFileName, &FileName, TRUE))) {
				return Status;
			}

			if (UpperFileName.Buffer == NULL || UpperFileName.Length == 0) {
				RtlFreeUnicodeString(&UpperFileName);
				return Status;
			}

			if (UpperFileName.Length < 7) {
				RtlFreeUnicodeString(&UpperFileName);
				return Status;
			}

			if (IF_HIDDEN_NAME(UpperFileName.Buffer)) {
				RtlZeroMemory(FileInformation, Length);
				RtlFreeUnicodeString(&UpperFileName);
				return STATUS_ACCESS_DENIED;
			}

			RtlFreeUnicodeString(&UpperFileName);

			return Status;

		case FileAllInformation:
			AllInformation = reinterpret_cast<PFILE_ALL_INFORMATION>(FileInformation);
			NameInformation = &AllInformation->NameInformation;

			FileName.Buffer = NameInformation->FileName;
			FileName.Length = static_cast<USHORT>(NameInformation->FileNameLength);
			FileName.MaximumLength = static_cast<USHORT>(NameInformation->FileNameLength);

			if (!NT_SUCCESS(RtlUpcaseUnicodeString(&UpperFileName, &FileName, TRUE))) {
				return Status;
			}

			if (UpperFileName.Buffer == NULL || UpperFileName.Length == 0) {
				RtlFreeUnicodeString(&UpperFileName);
				return Status;
			}

			if (UpperFileName.Length < 7) {
				RtlFreeUnicodeString(&UpperFileName);
				return Status;
			}

			if (IF_HIDDEN_NAME(UpperFileName.Buffer)) {
				RtlZeroMemory(FileInformation, Length);
				RtlFreeUnicodeString(&UpperFileName);
				return STATUS_ACCESS_DENIED;
			}

			RtlFreeUnicodeString(&UpperFileName);

			return Status;

		default:
			break;
		}
	}

	return Status;
}

NTSTATUS NTAPI HookNtQuerySection(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
	NTSTATUS Status = STATUS_SUCCESS;

	Status = OriginalNtQuerySection(SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);

	if (NT_SUCCESS(Status) && SectionInformation != nullptr && SectionInformationClass == SectionOriginalBaseInformation) {
		if (IsAddressShouldHide(*reinterpret_cast<PULONG_PTR>(SectionInformation))) {
			ZeroMemory(SectionInformation, SectionInformationLength);
			return STATUS_ACCESS_DENIED;
		}
	}

	return Status;
}

BOOLEAN InitMemoryImageHideInformation() {
	PPEB                  ProcessEnvironmentBlock = nullptr;
	PLDR_DATA_TABLE_ENTRY FirstEntry = nullptr;
	PLDR_DATA_TABLE_ENTRY CurrentEntry = nullptr;
	BOOLEAN               IsSandboxieModuleFound = FALSE;
	BOOLEAN               IsCurrentModuleFound = FALSE;

	ProcessEnvironmentBlock = NtCurrentPeb();
	FirstEntry = CurrentEntry = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	while (reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CONTAINING_RECORD(CurrentEntry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)) != FirstEntry) {

		if (_wcsnicmp(CurrentEntry->BaseDllName.Buffer, L"WrapLocale", CurrentEntry->BaseDllName.Length) == 0) {
			g_MemoryImageHideInformationList.push_back(MemoryImageHideInformation(THIS_BASE, THIS_BASE + CurrentEntry->SizeOfImage));
			IsSandboxieModuleFound = TRUE;
		}

		if ((reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase) < reinterpret_cast<ULONG_PTR>(InitMemoryImageHideInformation)) && ((THIS_BASE + CurrentEntry->SizeOfImage) > reinterpret_cast<ULONG_PTR>(InitMemoryImageHideInformation))) {
			g_MemoryImageHideInformationList.push_back(MemoryImageHideInformation(THIS_BASE, THIS_BASE + CurrentEntry->SizeOfImage));
			IsCurrentModuleFound = TRUE;
		}

		CurrentEntry = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry->InMemoryOrderLinks.Flink), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	}

	return (IsSandboxieModuleFound == TRUE) && (IsCurrentModuleFound == TRUE);
}

BOOLEAN IsAddressShouldHide(ULONG_PTR Address) {
	for (auto& Information : g_MemoryImageHideInformationList) {
		if (Information.ImageStartAddress <= Address && Information.ImageEndAddress >= Address)
			return TRUE;
	}

	return FALSE;
}

BOOLEAN IsAddressShouldHide(PVOID Address) {
	return IsAddressShouldHide(reinterpret_cast<ULONG_PTR>(Address));
}
