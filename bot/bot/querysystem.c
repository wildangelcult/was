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

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[0x0100];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	USHORT NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

__declspec(noinline) void setDr(PVOID param);

static void hookSystemProcessInformation(PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	ULONG nextOff, i;
	PSYSTEM_PROCESS_INFO curr;
	DbgPrintEx(0, 0, "[Bot] SystemProcessInformation - implementing\n");

	curr = SystemInformation;
	do {
		for (i = 0; i < curr->NumberOfThreads; ++i) {
			if (curr->Threads[i].StartAddress == setDr) {
				DbgPrintEx(0, 0, "[Bot] PID: %p Name: %wZ Thread count: %u\n", curr->UniqueProcessId, curr->ImageName, curr->NumberOfThreads);
			}
		}

		nextOff = curr->NextEntryOffset;
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
				hookSystemProcessInformation(SystemInformation, SystemInformationLength, ReturnLength);
				break;
			case SystemModuleInformation:
				DbgPrintEx(0, 0, "[Bot] SystemModuleInformation\n");
				break;
			/*
			case SystemHandleInformation:
				DbgPrintEx(0, 0, "[Bot] SystemHandleInformation\n");
				break;
			*/
			case SystemExtendedProcessInformation:
				DbgPrintEx(0, 0, "[Bot] SystemExtendedProcessInformation\n");
				break;
			/*
			case SystemExtendedHandleInformation:
				DbgPrintEx(0, 0, "[Bot] SystemExtendedHandleInformation\n");
				break;
			*/
			case SystemModuleInformationEx:
				DbgPrintEx(0, 0, "[Bot] SystemModuleInformationEx\n");
				break;
			case SystemProcessIdInformation:
				DbgPrintEx(0, 0, "[Bot] SystemProcessIdInformation\n");
				break;
			case SystemFullProcessInformation:
				DbgPrintEx(0, 0, "[Bot] SystemFullProcessInformation\n");
				break;
			default:
				break;
		}
	}

	return status;
}