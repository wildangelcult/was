#include "querysystem.h"
#include "handler.h"

//structs
//https://gist.github.com/TheWover/799822ce3d1239e0bd5764ac0b0adfda

HANDLE hiddenDriverPid;

__declspec(noinline) void setDr(PVOID param);

static void hookSystemProcessInformation(PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	ULONG nextOff, i;
	PSYSTEM_PROCESS_INFO curr;
	DbgPrintEx(0, 0, "[Bot] SystemProcessInformation - implementing\n");

	curr = SystemInformation;
	do {
		if (curr->UniqueProcessId == hiddenDriverPid) {
			DbgPrintEx(0, 0, "[Bot] PID: %p Name: %wZ\n", curr->UniqueProcessId, curr->ImageName);
		}

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