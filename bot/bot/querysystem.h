#ifndef __QUERYSYSTEM_H
#define __QUERYSYSTEM_H

#include "Hook-KdTrap/Utils.h"

typedef NTSTATUS (NTAPI* NtQuerySystemInformation_t)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

NTSTATUS NTAPI hookNtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

extern NtQuerySystemInformation_t origNtQuerySystemInformation;

#endif //__QUERYSYSTEM_H