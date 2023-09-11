#ifndef __QUERYSYSTEM_H
#define __QUERYSYSTEM_H

#include "Hook-KdTrap/Utils.h"

typedef NTSTATUS(NTAPI* ExpQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

NTSTATUS NTAPI hookExpQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

extern ExpQuerySystemInformation_t origExpQuerySystemInformation;

#endif //__QUERYSYSTEM_H