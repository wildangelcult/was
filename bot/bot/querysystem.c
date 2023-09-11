#include "querysystem.h"
#include "handler.h"

NTSTATUS NTAPI hookExpQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	return origExpQuerySystemInformation(SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
}