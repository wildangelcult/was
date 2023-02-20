#ifndef __FUN_H
#define __FUN_H

#include <Windows.h>
#include <ntdef.h>
#include <winternl.h>

typedef struct main_funs_s {
	NTSTATUS (NTAPI *NtCreateFile)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
	NTSTATUS (NTAPI *NtReadFile)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
	HANDLE (WINAPI *GetProcessHeap)(VOID);
	PVOID (NTAPI *RtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
	VOID (NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString,PCWSTR SourceString);
	NTSTATUS (NTAPI *RtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);

	PVOID sys_uni;
} main_funs_t;

//typedef NTSTATUS NTAPI (*sys_NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, DWORD NewAccessProtection, PDWORD OldAccessProtection);

#endif //__FUN_H
