#ifndef __NTDLL_H
#define __NTDLL_H

#define SE_LOAD_DRIVER_PRIVILEGE	10
#define SERVICE_TYPE_KERNEL		1

#define SystemModuleInformation		11
#define SystemHandleInformation		16
#define SystemExtendedHandleInformation	64

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
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);

#endif //__NTDLL_H
