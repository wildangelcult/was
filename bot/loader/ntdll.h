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

typedef unsigned short RTL_ATOM, *PRTL_ATOM;

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = 2,
	NonPagedPoolBaseCacheAligned = 4,
	NonPagedPoolBaseCacheAlignedMustS = 6,
	NonPagedPoolSession = 32,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = 516,
	NonPagedPoolSessionNx = 544,
} POOL_TYPE;

typedef PVOID (NTAPI *ExAllocatePoolWithTag_t)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
typedef VOID (NTAPI *ExFreePool_t)(PVOID P);

NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS NTAPI NtAddAtom(PWSTR AtomName, ULONG AtomNameLength, PRTL_ATOM Atom);

#endif //__NTDLL_H
