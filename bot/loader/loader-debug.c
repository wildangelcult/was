#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include "fun.h"

NTSTATUS NTAPI sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS NTAPI sys_NtCreateFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
NTSTATUS NTAPI sys_NtReadFile(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
void sys_uni();

void entry(main_funs_t* f);

//char buf[] = {0x90, 0x90, 0x90, 0x90, 0xC3};

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
	main_funs.sys_uni = sys_uni;

	//(*(void(*)(main_funs_t*))main_fun)(&main_funs);
	entry(&main_funs);

	return 0;
}
