#include <Windows.h>
#include <stdint.h>
#include "../fun.h"
#include <stdio.h>

#define SET_SYSCALL(x)	__asm__ __volatile__("mov %0, %%r13d\n\t" : : "a" (x) : "%r13")

#define NTDLL_MAX	3000000

enum syscalls_e {
	SYS_CREATEPROC = 0,
	SYS_MAX,
};

void entry(main_funs_t *fun) {
	uint8_t *ntdllBuf;
	uint16_t *ordinal;
	uint32_t numSys[SYS_MAX], *funName, *funAddr, exportVA;
	wchar_t filename_w[] = L"\\??\\c:\\Windows\\System32\\ntdll.dll";
	char strSys[] = "NtCreateUserProcess\0", *pStrSys, *name, *pName;
	PIMAGE_NT_HEADERS64 nt;
	PIMAGE_SECTION_HEADER exportSec = NULL, textSec;
	PIMAGE_EXPORT_DIRECTORY export;
	UNICODE_STRING filename;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statBlock;
	SIZE_T i, j, k;
	HANDLE hNtdll = NULL;

	/*
	for (i = 0; i < sizeof(statBlock); ++i) {
		*(((PBYTE)&statBlock) + i) = 0;
	}
	*/

	fun->RtlInitUnicodeString(&filename, filename_w);
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

	//export = (PIMAGE_EXPORT_DIRECTORY)(ntdllBuf + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	//funAddr = (uint32_t*)(ntdllBuf + export->AddressOfFunctions);
	//funName = (uint32_t*)(ntdllBuf + export->AddressOfNames);
	//ordinal = (uint16_t*)(ntdllBuf + export->AddressOfNameOrdinals);


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

	printf("%X\n", numSys[0]);
	return;
}
