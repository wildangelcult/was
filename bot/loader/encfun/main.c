#include <Windows.h>
#include <stdint.h>
#include "../fun.h"

void entry(main_funs_t *fun) {
	uint8_t *ntdllBuf;
	UNICODE_STRING filename;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statBlock;
	SIZE_T i;
	HANDLE hNtdll = NULL;
	wchar_t filename_w[] = L"\\??\\c:\\Windows\\System32\\ntdll.dll";

	for (i = 0; i < sizeof(statBlock); ++i) {
		*(((PBYTE)&statBlock) + i) = 0;
	}

	fun->RtlInitUnicodeString(&filename, filename_w);
	InitializeObjectAttributes(&attr, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);
	fun->NtCreateFile(&hNtdll, FILE_GENERIC_READ, &attr, &statBlock, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	ntdllBuf = (uint8_t*)fun->RtlAllocateHeap(fun->GetProcessHeap(), 0, 3000000);
	return;
}
