#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

NTSTATUS NTAPI sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

int main(int argc, char *argv[]) {
	HANDLE base, importBase;
	PIMAGE_IMPORT_DESCRIPTOR import;
	PIMAGE_EXPORT_DIRECTORY export;
	char path[MAX_PATH];

	base = GetModuleHandle(NULL);

	import = (PIMAGE_IMPORT_DESCRIPTOR)(base + ((PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; import->Name; ++import) {
		importBase = GetModuleHandle(base + import->Name);
		GetModuleFileName(importBase, path, MAX_PATH);
		printf("%s\n", path);
	}

	NtClose(base);

	return 0;
}
