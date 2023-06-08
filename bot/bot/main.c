#include <ntddk.h>
#include <intrin.h>

#include "Hook-KdTrap/HookKdTrap.h"
#include "handler.h"
#include "stdint.h"

__declspec(noinline) BOOLEAN fun(int n, int m) {
	int r;
	r = n * m;
	++r;
	return r >= 65;
}

ULONG_PTR setupDr(ULONG_PTR arg) {
	uint64_t dr7;

	__writedr(0, (uint64_t)fun);
	dr7 = __readdr(7);
	dr7 |= 0x1 << 1;
	dr7 &= ~(0xf << 16);
	__writedr(7, dr7);

	return 0;
}

extern uint32_t drHit;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	HookKdTrap(handler);

	KeIpiGenericCall(setupDr, 0);
	//__debugbreak();

	DbgPrintEx(0, 0, "[Bot] %p %p\n", __readdr(0), __readdr(7));
	DbgPrintEx(0, 0, "[Bot] %u\n", fun(4, 5));
	DbgPrintEx(0, 0, "[Bot] Hit %u\n", drHit);
	DbgPrintEx(0, 0, "[Bot] LOADED\n");
	return STATUS_SUCCESS;
}