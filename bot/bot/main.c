#include <ntddk.h>

#define GETREG(x, reg)	__asm__ __volatile__("mov %%" #reg ", %0\n\t" : "=r" (x) : : )

#define MAX_CORE 32

struct {
	UINT64 dr0, dr1, dr2, dr3, dr6, dr7;
} reg[MAX_CORE];

volatile long int cpuN = 0;

ULONG_PTR globalCall(ULONG_PTR arg) {
	UINT32 cpu = __readgsdword(0x24 + 0x180);
	InterlockedIncrement(&cpuN);
	GETREG(reg[cpu].dr0, db0);
	GETREG(reg[cpu].dr1, db1);
	GETREG(reg[cpu].dr2, db2);
	GETREG(reg[cpu].dr3, db3);
	GETREG(reg[cpu].dr6, db6);
	GETREG(reg[cpu].dr7, db7);
	return 0;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[%s] Driver unload\r\n", __FUNCTION__);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	SIZE_T i;

	DriverObject->DriverUnload = DriverUnload;
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[%s] Driver built at %s\r\n", __FUNCTION__, __TIMESTAMP__);

	KeIpiGenericCall(globalCall, 0);
	for (i = 0; i < cpuN; ++i) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[%s]\r\n\tDR0 : 0x%x\r\n\tDR1 : 0x%x\r\n\tDR2 : 0x%x\r\n\tDR3 : 0x%x\r\n\tDR6 : 0x%x\r\n\tDR7 : 0x%x\r\n",
			__FUNCTION__, reg[i].dr0, reg[i].dr1, reg[i].dr2, reg[i].dr3, reg[i].dr6, reg[i].dr7
		);
	}
	return STATUS_SUCCESS;
}
