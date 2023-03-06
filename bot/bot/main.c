#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[%s] Driver built at %s\r\n", __FUNCTION__, __TIMESTAMP__);
	return STATUS_SUCCESS;
}
