#ifndef __DRIVERENTRY_H
#define __DRIVERENTRY_H

void exceptionfun();

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);

ULONG GetWinver();

int _fltused;

#endif //__DRIVERENTRY_H
