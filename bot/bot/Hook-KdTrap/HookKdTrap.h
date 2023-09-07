#ifndef __HOOKKDTRAP_H
#define __HOOKKDTRAP_H

#include "../stdint.h"

typedef BOOLEAN (__stdcall *ExceptionCallback)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);

typedef struct funAddr_s {
	uint64_t NtEnumerateKey, ExpQuerySystemInformation;
} funAddr_t;

extern funAddr_t funAddr;

void HookKdTrap(ExceptionCallback Handler);

void UnHookKdTrap();

//uint64_t BpMe(uint64_t line);

#endif //__HOOKKDTRAP_H
