#ifndef __HOOKKDTRAP_H
#define __HOOKKDTRAP_H

typedef BOOLEAN (__stdcall *ExceptionCallback)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);

void HookKdTrap(ExceptionCallback Handler);

void UnHookKdTrap();

//uint64_t BpMe(uint64_t line);

#endif //__HOOKKDTRAP_H
