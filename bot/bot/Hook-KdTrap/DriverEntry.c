#include "Utils.h"
#include "HookKdTrap.h"
#include "DriverEntry.h"

//#define __nop() __asm__ __volatile__("nop" : : : )

__forceinline void KSleep(uint64_t ms)
{
    LARGE_INTEGER delay;
    delay.QuadPart = -1000 * ms;
    KeDelayExecutionThread(KernelMode, TRUE, &delay);
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(0, 0, "UnLoad\n");

	//todo Stop thread exceptionfun
	UnHookKdTrap();

	//__debugbreak();
}

BOOLEAN Handler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{
	if (Context->Rip - (uint64_t)exceptionfun < 0x500)
	{		
		if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
		{
			// mov al,[00000000]
			if (*(uint32_t*)Context->Rip == 0x25048A)
			{
				Context->Rip += 7;
				return TRUE;
			}
		}

		if (ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)
		{
			if (*(USHORT*)(Context->Rip) == 0x220F) // mov cr
			{
				Context->Rip += 3;
				return TRUE;
			}
		}

	}

	return FALSE;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	HookKdTrap(Handler);

	HANDLE thread = NULL;
	PsCreateSystemThread(&thread, 0L, NULL, NULL, NULL, (PKSTART_ROUTINE)exceptionfun, 0);

	return STATUS_SUCCESS;
}

__declspec(noinline) void TestSeh()
{
	_disable();
	__try
	{
		__nop();
		__debugbreak();
		KeBugCheck(0);
	}
	__except (1)
	{
		__nop();
		_enable();
	}

	__try
	{
#pragma warning(disable : 4197)
		volatile uint64_t a = (volatile uint64_t)1;
		volatile uint64_t b = (volatile uint64_t)0;
		__nop();
		volatile uint64_t c = a / b;
		KeBugCheck(0);
	}
	__except (1)
	{
		__nop();
	}
}

void exceptionfun()
{
	while (1)
	{
		//test seh are working
		TestSeh();
		
		DbgPrintEx(0, 0, "[HookKdTrap] Exception up ahead\n");
		//try some dangerous, see Handler
		*(volatile uint8_t*)0;
		__writecr3(__readcr3() | (uint64_t)1 << 63);
		*(volatile uint8_t*)0;
		DbgPrintEx(0, 0, "[HookKdTrap] After exception\n");

		//can't do this since this kind of fault doesn't go into KdTrap 
		//KiPageFault->MmAccessFault->MiSystemFault->BugCheck 
		//*(uint64_t*)exceptionfun = 0x6969696969696969;

		KSleep(5000);
	}

}
