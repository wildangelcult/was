#include "Utils.h"
#include "HookKdTrap.h"

//extern ULONG NtGlobalFlag;

#define BpMe

PVOID NtBase = 0;

typedef struct _CONTEXT_RETURN {
	PVOID   Stack;//rsp
	uint64_t Function;//rip
	uint64_t RCX;
	uint64_t RDX;
	uint64_t R8;
	uint64_t R9;
	uint64_t RAX;

	uint64_t R12;
	uint64_t R13;
	uint64_t R14;
	uint64_t R15;

	uint64_t RDI;
	uint64_t RSI;
	uint64_t RBX;
	uint64_t RBP;

	uint64_t RFlags;
} CONTEXT_RETURN;

//void HalpTscQueryCounterOrdered(uint64_t a1, uint64_t a2);
void HookPosition(uint64_t a1, uint64_t a2);
UINT64 CalledHookTimes = 0;//will be big
void* CalloutReturn(CONTEXT_RETURN*);
uint64_t GetR12();
uint64_t GetR13();
void SetR13(uint64_t NewR13);
void SetR12(uint64_t NewR12);
uint64_t HalpStallCounter = 0;
uint64_t OldHalQueryCounter = 0;

typedef void (__fastcall *KdAcquireDebuggerLockFn)(unsigned __int8* a1);
KdAcquireDebuggerLockFn KdAcquireDebuggerLock = 0;

typedef __int64 (__fastcall *KdReleaseDebuggerLockFn)(unsigned __int8 a1);
KdReleaseDebuggerLockFn KdReleaseDebuggerLock = 0;

/*
 
00 ffffe104`e7d16598 fffff801`11871824 nt!KeBugCheckEx
01 ffffe104`e7d165a0 fffff801`1164233f nt!MiRaisedIrqlFault+0x15a42c
02 ffffe104`e7d165f0 fffff801`11809cd8 nt!MmAccessFault+0x4ef
03 ffffe104`e7d16790 fffff801`11955e46 nt!KiPageFault+0x358
04 ffffe104`e7d16920 fffff801`11956d63 nt!MiBuildForkPte+0x5fa
05 ffffe104`e7d16a50 fffff801`11cd94b1 nt!MiCloneVads+0x4ab
06 ffffe104`e7d16ce0 fffff801`11be3d87 nt!MiCloneProcessAddressSpace+0x261
07 ffffe104`e7d16dc0 fffff801`11a58a57 nt!MmInitializeProcessAddressSpace+0x20764b
08 ffffe104`e7d16fb0 fffff801`11bc6162 nt!PspAllocateProcess+0x1d13
09 ffffe104`e7d17720 fffff801`11d071f5 nt!PspCreateProcess+0x242
0a ffffe104`e7d179f0 fffff801`1180d9f5 nt!NtCreateProcessEx+0x85
0b ffffe104`e7d17a50 00007ffe`3fd6da64 nt!KiSystemServiceCopyEnd+0x25
0c 000000cb`29e8f118 00000000`00000000 ntdll!NtCreateProcessEx+0x14

0: kd > k
#  Call Site
00 KMDFDriver1!HookPosition[E:\Visual_Studio_File\HelloWorld\KMDF Driver1\asm.asm @ 19]
01 nt!KeStallExecutionProcessor + 0x120
02 nt!KeFreezeExecution + 0x110
03 nt!KdEnterDebugger + 0x6d
04 nt!KdpReport + 0x74
05 nt!KdpTrap + 0x160
06 nt!KdTrap + 0x2d
07 nt!KiDispatchException + 0x177
08 nt!KxExceptionDispatchOnExceptionStack + 0x12
09 nt!KiExceptionDispatchOnExceptionStackContinue
0a nt!KiExceptionDispatch + 0x125
0b nt!KiGeneralProtectionFault + 0x320
0c nt!KiCustomRecurseRoutine0 + 0xd
0d nt!KiCustomRecurseRoutine9 + 0xd
0e nt!KiCustomRecurseRoutine8 + 0xd
0f nt!KiCustomRecurseRoutine7 + 0xd
10 nt!KiCustomAccessRoutine7 + 0x22
11 nt!ExpTimeRefreshDpcRoutine + 0x9f
12 nt!KiSwInterruptDispatch + 0xfe6
13 nt!KiProcessExpiredTimerList + 0x172
14 nt!KiRetireDpcList + 0x5dd
15 nt!KiIdleLoop + 0x9e
*/

//modify if not enough
#define MAX_CORE 32

struct DBGCTX
{
	struct
	{
		EXCEPTION_RECORD ExceptionContex[MAX_CORE];
		CONTEXT ExceptionRecord[MAX_CORE];
		CONTEXT_RETURN ReturnContex[MAX_CORE];
	}ThisCtx;

	struct
	{
		EXCEPTION_RECORD ExceptionContex[MAX_CORE];
		CONTEXT ExceptionRecord[MAX_CORE];
		CONTEXT_RETURN ReturnContex[MAX_CORE];
	}LastCtx;

};

//__declspec(dllexport) DBGCTX DbgCtx;

uint64_t KiDispatchException = 0;
uint64_t KdTrap = 0;
uint64_t KdpTrap = 0;
uint64_t KdEnterDebugger = 0;
uint64_t KdpReport = 0;
uint64_t KeFreezeExecution = 0;
//uint64_t* pKdDebuggerLock = 0;
//volatile int64_t bpCnt = 0;
//volatile int64_t hkCnt = 0;

void NTContinue(PCONTEXT Context, ULONG64 Rip)
{
	CONTEXT_RETURN Ctx;
	Ctx.Stack = (PVOID)Context->Rsp;
	Ctx.Function = Rip;
	Ctx.RAX = Context->Rax;

	Ctx.RCX = Context->Rcx;
	Ctx.RDX = Context->Rdx;
	Ctx.R8 = Context->R8;
	Ctx.R9 = Context->R9;

	Ctx.R12 = Context->R12;
	Ctx.R13 = Context->R13;
	Ctx.R14 = Context->R14;
	Ctx.R15 = Context->R15;

	Ctx.RDI = Context->Rdi;
	Ctx.RSI = Context->Rsi;
	Ctx.RBX = Context->Rbx;
	Ctx.RBP = Context->Rbp;

	Ctx.RFlags = Context->EFlags;

	CalloutReturn(&Ctx);

	BpMe(__LINE__);
	KeBugCheck(0);
}

/*
uint32_t LastLine = 0;
uint32_t ThisLine = 0;
uint64_t BpMe(uint64_t line)
{
	LastLine = ThisLine;
	ThisLine = line;
	//ba e1 KMDFDriver1!BpMe
	//DbgPrintEx(0, 0, "line:%lld\n", line);
	//__debugbreak();
	return line;
}
*/

ULONG g_Winver = 0;
ULONG GetWinver()
{
	if (!g_Winver)
	{
		PsGetVersion(0, 0, &g_Winver, 0);
	}
	return g_Winver;
}

uint32_t ExceptionStackOffset = 0;
uint32_t GetExceptionStackOffset()
{
	if (!ExceptionStackOffset)
	{
		if (GetWinver() >= 22000)
		{
			ExceptionStackOffset = 0x8268;
		}
		else
		{
			switch (GetWinver())
			{
			case 19045:
			case 19044:
			case 19043:
			case 19042:
			case 19041:
				ExceptionStackOffset = 0x7f28;
				break;

			case 18363:
			case 18362:
				ExceptionStackOffset = 0x5c28;
				break;

			default:
				break;
			}
		}

	}

	if (ExceptionStackOffset)
	{
		ExceptionStackOffset += 0x180;
	}
	else
	{
		__debugbreak();
	}

	return ExceptionStackOffset;
}

BOOLEAN IsCurrentExceptionOnExceptionStack()
{
	//winver too low, windows is not implementing Exception Stack
	if (!ExceptionStackOffset)
		return FALSE;

	if (
		__readgsbyte(ExceptionStackOffset - 2)	/* ExceptionStackActive */
		)
	{
		return FALSE;
	}

	return __readgsqword(ExceptionStackOffset) - (uint64_t)_AddressOfReturnAddress() < (uint64_t)0x6000;
}

typedef BOOLEAN (*stackTraceFn)(void* traceCtx, void** stack_current);

//template<typename F>
BOOLEAN DoStackTrace(stackTraceFn f, void* traceCtx, void* CustomStackFrame /*= 0*/, BOOLEAN ReverseDirection /*= FALSE*/)
{
	//__writegsbyte(0x5DA6, 1);// no exception stack

	void** stack_max = (void**)__readgsqword(0x1a8);
	void** stack_frame = (void**)_AddressOfReturnAddress();
	if (CustomStackFrame)
		stack_frame = (PVOID*)CustomStackFrame;

	BOOLEAN bExceptionOnExceptionStack = IsCurrentExceptionOnExceptionStack();

	if (bExceptionOnExceptionStack)
	{
		//BpMe(__LINE__);
		void** ExceptionStack_max = (PVOID*)__readgsqword(ExceptionStackOffset);
		stack_max = ExceptionStack_max;
	}
	else
	{
		if ((uint64_t)stack_max - (uint64_t)stack_frame > 0x6000 || stack_frame > stack_max)
		{
			//BpMe(__LINE__);
			return FALSE;
		}
	}

	if (ReverseDirection)
	{
		for (void** stack_current = stack_frame; stack_current < stack_max; ++stack_current)
		{
			if (f(traceCtx, stack_current))
			{
				return TRUE;
			}
		}
	}
	else
	{
		for (void** stack_current = stack_max; stack_current > stack_frame; --stack_current)
		{
			if (f(traceCtx, stack_current))
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

ExceptionCallback g_Handler = 0;
/*

00 KMDFDriver1!HookPosition
01 nt!KeStallExecutionProcessor+0x9b
02 nt!KeFreezeExecution+0x110
03 nt!KdEnterDebugger+0x6d
04 nt!KdpReport+0x74
05 nt!KdpTrap+0x160
06 nt!KdTrap+0x2d
07 nt!KiDispatchException+0x177
08 nt!KxExceptionDispatchOnExceptionStack+0x12
09 nt!KiExceptionDispatchOnExceptionStackContinue
0a nt!KiExceptionDispatch+0x125
0b nt!KiPageFault+0x443
0c nt!MiFastLockLeafPageTable+0x108
0d nt!MiMakeHyperRangeAccessible+0x20f
0e nt!MiExpandVadBitMap+0x8c
0f nt!MiInitializeVadBitMap+0x91
10 nt!MmInitializeProcessAddressSpace+0x19b
11 nt!PspAllocateProcess+0x1d42
12 nt!NtCreateUserProcess+0xa17
13 nt!KiSystemServiceCopyEnd+0x25
14 0x00007ffc`7c14e614


00 KMDFDriver1!ExceptionHandler
01 KMDFDriver1!HookPosition+0xa9
02 hal!KeStallExecutionProcessor+0xac
03 nt!KeFreezeExecution+0x26a
04 nt!KdEnterDebugger+0x64
05 nt!KdpReport+0x71
06 nt!KdpTrap+0x14d
07 nt!KdTrap+0x2c
08 nt!KiDispatchException+0x15f
09 nt!KiExceptionDispatch+0x11d
0a nt!KiBreakpointTrap+0x318
0b KMDFDriver1!DriverEntry+0xe0
0c nt!IopLoadDriver+0x4c2
0d nt!IopLoadUnloadDriver+0x4e
0e nt!ExpWorkerThread+0x105
0f nt!PspSystemThreadStartup+0x55
10 nt!KiStartSystemThread+0x2a
*/

typedef struct {
	CONTEXT_RETURN ReturnCtx;
	BOOLEAN bRbxFound, bNonVolatileRegFound, bStackFound, bRFlagsFound;
} trace_ExceptionHandler_ctx;

BOOLEAN trace_ExceptionHandler(void* traceCtx, void** stack_current) {
	trace_ExceptionHandler_ctx *ctx = traceCtx;
	if (!ctx->bRFlagsFound)
	{
		if (*(uint64_t*)(stack_current) > KdEnterDebugger &&
			*(uint64_t*)(stack_current)-KdEnterDebugger < 0x100 &&
			*(uint8_t*)(*(uint64_t*)(stack_current)-5) == 0xE8 &&			/* Make sure it's a call */
			*(uint32_t*)(*(uint64_t*)(stack_current)) == 0x48f08a44			/* mov r14b, al;  mov xxx */
			)
		{
			//BpMe(__LINE__);
			ctx->ReturnCtx.RFlags = *(uint64_t*)((uint64_t)stack_current - 0x8);
			ctx->bRFlagsFound = TRUE;
		}
		return FALSE;
	}

	if (!ctx->bNonVolatileRegFound)
	{
		if (*(uint64_t*)(stack_current) > KdpTrap && *(uint64_t*)(stack_current)-KdpTrap < 0x250)
		{
			ctx->ReturnCtx.RBP = *(uint64_t*)((uint64_t)stack_current + 0x10);
			ctx->ReturnCtx.RSI = *(uint64_t*)((uint64_t)stack_current + 0x18);
			ctx->ReturnCtx.RDI = *(uint64_t*)((uint64_t)stack_current + 0x20);

			ctx->ReturnCtx.R13 = *(uint64_t*)((uint64_t)stack_current - 0x8);
			ctx->ReturnCtx.R14 = *(uint64_t*)((uint64_t)stack_current - 0x10);
			ctx->ReturnCtx.R15 = *(uint64_t*)((uint64_t)stack_current - 0x18);

			ctx->ReturnCtx.R12 = GetR12();
			ctx->bNonVolatileRegFound = TRUE;
		}
		return FALSE;
	}

	if (!ctx->bRbxFound)
	{
		if (*(uint64_t*)(stack_current) > KdTrap && *(uint64_t*)(stack_current)-KdTrap < 0x50)
		{
			if (MmIsAddressValid(*(PVOID*)((uint64_t)stack_current + 8)))
			{
				ctx->ReturnCtx.RBX = *(uint64_t*)((uint64_t)stack_current + 8);
				ctx->bRbxFound = TRUE;
			}
		}
		return FALSE;
	}

	if (!ctx->bStackFound)
	{
		if (*(uint64_t*)(stack_current) > KiDispatchException + 0x100 &&
			*(uint64_t*)(stack_current)-KiDispatchException < 0x400)
		{
			ctx->ReturnCtx.Function = *(uint64_t*)(stack_current);
			//ctx.RBX = *(uint64_t*)((uint64_t)stack_current + 8);
			ctx->ReturnCtx.Stack = (PVOID)((uint64_t)stack_current + 8);
			ctx->bStackFound = TRUE;
		}
		return FALSE;
	}

	return TRUE;
}

void ExceptionHandler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{
	//enviroment: interrupt disabled 
	//todo : relpace unreliable SetR1X/GetR1X 

	//InterlockedIncrement64(&bpCnt);

	if (!ExceptionRecord || !Context || (uint64_t)ExceptionRecord->ExceptionAddress != Context->Rip)
	{
		BpMe(__LINE__);
		KeBugCheck(0);
	}

	//auto CurrentCpuNumber = __readgsdword(0x24 + 0x180);
	//DbgCtx.LastCtx.ExceptionContex[CurrentCpuNumber] = DbgCtx.ThisCtx.ExceptionContex[CurrentCpuNumber];
	//DbgCtx.LastCtx.ExceptionRecord[CurrentCpuNumber] = DbgCtx.ThisCtx.ExceptionRecord[CurrentCpuNumber];

	//DbgCtx.ThisCtx.ExceptionContex[CurrentCpuNumber] = *ExceptionRecord;
	//DbgCtx.ThisCtx.ExceptionRecord[CurrentCpuNumber] = *Context;


	if ((uint64_t)ExceptionRecord->ExceptionAddress > KdpTrap &&
		(uint64_t)ExceptionRecord->ExceptionAddress - KdpTrap < 0x250)
		KeBugCheck(0);

	if (g_Handler)
	{
		if (g_Handler(ExceptionRecord, Context))
		{
			NTContinue(Context, Context->Rip);
			KeBugCheck(0);
		}
	}

	/*
		it's other type of exception, continue to:

		kernel:
				|| !(unsigned __int8)KdTrap(a3, v14, (int)ExceptionRecord, (int)&v29, 0, 0)
			here->    && !RtlDispatchException(ExceptionRecord, (PCONTEXT)&v29))
				&& !(unsigned __int8)KdTrap(a3, v14, (int)ExceptionRecord, (int)&v29, 0, 1) )

		user:
			 if ( !KeGetCurrentThread()->ApcState.Process[1].AffinityPadding[9] && !KdIgnoreUmExceptions && v19 != -2147483597
			  || IsThisAKdTrap )
				{
					if ( KdTrap((__int64)TrapFrame, (__int64)ExceptionFrame_1, ExceptionRecord, (__int64)&Context, Context, 0) )
					{
						WILL NOT EXECUTE;
					}
			here->

	*/

	//CONTEXT_RETURN ReturnCtx{};
	//ReturnCtx.RAX = 0;

	// cost 8 hour for writing this stupid code 
	//ReturnCtx.RFlags = Context->EFlags;		
	//if (!IsCurrentExceptionOnExceptionStack())
	//	ReturnCtx.RFlags |= 0x200;
	//
	//if (ExGetPreviousMode() == UserMode)
	//	ReturnCtx.RFlags |= 0x40000;
	//
	////if((Context->SegCs & 3) == 0)
	////	ReturnCtx.RFlags = Context->EFlags | 0x200;
	////else
	////	ReturnCtx.RFlags = __readeflags() | 0x200;


	
	trace_ExceptionHandler_ctx traceCtx;
	traceCtx.ReturnCtx.RAX = 0;
	traceCtx.bRbxFound = FALSE;
	traceCtx.bNonVolatileRegFound = FALSE;
	traceCtx.bStackFound = FALSE;
	traceCtx.bRFlagsFound = FALSE;


	BOOLEAN traceResult = DoStackTrace(trace_ExceptionHandler, &traceCtx, _AddressOfReturnAddress(), TRUE);


	if (!traceResult)
	{
		BpMe(__LINE__);
		KeBugCheck(0);
	}

	//DbgPrintEx(0, 0, "Stack:%p, Function:%llx, RAX:%llx, R12:%llx, R13:%llx, R14:%llx, R15:%llx, RDI:%llx, RSI:%llx, RBX:%llx, RBP:%llx\n",
	//	ctx.Stack, ctx.Function, ctx.RAX, ctx.R12, ctx.R13, ctx.R14, ctx.R15, ctx.RDI, ctx.RSI, ctx.RBX, ctx.RBP);
	
	//DbgCtx.LastCtx.ReturnContex[CurrentCpuNumber] = DbgCtx.ThisCtx.ReturnContex[CurrentCpuNumber];
	//DbgCtx.ThisCtx.ReturnContex[CurrentCpuNumber] = ReturnCtx;

	BpMe(__LINE__);

	CalloutReturn(&traceCtx.ReturnCtx);

	BpMe(__LINE__);
	KeBugCheck(0);
}

typedef struct {
	BOOLEAN bKeStallExecutionProcessor, bKeFreezeExecution, bKdpReport, bKdpTrap, bKdTrap, bKiDispatchException;
} trace_CheckCallCtx_ctx;

BOOLEAN trace_CheckCallCtx(void* traceCtx, void** stack_current) {
	trace_CheckCallCtx_ctx *ctx = traceCtx;
	if (*(uint64_t*)stack_current == 0)
		return FALSE;

	if (!ctx->bKeStallExecutionProcessor)
	{
		if (*(uint64_t*)stack_current > (uint64_t)KeStallExecutionProcessor + 0x50 &&
			*(uint64_t*)stack_current - (uint64_t)KeStallExecutionProcessor < 0x200)
			ctx->bKeStallExecutionProcessor = TRUE;

		return FALSE;
	}

	if (!ctx->bKeFreezeExecution)
	{
		if (*(uint64_t*)stack_current > KeFreezeExecution + 0x50 &&
			*(uint64_t*)stack_current - KeFreezeExecution < 0x200)
			ctx->bKeFreezeExecution = TRUE;

		return FALSE;
	}

	if (!ctx->bKdpReport)
	{
		if (*(uint64_t*)stack_current > KdpReport + 0x50 &&
			*(uint64_t*)stack_current - KdpReport < 0x150)
			ctx->bKdpReport = TRUE;

		return FALSE;
	}

	if (!ctx->bKdpTrap)
	{
		if (*(uint64_t*)stack_current > KdpTrap + 0x50 &&
			*(uint64_t*)stack_current - KdpTrap < 0x250)
			ctx->bKdpTrap = TRUE;

		return FALSE;
	}

	if (!ctx->bKdTrap)
	{
		if (*(uint64_t*)stack_current > KdTrap &&
			*(uint64_t*)stack_current - KdTrap < 0x50)
			ctx->bKdTrap = TRUE;

		return FALSE;
	}

	if (!ctx->bKiDispatchException)
	{
		if (*(uint64_t*)stack_current > KiDispatchException + 0x100 &&
			*(uint64_t*)stack_current - KiDispatchException < 0x400)
			ctx->bKiDispatchException = TRUE;

		return FALSE;
	}

	return TRUE;
}

uint64_t CheckCallCtx()
{
	/*
	Find :
		nt!KeStallExecutionProcessor+0x120
		nt!KeFreezeExecution+0x110
		//nt!KdEnterDebugger+0x6dba
		nt!KdpReport+0x74
		nt!KdpTrap+0x160
		nt!KdTrap+0x2d
		nt!KiDispatchException+0x177

	todo :
		Increase code efficiency by recognize irrevalent calls and return early.
	*/

	trace_CheckCallCtx_ctx traceCtx;
	traceCtx.bKeStallExecutionProcessor = FALSE;
	traceCtx.bKeFreezeExecution = FALSE;
	traceCtx.bKdpReport = FALSE;
	traceCtx.bKdpTrap = FALSE;
	traceCtx.bKdTrap = FALSE;
	traceCtx.bKiDispatchException = FALSE;

	BOOLEAN traceResult = DoStackTrace(trace_CheckCallCtx, &traceCtx, _AddressOfReturnAddress(), TRUE);

	return traceResult;
}

typedef struct {
	uint64_t ExceptionRecord;
	uint64_t CorruptContext, CorruptR12;
	BOOLEAN bFoundExceptionRecord, bFoundCorruptReg;
} trace_FindExceptionRecord_ctx;

BOOLEAN trace_FindExceptionRecord(void* traceCtx, void** stack_current) {
	trace_FindExceptionRecord_ctx *ctx = traceCtx;
	if (!ctx->bFoundCorruptReg)
	{
		if (*(uint64_t*)(stack_current) > KeFreezeExecution &&
			*(uint64_t*)(stack_current)-KeFreezeExecution < 0x200)
		{
			//BpMe(__LINE__);
			if (GetWinver() <= 18363)
			{
				//BpMe(__LINE__);
				//r14
				uint64_t NewIrql = *(uint64_t*)((uint64_t)stack_current - 4 * 8);
				__writecr8(NewIrql);
			}
			else
			{
				if (ctx->CorruptContext)
				{
					if ((*(uint64_t*)((uint64_t)stack_current - 3 * 8) & ~0xFF) != ctx->CorruptContext)
					{
						//something went wrong
						BpMe(__LINE__);
						return FALSE;
						//__fastfail(0);
					}

					//r13
					ctx->CorruptContext = *(uint64_t*)((uint64_t)stack_current - 3 * 8);
				}

				//mov [rsp+10h], rbp
				uint64_t OrigIrql = *(uint64_t*)((uint64_t)stack_current + 0x10);
				__writecr8(OrigIrql);
			}

			//r12
			ctx->CorruptR12 = *(uint64_t*)((uint64_t)stack_current - 2 * 8);
			ctx->bFoundCorruptReg = TRUE;
		}
		return FALSE;
	}

	if (!ctx->bFoundExceptionRecord)
	{
		if (*(uint64_t*)(stack_current) > KdEnterDebugger &&
			*(uint64_t*)(stack_current)-KdEnterDebugger < 0x100 &&
			*(uint8_t*)(*(uint64_t*)(stack_current)-5) == 0xE8 &&			/* Make sure it's a call */
			*(uint32_t*)(*(uint64_t*)(stack_current)) == 0x48f08a44			/* mov r14b, al;  mov xxx */
			)
		{
			//r15
			ctx->ExceptionRecord = *(uint64_t*)((uint64_t)stack_current - 3 * 8);
			if (!ctx->ExceptionRecord)
				BpMe(__LINE__);
			ctx->bFoundExceptionRecord = TRUE;

			if (!ctx->CorruptContext)
			{
				BpMe(__LINE__);

				// Context from rsi in KiDispatchException
				ctx->CorruptContext = *(uint64_t*)((uint64_t)stack_current + 3 * 8);
			}
		}
		return FALSE;
	}

	return TRUE;
}

uint64_t FindExceptionRecord()
{
	/*
	uint64_t ExceptionRecord = 0;

	uint64_t CorruptContext = 0, CorruptR12 = 0;
	//if (GetWinver() > 18363)
	//{
	CorruptContext = GetR13();
	//}

	bool bFoundExceptionRecord = false;
	bool bFoundCorruptReg = false;
	*/

	trace_FindExceptionRecord_ctx traceCtx;
	traceCtx.ExceptionRecord = 0;

	traceCtx.CorruptContext = 0;
	traceCtx.CorruptR12 = 0;
	//if (GetWinver() > 18363)
	//{
	traceCtx.CorruptContext = GetR13();
	//}

	traceCtx.bFoundExceptionRecord = FALSE;
	traceCtx.bFoundCorruptReg = FALSE;


	//Find exception record and context. 
	//Trace from bottom to top since there will be nested exception
	BOOLEAN traceResult = DoStackTrace(trace_FindExceptionRecord, &traceCtx, _AddressOfReturnAddress(), TRUE);

	if (!traceResult || !traceCtx.CorruptContext)
	{
		BpMe(__LINE__);
		KeBugCheck(0);
	}

	//if (GetWinver() > 18363)
	//{
	SetR13(traceCtx.CorruptContext);
	//}

	SetR12(traceCtx.CorruptR12);

	return traceCtx.ExceptionRecord;
}

void HookKdTrap(ExceptionCallback Handler)
{

	//KeIpiGenericCall(ipicallback, 0);

	/*
	ba e1 nt!PnpCallDriverEntry
	ba e1 nt!guard_wrap_icall_retpoline_exit
	.reload;ba e1 nt!guard_wrap_icall_retpoline_exit;g

	ba e1 nt!KeStallExecutionProcessor
	ba e1 nt!KeBugCheck2
	ba e1 nt!KdpTrap
	ba e1 KMDFDriver1!HookPosition
	ba e1 KMDFDriver1!BpMe
	ba e1 KMDFDriver1!ExceptionHandler
	ba e1 KMDFDriver1!FindExceptionRecord
	*/

	//InitMemoryManager();
	//pDriverObject->DriverUnload = DriverUnload;

	//hkCnt = 0;
	CalledHookTimes = 0;
	PVOID halDll = 0;
	PVOID nt = 0;
	getKernelModuleByName("hal.dll", &halDll, 0);
	getKernelModuleByName("ntoskrnl.exe", &nt, 0);
	GetExceptionStackOffset();
	if (GetWinver() == 18362 || GetWinver() == 18363)
	{
		if (*KdDebuggerEnabled)
			__debugbreak();
	}
	else if (GetWinver() == 19043)
	{
		//ba e1 nt!guard_wrap_icall_retpoline_exit
		uint64_t guard_wrap_icall_retpoline_exit = (uint64_t)nt + (0xfffff806579fea80 - 0xfffff80657600000);
		if (MmIsAddressValid((PVOID)guard_wrap_icall_retpoline_exit) &&
			*(uint8_t*)guard_wrap_icall_retpoline_exit == 0xC3)
			((void(*)())guard_wrap_icall_retpoline_exit)();
	}

	//KiSwapToUmsThread+3E6
	KiDispatchException = (uint64_t)FindPatternSect(nt, "PAGE", "41 B1 01 48 83 65 20 00 C7 45 28 02 00 00 00 48 89 45 30 48 89 7D 38 C7 45 10 1C 07 00 C0 C7 45 14 01 00 00 00 C6 44 24 20 00 E8");
	if (KiDispatchException)
	{
		KiDispatchException = RVA(KiDispatchException + 42, 5);
	}
	else
	{
		KiDispatchException = (uint64_t)FindPatternSect(nt, ".text", "4C 8D 45 ? 48 8B D4 48 8B C8 E8 ? ? ? ? 48 8D 8C 24");
		KiDispatchException = RVA(KiDispatchException + 10, 5);
	}


	KdTrap = (uint64_t)FindPatternSect(nt, ".text", "48 83 EC 38 ? ? ? ? ? ? ? 8A 44 24 68 88 44 24 28 8A 44 24 60 88 44 24 20");
	KdpTrap = (uint64_t)FindPatternRange((PVOID)KdTrap, 0x50, "E8 ? ? ? ? EB");
	KdpTrap = RVA(KdpTrap, 5);


	KdEnterDebugger = (uint64_t)FindPatternSect(nt, ".text", "E8 ? ? ? ? 65 48 8B 2C 25 20 00 00 00 4D 8B C5");
	if (KdEnterDebugger)
	{
		KdEnterDebugger = RVA(KdEnterDebugger, 5);
	}
	else
	{
		KdEnterDebugger = (uint64_t)FindPatternSect(nt, "PAGEKD", "33 D2 33 C9 E8 ? ? ? ? 44 8A E0 33 D2");
		KdEnterDebugger = RVA(KdEnterDebugger + 4, 5);
	}

	KdpReport = (uint64_t)FindPatternSect(nt, "PAGEKD", "8A 44 24 78 88 44 24 28 E8");
	if (KdpReport)
	{
		KdpReport = RVA(KdpReport + 8, 5);
	}
	else
	{
		KdpReport = (uint64_t)FindPatternSect(nt, "PAGEKD", "E8 ? ? ? ? 44 8A D0 48 8B 5C 24 50");
		KdpReport = RVA(KdpReport, 5);
	}

	KeFreezeExecution = (uint64_t)FindPatternSect(nt, "PAGEKD", "E8 ? ? ? ? 44 8A F0 48 8B");
	KeFreezeExecution = RVA(KeFreezeExecution, 5);

	KdReleaseDebuggerLock = (KdReleaseDebuggerLockFn)GetProcAddress(nt, "KdReleaseDebuggerLock");
	KdAcquireDebuggerLock = (KdAcquireDebuggerLockFn)GetProcAddress(nt, "KdAcquireDebuggerLock");
	uint8_t now_irql = 0;
	KdAcquireDebuggerLock(&now_irql);
	KeLowerIrql(now_irql);
	//uint64_t KdDebuggerLockRva = (uint64_t)FindPatternSect(nt, ".text", "");
	//pKdDebuggerLock = (uint64_t*)RVA(KdDebuggerLockRva, 7);
	//*pKdDebuggerLock = 1;

	//HalpHpetQueryCounter


	//HalpTimerStallCounterPowerChange
	PUCHAR rva = FindPatternSect(halDll, ".text", "48 83 25 ? ? ? ? 00 48 89 1D ? ? ? ? EB");
	if (!rva)
	{
		rva = FindPatternSect(nt, ".text", "48 83 25 ? ? ? ? 00 48 89 1D ? ? ? ? EB");
		if (!rva)
			return;
	}
	//u poi(poi(nt!HalpStallCounter) + 70)
	HalpStallCounter = *(uint64_t*)RVA(rva + 8, 7);
	OldHalQueryCounter = *(uint64_t*)(HalpStallCounter + 0x70);
	*(uint64_t*)(HalpStallCounter + 0x70) = (uint64_t)HookPosition;


	//*(uint64_t*)0xfffff8017398d280 = 1;//KdDebuggerLock
	//*(uint64_t*)0xfffff8017398d2c0 = 0;//KiFreezeExecutionLock


	//KdpDebugRoutineSelect

	uint64_t pKdpDebugRoutineSelect = RVA2(KdTrap + 4, 7, 2);
	*(uint32_t*)(pKdpDebugRoutineSelect) = 1;

	//catch first time execption
	ULONG *aa = &NtGlobalFlag;
	PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(*(PVOID*)aa);
	int one = 1;
	WritePhysicalSafe2(phys.QuadPart, &one, 4);

	g_Handler = Handler;

	//MY CODE
	//*myAddr = (uint64_t)FindPatternSect(nt, ".text", "0F 84 ? ? ? ? C1 E0 03");
	//*myAddr = RVA((*myAddr), 6);
	funAddr.NtEnumerateKey = (uint64_t)FindPatternSect(nt, "PAGE", "E8 ? ? ? ? 8B F0 3D ? ? ? ? 0F 85 ? ? ? ? 8B 55 67");
	funAddr.NtEnumerateKey = RVA((funAddr.NtEnumerateKey), 5);
	funAddr.ExpQuerySystemInformation = (uint64_t)FindPatternSect(nt, "PAGE", "E8 ? ? ? ? 48 83 C4 38 C3 CC 74 43");
	funAddr.ExpQuerySystemInformation = RVA((funAddr.ExpQuerySystemInformation), 5);

	//*(uint64_t*)0xfffff8007e450c64 = 1;

	//exceptionfun();

	//*(volatile char*)0;
	//int a = 1;
	//__debugbreak();
	//a = 1;
	//__debugbreak();
	//a = 1;
	//__debugbreak();
	//
	//DbgPrintEx(0, 0, "bpCnt %lld\n", bpCnt);
	//__debugbreak();
	//DbgPrintEx(0, 0, "bpCnt %lld\n", bpCnt);
	//
	//DbgPrintEx(0, 0, "bpCnt %lld\n", bpCnt);

	/*
		00 nt!DbgBreakPointWithStatus
		01 nt!KiBugCheckDebugBreak+0x12
		02 nt!KeBugCheck2+0x952
		03 nt!KeBugCheckEx+0x107
		04 nt!PspSystemThreadStartup$filt$0+0x44
		05 nt!_C_specific_handler+0xac
		06 nt!RtlpExecuteHandlerForException+0x12
		07 nt!RtlDispatchException+0x4a5
		08 nt!KiDispatchException+0x16e
		09 nt!KiExceptionDispatch+0x11d
		0a nt!KiPageFault+0x445
		0b KMDFDriver1!DriverEntry+0xf1 [E:\Visual_Studio_File\HelloWorld\KMDF Driver1\Drivermain.cpp @ 1288]
		0c nt!IopLoadDriver+0x4c2
		0d nt!IopLoadUnloadDriver+0x4e
		0e nt!ExpWorkerThread+0x105
		0f nt!PspSystemThreadStartup+0x55
		10 nt!KiStartSystemThread+0x2a
	*/

	//InitMemoryManager();
	//getKernelModuleByName("ntoskrnl.exe", &NtBase, 0);

	//__debugbreak(); 
	//EptBuildMtrrMap();
	//auto PhyRange = MmGetPhysicalMemoryRanges();
	//PVOID TestPage = ExAllocatePool(NonPagedPool, 0x1000);
	//memset(TestPage, 0, 0x1000);
	//ULONG64 Physical = 0;
	//ULONG64 RemoveSize = 0x1000;
	//MmRemovePhysicalMemory((PPHYSICAL_ADDRESS )&Physical, (PLARGE_INTEGER)&RemoveSize);


	//HANDLE InsertPid = 0;
	//GetProcessIdByProcessName(L"dwm.exe", &InsertPid);
	//if(!InsertPid)
	//	return STATUS_UNSUCCESSFUL;
	//
	//PEPROCESS TargetProcess;
	//if (!NT_SUCCESS(PsLookupProcessByProcessId(InsertPid, &TargetProcess)))
	//{
	//	//__debugbreak();
	//	return STATUS_UNSUCCESSFUL;
	//}
	//
	//ULONG64 pBBTBuffer = (uint64_t)FindPatternSect(NtBase, ".text", "49 83 C2 08 49 83 C6 08 48 FF C5 44 03 DF 75 ? 48");
	//DbgPrintEx(0, 0, "pBBTBuffer %llx\n", pBBTBuffer);
	//if (pBBTBuffer)
	//{
	//	pBBTBuffer += 16;
	//	pBBTBuffer = RVA2(pBBTBuffer, 8, 3);
	//	*(ULONG64*)pBBTBuffer = 1;
	//	uint64_t UserCr3 = *(uint64_t*)((uint64_t)TargetProcess + 0x388);//0x388
	//	DbgPrintEx(0, 0, "UserCr3 %llx\n", UserCr3);
	//	PVOID Allocated = AllocateProcessUserSpace(UserCr3,1,true);
	//	DbgPrintEx(0, 0, "Allocated %llx\n", Allocated);
	//}

}

void UnHookKdTrap()
{
	//indicates the things are working
	if (NtGlobalFlag == 1)
	{
		//todo halt processor

		ULONG *aa = &NtGlobalFlag;
		PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(*(PVOID*)aa);
		int zero = 0;
		WritePhysicalSafe2(phys.QuadPart, &zero, 4);

		uint64_t pKdpDebugRoutineSelect = RVA2(KdTrap + 4, 7, 2);
		*(uint32_t*)(pKdpDebugRoutineSelect) = 0;

		*(uint64_t*)(HalpStallCounter + 0x70) = OldHalQueryCounter;

		KdReleaseDebuggerLock((unsigned __int8)__readcr8());
	}

}
