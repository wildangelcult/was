#include <stdio.h>
#include "../hde/hde64.h"

uint8_t code[] = 
#include "test.hex"
;
hde64s hs;

void printReg() {
	if (!hs.rex_b) {
		switch (hs.modrm_rm) {
			case 0:
				printf("rax");
				break;
			case 1:
				printf("rcx");
				break;
			case 2:
				printf("rdx");
				break;
			case 3:
				printf("rbx");
				break;
			case 4:
				printf("rsp");
				break;
			case 5:
				printf("rbp");
				break;
			case 6:
				printf("rsi");
				break;
			case 7:
				printf("rdi");
				break;
			default:
				printf("err");
				break;
		}
	} else {
		switch (hs.modrm_rm) {
			case 0:
				printf("r8 ");
				break;
			case 1:
				printf("r9 ");
				break;
			case 2:
				printf("r10");
				break;
			case 3:
				printf("r11");
				break;
			case 4:
				printf("r12");
				break;
			case 5:
				printf("r13");
				break;
			case 6:
				printf("r14");
				break;
			case 7:
				printf("r15");
				break;
			default:
				printf("err");
				break;
		}
	}
}

void printDr() {
	switch (hs.modrm_reg) {
		case 0:
			printf("dr0");
			break;
		case 1:
			printf("dr1");
			break;
		case 2:
			printf("dr2");
			break;
		case 3:
			printf("dr3");
			break;
		case 4:
			printf("dr4");
			break;
		case 5:
			printf("dr5");
			break;
		case 6:
			printf("dr6");
			break;
		case 7:
			printf("dr7");
			break;
		default:
			printf("err");
			break;
	}
}

int main() {
	uint32_t i;
	uint8_t *p;
	p = code;

	for (i = 0; i < 128; ++i) {
		p += hde64_disasm(p, &hs);
		printf("mov ");
		printReg();
		putchar(' ');
		printDr();
		putchar('\n');
		if ((i+1) % 16 == 0) {
			putchar('\n');
		}
	}

	return 0;
}
