#include <Windows.h>
#include <stdio.h>

char buf[] = "\x90\x90\x90\x90\x90\x90\x90\x90\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC";

int main(int argc, char *argv[]) {
	void *bufAddr = &buf;
	ULONG nBytes = 16;
	ULONG oldProt = 0;


	printf("BaseAddress - %p\nNumberOfBytes - %u\nOldProt - %x\n------------------\n", bufAddr, nBytes, oldProt);
	VirtualProtect(bufAddr, nBytes, PAGE_EXECUTE_READ, &oldProt);
	printf("BaseAddress - %p\nNumberOfBytes - %u\nOldProt - %x\n", bufAddr, nBytes, oldProt);

	(*(void(*)())buf)();
	return 0;
}
