#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define NTDLL_SIZE 3000000

int main(int argc, char *argv[]) {
	FILE *fp = fopen("C:\\Windows\\System32\\ntdll.dll", "rb");
	uint8_t *buf = (uint8_t*)malloc(NTDLL_SIZE);
	fread(buf, 1, NTDLL_SIZE, fp);
	//printf("%u\n", fread(buf, 1, NTDLL_SIZE, fp));
	PIMAGE_DOS_HEADER dos = buf;
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buf + dos->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

	printf("%x\n", dos->e_magic);
	printf("%x\n", nt->Signature);
	printf("%x - %x = %d\n", section->VirtualAddress, section->PointerToRawData, - section->VirtualAddress + section->PointerToRawData);

	free(buf);
	return 0;
}
