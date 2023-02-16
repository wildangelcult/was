#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
	FILE *fp;
	long int fileSize;
	uint8_t *readBuf;
	PIMAGE_NT_HEADERS64 ntHeaders;

	if (argc < 2) {
		fprintf(stderr, "Usage:\n\t%s [file to check]\n", argv[0]);
		return 1;
	}

	if ((fp = fopen(argv[1], "rb")) == NULL) {
		fprintf(stderr, "[-] Cannot open file: %s\n", argv[1]);
		return 1;
	}


	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	readBuf = malloc(fileSize);
	fread(readBuf, 1, fileSize, fp);
	fclose(fp);

	if (fileSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))) {
		fprintf(stderr, "[-] File is too small to be a PE file\n");
		return 1;
	}

	if (((PIMAGE_DOS_HEADER)readBuf)->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "[-] Wtf man it's not even a dos executable\n");
		return 1;
	}

	ntHeaders = (PIMAGE_NT_HEADERS64)(readBuf + ((PIMAGE_DOS_HEADER)readBuf)->e_lfanew);

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

	//checks for size of .reloc section
	if (!(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)) {
		fprintf(stderr, "[-] No .reloc section\n");
		return 1;
	}

	printf("[*] Base: %x\n", ntHeaders->OptionalHeader.ImageBase);
	PIMAGE_EXPORT_DIRECTORY export = (PIMAGE_EXPORT_DIRECTORY)(readBuf + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	uint32_t *names = (uint32_t*)(readBuf + export->AddressOfNames);
	printf("[*] RVA: %x\n", export->AddressOfNames);
	printf("[*] Names: %s\n", names);

//	printf("[*] First export %s\n", (char*)(readBuf + ((uint32_t*)(readBuf + ((PIMAGE_EXPORT_DIRECTORY)(readBuf + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))->AddressOfNames))[0]));

	printf("[+] Done\n");

	free(readBuf);

	return 0;
}
