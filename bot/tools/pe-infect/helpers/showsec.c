#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	FILE *fp;
	long int fileSize;
	uint8_t *buf;
	PIMAGE_NT_HEADERS64 ntHeaders;
	PIMAGE_SECTION_HEADER sec;
	WORD i;
	if (argc < 2) {
		printf("Usage:\n\t%s [input pe]\n", argv[0]);
		return 1;
	}

	if ((fp = fopen(argv[1], "rb")) == NULL) {
		printf("[-] Cannot open file %s\n", argv[1]);
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = malloc(fileSize);
	fread(buf, 1, fileSize, fp);
	fclose(fp);

	ntHeaders = (PIMAGE_NT_HEADERS64)(buf + ((PIMAGE_DOS_HEADER)buf)->e_lfanew);

	for (i = 0, sec = IMAGE_FIRST_SECTION(ntHeaders); i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		printf("%s\n", sec[i].Name);
	}

	free(buf);

	return 0;
}
