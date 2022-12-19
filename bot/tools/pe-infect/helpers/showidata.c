#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;

    for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        // Is the RVA within this section?
        if ( (rva >= section->VirtualAddress) &&
             (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }

    return 0;
}

LPVOID GetPtrFromRVA( DWORD rva, PIMAGE_NT_HEADERS pNTHeader, BYTE* imageBase )
{
	PIMAGE_SECTION_HEADER pSectionHdr;
	INT delta;

	pSectionHdr = GetEnclosingSectionHeader( rva, pNTHeader );
	if ( !pSectionHdr )
		return 0;

	delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
	return (PVOID) ( imageBase + rva - delta );
}

int main(int argc, char *argv[]) {
	FILE *fp;
	long int fileSize;
	uint8_t *buf;
	PIMAGE_NT_HEADERS64 ntHeaders;
	PIMAGE_IMPORT_DESCRIPTOR desc;

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

	desc = GetPtrFromRVA(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ntHeaders, buf);

	for (;; ++desc) {
		if (!desc->TimeDateStamp && !desc->Name) {
			break;
		}

		printf("%s\n", GetPtrFromRVA(desc->Name, ntHeaders, buf));
	}

	free(buf);

	return 0;
}
