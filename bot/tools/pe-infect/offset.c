#include <Windows.h>
#include <stdio.h>

int main() {
	BYTE* p = NULL;

	printf("%p\n", &((PIMAGE_NT_HEADERS64)p)->OptionalHeader.DataDirectory);
	
	return 0;
}
