#include <Windows.h>
#include <stdio.h>

int main() {
	wchar_t path[MAX_PATH] = L"\\??\\";
	//wcscat(path, L"dgiuarohwoiahowhfoiah");
	printf("%ls", path);
}
