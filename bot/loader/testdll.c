#include <Windows.h>

#define BUF_SIZE 512

void DllMain() {
	BYTE buf[BUF_SIZE];
	DWORD len = BUF_SIZE;
	FreeConsole();
	GetUserName(buf, &len);
	HANDLE hFile = CreateFile("user.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, buf, len, NULL, NULL);
	CloseHandle(hFile);
	ExitProcess(0);
}
