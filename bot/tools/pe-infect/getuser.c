#include <windows.h>
#define BUF_SIZE 512

int _main() {
	BYTE buf[BUF_SIZE];
	size_t len = BUF_SIZE;
	GetUserName(buf, &len);
	HANDLE hFile = CreateFile("user.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, buf, len, NULL, NULL);
	CloseHandle(hFile);
	return 0;
}
