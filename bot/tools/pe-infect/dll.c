#include <Windows.h>
#define BUF_SIZE 512

void thread(HANDLE dllHandle) {
	BYTE buf[BUF_SIZE];
	DWORD len = BUF_SIZE;
	GetUserName(buf, &len);
	HANDLE hFile = CreateFile("C:\\user.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, buf, len, NULL, NULL);
	CloseHandle(hFile);
	FreeLibraryAndExitThread(dllHandle, 0);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH)
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread, NULL, 0, NULL);
	return TRUE;
}
