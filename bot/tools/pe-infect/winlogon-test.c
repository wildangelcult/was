#include <Windows.h>

int WINAPI _main() {
	LoadLibraryExW(NULL, NULL, 0);
	for (;;) {}
	return 0;
}
