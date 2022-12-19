#include <Windows.h>

int main() {
	LoadLibrary("dll.dll");
	while(1) {}
	return 0;
}
