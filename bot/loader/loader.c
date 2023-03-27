#include <Windows.h>
#include <winternl.h>
#include <stdint.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#include "driver.h"
#include "util.h"

uint8_t bot[] = 
#include "bot.h"
;

int main(int argc, char *argv[]) {
	rand_init();
	driver_open();
	driver_init();


	system("pause");
	driver_close();
	return 0;
}
