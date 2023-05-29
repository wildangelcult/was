#include <stdint.h>
#include <intrin.h>

#define BpMe

uint64_t fun(int n) {
	*(volatile uint8_t*)0;
	*(volatile uint8_t*)0;
	return 0;
}
