#include <stdio.h>
#include <stdint.h>

uint16_t checksum(uint16_t n, uint16_t m) {
	uint32_t r;
	r = n + m;
	r += (r & 0x10) >> 4;
	r &= ~0x10;
	return r;
}

int main() {
	uint16_t n = 0xb, m = 0x6;
	printf("%x + %x = %x\n", n, m, checksum(n, m));
	return 0;
}
