#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] += 99;
		buf[i] ^= 185;
		buf[i] = ~buf[i];
		buf[i] = ~buf[i];
		buf[i] = -buf[i];
		buf[i] = -buf[i];
		buf[i] -= 18;
		buf[i] += 149;
	}
}
