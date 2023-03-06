#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] += 142;
		buf[i] = -buf[i];
		buf[i] += 128;
		buf[i] ^= 197;
		buf[i] ^= 35;
		buf[i] = -buf[i];
	}
}
