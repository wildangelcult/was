#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] = ~buf[i];
		buf[i] += 103;
		buf[i] -= 214;
		buf[i] = ~buf[i];
		buf[i] ^= 140;
		buf[i] = -buf[i];
	}
}
