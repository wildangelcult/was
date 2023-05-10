#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] ^= 53;
		buf[i] ^= 164;
		buf[i] = -buf[i];
		buf[i] = -buf[i];
		buf[i] = ~buf[i];
		buf[i] += 162;
		buf[i] = ~buf[i];
	}
}
