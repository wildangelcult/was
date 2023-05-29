#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] = -buf[i];
		buf[i] += 199;
		buf[i] = -buf[i];
		buf[i] = -buf[i];
		buf[i] += 194;
		buf[i] ^= 9;
		buf[i] = ~buf[i];
	}
}
