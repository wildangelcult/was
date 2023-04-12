#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] += 212;
		buf[i] += 207;
		buf[i] += 180;
		buf[i] ^= 117;
		buf[i] ^= 68;
	}
}
