#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] = -buf[i];
		buf[i] += 173;
		buf[i] -= 151;
		buf[i] = ~buf[i];
		buf[i] -= 8;
	}
}
