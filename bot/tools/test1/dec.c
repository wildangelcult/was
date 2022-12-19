#include <stdint.h>
void decrypt(uint8_t *buf, size_t bufSize) {
	size_t i;
	for (i = 0; i < bufSize; ++i) {
		buf[i] -= 105;
		buf[i] -= 218;
		buf[i] = ~buf[i];
		buf[i] = -buf[i];
		buf[i] ^= 173;
		buf[i] -= 82;
		buf[i] -= 201;
		buf[i] -= 71;
	}
}
