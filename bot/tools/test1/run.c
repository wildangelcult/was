#include <stdio.h>
#include <stdint.h>
#define sizeof(x) (sizeof(x) - 1)

void decrypt(uint8_t *buf, size_t bufSize);

int main() {
	char payload[] = 
#include "payload.h"
	;
	char payload2[] = 
#include "payload2.h"
	;

	FILE *fw;

	printf("%u\n", sizeof(payload));

	decrypt(payload, sizeof(payload));
	decrypt(payload2, sizeof(payload2));

	fw = fopen("decrypted.bin", "wb");
	fwrite(payload, 1, sizeof(payload), fw);
	fclose(fw);

	fw = fopen("decrypted2.bin", "wb");
	fwrite(payload2, 1, sizeof(payload2), fw);
	fclose(fw);
}
