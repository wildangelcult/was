#include <stdio.h>
#include <stdint.h>

void decrypt(uint8_t *buf, size_t bufSize);

int main() {
	char payload[] = 
#include "payload.h"
	;
	FILE *fw;

	decrypt(payload, sizeof(payload));
	fw = fopen("payload.exe", "wb");
	fwrite(payload, 1, sizeof(payload), fw);
	fclose(fw);
}
