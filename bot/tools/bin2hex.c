#include <stdio.h>

int main(int argc, char *argv[]) {
	FILE *fw, *fr;
	long int i, size;
	unsigned char byte;

	if (argc < 3) {
		fprintf(stderr, "Usage:\n\t%s [input] [output]\n", argv[0]);
		return 1;
	}

	if ((fr = fopen(argv[1], "rb")) == NULL) {
		fprintf(stderr, "[-] Cannot open file: %s\n", argv[1]);
		return 1;
	}

	if ((fw = fopen(argv[2], "w")) == NULL) {
		fprintf(stderr, "[-] Cannot open file: %s\n", argv[2]);
		return 1;
	}


	fseek(fr, 0, SEEK_END);
	size = ftell(fr);
	fseek(fr, 0, SEEK_SET);

	putc('{', fw);
	for (i = 0; i < size; ++i) {
		fread(&byte, 1, 1, fr);
		fprintf(fw, "0x%02hhx, ", byte);
	}
	putc('}', fw);

	fclose(fw);
	fclose(fr);
	return 0;
}
