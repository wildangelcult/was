#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define MIN_OPS 5
#define MAX_OPS 8

typedef enum op_e {
	OP_ADD = 0,
	OP_SUB,
	OP_NEG,
	OP_NOT,
	OP_XOR,
	OP_MAX
} op_t;


op_t invops[OP_MAX] = {
	OP_SUB,
	OP_ADD,
	OP_NEG,
	OP_NOT,
	OP_XOR
};

typedef enum argv_e {
	ARGV_FILENAME 		= 0,
	ARGV_MODE		= 1,
	ARGV_IN_BIN		= 2,
	ARGV_OUT_PAYLOAD	= 3,
	ARGV_OUT_DEC		= 4,
	ARGV_IN_CODE		= 4,
	ARGV_OUT_ENC,
	ARGV_OUT_CODE,
} argv_t;


uint32_t x, y, z, w;

void rand_init() {
	x = time(NULL);
	y = GetProcessId(GetCurrentProcess());
	z = clock();
	w = z ^ y;
}

uint32_t rand_next() {
	uint32_t t = x;
	t ^= t << 11;
	t ^= t >> 8;
	x = y; y = z; z = w;
	w ^= w >> 19;
	w ^= t;
	return w;
}
//check PE, no need coz this crypter is used only inside this project
//i just kept it here if i ever need it
#if 0 
	if (fileSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))) {
		fprintf(stderr, "[-] File is too small to be a PE file\n");
		return 1;
	}

	if (((PIMAGE_DOS_HEADER)readBuf)->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "[-] Wtf man it's not even a dos executable\n");
		return 1;
	}

	ntHeaders = (PIMAGE_NT_HEADERS64)(readBuf + ((PIMAGE_DOS_HEADER)readBuf)->e_lfanew);

	//check if PE
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "[-] Not a PE file\n");
		return 1;
	}

	//check machine
	if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		fprintf(stderr, "[-] Only supporting 64 bit files, who uses 32 bit anyway\n");
		return 1;
	}

	//checks for size of .reloc section
	if (!(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)) {
		fprintf(stderr, "[-] No .reloc section\n");
		return 1;
	}

#endif

int main(int argc, char *argv[]) {
	FILE *fp;
	long int inBinSize, j;
	uint8_t *inBin, ops[MAX_OPS], vals[MAX_OPS], nOps, i;
	PIMAGE_NT_HEADERS64 ntHeaders;

	rand_init();

	if (argc < 2) {
		fprintf(stderr, "Usage:\n\t%s [mode] [opts]\n\nMODE: simple\n\t%s simple [input binary] [output payload] [output dec func] [output enc func] [output code func]\n\nMODE: encrypt\n\t%s encrypt [input binary] [output payload] [input code func] ", argv[ARGV_FILENAME], argv[ARGV_FILENAME], argv[ARGV_FILENAME]);
		return 1;
	}

	if (argv[ARGV_MODE][0] == 's' && argc < 7) {
		return 1;
	}

	if (argv[ARGV_MODE][0] != 's' && argc < 5) {
		return 1;
	}

	if ((fp = fopen(argv[ARGV_IN_BIN], "rb")) == NULL) {
		fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_IN_BIN]);
		return 1;
	}


	fseek(fp, 0, SEEK_END);
	inBinSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	inBin = malloc(inBinSize);
	fread(inBin, 1, inBinSize, fp);
	fclose(fp);

	if (argv[ARGV_MODE][0] == 's') {

		nOps = (uint8_t)((rand_next() % (MAX_OPS + 1 - MIN_OPS)) + MIN_OPS);
		
		for (i = 0; i < nOps; ++i) {
			ops[i] = (uint8_t)(rand_next() % OP_MAX);
			vals[i] = (uint8_t)(rand_next() & 0xFF);
		}

		for (j = 0; j < inBinSize; ++j) {
			for (i = 0; i < nOps; ++i) {
				switch (ops[i]) {
					case OP_ADD:
						inBin[j] += vals[i];
						break;
					case OP_SUB:
						inBin[j] -= vals[i];
						break;
					case OP_NEG:
						inBin[j] = -inBin[j];
						break;
					case OP_NOT:
						inBin[j] = ~inBin[j];
						break;
					case OP_XOR:
						inBin[j] ^= vals[i];
						break;
					default:
						fprintf(stderr, "[-] Unsupported operation\n");
						return 1;
				}
			}
		}

		if ((fp = fopen(argv[ARGV_OUT_PAYLOAD], "w")) == NULL) {
			fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_OUT_PAYLOAD]);;
			return 1;
		}

		putc('{', fp);
		for (j = 0; j < inBinSize; ++j) {
			fprintf(fp, "0x%02hhx, ", inBin[j]);
		}
		putc('}', fp);

		fclose(fp);


		if ((fp = fopen(argv[ARGV_OUT_DEC], "w")) == NULL) {
			fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_OUT_DEC]);;
			return 1;
		}
		fprintf(fp,
			"#include <stdint.h>\n"
			"void decrypt(uint8_t *buf, size_t bufSize) {\n"
			"\tsize_t i;\n"
			"\tfor (i = 0; i < bufSize; ++i) {\n"
		);

		for (i = nOps - 1; i != (uint8_t)-1; --i) {
			switch (invops[ops[i]]) {
				case OP_ADD:
					fprintf(fp, "\t\tbuf[i] += %hhu;\n", vals[i]);
					break;
				case OP_SUB:
					fprintf(fp, "\t\tbuf[i] -= %hhu;\n", vals[i]);
					break;
				case OP_NEG:
					fprintf(fp, "\t\tbuf[i] = -buf[i];\n");
					break;
				case OP_NOT:
					fprintf(fp, "\t\tbuf[i] = ~buf[i];\n");
					break;
				case OP_XOR:
					fprintf(fp, "\t\tbuf[i] ^= %hhu;\n", vals[i]);
					break;
				default:
					fprintf(stderr, "[-] Unsupported operation\n");
					return 1;
			}
		}

		fprintf(fp, "\t}\n}\n");

		fclose(fp);

		if (argv[ARGV_OUT_ENC][0] != '-') {
			if ((fp = fopen(argv[ARGV_OUT_ENC], "w")) == NULL) {
				fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_OUT_ENC]);;
				return 1;
			}
			fprintf(fp,
				"#include <stdint.h>\n"
				"void encrypt(uint8_t *buf, size_t bufSize) {\n"
				"\tsize_t i;\n"
				"\tfor (i = 0; i < bufSize; ++i) {\n"
			);

			for (i = 0; i < nOps; ++i) {
				switch (ops[i]) {
					case OP_ADD:
						fprintf(fp, "\t\tbuf[i] += %hhu;\n", vals[i]);
						break;
					case OP_SUB:
						fprintf(fp, "\t\tbuf[i] -= %hhu;\n", vals[i]);
						break;
					case OP_NEG:
						fprintf(fp, "\t\tbuf[i] = -buf[i];\n");
						break;
					case OP_NOT:
						fprintf(fp, "\t\tbuf[i] = ~buf[i];\n");
						break;
					case OP_XOR:
						fprintf(fp, "\t\tbuf[i] ^= %hhu;\n", vals[i]);
						break;
					default:
						fprintf(stderr, "[-] Unsupported operation\n");
						return 1;
				}
			}
			fprintf(fp, "\t}\n}\n");
			fclose(fp);
		}

		if (argv[ARGV_OUT_CODE][0] != '-') {
			if ((fp = fopen(argv[ARGV_OUT_CODE], "w")) == NULL) {
				fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_OUT_CODE]);;
				return 1;
			}

			
			fprintf(fp, "%hhu\n", nOps);
			for (i = 0; i < nOps; ++i) {
				fprintf(fp, "%hhu,", ops[i]);
				fprintf(fp, "%hhu,", vals[i]);
			}

			fclose(fp);
		}
	} else { //mode encrypt
		if ((fp = fopen(argv[ARGV_IN_CODE], "r")) == NULL) {
			fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_IN_CODE]);;
			return 1;
		}
		fscanf(fp, "%hhu\n", &nOps);
		for (i = 0; i < nOps; ++i) {
			fscanf(fp, "%hhu,", ops + i);
			fscanf(fp, "%hhu,", vals + i);
		}
		fclose(fp);

		//i could use a function instead of copying code, but suck my d
		for (j = 0; j < inBinSize; ++j) {
			for (i = 0; i < nOps; ++i) {
				switch (ops[i]) {
					case OP_ADD:
						inBin[j] += vals[i];
						break;
					case OP_SUB:
						inBin[j] -= vals[i];
						break;
					case OP_NEG:
						inBin[j] = -inBin[j];
						break;
					case OP_NOT:
						inBin[j] = ~inBin[j];
						break;
					case OP_XOR:
						inBin[j] ^= vals[i];
						break;
					default:
						fprintf(stderr, "[-] Unsupported operation\n");
						return 1;
				}
			}
		}

		if ((fp = fopen(argv[ARGV_OUT_PAYLOAD], "w")) == NULL) {
			fprintf(stderr, "[-] Cannot open file: %s\n", argv[ARGV_OUT_PAYLOAD]);;
			return 1;
		}

		putc('{', fp);
		for (j = 0; j < inBinSize; ++j) {
			fprintf(fp, "0x%02hhx, ", inBin[j]);
		}
		putc('}', fp);

		fclose(fp);
	}

	free(inBin);

	return 0;
}
