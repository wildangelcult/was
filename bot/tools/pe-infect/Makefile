.PHONY: all sc winlogon
all: sc

sc:
	nasm -f bin shellcode.asm -o shellcode.o
	../bin2hex.exe shellcode.o shellcode.h
	gcc peinfect.c -o peinfect

winlogon:
	gcc -nostdlib -ffreestanding -mconsole -nostartfiles -Llib -lapi-ms-win-core-libraryloader-l1-2-0 winlogon-test.c -o winlogon
