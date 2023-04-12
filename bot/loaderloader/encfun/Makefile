.PHONY: all compile fud clean
all: compile fud

compile:
	gcc -c main.c
	objcopy -O binary -j .text main.o main.bin
	nasm -f bin sys_protect.asm -o sys_protect.bin
	nasm -f bin sys_create.asm -o sys_create.bin
	nasm -f bin sys_read.asm -o sys_read.bin
	nasm -f bin sys_uni.asm -o sys_uni.bin

fud:
	../../tools/genfun.exe s main.bin main.h decrypt.c - encrypt.code
	../../tools/genfun.exe e sys_protect.bin sys_protect.h encrypt.code
	../../tools/genfun.exe e sys_create.bin sys_create.h encrypt.code
	../../tools/genfun.exe e sys_read.bin sys_read.h encrypt.code
	../../tools/genfun.exe e sys_uni.bin sys_uni.h encrypt.code

clean:
	rm -f *.o *.exe *.bin
