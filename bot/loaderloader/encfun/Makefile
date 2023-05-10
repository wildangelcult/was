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
	../../tools/genfun.exe s main.bin main.hex decrypt.c - encrypt.code
	../../tools/genfun.exe e sys_protect.bin sys_protect.hex encrypt.code
	../../tools/genfun.exe e sys_create.bin sys_create.hex encrypt.code
	../../tools/genfun.exe e sys_read.bin sys_read.hex encrypt.code
	../../tools/genfun.exe e sys_uni.bin sys_uni.hex encrypt.code
	#other
	../../tools/genfun.exe e jmp_inst.byte jmp_inst.hex encrypt.code
	../../tools/genfun.exe e str_kernel.str str_kernel.hex encrypt.code
	../../tools/genfun.exe e str_ntdll.str str_ntdll.hex encrypt.code
	../../tools/genfun.exe e str_getHeap.str str_getHeap.hex encrypt.code
	../../tools/genfun.exe e str_allocHeap.str str_allocHeap.hex encrypt.code
	../../tools/genfun.exe e str_uni.str str_uni.hex encrypt.code
	../../tools/genfun.exe e str_params.str str_params.hex encrypt.code

clean:
	rm -f *.o *.exe *.bin *.hex
