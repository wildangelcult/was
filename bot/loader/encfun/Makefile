.PHONY: all
all:
	gcc -c main.c
	objcopy -O binary -j .text main.o main.bin
	../../tools/bin2hex.exe main.bin main.h
