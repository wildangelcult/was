#DEBUG := -g -ggdb

.PHONY: all clean testdll
all:
	make -C encfun
	nasm -fwin64 syscalls.asm -o syscalls.o
	gcc -c loaderloader.c $(DEBUG)
	gcc loaderloader.o syscalls.o -o loaderloader -lkernel32 -lntdll $(DEBUG)

testdll:
	gcc testdll.c -nostdlib -nostartfiles -e DllMain -shared -lkernel32 -ladvapi32 -s -o testdll.dll

clean:
	rm -f *.o *.exe *.bin
