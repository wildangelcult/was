#DEBUG := -g -ggdb

.PHONY: all clean testdll
all:
	make -C encfun
	nasm -fwin64 sys_protect.asm -o sys_protect.o
	../tools/genfun.exe e testdll.dll loader.h encfun/encrypt.code
	gcc loaderloader.c encfun/decrypt.c sys_protect.o -o loaderloader -lkernel32 -lntdll $(DEBUG)

testdll:
	gcc testdll.c -nostdlib -nostartfiles -e DllMain -shared -lkernel32 -ladvapi32 -s -o testdll.dll

clean:
	rm -f *.o *.exe *.bin
