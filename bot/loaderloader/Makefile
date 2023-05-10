.PHONY: all compile fud fud1 final clean testdll loader

CFLAGS := -DDEBUG
ifndef DEBUG
CFLAGS := -s
endif

all: compile loader final

compile:
	make -C encfun
	nasm -fwin64 sys_protect.asm -o sys_protect.o

loader:
	make -C ../loader

fud1:
	make -C encfun fud

final:
	#../tools/genfun.exe e testdll.dll loader.hex encfun/encrypt.code
	../tools/genfun.exe e ../loader/loader.dll loader.hex encfun/encrypt.code
	#gcc loaderloader.c encfun/decrypt.c sys_protect.o -o loaderloader -lkernel32 -lntdll $(CFLAGS)
	gcc loaderloader.c encfun/decrypt.c sys_protect.o -nostdlib -nostartfiles -e entry -o loaderloader -lkernel32 -lntdll $(CFLAGS)

fud: fud1 final

testdll:
	gcc testdll.c -nostdlib -nostartfiles -e DllMain -shared -lkernel32 -ladvapi32 -s -o testdll.dll

clean:
	make -C encfun clean
	rm -f *.o *.exe *.bin
