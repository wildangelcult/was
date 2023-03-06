.PHONY: all clean

DEBUG ?= 1

CFLAGS := -DDEBUG
ifndef DEBUG
CFLAGS := -s
endif

all:
	#gcc loader.c -nostdlib -nostartfiles -e DllMain -shared -lkernel32 -o loader.dll $(CFLAGS)
	gcc loader.c ../loaderloader/sys_protect.o -lntdll -lkernel32 -o loader.exe $(CFLAGS)

clean:
	rm -f *.o *.exe
