.PHONY: all clean

OBJS := main.o

all:
	clang -c main.c
	clang -shared -Wl,--subsystem,native -Wl,--image-base,0x10000 -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat -nostartfiles -nostdlib $(OBJS) -o bot.sys -lntoskrnl

clean:
	rm -f *.exe *.o *.sys
