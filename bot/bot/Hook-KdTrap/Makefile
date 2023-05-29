.PHONY: all clean

OBJS := DriverEntry.o HookKdTrap.o

all:
	clang -fms-extensions -fexceptions -O1 -c DriverEntry.c
	clang -fms-extensions -fexceptions -c HookKdTrap.c
	clang -shared -Wl,--subsystem,native -Wl,--image-base,0x10000 -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat -nostartfiles -nostdlib $(OBJS) -o hook-kdtrap.sys -lntoskrnl

%.o: %.c
	clang -fms-extensions -fexceptions -c $<

clean:
	rm -f *.exe *.o *.sys
