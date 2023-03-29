#ifndef __DRIVER_H
#define __DRIVER_H

void driver_open();
void driver_close();
void driver_init();

uint32_t driver_read32(PBYTE addr);
void driver_write32(PBYTE addr, uint32_t val);;

uint64_t driver_getKernelModule(char *module, PULONG imageSize);

#endif //__DRIVER_H
