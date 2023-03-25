#ifndef __UTIL_H
#define __UTIL_H

#include <stdint.h>
void rand_init();
uint32_t rand_next();
uint32_t rand_range(uint32_t min, uint32_t max);
/*
size_t wstrlen(const wchar_t *str);
wchar_t* wstrcat(wchar_t *dest, const wchar_t *src, int destSize);
*/

#endif //__UTIL_H
