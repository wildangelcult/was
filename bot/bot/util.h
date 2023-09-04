#ifndef __UTIL_H
#define __UTIL_H

#include "stdint.h"

typedef struct rand_state_s {
	uint32_t x, y, z, w;
} rand_state_t;

void rand_init(rand_state_t *s);
uint32_t rand_next(rand_state_t *s);
uint32_t rand_range(rand_state_t* s, uint32_t min, uint32_t max);
uint32_t rand_tag(rand_state_t *s);

#endif //__UTIL_H