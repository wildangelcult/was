#include "util.h"
#include <ntddk.h>

void rand_init(rand_state_t* s) {
	LARGE_INTEGER i;

	KeQuerySystemTime(&i);
	s->x = i.LowPart;
	s->y = PsGetCurrentProcessId();
	KeQueryTickCount(&i);
	s->z = i.LowPart;
	s->w = s->z ^ s->y;
}
uint32_t rand_next(rand_state_t *s) {
	uint32_t t = s->x;
	t ^= t << 11;
	t ^= t >> 8;
	s->x = s->y; s->y = s->z; s->z = s->w;
	s->w ^= s->w >> 19;
	s->w ^= t;
	return s->w;
}

uint32_t rand_range(rand_state_t *s, uint32_t min, uint32_t max) {
	return (rand_next(s) % (max - min + 1)) + min;
}

uint32_t rand_tag(rand_state_t* s) {
	uint32_t tag = 0, i;

	for (i = 0; i < 4; ++i) {
		tag = (tag << 8) + rand_range(s, 0x20, 0x7e);
	}

	return tag;
}
