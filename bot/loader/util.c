#include <Windows.h>
#include <stdint.h>

static struct {
	uint32_t x, y, z, w;
} rand_state;

void rand_init() {
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	rand_state.x = ft.dwLowDateTime;
	rand_state.y = GetProcessId(GetCurrentProcess());
	rand_state.z = GetTickCount();
	rand_state.w = rand_state.z ^ rand_state.y;
}

uint32_t rand_next() {
	uint32_t t = rand_state.x;
	t ^= t << 11;
	t ^= t >> 8;
	rand_state.x = rand_state.y; rand_state.y = rand_state.z; rand_state.z = rand_state.w;
	rand_state.w ^= rand_state.w >> 19;
	rand_state.w ^= t;
	return rand_state.w;
}

uint32_t rand_range(uint32_t min, uint32_t max) {
	return (rand_next() % (max - min + 1)) + min;
}

/*
size_t wstrlen(const wchar_t *str) {
	const wchar_t *s;
	for (s = str; *s; ++s)
		;
	return s - str;
}

wchar_t* wstrcat(wchar_t *dest, const wchar_t *src, int destSize) {
	wchar_t *ptr;
	int n = wstrlen(dest);

	ptr = dest + n;
	n = destSize - n;

	while (*src && (n-- > 0)) {
		*ptr++ = *src++;
	}

	*ptr = 0;

	return dest;
}
*/
