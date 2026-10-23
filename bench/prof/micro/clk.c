/* 测 vDSO clock_gettime 与 ev_time 等价调用（CLOCK_REALTIME）的单次耗时 */
#include <stdio.h>
#include <time.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
int main(void) {
	const int n = 5000000; struct timespec t; volatile long s = 0;
	clockid_t ids[2] = {CLOCK_MONOTONIC, CLOCK_REALTIME};
	for (int k = 0; k < 2; k++) {
		double a = now();
		for (int i = 0; i < n; i++) { clock_gettime(ids[k], &t); s += t.tv_nsec; }
		double b = now();
		printf("%s: %.1f ns/call\n", k ? "CLOCK_REALTIME" : "CLOCK_MONOTONIC", (b - a) / n * 1e9);
	}
	return 0;
}
