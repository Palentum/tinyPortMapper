/* 测“唤醒另一 CPU 上阻塞的接收者”对发送方 send() 的额外耗时：
 * 发送方 CPU0，接收方 CPU4；mode=block 接收方阻塞 recv（需要唤醒），mode=spin 接收方 MSG_DONTWAIT 忙轮询（无等待者）。
 * 每次 send 后发送方忙等 gap_us，让阻塞接收者重新入睡、其 CPU 进入 idle。 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec * 1e-3; }
static void pin(int c) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(c, &s); sched_setaffinity(0, sizeof s, &s); }
int main(int argc, char **argv) {
	int spin = argc > 1 && !strcmp(argv[1], "spin");
	double gap = argc > 2 ? atof(argv[2]) : 100;
	int n = 50000;
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(23456)};
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int r = socket(AF_INET, SOCK_DGRAM, 0);
	bind(r, (void *)&a, sizeof a);
	pid_t p = fork();
	if (p == 0) {
		pin(4);
		char b[128];
		for (;;) recv(r, b, sizeof b, spin ? MSG_DONTWAIT : 0);
	}
	pin(0);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	connect(s, (void *)&a, sizeof a);
	char buf[64] = {0};
	usleep(200000);
	double tot = 0;
	for (int i = 0; i < n; i++) {
		double t0 = now();
		send(s, buf, sizeof buf, 0);
		double t1 = now();
		tot += t1 - t0;
		while (now() - t1 < gap) {}
	}
	printf("mode=%s gap=%.0fus send() avg %.2f us\n", spin ? "spin(no waiter)" : "block(wakeup)", gap, tot / n);
	kill(p, SIGKILL);
	return 0;
}
