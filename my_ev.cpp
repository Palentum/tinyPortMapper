#pragma GCC diagnostic push

#pragma GCC diagnostic ignored "-Wextra"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wcomment"
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#pragma GCC diagnostic ignored "-Wunused-value"

#pragma GCC diagnostic ignored "-Wall"
#pragma GCC diagnostic ignored "-W"

#include "my_ev_common.h"
#include "ev.c"

#pragma GCC diagnostic pop

//libev 每轮循环在 epoll 返回后把 CLOCK_MONOTONIC 读进 mn_now（ev_timer 也按它计时），4.24 没有公开的读取接口；ev_now() 是按它插值、每 0.5 s 与墙钟对齐一次的 ev_rt_now
ev_tstamp my_ev_mono_now(struct ev_loop *loop)
{
	return loop->mn_now;
}
