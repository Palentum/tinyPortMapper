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

//libev/ev.c 的 fd_reify 有本地补丁（T13）：本轮经 ev_io_set 登记的 fd 按新 fd 处理，传给 backend 的旧掩码为 0。它只对 epoll 正确，
//换 libev 或编入别的后端时在这里编译失败，处理办法见 AGENTS.md
#ifndef TPM_LIBEV_FD_REIFY_PATCH
#error "libev/ev.c 缺少 T13 的 fd_reify 本地补丁：重新打上（只对 epoll 正确），或决定不再保留时连同本检查一起删除"
#endif
#if EV_USE_POLL || EV_USE_SELECT || EV_USE_KQUEUE || EV_USE_PORT || EV_USE_LINUXAIO || EV_USE_IOURING
#error "libev/ev.c 中 T13 的 fd_reify 补丁只对 epoll 后端正确：编入其他后端前先把补丁限定为 backend == EVBACKEND_EPOLL，再删掉本检查"
#endif
//libev/ev_epoll.c 的 epoll_poll 也有本地补丁（T14）：EPOLLERR/EPOLLHUP 只算作 fd 想要的事件，省掉一次多余的 MOD
#ifndef TPM_LIBEV_EPOLL_HUP_PATCH
#error "libev/ev_epoll.c 缺少 T14 的 ERR/HUP 映射补丁：重新打上，或决定不再保留时连同本检查一起删除"
#endif

//libev 每轮循环在 epoll 返回后把 CLOCK_MONOTONIC 读进 mn_now（ev_timer 也按它计时），4.24 没有公开的读取接口；ev_now() 是按它插值、每 0.5 s 与墙钟对齐一次的 ev_rt_now
ev_tstamp my_ev_mono_now(struct ev_loop *loop)
{
	return loop->mn_now;
}
