
#define EV_STANDALONE 1
#define EV_COMMON  void *data; unsigned long long u64;
#define EV_COMPAT3 0
// libev 只在 glibc 下自动启用 epoll/eventfd，musl（OpenWRT）会回落到 poll/pipe；这里固定为只用 epoll
#define EV_USE_EPOLL   1
#define EV_USE_EVENTFD 1
#define EV_USE_POLL    0
#define EV_USE_SELECT  0
//#define EV_VERIFY 2
