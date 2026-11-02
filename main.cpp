#include "common.h"
#include "log.h"
#include "git_version.h"
#include "config.h"

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/prctl.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sched.h>
#include <limits.h>
#include <linux/filter.h>
#include <thread>
#include <system_error>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <algorithm>

using  namespace std;

typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;

int disable_conn_clear=0;
int disable_tcp_nodelay=0;
//--disable-splice（D48）：TCP 只走 recv/send 拷贝路径，不创建 pipe。splice 本身不可用时由碰到的 worker 运行期置 1（审查 L1），各 worker 都读：relaxed 原子（M2）
std::atomic<int> disable_splice(0);
int sock_buf_explicit=0;//给了 --sock-buf：TCP socket 才设 SO_SNDBUF/SO_RCVBUF，否则交给内核自动调优
//--udp-gro（U5，D41）：UDP 监听与会话 socket 开 UDP_GRO，收到的 GRO 合并包整包带 UDP_SEGMENT 转发。第一个监听 socket 开不了
//（5.0 以前的内核）时清零，这时还没有 socket 开着 UDP_GRO；为 1 时各 worker 的 udp_batch 的 in/rin 带着收 cmsg 的控制缓冲
int udp_gro=0;

int max_pending_packet=0;

static app_config_t app_config;

int listen_fd_buf_size=2*1024*1024;//UDP 监听 socket 的 SO_SNDBUF/SO_RCVBUF，--udp-listen-buf
static const u32_t dns_refresh_interval=30000;
//DNS 线程数取引用的域名个数，最多这么多（D108）：getaddrinfo 没有截止时间（glibc 的 TCP 回退可能永远不返回），一个线程只卡一个域名
static const int dns_thread_max=4;
//DNS 换掉的旧地址上的 UDP 会话：客户端发来的包这么久没等到一个回包就算不可用（remote_sweep）
static const my_time_t udp_unans_timeout=10000;
//同上，TCP：上游 socket 连续超时重传（含 SYN）或零窗口探测没有应答到这么多次就算不可用
static const int tcp_unans_probes=3;
static const int max_accept_per_round=8;
//内核把 listen backlog 截断为所在网络命名空间的 net.core.somaxconn（5.4 起默认 4096，以前 128）。不用 SOMAXCONN：musl 与 glibc 2.31 以前都定义为 128；不超过 65535：4.1 以前 sk_max_ack_backlog 是 u16
static const int listen_backlog=65535;
static const my_time_t lru_move_interval=1000;
//worker 线程数（M2，S1，--threads N|auto）：每个 worker 一个线程、一个 loop，每条规则在每个 worker 各有一个监听（N>1 时组成 SO_REUSEPORT 组，D67）。
//默认 1（D5：P4 门槛通过前）；为 1 时也是主线程 + 1 个 worker 线程（D62）
static int worker_count=1;
static const int worker_count_max=64;
static const int worker_count_auto_max=8;//auto：可用 CPU 数，最多这么多（D5）
//CPU 亲和（M5，D70，--cpu-affinity）：worker k 绑到启动时可用 CPU 里的第 k 个；N>1 时每个 TCP reuseport 组挂按 CPU 分流的 cBPF（cpu_steer_code，D73：UDP 不挂）
static int cpu_affinity=0;
static vector<int> worker_cpus;//主线程在 pthread_create 之前写好，worker 线程只在启动时读自己那一项（A7：不进 worker_t）
static vector<struct sock_filter> cpu_steer_code;//空：不挂
static const size_t worker_stack_size=256*1024;//musl 1.1.16（OpenWRT SDK）默认线程栈 80 KiB；回调里最大的栈上数组是 log0 的 1 KiB 行缓冲
//上游第一次 send 不超过这么多字节时才不设 TCP_NODELAY（T15）。536 是 TCP_MSS_DEFAULT：对端初始窗口比它大时，这么多数据整段落在窗口内；
//比它小时内核把 MSS 截到窗口（tcp_bound_to_half_wnd），也不会在窗口边沿切出小段。更大的第一次写入可能被没对齐 MSS 的窗口边沿
//切出一个小段（如后端接收缓冲 8 KiB 时初始窗口 7240、路径 MSS 1388），尾段就要等这个小段的 ACK
static const int nodelay_first_max=536;

int VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV;

//侵入式双链表（T9）：节点就是连接对象本身（继承 lru_node_t），表头最近活动、表尾最久未活动；挂入、挪动、摘除都不分配内存、不查哈希
struct lru_collector_t:not_copy_able_t
{
	typedef lru_node_t* key_t;
	lru_node_t head;//哨兵：head.next 是表头，head.prev 是表尾；指向自身，所以本对象不能复制或移动
	int cnt;
	loop_clock_t *clock;//所属 worker 的时间缓存（M1），规则建好时设置
	lru_collector_t(const lru_collector_t &)=delete;
	lru_collector_t & operator=(const lru_collector_t &)=delete;
	lru_collector_t()
	{
		head.prev=head.next=&head;
		cnt=0;
		clock=0;
	}
	void link_front(key_t key)
	{
		key->prev=&head;
		key->next=head.next;
		head.next->prev=key;
		head.next=key;
	}
	void unlink(key_t key)
	{
		key->prev->next=key->next;
		key->next->prev=key->prev;
	}
	my_time_t update(key_t key)//返回本轮缓存的时间，调用方不必再取一次
	{
		DEBUG_ASSERT(key->next!=0);

		my_time_t value=clock->now();
		DEBUG_ASSERT(value >=head.next->ts);
		//距上次挪动不到 lru_move_interval 就不挪：链表仍按 ts 有序，ts 最多比实际最后活动早这么多，超时最多提前这么多（T8）
		if(value-key->ts<lru_move_interval) return value;
		key->ts=value;
		unlink(key);
		link_front(key);

		return value;
	}
	int new_key(key_t key)
	{
		DEBUG_ASSERT(key->next==0);

		my_time_t value=clock->now();
		if(!empty())
		{
			DEBUG_ASSERT(value >=head.next->ts);
		}
		key->ts=value;
		link_front(key);
		cnt++;

		return 0;
	}
	int size()
	{
		return cnt;
	}
	int empty()
	{
		return cnt==0;
	}

	my_time_t peek_back(key_t &key)
	{
		DEBUG_ASSERT(!empty());
		key=head.prev;
		return key->ts;
	}
	void erase(key_t key)
	{
		DEBUG_ASSERT(key->next!=0);
		unlink(key);
		key->prev=key->next=0;
		cnt--;
	}
};

//ASan 构建：池里空闲的对象和缓冲标为不可访问（T11）。对象常在同一轮被下一个连接取走，漏了 ev_io_stop 时多数先触发 libev 的 corrupted watcher 断言，没被复用时才报 use-after-poison
#ifdef __SANITIZE_ADDRESS__
extern "C" void __asan_poison_memory_region(void const volatile *addr, size_t size);
extern "C" void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
extern "C" int __asan_address_is_poisoned(void const volatile *addr);
#define pool_poison(p,n) __asan_poison_memory_region((p),(n))
#define pool_unpoison(p,n) __asan_unpoison_memory_region((p),(n))
#define pool_assert_not_free(p) assert(!__asan_address_is_poisoned(p))//重复归还：池满时 free 不检查用户投毒，之后的 unpoison 会让已释放的内存对 ASan 不可见
#else
#define pool_poison(p,n) ((void)(p),(void)(n))
#define pool_unpoison(p,n) ((void)(p),(void)(n))
#define pool_assert_not_free(p) ((void)(p))
#endif

//空闲链表：链接指针存在空闲块自己的开头，后进先出（刚归还的还在缓存里）
struct free_list_t
{
	void *head;
	int cnt;
	free_list_t()
	{
		head=0;
		cnt=0;
	}
	void push(void *p,size_t size)
	{
		*(void **)p=head;
		head=p;
		cnt++;
		pool_poison(p,size);
	}
	void *pop(size_t size)
	{
		void *p=head;
		pool_unpoison(p,size);
		head=*(void **)p;
		cnt--;
		return p;
	}
};

//归还连接对象时它的 watcher 必须都已 ev_io_stop（X1 常开检查，D30）。仍是 active（挂在 libev 的 anfds[fd] 链表上）或 pending（在本轮待回调队列里）时，
//本轮后面的连接复用这块内存与 fd 号，ev_io_start 会把链表接成环：libev 的 corrupted watcher 断言只认自环，多节点环和不同 fd 号的旧 watcher
//（活锁、串流、旧事件回调到新连接）它查不到。所以发布构建也检查，违反就记日志后中止；每次归还读 4 个（UDP 2 个）字段、一次跳转。
//直接读 ev_io 的成员，与 ev_is_active/ev_is_pending 等价，不经它们的 ev_watcher* 强转（不新增 strict-aliasing 告警）
static inline int pool_watchers_busy(tcp_pair_t *p)
{
	return p->local.ev.active|p->local.ev.pending|p->remote.ev.active|p->remote.ev.pending;
}
static inline int pool_watchers_busy(udp_pair_t *p)
{
	return p->ev.active|p->ev.pending;
}
static void __attribute__((noinline,cold)) pool_put_busy_abort()
{
	mylog(log_fatal,"connection object returned to the pool while libev still references one of its watchers (missing ev_io_stop)\n");
	fflush(stdout);
	abort();
}

static const int obj_pool_slab_objs=64;
//连接对象池（T11）：一次 malloc 64 个对象（slab），释放的对象进空闲链表，建连先从链表取，热路径上不调 malloc；slab 不归还，保留量为全部规则连接数的峰值向上取整到 64。
//取出时就地重新构造，状态与新对象相同（LRU 的 prev/next 为 0，watcher 清零，对 ev_io_stop 等价于 ev_init）。归还前两个 watcher 都要 ev_io_stop：
//它同时清除本轮还没回调的事件，归还后同一轮里后面 accept 的连接就可能取走这块内存（T10）
template<class T> struct obj_pool_t
{
	free_list_t free_objs;
	int slabs;//已分配的 slab 数（O1）：在用对象数 = slabs*obj_pool_slab_objs-free_objs.cnt
	obj_pool_t()
	{
		slabs=0;
	}
	T *get()
	{
		if(free_objs.head==0)
		{
			char *slab=(char *)malloc(sizeof(T)*obj_pool_slab_objs);
			if(slab==0) return 0;//调用方只拒这个客户端，不退出进程（T11 审查 F2）
			slabs++;
			for(int i=0;i<obj_pool_slab_objs;i++)
				free_objs.push(slab+sizeof(T)*i,sizeof(T));
		}
		return new(free_objs.pop(sizeof(T))) T();
	}
	void put(T *obj)
	{
		if(pool_watchers_busy(obj)) pool_put_busy_abort();
		obj->~T();
		free_objs.push(obj,sizeof(T));
	}
};

static const int tcp_buf_pool_max_free=64;//D19：一轮 epoll_wait 起步取 64 个事件，一轮里归还又借走的块一般不超过它；最多留 4 MiB
//TCP 收发缓冲池（T11），每块 max_data_len_tcp：tcp_scratch 之外只有 send 没发完的方向持有一块（D17），排空后归还
struct tcp_buf_pool_t
{
	free_list_t free_bufs;
	int alloc;//已 malloc 还没 free 的块数（O1）：每块要么是 tcp_scratch，要么属于某个方向，要么在空闲链表里
	tcp_buf_pool_t()
	{
		alloc=0;
	}
	char *get()
	{
		if(free_bufs.head!=0) return (char *)free_bufs.pop(max_data_len_tcp);
		char *buf=(char *)malloc(max_data_len_tcp);
		if(buf==0) return 0;//调用方只关这一对，不退出进程（T11 审查 F2）
		alloc++;
		return buf;
	}
	void put(char *buf)
	{
		pool_assert_not_free(buf);
		if(free_bufs.cnt>=tcp_buf_pool_max_free)
		{
			free(buf);
			alloc--;
			return;
		}
		free_bufs.push(buf,max_data_len_tcp);
	}
};

//D46：本方向上一次读到这么多字节，下一次读就 splice（探针：每次 64 B 时 splice 比 recv+send 慢 3.7%，2 KB 持平，16 KB 快 19%，64 KB 快 58%）
static const int splice_read_min=16384;
//pipe 大小（B3，D55、D57，--pipe-size）：新 pipe 不到这么大就用 F_SETPIPE_SZ 扩上去（只扩不缩：64K 页内核默认已是 1 MiB），
//一次 splice 进 pipe 也最多读这么多：背压时它整段留在方向持有的 pipe 里，是不计入 tcp_mem 与 memcg 的内核页（D51 原为 64 KiB）。
//5.5 起（4.19.y、5.4.y 回移）内核按 pipe 空闲槽数 × PAGE_SIZE 截断一次读，4.9/4.14 不截断。一个片段占一个槽：网卡来源每槽约 1 MSS，
//16 槽一次只有约 22 KiB（B12 审查 M3），64 槽约 90 KB。启动时 tcp_pipe_probe() 换成实际值（内核向上取到 2 的幂页数）
static int tcp_pipe_size=256*1024;
static int pipe_size_explicit=0;//给了 --pipe-size
//splice 时一次回调最多搬这么多（D53、D55、D56）：源端这次读够 splice_more_min 且整段写出就接着读，源端读得少或目的端没写完就停。
//每次写出都可能唤醒一次接收方，一次回调搬得越多唤醒越少，同一轮里其他连接等得越久。同进程 8 条大流量与 64 B 往返：
//64K × 4 次 115 Gbit/s、p50 295 µs，256K × 1 次 161、216 µs，256K × 4 次 173、774 µs。--pipe-size 大于 256 KiB 时每回调
//(大小 ÷ 256 KiB) 个满 pipe，用其他连接的延迟换吞吐（D56）：1 MiB 时 4 MiB，207–213 Gbit/s，往返 p99 2.8 ms（同 realm -p 256）
static int splice_turn_max=256*1024;
static const int splice_more_min=65536;//64K pipe（扩容失败）满一次、网卡来源 64 槽满一次都够这个数
static int tcp_pipe_min_size=65536;//新 pipe 不到 16 槽（fs.pipe-user-pages-soft 已满时只有 2 页）就不用：每次 splice 只能搬 2 个片段。按槽数判断（D58），启动时按页大小设
static const int tcp_pipe_pool_max_free=64;//同 D19；pipe 比 16 页大时按页数折算，见 tcp_pipe_pool_t::max_free
static int tcp_pipe_max_free=tcp_pipe_pool_max_free;//tcp_pipe_pool_t::max_free 的值：启动时 tcp_pipe_probe() 按 pipe 大小与 worker 数算出，之后只读，worker 的 pipe 池构造时取它（M1、D64）

//pipe 里还有多少字节，只给 DEBUG_ASSERT 用：还池与复用的 pipe 必须是空的，计账错了就会把一个连接的数据写给另一个连接
static inline int tcp_pipe_len(const tcp_pipe_t &p)
{
	int n=-1;
	ioctl(p.r,FIONREAD,&n);
	return n;
}

//pipe 创建失败、扩容失败各只有整个进程的第一次记 info，之后 debug（B3 审查 L1）；各 worker 共用（M2），由把它从 0 换成 1 的线程记 info
static std::atomic<int> pipe_fail_logged(0),pipe_grow_logged(0);
//pipe 池（B2，D47）：splice 都读进 tcp_pipe_scratch，整段写出就留着给下一次；没写完时连同数据交给该方向（tcp_info_t::pipe），
//排空后还回来。空闲的最多留 max_free 个，多出的 close；有残留数据的 pipe 不复用，释放连接对时直接 close
struct tcp_pipe_pool_t
{
	tcp_pipe_t free_pipes[tcp_pipe_pool_max_free];
	int free_cnt;
	int alloc;//已创建还没关闭的 pipe 数（O1）：每个要么是 scratch，要么属于某个方向，要么在空闲表里
	int blocked;//创建失败过：到下一个定时器周期（clear_timer_cb 清零）之前不再创建，免得每次读都试
	int grow_blocked;//扩容失败过（D58）：到下一个定时器周期之前新建的 pipe 不再试扩
	u64_t resize_fail;//没能扩到 tcp_pipe_size 的新 pipe 个数（含 grow_blocked 期间没试的），stats pool 行输出
	//空闲的最多留几个：整个进程合计不超过 64 个 16 页 pipe 的 1024 页（B3 审查 M1），按 worker 数均分、每个 worker 至少 1 个（D64）。
	//fs.pipe-user-pages-soft 按 uid、按容量计页，池里的空 pipe 也算，留多了同 uid 的其他进程（以 root 运行时含没有 CAP_SYS_RESOURCE
	//的容器 root）只能拿到 2 页的 pipe。1 个 worker 时 256 KiB 16 个、1 MiB 4 个；构造时取 tcp_pipe_probe() 算出的 tcp_pipe_max_free
	int max_free;
	//新 pipe 因配额只有 2 页（不到 16 槽）之后，到下一个定时器周期之前不再建 pipe：这期间还回来的 pipe 马上会被别的方向借走，
	//留到 64 个，否则超过 max_free 的被关掉、那些方向只能走拷贝（复审 R1：非 root 2000 条停读、--pipe-size 1024 时 63.4 → 73.2 Gbit/s）。
	//clear_timer_cb 清标志时裁回 max_free。fd 不够时不放宽（D52）
	int quota_hit;
	tcp_pipe_pool_t()
	{
		free_cnt=0;
		alloc=0;
		blocked=0;
		grow_blocked=0;
		resize_fail=0;
		max_free=tcp_pipe_max_free;
		quota_hit=0;
	}
	int fail_level()//创建失败：到下一个定时器周期之前不再创建；只有第一次记 info
	{
		blocked=1;
		return pipe_fail_logged.exchange(1,memory_order_relaxed)?log_debug:log_info;
	}
	int get(tcp_pipe_t &p)
	{
		if(free_cnt>0)
		{
			p=free_pipes[--free_cnt];
			return 0;
		}
		return create(p);
	}
	int __attribute__((noinline)) create(tcp_pipe_t &p)//池空时才走到，不内联进 tcp_cb
	{
		if(blocked) return -1;
		int fds[2];
		if(pipe2(fds,O_NONBLOCK|O_CLOEXEC)!=0)
		{
			//EMFILE、ENFILE，或到了 fs.pipe-user-pages-hard
			int level=fail_level();
			mylog(level,"[tcp]pipe2 failed (%s), forwarding by copy instead of splice until the next timer tick\n",get_sock_error());
			return -1;
		}
		//最后 1/4 的 fd 只留给 socket（D52）：持有数据的 pipe 每方向占 2 个 fd，nofile 小时会挤掉新连接（C5、C6）
		struct rlimit rl;
		if(getrlimit(RLIMIT_NOFILE,&rl)==0&&rl.rlim_cur!=RLIM_INFINITY&&(rlim_t)max(fds[0],fds[1])>=rl.rlim_cur/4*3)
		{
			close(fds[0]);
			close(fds[1]);
			int level=fail_level();
			mylog(level,"[tcp]pipe fd %d is in the last quarter of RLIMIT_NOFILE (%llu), forwarding by copy instead of splice until the next timer tick\n",max(fds[0],fds[1]),(unsigned long long)rl.rlim_cur);
			return -1;
		}
		int size=fcntl(fds[1],F_GETPIPE_SZ);
		if(size<tcp_pipe_min_size)
		{
			close(fds[0]);
			close(fds[1]);
			quota_hit=1;
			int level=fail_level();
			mylog(level,"[tcp]new pipe has only %d bytes (fs.pipe-user-pages-soft reached?), forwarding by copy instead of splice until the next timer tick\n",size);
			return -1;
		}
		//扩到 tcp_pipe_size（D55）。失败（非特权用户到了 fs.pipe-user-pages-soft 时 EPERM，或 ENOMEM）时这个 pipe 保持原大小照常用（D58）
		if(size<tcp_pipe_size)
		{
			if(grow_blocked||fcntl(fds[1],F_SETPIPE_SZ,tcp_pipe_size)<0)
			{
				resize_fail++;
				if(!grow_blocked)
				{
					grow_blocked=1;
					int level=pipe_grow_logged.exchange(1,memory_order_relaxed)?log_debug:log_info;
					mylog(level,"[tcp]enlarging a new pipe to %d bytes failed (%s), new pipes keep %d bytes until the next timer tick (fs.pipe-user-pages-soft reached?)\n",tcp_pipe_size,get_sock_error(),size);
				}
			}
		}
		p.r=fds[0];
		p.w=fds[1];
		alloc++;
		return 0;
	}
	void put(tcp_pipe_t &p)//p 已排空
	{
		DEBUG_ASSERT(tcp_pipe_len(p)==0);
		if(free_cnt>=(quota_hit?tcp_pipe_pool_max_free:max_free)) discard(p);
		else free_pipes[free_cnt++]=p;
		p.r=p.w=-1;
	}
	//扩容失败过之后，没扩上去的 pipe 会一直当 scratch、在池里循环使用（B3 审查 M2）：clear_timer_cb 每个周期对 scratch 调一次，
	//池里的小 pipe 轮到当 scratch 时也会扩上。失败就到下一个周期之前不再试扩新 pipe
	void regrow(tcp_pipe_t &p)
	{
		if(fcntl(p.w,F_GETPIPE_SZ)<tcp_pipe_size&&fcntl(p.w,F_SETPIPE_SZ,tcp_pipe_size)<0) grow_blocked=1;
	}
	void discard(tcp_pipe_t &p)//可能还有数据：直接关掉
	{
		close(p.r);
		close(p.w);
		alloc--;
		p.r=p.w=-1;
	}
};

//启动时用一个 pipe 试一次 tcp_pipe_size（D57）：超过 fs.pipe-max-size 又没有 CAP_SYS_RESOURCE（只认初始 user namespace）时 EPERM，
//降到 pipe-max-size：给了 --pipe-size 时 warn，默认值只记 info（同 D40）。别的失败（如配额已满）留给 create() 逐个回退
static void tcp_pipe_probe()
{
	int page=(int)sysconf(_SC_PAGESIZE);
	tcp_pipe_min_size=16*page;
	//内核把 F_SETPIPE_SZ 的大小向上取到 2 的幂页数（如 300 KiB → 512 KiB），先按同样规则取整：探测没设成功时读上限与每回调预算也与之后的 pipe 一致（审查 L2）
	int pages=1;
	while(pages*page<tcp_pipe_size) pages*=2;
	tcp_pipe_size=pages*page;
	int fds[2];
	if(pipe2(fds,O_CLOEXEC)==0)
	{
		int size=fcntl(fds[1],F_GETPIPE_SZ);
		if(size>0&&size<tcp_pipe_size)
		{
			int r=fcntl(fds[1],F_SETPIPE_SZ,tcp_pipe_size);
			if(r>0) tcp_pipe_size=r;
			else if(errno==EPERM)
			{
				int max_size=0;
				FILE *f=fopen("/proc/sys/fs/pipe-max-size","r");
				if(f!=0)
				{
					if(fscanf(f,"%d",&max_size)!=1) max_size=0;
					fclose(f);
				}
				if(max_size>0&&tcp_pipe_size>max_size)
				{
					mylog(pipe_size_explicit?log_warn:log_info,"%s %d KiB is above fs.pipe-max-size (%d KiB) and CAP_SYS_RESOURCE is missing, using %d KiB\n",
						pipe_size_explicit?"--pipe-size":"default pipe size",tcp_pipe_size/1024,max_size/1024,max_size/1024);
					tcp_pipe_size=max_size;
				}
			}
		}
		close(fds[0]);
		close(fds[1]);
	}
	splice_turn_max=tcp_pipe_size<=256*1024?256*1024:tcp_pipe_size/(256*1024)*tcp_pipe_size;
	tcp_pipe_max_free=max(1,tcp_pipe_pool_max_free*16/max(16,tcp_pipe_size/page)/worker_count);//D64：合计页数按 worker 均分
}
//splice 写不完时对目的端调用（D54）：主机越过 tcp_mem 压力线时内核把目的 socket 的 sndbuf 缩到当时队列的一半（sk_stream_moderate_sndbuf），
//压力期间不再放大。回环这类 MSS 接近 64 KiB 的目的端缩完装不下 2 段，只有 1 段在途，接收方对单个满长段延迟 ACK（约 40 ms），
//2000 条停读连接时吞吐只有拷贝路径的一半（拷贝路径很少被缩）。这时锁到 2×MSS（内核再翻倍，4 段），代价是这个 socket 不再自动调大。
//sndbuf 最小约 4.6 KB（SOCK_MIN_SNDBUF），MSS 1448 这类网卡路径永远有 3 段以上：第一次读 MSS 后就不再查（每方向一次 getsockopt）。
//只按 sndbuf 判断、不看 MSS 时，网卡路径新连接约 87 KB 的 sndbuf 也会被锁住，10 ms RTT 单流 1.55 → 0.17 Gbit/s。给了 --sock-buf 时不动
static const int tcp_min_sndbuf=4608;
static void tcp_unshrink_sndbuf(tcp_info_t &info)
{
	if(sock_buf_explicit) return;
	socklen_t len;
	if(info.mss==0)
	{
		len=sizeof(info.mss);
		if(getsockopt(info.fd,IPPROTO_TCP,TCP_MAXSEG,&info.mss,&len)!=0||info.mss<=0) info.mss=-1;
	}
	if(2*info.mss<=tcp_min_sndbuf) return;
	int sb=0;
	len=sizeof(sb);
	if(getsockopt(info.fd,SOL_SOCKET,SO_SNDBUF,&sb,&len)!=0||sb>=2*info.mss) return;
	int val=2*info.mss;
	setsockopt(info.fd,SOL_SOCKET,SO_SNDBUF,&val,sizeof(val));
	mylog(log_debug,"[tcp]fd=%d sndbuf shrunk to %d (mss %d), set SO_SNDBUF to %d\n",info.fd,sb,info.mss,val);
}

static const int udp_batch_max=64;//U1：一次 recvmmsg 最多收这么多包，也是一次回调最多处理的包数（D35）
//U4：会话 socket 每次回调最多收这么多回包（D37）。所有客户端的入向共用一个监听 socket、每轮一批，回程每个会话各一个 socket：
//转发器跟不上时每轮回程是"积压会话数 × 本值"，取 64 时入向只剩约 1/6（同进程 TCP 的往返也随轮长变慢），取 16 时与 U4 之前相当
static const int udp_return_quota=16;
static const int udp_slot_len=2048;
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
//U5：一次 GSO 发送最多这么多段。UDP_MAX_SEGMENTS 在 4.18–6.8 是 64、6.9 起 128（部分 LTS 已回移），按最小值；GRO 本身最多聚合 64 段
static const int udp_gso_max_segs=64;
//发包的 cmsg（UDP_SEGMENT，u16）；union 保证 cmsghdr 的对齐。
//64 位 musl 的 cmsghdr 在 cmsg_len 旁有填充，内核读的是 size_t：只按字段名写，缓冲在 worker_new() 清零的页里，填充恒为 0
union udp_ctrl_t
{
	cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))];
};
//收包的 cmsg：内核依次写 UDP_GRO（int）、IPV6_PKTINFO、IP_PKTINFO（D87），按三者都在的大小，任何组合都不会 MSG_CTRUNC
union udp_recv_ctrl_t
{
	cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(in6_pktinfo))+CMSG_SPACE(sizeof(in_pktinfo))];
};
//回程发送条目的 cmsg（D87）：[UDP_SEGMENT][IP_PKTINFO 或 IPV6_PKTINFO]，pktinfo 从 CMSG_SPACE(u16) 处开始（内核在那里找下一个 cmsg，
//udp_ret_pi），只带其中一个时 msg_control 指向那一段。pktinfo 的 msg_controllen 按 CMSG_LEN 计（IPv6 为 36）：内核栈上的控制缓冲是
//sizeof(cmsghdr)+20，超出就每条消息 kmalloc 一次
union udp_ret_ctrl_t
{
	cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(uint16_t))+CMSG_SPACE(sizeof(in6_pktinfo))];
};
static inline cmsghdr *udp_ret_pi(udp_ret_ctrl_t &c)
{
	return (cmsghdr *)(c.buf+CMSG_SPACE(sizeof(uint16_t)));
}
//UDP 监听 socket 的入向批（U1、U3，D34）。每条消息两段 iov：2 KB 的槽（64 个连续排列，MTU 级的包只碰这里）加本消息自己的溢出区，
//合计 max_data_len_udp；每个 worker 一份（M1，原为 BSS），在 worker_new() 用 mmap 分配的页里：溢出区只有大于 2 KB 的包才碰到它的页，
//常驻内存随大包增长，最多约 4 MiB
struct udp_batch_t
{
	mmsghdr in[udp_batch_max];//recvmmsg 用：msg_name 指向 addr[i]，iov 固定指向 slot[i]、overflow[i]
	iovec in_iov[udp_batch_max][2];
	address_t::storage_t addr[udp_batch_max];
	udp_pair_t *pair[udp_batch_max];//第 i 个包所属的会话，0 表示已丢弃
	//sendmmsg 用：同一会话的包排在一起。msg_name 为 0：connected socket 上带地址就改发到那个地址。udp_send_group 直接调 syscall，
	//64 位 musl 的 __pad1/__pad2 必须保持 0（非 0 时内核报 EMSGSIZE）：只按字段名赋值，不要把别处的 msghdr 整个赋进来
	mmsghdr out[udp_batch_max];
	iovec out_iov[udp_batch_max][2];
	udp_pair_t *group_pair[udp_batch_max];//组按会话在本批首次出现的顺序编号
	int group_cnt[udp_batch_max];
	int group_pos[udp_batch_max];
	char slot[udp_batch_max][udp_slot_len];
	char overflow[udp_batch_max][max_data_len_udp-udp_slot_len];
	//回程批（U4，D36）：会话 socket 收到的回包也放在上面的槽和溢出区里，占 slot[0..rn)，攒到本轮循环阻塞之前（ev_prepare）
	//跨会话发出；批满时立即发出。入向收包之前（udp_accept_cb）也先发出，所以入向用这些槽时回程批总是空的，别处要用槽同样先发出
	mmsghdr rin[udp_batch_max];//会话 socket 的 recvmmsg 用：msg_name 为 0（来源就是上游），iov 与 in[i] 共用 in_iov[i]
	address_t raddr[udp_batch_max];//收包时拷下的客户端地址：会话在发出之前被释放、对象被池交给别的客户端也不受影响
	udp_local_t rlocal[udp_batch_max];//同 raddr，收包时拷下的会话本地地址（D87），family 为 0 时回包不挂 pktinfo
	forward_rule_t *rrule[udp_batch_max];//回包所属的规则（监听 socket 与计数），0 表示丢弃或已放进本次发出的组
	mmsghdr rout[udp_batch_max];//对监听 socket 的 sendmmsg 用，一次放一个规则的组；填充同 out，必须保持 0
	iovec rout_iov[udp_batch_max][2];
	int rn;
	//U5（--udp-gro）、D87（通配监听的 PKTINFO）：ctrl[i] 收槽 i 的 cmsg，in[i] 与 rin[i] 共用（槽 i 同一时刻只属于一方），in_ctrl 为 1 时
	//in[] 挂着它；gso[i] 是收包时从中取出的段长，槽 i 里不是 GRO 合并包时为 0。out_ctrl/rout_ctrl 给发送条目挂 UDP_SEGMENT，rout_ctrl
	//还挂回程的 pktinfo；seg 把一个合并包切开重发（udp_send_split），填充同 out，必须保持 0。udp_gro 为 0 且没有通配监听时都不用
	udp_recv_ctrl_t ctrl[udp_batch_max];
	int in_ctrl;
	int gso[udp_batch_max];
	unsigned char roff[udp_batch_max];//回包所属会话收包时的 gso_off[1]（D45），按槽
	udp_ctrl_t out_ctrl[udp_batch_max];
	udp_ret_ctrl_t rout_ctrl[udp_batch_max];
	unsigned char rout_off[udp_batch_max];//rout 第 i 条的 roff，udp_send_group 关掉 GSO 时也改它
	mmsghdr seg[udp_batch_max];
	iovec seg_iov[udp_batch_max][2];
	udp_ret_ctrl_t seg_ctrl[udp_batch_max];
	static void init_segment(cmsghdr &h)
	{
		h.cmsg_level=SOL_UDP;
		h.cmsg_type=UDP_SEGMENT;
		h.cmsg_len=CMSG_LEN(sizeof(uint16_t));//内核要求恰好是这个长度，否则 EINVAL
	}
	//所属 worker 的监听 socket 开了 UDP_GRO（udp_gro_listen，rin_too 为 1：会话 socket 也开）或 PKTINFO（udp_pktinfo_listen）之后调用，可重复
	void attach_ctrl(int rin_too)
	{
		in_ctrl=1;
		for(int i=0;i<udp_batch_max;i++)
		{
			in[i].msg_hdr.msg_control=&ctrl[i];
			in[i].msg_hdr.msg_controllen=sizeof(ctrl[i]);
			if(!rin_too) continue;
			rin[i].msg_hdr.msg_control=&ctrl[i];
			rin[i].msg_hdr.msg_controllen=sizeof(ctrl[i]);
		}
	}
	udp_batch_t()
	{
		for(int i=0;i<udp_batch_max;i++)
		{
			in_iov[i][0].iov_base=slot[i];
			in_iov[i][0].iov_len=udp_slot_len;
			in_iov[i][1].iov_base=overflow[i];
			in_iov[i][1].iov_len=sizeof(overflow[i]);
			in[i].msg_hdr.msg_name=&addr[i];
			in[i].msg_hdr.msg_namelen=sizeof(addr[i]);
			in[i].msg_hdr.msg_iov=in_iov[i];
			in[i].msg_hdr.msg_iovlen=2;
			out[i].msg_hdr.msg_iov=out_iov[i];
			rin[i].msg_hdr.msg_iov=in_iov[i];
			rin[i].msg_hdr.msg_iovlen=2;
			rout[i].msg_hdr.msg_iov=rout_iov[i];
			seg[i].msg_hdr.msg_iov=seg_iov[i];
			init_segment(out_ctrl[i].hdr);
			init_segment(rout_ctrl[i].hdr);
			init_segment(seg_ctrl[i].hdr);
		}
		rn=0;
		in_ctrl=0;
	}
};
//发送用的 iov：第 i 个包的前 2 KB 在 b.slot[i]，其余在 b.overflow[i]
static inline void udp_batch_set_iov(udp_batch_t &b,mmsghdr &m,iovec *iov,int i,int len)
{
	iov[0].iov_base=b.slot[i];
	if(len<=udp_slot_len)
	{
		iov[0].iov_len=len;
		m.msg_hdr.msg_iovlen=1;
	}
	else
	{
		iov[0].iov_len=udp_slot_len;
		iov[1].iov_base=b.overflow[i];
		iov[1].iov_len=len-udp_slot_len;
		m.msg_hdr.msg_iovlen=2;
	}
}
//U5：len 字节的包按段长 gso 切成的数据报数，gso 为 0 时是 1
static inline int udp_segs(size_t len,int gso)
{
	return gso==0?1:(int)((len+gso-1)/gso);
}
//D87：收到的 IPV6_PKTINFO 目的地址 a 记成会话本地地址。v4-mapped 按 IPv4 记（回包挂 IP_PKTINFO），组播与受限广播不记（不能作源；
//子网广播认不出来，交给 D90 的回退）；链路本地地址只在客户端也带 scope_id 时记，回包的出口由客户端地址的 scope_id 决定
static inline void udp_local_from6(const in6_addr &a,const address_t::storage_t &from,udp_local_t &l)
{
	if(IN6_IS_ADDR_V4MAPPED(&a))
	{
		memcpy(&l.v4,&a.s6_addr[12],sizeof(l.v4));
		u32_t h=ntohl(l.v4.s_addr);
		if((h>>28)!=0xe&&h!=0xffffffffu) l.family=AF_INET;
		return;
	}
	if(IN6_IS_ADDR_MULTICAST(&a)) return;
	if(IN6_IS_ADDR_LINKLOCAL(&a)&&(from.ipv6.sin6_family!=AF_INET6||from.ipv6.sin6_scope_id==0)) return;
	l.v6=a;
	l.family=AF_INET6;
}
//U5、D87：收到的条目带 UDP_GRO cmsg 时返回其中的 gso_size，否则 0；控制数据被截断（MSG_CTRUNC）时返回 -1，调用方丢掉这个包：
//段长可能就在被截掉的部分里，当成普通数据报会把合并包作为一个大数据报发出（审查 L4；内核先写 SO_TIMESTAMP 等 cmsg 再写 UDP_GRO、
//PKTINFO，将来给这些 socket 加别的 cmsg 时要加大 udp_recv_ctrl_t）。local 不为 0 时取出这个包的目的地址（没有 PKTINFO 时 family
//保持 0），from 是发送方地址。同时把内核改写的 msg_controllen 恢复成缓冲大小，下一次收包之前必须做。
//gso_size 是 int（按 u16 读在大端 MIPS 上得到 0）
static inline int udp_recv_ctrl(msghdr &h,udp_local_t *local,const address_t::storage_t &from)
{
	int g=0;
	if(h.msg_flags&MSG_CTRUNC)
		g=-1;
	else
	{
		for(cmsghdr *c=CMSG_FIRSTHDR(&h);c!=0;c=CMSG_NXTHDR(&h,c))
		{
			if(c->cmsg_level==SOL_UDP&&c->cmsg_type==UDP_GRO)
				memcpy(&g,CMSG_DATA(c),sizeof(g));
			else if(local!=0&&c->cmsg_level==SOL_IP&&c->cmsg_type==IP_PKTINFO)
			{
				//ipi_spec_dst：单播时等于目的地址，广播/组播时是收包网卡的地址；选项开启之前就排队的包为 0，退回目的地址
				in_pktinfo pi;
				memcpy(&pi,CMSG_DATA(c),sizeof(pi));
				local->v4=pi.ipi_spec_dst.s_addr!=0?pi.ipi_spec_dst:pi.ipi_addr;
				local->family=AF_INET;
			}
			else if(local!=0&&c->cmsg_level==SOL_IPV6&&c->cmsg_type==IPV6_PKTINFO)
			{
				in6_pktinfo pi;
				memcpy(&pi,CMSG_DATA(c),sizeof(pi));
				udp_local_from6(pi.ipi6_addr,from,*local);
			}
		}
	}
	h.msg_controllen=sizeof(udp_recv_ctrl_t);
	return g;
}
//U5：第 i 个槽里 len 字节的包是 GRO 合并包且多于 1 段时返回段长（发送时挂 UDP_SEGMENT），否则 0：
//没有 TX 校验和 offload 的出口在 6.11 以前连单段的 GSO 也报 EIO（探针实测）
static inline int udp_batch_gso(udp_batch_t &b,int i,int len)
{
	int g=b.gso[i];
	DEBUG_ASSERT(g<=0xffff);
	return g!=0&&len>g?g:0;
}
//U5：发送条目 m 发第 i 个槽里 len 字节的包，按 udp_batch_gso 挂 UDP_SEGMENT（段长同收到的）或不挂
static inline void udp_batch_set_gso(udp_batch_t &b,mmsghdr &m,udp_ctrl_t &c,int i,int len)
{
	int g=udp_batch_gso(b,i,len);
	if(g!=0)
	{
		uint16_t v=(uint16_t)g;
		memcpy(CMSG_DATA(&c.hdr),&v,sizeof(v));
		m.msg_hdr.msg_control=&c;
		m.msg_hdr.msg_controllen=CMSG_SPACE(sizeof(uint16_t));
	}
	else
	{
		m.msg_hdr.msg_control=0;
		m.msg_hdr.msg_controllen=0;
	}
}
//D87：在 h 处写本地地址 l 的 pktinfo，返回它占的 msg_controllen（CMSG_LEN）。IPv4 与 v4-mapped 客户端都用 SOL_IP 的 IP_PKTINFO
//（3.10 起都生效；v4-mapped 的 IPV6_PKTINFO 3.15 以前被忽略）。ifindex 填 0，出口由路由（及客户端地址的 scope_id）决定
static inline socklen_t udp_set_pktinfo(cmsghdr &h,const udp_local_t &l)
{
	if(l.family==AF_INET)
	{
		in_pktinfo pi;
		memset(&pi,0,sizeof(pi));
		pi.ipi_spec_dst=l.v4;
		h.cmsg_level=SOL_IP;
		h.cmsg_type=IP_PKTINFO;
		h.cmsg_len=CMSG_LEN(sizeof(pi));
		memcpy(CMSG_DATA(&h),&pi,sizeof(pi));
		return CMSG_LEN(sizeof(pi));
	}
	in6_pktinfo pi;
	memset(&pi,0,sizeof(pi));
	pi.ipi6_addr=l.v6;
	h.cmsg_level=SOL_IPV6;
	h.cmsg_type=IPV6_PKTINFO;
	h.cmsg_len=CMSG_LEN(sizeof(pi));
	memcpy(CMSG_DATA(&h),&pi,sizeof(pi));
	return CMSG_LEN(sizeof(pi));
}
//D87：回程发送条目 m 的控制数据：段长 gso 不为 0 时挂 UDP_SEGMENT，本地地址 l 有值时挂 pktinfo，两者都没有时不挂
static inline void udp_ret_set_ctrl(mmsghdr &m,udp_ret_ctrl_t &c,int gso,const udp_local_t &l)
{
	socklen_t len=l.family!=0?udp_set_pktinfo(*udp_ret_pi(c),l):0;
	if(gso!=0)
	{
		uint16_t v=(uint16_t)gso;
		memcpy(CMSG_DATA(&c.hdr),&v,sizeof(v));
		m.msg_hdr.msg_control=&c;
		m.msg_hdr.msg_controllen=CMSG_SPACE(sizeof(uint16_t))+len;
	}
	else if(len!=0)
	{
		m.msg_hdr.msg_control=udp_ret_pi(c);
		m.msg_hdr.msg_controllen=len;
	}
	else
	{
		m.msg_hdr.msg_control=0;
		m.msg_hdr.msg_controllen=0;
	}
}

//UDP 会话的键（U2）：族、端口、地址，IPv6 再加 scope_id（同一个 fe80:: 地址在不同网卡上是不同的对端）。sockaddr 的其余字节不比：
//from_sockaddr 先清零，内核填的 sin6_flowinfo 恒为 0，结果与比较整个 address_t 相同
static inline int udp_key_eq(const address_t &a,const address_t &b)
{
	if(a.inner.ipv4.sin_family!=b.inner.ipv4.sin_family||a.inner.ipv4.sin_port!=b.inner.ipv4.sin_port) return 0;
	if(a.inner.ipv4.sin_family==AF_INET) return a.inner.ipv4.sin_addr.s_addr==b.inner.ipv4.sin_addr.s_addr;
	u64_t x[2],y[2];
	memcpy(x,&a.inner.ipv6.sin6_addr,sizeof(x));
	memcpy(y,&b.inner.ipv6.sin6_addr,sizeof(y));
	return x[0]==y[0]&&x[1]==y[1]&&a.inner.ipv6.sin6_scope_id==b.inner.ipv6.sin6_scope_id;
}
static inline u64_t udp_key_mix(u64_t x)//murmur3 的 fmix64
{
	x^=x>>33;
	x*=0xff51afd7ed558ccdULL;
	x^=x>>33;
	x*=0xc4ceb9fe1a85ec53ULL;
	x^=x>>33;
	return x;
}
//每个 64 位字并入后混合一次：IPv4 一次，IPv6 三次。族不参与：一个会话表只属于一个监听 socket
static inline u32_t udp_key_hash(const address_t &a)
{
	if(a.inner.ipv4.sin_family==AF_INET)
		return (u32_t)udp_key_mix((u64_t)a.inner.ipv4.sin_addr.s_addr<<16|a.inner.ipv4.sin_port);
	u64_t w[2];
	memcpy(w,&a.inner.ipv6.sin6_addr,sizeof(w));
	u64_t h=udp_key_mix((u64_t)a.inner.ipv6.sin6_scope_id<<16|a.inner.ipv6.sin6_port);
	h=udp_key_mix(h^w[0]);
	return (u32_t)udp_key_mix(h^w[1]);
}

static const u32_t udp_table_min_cap=64;
//客户端地址 → UDP 会话（U2）：开放寻址、线性探测，容量是 2 的幂，最多装到 3/4。槽里存会话指针和键的哈希：探测时先比哈希，
//不读别的会话对象；扩容时按存下的哈希重新放，不重算。删除用后移（backward shift），没有墓碑。容量从 64 起按需翻倍、不缩
//（同对象池的 slab），每条规则最多 max_conn_num 个会话，即最多 32768 槽（LP64 512 KiB）
struct udp_table_t:not_copy_able_t
{
	struct slot_t
	{
		udp_pair_t *pair;//0 为空槽
		u32_t hash;
	};
	slot_t *slots;
	u32_t mask;//容量 - 1；slots 为 0 时为 0
	int cnt;
	udp_table_t()
	{
		slots=0;
		mask=0;
		cnt=0;
	}
	udp_pair_t *find(const address_t &addr,u32_t hash)
	{
		if(slots==0) return 0;
		for(u32_t i=hash&mask;;i=(i+1)&mask)
		{
			if(slots[i].pair==0) return 0;
			if(slots[i].hash==hash&&udp_key_eq(slots[i].pair->adress,addr)) return slots[i].pair;
		}
	}
	//保证再插入一个也不超过 3/4；扩容的 malloc 失败时返回 -1，调用方只拒这个新会话
	int reserve_one()
	{
		if(slots!=0&&(u32_t)(cnt+1)*4<=(mask+1)*3) return 0;
		return grow();
	}
	int __attribute__((noinline)) grow()//不内联进 udp_accept_cb
	{
		u32_t cap=slots?mask+1:0;
		u32_t new_cap=cap?cap*2:udp_table_min_cap;
		slot_t *n=(slot_t *)calloc(new_cap,sizeof(slot_t));
		if(n==0) return -1;
		u32_t new_mask=new_cap-1;
		for(u32_t i=0;i<cap;i++)
		{
			if(slots[i].pair==0) continue;
			u32_t j=slots[i].hash&new_mask;
			while(n[j].pair!=0) j=(j+1)&new_mask;
			n[j]=slots[i];
		}
		free(slots);
		slots=n;
		mask=new_mask;
		return 0;
	}
	void insert(udp_pair_t *pair,u32_t hash)//先 reserve_one() 成功，且表里没有这个地址
	{
		DEBUG_ASSERT(slots!=0&&(u32_t)(cnt+1)*4<=(mask+1)*3);
		u32_t i=hash&mask;
		while(slots[i].pair!=0) i=(i+1)&mask;
		slots[i].pair=pair;
		slots[i].hash=hash;
		cnt++;
	}
	void erase(udp_pair_t *pair,u32_t hash)
	{
		u32_t i=hash&mask;
		while(slots[i].pair!=pair)
		{
			if(slots[i].pair==0)
			{
				DEBUG_ASSERT(0==1);
				return;
			}
			i=(i+1)&mask;
		}
		//空出 i 后向后扫到空槽：j 处的项从它的起始位置探测到 j 时经过 i，就挪到 i，j 成为新的空位（Knuth 6.4 算法 R）
		for(u32_t j=(i+1)&mask;slots[j].pair!=0;j=(j+1)&mask)
		{
			if(((j-slots[j].hash)&mask)>=((j-i)&mask))
			{
				slots[i]=slots[j];
				i=j;
			}
		}
		slots[i].pair=0;
		cnt--;
	}
};

struct worker_t;
struct conn_manager_udp_t
{
	worker_t *worker;//所属 worker（M1）：erase 用它的 loop 停 watcher、把会话还回它的池
	std::atomic<int> *conns;//本规则在所有 worker 合计的会话数（M4，S7）：max_conn_num 按它判断，建会话时加、erase 时减
	udp_table_t sessions;
	udp_pair_t *last_hit;//上一次查到的会话：同一客户端连续来包时不算哈希、不查表；释放这个会话时清零

	long long last_clear_time;
	lru_collector_t lru;
	//list<udp_pair_t>::iterator clear_it;
	//O1 累计计数，SIGUSR1 时输出：total 新建的会话数；pkts/bytes 发送成功的包数与字节数，drop 发送失败（含 EAGAIN）丢掉的包数。[0] 客户端→上游，[1] 上游→客户端
	u64_t total;
	u64_t pkts[2],bytes[2],drop[2];
	//U5（D42、D45）：gro 以 GRO 合并包形式收到的数据报数，gso_fallback 某个会话在这个方向的 GSO 发送失败（EIO/EINVAL/EMSGSIZE）、改为逐包发送的次数
	u64_t gro[2],gso_fallback[2];
	std::atomic<int> *gso_logged;//U5：本规则这个方向的 GSO 回退已写过一行 info，之后的写 debug（审查 L3）；所有 worker 共用（rule_shared_t，M2），下标同 gro
	std::atomic<int> *pktinfo_logged;//D90：同 gso_logged，回程 pktinfo 的回退

	conn_manager_udp_t()
	{
		worker=0;
		conns=0;
		last_hit=0;
		last_clear_time=0;
		//clear_it=udp_pair_list.begin();
		total=0;
		memset(pkts,0,sizeof(pkts));
		memset(bytes,0,sizeof(bytes));
		memset(drop,0,sizeof(drop));
		memset(gro,0,sizeof(gro));
		memset(gso_fallback,0,sizeof(gso_fallback));
		gso_logged=0;
		pktinfo_logged=0;
	}
	//没找到时返回 0，hash 为 addr 的哈希，供随后的 insert 用；命中 last_hit 时不算哈希
	udp_pair_t *find(const address_t &addr,u32_t &hash)
	{
		if(last_hit!=0&&udp_key_eq(last_hit->adress,addr)) return last_hit;
		hash=udp_key_hash(addr);
		udp_pair_t *pair=sessions.find(addr,hash);
		if(pair!=0) last_hit=pair;
		return pair;
	}

	int erase(udp_pair_t *pair);//定义在 worker_t 之后

	int clear_inactive()
	{
		if(lru.clock->now()-last_clear_time>conn_clear_interval)
		{
			last_clear_time=lru.clock->now();
			return clear_inactive0();
		}
		return 0;
	}
	int clear_inactive0()
	{
		if(disable_conn_clear) return 0;

		int cnt=0;
		//list<tcp_pair_t>::iterator it=clear_it,old_it;
		int size=lru.size();
		int num_to_clean=size/conn_clear_ratio+conn_clear_min;   //clear 2% each time,to avoid latency glitch

		u64_t current_time=lru.clock->now();
		num_to_clean=min(num_to_clean,size);
		for(;;)
		{
			if(cnt>=num_to_clean) break;
			//if(tcp_pair_list.begin()==tcp_pair_list.end()) break;
			if(lru.empty()) break;
			lru_collector_t::key_t key;
			my_time_t ts=lru.peek_back(key);
			if(current_time- ts < conn_timeout_udp) break;

			erase( static_cast<udp_pair_t *>(key) );

			cnt++;
		}
		return 0;
	}
};

struct conn_manager_tcp_t
{
	worker_t *worker;//所属 worker（M1）：erase 用它的 loop 停 watcher、把缓冲、pipe 与连接对还回它的池
	std::atomic<int> *conns;//本规则在所有 worker 合计的连接对数（M4，S7）：max_conn_num 按它判断，建连时加、erase/erase_closed 时减
	long long last_clear_time;
	lru_collector_t lru;
	//O1 累计计数，SIGUSR1 时输出：total 建立的连接对数；bytes 发送成功的字节数，[0] 客户端→上游（从 local 读、发往 remote），[1] 上游→客户端；
	//splice_bytes 其中经 splice 从 pipe 写出的部分，splice_fallback 想 splice 但拿不到 pipe、改走 recv 的读次数（D49）
	u64_t total;
	u64_t bytes[2];
	u64_t splice_bytes[2];
	u64_t splice_fallback;
	conn_manager_tcp_t()
	{
		worker=0;
		conns=0;
		last_clear_time=0;
		total=0;
		memset(bytes,0,sizeof(bytes));
		memset(splice_bytes,0,sizeof(splice_bytes));
		splice_fallback=0;
	}
	int erase(tcp_pair_t *pair);//定义在 worker_t 之后
	int erase_closed(tcp_pair_t *pair);

	int clear_inactive()
	{
		if(lru.clock->now()-last_clear_time>conn_clear_interval)
		{
			last_clear_time=lru.clock->now();
			return clear_inactive0();
		}
		return 0;
	}
	int clear_inactive0()
	{

		if(disable_conn_clear) return 0;

		int cnt=0;
		//list<tcp_pair_t>::iterator it=clear_it,old_it;
		int size=lru.size();
		int num_to_clean=size/conn_clear_ratio+conn_clear_min;   //clear 2% each time,to avoid latency glitch

		u64_t current_time=lru.clock->now();
		num_to_clean=min(num_to_clean,size);
		for(;;)
		{
			if(cnt>=num_to_clean) break;
			//if(tcp_pair_list.begin()==tcp_pair_list.end()) break;
			if(lru.empty()) break;
			lru_collector_t::key_t key;
			my_time_t ts=lru.peek_back(key);
			if(current_time- ts < conn_timeout_tcp) break;

			erase( static_cast<tcp_pair_t *>(key) );

			cnt++;
		}
		//clear_it=it;

		return 0;
	}
};

//worker 的规则副本里的一个 remote（DNS 的刷新时间与查询状态在主线程的 dns_targets 里，M3）
struct remote_target_t
{
	address_t addr;
	int is_domain;
	char remote_str[max_remote_len];
	char host[max_domain_len];
	u32_t port;
	u32_t gen;//本 worker 收到的地址变化次数（worker_dns_update 加一）：连接对与会话建立时记下，不同即连在旧地址上
	my_time_t sweep_at;//旧地址上还留着可用的连接对或会话时，worker_tick 到这个时间再查一次（remote_sweep）；0 为没有
	my_time_t swept_at;//上一次 remote_sweep 的时间
	remote_target_t()
	{
		is_domain=0;
		remote_str[0]=0;
		host[0]=0;
		port=0;
		gen=0;
		sweep_at=0;
		swept_at=0;
	}
};

struct rule_shared_t;

struct forward_rule_t:not_copy_able_t
{
	int index;
	address_t local_addr;
	int enable_tcp;
	int enable_udp;
	vector<remote_target_t> remote_targets;
	balance_strategy_t balance_strategy;
	vector<int> balance_weights;
	rule_shared_t *shared;//本规则所有 worker 共用的状态，roundrobin 经它选 remote（D85）
	worker_t *worker;//所属 worker（M1）：本对象是这条规则在它那里的运行时，连接对与会话经 owner 找到它
	int local_listen_fd_tcp;
	int local_listen_fd_udp;
	int udp_pktinfo;//D87：UDP 监听在通配地址上且开了 PKTINFO（每个 worker 的监听分别设，udp_pktinfo_listen）：回包挂客户端发往的本地地址
	ev_io tcp_accept_watcher;
	ev_io udp_accept_watcher;
	conn_manager_tcp_t tcp_manager;
	conn_manager_udp_t udp_manager;
	forward_rule_t()
	{
		index=0;
		enable_tcp=0;
		enable_udp=0;
		balance_strategy=balance_strategy_off;
		shared=0;
		worker=0;
		local_listen_fd_tcp=-1;
		local_listen_fd_udp=-1;
		udp_pktinfo=0;
	}
};

//每条规则在所有 worker 之间共用的状态，主线程按规则分配，各 worker 的管理器存指针，relaxed：tcp/udp 是合计的连接数（M4，S7），
//只在建连/建会话与释放时访问；gso_logged 是每个方向的 GSO 回退是否已记过 info（U5 审查 L3，按规则而不是按 worker）；
//rr_next 是 roundrobin 的选择序号，rr_seq 是一个周期的选择序列（D85，见 rr_build_seq），启动 worker 之前算好，之后只读
struct rule_shared_t
{
	std::atomic<int> tcp,udp;
	std::atomic<unsigned> rr_next;
	std::atomic<int> gso_logged[2];
	std::atomic<int> pktinfo_logged;//D90：回程的 pktinfo 回退已写过一行 info
	vector<unsigned char> rr_seq;
	rule_shared_t():tcp(0),udp(0),rr_next(0),pktinfo_logged(0)
	{
		gso_logged[0].store(0);
		gso_logged[1].store(0);
	}
};
static rule_shared_t *rule_shared;//下标为规则序号 - 1，进程生命周期内不释放

//主线程发给 worker 的控制消息（M3，S4）：经 worker_post() 进 worker 的队列，worker 在自己 loop 上的 ctrl_watcher 回调里处理
enum worker_msg_type_t
{
	worker_msg_dns=1,//rule_index 的 remote remote_index 的地址换成 addr（S5）
	worker_msg_stats,//取统计快照回传主线程（D63）
	worker_msg_exit//退出 loop（M6）
};
struct worker_msg_t
{
	int type;
	int rule_index;
	int remote_index;
	address_t addr;
	worker_msg_t(int t)
	{
		type=t;
		rule_index=0;
		remote_index=0;
	}
};

//每个 worker 的全部可变状态（M1，D59、D60；M2 起每个 worker 一个线程，D62）：自己的 loop 与时间缓存、规则运行时（监听 fd 与 watcher、
//管理器与计数、remote 地址副本）、连接对象池、缓冲池与 scratch、pipe 池与 scratch pipe、UDP 批缓冲、定时器与控制消息队列。
//热路径经 forward_rule_t::worker（连接对与会话经 owner）取到它，不用 thread_local（mips24kc 上 TLS 指针是 rdhwr，可能由内核模拟，
//T11 审查 F10），也不用 ev_userdata（ev.c 里的非内联函数）。除 ctrl_mutex 保护的 ctrl_queue 外只有本 worker 的线程访问；
//主线程只在启动 worker 线程之前建它、之后只经 worker_post() 发消息
struct worker_t:not_copy_able_t
{
	int id;//从 0 起，统计行与线程名用
	struct ev_loop *loop;
	loop_clock_t clock;
	char *tcp_scratch;//recv 都读进这一块，读到的数据整块发完就留着给下一次 recv；没发完时整块交给该方向，下一次 recv 前再从池里取一块
	tcp_pipe_t tcp_pipe_scratch;//splice 都读进它，用法同 tcp_scratch（D47）
	tcp_buf_pool_t tcp_buf_pool;
	tcp_pipe_pool_t tcp_pipe_pool;
	obj_pool_t<tcp_pair_t> tcp_pair_pool;
	obj_pool_t<udp_pair_t> udp_pair_pool;
	list<forward_rule_t> rules;//各规则在本 worker 的运行时，按规则序号排列
	ev_prepare udp_flush_watcher;//每轮阻塞之前发出回程批（U4），有规则开 UDP 时才 start
	ev_timer tick_timer;//每 timer_interval 跑一次 worker_tick()（L7）
	ev_async ctrl_watcher;//主线程发来消息时唤醒（S4）
	//直接用 pthread 的锁（审查 I-5）：libstdc++ 的 std::mutex 在 _GLIBCXX_GTHREAD_USE_WEAK 为 1 的工具链上靠弱符号判断是否多线程。
	//OpenWRT SDK 的 GCC 5.4 与 Alpine 对 musl 都定义为 0，是真锁（D97）；为 1 的是 glibc<2.34，all 在那里动态链接（D95）
	pthread_mutex_t ctrl_mutex;
	std::deque<worker_msg_t> ctrl_queue;
	pthread_t thread;
	udp_batch_t udp_batch;
	//建 UDP 会话碰上临时端口用完（connect 返回 EAGAIN）或 fd 用完（EMFILE/ENFILE）：到下一个定时器周期（worker_tick 清零）之前不再建。
	//这两种失败与来源无关，下一个包注定同样失败；端口用完时每次 connect 都要扫完整个端口表（28232 个端口占满时约 1 ms，D80）
	int udp_new_blocked;
	worker_t(int i,struct ev_loop *l)
	{
		id=i;
		loop=l;
		clock.loop=l;
		tcp_scratch=0;
		tcp_pipe_scratch.r=tcp_pipe_scratch.w=-1;
		//清零等同 ev_init（同 T11 的 watcher），不用 ev_*_init 宏：不新增 strict-aliasing 告警；回调与参数由 event_loop() 设
		memset(&udp_flush_watcher,0,sizeof(udp_flush_watcher));
		memset(&tick_timer,0,sizeof(tick_timer));
		memset(&ctrl_watcher,0,sizeof(ctrl_watcher));
		memset(&thread,0,sizeof(thread));
		pthread_mutex_init(&ctrl_mutex,0);
		udp_new_blocked=0;
	}
};
//worker_t 很大（udp_batch 约 4.2 MiB）：在 mmap 的匿名页上就地构造，进程生命周期内不释放（myexit 直接 _exit）。页面清零、按需分配：
//udp_batch 的溢出区只有大包落到时才常驻；构造函数不写的字节（64 位 musl msghdr 的 __pad1/__pad2）恒为 0，udp_send_group 直接调
//syscall(SYS_sendmmsg) 依赖这一点（原来靠 BSS 清零）。new 不保证清零，memset 会让溢出区全部常驻。
//不用透明大页（M1 审查 L1）：THP=always 时，第一次写入整段落在映射内、按 2 MiB 对齐的区间就分配一个 2 MiB 大页，khugepaged
//也会把只有一页常驻的这种区间合并成大页（原来的 BSS 同样如此）；有的内核把这么大的匿名映射按 2 MiB 对齐，构造函数的写入就在启动时
//整页分配。溢出区于是不再按需常驻。没有 THP 的内核返回 EINVAL，不用管
static worker_t *worker_new(int id,struct ev_loop *loop)
{
	void *p=mmap(0,sizeof(worker_t),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(p==MAP_FAILED)
	{
		mylog(log_fatal,"mmap for a %d-byte worker failed, %s\n",(int)sizeof(worker_t),get_sock_error());
		myexit(1);
	}
	madvise(p,sizeof(worker_t),MADV_NOHUGEPAGE);
	return new(p) worker_t(id,loop);
}
//主线程的 worker 表：启动时建好，之后只用来给各 worker 发消息（S4）。worker 的热路径不碰它
static vector<worker_t *> workers;
//主线程给 worker 发一条控制消息：进队列后经 ev_async 唤醒它的 loop（libev 保证 ev_async_send 可从别的线程调用）
static void worker_post(worker_t &w,const worker_msg_t &m)
{
	pthread_mutex_lock(&w.ctrl_mutex);
	w.ctrl_queue.push_back(m);
	pthread_mutex_unlock(&w.ctrl_mutex);
	ev_async_send(w.loop,&w.ctrl_watcher);
}

int conn_manager_tcp_t::erase(tcp_pair_t *pair)
{
	//两侧都 stop 之后才能归还：watcher->data 直接指向本对象，ev_io_stop 同时清除本轮还没回调的事件，归还后不会再有它的回调。
	//close 后 fd 号、归还后对象都可能被本轮后面 accept 的连接复用，它的 watcher 经 ev_io_init（EV__IOFDSET）重新登记进 epoll（T10、T11），
	//fd_reify 对它直接 ADD，不受 libev 缓存的旧掩码影响（T13）
	struct ev_loop * loop= worker->loop;
	ev_io_stop(loop, &pair->local.ev);
	ev_io_stop(loop, &pair->remote.ev);

	close(pair->local.fd);
	close(pair->remote.fd);
	mylog(log_info,"[tcp]inactive connection {%s} cleared, tcp connections=%d\n",pair->addr.get_str(),lru.size()-1);
	mylog(log_debug,"[tcp] lru.size()=%d\n",(int)lru.size()-1);
	lru.erase(pair);
	if(pair->local.buf) worker->tcp_buf_pool.put(pair->local.buf);
	if(pair->remote.buf) worker->tcp_buf_pool.put(pair->remote.buf);
	if(pair->local.pipe.r>=0) worker->tcp_pipe_pool.discard(pair->local.pipe);//方向持有 pipe 时里面一定有数据
	if(pair->remote.pipe.r>=0) worker->tcp_pipe_pool.discard(pair->remote.pipe);
	worker->tcp_pair_pool.put(pair);
	conns->fetch_sub(1,memory_order_relaxed);
	return 0;
}
int conn_manager_tcp_t::erase_closed(tcp_pair_t *pair)//just a copy of erase()
{
	struct ev_loop * loop= worker->loop;
	ev_io_stop(loop, &pair->local.ev);
	ev_io_stop(loop, &pair->remote.ev);

	close(pair->local.fd);
	close(pair->remote.fd);
	mylog(log_info,"[tcp]closed connection {%s} cleared, tcp connections=%d\n",pair->addr.get_str(),lru.size()-1);
	mylog(log_debug,"[tcp] lru.size()=%d\n",(int)lru.size()-1);
	lru.erase(pair);
	if(pair->local.buf) worker->tcp_buf_pool.put(pair->local.buf);
	if(pair->remote.buf) worker->tcp_buf_pool.put(pair->remote.buf);
	if(pair->local.pipe.r>=0) worker->tcp_pipe_pool.discard(pair->local.pipe);//方向持有 pipe 时里面一定有数据
	if(pair->remote.pipe.r>=0) worker->tcp_pipe_pool.discard(pair->remote.pipe);
	worker->tcp_pair_pool.put(pair);
	conns->fetch_sub(1,memory_order_relaxed);
	return 0;
}
int conn_manager_udp_t::erase(udp_pair_t *pair)
{
	DEBUG_ASSERT(pair->batch_group<0);
	struct ev_loop * loop= worker->loop;
	ev_io_stop(loop, &pair->ev);

	mylog(log_info,"[udp]inactive connection {%s} cleared, udp connections=%d\n",pair->adress.get_str(),lru.size()-1);
	mylog(log_debug,"[udp] lru.size()=%d\n",(int)lru.size()-1);

	//归还后对象还留着旧地址：last_hit 不清零的话，这个客户端的下一个包会命中已归还的对象
	if(last_hit==pair) last_hit=0;
	sessions.erase(pair,udp_key_hash(pair->adress));

	close(pair->fd);
	lru.erase(pair);
	worker->udp_pair_pool.put(pair);
	conns->fetch_sub(1,memory_order_relaxed);

	return 0;
}
//fd 用完（accept4、上游 socket() 或 UDP 会话 socket() 返回 EMFILE/ENFILE）时关掉空闲 pipe 与 scratch pipe，给 socket 腾出 fd，
//并暂停创建到下一个定时器周期（D52）；返回关掉的个数，不为 0 时调用方再试一次。方向持有的 pipe 里有数据，不动
static int tcp_pipe_trim(worker_t &w)
{
	int n=w.tcp_pipe_pool.free_cnt+(w.tcp_pipe_scratch.r>=0);
	while(w.tcp_pipe_pool.free_cnt>0) w.tcp_pipe_pool.discard(w.tcp_pipe_pool.free_pipes[--w.tcp_pipe_pool.free_cnt]);
	if(w.tcp_pipe_scratch.r>=0) w.tcp_pipe_pool.discard(w.tcp_pipe_scratch);
	w.tcp_pipe_pool.blocked=1;
	w.tcp_pipe_pool.quota_hit=0;//fd 不够时池不放宽到 64（复审 R1）
	if(n>0) mylog(log_debug,"[tcp]out of file descriptors, closed %d idle pipes\n",n);
	return n;
}
struct dns_refresh_entry_t
{
	int rule_index;
	int remote_index;
	u32_t port;
	address_t current_addr;
};

//一个域名一个请求（D108）：引用它的各（规则，remote）一起查一次
struct dns_refresh_request_t
{
	char host[max_domain_len];
	std::vector<dns_refresh_entry_t> entries;
};

struct dns_refresh_result_t
{
	int rule_index;
	int remote_index;
	char host[max_domain_len];
	u32_t port;
	int ok;
	int current_still_valid;
	address_t next_addr;
	char err[dns_error_len];
};

static ev_async dns_async_watcher;
static std::mutex dns_mutex;
static std::condition_variable dns_cv;
static std::deque<dns_refresh_request_t> dns_requests;
static std::deque<dns_refresh_result_t> dns_results;
static struct ev_loop *dns_loop=0;
static int dns_worker_started=0;

//主线程的 DNS 主表（M3，S5）：每个域名 remote 一项。调度与查询结果都只在主线程处理，地址变化经 worker_post() 下发给各 worker 的规则副本
struct dns_target_t
{
	int rule_index;
	int remote_index;
	char host[max_domain_len];
	u32_t port;
	address_t addr;
	my_time_t last_dns_refresh_time;
	int dns_query_pending;
	int dns_stuck_warned;//这次查询已超过 2 个刷新周期没有返回、记过 warn（结果到达时清零）
};
static vector<dns_target_t> dns_targets;
static loop_clock_t main_clock;//主线程（默认 loop）自己的时间缓存：不能跨线程读 worker 的 loop（§6.5"时间"）

static void set_addr_port(address_t &addr,u32_t port)
{
	if(addr.get_type()==AF_INET) addr.inner.ipv4.sin_port=htons((u16_t)port);
	else if(addr.get_type()==AF_INET6) addr.inner.ipv6.sin6_port=htons((u16_t)port);
}

//DNS 线程（D108，最多 dns_thread_max 个）：一个请求查一次，按各项的端口与当前地址拆成各项的结果，一次加锁全部交给主线程
static void dns_worker_main()
{
	for(;;)
	{
		dns_refresh_request_t request;
		{
			std::unique_lock<std::mutex> lock(dns_mutex);
			while(dns_requests.empty())
			{
				dns_cv.wait(lock);
			}
			request=dns_requests.front();
			dns_requests.pop_front();
		}

		//解析结果带 entries[0] 的端口：各项的当前地址换成这个端口再找
		int n=(int)request.entries.size();
		u32_t port=request.entries[0].port;
		std::vector<address_t> find(n);
		std::vector<int> found(n);
		for(int k=0;k<n;k++)
		{
			find[k]=request.entries[k].current_addr;
			set_addr_port(find[k],port);
		}
		address_t addrs[dns_max_result];
		int addr_count=0;
		char err[dns_error_len];
		int ret=resolve_domain_addresses(request.host,port,addrs,dns_max_result,addr_count,err,sizeof(err),&find[0],&found[0],n);

		std::vector<dns_refresh_result_t> results(n);
		for(int k=0;k<n;k++)
		{
			const dns_refresh_entry_t &entry=request.entries[k];
			dns_refresh_result_t &result=results[k];
			memset(&result,0,sizeof(result));
			result.rule_index=entry.rule_index;
			result.remote_index=entry.remote_index;
			snprintf(result.host,sizeof(result.host),"%s",request.host);
			result.port=entry.port;
			if(ret==0)
			{
				address_t entry_addrs[dns_max_result];
				for(int i=0;i<addr_count;i++)
				{
					entry_addrs[i]=addrs[i];
					set_addr_port(entry_addrs[i],entry.port);
				}
				result.ok=1;
				result.next_addr=pick_remote_addr(entry_addrs,addr_count,found[k]?&entry.current_addr:0);
				result.current_still_valid=result.next_addr==entry.current_addr;
			}
			else
			{
				result.ok=0;
				result.current_still_valid=0;
				snprintf(result.err,sizeof(result.err),"%s",err);
			}
		}

		{
			std::lock_guard<std::mutex> lock(dns_mutex);
			dns_results.insert(dns_results.end(),results.begin(),results.end());
		}
		ev_async_send(dns_loop,&dns_async_watcher);
	}
}

//一条 DNS 结果（主线程）：更新主表，地址变了就让每个 worker 换自己规则副本里的地址（worker_dns_update）
static void dns_apply_result(dns_refresh_result_t &result)
{
	dns_target_t *t=0;
	for(size_t i=0;i<dns_targets.size();i++)
	{
		if(dns_targets[i].rule_index==result.rule_index&&dns_targets[i].remote_index==result.remote_index)
		{
			t=&dns_targets[i];
			break;
		}
	}
	if(t==0)
	{
		return;
	}
	if(strcmp(t->host,result.host)!=0||t->port!=result.port)
	{
		return;
	}
	t->dns_query_pending=0;
	if(t->dns_stuck_warned)
	{
		for(size_t j=0;j<dns_targets.size();j++)
			if(strcmp(dns_targets[j].host,t->host)==0) dns_targets[j].dns_stuck_warned=0;
		mylog(log_info,"domain %s: lookup returned after %d s\n",t->host,(int)((main_clock.now()-t->last_dns_refresh_time)/1000));
	}

	if(result.ok==0)
	{
		mylog(log_warn,"rule %d remote %d domain %s:%u resolve failed: %s, keeping current address\n",t->rule_index,t->remote_index,t->host,t->port,result.err);
		return;
	}
	if(result.current_still_valid)
	{
		return;
	}
	if(result.next_addr==t->addr)
	{
		return;
	}
	t->addr=result.next_addr;
	worker_msg_t m(worker_msg_dns);
	m.rule_index=t->rule_index;
	m.remote_index=t->remote_index;
	m.addr=result.next_addr;
	for(size_t i=0;i<workers.size();i++)
		worker_post(*workers[i],m);
}

//关掉 remote r 连在旧地址上（gen 不是当前的）、已不可用的连接对与会话：DNS 换地址只让新连接改连新地址，旧连接还能用就留着。
//TCP 看上游 socket 的 TCP_INFO：连续超时重传或零窗口探测没有应答达到 tcp_unans_probes 次（收到推进 snd_una 的 ACK 时重传数清零，
//收到任何 ACK 时探测数清零；没有路由、待发数据发不出去时也走零窗口探测的定时器，计入探测数），或 getsockopt 失败；
//UDP 看 unans：客户端的包等了 udp_unans_timeout 还没有回包。
//TCP 连接对上次查到没有在途数据（sweep_idle）、之后也没有收发的不再 getsockopt：内核没有可重传的东西，不会由可用变为不可用。
//ts 最多比实际最后活动早 lru_move_interval，所以 ts+lru_move_interval 不晚于上一次检查才算没有收发。子集应答的域名地址一直在变，
//旧地址上的连接一直都有，不跳过的话每次都要逐条 getsockopt（20k 条 40–107 ms，D94）。
//沿 LRU 遍历（先取下一个，再释放当前的）；closed、kept 的 [0] 为 TCP、[1] 为 UDP，kept 只数旧地址上还可用的。
//还有留下的就在 dns_refresh_interval 后由 worker_tick 再查一次
static void remote_sweep(forward_rule_t &rule,int r,int closed[2],int kept[2])
{
	remote_target_t &target=rule.remote_targets[r];
	my_time_t now=rule.worker->clock.now();
	closed[0]=closed[1]=kept[0]=kept[1]=0;
	conn_manager_tcp_t &tcp=rule.tcp_manager;
	for(lru_node_t *node=tcp.lru.head.next;node!=&tcp.lru.head;)
	{
		tcp_pair_t *pair=static_cast<tcp_pair_t *>(node);
		node=node->next;
		if(pair->remote_index!=r||pair->gen==target.gen) continue;
		if(pair->sweep_idle&&pair->ts+lru_move_interval<=target.swept_at)
		{
			kept[0]++;
			continue;
		}
		struct tcp_info info;
		socklen_t len=sizeof(info);
		if(getsockopt(pair->remote.fd,IPPROTO_TCP,TCP_INFO,&info,&len)==0&&info.tcpi_retransmits<tcp_unans_probes&&info.tcpi_probes<tcp_unans_probes)
		{
			pair->sweep_idle=info.tcpi_unacked==0&&info.tcpi_backoff==0&&info.tcpi_retransmits==0&&info.tcpi_probes==0;
			kept[0]++;
			continue;
		}
		tcp.erase_closed(pair);
		closed[0]++;
	}
	conn_manager_udp_t &udp=rule.udp_manager;
	for(lru_node_t *node=udp.lru.head.next;node!=&udp.lru.head;)
	{
		udp_pair_t *pair=static_cast<udp_pair_t *>(node);
		node=node->next;
		if(pair->remote_index!=r||pair->gen==target.gen) continue;
		if(pair->unans==0||now-pair->unans<udp_unans_timeout)
		{
			kept[1]++;
			continue;
		}
		udp.erase(pair);
		closed[1]++;
	}
	target.swept_at=now;
	target.sweep_at=kept[0]+kept[1]>0?now+dns_refresh_interval:0;
}

//worker 收到 DNS 更新（S5）：换自己规则副本里的地址，新连接从此连新地址；本 worker 里连在旧地址上的只关掉已不可用的（remote_sweep），
//记一行（N 个 worker 各一行）
static void worker_dns_update(worker_t &w,const worker_msg_t &m)
{
	for(auto rule_it=w.rules.begin();rule_it!=w.rules.end();++rule_it)
	{
		if(rule_it->index!=m.rule_index)
		{
			continue;
		}
		forward_rule_t &rule=*rule_it;
		remote_target_t &target=rule.remote_targets[m.remote_index];
		address_t next_addr=m.addr;
		char old_addr[max_addr_len];
		char new_addr[max_addr_len];
		target.addr.to_str(old_addr);
		next_addr.to_str(new_addr);
		target.addr=next_addr;
		target.gen++;
		int closed[2],kept[2];
		remote_sweep(rule,m.remote_index,closed,kept);
		mylog(log_info,"rule %d remote %d domain %s:%u changed from %s to %s, closed unresponsive tcp=%d udp=%d, kept tcp=%d udp=%d\n",rule.index,m.remote_index,target.host,target.port,old_addr,new_addr,closed[0],closed[1],kept[0],kept[1]);
		return;
	}
}

static void dns_result_cb(struct ev_loop *loop, struct ev_async *watcher, int revents)
{
	std::deque<dns_refresh_result_t> results;
	{
		std::lock_guard<std::mutex> lock(dns_mutex);
		results.swap(dns_results);
	}

	for(auto it=results.begin();it!=results.end();++it)
	{
		dns_apply_result(*it);
	}
}

static void start_dns_worker(struct ev_loop *loop)
{
	if(dns_worker_started)
	{
		return;
	}
	if(dns_targets.empty())
	{
		return;
	}
	dns_loop=loop;
	ev_async_init(&dns_async_watcher,dns_result_cb);
	ev_async_start(loop,&dns_async_watcher);
	dns_worker_started=1;
	//每个域名同时最多一个请求在途（schedule_dns_refresh），线程比域名多也用不上：一个域名的查询卡住只占一个线程
	int hosts=0;
	for(size_t i=0;i<dns_targets.size();i++)
	{
		size_t j=0;
		while(j<i&&strcmp(dns_targets[j].host,dns_targets[i].host)!=0) j++;
		if(j==i) hosts++;
	}
	int n=hosts<dns_thread_max?hosts:dns_thread_max;
	for(int k=0;k<n;k++)
	{
		try
		{
			std::thread(dns_worker_main).detach();
		}
		catch(const std::system_error &e)//建不出线程（RLIMIT_NPROC、cgroup pids.max、内存）：与 worker 线程一样记 fatal 退出，不走 terminate/abort（D106）
		{
			mylog(log_fatal,"create DNS thread failed, %d:%s\n",e.code().value(),e.code().message().c_str());
			myexit(-1);
		}
	}
}

//同一域名的各项合并为一个请求（D108）：一起入队、结果一起回来，此后一直同步
static void schedule_dns_refresh()
{
	my_time_t now=main_clock.now();
	for(size_t i=0;i<dns_targets.size();i++)
	{
		dns_target_t &target=dns_targets[i];
		if(target.dns_query_pending)
		{
			//同一域名的各项同步：每个域名每次卡住只记一行
			if(!target.dns_stuck_warned&&now-target.last_dns_refresh_time>=2*dns_refresh_interval)
			{
				for(size_t j=0;j<dns_targets.size();j++)
					if(strcmp(dns_targets[j].host,target.host)==0) dns_targets[j].dns_stuck_warned=1;
				mylog(log_warn,"domain %s: no lookup result for %d s, keeping current address\n",target.host,(int)((now-target.last_dns_refresh_time)/1000));
			}
			continue;
		}
		if(now-target.last_dns_refresh_time<dns_refresh_interval)
		{
			continue;
		}
		dns_refresh_request_t request;
		snprintf(request.host,sizeof(request.host),"%s",target.host);
		for(size_t j=0;j<dns_targets.size();j++)
		{
			dns_target_t &t=dns_targets[j];
			if(t.dns_query_pending||strcmp(t.host,target.host)!=0)
			{
				continue;
			}
			dns_refresh_entry_t entry;
			entry.rule_index=t.rule_index;
			entry.remote_index=t.remote_index;
			entry.port=t.port;
			entry.current_addr=t.addr;
			request.entries.push_back(entry);
			t.dns_query_pending=1;
			t.last_dns_refresh_time=now;
		}
		{
			std::lock_guard<std::mutex> lock(dns_mutex);
			dns_requests.push_back(request);
		}
		dns_cv.notify_one();
	}
}

static int select_remote_index(forward_rule_t &rule, const address_t &client_addr)
{
	int remote_count=(int)rule.remote_targets.size();
	DEBUG_ASSERT(remote_count>0);
	if(remote_count==1||rule.balance_strategy==balance_strategy_off)
	{
		return 0;
	}
	DEBUG_ASSERT((int)rule.balance_weights.size()==remote_count);

	if(rule.balance_strategy==balance_strategy_roundrobin)
	{
		//所有 worker 共用一条序列（D85）：本规则第 k 次选择（TCP 与 UDP 合计，按到达序号的先后）与 threads=1 的第 k 次相同。
		//序号在 2^32 处回绕，周期不整除 2^32 时那一步相位不连续，约 43 亿次新建一次
		const vector<unsigned char> &seq=rule.shared->rr_seq;
		DEBUG_ASSERT(!seq.empty());
		unsigned k=rule.shared->rr_next.fetch_add(1,memory_order_relaxed);
		int best=seq[k%seq.size()];
		DEBUG_ASSERT(best<remote_count);
		return best;
	}

	if(rule.balance_strategy==balance_strategy_iphash)
	{
		const sockaddr *sa=(const sockaddr*)&client_addr.inner;
		const unsigned char *hash_data=0;
		int hash_len=0;
		if(sa->sa_family==AF_INET)
		{
			hash_data=(const unsigned char*)&client_addr.inner.ipv4.sin_addr;
			hash_len=sizeof(client_addr.inner.ipv4.sin_addr);
		}
		else if(sa->sa_family==AF_INET6)
		{
			hash_data=(const unsigned char*)&client_addr.inner.ipv6.sin6_addr;
			hash_len=sizeof(client_addr.inner.ipv6.sin6_addr);
		}
		else
		{
			DEBUG_ASSERT(0==1);
		}
		u32_t hash=sdbm((unsigned char*)hash_data,hash_len);
		int total=0;
		for(int i=0;i<remote_count;i++)
		{
			DEBUG_ASSERT(rule.balance_weights[i]>0);
			total+=rule.balance_weights[i];
		}
		DEBUG_ASSERT(total>0);
		int bucket=(int)(hash%(u32_t)total);
		int cursor=0;
		for(int i=0;i<remote_count;i++)
		{
			cursor+=rule.balance_weights[i];
			if(bucket<cursor)
			{
				return i;
			}
		}
		DEBUG_ASSERT(0==1);
		return 0;
	}

	DEBUG_ASSERT(0==1);
	return 0;
}

//每次 send 之前调用，info 是接收这次 send 的一侧（T15）：上游的 TCP_NODELAY 推迟到第二次 send 之前才设。
//Nagle（Linux 用 Minshall 变体）只扣"前面还有没确认的小段"时的小段，第一次 send 的那一小段不会被扣；
//只往上游写一次的短连接（CRR、小的 RPC 请求）省一次 setsockopt。客户端一侧的 nodelay_wait 总是 0
static inline void nodelay_before_send(tcp_info_t &info,int len)
{
	if(info.nodelay_wait==0) return;
	if(info.nodelay_wait==1&&len<=nodelay_first_max)
	{
		info.nodelay_wait=2;
		return;
	}
	int yes=1;
	setsockopt(info.fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	info.nodelay_wait=0;
}

//首轮 splice 读返回 EPERM/EINVAL/EOPNOTSUPP 时，区分 splice 本身不可用与这条连接被 splice 取走的待决错误（D110）：没开 IP_RECVERR 时
//ICMP 错误和重传时的路由错误先记在 sk_err_soft，超时放弃才进 sk_err，可能正是这几个值（IPv4 源路由失败 EOPNOTSUPP、黑洞路由 EINVAL、IPsec block EPERM；
//没有映射到 ENOSYS 的，它不经这里）。sk_err 只随 tcp_done 写入，之后状态是 CLOSE；能 splice 时报错说明一个字节都没读到：接收队列为空，
//或队首是紧急字节（FIONREAD 也是 0）。两条都满足才算连接的错误，这时即使其实是 splice 不可用，关掉这一对也对（连接已断，或两个方向都已 EOF；
//紧急字节之后的数据能 splice 时同样读不到）。换页失败等读不到又有数据的少见情况 FIONREAD 大于 0，仍按不可用处理。不改 errno
static int tcp_splice_err_is_sock(int fd)
{
	int saved=errno;
	struct tcp_info info;
	socklen_t len=sizeof(info);
	int inq=-1;
	int ret=getsockopt(fd,IPPROTO_TCP,TCP_INFO,&info,&len)==0&&info.tcpi_state==TCP_CLOSE&&ioctl(fd,FIONREAD,&inq)==0&&inq==0;
	errno=saved;
	return ret;
}

//同一 fd 上切换事件一律 stop → 改 events → start，不经 ev_io_init：EV__IOFDSET 表示新 fd，libev fd_reify 的本地补丁
//对它直接 ADD，fd 仍在 epoll 中时就成了 ADD（EEXIST）再 MOD（T13）
void tcp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	//mylog(log_info,"[tcp]tcp_cb called \n");
	tcp_pair_t &tcp_pair=*(tcp_pair_t *)watcher->data;
	DEBUG_ASSERT(tcp_pair.owner!=0);
	conn_manager_tcp_t &conn_manager_tcp=tcp_pair.owner->tcp_manager;
	worker_t &w=*tcp_pair.owner->worker;

	//epoll_ctl 失败（如 ADD 超过 fs.epoll.max_user_watches 的 ENOSPC、ENOMEM）：libev 的 fd_kill 已停掉这个 watcher，只释放这一对（C9）。
	//两侧都失败时，另一侧还没回调的 EV_ERROR 由 erase_closed 里的 ev_io_stop 清除
	if((revents&EV_ERROR) !=0)
	{
		mylog(log_warn,"[tcp]connection {%s} closed bc of EV_ERROR (epoll_ctl failed),fd=%d\n",tcp_pair.addr.get_str(),watcher->fd);
		conn_manager_tcp.erase_closed(&tcp_pair);
		return;
	}
	if((revents&(EV_READ|EV_WRITE))==0)
	{
		mylog(log_fatal,"[tcp]got unexpected event,events[idx].events=%x\n",(u32_t)revents);
		myexit(-1);
	}

	tcp_info_t *my_info_p,*other_info_p;
	if(watcher==&tcp_pair.local.ev)
	{
		mylog(log_trace,"[tcp]watcher==&tcp_pair.local.ev\n");
		my_info_p=&tcp_pair.local;
		other_info_p=&tcp_pair.remote;
	}
	else
	{
		DEBUG_ASSERT(watcher==&tcp_pair.remote.ev);
		mylog(log_trace,"[tcp]watcher==&tcp_pair.remote.ev\n");
		my_info_p=&tcp_pair.remote;
		other_info_p=&tcp_pair.local;
	}
	tcp_info_t &my_info=*my_info_p;
	tcp_info_t &other_info=*other_info_p;

	int my_fd=my_info.fd;
	int other_fd=other_info.fd;

	DEBUG_ASSERT(watcher->fd==my_fd);

	//zdmylog(log_info,"[tcp]my_fd=%d,other_fd=%d \n",my_fd,other_fd);

	//上游建连中（CONNECTING）：watcher 同时等读写。建连失败时 EPOLLERR/EPOLLHUP 被 libev 报成读写同时就绪，
	//只报可写就是连上了；报了可读（失败，或连上后已有数据、FIN、RST）才用 SO_ERROR 区分
	if(!my_info.connected)
	{
		if( (revents & EV_READ) !=0 )
		{
			int err=0;
			socklen_t err_len=sizeof(err);
			if(getsockopt(my_fd,SOL_SOCKET,SO_ERROR,&err,&err_len)!=0) err=errno;
			if(err!=0)
			{
				mylog(log_warn,"[tcp]connect to remote {%s} failed,connection {%s} closed bc of %d:%s\n",tcp_pair.owner->remote_targets[tcp_pair.remote_index].remote_str,tcp_pair.addr.get_str(),err,strerror(err));
				conn_manager_tcp.erase_closed(&tcp_pair);
				return;
			}
		}
		my_info.connected=1;
		//OPEN：建连期间客户端读到的数据由写分支发出，EOF 由下面推迟的 shutdown 发出；都没有就不再等可写
		if(other_info.data_len==0&&!other_info.eof)
		{
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_WRITE;
			ev_io_start(loop, &my_info.ev);
			revents&=~EV_WRITE;
			if( (revents & EV_READ) ==0) return;
		}
		else if(other_info.data_len!=0&&(revents & EV_WRITE)!=0)
		{
			//先发留下的数据、本轮不读：C7 实测这样后端只多写暂停时没写完的那一块。可读是水平触发，下一轮还会报
			revents&=~EV_READ;
		}
	}

	//推迟的 shutdown：上游建连期间客户端已 EOF，连上后从上面落到这里；建连之后只有它会在没有待发数据时挂 EV_WRITE。放在读写分支之前：写分支只处理有待发数据的情况
	if( (revents & EV_WRITE) !=0 && (my_info.ev.events&EV_WRITE) !=0 && other_info.data_len==0 )
	{
		DEBUG_ASSERT(other_info.eof);
		ev_io_stop(loop, &my_info.ev);
		my_info.ev.events&=~EV_WRITE;
		ev_io_start(loop, &my_info.ev);
		if(shutdown(my_fd,SHUT_WR)!=0)
		{
			mylog(log_info,"[tcp]shutdown failed,connection {%s} closed bc of %s\n",tcp_pair.addr.get_str(),get_sock_error());
			conn_manager_tcp.erase_closed(&tcp_pair);
			return;
		}
		revents&=~EV_WRITE;
		if( (revents & EV_READ) ==0) return;
	}

	if( (revents & EV_READ) !=0  )
	{
		mylog(log_trace,"[tcp]events[idx].events & EPOLLIN !=0 \n");
		if((my_info.ev.events&EV_READ) ==0)
		{
			mylog(log_debug,"[tcp]out of date event, my_info.ev.events&EPOLLIN) ==0 \n");
			return;
		}
		DEBUG_ASSERT(my_info.data_len==0&&my_info.buf==0&&my_info.pipe.r<0);
		int dir=(my_info_p==&tcp_pair.remote);//本方向在计数里的下标
		int recv_len=-1;
		int spliced=0;
		//B2：本方向上一次读够大（D46）就 splice 进 scratch pipe，再从 pipe 写出，不经用户态；拿不到 pipe 时这次照常 recv（D47）。
		//上游建连中不写出，只走 recv
		if(my_info.splice_next&&other_info.connected&&!disable_splice.load(memory_order_relaxed))
		{
			if(w.tcp_pipe_scratch.r<0&&w.tcp_pipe_pool.get(w.tcp_pipe_scratch)!=0)
			{
				conn_manager_tcp.splice_fallback++;
			}
			else
			{
				DEBUG_ASSERT(tcp_pipe_len(w.tcp_pipe_scratch)==0);
				recv_len=splice(my_fd,0,w.tcp_pipe_scratch.w,0,tcp_pipe_size,SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
				spliced=1;
				//队首是紧急数据（对端 MSG_OOB）时非阻塞 splice 返回 EAGAIN，epoll 却一直报可读，这一次改用 recv：
				//它跳过紧急字节（没有 SO_OOBINLINE），与拷贝路径一致。别的原因（如页分配失败）同样交给 recv
				if(recv_len<0&&errno==EAGAIN) spliced=0;
				else if(recv_len<0&&(errno==ENOSYS||((errno==EPERM||errno==EINVAL||errno==EOPNOTSUPP)&&!tcp_splice_err_is_sock(my_fd))))
				{
					//splice 本身不可用（如 seccomp 白名单里没有它）：什么都没读，整个进程改走拷贝（审查 L1）。
					//这条连接的待决错误不算（D110）：落到下面按读出错关闭（这时再 recv 只会读到 0）
					mylog(log_warn,"[tcp]splice failed (%s), forwarding all TCP by copy from now on\n",get_sock_error());
					disable_splice.store(1,memory_order_relaxed);
					spliced=0;
				}
			}
		}
		if(!spliced)
		{
			if(w.tcp_scratch==0)
			{
				w.tcp_scratch=w.tcp_buf_pool.get();
				if(w.tcp_scratch==0)
				{
					mylog(log_warn,"[tcp]connection {%s} closed bc of malloc for a %d-byte buffer failed\n",tcp_pair.addr.get_str(),max_data_len_tcp);
					conn_manager_tcp.erase_closed(&tcp_pair);
					return;
				}
			}
			recv_len=recv(my_fd,w.tcp_scratch,max_data_len_tcp,0);
		}
		mylog(log_trace,"fd=%d,recv_len=%d\n",my_fd,recv_len);
		if(recv_len==0)
		{
			if(my_info.err!=0)
			{
				//读分支往本侧写出时出错，sk_err 已被那次写出取走，这里读到 0 不是对端的 FIN（D111）：按那个错误关闭，不向另一侧转发半关闭
				errno=my_info.err;
				mylog(log_info,"[tcp]send_len=-1,connection {%s} closed bc of %s\n",tcp_pair.addr.get_str(),get_sock_error());
				conn_manager_tcp.erase_closed(&tcp_pair);
				return;
			}
			if(other_info.eof)
			{
				mylog(log_info,"[tcp]recv_len=%d,connection {%s} closed bc of EOF\n",recv_len,tcp_pair.addr.get_str());
				conn_manager_tcp.erase_closed(&tcp_pair);
				return;
			}
			//半关闭：只有缓冲为空时才 recv，所以本方向没有待发数据，直接把 EOF 转给另一侧；反方向照常转发
			conn_manager_tcp.lru.update(&tcp_pair);
			my_info.eof=1;
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_READ;
			ev_io_start(loop, &my_info.ev);
			if(other_info.connected)
			{
				mylog(log_debug,"[tcp]connection {%s} half-closed by fd=%d\n",tcp_pair.addr.get_str(),my_fd);
				if(shutdown(other_fd,SHUT_WR)!=0)
				{
					mylog(log_info,"[tcp]shutdown failed,connection {%s} closed bc of %s\n",tcp_pair.addr.get_str(),get_sock_error());
					conn_manager_tcp.erase_closed(&tcp_pair);
				}
			}
			else
			{
				//上游还在建连：此时 shutdown 会中止 connect。它本来就在等可写，连上后再发
				mylog(log_debug,"[tcp]connection {%s} half-closed by fd=%d,shutdown deferred until connected\n",tcp_pair.addr.get_str(),my_fd);
			}
			return;
		}
		if(recv_len<0)
		{
			mylog(log_info,"[tcp]recv_len=%d,connection {%s} closed bc of %s,fd=%d\n",recv_len,tcp_pair.addr.get_str(),get_sock_error(),my_fd);
			conn_manager_tcp.erase_closed(&tcp_pair);
			return;
		}
		conn_manager_tcp.lru.update(&tcp_pair);
		//tcp_pair.last_active_time=get_current_time();

		my_info.splice_next=(recv_len>=splice_read_min);
		my_info.data_len=recv_len;

		//上游建连中不发：它本来就在等可写，数据留在缓冲里、停读本侧，连上后由写分支发出
		int send_len=0;
		if(spliced)
		{
			DEBUG_ASSERT((other_info.ev.events & EV_WRITE)==0);
			for(int moved=recv_len;;moved+=recv_len)//moved：本回调读进 pipe 的字节
			{
				nodelay_before_send(other_info,my_info.data_len);
				send_len=splice(w.tcp_pipe_scratch.r,0,other_fd,0,my_info.data_len,SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
				if(send_len>0)
				{
					my_info.data_len-=send_len;
					conn_manager_tcp.bytes[dir]+=send_len;
					conn_manager_tcp.splice_bytes[dir]+=send_len;
				}
				else if(send_len<0&&errno!=EAGAIN) other_info.err=errno;//D111，同 send
				if(my_info.data_len!=0)
				{
					//没写完（含 EAGAIN；出错时记在 other_info.err，同 send）：scratch pipe 连同数据交给本方向，下一次 splice 前再从池里取一个
					my_info.pipe=w.tcp_pipe_scratch;
					w.tcp_pipe_scratch.r=w.tcp_pipe_scratch.w=-1;
					tcp_unshrink_sndbuf(other_info);
					break;
				}
				//写完了：源端这次读够 splice_more_min 就接着搬，直到本回调搬满 splice_turn_max（D53、D55）
				if(moved>=splice_turn_max||recv_len<splice_more_min) break;
				recv_len=splice(my_fd,0,w.tcp_pipe_scratch.w,0,min(tcp_pipe_size,splice_turn_max-moved),SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
				if(recv_len<=0)
				{
					//EOF 与 EAGAIN（含紧急数据）留给下一次回调按第一轮处理：EOF 一直可读，下一次 splice 仍读到 0。
					//出错必须现在关：splice 已经取走 sk_err，下一次只会读到 0，RST 会被当成正常的 EOF
					if(recv_len<0&&errno!=EAGAIN)
					{
						mylog(log_info,"[tcp]recv_len=%d,connection {%s} closed bc of %s,fd=%d\n",recv_len,tcp_pair.addr.get_str(),get_sock_error(),my_fd);
						conn_manager_tcp.erase_closed(&tcp_pair);
						return;
					}
					break;
				}
				my_info.splice_next=(recv_len>=splice_read_min);
				my_info.data_len=recv_len;
			}
		}
		else
		{
			my_info.begin=w.tcp_scratch;
			if(other_info.connected)
			{
				DEBUG_ASSERT((other_info.ev.events & EV_WRITE)==0);
				nodelay_before_send(other_info,my_info.data_len);
				send_len=send(other_fd,my_info.begin,my_info.data_len,0);
			}
			if(send_len>0)
			{
				my_info.data_len-=send_len;
				my_info.begin+=send_len;
				conn_manager_tcp.bytes[dir]+=send_len;
			}
			else if(send_len<0&&errno!=EAGAIN)
			{
				//出错（RST、超时）时这次 send 已取走目的端的 sk_err：记下来，仍按没发完处理，由目的端的回调关闭（D111）。不在这里关：目的端可读时
				//它的回调先读一轮（一次 recv 或 D53 的几轮 splice），把 RST 之前到达的数据（如后端拒绝上传时先回的响应）转发出去，同一回调的写分支再关闭，与写出时就失败的情况相同
				other_info.err=errno;
			}
			if(my_info.data_len!=0)
			{
				//没发完（含上游还在建连、出错）：剩下的数据连同 scratch 整块留给本方向，不拷贝（D17）；下一次 recv 前再从池里取一块
				my_info.buf=w.tcp_scratch;
				w.tcp_scratch=0;
			}
		}

		if(my_info.data_len!=0)
		{

			//epoll_event ev;

			//ev=other_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, other_fd, &ev);
			//assert(ret==0);
			if(other_info.connected)
			{
				ev_io_stop(loop, &other_info.ev);
				other_info.ev.events|=EV_WRITE;
				ev_io_start(loop, &other_info.ev);
			}


			//ev=my_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, my_fd, &ev);
			//assert(ret==0);
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_READ;
			ev_io_start(loop, &my_info.ev);

		}

	}
	//读完接着写（审查 #2，D86）：同一 fd 又可读又有待写数据时两边都处理。只走读分支的话，另一方向持有的数据要等这一侧某一轮不可读才发得出去，
	//那个方向的源端也一直停读。读分支提前返回的路径（半关闭、过时事件）上本侧已不再等读，下一轮只报写，最多推迟一轮
	if( (revents & EV_WRITE) !=0)
	{
		mylog(log_trace,"[tcp]events[idx].events & EPOLLOUT !=0\n");

		if( (my_info.ev.events&EV_WRITE) ==0)
		{
			mylog(log_debug,"[tcp]out of date event, my_info.ev.events&EPOLLOUT) ==0 \n");
			return;
		}

		DEBUG_ASSERT(other_info.data_len!=0&&(other_info.buf!=0)!=(other_info.pipe.r>=0));
		if(my_info.err!=0)
		{
			//读分支往本侧写出时已出错（D111）：sk_err 已被取走，再写只会得到 EPIPE，按记下的错误关闭
			errno=my_info.err;
			mylog(log_info,"[tcp]send_len=-1,connection {%s} closed bc of %s\n",tcp_pair.addr.get_str(),get_sock_error());
			conn_manager_tcp.erase_closed(&tcp_pair);
			return;
		}
		int dir=(other_info_p==&tcp_pair.remote);
		nodelay_before_send(my_info,other_info.data_len);
		int send_len;
		if(other_info.pipe.r>=0)
			send_len=splice(other_info.pipe.r,0,my_fd,0,other_info.data_len,SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
		else
			send_len=send(my_fd,other_info.begin,other_info.data_len,0);
		if(send_len==0)
		{
			mylog(log_warn,"[tcp]send_len=%d,connection {%s} closed bc of send_len==0\n",send_len,tcp_pair.addr.get_str());
			conn_manager_tcp.erase_closed(&tcp_pair);
			return;
		}
		if(send_len<0)
		{
			//EPOLLOUT 只看本 socket 的剩余空间：主机越过 tcp_mem[2]（或 memcg 记账失败）时，队列接近空的 socket 发送仍返回 EAGAIN，
			//当作没写出、继续等可写（D50）；越限期间这样的 socket 每轮重试一次
			if(errno==EAGAIN)
			{
				//越限期间这样的 socket 每轮重试，第一次记 info 便于从日志对上 CPU 占用，之后 debug；各 worker 共用（M2）
				static std::atomic<int> logged(0);
				int level=logged.exchange(1,memory_order_relaxed)?log_debug:log_info;
				mylog(level,"[tcp]send to fd=%d returned EAGAIN although writable (TCP memory above net.ipv4.tcp_mem or a cgroup limit?), retrying\n",my_fd);
				return;
			}
			mylog(log_info,"[tcp]send_len=%d,connection {%s} closed bc of %s\n",send_len,tcp_pair.addr.get_str(),get_sock_error());
			conn_manager_tcp.erase_closed(&tcp_pair);
			return;
		}
		conn_manager_tcp.lru.update(&tcp_pair);

		//tcp_pair.last_active_time=get_current_time();

		mylog(log_trace,"[tcp]fd=%d send len=%d\n",my_fd,send_len);
		other_info.data_len-=send_len;
		conn_manager_tcp.bytes[dir]+=send_len;
		if(other_info.pipe.r>=0) conn_manager_tcp.splice_bytes[dir]+=send_len;
		else other_info.begin+=send_len;
		if(other_info.pipe.r>=0&&other_info.data_len!=0) tcp_unshrink_sndbuf(my_info);

		if(other_info.data_len==0)
		{
			if(other_info.pipe.r>=0)
			{
				w.tcp_pipe_pool.put(other_info.pipe);
			}
			else
			{
				w.tcp_buf_pool.put(other_info.buf);
				other_info.buf=0;
			}

			//ev=my_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, my_fd, &ev);
			//assert(ret==0);
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_WRITE;
			ev_io_start(loop, &my_info.ev);

			DEBUG_ASSERT((other_info.ev.events & EV_READ)==0);



			//ev=other_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, other_fd, &ev);
			//assert(ret==0);
			ev_io_stop(loop, &other_info.ev);
			other_info.ev.events|=EV_READ;
			ev_io_start(loop, &other_info.ev);
		}
		else
		{
			//keep waitting for EPOLLOUT;
		}
	}
}
//接受一个连接；返回 0 表示本轮到此为止（backlog 已空、accept 失败，或上游 connect 立即失败）
static int tcp_accept_one(struct ev_loop *loop, struct ev_io *watcher)
{
	forward_rule_t *rule=(forward_rule_t *)watcher->data;
	DEBUG_ASSERT(rule!=0);
	conn_manager_tcp_t &conn_manager_tcp=rule->tcp_manager;
	worker_t &w=*rule->worker;
	int ret;
	int local_listen_fd_tcp=watcher->fd;
	/*if((events[idx].events & EPOLLERR) !=0 ||(events[idx].events & EPOLLHUP) !=0)
	{
		mylog(log_error,"[tcp]EPOLLERR or EPOLLHUP from listen_fd events[idx].events=%x \n",events[idx].events);
		//if there is an error, we will eventually get it at accept()
	}*/

	socklen_t tmp_len = sizeof(address_t::storage_t);
	address_t::storage_t tmp_sockaddr_in={0};
	memset(&tmp_sockaddr_in,0,sizeof(tmp_sockaddr_in));

	//Linux 上 accept 得到的 socket 不继承监听 socket 的 O_NONBLOCK，用 accept4 一次设好，省掉两次 fcntl
	int new_fd=accept4(local_listen_fd_tcp, (struct sockaddr*) &tmp_sockaddr_in,&tmp_len,SOCK_NONBLOCK|SOCK_CLOEXEC);
	if(new_fd<0)
	{
		int err=errno;
		if(err==EAGAIN||err==EWOULDBLOCK) return 0;//backlog 已取空，是一轮的正常结束，不记日志
		mylog(log_warn,"[tcp]accept failed %d %s\n", new_fd,get_sock_error());
		//fd 用完时先关掉空闲 pipe，关掉了就接着 accept（客户端还在 backlog 里），否则按 C6 停到下一个周期（D52）
		if((err==EMFILE||err==ENFILE)&&tcp_pipe_trim(w)>0) return 1;
		if(err!=EINTR&&err!=ECONNABORTED)
		{
			//EMFILE/ENFILE/ENOMEM or an LSM denial: the connection stays in the backlog and the level-triggered watcher would fire again at once; clear_timer_cb restarts it
			ev_io_stop(loop,watcher);
		}
		return 0;
	}

	address_t tmp_addr;
	tmp_addr.from_sockaddr((sockaddr*)&tmp_sockaddr_in,tmp_len);

	//max_conn_num 按本规则在所有 worker 合计的连接数（M4）：先占一个名额，之后没建成连接对的路径都还回去
	if(conn_manager_tcp.conns->fetch_add(1,memory_order_relaxed)>=max_conn_num)
	{
		conn_manager_tcp.conns->fetch_sub(1,memory_order_relaxed);
		mylog(log_warn,"[tcp]new connection from {%s},but ignored,bc of max_conn_num reached\n",tmp_addr.get_str());
		close(new_fd);
		return 1;
		//continue;
	}
	//先取对象再建上游 socket：分配失败时上游看不到这次连接，也不推进 roundrobin
	tcp_pair_t *new_pair=w.tcp_pair_pool.get();
	if(new_pair==0)
	{
		conn_manager_tcp.conns->fetch_sub(1,memory_order_relaxed);
		mylog(log_warn,"[tcp]new connection from {%s},but malloc for connection objects failed\n",tmp_addr.get_str());
		close(new_fd);
		return 1;
	}
	int remote_index=select_remote_index(*rule,tmp_addr);
	address_t &remote_addr=rule->remote_targets[remote_index].addr;


	int new_remote_fd = socket(remote_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	if(new_remote_fd<0&&(errno==EMFILE||errno==ENFILE)&&tcp_pipe_trim(w)>0)//fd 用完时关掉空闲 pipe 再试一次（D52）
		new_remote_fd = socket(remote_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	if(new_remote_fd<0)
	{
		mylog(log_warn,"[tcp]new connection from {%s},but create new_remote_fd failed,%s\n",tmp_addr.get_str(),get_sock_error());
		w.tcp_pair_pool.put(new_pair);
		conn_manager_tcp.conns->fetch_sub(1,memory_order_relaxed);
		close(new_fd);
		return 1;
	}
	if(sock_buf_explicit)
		set_buf_size(new_remote_fd,socket_buf_size);

	ret=connect(new_remote_fd,(struct sockaddr*) &remote_addr.inner,remote_addr.get_len());
	if(ret!=0&&errno!=EINPROGRESS)
	{
		//立即失败（如无路由的 ENETUNREACH、本地端口耗尽的 EADDRNOTAVAIL）：不建连接对
		mylog(log_warn,"[tcp]new connection from {%s},but connect to remote {%s} failed,%s\n",tmp_addr.get_str(),rule->remote_targets[remote_index].remote_str,get_sock_error());
		w.tcp_pair_pool.put(new_pair);
		conn_manager_tcp.conns->fetch_sub(1,memory_order_relaxed);
		close(new_remote_fd);
		close(new_fd);
		//EADDRNOTAVAIL 要先扫完整个临时端口范围（每次可达数 ms）：结束本轮，端口耗尽时回到每次迭代拒绝一个
		return 0;
	}
	if(ret!=0)
	{
		mylog(log_debug,"[tcp]connect returned %d,errno=%s\n",ret,get_sock_error());
	}
	else
	{
		mylog(log_debug,"[tcp]connect returned 0\n");
	}

	tcp_pair_t &tcp_pair=*new_pair;

	conn_manager_tcp.lru.new_key(&tcp_pair);
	conn_manager_tcp.total++;

	tcp_pair.owner=rule;
	tcp_pair.remote_index=remote_index;
	tcp_pair.gen=rule->remote_targets[remote_index].gen;
	tcp_pair.addr=tmp_addr;

	mylog(log_info,"[tcp]new_connection from {%s},fd1=%d,fd2=%d,tcp connections=%d\n",tcp_pair.addr.get_str(),new_fd,new_remote_fd,conn_manager_tcp.lru.size());

	tcp_pair.local.connected=1;
	tcp_pair.remote.connected=(ret==0);

	tcp_pair.local.fd=new_fd;
	//tcp_pair.local.ev.events=EV_READ;
	tcp_pair.local.ev.data=&tcp_pair;

	tcp_pair.remote.fd=new_remote_fd;
	//tcp_pair.remote.ev.events=EV_READ;
	tcp_pair.remote.ev.data=&tcp_pair;
	tcp_pair.remote.nodelay_wait=!disable_tcp_nodelay;//TCP_NODELAY 由 nodelay_before_send 在 send 之前设（T15）

	conn_manager_tcp.lru.update(&tcp_pair);
	//tcp_pair.last_active_time=get_current_time();

	//epoll_event ev;

	//ev=tcp_pair.local.ev;
	//ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_fd, &ev);
	//assert(ret==0);
	ev_io_init (&tcp_pair.local.ev, tcp_cb, new_fd, EV_READ);
	ev_io_start(loop, &tcp_pair.local.ev);

	//ev=tcp_pair.remote.ev;
	//ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_remote_fd, &ev);
	//assert(ret==0);

	//建连中同时等读写，由 tcp_cb 判定建连结果
	ev_io_init (&tcp_pair.remote.ev, tcp_cb, new_remote_fd, tcp_pair.remote.connected?EV_READ:EV_READ|EV_WRITE);
	ev_io_start(loop, &tcp_pair.remote.ev);
	return 1;
}
void tcp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if((revents&EV_ERROR) !=0)
	{
		//e.g. re-adding the listen fd to epoll after a pause failed; libev has already stopped the watcher, clear_timer_cb restarts it
		mylog(log_warn,"[tcp]accept watcher of listen fd %d got EV_ERROR\n",watcher->fd);
		return ;
	}
	//一直 accept 到 backlog 为空，每轮循环最多 max_accept_per_round 个（D13）：其他 watcher 每轮只做一次收发，
	//而每个新连接要做 accept、socket、connect 等十来次 syscall，上限决定建连突发时事件循环一轮停多久
	for(int i=0;i<max_accept_per_round;i++)
	{
		if(!tcp_accept_one(loop,watcher)) break;
	}
}

//一个 worker 每个定时器周期要做的事（M1）：清空闲连接、再查 DNS 旧地址上留下的连接（remote_sweep）、重启被停掉的监听 watcher、
//pipe 池标志复位与重扩。由 worker 自己 loop 上的定时器调用（L7）
static void worker_tick(worker_t &w)
{
	my_time_t now=w.clock.now();
	for(auto it=w.rules.begin();it!=w.rules.end();++it)
	{
		it->tcp_manager.clear_inactive();
		it->udp_manager.clear_inactive();
		for(size_t r=0;r<it->remote_targets.size();r++)
		{
			remote_target_t &target=it->remote_targets[r];
			if(target.sweep_at==0||now<target.sweep_at) continue;
			int closed[2],kept[2];
			remote_sweep(*it,(int)r,closed,kept);
			if(closed[0]+closed[1]>0)
				mylog(log_info,"rule %d remote %d domain %s:%u old address check: closed unresponsive tcp=%d udp=%d, kept tcp=%d udp=%d\n",it->index,(int)r,target.host,target.port,closed[0],closed[1],kept[0],kept[1]);
		}
		if(it->enable_tcp&&!ev_is_active(&it->tcp_accept_watcher))
		{
			ev_io_start(w.loop,&it->tcp_accept_watcher);
		}
		if(it->enable_udp&&!ev_is_active(&it->udp_accept_watcher))
		{
			ev_io_start(w.loop,&it->udp_accept_watcher);
		}
	}
	w.udp_new_blocked=0;//建 UDP 会话同上（D80）；放在 clear_inactive 之后，过期会话刚还回的端口这一周期就能用上
	w.tcp_pipe_pool.blocked=0;//创建 pipe 失败后每个周期最多再试一次（每次失败都会重新置位）
	w.tcp_pipe_pool.grow_blocked=0;//扩容同上
	if(w.tcp_pipe_pool.quota_hit)//复审 R1：配额满期间多留的空闲 pipe 裁回 max_free
	{
		w.tcp_pipe_pool.quota_hit=0;
		while(w.tcp_pipe_pool.free_cnt>w.tcp_pipe_pool.max_free) w.tcp_pipe_pool.discard(w.tcp_pipe_pool.free_pipes[--w.tcp_pipe_pool.free_cnt]);
	}
	if(w.tcp_pipe_pool.resize_fail!=0&&w.tcp_pipe_scratch.r>=0) w.tcp_pipe_pool.regrow(w.tcp_pipe_scratch);
}
//worker 的定时器（每 timer_interval）
void clear_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents)
{
	worker_tick(*(worker_t *)timer->data);
}
//主线程的定时器（每 timer_interval）：DNS 调度、统计超时检查、刷新日志
static void stats_check_late();
static void main_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents)
{
	schedule_dns_refresh();
	stats_check_late();
	//stdout 不是终端时 log0 不逐行刷新，各线程写的日志最多晚一个 timer_interval 写出（D3）
	fflush(stdout);
}
//U5：给 UDP socket 开 UDP_GRO（5.0 起）：网卡 GRO 阶段为它聚合同一条流的包，收到时带 UDP_GRO cmsg。
//副作用：任何一个 socket 开了它，内核就打开全局 static key，本机所有入站 UDP 在 GRO 阶段都多一次 socket 查找
static int udp_gro_set(int fd)
{
	int one=1;
	return setsockopt(fd,SOL_UDP,UDP_GRO,&one,sizeof(one));
}
static void udp_flush_return(udp_batch_t &b);
//会话 socket 可读（回程，U4）：回包收进回程批，由 udp_flush_return 跨会话发给客户端
void udp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	udp_pair_t & udp_pair=*(udp_pair_t *)watcher->data;
	int udp_fd=udp_pair.fd;
	DEBUG_ASSERT(udp_pair.owner!=0);
	conn_manager_udp_t &conn_manager_udp=udp_pair.owner->udp_manager;
	//同 tcp_cb：libev 已停掉这个 watcher，只释放这个会话（C9）；客户端的下一个包会新建会话
	if((revents&EV_ERROR) !=0)
	{
		mylog(log_warn,"[udp]connection {%s} closed bc of EV_ERROR (epoll_ctl failed),udp fd=%d\n",udp_pair.adress.get_str(),udp_fd);
		conn_manager_udp.erase(&udp_pair);
		return;
	}
	//assert(conn_manager.exist_fd(udp_fd));
	//if(!conn_manager.exist_fd(udp_fd)) continue;

	/*
	if((events[idx].events & EPOLLERR) !=0 ||(events[idx].events & EPOLLHUP) !=0)
	{
		mylog(log_warn,"[udp]EPOLLERR or EPOLLHUP from udp_remote_fd events[idx].events=%x \n",events[idx].events);

	}*/

	udp_batch_t &b=udp_pair.owner->worker->udp_batch;
	DEBUG_ASSERT(b.rn<udp_batch_max);//批满时当场就发出了
	//每次回调只收一次（D36，同 D35）：最多 udp_return_quota 个（D37），也不超过批里剩下的空位，没收完的由水平触发的 epoll 下一轮再报
	int vlen=udp_batch_max-b.rn;
	if(vlen>udp_return_quota) vlen=udp_return_quota;
	int n=recvmmsg(udp_fd,b.rin+b.rn,vlen,MSG_DONTWAIT,0);
	if(n<0)
	{
		//EAGAIN：唤醒本轮的包校验和错误、已被内核丢掉；ECONNREFUSED 等 ICMP 错误在这里取走
		if(errno!=EAGAIN&&errno!=EWOULDBLOCK)
			mylog(log_warn,"[udp]recv failed %d ,udp_fd%d,errno:%s\n", n,udp_fd,get_sock_error());
		return;
	}
	for(int i=b.rn;i<b.rn+n;i++)
	{
		mylog(log_trace, "[udp]received data from udp fd %d, len=%d\n", udp_fd,(int)b.rin[i].msg_len);
		if(udp_gro) b.gso[i]=udp_recv_ctrl(b.rin[i].msg_hdr,0,b.addr[i]);
		if(b.rin[i].msg_hdr.msg_flags&MSG_TRUNC)
		{
			mylog(log_warn,"huge packet from {%s}, data_len > %d,dropped\n",udp_pair.adress.get_str(),max_data_len_udp);
			b.rrule[i]=0;
			continue;
		}
		if(udp_gro)
		{
			if(b.gso[i]<0)
			{
				mylog(log_warn,"[udp]packet for {%s} dropped: control data truncated (MSG_CTRUNC), GRO segment size unknown\n",udp_pair.adress.get_str());
				b.rrule[i]=0;
				continue;
			}
			if(b.gso[i]!=0) conn_manager_udp.gro[1]+=udp_segs(b.rin[i].msg_len,b.gso[i]);
			b.roff[i]=udp_pair.gso_off[1];
		}
		b.raddr[i]=udp_pair.adress;
		b.rlocal[i]=udp_pair.local;
		b.rrule[i]=udp_pair.owner;
	}
	b.rn+=n;
	conn_manager_udp.lru.update(&udp_pair);
	udp_pair.unans=0;//收到回包：上游还在应答（remote_sweep）
	//udp_pair.last_active_time=get_current_time();
	if(b.rn==udp_batch_max) udp_flush_return(b);
}
//客户端 tmp_addr 的第一个包：建会话。失败时返回 0，这个包丢弃；hash 是 find() 算出的 tmp_addr 的哈希。不内联进逐包的循环
static udp_pair_t * __attribute__((noinline)) udp_new_session(struct ev_loop *loop,forward_rule_t *rule,address_t &tmp_addr,u32_t hash)
{
	conn_manager_udp_t &conn_manager_udp=rule->udp_manager;
	worker_t &w=*rule->worker;
	if(w.udp_new_blocked) return 0;//D80：不占名额、不扩表、不推进轮询，也不记日志
	//同 TCP（M4）：按本规则所有 worker 合计的会话数，先占一个名额，没建成会话的路径都还回去
	if(conn_manager_udp.conns->fetch_add(1,memory_order_relaxed)>=max_conn_num)
	{
		conn_manager_udp.conns->fetch_sub(1,memory_order_relaxed);
		mylog(log_info,"[udp]new connection from {%s},but ignored,bc of max_conv_num reached\n",tmp_addr.get_str());
		return 0;
	}
	//会话表要扩容时在选上游、建 socket 之前做：失败只丢这个包，轮询序号不前进
	if(conn_manager_udp.sessions.reserve_one()!=0)
	{
		conn_manager_udp.conns->fetch_sub(1,memory_order_relaxed);
		mylog(log_info,"[udp]new connection from {%s},but malloc for connection objects failed\n",tmp_addr.get_str());
		return 0;
	}
	int remote_index=select_remote_index(*rule,tmp_addr);
	address_t &remote_addr=rule->remote_targets[remote_index].addr;
	int new_udp_fd=remote_addr.new_connected_udp_fd();
	if(new_udp_fd==-1&&(errno==EMFILE||errno==ENFILE)&&tcp_pipe_trim(w)>0)//同 TCP：fd 用完时关掉空闲 pipe 再试一次（D52）
		new_udp_fd=remote_addr.new_connected_udp_fd();
	if(new_udp_fd==-1)
	{
		conn_manager_udp.conns->fetch_sub(1,memory_order_relaxed);
		if(errno==EAGAIN||errno==EMFILE||errno==ENFILE)
		{
			w.udp_new_blocked=1;
			mylog(log_warn,"[udp]new connection from {%s},but no free local port or fd for udp fd (%s),not creating udp sessions until the next timer tick\n",tmp_addr.get_str(),get_sock_error());
		}
		else mylog(log_info,"[udp]new connection from {%s} ,but create udp fd failed\n",tmp_addr.get_str());
		return 0;
	}
	//U5：回包经网卡时也聚合；失败时这个会话只是收不到合并包
	if(udp_gro&&udp_gro_set(new_udp_fd)!=0)
		mylog(log_debug,"[udp]setsockopt UDP_GRO failed on udp fd %d (%s)\n",new_udp_fd,get_sock_error());

	udp_pair_t *new_pair=w.udp_pair_pool.get();
	if(new_pair==0)
	{
		conn_manager_udp.conns->fetch_sub(1,memory_order_relaxed);
		mylog(log_info,"[udp]new connection from {%s},but malloc for connection objects failed\n",tmp_addr.get_str());
		close(new_udp_fd);
		return 0;
	}
	udp_pair_t &udp_pair=*new_pair;
	conn_manager_udp.lru.new_key(&udp_pair);
	conn_manager_udp.total++;
	udp_pair.owner=rule;
	udp_pair.remote_index=remote_index;
	udp_pair.gen=rule->remote_targets[remote_index].gen;

	udp_pair.fd=new_udp_fd;
	udp_pair.ev.data=&udp_pair;
	ev_io_init (&udp_pair.ev, udp_cb, new_udp_fd, EV_READ);
	ev_io_start(loop, &udp_pair.ev);

	mylog(log_info,"[udp]new connection from {%s},udp fd=%d,udp connections=%d\n",tmp_addr.get_str(),new_udp_fd,conn_manager_udp.lru.size());

	udp_pair.adress=tmp_addr;

	conn_manager_udp.sessions.insert(&udp_pair,hash);
	conn_manager_udp.last_hit=&udp_pair;
	return &udp_pair;
}
//U5：发送条目 m 带 UDP_SEGMENT 时返回段长，否则 0。UDP_SEGMENT 总是第一个 cmsg；回程条目可能只带 pktinfo（D87）
static inline int udp_msg_gso(const mmsghdr &m)
{
	if(m.msg_hdr.msg_controllen==0) return 0;
	const cmsghdr *c=(const cmsghdr *)m.msg_hdr.msg_control;
	if(c->cmsg_level!=SOL_UDP) return 0;
	uint16_t g;
	memcpy(&g,CMSG_DATA(c),sizeof(g));
	return g;
}
//D87：回程条目 m 带的 pktinfo cmsg，没有时为 0（布局见 udp_ret_ctrl_t）
static inline const cmsghdr *udp_msg_pktinfo(const mmsghdr &m)
{
	if(m.msg_hdr.msg_controllen==0) return 0;
	const cmsghdr *c=(const cmsghdr *)m.msg_hdr.msg_control;
	if(c->cmsg_level!=SOL_UDP) return c;
	if(m.msg_hdr.msg_controllen>CMSG_SPACE(sizeof(uint16_t))) return (const cmsghdr *)((const char *)c+CMSG_SPACE(sizeof(uint16_t)));
	return 0;
}
static inline size_t udp_msg_len(const mmsghdr &m)
{
	size_t len=0;
	for(int k=0;k<(int)m.msg_hdr.msg_iovlen;k++)
		len+=m.msg_hdr.msg_iov[k].iov_len;
	return len;
}
//条目 m 里的数据报数（O1 的 pkts/drop 按数据报计，U5）
static inline int udp_msg_segs(const mmsghdr &m)
{
	int g=udp_msg_gso(m);
	if(g==0) return 1;
	return udp_segs(udp_msg_len(m),g);
}
static int udp_msgs_segs(const mmsghdr *msgs,int from,int to)
{
	if(!udp_gro) return to-from;
	int n=0;
	for(int i=from;i<to;i++)
		n+=udp_msg_segs(msgs[i]);
	return n;
}
static void udp_send_warn(int dir,int ret,int dropped)
{
	if(dir==0)
		mylog(log_warn,"[udp]sendmmsg returned %d,%s,dropped %d packets\n",ret,get_sock_error(),dropped);
	else
		mylog(log_warn,"[udp]sendmmsg to clients returned %d,%s,dropped %d packets\n",ret,get_sock_error(),dropped);
}
//U5（审查 L1）：5.0–5.15 未打补丁的内核（v5.16 修复，回移到 5.4.151–180、5.10.81–100 之间）按含 IP/UDP 头的长度判断段数上限，
//64 个满段必报 EINVAL。碰到一次就置 1，之后每次 GSO 至多 udp_gso_cap() 段，段数加头长不超过 64 段。6.13 以前段长超过路径 MTU
//也报 EINVAL，段长 ≤1023 B 的 64 段合并包碰上它时会误置：只是此后 64 段的合并包拆成两块发，那个会话随后照常回退
static std::atomic<int> udp_gso_hdr_cap(0);//各 worker 共用（M2）：relaxed，两个 worker 同时碰上时各记一行 debug
static inline int udp_gso_cap(int gso)
{
	return udp_gso_hdr_cap.load(memory_order_relaxed)?udp_gso_max_segs-(48+gso-1)/gso:udp_gso_max_segs;
}
//段长 gso、segs 段的 GSO 发送报 err 时：是上面的旧内核上限就记住并返回 1（按更小的块重发即可，不关 GSO），否则 0
static int udp_gso_old_limit(int err,int gso,int segs)
{
	if(err!=EINVAL||udp_gso_hdr_cap.load(memory_order_relaxed)||segs<=udp_gso_max_segs-(48+gso-1)/gso) return 0;
	udp_gso_hdr_cap.store(1,memory_order_relaxed);
	mylog(log_debug,"[udp]GSO send of %d segments failed with EINVAL (Linux 5.0-5.15 count the IP/UDP headers against UDP_MAX_SEGMENTS, or the path MTU is smaller), sending at most %d segments at a time from now on\n",segs,udp_gso_cap(gso));
	return 1;
}
//U5：GSO 本身发不出去：6.11 以前出口没有 TX 校验和 offload、或带 IPsec 时 EIO；段长超过路径 MTU 时 6.13 以前 EINVAL、6.14 起 EMSGSIZE；
//段数超过内核的 UDP_MAX_SEGMENTS 时 EINVAL
static inline int udp_gso_errno(int err)
{
	return err==EIO||err==EINVAL||err==EMSGSIZE;
}
//U5：一组发送的 GSO 回退状态（D41、D45），都按会话：入向一组属于一个会话，off 指向它的 gso_off[0]、stride 为 0；回程一组是一个规则
//发往各客户端的回包，off[i] 是第 i 条所属会话收包时的 gso_off[1]（udp_batch.rout_off，不持有会话指针，D36）、stride 为 1
struct udp_send_ctx_t
{
	conn_manager_udp_t &mgr;
	int fd;
	int dir;
	unsigned char *off;
	int stride;
	udp_pair_t *pair;//入向的会话；回程为 0
	udp_batch_t &b;//所属 worker 的批：udp_send_split 用它的 seg
};
//第 i 条的 GSO 本身发不出去：这个会话这个方向此后不用 GSO。回程按客户端地址找到会话置位（会话已释放就只改本次发出的条目），
//同一组里发往同一客户端的其余条目也改为逐包。计数；info 每条规则每个方向只写第一次，之后 debug（审查 L3）
static void __attribute__((noinline,cold)) udp_gso_turn_off(udp_send_ctx_t &c,mmsghdr *msgs,int i,int cnt)
{
	address_t *client;
	if(c.dir==0)
	{
		c.pair->gso_off[0]=1;
		client=&c.pair->adress;
	}
	else
	{
		client=(address_t *)msgs[i].msg_hdr.msg_name;//指向 udp_batch.raddr[j].inner，inner 是 address_t 唯一的数据成员
		for(int k=i;k<cnt;k++)
			if(udp_key_eq(*(address_t *)msgs[k].msg_hdr.msg_name,*client)) c.off[k]=1;
		u32_t hash;
		udp_pair_t *pair=c.mgr.find(*client,hash);
		if(pair!=0) pair->gso_off[1]=1;
	}
	c.mgr.gso_fallback[c.dir]++;
	int level=c.mgr.gso_logged[c.dir].exchange(1,memory_order_relaxed)?log_debug:log_info;
	mylog(level,"[udp]GSO send %s {%s} on %s fd %d failed (%s), sending its GRO packets datagram by datagram from now on\n",
		c.dir==0?"from":"to",client->get_str(),c.dir==0?"session":"listen",c.fd,get_sock_error());
}
//D90：回程带 pktinfo 的条目发送失败、源地址不可用：地址已删除，目的是子网广播地址，IPv6 AnyIP（lo 上的 local 路由）作源，
//IPv4 为 EINVAL（5.4 以前）或 ENETUNREACH，IPv6 为 EINVAL；ifindex 无效时 ENODEV
static inline int udp_pktinfo_errno(int err)
{
	return err==EINVAL||err==ENETUNREACH||err==ENODEV||err==EADDRNOTAVAIL;
}
//D90：回程第 i 条带 pktinfo、发送报 udp_pktinfo_errno：本组 [i,cnt) 里发往同一客户端的条目都去掉 pktinfo（保留 UDP_SEGMENT），
//会话忘掉记下的本地地址（会话已释放就只改本次发出的条目），直到客户端再发来包；调用方原地重发，源地址由内核选。
//带 UDP_SEGMENT 的条目报 EINVAL 时也先按这里处理，重发仍失败才算 GSO 的错误：碰上旧内核的段数上限或段长超过路径 MTU 时，
//这个客户端的源地址要等它下一个包才恢复，但会话的 GSO 不会因为源地址的问题被误关。info 每条规则只写第一次，之后 debug（同审查 L3）
static void __attribute__((noinline,cold)) udp_pktinfo_off(udp_send_ctx_t &c,mmsghdr *msgs,int i,int cnt)
{
	DEBUG_ASSERT(c.dir==1);
	int err=errno;
	char local[INET6_ADDRSTRLEN]="?";
	const cmsghdr *pi=udp_msg_pktinfo(msgs[i]);
	if(pi->cmsg_level==SOL_IP)
	{
		in_pktinfo v;
		memcpy(&v,CMSG_DATA(pi),sizeof(v));
		inet_ntop(AF_INET,&v.ipi_spec_dst,local,sizeof(local));
	}
	else
	{
		in6_pktinfo v;
		memcpy(&v,CMSG_DATA(pi),sizeof(v));
		inet_ntop(AF_INET6,&v.ipi6_addr,local,sizeof(local));
	}
	address_t *client=(address_t *)msgs[i].msg_hdr.msg_name;
	for(int k=i;k<cnt;k++)
	{
		mmsghdr &m=msgs[k];
		if(!udp_key_eq(*(address_t *)m.msg_hdr.msg_name,*client)||udp_msg_pktinfo(m)==0) continue;
		if(udp_msg_gso(m)!=0)
			m.msg_hdr.msg_controllen=CMSG_SPACE(sizeof(uint16_t));
		else
		{
			m.msg_hdr.msg_control=0;
			m.msg_hdr.msg_controllen=0;
		}
	}
	u32_t hash;
	udp_pair_t *pair=c.mgr.find(*client,hash);
	if(pair!=0) pair->local.family=0;
	int level=c.mgr.pktinfo_logged->exchange(1,memory_order_relaxed)?log_debug:log_info;
	errno=err;
	mylog(level,"[udp]sending to {%s} from %s on listen fd %d failed (%s), letting the kernel choose the source address until the client sends again\n",
		client->get_str(),local,c.fd,get_sock_error());
}
//U5：msg 的 iov（槽与溢出区）里 [off,off+len) 这一段写进 dst，返回用了几个 iovec（至多 2）
static int udp_iov_range(const msghdr &src,size_t off,size_t len,iovec *dst)
{
	int n=0;
	for(int k=0;k<(int)src.msg_iovlen&&len>0;k++)
	{
		size_t l=src.msg_iov[k].iov_len;
		if(off>=l)
		{
			off-=l;
			continue;
		}
		size_t take=min(l-off,len);
		dst[n].iov_base=(char *)src.msg_iov[k].iov_base+off;
		dst[n].iov_len=take;
		n++;
		len-=take;
		off=0;
	}
	return n;
}
//U5：把第 i 条（GRO 合并包）切成每块至多 udp_gso_cap() 段（这个会话这个方向已关 GSO 时每块一个数据报）发出，用于：sendmmsg 发它失败之后、
//已关 GSO、段数超过上限。一次 sendmmsg 至多 udp_batch_max 块，失败语义同 udp_send_group：GSO 本身的错误先关掉 GSO，这一块改为逐个
//数据报重发；其他错误丢掉这一块；EAGAIN 时把这个包剩下的数据报数记进 left、返回 -1，由调用方连同本组剩下的包一起计入 drop、记一行 warn
static int udp_send_split(udp_send_ctx_t &c,mmsghdr *msgs,int i,int cnt,int &left)
{
	udp_batch_t &b=c.b;
	const mmsghdr &m=msgs[i];
	const int gso=udp_msg_gso(m);
	const size_t len=udp_msg_len(m);
	DEBUG_ASSERT(gso>0);
	size_t off=0;
	while(off<len)
	{
		const size_t piece=(size_t)gso*(c.off[c.stride*i]?1:udp_gso_cap(gso));
		const cmsghdr *pi=udp_msg_pktinfo(m);//D87：回程的每块带同一个 pktinfo；udp_pktinfo_off 去掉之后为 0
		int n=0;
		for(size_t o=off;o<len&&n<udp_batch_max;o+=piece,n++)
		{
			mmsghdr &s=b.seg[n];
			udp_ret_ctrl_t &sc=b.seg_ctrl[n];
			size_t l=min(piece,len-o);
			s.msg_hdr.msg_name=m.msg_hdr.msg_name;
			s.msg_hdr.msg_namelen=m.msg_hdr.msg_namelen;
			s.msg_hdr.msg_iovlen=udp_iov_range(m.msg_hdr,o,l,b.seg_iov[n]);
			socklen_t pl=0;
			if(pi!=0)
			{
				pl=pi->cmsg_len;
				memcpy(udp_ret_pi(sc),pi,pl);
			}
			if(l>(size_t)gso)
			{
				uint16_t v=(uint16_t)gso;
				memcpy(CMSG_DATA(&sc.hdr),&v,sizeof(v));
				s.msg_hdr.msg_control=&sc;
				s.msg_hdr.msg_controllen=CMSG_SPACE(sizeof(uint16_t))+pl;
			}
			else if(pl!=0)
			{
				s.msg_hdr.msg_control=udp_ret_pi(sc);
				s.msg_hdr.msg_controllen=pl;
			}
			else
			{
				s.msg_hdr.msg_control=0;
				s.msg_hdr.msg_controllen=0;
			}
		}
		int ret=(int)syscall(SYS_sendmmsg,(long)c.fd,b.seg,(long)n,0L);
		if(ret>0)
		{
			for(int k=0;k<ret;k++)
			{
				c.mgr.pkts[c.dir]+=udp_msg_segs(b.seg[k]);
				c.mgr.bytes[c.dir]+=b.seg[k].msg_len;
				off+=udp_msg_len(b.seg[k]);
			}
			continue;
		}
		if(errno==EAGAIN||errno==EWOULDBLOCK)
		{
			left=udp_segs(len-off,gso);
			return -1;
		}
		if(udp_pktinfo_errno(errno)&&udp_msg_pktinfo(b.seg[0])!=0)
		{
			udp_pktinfo_off(c,msgs,i,cnt);
			continue;
		}
		if(udp_msg_gso(b.seg[0])!=0&&udp_gso_errno(errno))
		{
			if(!udp_gso_old_limit(errno,gso,udp_msg_segs(b.seg[0])))
				udp_gso_turn_off(c,msgs,i,cnt);
			continue;
		}
		int dropped=udp_msg_segs(b.seg[0]);
		c.mgr.drop[c.dir]+=dropped;
		udp_send_warn(c.dir,ret,dropped);
		off+=udp_msg_len(b.seg[0]);
	}
	return 0;
}
//sendmmsg 不能直接发的条目（U5）：GRO 合并包，而它的会话这个方向已关 GSO，或段数超过上限
static inline int udp_gso_split_needed(const mmsghdr &m,unsigned char gso_off)
{
	int g=udp_msg_gso(m);
	if(g==0) return 0;
	return gso_off||udp_segs(udp_msg_len(m),g)>udp_gso_cap(g);
}
//一组 cnt 个包，dir 为 0 时是一个会话本批的入向包（U3，发往会话 socket），为 1 时是一个规则的回包（U4，发往监听 socket，
//各包带客户端地址）：sendmmsg 只发出一部分时从断点接着发（内核不报断点处的错误，重发一次才知道它是否仍失败）。
//EAGAIN 丢掉剩下的包，不排队（UDP 语义）；其他错误（EMSGSIZE 等）只丢断点处这一个包。入向时上一个包引来的 ICMP（ECONNREFUSED）
//只让断点处的发送失败，错误随之被取走，重发就成功：只有一组的第一个包碰上它时才丢包、记 warn（逐包 send 时每次都丢）；
//监听 socket 没有 connect，不收 ICMP 错误。
//U5：带 UDP_SEGMENT 的条目（GRO 合并包）发送失败时不按一个包丢，交给 udp_send_split 重发：GSO 本身的错误（udp_gso_errno）
//先关掉它所属会话这个方向的 GSO（udp_gso_turn_off）再逐个数据报发，其他错误按至多上限段再发一次。pkts/drop 按数据报计。
//直接调 syscall：64 位 musl 的 sendmmsg() 是逐条 sendmsg() 的循环（它的 msghdr 用 int 加填充，内核用 size_t）；
//udp_batch.out/rout/seg 在 worker_new() 清零的页里，musl 的 __pad1/__pad2 从不写入、恒为 0，内核读到的 msg_iovlen/msg_controllen 就是本值
static void udp_send_group(udp_send_ctx_t &c,mmsghdr *msgs,int cnt)
{
	for(int sent=0;sent<cnt;)
	{
		int end=cnt;
		int left=0;
		if(udp_gro)
		{
			end=sent;
			while(end<cnt&&!udp_gso_split_needed(msgs[end],c.off[c.stride*end])) end++;
			if(end==sent)
			{
				if(udp_send_split(c,msgs,sent,cnt,left)<0) goto eagain;
				sent++;
				continue;
			}
		}
		{
			int ret=(int)syscall(SYS_sendmmsg,(long)c.fd,msgs+sent,(long)(end-sent),0L);//变参按 long 读
			if(ret>0)
			{
				c.mgr.pkts[c.dir]+=ret;
				for(int i=sent;i<sent+ret;i++)
				{
					c.mgr.bytes[c.dir]+=msgs[i].msg_len;
					if(udp_msg_gso(msgs[i])!=0)
						c.mgr.pkts[c.dir]+=udp_msg_segs(msgs[i])-1;
				}
				sent+=ret;
				continue;
			}
			if(errno==EAGAIN||errno==EWOULDBLOCK) goto eagain;
			if(udp_pktinfo_errno(errno)&&udp_msg_pktinfo(msgs[sent])!=0)//D90：去掉 pktinfo 原地重发
			{
				udp_pktinfo_off(c,msgs,sent,cnt);
				continue;
			}
			if(udp_msg_gso(msgs[sent])!=0)
			{
				if(udp_gso_errno(errno)&&!udp_gso_old_limit(errno,udp_msg_gso(msgs[sent]),udp_msg_segs(msgs[sent])))
					udp_gso_turn_off(c,msgs,sent,cnt);
				if(udp_send_split(c,msgs,sent,cnt,left)<0) goto eagain;
				sent++;
				continue;
			}
			c.mgr.drop[c.dir]+=1;
			udp_send_warn(c.dir,ret,1);
			sent++;
			continue;
		}
	eagain:
		//left：udp_send_split 停下的那个合并包还没发的数据报，它本身已算在 sent 之前，所以本组剩下的从 sent+1 起
		{
			int dropped=left!=0?left+udp_msgs_segs(msgs,sent+1,cnt):udp_msgs_segs(msgs,sent,cnt);
			c.mgr.drop[c.dir]+=dropped;
			udp_send_warn(c.dir,-1,dropped);
		}
		break;
	}
}
//发出回程批（U4，D36）：按规则分组，每组对该规则的监听 socket 一次 sendmmsg，msg_name 是收包时拷下的客户端地址。
//组按规则在批里首次出现的顺序，组内保持到达顺序；通常只有一个规则，扫一遍就放完
static void udp_flush_return(udp_batch_t &b)
{
	for(int i=0;i<b.rn;i++)
	{
		forward_rule_t *rule=b.rrule[i];
		if(rule==0) continue;
		int cnt=0;
		for(int j=i;j<b.rn;j++)
		{
			if(b.rrule[j]!=rule) continue;
			b.rrule[j]=0;
			mmsghdr &m=b.rout[cnt];
			m.msg_hdr.msg_name=&b.raddr[j].inner;
			m.msg_hdr.msg_namelen=b.raddr[j].get_len();
			udp_batch_set_iov(b,m,b.rout_iov[cnt],j,b.rin[j].msg_len);
			//rlocal 只在通配监听的规则里有值（D87）；rout 各条跨次 flush 复用，所以每次都写
			udp_ret_set_ctrl(m,b.rout_ctrl[cnt],udp_gro?udp_batch_gso(b,j,b.rin[j].msg_len):0,b.rlocal[j]);
			if(udp_gro) b.rout_off[cnt]=b.roff[j];
			cnt++;
		}
		udp_send_ctx_t c={rule->udp_manager,rule->local_listen_fd_udp,1,b.rout_off,1,0,b};
		udp_send_group(c,b.rout,cnt);
	}
	b.rn=0;
}
//每轮循环阻塞之前（ev_prepare）发出回程批。不用 ev_check：libev 在同一优先级内按入队的逆序回调，check watcher 最后入队，
//反而在本轮的 I/O 回调之前执行
static void udp_flush_cb(struct ev_loop *loop, ev_prepare *watcher, int revents)
{
	udp_batch_t &b=((worker_t *)watcher->data)->udp_batch;
	if(b.rn!=0) udp_flush_return(b);
}
//recvmmsg 收到的 n 个包（U1、U3）：逐包查找或新建会话，再按会话分组，每个会话一次 sendmmsg。会话内保持到达顺序，
//各组按会话在本批首次出现的顺序发出
static void udp_forward_batch(struct ev_loop *loop,forward_rule_t *rule,int n)
{
	conn_manager_udp_t &conn_manager_udp=rule->udp_manager;
	udp_batch_t &b=rule->worker->udp_batch;
	int groups=0;
	for(int i=0;i<n;i++)
	{
		msghdr &h=b.in[i].msg_hdr;
		int data_len=b.in[i].msg_len;
		address_t tmp_addr;
		tmp_addr.from_sockaddr((sockaddr*)&b.addr[i],h.msg_namelen);
		h.msg_namelen=sizeof(b.addr[i]);//内核按实际地址长度改写了它，下一次 recvmmsg 之前恢复
		b.pair[i]=0;
		int gso=0;
		udp_local_t local;
		local.family=0;
		if(b.in_ctrl) gso=udp_recv_ctrl(h,rule->udp_pktinfo?&local:0,b.addr[i]);
		if(udp_gro) b.gso[i]=gso;

		//每包都走这里：地址只在记日志时格式化（T7）
		mylog(log_trace, "[udp]received data from udp_listen_fd from {%s}, len=%d\n",tmp_addr.get_str(),data_len);

		if(h.msg_flags&MSG_TRUNC)
		{
			mylog(log_warn,"huge packet from {%s}, data_len > %d,dropped\n",tmp_addr.get_str(),max_data_len_udp);
			continue;
		}
		if(gso<0)
		{
			mylog(log_warn,"[udp]packet from {%s} dropped: control data truncated (MSG_CTRUNC), GRO segment size unknown\n",tmp_addr.get_str());
			continue;
		}
		if(gso!=0) conn_manager_udp.gro[0]+=udp_segs(data_len,gso);

		u32_t hash;
		udp_pair_t *pair=conn_manager_udp.find(tmp_addr,hash);
		if(pair==0)
		{
			pair=udp_new_session(loop,rule,tmp_addr,hash);
			if(pair==0) continue;
		}
		if(rule->udp_pktinfo) pair->local=local;//D89：以客户端最近一个包的目的地址为准
		if(pair->batch_group<0)
		{
			pair->batch_group=groups;
			b.group_pair[groups]=pair;
			b.group_cnt[groups]=0;
			groups++;
		}
		b.group_cnt[pair->batch_group]++;
		b.pair[i]=pair;
	}
	//计数排序：group_pos 先是各组在 out 里的起点，放完后是终点
	int pos=0;
	for(int g=0;g<groups;g++)
	{
		b.group_pos[g]=pos;
		pos+=b.group_cnt[g];
	}
	for(int i=0;i<n;i++)
	{
		if(b.pair[i]==0) continue;
		int j=b.group_pos[b.pair[i]->batch_group]++;
		udp_batch_set_iov(b,b.out[j],b.out_iov[j],i,b.in[i].msg_len);
		if(udp_gro) udp_batch_set_gso(b,b.out[j],b.out_ctrl[j],i,b.in[i].msg_len);
	}
	for(int g=0;g<groups;g++)
	{
		udp_pair_t &udp_pair=*b.group_pair[g];
		udp_pair.batch_group=-1;
		my_time_t now=conn_manager_udp.lru.update(&udp_pair);
		if(udp_pair.unans==0) udp_pair.unans=now;//上一个回包之后的第一个包（remote_sweep）
		int cnt=b.group_cnt[g];
		udp_send_ctx_t c={conn_manager_udp,udp_pair.fd,0,&udp_pair.gso_off[0],0,&udp_pair,b};
		udp_send_group(c,b.out+b.group_pos[g]-cnt,cnt);
	}
}
void udp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	forward_rule_t *rule=(forward_rule_t *)watcher->data;
	DEBUG_ASSERT(rule!=0);

	if((revents&EV_ERROR) !=0)
	{
		//同 tcp_accept_cb：如启动时 ADD 监听 fd 失败；libev 已停掉这个 watcher，clear_timer_cb 下一跳重新 start（C9）
		mylog(log_warn,"[udp]accept watcher of listen fd %d got EV_ERROR\n",watcher->fd);
		return ;
	}

	int local_listen_fd_udp=watcher->fd;
	udp_batch_t &b=rule->worker->udp_batch;
	//回程批占着同一组槽（D36）：先发出，入向这一批才能从 slot[0] 起收
	if(b.rn!=0) udp_flush_return(b);
	//每次回调只收一批（D35）：没收完的由水平触发的 epoll 下一轮再报，一轮里入向最多占 udp_batch_max 个包，
	//回程与 TCP 不会被长时间挤占
	int n=recvmmsg(local_listen_fd_udp,b.in,udp_batch_max,MSG_DONTWAIT,0);//socket 本身也非阻塞；阻塞时会等凑满一批
	if(n<0)
	{
		//EAGAIN：唤醒本轮的包校验和错误、已被内核丢掉
		if(errno!=EAGAIN&&errno!=EWOULDBLOCK)
			mylog(log_debug,"[udp]recvmmsg error,errno %s\n",get_sock_error());
		return;
	}
	udp_forward_batch(loop,rule,n);
}
//SIGUSR1 统计（O1，D25–D27，D63）：worker 在自己线程上、两个回调之间取快照（这时池的计数与连接对能对上），回传主线程；
//主线程收齐后求和输出。当前连接数、半关闭对数、持有的块数在这里沿 LRU 现数，热路径上只累加转发计数
struct rule_stats_t
{
	int index,enable_tcp,enable_udp;
	int tcp_conns,half_closed,udp_sessions,table_cnt;
	u64_t tcp_total,tcp_bytes[2],splice_bytes[2],splice_fallback;
	u64_t udp_total,pkts[2],udp_bytes[2],drop[2],gro[2],gso_fallback[2];
};
struct worker_stats_t
{
	int id;
	vector<rule_stats_t> rules;
	int bufs_alloc,bufs_held,bufs_free,scratch;
	int tcp_slabs,tcp_free,udp_slabs,udp_free;
	int pipes_alloc,pipes_held,pipes_free,pipe_scratch;
	u64_t resize_fail;
	int tcp_conns,udp_conns;
	u64_t tcp_total,udp_total;
};
static ev_async stats_watcher;//worker 回传快照时唤醒主线程
static pthread_mutex_t stats_mutex=PTHREAD_MUTEX_INITIALIZER;//同 worker_t::ctrl_mutex，不用 std::mutex
static vector<worker_stats_t> stats_replies;//stats_mutex 保护
static vector<worker_stats_t> stats_got;//本轮已收到的（主线程）
static int stats_waiting=0;//本轮已发出、还没收齐
static int stats_again=0;//本轮没收齐时又来了 SIGUSR1：收齐后再来一轮
static my_time_t stats_sent_time=0;//本轮发出的时间（main_clock）
static int stats_late_logged=0;//本轮超时没收齐已记过 warn
static const my_time_t stats_answer_timeout=5000;

//worker 线程：取一份快照回传主线程
static void worker_stats(worker_t &w)
{
	worker_stats_t st;
	st.id=w.id;
	int held=0,pipes_held=0;
	st.tcp_conns=st.udp_conns=0;
	st.tcp_total=st.udp_total=0;
	for(auto it=w.rules.begin();it!=w.rules.end();++it)
	{
		forward_rule_t &rule=*it;
		conn_manager_tcp_t &tcp=rule.tcp_manager;
		conn_manager_udp_t &udp=rule.udp_manager;
		rule_stats_t r;
		r.index=rule.index;
		r.enable_tcp=rule.enable_tcp;
		r.enable_udp=rule.enable_udp;
		r.half_closed=0;
		for(lru_node_t *node=tcp.lru.head.next;node!=&tcp.lru.head;node=node->next)
		{
			tcp_pair_t *pair=static_cast<tcp_pair_t *>(node);
			r.half_closed+=(pair->local.eof||pair->remote.eof);
			held+=(pair->local.buf!=0)+(pair->remote.buf!=0);
			pipes_held+=(pair->local.pipe.r>=0)+(pair->remote.pipe.r>=0);
		}
		r.tcp_conns=tcp.lru.size();
		r.tcp_total=tcp.total;
		memcpy(r.tcp_bytes,tcp.bytes,sizeof(r.tcp_bytes));
		memcpy(r.splice_bytes,tcp.splice_bytes,sizeof(r.splice_bytes));
		r.splice_fallback=tcp.splice_fallback;
		r.udp_sessions=udp.lru.size();
		r.table_cnt=udp.sessions.cnt;
		r.udp_total=udp.total;
		memcpy(r.pkts,udp.pkts,sizeof(r.pkts));
		memcpy(r.udp_bytes,udp.bytes,sizeof(r.udp_bytes));
		memcpy(r.drop,udp.drop,sizeof(r.drop));
		memcpy(r.gro,udp.gro,sizeof(r.gro));
		memcpy(r.gso_fallback,udp.gso_fallback,sizeof(r.gso_fallback));
		st.tcp_conns+=r.tcp_conns;
		st.udp_conns+=r.udp_sessions;
		st.tcp_total+=r.tcp_total;
		st.udp_total+=r.udp_total;
		st.rules.push_back(r);
	}
	st.bufs_alloc=w.tcp_buf_pool.alloc;
	st.bufs_held=held;
	st.bufs_free=w.tcp_buf_pool.free_bufs.cnt;
	st.scratch=(w.tcp_scratch!=0);
	st.tcp_slabs=w.tcp_pair_pool.slabs;
	st.tcp_free=w.tcp_pair_pool.free_objs.cnt;
	st.udp_slabs=w.udp_pair_pool.slabs;
	st.udp_free=w.udp_pair_pool.free_objs.cnt;
	st.pipes_alloc=w.tcp_pipe_pool.alloc;
	st.pipes_held=pipes_held;
	st.pipes_free=w.tcp_pipe_pool.free_cnt;
	st.pipe_scratch=(w.tcp_pipe_scratch.r>=0);
	st.resize_fail=w.tcp_pipe_pool.resize_fail;
	pthread_mutex_lock(&stats_mutex);
	stats_replies.push_back(st);
	pthread_mutex_unlock(&stats_mutex);
	ev_async_send(main_clock.loop,&stats_watcher);
}
//主线程：给每个 worker 发一轮统计请求
static void stats_request()
{
	stats_waiting=1;
	stats_sent_time=main_clock.now();
	stats_late_logged=0;
	for(size_t i=0;i<workers.size();i++)
		worker_post(*workers[i],worker_msg_t(worker_msg_stats));
}
//主线程：收齐一轮后输出（D63）。N>1 时先每 worker 一行，再按规则求和的 tcp/udp 行，最后求和的 pool 行（一组的结尾：读者等到它就是写完了）；
//1 个 worker 时与 M2 之前逐字节相同。整组写完之前锁住 stdout：worker 线程这时写的日志行排在整组之后，不会插进来（测试与 bench/lib.sh
//从 pool 行往前找连续的规则行）。写出之后再对每个 worker 的快照核对不变式：DEBUG_ASSERT 构建里对不上时日志里留着这一组数
static void stats_print(vector<worker_stats_t> &all)
{
	sort(all.begin(),all.end(),[](const worker_stats_t &a,const worker_stats_t &b){return a.id<b.id;});
	flockfile(stdout);//log0 的 fwrite 在同一线程里再加锁不会阻塞（stdio 的锁可重入）
	if(all.size()>1)
	{
		for(size_t i=0;i<all.size();i++)
			mylog_unfiltered(log_info,"stats worker %d: tcp_conns=%d tcp_total=%llu udp_sessions=%d udp_total=%llu\n",
				all[i].id,all[i].tcp_conns,all[i].tcp_total,all[i].udp_conns,all[i].udp_total);
	}
	worker_stats_t sum=all[0];
	for(size_t i=1;i<all.size();i++)
	{
		worker_stats_t &st=all[i];
		for(size_t j=0;j<sum.rules.size();j++)
		{
			rule_stats_t &a=sum.rules[j],&b=st.rules[j];
			a.tcp_conns+=b.tcp_conns;
			a.half_closed+=b.half_closed;
			a.udp_sessions+=b.udp_sessions;
			a.tcp_total+=b.tcp_total;
			a.splice_fallback+=b.splice_fallback;
			a.udp_total+=b.udp_total;
			for(int d=0;d<2;d++)
			{
				a.tcp_bytes[d]+=b.tcp_bytes[d];
				a.splice_bytes[d]+=b.splice_bytes[d];
				a.pkts[d]+=b.pkts[d];
				a.udp_bytes[d]+=b.udp_bytes[d];
				a.drop[d]+=b.drop[d];
				a.gro[d]+=b.gro[d];
				a.gso_fallback[d]+=b.gso_fallback[d];
			}
		}
		sum.bufs_alloc+=st.bufs_alloc;
		sum.bufs_held+=st.bufs_held;
		sum.bufs_free+=st.bufs_free;
		sum.scratch+=st.scratch;
		sum.tcp_slabs+=st.tcp_slabs;
		sum.tcp_free+=st.tcp_free;
		sum.udp_slabs+=st.udp_slabs;
		sum.udp_free+=st.udp_free;
		sum.pipes_alloc+=st.pipes_alloc;
		sum.pipes_held+=st.pipes_held;
		sum.pipes_free+=st.pipes_free;
		sum.pipe_scratch+=st.pipe_scratch;
		sum.resize_fail+=st.resize_fail;
	}
	for(size_t j=0;j<sum.rules.size();j++)
	{
		rule_stats_t &r=sum.rules[j];
		if(r.enable_tcp)
			mylog_unfiltered(log_info,"stats rule %d tcp: conns=%d total=%llu half_closed=%d up_bytes=%llu down_bytes=%llu up_splice=%llu down_splice=%llu splice_fallback=%llu\n",
				r.index,r.tcp_conns,r.tcp_total,r.half_closed,r.tcp_bytes[0],r.tcp_bytes[1],r.splice_bytes[0],r.splice_bytes[1],r.splice_fallback);
		if(r.enable_udp&&!udp_gro)
			mylog_unfiltered(log_info,"stats rule %d udp: sessions=%d total=%llu up_pkts=%llu up_bytes=%llu down_pkts=%llu down_bytes=%llu up_drop=%llu down_drop=%llu\n",
				r.index,r.udp_sessions,r.udp_total,r.pkts[0],r.udp_bytes[0],r.pkts[1],r.udp_bytes[1],r.drop[0],r.drop[1]);
		if(r.enable_udp&&udp_gro)//D42：只在 --udp-gro 时多这四项
			mylog_unfiltered(log_info,"stats rule %d udp: sessions=%d total=%llu up_pkts=%llu up_bytes=%llu down_pkts=%llu down_bytes=%llu up_drop=%llu down_drop=%llu up_gro=%llu down_gro=%llu up_gso_fallback=%llu down_gso_fallback=%llu\n",
				r.index,r.udp_sessions,r.udp_total,r.pkts[0],r.udp_bytes[0],r.pkts[1],r.udp_bytes[1],r.drop[0],r.drop[1],
				r.gro[0],r.gro[1],r.gso_fallback[0],r.gso_fallback[1]);
	}
	mylog_unfiltered(log_info,"stats pool: bufs alloc=%d held=%d free=%d scratch=%d tcp_pairs slabs=%d free=%d udp_pairs slabs=%d free=%d pipes alloc=%d held=%d free=%d scratch=%d resize_fail=%llu\n",
		sum.bufs_alloc,sum.bufs_held,sum.bufs_free,sum.scratch,
		sum.tcp_slabs,sum.tcp_free,sum.udp_slabs,sum.udp_free,
		sum.pipes_alloc,sum.pipes_held,sum.pipes_free,sum.pipe_scratch,sum.resize_fail);
	fflush(stdout);
	funlockfile(stdout);
	for(size_t i=0;i<all.size();i++)
	{
		worker_stats_t &st=all[i];
		DEBUG_ASSERT(st.bufs_alloc==st.bufs_held+st.bufs_free+st.scratch);
		DEBUG_ASSERT(st.pipes_alloc==st.pipes_held+st.pipes_free+st.pipe_scratch);
		DEBUG_ASSERT(st.tcp_slabs*obj_pool_slab_objs-st.tcp_free==st.tcp_conns);
		DEBUG_ASSERT(st.udp_slabs*obj_pool_slab_objs-st.udp_free==st.udp_conns);
		for(size_t j=0;j<st.rules.size();j++)
			DEBUG_ASSERT(st.rules[j].table_cnt==st.rules[j].udp_sessions);
	}
}
static void stats_reply_cb(struct ev_loop *loop, ev_async *watcher, int revents)
{
	pthread_mutex_lock(&stats_mutex);
	for(size_t i=0;i<stats_replies.size();i++)
		stats_got.push_back(stats_replies[i]);
	stats_replies.clear();
	pthread_mutex_unlock(&stats_mutex);
	if(stats_got.size()<workers.size()) return;
	stats_print(stats_got);
	stats_got.clear();
	stats_waiting=0;
	if(stats_again)
	{
		stats_again=0;
		stats_request();
	}
}
//主线程定时器里调用：一轮统计发出后 stats_answer_timeout 还没收齐（worker 卡在很长的回调或死循环里）就记一行 warn，指出没回的 worker，
//继续等（审查 L-5：否则之后的 SIGUSR1 都被合并进这一轮，没有任何输出）。warn 与统计行一样，除 --log-level 0 外都写（D112）
static void stats_check_late()
{
	if(!stats_waiting||stats_late_logged||main_clock.now()-stats_sent_time<stats_answer_timeout) return;
	stats_late_logged=1;
	char ids[512];
	int len=0;
	ids[0]=0;
	for(size_t i=0;i<workers.size();i++)
	{
		int got=0;
		for(size_t j=0;j<stats_got.size();j++)
			got|=(stats_got[j].id==workers[i]->id);
		if(!got&&len<(int)sizeof(ids)-8)
			len+=snprintf(ids+len,sizeof(ids)-len," %d",workers[i]->id);
	}
	mylog_unfiltered(log_warn,"stats: worker(s)%s did not answer SIGUSR1 within %d s, still waiting\n",ids,(int)(stats_answer_timeout/1000));
}
void sigusr1_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	if(stats_waiting)//上一轮还没收齐：收齐后再来一轮（同一时刻的多个 SIGUSR1 本来就会被合并）
	{
		stats_again=1;
		return;
	}
	stats_request();
}

//worker 的控制消息（S4），在它自己的 loop 上、两个回调之间处理
static void worker_ctrl_cb(struct ev_loop *loop, ev_async *watcher, int revents)
{
	worker_t &w=*(worker_t *)watcher->data;
	std::deque<worker_msg_t> msgs;
	pthread_mutex_lock(&w.ctrl_mutex);
	msgs.swap(w.ctrl_queue);
	pthread_mutex_unlock(&w.ctrl_mutex);
	for(auto it=msgs.begin();it!=msgs.end();++it)
	{
		if(it->type==worker_msg_dns) worker_dns_update(w,*it);
		else if(it->type==worker_msg_stats) worker_stats(w);
		else if(it->type==worker_msg_exit) ev_break(loop,EVBREAK_ALL);
	}
}
static sem_t workers_exited;//每个 worker 线程退出 loop 后 post 一次（M6）
static void *worker_main(void *arg)
{
	worker_t &w=*(worker_t *)arg;
	char name[16];
	snprintf(name,sizeof(name),"worker%d",w.id);
	prctl(PR_SET_NAME,name,0,0,0);//top -H、/proc/<pid>/task/<tid>/comm 里认得出
	if(cpu_affinity)//A3：绑不上只影响分流后的局部性，照常转发
	{
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(worker_cpus[w.id],&set);
		if(sched_setaffinity(0,sizeof(set),&set)!=0)
			mylog(log_warn,"worker %d: sched_setaffinity to cpu %d failed, %s, running unpinned\n",w.id,worker_cpus[w.id],get_sock_error());
	}
	ev_run(w.loop,0);
	if(w.udp_batch.rn!=0) udp_flush_return(w.udp_batch);//本轮收下的回包照发：ev_break 之后不再有 ev_prepare
	sem_post(&workers_exited);
	return 0;
}
//有序退出（M6，S8）：通知每个 worker 退出 loop，合计最多等 1 s，再由调用方 myexit。不用 pthread_join：worker 卡住时 SIGTERM 也要能退出，
//musl 1.1.16 又没有 pthread_timedjoin_np。DNS 线程不等：它可能阻塞在 getaddrinfo 里，_exit 直接结束它
static void workers_stop()
{
	for(size_t i=0;i<workers.size();i++)
		worker_post(*workers[i],worker_msg_t(worker_msg_exit));
	struct timespec deadline;
	clock_gettime(CLOCK_REALTIME,&deadline);
	deadline.tv_sec+=1;
	for(size_t i=0;i<workers.size();i++)
	{
		while(sem_timedwait(&workers_exited,&deadline)!=0)
		{
			if(errno==EINTR) continue;
			mylog(log_warn,"%d of %d workers did not stop within 1 s, exiting anyway\n",(int)(workers.size()-i),(int)workers.size());
			return;
		}
	}
}
void sigpipe_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigpipe, ignored\n");
}

void sigterm_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigterm, exit\n");
	workers_stop();
	myexit(0);
}

void sigint_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigint, exit\n");
	workers_stop();
	myexit(0);
}


static void check_and_record_listen(unordered_map<address_t,int,address_t::hash_function> &listen_rules,forward_rule_t &rule,const char *protocol)
{
	auto it=listen_rules.find(rule.local_addr);
	if(it!=listen_rules.end())
	{
		char listen_addr[max_addr_len];
		rule.local_addr.to_str(listen_addr);
		mylog(log_fatal,"rule %d [%s] listen address %s conflicts with rule %d\n",rule.index,protocol,listen_addr,it->second);
		myexit(-1);
	}
	listen_rules[rule.local_addr]=rule.index;
}

//U5：监听 socket 开 UDP_GRO。开成功时给所属 worker 的 udp_batch 挂上收 cmsg 的控制缓冲（每个 worker 一份批，重复挂是同样的指针）；
//第一个就失败（5.0 以前的内核）时整个特性关闭，这时还没有 socket 开着 UDP_GRO。之后的失败每条规则只记一行（warned 由调用方按规则给）：那个监听 socket 收到的都是普通数据报
static void udp_gro_listen(forward_rule_t &rule,int &warned)
{
	static int gro_socks=0;
	if(udp_gro_set(rule.local_listen_fd_udp)==0)
	{
		gro_socks++;
		rule.worker->udp_batch.attach_ctrl(1);
		return;
	}
	if(!warned)//每条规则只记一行（各 worker 的监听 socket 一样，M2）
		mylog(log_warn,"rule %d [udp] setsockopt UDP_GRO failed (%s): --udp-gro needs Linux 5.0 or later%s\n",
			rule.index,get_sock_error(),gro_socks==0?", UDP_GRO stays off":"");
	warned=1;
	if(gro_socks==0) udp_gro=0;
}
//D87、D88：通配地址的 UDP 监听开收包的 PKTINFO，回包以客户端发往的地址为源（udp_ret_set_ctrl）。[::] 开 IPV6_RECVPKTINFO：
//IPv4 客户端的目的以 v4-mapped 地址给出（3.14 起；3.10–3.13 上没有，这些客户端的回包照旧由内核选源）；只收 IPv4 的 0.0.0.0 与
//[::ffff:0.0.0.0] 开 IP_PKTINFO（3.10 起，v6 socket 上也行，带 ipi_spec_dst）。具体地址的监听不用：内核本来就以绑定的地址为源。
//失败时这条规则在这个 worker 照旧由内核选源，每条规则只记一行（warned 由调用方按规则给）
static void udp_pktinfo_listen(forward_rule_t &rule,int &warned)
{
	const address_t::storage_t &a=rule.local_addr.inner;
	int level=IPPROTO_IP,opt=IP_PKTINFO;
	const char *name="IP_PKTINFO";
	if(a.ipv4.sin_family==AF_INET)
	{
		if(a.ipv4.sin_addr.s_addr!=htonl(INADDR_ANY)) return;
	}
	else if(IN6_IS_ADDR_UNSPECIFIED(&a.ipv6.sin6_addr))
	{
		level=IPPROTO_IPV6;
		opt=IPV6_RECVPKTINFO;
		name="IPV6_RECVPKTINFO";
	}
	else
	{
		static const unsigned char v4any[16]={0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0};
		if(memcmp(&a.ipv6.sin6_addr,v4any,sizeof(v4any))!=0) return;
	}
	int one=1;
	if(setsockopt(rule.local_listen_fd_udp,level,opt,&one,sizeof(one))==0)
	{
		rule.udp_pktinfo=1;
		rule.worker->udp_batch.attach_ctrl(0);
		return;
	}
	if(!warned)
		mylog(log_warn,"rule %d [udp] setsockopt %s failed (%s): replies go out from the address the kernel chooses\n",rule.index,name,get_sock_error());
	warned=1;
}

//第 i 条规则在 worker w 里的运行时（rules 按规则序号排列）
static forward_rule_t &worker_rule(worker_t &w,size_t i)
{
	auto it=w.rules.begin();
	advance(it,i);
	return *it;
}

//roundrobin 的选择序列（D85）：nginx 平滑加权轮询从全 0 开始走一个周期。每个周期里每个 remote 正好被选中"权重"次，走完各节点回到全 0，
//之后按同样的顺序重复，所以权重和 T 步就是完整的序列（T ≤ 255×255）。主线程在启动 worker 之前给每条 roundrobin 规则算一次；remote 最多 255 个，下标存一个字节
static void rr_build_seq(const vector<int> &weights,vector<unsigned char> &seq)
{
	int n=(int)weights.size();
	int total=0;
	for(int i=0;i<n;i++) total+=weights[i];
	vector<int> current(n,0);
	seq.resize(total);
	for(int k=0;k<total;k++)
	{
		int best=-1;
		for(int i=0;i<n;i++)
		{
			current[i]+=weights[i];
			if(best==-1||current[i]>current[best]) best=i;
		}
		current[best]-=total;
		seq[k]=(unsigned char)best;
	}
	for(int i=0;i<n;i++) assert(current[i]==0);
}

//在 worker w 里建第 i 条规则的运行时（不含监听，见 start_forward_rule）：规则配置与 remote 地址的副本，
//两个管理器指向 w 与本规则的全局连接计数，roundrobin 经 shared 用所有 worker 共用的序列（D85）
static void worker_add_rule(worker_t *w,size_t i)
{
	w->rules.emplace_back();
	forward_rule_t &rule=w->rules.back();
	rule.worker=w;
	rule.shared=&rule_shared[i];
	rule.tcp_manager.worker=rule.udp_manager.worker=w;
	rule.tcp_manager.lru.clock=rule.udp_manager.lru.clock=&w->clock;
	rule.tcp_manager.conns=&rule_shared[i].tcp;
	rule.udp_manager.conns=&rule_shared[i].udp;
	rule.udp_manager.gso_logged=rule_shared[i].gso_logged;
	rule.udp_manager.pktinfo_logged=&rule_shared[i].pktinfo_logged;
	forward_rule_config_t &rule_config=app_config.rules[i];
	rule.index=(int)i+1;
	rule.local_addr=rule_config.local_addr;
	rule.enable_tcp=rule_config.enable_tcp;
	rule.enable_udp=rule_config.enable_udp;
	rule.balance_strategy=rule_config.balance_strategy;
	rule.balance_weights=rule_config.balance_weights;
	assert(!rule_config.remote_targets.empty());
	rule.remote_targets.reserve(rule_config.remote_targets.size());
	for(size_t j=0;j<rule_config.remote_targets.size();j++)
	{
		const remote_target_config_t &config_target=rule_config.remote_targets[j];
		remote_target_t target;
		target.addr=config_target.addr;
		target.is_domain=config_target.is_domain;
		snprintf(target.remote_str,sizeof(target.remote_str),"%s",config_target.remote_str);
		snprintf(target.host,sizeof(target.host),"%s",config_target.host);
		target.port=config_target.port;
		rule.remote_targets.push_back(target);
	}
	if(rule.balance_strategy!=balance_strategy_off)
	{
		assert(rule.balance_weights.size()==rule.remote_targets.size());
	}
}

//建监听组之前先用一个只带 SO_REUSEADDR、不带 SO_REUSEPORT 的 socket bind 一次再关掉（S2）。TCP：地址已被占用（另一个实例，本配置里重叠的
//地址如 [::]:p 与 0.0.0.0:p，或同 uid 只设了 SO_REUSEPORT 的别的程序）时照旧报 bind 失败退出，否则同 uid 的 reuseport socket 会被静默加入
//同一组、分走连接。UDP：只有占用者没带 SO_REUSEADDR（什么都没设，或只设了 SO_REUSEPORT）时失败，带了的照旧能 bind（审查 L-1：与 M2 之前
//相同），另一个实例、重叠的规则都算（重叠的按族分：IPv4 客户端进 0.0.0.0，IPv6 进 [::]）。能 bind 不等于分担：同一地址上的数据报只交给
//一个实例（IPv4 是后 bind 的；IPv6 的 reuseport socket 排在链尾，先起的 N=1 实例保留），只有两个实例同 uid 且都是 N>1 时，后起实例的
//socket 加入前一个的组、按哈希分走客户端，前一个已有的客户端也随之重排。探测时设了 SO_REUSEADDR，TIME_WAIT 不影响
static void listen_probe(forward_rule_t &rule,int type,const char *protocol,const char *listen_addr)
{
	int yes=1;
	int probe=socket(rule.local_addr.get_type(), type|SOCK_CLOEXEC, 0);
	if(probe<0)
	{
		mylog(log_fatal,"rule %d [%s] create listen socket failed on %s, %s\n",rule.index,protocol,listen_addr,get_sock_error());
		myexit(1);
	}
	setsockopt(probe, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if(::bind(probe, (struct sockaddr*) &rule.local_addr.inner, rule.local_addr.get_len()) !=0)
	{
		mylog(log_fatal,"rule %d [%s] socket bind failed on %s, %s\n",rule.index,protocol,listen_addr,get_sock_error());
		myexit(1);
	}
	close(probe);
}

//--cpu-affinity（M5，A2/A4）：可用 CPU（taskset/cpuset 之后的）按升序取前 worker_count 个，不够就退出（D70）。此时主线程还是进程里唯一的线程。
//N>1 时建分流程序：SYN 的 softirq 在 worker k 的 CPU 上就选组里第 k 个 socket，否则返回越界值，内核回退到原来的四元组哈希（不返回 N：
//同 uid 后来加入组的 socket 排在第 N 个，返回 N 会把非 worker CPU 上的连接全给它）
static void cpu_affinity_init()
{
	cpu_set_t set;
	CPU_ZERO(&set);
	if(sched_getaffinity(0,sizeof(set),&set)!=0)
	{
		mylog(log_fatal,"--cpu-affinity: sched_getaffinity failed, %s\n",get_sock_error());
		myexit(-1);
	}
	char list[512];
	int len=0;
	for(int c=0;c<(int)(8*sizeof(set))&&(int)worker_cpus.size()<worker_count;c++)//不用 CPU_SETSIZE：musl 1.2.4 以前是 128，cpu_set_t 却有 1024 位
	{
		if(!CPU_ISSET(c,&set)) continue;
		worker_cpus.push_back(c);
		len+=snprintf(list+len,sizeof(list)-len,"%s%d",len?",":"",c);//64 个 4 位数也放得下
	}
	if((int)worker_cpus.size()<worker_count)
	{
		mylog(log_fatal,"--cpu-affinity: %d worker threads but only %d usable cpus\n",worker_count,(int)worker_cpus.size());
		myexit(-1);
	}
	mylog(log_info,"cpu affinity: workers on cpus %s\n",list);
	if(worker_count==1) return;//A6：没有 reuseport 组（D67）
	struct sock_filter ld=BPF_STMT(BPF_LD|BPF_W|BPF_ABS,(u32_t)(SKF_AD_OFF+SKF_AD_CPU));
	cpu_steer_code.push_back(ld);
	for(int k=0;k<worker_count;k++)
	{
		struct sock_filter jeq=BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(u32_t)worker_cpus[k],0,1);
		struct sock_filter ret=BPF_STMT(BPF_RET|BPF_K,(u32_t)k);
		cpu_steer_code.push_back(jeq);
		cpu_steer_code.push_back(ret);
	}
	struct sock_filter hash=BPF_STMT(BPF_RET|BPF_K,0xffffffffu);
	cpu_steer_code.push_back(hash);
}

//A5：组里全部成员已入组（TCP 在 listen 时，按 worker 次序，下标 k 即 worker k）之后挂到任一成员上即作用于整组。
//只挂 TCP（D73）：UDP 每个数据报都要选一次，WireGuard 入口、分片、veth 等情形下同一客户端的收包 CPU 不断变化，会在几个 worker 上各建会话。
//失败（要 4.6）只是按哈希分配：第一次 warn，之后 debug
static void cpu_steer_attach(forward_rule_t &rule)
{
	static int warned=0;
	struct sock_fprog prog;
	prog.len=(unsigned short)cpu_steer_code.size();
	prog.filter=&cpu_steer_code[0];
	if(setsockopt(rule.local_listen_fd_tcp,SOL_SOCKET,SO_ATTACH_REUSEPORT_CBPF,&prog,sizeof(prog))==0) return;
	mylog(warned?log_debug:log_warn,"rule %d [tcp] setsockopt SO_ATTACH_REUSEPORT_CBPF failed (%s): steering by cpu needs Linux 4.6 or later, new connections are spread by hash\n",
		rule.index,get_sock_error());
	warned=1;
}

//D107：remote 指回本进程的监听（自环或跨规则成环）。一条流每过一跳就成为同一监听的新客户端，直到 fd 或 max_conn_num 用完，
//同进程的其他规则随之停转。启动时按各 remote 当时的地址查（之后 DNS 变成本机地址不查）：边 = 规则 u 的某个 remote 落到规则 v 的同协议监听；
//在环上的边确定时 fatal，A→B→外部这样的链照常。确定：remote 等于具体监听地址；或 TCP 通配监听（[::] 在 v6only=0 时也收 IPv4）
//同端口且 remote 是回环、未指定或本机网卡地址（TCP 监听在时，别的 socket 绑不了同端口的具体地址，只有之后起来的同 uid SO_REUSEPORT socket 能）。UDP 通配监听那种只 warn：
//带 SO_REUSEADDR 的 UDP socket 能与它共存并接走发往具体地址的包（如 systemd-resolved 的 127.0.0.53:53）
struct loop_edge_t
{
	int from,to;//规则下标
	size_t remote;
	int sure;
};
static void loop_ip(const address_t &a,in6_addr &ip)//IPv4 写成 v4-mapped
{
	if(a.inner.ipv4.sin_family==AF_INET)
	{
		memset(&ip,0,sizeof(ip));
		ip.s6_addr[10]=ip.s6_addr[11]=0xff;
		memcpy(&ip.s6_addr[12],&a.inner.ipv4.sin_addr,4);
	}
	else ip=a.inner.ipv6.sin6_addr;
}
static int loop_port(const address_t &a)
{
	return ntohs(a.inner.ipv4.sin_family==AF_INET?a.inner.ipv4.sin_port:a.inner.ipv6.sin6_port);
}
//remote 是否落到 rule 的 tcp（udp=0）或 udp 监听上；落到时 sure 为 0 表示可能被更具体的 socket 接走
static int loop_reaches(const address_t &remote,forward_rule_t &rule,int udp,const vector<in6_addr> &locals,int &sure)
{
	static const unsigned char v4any[16]={0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0};
	if(loop_port(remote)!=loop_port(rule.local_addr)) return 0;
	in6_addr ip,l;
	loop_ip(remote,ip);
	loop_ip(rule.local_addr,l);
	int v4=IN6_IS_ADDR_V4MAPPED(&ip);
	if(v4?memcmp(ip.s6_addr,v4any,16)==0:IN6_IS_ADDR_UNSPECIFIED(&ip))//connect 到未指定地址实际发往回环
	{
		if(v4) ip.s6_addr[12]=127,ip.s6_addr[15]=1;
		else ip=in6addr_loopback;
	}
	sure=1;
	if(memcmp(&ip,&l,sizeof(ip))==0) return 1;
	if(memcmp(l.s6_addr,v4any,16)==0)
	{
		if(!v4) return 0;
	}
	else if(IN6_IS_ADDR_UNSPECIFIED(&l))
	{
		int v6only=0;
		socklen_t len=sizeof(v6only);
		getsockopt(udp?rule.local_listen_fd_udp:rule.local_listen_fd_tcp,IPPROTO_IPV6,IPV6_V6ONLY,&v6only,&len);
		if(v4&&v6only) return 0;
	}
	else return 0;
	int local=v4?ip.s6_addr[12]==127:IN6_IS_ADDR_LOOPBACK(&ip);
	for(size_t i=0;i<locals.size()&&!local;i++)
		local=memcmp(&locals[i],&ip,sizeof(ip))==0;
	sure=!udp;
	return local;
}
static int loop_path(const vector<loop_edge_t> &edges,int from,int to,int sure_only)//from 能否经边走到 to
{
	vector<int> seen(app_config.rules.size(),0),stack(1,from);
	seen[from]=1;
	while(!stack.empty())
	{
		int u=stack.back();
		stack.pop_back();
		if(u==to) return 1;
		for(size_t i=0;i<edges.size();i++)
			if(edges[i].from==u&&(edges[i].sure||!sure_only)&&!seen[edges[i].to])
				seen[edges[i].to]=1,stack.push_back(edges[i].to);
	}
	return 0;
}
static void check_forward_loops()
{
	vector<in6_addr> locals;
	struct ifaddrs *ifs=0;
	if(getifaddrs(&ifs)==0)
	{
		for(struct ifaddrs *p=ifs;p;p=p->ifa_next)
		{
			if(!p->ifa_addr||(p->ifa_addr->sa_family!=AF_INET&&p->ifa_addr->sa_family!=AF_INET6)) continue;
			address_t a;
			a.from_sockaddr(p->ifa_addr,p->ifa_addr->sa_family==AF_INET?sizeof(sockaddr_in):sizeof(sockaddr_in6));
			locals.push_back(in6_addr());
			loop_ip(a,locals.back());
		}
		freeifaddrs(ifs);
	}
	else mylog(log_warn,"getifaddrs failed, %s: the forwarding loop check only knows loopback addresses\n",get_sock_error());
	for(int udp=0;udp<=1;udp++)
	{
		const char *proto=udp?"udp":"tcp";
		vector<loop_edge_t> edges;
		for(size_t u=0;u<app_config.rules.size();u++)
		{
			forward_rule_t &from=worker_rule(*workers[0],u);
			if(!(udp?from.enable_udp:from.enable_tcp)) continue;
			for(size_t j=0;j<from.remote_targets.size();j++)
				for(size_t v=0;v<app_config.rules.size();v++)
				{
					forward_rule_t &to=worker_rule(*workers[0],v);
					loop_edge_t e;
					if((udp?to.enable_udp:to.enable_tcp)&&loop_reaches(from.remote_targets[j].addr,to,udp,locals,e.sure))
					{
						e.from=(int)u,e.to=(int)v,e.remote=j;
						edges.push_back(e);
					}
				}
		}
		for(size_t i=0;i<edges.size();i++)
		{
			const loop_edge_t &e=edges[i];
			if(!loop_path(edges,e.to,e.from,e.sure)) continue;
			forward_rule_t &from=worker_rule(*workers[0],e.from),&to=worker_rule(*workers[0],e.to);
			remote_target_t &r=from.remote_targets[e.remote];
			char remote[max_remote_len+max_addr_len+4],listen_addr[max_addr_len],via[64]="";
			if(r.is_domain)
			{
				char addr[max_addr_len];
				r.addr.to_str(addr);
				snprintf(remote,sizeof(remote),"%s (%s)",r.remote_str,addr);
			}
			else snprintf(remote,sizeof(remote),"%s",r.remote_str);
			to.local_addr.to_str(listen_addr);
			if(e.to!=e.from) snprintf(via,sizeof(via),", which forwards back to rule %d",from.index);
			if(e.sure)
			{
				mylog(log_fatal,"rule %d [%s] remote %s reaches the listen address %s of rule %d%s: forwarding loop\n",
					from.index,proto,remote,listen_addr,to.index,via);
				myexit(-1);
			}
			mylog(log_warn,"rule %d [%s] remote %s has the port of the wildcard listen address %s of rule %d%s: forwarding loop unless another socket is bound to that address and port\n",
				from.index,proto,remote,listen_addr,to.index,via);
		}
	}
}

//建第 i 条规则的监听（M2，S2）：每个 worker 一个 socket；N>1 时都设 SO_REUSEPORT，内核按四元组哈希（--cpu-affinity 时 TCP 先按 CPU，M5）把新连接与 UDP 流分给它们。由主线程在启动
//worker 线程之前全部建好、bind 完，组成员在进程生命周期内固定（同 uid 的另一个 N>1 实例加入 UDP 组时除外，见 listen_probe）：成员一变，
//UDP 四元组到 socket 的映射就整体重排。
//N=1 时与 M2 之前一样只设 SO_REUSEADDR（D67）：一个监听用不着分流，reuseport 却让发往监听的每个 SYN 与数据报在 softirq 里多一次选择
//（loopback 实测 1400 B 单流正向客户端发包 −3%、转发器每数据报 CPU +2.5%）
static void start_forward_rule(size_t i)
{
	forward_rule_t &rule0=worker_rule(*workers[0],i);
	char listen_addr[max_addr_len];
	rule0.local_addr.to_str(listen_addr);
	int yes=1;

	if(rule0.enable_tcp)
	{
		listen_probe(rule0,SOCK_STREAM,"tcp",listen_addr);
		for(size_t k=0;k<workers.size();k++)
		{
			worker_t &w=*workers[k];
			forward_rule_t &rule=worker_rule(w,i);
			rule.local_listen_fd_tcp=socket(rule.local_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
			if(rule.local_listen_fd_tcp<0)
			{
				mylog(log_fatal,"rule %d [tcp] create listen socket failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}

			setsockopt(rule.local_listen_fd_tcp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
			if(worker_count>1&&setsockopt(rule.local_listen_fd_tcp, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))!=0)
			{
				mylog(log_fatal,"rule %d [tcp] setsockopt SO_REUSEPORT failed on %s (needs Linux 3.9 or later), %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}
			//accept 得到的 socket 继承监听 socket 的 TCP_NODELAY，客户端一侧不必每个连接再设一次
			if(!disable_tcp_nodelay)
				setsockopt(rule.local_listen_fd_tcp, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
			//accept 得到的 socket 也继承缓冲大小和 SOCK_*BUF_LOCK 锁位：只有 --sock-buf 时在这里设一次
			if(sock_buf_explicit)
				set_buf_size(rule.local_listen_fd_tcp,socket_buf_size);

			if(::bind(rule.local_listen_fd_tcp, (struct sockaddr*) &rule.local_addr.inner, rule.local_addr.get_len()) !=0)
			{
				mylog(log_fatal,"rule %d [tcp] socket bind failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}

			if(listen(rule.local_listen_fd_tcp, listen_backlog) !=0)
			{
				mylog(log_fatal,"rule %d [tcp] socket listen failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}

			ev_io_init(&rule.tcp_accept_watcher, tcp_accept_cb, rule.local_listen_fd_tcp, EV_READ);
			rule.tcp_accept_watcher.data=&rule;
			ev_io_start(w.loop, &rule.tcp_accept_watcher);
		}
		if(!cpu_steer_code.empty()) cpu_steer_attach(rule0);
	}

	if(rule0.enable_udp)
	{
		listen_probe(rule0,SOCK_DGRAM,"udp",listen_addr);
		int gro_warned=0,pktinfo_warned=0;
		for(size_t k=0;k<workers.size();k++)
		{
			worker_t &w=*workers[k];
			forward_rule_t &rule=worker_rule(w,i);
			rule.local_listen_fd_udp=socket(rule.local_addr.get_type(), SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_UDP);
			if(rule.local_listen_fd_udp<0)
			{
				mylog(log_fatal,"rule %d [udp] create listen socket failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}

			setsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
			if(worker_count>1&&setsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))!=0)
			{
				mylog(log_fatal,"rule %d [udp] setsockopt SO_REUSEPORT failed on %s (needs Linux 3.9 or later), %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}
			set_udp_buf_size(rule.local_listen_fd_udp,listen_fd_buf_size);
			if(k==0)//各 worker 的监听 socket 同样设置，每条规则只记一行（S11）
			{
				//内核保存的是请求值的 2 倍；没有 CAP_NET_ADMIN 时先被 rmem_max/wmem_max 截断（6.18 以前默认 212992）
				int rcv=0,snd=0;
				socklen_t opt_len=sizeof(rcv);
				getsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_RCVBUF, &rcv, &opt_len);
				opt_len=sizeof(snd);
				getsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_SNDBUF, &snd, &opt_len);
				if(rcv<2*listen_fd_buf_size||snd<2*listen_fd_buf_size)
					mylog(log_info,"rule %d [udp] listen socket buffers are rcv %d / snd %d bytes instead of %d: capped by net.core.rmem_max/wmem_max, raise them to at least %d or run with CAP_NET_ADMIN\n",
						rule.index,rcv,snd,2*listen_fd_buf_size,listen_fd_buf_size);
			}
			if(udp_gro) udp_gro_listen(rule,gro_warned);
			udp_pktinfo_listen(rule,pktinfo_warned);

			if(::bind(rule.local_listen_fd_udp, (struct sockaddr*) &rule.local_addr.inner, rule.local_addr.get_len()) !=0)
			{
				mylog(log_fatal,"rule %d [udp] socket bind failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
				myexit(1);
			}

			ev_io_init(&rule.udp_accept_watcher, udp_accept_cb, rule.local_listen_fd_udp, EV_READ);
			rule.udp_accept_watcher.data=&rule;
			ev_io_start(w.loop, &rule.udp_accept_watcher);
		}
	}
}

//主线程（D62）：默认 loop 只管信号、DNS、统计汇总与刷新日志；转发全在 worker 线程，每个 worker 一个 ev_loop_new 的 epoll loop（§5）。
//worker、规则运行时、监听与各 watcher 都由主线程在启动 worker 线程之前建好（之后主线程只经 worker_post 访问 worker）
int event_loop()
{
	struct ev_loop * loop= ev_default_loop(0);
	assert(loop != NULL);
	mylog(log_info,"event backend: %s\n",ev_backend(loop)==EVBACKEND_EPOLL?"epoll":"unknown");
	main_clock.loop=loop;
	unordered_map<address_t,int,address_t::hash_function> tcp_listen_rules;
	unordered_map<address_t,int,address_t::hash_function> udp_listen_rules;
	tcp_listen_rules.reserve(app_config.rules.size());
	udp_listen_rules.reserve(app_config.rules.size());

	if(app_config.rules.empty())
	{
		mylog(log_fatal,"no forward rules configured\n");
		myexit(-1);
	}
	rule_shared=new rule_shared_t[app_config.rules.size()];
	for(size_t i=0;i<app_config.rules.size();i++)
		if(app_config.rules[i].balance_strategy==balance_strategy_roundrobin)
			rr_build_seq(app_config.rules[i].balance_weights,rule_shared[i].rr_seq);
	if(cpu_affinity) cpu_affinity_init();

	for(int k=0;k<worker_count;k++)
	{
		struct ev_loop *l=ev_loop_new(EVBACKEND_EPOLL);
		if(l==0||ev_backend(l)!=EVBACKEND_EPOLL)
		{
			mylog(log_fatal,"failed to create epoll event loop for worker %d\n",k);
			myexit(-1);
		}
		worker_t *w=worker_new(k,l);
		workers.push_back(w);
		for(size_t i=0;i<app_config.rules.size();i++)
			worker_add_rule(w,i);
	}
	mylog(log_info,"worker threads: %d\n",worker_count);

	int any_udp=0;
	for(size_t i=0;i<app_config.rules.size();i++)
	{
		forward_rule_t &rule=worker_rule(*workers[0],i);
		if(rule.enable_tcp)
		{
			check_and_record_listen(tcp_listen_rules,rule,"tcp");
		}
		if(rule.enable_udp)
		{
			check_and_record_listen(udp_listen_rules,rule,"udp");
			any_udp=1;
		}
		start_forward_rule(i);
	}
	check_forward_loops();

	//DNS 主表（S5）：每个域名 remote 一项，启动时算作刚刷新过
	my_time_t now=main_clock.now();
	for(size_t i=0;i<app_config.rules.size();i++)
	{
		for(size_t j=0;j<app_config.rules[i].remote_targets.size();j++)
		{
			const remote_target_config_t &config_target=app_config.rules[i].remote_targets[j];
			if(!config_target.is_domain) continue;
			dns_target_t target;
			target.rule_index=(int)i+1;
			target.remote_index=(int)j;
			snprintf(target.host,sizeof(target.host),"%s",config_target.host);
			target.port=config_target.port;
			target.addr=config_target.addr;
			target.last_dns_refresh_time=now;
			target.dns_query_pending=0;
			target.dns_stuck_warned=0;
			dns_targets.push_back(target);
		}
	}

	struct ev_timer main_timer;
	ev_timer_init(&main_timer, main_timer_cb, 0, timer_interval/1000.0);
	ev_timer_start(loop, &main_timer);
	//这几个 watcher 已清零（BSS、worker_t 的构造函数），等同 ev_init；只填回调与参数，不用 ev_*_init 宏：不新增 strict-aliasing 告警
	stats_watcher.cb=stats_reply_cb;
	ev_async_start(loop, &stats_watcher);

	for(size_t k=0;k<workers.size();k++)
	{
		worker_t *w=workers[k];
		w->tick_timer.cb=clear_timer_cb;
		w->tick_timer.repeat=timer_interval/1000.0;//at 为 0：同 ev_timer_init(…, 0, timer_interval)，第一轮就跑一次
		w->tick_timer.data=w;
		ev_timer_start(w->loop, &w->tick_timer);
		w->ctrl_watcher.cb=worker_ctrl_cb;
		w->ctrl_watcher.data=w;
		ev_async_start(w->loop, &w->ctrl_watcher);
		w->udp_flush_watcher.cb=udp_flush_cb;
		w->udp_flush_watcher.data=w;
		if(any_udp)
			ev_prepare_start(w->loop, &w->udp_flush_watcher);
	}

	sem_init(&workers_exited,0,0);
	//worker 线程与 DNS 线程屏蔽信号（D62）：发给进程的信号都由主线程上 libev 的处理函数接住；worker 写向已 RST 的对端产生的 SIGPIPE
	//留在那个线程上待决，不处理（send/splice 照样返回 EPIPE）。abort() 用的 SIGABRT 与同步的故障信号不屏蔽（审查 L-3：musl 1.1.20
	//以前的 abort() 不解除屏蔽，worker 里的中止会变成 SIGSEGV/SIGILL）
	sigset_t all,old;
	sigfillset(&all);
	sigdelset(&all,SIGABRT);
	sigdelset(&all,SIGSEGV);
	sigdelset(&all,SIGBUS);
	sigdelset(&all,SIGFPE);
	sigdelset(&all,SIGILL);
	sigdelset(&all,SIGTRAP);
	pthread_sigmask(SIG_BLOCK,&all,&old);
	start_dns_worker(loop);
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr,worker_stack_size);
	for(size_t k=0;k<workers.size();k++)
	{
		int err=pthread_create(&workers[k]->thread,&attr,worker_main,workers[k]);
		if(err!=0)
		{
			mylog(log_fatal,"create thread for worker %d failed, %d:%s\n",(int)k,err,strerror(err));
			myexit(-1);
		}
	}
	pthread_attr_destroy(&attr);
	pthread_sigmask(SIG_SETMASK,&old,0);

	ev_run(loop, 0);
	myexit(0);
	return 0;
}
void print_help()
{
	char git_version_buf[100]={0};
	strncpy(git_version_buf,gitversion,10);

	printf("\n");
	printf("tinyPortMapper\n");
	printf("git version:%s    ",git_version_buf);
	printf("build date:%s %s\n",__DATE__,__TIME__);
	printf("repository: https://github.com/wangyu-/tinyPortMapper\n");
	printf("\n");
	printf("usage:\n");
	printf("    ./this_program  -l <listen_ip>:<listen_port> -r <remote_ip_or_domain>:<remote_port> [-r <remote_ip_or_domain>:<remote_port> ...] [options]\n");
	printf("    ./this_program  -c <config_file>  [options]\n");
	printf("\n");

	printf("main options:\n");
	printf("    -c, --config <path>                 use config file\n");
	printf("    -l <listen_ip>:<listen_port>        listen address\n");
	printf("    -r <remote_ip_or_domain>:<remote_port> remote target, can be repeated\n");
	printf("    --balance <strategy: weights>       load balance repeated -r remotes, strategies: roundrobin, iphash\n");
	printf("    -t                                  enable TCP forwarding/mapping\n");
	printf("    -u                                  enable UDP forwarding/mapping\n");
	printf("    remote supports IPv4, [IPv6], or hostname; hostname is refreshed every 30s\n");
	printf("\n");

	printf("other options:\n");
	printf("    --sock-buf            <number>        buf size for socket, >=10 and <=10240, unit: kbyte\n");
	printf("                                          TCP: kernel autotuning if not set; setting it disables autotuning\n");
	printf("                                          and is capped by net.core.rmem_max/wmem_max; UDP sessions: default 1024\n");
	printf("    --udp-listen-buf      <number>        buf size for UDP listen sockets, >=10 and <=10240, unit: kbyte, default 2048\n");
	printf("                                          UDP buffers are capped by net.core.rmem_max/wmem_max unless running with CAP_NET_ADMIN\n");
	printf("                                          (UDP sessions: set past the cap only for a --sock-buf value, or with --udp-gro\n");
	printf("                                          for the send buffer, which then takes this size if larger)\n");
	printf("    --disable-tcp-nodelay                 do not set TCP_NODELAY on forwarded TCP connections (set on both sides by default)\n");
	printf("    --disable-splice                      forward TCP by recv/send copies only; by default a direction whose last read\n");
	printf("                                          was at least 16 KiB moves the next one with splice through a pipe\n");
	printf("    --pipe-size           <number>        pipe size for TCP splice, >=64 and <=1024, unit: kbyte, default 256\n");
	printf("                                          above 256, bulk throughput rises and other connections wait longer\n");
	printf("    --udp-gro                             receive UDP with UDP_GRO and forward merged packets with UDP_SEGMENT (GSO),\n");
	printf("                                          Linux 5.0 or later, off by default\n");
	printf("    --threads             <number|auto>   worker threads, >=1 and <=64, default 1; auto: the usable CPUs, at most 8.\n");
	printf("                                          above 1, every rule gets one SO_REUSEPORT listener per worker (Linux 3.9+)\n");
	printf("    --cpu-affinity                        pin worker i to the i-th usable CPU; above 1 worker, also send each new TCP\n");
	printf("                                          connection to the worker on the CPU that received it (Linux 4.6+),\n");
	printf("                                          off by default; needs the NIC's receive queues spread over those CPUs\n");
	printf("    --log-level           <number>        0: never    1: fatal   2: error   3: warn \n");
	printf("                                          4: info (default)      5: debug   6: trace\n");
	printf("    --log-position                        enable file name, function name, line number in log\n");
	printf("    --disable-color                       disable log color\n");
	printf("    --enable-color                        enable log color, log color is enabled by default on most platforms\n");
	printf("    -h,--help                             print this help message\n");
	printf("\n");


	//printf("common options,these options must be same on both side\n");
}
//命令行数值选项的值只认十进制数字：符号、空白、单位后缀、十六进制、空串与超过 INT_MAX 都返回 -1，由调用方按越界报错（D100；
//sscanf("%d") 会把 "512k" 读成 512、"4294968320" 回绕成 1024）
static int parse_uint_arg(const char *s)
{
	if(s[0]==0) return -1;
	int value=0;
	for(const char *p=s;*p;p++)
	{
		if(*p<'0'||*p>'9') return -1;
		if(value>(INT_MAX-(*p-'0'))/10) return -1;
		value=value*10+(*p-'0');
	}
	return value;
}
void process_arg(int argc, char *argv[])
{
	int i;
	int opt;
    static struct option long_options[] =
      {
		{"config", required_argument,    0, 'c'},
		{"balance", required_argument,    0, 1},
		{"log-level", required_argument,    0, 1},
		{"log-position", no_argument,    0, 1},
		{"disable-color", no_argument,    0, 1},
		{"enable-color", no_argument,    0, 1},
		{"sock-buf", required_argument,    0, 1},
		{"udp-listen-buf", required_argument,    0, 1},
		{"disable-tcp-nodelay", no_argument,    0, 1},
		{"disable-splice", no_argument,    0, 1},
		{"pipe-size", required_argument,    0, 1},
		{"udp-gro", no_argument,    0, 1},
		{"threads", required_argument,    0, 1},
		{"cpu-affinity", no_argument,    0, 1},
		{NULL, 0, 0, 0}
      };
    int option_index = 0;
	if (argc == 1)
	{
		print_help();
		myexit( -1);
	}
	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"-h")==0||strcmp(argv[i],"--help")==0)
		{
			print_help();
			myexit(0);
		}
	}
	//日志级别和颜色要在第一行日志之前定下来，所以先用同一张 long_options 单独过一遍 getopt_long：
	//--log-level=N、缩写、"--" 之后不再解析、哪个参数被当作选项的值，都与下面的正式解析一致。
	//在 argv 的副本上做（GNU getopt 会重排 argv，下面回显的仍是原始顺序）；opterr=0，未知选项、缺值等留给正式解析报
	vector<char*> argv_copy(argv,argv+argc+1);
	opterr=0;
	optind=1;
	while ((opt = getopt_long(argc, &argv_copy[0], "c:l:r:tuh",long_options,&option_index)) != -1)
	{
		if(opt!=1) continue;
		if(strcmp(long_options[option_index].name,"log-level")==0)
		{
			int tmp=parse_uint_arg(optarg);
			if(0<=tmp&&tmp<log_end)
			{
				log_level=tmp;
			}
			else
			{
				log_bare(log_fatal,"invalid log_level\n");
				myexit(-1);
			}
		}
		else if(strcmp(long_options[option_index].name,"disable-color")==0)
		{
			enable_log_color=0;
		}
		else if(strcmp(long_options[option_index].name,"enable-color")==0)
		{
			enable_log_color=1;
		}
	}
	opterr=1;

    mylog(log_info,"argc=%d ", argc);

	for (i = 0; i < argc; i++) {
		log_bare(log_info, "%s ", argv[i]);
	}
	log_bare(log_info, "\n");

	if (argc == 1)
	{
		print_help();
		myexit(-1);
	}

	app_config.rules.clear();
	const char *config_path=0;
	const char *local_arg=0;
	vector<const char*> remote_args;
	const char *balance_arg=0;
	int no_l = 1;
	int cli_enable_tcp=0,cli_enable_udp=0;
	int used_cli_rule_option=0;

	optind=1;
	while ((opt = getopt_long(argc, argv, "c:l:r:tuh",long_options,&option_index)) != -1)
	{
		switch (opt)
		{
		case 'c':
			if(config_path!=0)
			{
				mylog(log_fatal,"duplicate -c/--config option\n");
				myexit(-1);
			}
			config_path=optarg;
			break;
		case 'l':
			if(local_arg!=0)
			{
				mylog(log_fatal,"duplicate -l option\n");
				myexit(-1);
			}
			no_l = 0;
			local_arg=optarg;
			used_cli_rule_option=1;
			break;
		case 'r':
			remote_args.push_back(optarg);
			used_cli_rule_option=1;
			break;
		case 't':
			cli_enable_tcp=1;
			used_cli_rule_option=1;
			break;
		case 'u':
			cli_enable_udp=1;
			used_cli_rule_option=1;
			break;
		case 'h':
			break;
		case 1:
			if(strcmp(long_options[option_index].name,"log-level")==0)//log-level、disable-color、enable-color 已在开头的预扫描里处理
			{
			}
			else if(strcmp(long_options[option_index].name,"disable-color")==0)
			{
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"enable-color")==0)
			{
				//enable_log_color=0;
			}
			else if(strcmp(long_options[option_index].name,"log-position")==0)
			{
				enable_log_position=1;
			}
			else if(strcmp(long_options[option_index].name,"balance")==0)
			{
				if(balance_arg!=0)
				{
					mylog(log_fatal,"duplicate --balance option\n");
					myexit(-1);
				}
				balance_arg=optarg;
				used_cli_rule_option=1;
			}
			else if(strcmp(long_options[option_index].name,"sock-buf")==0)
			{
				int tmp=parse_uint_arg(optarg);
				if(10<=tmp&&tmp<=10*1024)
				{
					socket_buf_size=tmp*1024;
					sock_buf_explicit=1;
				}
				else
				{
					mylog(log_fatal,"sock-buf value must be between 10 and 10240 (kbyte)\n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"udp-listen-buf")==0)
			{
				int tmp=parse_uint_arg(optarg);
				if(10<=tmp&&tmp<=10*1024)
				{
					listen_fd_buf_size=tmp*1024;
				}
				else
				{
					mylog(log_fatal,"udp-listen-buf value must be between 10 and 10240 (kbyte)\n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"disable-tcp-nodelay")==0)
			{
				disable_tcp_nodelay=1;
			}
			else if(strcmp(long_options[option_index].name,"disable-splice")==0)
			{
				disable_splice=1;
			}
			else if(strcmp(long_options[option_index].name,"pipe-size")==0)
			{
				int tmp=parse_uint_arg(optarg);
				if(64<=tmp&&tmp<=1024)
				{
					tcp_pipe_size=tmp*1024;
					pipe_size_explicit=1;
				}
				else
				{
					mylog(log_fatal,"pipe-size value must be between 64 and 1024 (kbyte)\n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"udp-gro")==0)
			{
				udp_gro=1;
			}
			else if(strcmp(long_options[option_index].name,"cpu-affinity")==0)
			{
				cpu_affinity=1;
			}
			else if(strcmp(long_options[option_index].name,"threads")==0)
			{
				int tmp=-1;
				if(strcmp(optarg,"auto")==0)
				{
					//可用的 CPU（taskset/cpuset 限制之后的），最多 worker_count_auto_max 个（D5）
					cpu_set_t set;
					CPU_ZERO(&set);
					tmp=1;
					if(sched_getaffinity(0,sizeof(set),&set)==0&&CPU_COUNT(&set)>0) tmp=CPU_COUNT(&set);
					tmp=min(tmp,worker_count_auto_max);
				}
				else
					tmp=parse_uint_arg(optarg);
				if(1<=tmp&&tmp<=worker_count_max)
				{
					worker_count=tmp;
				}
				else
				{
					mylog(log_fatal,"threads value must be between 1 and %d, or auto\n",worker_count_max);
					myexit(-1);
				}
			}
			else
			{
				mylog(log_fatal,"unknown option\n");
				myexit(-1);
			}
			break;
		default://具体原因 getopt_long 已经写到 stderr（已并到 stdout）
			mylog(log_fatal,"invalid command line option, see -h\n");
			myexit(-1);
		}
	}
	if(optind<argc)//多余的位置参数（"-r a:1 b:2" 里的 b:2、"--" 之后的参数）以前被静默忽略（D101）
	{
		mylog(log_fatal,"unexpected argument '%s'\n",argv[optind]);//加引号：空参数（如 systemd 的 ${VAR} 未设置）显示为 ''
		myexit(-1);
	}

	if(config_path!=0)
	{
		if(used_cli_rule_option)
		{
			mylog(log_fatal,"-c/--config cannot be combined with -l/-r/-t/-u/--balance\n");
			myexit(-1);
		}
		struct stat st;
		if(stat(config_path,&st)!=0)
		{
			mylog(log_fatal,"config file %s cannot be accessed\n",config_path);
			myexit(-1);
		}
		if(!S_ISREG(st.st_mode))
		{
			mylog(log_fatal,"config path %s must be a regular file\n",config_path);
			myexit(-1);
		}
		load_config_file(config_path,app_config);
	}
	else
	{
		if (no_l)
			mylog(log_fatal,"error: -l not found\n");
		if (remote_args.empty())
			mylog(log_fatal,"error: -r not found\n");
		if (no_l || remote_args.empty())
			myexit(-1);

		if(cli_enable_tcp==0&&cli_enable_udp==0)
		{
			mylog(log_fatal,"you must specify -t or -u or both\n");
			myexit(-1);
		}

		if(strlen(local_arg)>=max_addr_len)
		{
			mylog(log_fatal,"-l address is too long\n");
			myexit(-1);
		}
		if(remote_args.size()>(size_t)max_remote_targets)
		{
			mylog(log_fatal,"too many -r remote targets\n");
			myexit(-1);
		}
		for(size_t remote_i=0;remote_i<remote_args.size();remote_i++)
		{
			if(strlen(remote_args[remote_i])>=max_remote_len)
			{
				mylog(log_fatal,"-r address is too long\n");
				myexit(-1);
			}
		}

		forward_rule_config_t rule;
		rule.enable_tcp=cli_enable_tcp;
		rule.enable_udp=cli_enable_udp;
		snprintf(rule.listen_str,sizeof(rule.listen_str),"%s",local_arg);
		char err[dns_error_len];
		if(rule.local_addr.from_str(rule.listen_str,err,sizeof(err))!=0)
		{
			mylog(log_fatal,"-l %s: %s\n",local_arg,err);
			myexit(-1);
		}
		rule.remote_targets.reserve(remote_args.size());
		for(size_t remote_i=0;remote_i<remote_args.size();remote_i++)
		{
			remote_target_config_t target;
			if(parse_remote_config_target(remote_args[remote_i],target,err,sizeof(err))!=0)
			{
				mylog(log_fatal,"-r remote: %s\n",err);
				myexit(-1);
			}
			rule.remote_targets.push_back(target);
		}
		if(parse_balance_spec(balance_arg,(int)rule.remote_targets.size(),rule.balance_strategy,rule.balance_weights,err,sizeof(err))!=0)
		{
			mylog(log_fatal,"--balance: %s\n",err);
			myexit(-1);
		}
		app_config.rules.push_back(rule);
	}

	if(app_config.rules.empty())
	{
		mylog(log_fatal,"no forward rules configured\n");
		myexit(-1);
	}
}

int unit_test()
{
	//lru_cache_t<string,u64_t> cache;

	address_t::hash_function hash;
	address_t test;
	test.from_str((char*)"[2001:19f0:7001:1111:00:ff:11:22]:443",0,0);
	printf("%s\n",test.get_str());
	printf("%d\n",hash(test));
	test.from_str((char*)"44.55.66.77:443",0,0);
	printf("%s\n",test.get_str());
	printf("%d\n",hash(test));

	return 0;
}

int main(int argc, char *argv[])
{
	//启动时关着的 0/1/2 先用 /dev/null 补上，再把 stderr 并到 stdout，之后 libev 的 epoll fd、eventfd 与各 socket 都从 3 起分配。
	//不补时它们会落到这几个号上，被 dup2(1,2) 覆盖或被当成 stdout：2>&- 时首次 epoll_wait 中止，>&- 2>&- 时信号、DNS 结果、统计都送不到主线程
	for(int fd=0;fd<=2;fd++)
	{
		if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF) continue;
		if(open("/dev/null",O_RDWR)!=fd)//按 0、1、2 的顺序补，open 返回最小的空闲号
		{
			mylog(log_fatal,"failed to open /dev/null for fd %d\n",fd);
			myexit(-1);
		}
	}
	dup2(1, 2);		//redirect stderr to stdout
    struct ev_loop* loop=ev_default_loop(0);
    if(loop==NULL)
    {
        mylog(log_fatal,"failed to create epoll event loop\n");
        myexit(-1);
    }
    ev_signal signal_watcher_sigpipe;
    ev_signal_init(&signal_watcher_sigpipe, sigpipe_cb, SIGPIPE);
    ev_signal_start(loop, &signal_watcher_sigpipe);

    ev_signal signal_watcher_sigusr1;
    ev_signal_init(&signal_watcher_sigusr1, sigusr1_cb, SIGUSR1);
    ev_signal_start(loop, &signal_watcher_sigusr1);

	//unit_test();
	assert(sizeof(u64_t)==8);
	assert(sizeof(i64_t)==8);
	assert(sizeof(u32_t)==4);
	assert(sizeof(i32_t)==4);
	int i, j, k;
	process_arg(argc,argv);
	//SIGTERM、SIGINT 解析完参数才交给 libev（D105）：process_arg 里同步解析域名 remote，解析器在 EINTR 后接着等，期间保持默认处置，收到即终止；
	//之后的启动步骤都很快，信号留到 ev_run 走有序退出。SIGPIPE、SIGUSR1 在上面就接住：它们的默认处置也是终止进程
    ev_signal signal_watcher_sigterm;
    ev_signal_init(&signal_watcher_sigterm, sigterm_cb, SIGTERM);
    ev_signal_start(loop, &signal_watcher_sigterm);

    ev_signal signal_watcher_sigint;
    ev_signal_init(&signal_watcher_sigint, sigint_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher_sigint);

	if(!disable_splice) tcp_pipe_probe();

	event_loop();

	return 0;
}
