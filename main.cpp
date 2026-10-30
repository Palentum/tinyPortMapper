#include "common.h"
#include "log.h"
#include "git_version.h"
#include "config.h"

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>

using  namespace std;

typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;

int disable_conn_clear=0;
int disable_tcp_nodelay=0;
int disable_splice=0;//--disable-splice（D48）：TCP 只走 recv/send 拷贝路径，不创建 pipe
int sock_buf_explicit=0;//给了 --sock-buf：TCP socket 才设 SO_SNDBUF/SO_RCVBUF，否则交给内核自动调优
//--udp-gro（U5，D41）：UDP 监听与会话 socket 开 UDP_GRO，收到的 GRO 合并包整包带 UDP_SEGMENT 转发。第一个监听 socket 开不了
//（5.0 以前的内核）时清零，这时还没有 socket 开着 UDP_GRO；为 1 时 udp_batch 的 in/rin 带着收 cmsg 的控制缓冲
int udp_gro=0;

int max_pending_packet=0;

static app_config_t app_config;

int listen_fd_buf_size=2*1024*1024;//UDP 监听 socket 的 SO_SNDBUF/SO_RCVBUF，--udp-listen-buf
static const u32_t dns_refresh_interval=30000;
static const int max_accept_per_round=8;
//内核把 listen backlog 截断为所在网络命名空间的 net.core.somaxconn（5.4 起默认 4096，以前 128）。不用 SOMAXCONN：musl 与 glibc 2.31 以前都定义为 128；不超过 65535：4.1 以前 sk_max_ack_backlog 是 u16
static const int listen_backlog=65535;
static const my_time_t lru_move_interval=1000;
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
	lru_collector_t(const lru_collector_t &)=delete;
	lru_collector_t & operator=(const lru_collector_t &)=delete;
	lru_collector_t()
	{
		head.prev=head.next=&head;
		cnt=0;
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
	int update(key_t key)
	{
		DEBUG_ASSERT(key->next!=0);

		my_time_t value=get_current_time();
		DEBUG_ASSERT(value >=head.next->ts);
		//距上次挪动不到 lru_move_interval 就不挪：链表仍按 ts 有序，ts 最多比实际最后活动早这么多，超时最多提前这么多（T8）
		if(value-key->ts<lru_move_interval) return 0;
		key->ts=value;
		unlink(key);
		link_front(key);

		return 0;
	}
	int new_key(key_t key)
	{
		DEBUG_ASSERT(key->next==0);

		my_time_t value=get_current_time();
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
//一次 splice 进 pipe 最多读这么多（D51，同 recv 的 64 KiB）：背压时它整段留在方向持有的 pipe 里，是不计入 tcp_mem 与 memcg 的内核页。
//5.12 起内核按 pipe 剩余空间截断（默认 16 × PAGE_SIZE，4K 页上恰好 64 KiB）；更早的内核不截断，16 个槽可各放一个 32 KiB 的本机片段，约 512 KiB
static const int splice_read_max=max_data_len_tcp;
//D53：splice 时一次回调最多搬这么多轮（每轮至多 splice_read_max），源端读不满或目的端没写完就停。每轮写出都可能唤醒一次接收方，
//转发器满载、源端积压时一轮一回调让每 64 KiB 唤醒一次：同进程 8 条大流量 1 轮 85、4 轮 113、8 轮 123 Gbit/s；代价是一次回调更长，
//同一轮里其他连接多等：同时测的 64 B 往返 p50 1 轮 106、4 轮 297、8 轮 549 µs（realm-1c 3950 µs）
static const int splice_rounds_max=4;
static const int tcp_pipe_min_size=65536;//新 pipe 小于它（fs.pipe-user-pages-soft 已满时只有 2 页）就不用：每次 splice 只能搬 2 个片段
static const int tcp_pipe_pool_max_free=64;//同 D19

//pipe 里还有多少字节，只给 DEBUG_ASSERT 用：还池与复用的 pipe 必须是空的，计账错了就会把一个连接的数据写给另一个连接
static inline int tcp_pipe_len(const tcp_pipe_t &p)
{
	int n=-1;
	ioctl(p.r,FIONREAD,&n);
	return n;
}

//pipe 池（B2，D47）：splice 都读进 tcp_pipe_scratch，整段写出就留着给下一次；没写完时连同数据交给该方向（tcp_info_t::pipe），
//排空后还回来。空闲的最多留 tcp_pipe_pool_max_free 个，多出的 close；有残留数据的 pipe 不复用，释放连接对时直接 close
struct tcp_pipe_pool_t
{
	tcp_pipe_t free_pipes[tcp_pipe_pool_max_free];
	int free_cnt;
	int alloc;//已创建还没关闭的 pipe 数（O1）：每个要么是 scratch，要么属于某个方向，要么在空闲表里
	int blocked;//创建失败过：到下一个定时器周期（clear_timer_cb 清零）之前不再创建，免得每次读都试
	int failures;//创建失败次数，只有第一次记 info
	tcp_pipe_pool_t()
	{
		free_cnt=0;
		alloc=0;
		blocked=0;
		failures=0;
	}
	int fail_level()//创建失败：到下一个定时器周期之前不再创建；只有第一次记 info
	{
		blocked=1;
		return failures++==0?log_info:log_debug;
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
			int level=fail_level();
			mylog(level,"[tcp]new pipe has only %d bytes (fs.pipe-user-pages-soft reached?), forwarding by copy instead of splice until the next timer tick\n",size);
			return -1;
		}
		p.r=fds[0];
		p.w=fds[1];
		alloc++;
		return 0;
	}
	void put(tcp_pipe_t &p)//p 已排空
	{
		DEBUG_ASSERT(tcp_pipe_len(p)==0);
		if(free_cnt>=tcp_pipe_pool_max_free) discard(p);
		else free_pipes[free_cnt++]=p;
		p.r=p.w=-1;
	}
	void discard(tcp_pipe_t &p)//可能还有数据：直接关掉
	{
		close(p.r);
		close(p.w);
		alloc--;
		p.r=p.w=-1;
	}
};

//每个 worker 一份（P4 移进 worker_t）
static obj_pool_t<tcp_pair_t> tcp_pair_pool;
static obj_pool_t<udp_pair_t> udp_pair_pool;
static tcp_buf_pool_t tcp_buf_pool;
static char *tcp_scratch=0;//recv 都读进这一块，读到的数据整块发完就留着给下一次 recv；没发完时整块交给该方向，下一次 recv 前再从池里取一块
static tcp_pipe_pool_t tcp_pipe_pool;
static tcp_pipe_t tcp_pipe_scratch={-1,-1};//splice 都读进它，用法同 tcp_scratch（D47）
//fd 用完（accept4、上游 socket() 或 UDP 会话 socket() 返回 EMFILE/ENFILE）时关掉空闲 pipe 与 scratch pipe，给 socket 腾出 fd，
//并暂停创建到下一个定时器周期（D52）；返回关掉的个数，不为 0 时调用方再试一次。方向持有的 pipe 里有数据，不动
static int tcp_pipe_trim()
{
	int n=tcp_pipe_pool.free_cnt+(tcp_pipe_scratch.r>=0);
	while(tcp_pipe_pool.free_cnt>0) tcp_pipe_pool.discard(tcp_pipe_pool.free_pipes[--tcp_pipe_pool.free_cnt]);
	if(tcp_pipe_scratch.r>=0) tcp_pipe_pool.discard(tcp_pipe_scratch);
	tcp_pipe_pool.blocked=1;
	if(n>0) mylog(log_debug,"[tcp]out of file descriptors, closed %d idle pipes\n",n);
	return n;
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
//收包的 cmsg（UDP_GRO，int）与发包的 cmsg（UDP_SEGMENT，u16）共用这个大小；union 保证 cmsghdr 的对齐。
//64 位 musl 的 cmsghdr 在 cmsg_len 旁有填充，内核读的是 size_t：只按字段名写，缓冲在 BSS 里，填充恒为 0
union udp_ctrl_t
{
	cmsghdr hdr;
	char buf[CMSG_SPACE(sizeof(int))];
};
//UDP 监听 socket 的入向批（U1、U3，D34）。每条消息两段 iov：2 KB 的槽（64 个连续排列，MTU 级的包只碰这里）加本消息自己的溢出区，
//合计 max_data_len_udp；溢出区是 BSS，只有大于 2 KB 的包才碰到它的页，常驻内存随大包增长，最多约 4 MiB
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
	forward_rule_t *rrule[udp_batch_max];//回包所属的规则（监听 socket 与计数），0 表示丢弃或已放进本次发出的组
	mmsghdr rout[udp_batch_max];//对监听 socket 的 sendmmsg 用，一次放一个规则的组；填充同 out，必须保持 0
	iovec rout_iov[udp_batch_max][2];
	int rn;
	//U5（--udp-gro）：ctrl[i] 收槽 i 的 cmsg，in[i] 与 rin[i] 共用（槽 i 同一时刻只属于一方）；gso[i] 是收包时从中取出的段长，
	//槽 i 里不是 GRO 合并包时为 0。out_ctrl/rout_ctrl 给发送条目挂 UDP_SEGMENT；seg 把一个合并包切开重发（udp_send_split），
	//填充同 out，必须保持 0。udp_gro 为 0 时都不用
	udp_ctrl_t ctrl[udp_batch_max];
	int gso[udp_batch_max];
	unsigned char roff[udp_batch_max];//回包所属会话收包时的 gso_off[1]（D45），按槽
	udp_ctrl_t out_ctrl[udp_batch_max];
	udp_ctrl_t rout_ctrl[udp_batch_max];
	unsigned char rout_off[udp_batch_max];//rout 第 i 条的 roff，udp_send_group 关掉 GSO 时也改它
	mmsghdr seg[udp_batch_max];
	iovec seg_iov[udp_batch_max][2];
	udp_ctrl_t seg_ctrl[udp_batch_max];
	static void init_segment(udp_ctrl_t &c)
	{
		c.hdr.cmsg_level=SOL_UDP;
		c.hdr.cmsg_type=UDP_SEGMENT;
		c.hdr.cmsg_len=CMSG_LEN(sizeof(uint16_t));//内核要求恰好是这个长度，否则 EINVAL
	}
	void attach_ctrl()//第一个监听 socket 开了 UDP_GRO 之后调用一次
	{
		for(int i=0;i<udp_batch_max;i++)
		{
			in[i].msg_hdr.msg_control=rin[i].msg_hdr.msg_control=&ctrl[i];
			in[i].msg_hdr.msg_controllen=rin[i].msg_hdr.msg_controllen=sizeof(ctrl[i]);
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
			init_segment(out_ctrl[i]);
			init_segment(rout_ctrl[i]);
			init_segment(seg_ctrl[i]);
		}
		rn=0;
	}
};
static udp_batch_t udp_batch;
//发送用的 iov：第 i 个包的前 2 KB 在 slot[i]，其余在 overflow[i]
static inline void udp_batch_set_iov(mmsghdr &m,iovec *iov,int i,int len)
{
	iov[0].iov_base=udp_batch.slot[i];
	if(len<=udp_slot_len)
	{
		iov[0].iov_len=len;
		m.msg_hdr.msg_iovlen=1;
	}
	else
	{
		iov[0].iov_len=udp_slot_len;
		iov[1].iov_base=udp_batch.overflow[i];
		iov[1].iov_len=len-udp_slot_len;
		m.msg_hdr.msg_iovlen=2;
	}
}
//U5：len 字节的包按段长 gso 切成的数据报数，gso 为 0 时是 1
static inline int udp_segs(size_t len,int gso)
{
	return gso==0?1:(int)((len+gso-1)/gso);
}
//U5：收到的条目带 UDP_GRO cmsg 时返回其中的 gso_size，否则 0；控制数据被截断（MSG_CTRUNC）时返回 -1，调用方丢掉这个包：
//段长可能就在被截掉的部分里，当成普通数据报会把合并包作为一个大数据报发出（审查 L4；内核先写 SO_TIMESTAMP 等 cmsg 再写 UDP_GRO，
//将来给这些 socket 加别的 cmsg 时要加大 udp_ctrl_t）。同时把内核改写的 msg_controllen 恢复成缓冲大小，下一次收包之前必须做。
//gso_size 是 int（按 u16 读在大端 MIPS 上得到 0）
static inline int udp_recv_gso(msghdr &h)
{
	int g=0;
	if(h.msg_flags&MSG_CTRUNC)
		g=-1;
	else
	{
		for(cmsghdr *c=CMSG_FIRSTHDR(&h);c!=0;c=CMSG_NXTHDR(&h,c))
		{
			if(c->cmsg_level==SOL_UDP&&c->cmsg_type==UDP_GRO)
			{
				memcpy(&g,CMSG_DATA(c),sizeof(g));
				break;
			}
		}
	}
	h.msg_controllen=sizeof(udp_ctrl_t);
	return g;
}
//U5：发送条目 m 发第 i 个槽里 len 字节的包，槽里是 GRO 合并包且多于 1 段时挂 UDP_SEGMENT（段长同收到的），否则不挂：
//没有 TX 校验和 offload 的出口在 6.11 以前连单段的 GSO 也报 EIO（探针实测）
static inline void udp_batch_set_gso(mmsghdr &m,udp_ctrl_t &c,int i,int len)
{
	int g=udp_batch.gso[i];
	if(g!=0&&len>g)
	{
		DEBUG_ASSERT(g<=0xffff);
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

struct conn_manager_udp_t
{
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
	unsigned char gso_logged[2];//U5：这个方向的 GSO 回退已写过一行 info，之后的写 debug（审查 L3）

	conn_manager_udp_t()
	{
		last_hit=0;
		last_clear_time=0;
		//clear_it=udp_pair_list.begin();
		total=0;
		memset(pkts,0,sizeof(pkts));
		memset(bytes,0,sizeof(bytes));
		memset(drop,0,sizeof(drop));
		memset(gro,0,sizeof(gro));
		memset(gso_fallback,0,sizeof(gso_fallback));
		memset(gso_logged,0,sizeof(gso_logged));
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

	int erase(udp_pair_t *pair)
	{
		DEBUG_ASSERT(pair->batch_group<0);
		struct ev_loop * loop= ev_default_loop (0);
		ev_io_stop(loop, &pair->ev);

		mylog(log_info,"[udp]inactive connection {%s} cleared, udp connections=%d\n",pair->adress.get_str(),lru.size()-1);
		mylog(log_debug,"[udp] lru.size()=%d\n",(int)lru.size()-1);

		//归还后对象还留着旧地址：last_hit 不清零的话，这个客户端的下一个包会命中已归还的对象
		if(last_hit==pair) last_hit=0;
		sessions.erase(pair,udp_key_hash(pair->adress));

		close(pair->fd);
		lru.erase(pair);
		udp_pair_pool.put(pair);

		return 0;
	}

	int clear_remote_index(int remote_index)
	{
		int cnt=0;
		//沿 LRU 遍历全部会话：先取下一个，再释放当前的
		for(lru_node_t *node=lru.head.next;node!=&lru.head;)
		{
			udp_pair_t *pair=static_cast<udp_pair_t *>(node);
			node=node->next;
			if(pair->remote_index==remote_index)
			{
				erase(pair);
				cnt++;
			}
		}
		return cnt;
	}

	int clear_inactive()
	{
		if(get_current_time()-last_clear_time>conn_clear_interval)
		{
			last_clear_time=get_current_time();
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

		u64_t current_time=get_current_time();
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
		last_clear_time=0;
		total=0;
		memset(bytes,0,sizeof(bytes));
		memset(splice_bytes,0,sizeof(splice_bytes));
		splice_fallback=0;
	}
	int erase(tcp_pair_t *pair)
	{
		//两侧都 stop 之后才能归还：watcher->data 直接指向本对象，ev_io_stop 同时清除本轮还没回调的事件，归还后不会再有它的回调。
		//close 后 fd 号、归还后对象都可能被本轮后面 accept 的连接复用，它的 watcher 经 ev_io_init（EV__IOFDSET）重新登记进 epoll（T10、T11），
		//fd_reify 对它直接 ADD，不受 libev 缓存的旧掩码影响（T13）
		struct ev_loop * loop= ev_default_loop (0);
		ev_io_stop(loop, &pair->local.ev);
		ev_io_stop(loop, &pair->remote.ev);

		close(pair->local.fd);
		close(pair->remote.fd);
		mylog(log_info,"[tcp]inactive connection {%s} cleared, tcp connections=%d\n",pair->addr.get_str(),lru.size()-1);
		mylog(log_debug,"[tcp] lru.size()=%d\n",(int)lru.size()-1);
		lru.erase(pair);
		if(pair->local.buf) tcp_buf_pool.put(pair->local.buf);
		if(pair->remote.buf) tcp_buf_pool.put(pair->remote.buf);
		if(pair->local.pipe.r>=0) tcp_pipe_pool.discard(pair->local.pipe);//方向持有 pipe 时里面一定有数据
		if(pair->remote.pipe.r>=0) tcp_pipe_pool.discard(pair->remote.pipe);
		tcp_pair_pool.put(pair);
		return 0;
	}
	int erase_closed(tcp_pair_t *pair)//just a copy of erase()
	{
		struct ev_loop * loop= ev_default_loop (0);
		ev_io_stop(loop, &pair->local.ev);
		ev_io_stop(loop, &pair->remote.ev);

		close(pair->local.fd);
		close(pair->remote.fd);
		mylog(log_info,"[tcp]closed connection {%s} cleared, tcp connections=%d\n",pair->addr.get_str(),lru.size()-1);
		mylog(log_debug,"[tcp] lru.size()=%d\n",(int)lru.size()-1);
		lru.erase(pair);
		if(pair->local.buf) tcp_buf_pool.put(pair->local.buf);
		if(pair->remote.buf) tcp_buf_pool.put(pair->remote.buf);
		if(pair->local.pipe.r>=0) tcp_pipe_pool.discard(pair->local.pipe);//方向持有 pipe 时里面一定有数据
		if(pair->remote.pipe.r>=0) tcp_pipe_pool.discard(pair->remote.pipe);
		tcp_pair_pool.put(pair);
		return 0;
	}
	int clear_remote_index(int remote_index)
	{
		int cnt=0;
		//沿 LRU 遍历全部连接对：先取下一个，再释放当前的
		for(lru_node_t *node=lru.head.next;node!=&lru.head;)
		{
			tcp_pair_t *pair=static_cast<tcp_pair_t *>(node);
			node=node->next;
			if(pair->remote_index==remote_index)
			{
				erase_closed(pair);
				cnt++;
			}
		}
		return cnt;
	}

	int clear_inactive()
	{
		if(get_current_time()-last_clear_time>conn_clear_interval)
		{
			last_clear_time=get_current_time();
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

		u64_t current_time=get_current_time();
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

struct remote_target_t
{
	address_t addr;
	int is_domain;
	char remote_str[max_remote_len];
	char host[max_domain_len];
	u32_t port;
	my_time_t last_dns_refresh_time;
	int dns_query_pending;
	remote_target_t()
	{
		is_domain=0;
		remote_str[0]=0;
		host[0]=0;
		port=0;
		last_dns_refresh_time=0;
		dns_query_pending=0;
	}
};

struct balance_rr_node_t
{
	int current_weight;
	int effective_weight;
	int weight;
	balance_rr_node_t()
	{
		current_weight=0;
		effective_weight=0;
		weight=0;
	}
};

struct forward_rule_t:not_copy_able_t
{
	int index;
	address_t local_addr;
	int enable_tcp;
	int enable_udp;
	vector<remote_target_t> remote_targets;
	balance_strategy_t balance_strategy;
	vector<int> balance_weights;
	vector<balance_rr_node_t> rr_nodes;
	int local_listen_fd_tcp;
	int local_listen_fd_udp;
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
		local_listen_fd_tcp=-1;
		local_listen_fd_udp=-1;
	}
};

static list<forward_rule_t> forward_rules;

struct dns_refresh_request_t
{
	int rule_index;
	int remote_index;
	char host[max_domain_len];
	u32_t port;
	address_t current_addr;
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
static std::thread dns_thread;
static std::mutex dns_mutex;
static std::condition_variable dns_cv;
static std::deque<dns_refresh_request_t> dns_requests;
static std::deque<dns_refresh_result_t> dns_results;
static struct ev_loop *dns_loop=0;
static int dns_worker_started=0;

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

		dns_refresh_result_t result;
		memset(&result,0,sizeof(result));
		result.rule_index=request.rule_index;
		result.remote_index=request.remote_index;
		snprintf(result.host,sizeof(result.host),"%s",request.host);
		result.port=request.port;

		address_t addrs[dns_max_result];
		int addr_count=0;
		char err[dns_error_len];
		if(resolve_domain_addresses(request.host,request.port,addrs,dns_max_result,addr_count,err,sizeof(err))==0)
		{
			result.ok=1;
			result.current_still_valid=0;
			result.next_addr=addrs[0];
			for(int i=0;i<addr_count;i++)
			{
				if(addrs[i]==request.current_addr)
				{
					result.current_still_valid=1;
					result.next_addr=request.current_addr;
					break;
				}
			}
		}
		else
		{
			result.ok=0;
			result.current_still_valid=0;
			snprintf(result.err,sizeof(result.err),"%s",err);
		}

		{
			std::lock_guard<std::mutex> lock(dns_mutex);
			dns_results.push_back(result);
		}
		ev_async_send(dns_loop,&dns_async_watcher);
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
		dns_refresh_result_t &result=*it;
		forward_rule_t *rule_p=0;
		for(auto rule_it=forward_rules.begin();rule_it!=forward_rules.end();++rule_it)
		{
			if(rule_it->index==result.rule_index)
			{
				rule_p=&*rule_it;
				break;
			}
		}
		if(rule_p==0)
		{
			continue;
		}
		forward_rule_t &rule=*rule_p;
		if(result.remote_index<0||result.remote_index>=(int)rule.remote_targets.size())
		{
			continue;
		}
		remote_target_t &target=rule.remote_targets[result.remote_index];
		if(target.is_domain==0)
		{
			continue;
		}
		if(strcmp(target.host,result.host)!=0||target.port!=result.port)
		{
			continue;
		}
		target.dns_query_pending=0;

		if(result.ok==0)
		{
			mylog(log_warn,"rule %d remote %d domain %s:%u resolve failed: %s, keeping current address\n",rule.index,result.remote_index,target.host,target.port,result.err);
			continue;
		}
		if(result.current_still_valid)
		{
			continue;
		}
		if(result.next_addr==target.addr)
		{
			continue;
		}
		char old_addr[max_addr_len];
		char new_addr[max_addr_len];
		target.addr.to_str(old_addr);
		result.next_addr.to_str(new_addr);
		target.addr=result.next_addr;
		int tcp_closed=rule.tcp_manager.clear_remote_index(result.remote_index);
		int udp_closed=rule.udp_manager.clear_remote_index(result.remote_index);
		mylog(log_info,"rule %d remote %d domain %s:%u changed from %s to %s, reloaded target connections tcp=%d udp=%d\n",rule.index,result.remote_index,target.host,target.port,old_addr,new_addr,tcp_closed,udp_closed);
	}
}

static void start_dns_worker(struct ev_loop *loop)
{
	if(dns_worker_started)
	{
		return;
	}
	int has_domain=0;
	for(auto it=forward_rules.begin();it!=forward_rules.end();++it)
	{
		for(size_t i=0;i<it->remote_targets.size();i++)
		{
			if(it->remote_targets[i].is_domain)
			{
				has_domain=1;
				break;
			}
		}
		if(has_domain)
		{
			break;
		}
	}
	if(!has_domain)
	{
		return;
	}
	dns_loop=loop;
	ev_async_init(&dns_async_watcher,dns_result_cb);
	ev_async_start(loop,&dns_async_watcher);
	dns_worker_started=1;
	dns_thread=std::thread(dns_worker_main);
	dns_thread.detach();
}

static void schedule_dns_refresh(forward_rule_t &rule)
{
	my_time_t now=get_current_time();
	for(size_t i=0;i<rule.remote_targets.size();i++)
	{
		remote_target_t &target=rule.remote_targets[i];
		if(target.is_domain==0)
		{
			continue;
		}
		if(target.dns_query_pending)
		{
			continue;
		}
		if(now-target.last_dns_refresh_time<dns_refresh_interval)
		{
			continue;
		}
		dns_refresh_request_t request;
		memset(&request,0,sizeof(request));
		request.rule_index=rule.index;
		request.remote_index=(int)i;
		snprintf(request.host,sizeof(request.host),"%s",target.host);
		request.port=target.port;
		request.current_addr=target.addr;
		{
			std::lock_guard<std::mutex> lock(dns_mutex);
			dns_requests.push_back(request);
		}
		target.dns_query_pending=1;
		target.last_dns_refresh_time=now;
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
		DEBUG_ASSERT((int)rule.rr_nodes.size()==remote_count);
		int best=-1;
		int total=0;
		for(int i=0;i<remote_count;i++)
		{
			balance_rr_node_t &node=rule.rr_nodes[i];
			DEBUG_ASSERT(node.weight>0);
			DEBUG_ASSERT(node.effective_weight>0);
			node.current_weight+=node.effective_weight;
			total+=node.effective_weight;
			if(best==-1||node.current_weight>rule.rr_nodes[best].current_weight)
			{
				best=i;
			}
		}
		DEBUG_ASSERT(best>=0);
		DEBUG_ASSERT(total>0);
		rule.rr_nodes[best].current_weight-=total;
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

//同一 fd 上切换事件一律 stop → 改 events → start，不经 ev_io_init：EV__IOFDSET 表示新 fd，libev fd_reify 的本地补丁
//对它直接 ADD，fd 仍在 epoll 中时就成了 ADD（EEXIST）再 MOD（T13）
void tcp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	//mylog(log_info,"[tcp]tcp_cb called \n");
	tcp_pair_t &tcp_pair=*(tcp_pair_t *)watcher->data;
	DEBUG_ASSERT(tcp_pair.owner!=0);
	conn_manager_tcp_t &conn_manager_tcp=tcp_pair.owner->tcp_manager;

	//epoll_ctl 失败（如 ADD 超过 fs.epoll.max_user_watches 的 ENOSPC、ENOMEM）：libev 的 fd_kill 已停掉这个 watcher，只释放这一对（C9）。
	//两侧都失败时，另一侧还没回调的 EV_ERROR 由 erase_closed 里的 ev_io_stop 清除
	if((revents&EV_ERROR) !=0)
	{
		mylog(log_warn,"[tcp]connection {%s} closed bc of EV_ERROR (epoll_ctl failed),fd=%d\n",tcp_pair.addr.get_str(),watcher->fd);
		conn_manager_tcp.erase_closed(&tcp_pair);
		return;
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
			if( (revents & EV_READ) ==0) return;
		}
		else if(other_info.data_len!=0&&(revents & EV_WRITE)!=0)
		{
			//先发留下的数据：上游连上后持续可读时，下面的 if/else if 每轮都只走读分支。可读是水平触发，下一轮还会报
			revents&=~EV_READ;
		}
	}

	//推迟的 shutdown：上游建连期间客户端已 EOF，连上后从上面落到这里；建连之后只有它会在没有待发数据时挂 EV_WRITE。先于读处理，否则本侧每轮都可读时下面的 if/else if 永远轮不到写
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
		if(my_info.splice_next&&other_info.connected&&!disable_splice)
		{
			if(tcp_pipe_scratch.r<0&&tcp_pipe_pool.get(tcp_pipe_scratch)!=0)
			{
				conn_manager_tcp.splice_fallback++;
			}
			else
			{
				DEBUG_ASSERT(tcp_pipe_len(tcp_pipe_scratch)==0);
				recv_len=splice(my_fd,0,tcp_pipe_scratch.w,0,splice_read_max,SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
				spliced=1;
				//队首是紧急数据（对端 MSG_OOB）时非阻塞 splice 返回 EAGAIN，epoll 却一直报可读，这一次改用 recv：
				//它跳过紧急字节（没有 SO_OOBINLINE），与拷贝路径一致。别的原因（如页分配失败）同样交给 recv
				if(recv_len<0&&errno==EAGAIN) spliced=0;
				else if(recv_len<0&&(errno==ENOSYS||errno==EPERM||errno==EINVAL||errno==EOPNOTSUPP))
				{
					//splice 本身不可用（如 seccomp 白名单里没有它）：什么都没读，整个进程改走拷贝（审查 L1）
					mylog(log_warn,"[tcp]splice failed (%s), forwarding all TCP by copy from now on\n",get_sock_error());
					disable_splice=1;
					spliced=0;
				}
			}
		}
		if(!spliced)
		{
			if(tcp_scratch==0)
			{
				tcp_scratch=tcp_buf_pool.get();
				if(tcp_scratch==0)
				{
					mylog(log_warn,"[tcp]connection {%s} closed bc of malloc for a %d-byte buffer failed\n",tcp_pair.addr.get_str(),max_data_len_tcp);
					conn_manager_tcp.erase_closed(&tcp_pair);
					return;
				}
			}
			recv_len=recv(my_fd,tcp_scratch,max_data_len_tcp,0);
		}
		mylog(log_trace,"fd=%d,recv_len=%d\n",my_fd,recv_len);
		if(recv_len==0)
		{
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
			for(int round=1;;round++)
			{
				nodelay_before_send(other_info,my_info.data_len);
				send_len=splice(tcp_pipe_scratch.r,0,other_fd,0,my_info.data_len,SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
				if(send_len>0)
				{
					my_info.data_len-=send_len;
					conn_manager_tcp.bytes[dir]+=send_len;
					conn_manager_tcp.splice_bytes[dir]+=send_len;
				}
				if(my_info.data_len!=0)
				{
					//没写完（含 EAGAIN；出错时留给写分支，同 send）：scratch pipe 连同数据交给本方向，下一次 splice 前再从池里取一个
					my_info.pipe=tcp_pipe_scratch;
					tcp_pipe_scratch.r=tcp_pipe_scratch.w=-1;
					tcp_unshrink_sndbuf(other_info);
					break;
				}
				//写完了：源端这一轮读满就接着搬（D53）
				if(round>=splice_rounds_max||recv_len<splice_read_max) break;
				recv_len=splice(my_fd,0,tcp_pipe_scratch.w,0,splice_read_max,SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
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
			my_info.begin=tcp_scratch;
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
			if(my_info.data_len!=0)
			{
				//没发完（含上游还在建连）：剩下的数据连同 scratch 整块留给本方向，不拷贝（D17）；下一次 recv 前再从池里取一块
				my_info.buf=tcp_scratch;
				tcp_scratch=0;
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
	else if( (revents & EV_WRITE) !=0)
	{
		mylog(log_trace,"[tcp]events[idx].events & EPOLLOUT !=0\n");

		if( (my_info.ev.events&EV_WRITE) ==0)
		{
			mylog(log_debug,"[tcp]out of date event, my_info.ev.events&EPOLLOUT) ==0 \n");
			return;
		}

		DEBUG_ASSERT(other_info.data_len!=0&&(other_info.buf!=0)!=(other_info.pipe.r>=0));
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
				static int logged=0;//越限期间这样的 socket 每轮重试，第一次记 info 便于从日志对上 CPU 占用，之后 debug
				mylog(logged?log_debug:log_info,"[tcp]send to fd=%d returned EAGAIN although writable (TCP memory above net.ipv4.tcp_mem or a cgroup limit?), retrying\n",my_fd);
				logged=1;
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
				tcp_pipe_pool.put(other_info.pipe);
			}
			else
			{
				tcp_buf_pool.put(other_info.buf);
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
	else
	{
		mylog(log_fatal,"[tcp]got unexpected event,events[idx].events=%x\n",(u32_t)revents);
		myexit(-1);
	}
}
//接受一个连接；返回 0 表示本轮到此为止（backlog 已空、accept 失败，或上游 connect 立即失败）
static int tcp_accept_one(struct ev_loop *loop, struct ev_io *watcher)
{
	forward_rule_t *rule=(forward_rule_t *)watcher->data;
	DEBUG_ASSERT(rule!=0);
	conn_manager_tcp_t &conn_manager_tcp=rule->tcp_manager;
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
		if((err==EMFILE||err==ENFILE)&&tcp_pipe_trim()>0) return 1;
		if(err!=EINTR&&err!=ECONNABORTED)
		{
			//EMFILE/ENFILE/ENOMEM or an LSM denial: the connection stays in the backlog and the level-triggered watcher would fire again at once; clear_timer_cb restarts it
			ev_io_stop(loop,watcher);
		}
		return 0;
	}

	address_t tmp_addr;
	tmp_addr.from_sockaddr((sockaddr*)&tmp_sockaddr_in,tmp_len);

	if(conn_manager_tcp.lru.size()>=max_conn_num)
	{
		mylog(log_warn,"[tcp]new connection from {%s},but ignored,bc of max_conn_num reached\n",tmp_addr.get_str());
		close(new_fd);
		return 1;
		//continue;
	}
	//先取对象再建上游 socket：分配失败时上游看不到这次连接，也不推进 roundrobin
	tcp_pair_t *new_pair=tcp_pair_pool.get();
	if(new_pair==0)
	{
		mylog(log_warn,"[tcp]new connection from {%s},but malloc for connection objects failed\n",tmp_addr.get_str());
		close(new_fd);
		return 1;
	}
	int remote_index=select_remote_index(*rule,tmp_addr);
	address_t &remote_addr=rule->remote_targets[remote_index].addr;


	int new_remote_fd = socket(remote_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	if(new_remote_fd<0&&(errno==EMFILE||errno==ENFILE)&&tcp_pipe_trim()>0)//fd 用完时关掉空闲 pipe 再试一次（D52）
		new_remote_fd = socket(remote_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	if(new_remote_fd<0)
	{
		mylog(log_warn,"[tcp]new connection from {%s},but create new_remote_fd failed,%s\n",tmp_addr.get_str(),get_sock_error());
		tcp_pair_pool.put(new_pair);
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
		tcp_pair_pool.put(new_pair);
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

void clear_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents)
{
	for(auto it=forward_rules.begin();it!=forward_rules.end();++it)
	{
		it->tcp_manager.clear_inactive();
		it->udp_manager.clear_inactive();
		schedule_dns_refresh(*it);
		if(it->enable_tcp&&!ev_is_active(&it->tcp_accept_watcher))
		{
			ev_io_start(loop,&it->tcp_accept_watcher);
		}
		if(it->enable_udp&&!ev_is_active(&it->udp_accept_watcher))
		{
			ev_io_start(loop,&it->udp_accept_watcher);
		}
	}
	tcp_pipe_pool.blocked=0;//创建 pipe 失败后每个周期最多再试一次（每次失败都会重新置位）
	//stdout 不是终端时 log0 不逐行刷新，日志最多晚一个 timer_interval 写出（D3）
	fflush(stdout);
}
//U5：给 UDP socket 开 UDP_GRO（5.0 起）：网卡 GRO 阶段为它聚合同一条流的包，收到时带 UDP_GRO cmsg。
//副作用：任何一个 socket 开了它，内核就打开全局 static key，本机所有入站 UDP 在 GRO 阶段都多一次 socket 查找
static int udp_gro_set(int fd)
{
	int one=1;
	return setsockopt(fd,SOL_UDP,UDP_GRO,&one,sizeof(one));
}
static void udp_flush_return();
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

	udp_batch_t &b=udp_batch;
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
		if(udp_gro) b.gso[i]=udp_recv_gso(b.rin[i].msg_hdr);
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
		b.rrule[i]=udp_pair.owner;
	}
	b.rn+=n;
	conn_manager_udp.lru.update(&udp_pair);
	//udp_pair.last_active_time=get_current_time();
	if(b.rn==udp_batch_max) udp_flush_return();
}
//客户端 tmp_addr 的第一个包：建会话。失败时返回 0，这个包丢弃；hash 是 find() 算出的 tmp_addr 的哈希。不内联进逐包的循环
static udp_pair_t * __attribute__((noinline)) udp_new_session(struct ev_loop *loop,forward_rule_t *rule,address_t &tmp_addr,u32_t hash)
{
	conn_manager_udp_t &conn_manager_udp=rule->udp_manager;
	if(conn_manager_udp.lru.size()>=max_conn_num)
	{
		mylog(log_info,"[udp]new connection from {%s},but ignored,bc of max_conv_num reached\n",tmp_addr.get_str());
		return 0;
	}
	//会话表要扩容时在选上游、建 socket 之前做：失败只丢这个包，轮询序号不前进
	if(conn_manager_udp.sessions.reserve_one()!=0)
	{
		mylog(log_info,"[udp]new connection from {%s},but malloc for connection objects failed\n",tmp_addr.get_str());
		return 0;
	}
	int remote_index=select_remote_index(*rule,tmp_addr);
	address_t &remote_addr=rule->remote_targets[remote_index].addr;
	int new_udp_fd=remote_addr.new_connected_udp_fd();
	if(new_udp_fd==-1&&(errno==EMFILE||errno==ENFILE)&&tcp_pipe_trim()>0)//同 TCP：fd 用完时关掉空闲 pipe 再试一次（D52）
		new_udp_fd=remote_addr.new_connected_udp_fd();
	if(new_udp_fd==-1)
	{
		mylog(log_info,"[udp]new connection from {%s} ,but create udp fd failed\n",tmp_addr.get_str());
		return 0;
	}
	//U5：回包经网卡时也聚合；失败时这个会话只是收不到合并包
	if(udp_gro&&udp_gro_set(new_udp_fd)!=0)
		mylog(log_debug,"[udp]setsockopt UDP_GRO failed on udp fd %d (%s)\n",new_udp_fd,get_sock_error());

	udp_pair_t *new_pair=udp_pair_pool.get();
	if(new_pair==0)
	{
		mylog(log_info,"[udp]new connection from {%s},but malloc for connection objects failed\n",tmp_addr.get_str());
		close(new_udp_fd);
		return 0;
	}
	udp_pair_t &udp_pair=*new_pair;
	conn_manager_udp.lru.new_key(&udp_pair);
	conn_manager_udp.total++;
	udp_pair.owner=rule;
	udp_pair.remote_index=remote_index;

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
//U5：发送条目 m 带 UDP_SEGMENT 时返回段长，否则 0
static inline int udp_msg_gso(const mmsghdr &m)
{
	if(m.msg_hdr.msg_controllen==0) return 0;
	uint16_t g;
	memcpy(&g,CMSG_DATA((cmsghdr *)m.msg_hdr.msg_control),sizeof(g));
	return g;
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
	if(m.msg_hdr.msg_controllen==0) return 1;
	return udp_segs(udp_msg_len(m),udp_msg_gso(m));
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
static int udp_gso_hdr_cap=0;
static inline int udp_gso_cap(int gso)
{
	return udp_gso_hdr_cap?udp_gso_max_segs-(48+gso-1)/gso:udp_gso_max_segs;
}
//段长 gso、segs 段的 GSO 发送报 err 时：是上面的旧内核上限就记住并返回 1（按更小的块重发即可，不关 GSO），否则 0
static int udp_gso_old_limit(int err,int gso,int segs)
{
	if(err!=EINVAL||udp_gso_hdr_cap||segs<=udp_gso_max_segs-(48+gso-1)/gso) return 0;
	udp_gso_hdr_cap=1;
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
	int level=c.mgr.gso_logged[c.dir]?log_debug:log_info;
	c.mgr.gso_logged[c.dir]=1;
	mylog(level,"[udp]GSO send %s {%s} on %s fd %d failed (%s), sending its GRO packets datagram by datagram from now on\n",
		c.dir==0?"from":"to",client->get_str(),c.dir==0?"session":"listen",c.fd,get_sock_error());
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
	udp_batch_t &b=udp_batch;
	const mmsghdr &m=msgs[i];
	const int gso=udp_msg_gso(m);
	const size_t len=udp_msg_len(m);
	DEBUG_ASSERT(gso>0);
	size_t off=0;
	while(off<len)
	{
		const size_t piece=(size_t)gso*(c.off[c.stride*i]?1:udp_gso_cap(gso));
		int n=0;
		for(size_t o=off;o<len&&n<udp_batch_max;o+=piece,n++)
		{
			mmsghdr &s=b.seg[n];
			size_t l=min(piece,len-o);
			s.msg_hdr.msg_name=m.msg_hdr.msg_name;
			s.msg_hdr.msg_namelen=m.msg_hdr.msg_namelen;
			s.msg_hdr.msg_iovlen=udp_iov_range(m.msg_hdr,o,l,b.seg_iov[n]);
			if(l>(size_t)gso)
			{
				uint16_t v=(uint16_t)gso;
				memcpy(CMSG_DATA(&b.seg_ctrl[n].hdr),&v,sizeof(v));
				s.msg_hdr.msg_control=&b.seg_ctrl[n];
				s.msg_hdr.msg_controllen=CMSG_SPACE(sizeof(uint16_t));
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
		if(b.seg[0].msg_hdr.msg_controllen!=0&&udp_gso_errno(errno))
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
	if(m.msg_hdr.msg_controllen==0) return 0;
	return gso_off||udp_msg_segs(m)>udp_gso_cap(udp_msg_gso(m));
}
//一组 cnt 个包，dir 为 0 时是一个会话本批的入向包（U3，发往会话 socket），为 1 时是一个规则的回包（U4，发往监听 socket，
//各包带客户端地址）：sendmmsg 只发出一部分时从断点接着发（内核不报断点处的错误，重发一次才知道它是否仍失败）。
//EAGAIN 丢掉剩下的包，不排队（UDP 语义）；其他错误（EMSGSIZE 等）只丢断点处这一个包。入向时上一个包引来的 ICMP（ECONNREFUSED）
//只让断点处的发送失败，错误随之被取走，重发就成功：只有一组的第一个包碰上它时才丢包、记 warn（逐包 send 时每次都丢）；
//监听 socket 没有 connect，不收 ICMP 错误。
//U5：带 UDP_SEGMENT 的条目（GRO 合并包）发送失败时不按一个包丢，交给 udp_send_split 重发：GSO 本身的错误（udp_gso_errno）
//先关掉它所属会话这个方向的 GSO（udp_gso_turn_off）再逐个数据报发，其他错误按至多上限段再发一次。pkts/drop 按数据报计。
//直接调 syscall：64 位 musl 的 sendmmsg() 是逐条 sendmsg() 的循环（它的 msghdr 用 int 加填充，内核用 size_t）；
//udp_batch.out/rout/seg 在 BSS 里，musl 的 __pad1/__pad2 从不写入、恒为 0，内核读到的 msg_iovlen/msg_controllen 就是本值
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
					if(msgs[i].msg_hdr.msg_controllen!=0)
						c.mgr.pkts[c.dir]+=udp_msg_segs(msgs[i])-1;
				}
				sent+=ret;
				continue;
			}
			if(errno==EAGAIN||errno==EWOULDBLOCK) goto eagain;
			if(msgs[sent].msg_hdr.msg_controllen!=0)
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
static void udp_flush_return()
{
	udp_batch_t &b=udp_batch;
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
			udp_batch_set_iov(m,b.rout_iov[cnt],j,b.rin[j].msg_len);
			if(udp_gro)
			{
				udp_batch_set_gso(m,b.rout_ctrl[cnt],j,b.rin[j].msg_len);
				b.rout_off[cnt]=b.roff[j];
			}
			cnt++;
		}
		udp_send_ctx_t c={rule->udp_manager,rule->local_listen_fd_udp,1,b.rout_off,1,0};
		udp_send_group(c,b.rout,cnt);
	}
	b.rn=0;
}
//每轮循环阻塞之前（ev_prepare）发出回程批。不用 ev_check：libev 在同一优先级内按入队的逆序回调，check watcher 最后入队，
//反而在本轮的 I/O 回调之前执行
static void udp_flush_cb(struct ev_loop *loop, ev_prepare *watcher, int revents)
{
	if(udp_batch.rn!=0) udp_flush_return();
}
//recvmmsg 收到的 n 个包（U1、U3）：逐包查找或新建会话，再按会话分组，每个会话一次 sendmmsg。会话内保持到达顺序，
//各组按会话在本批首次出现的顺序发出
static void udp_forward_batch(struct ev_loop *loop,forward_rule_t *rule,int n)
{
	conn_manager_udp_t &conn_manager_udp=rule->udp_manager;
	udp_batch_t &b=udp_batch;
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
		if(udp_gro) gso=b.gso[i]=udp_recv_gso(h);

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
		udp_batch_set_iov(b.out[j],b.out_iov[j],i,b.in[i].msg_len);
		if(udp_gro) udp_batch_set_gso(b.out[j],b.out_ctrl[j],i,b.in[i].msg_len);
	}
	for(int g=0;g<groups;g++)
	{
		udp_pair_t &udp_pair=*b.group_pair[g];
		udp_pair.batch_group=-1;
		conn_manager_udp.lru.update(&udp_pair);
		int cnt=b.group_cnt[g];
		udp_send_ctx_t c={conn_manager_udp,udp_pair.fd,0,&udp_pair.gso_off[0],0,&udp_pair};
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
	//回程批占着同一组槽（D36）：先发出，入向这一批才能从 slot[0] 起收
	if(udp_batch.rn!=0) udp_flush_return();
	//每次回调只收一批（D35）：没收完的由水平触发的 epoll 下一轮再报，一轮里入向最多占 udp_batch_max 个包，
	//回程与 TCP 不会被长时间挤占
	int n=recvmmsg(local_listen_fd_udp,udp_batch.in,udp_batch_max,MSG_DONTWAIT,0);//socket 本身也非阻塞；阻塞时会等凑满一批
	if(n<0)
	{
		//EAGAIN：唤醒本轮的包校验和错误、已被内核丢掉
		if(errno!=EAGAIN&&errno!=EWOULDBLOCK)
			mylog(log_debug,"[udp]recvmmsg error,errno %s\n",get_sock_error());
		return;
	}
	udp_forward_batch(loop,rule,n);
}
//SIGUSR1 输出统计（O1，D25–D27）：每条规则的 TCP、UDP 各一行，再加一行进程级的池。当前连接数、半关闭对数、
//持有的块数在这里沿 LRU 现数，热路径上只累加转发计数。只在回调之间调用：这时池的计数与连接对能对上
void sigusr1_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	int held=0,pipes_held=0,tcp_conns=0,udp_conns=0;
	for(auto it=forward_rules.begin();it!=forward_rules.end();++it)
	{
		forward_rule_t &rule=*it;
		conn_manager_tcp_t &tcp=rule.tcp_manager;
		conn_manager_udp_t &udp=rule.udp_manager;
		int half_closed=0;
		for(lru_node_t *node=tcp.lru.head.next;node!=&tcp.lru.head;node=node->next)
		{
			tcp_pair_t *pair=static_cast<tcp_pair_t *>(node);
			half_closed+=(pair->local.eof||pair->remote.eof);
			held+=(pair->local.buf!=0)+(pair->remote.buf!=0);
			pipes_held+=(pair->local.pipe.r>=0)+(pair->remote.pipe.r>=0);
		}
		tcp_conns+=tcp.lru.size();
		udp_conns+=udp.lru.size();
		if(rule.enable_tcp)
			mylog_unfiltered(log_info,"stats rule %d tcp: conns=%d total=%llu half_closed=%d up_bytes=%llu down_bytes=%llu up_splice=%llu down_splice=%llu splice_fallback=%llu\n",
				rule.index,tcp.lru.size(),tcp.total,half_closed,tcp.bytes[0],tcp.bytes[1],tcp.splice_bytes[0],tcp.splice_bytes[1],tcp.splice_fallback);
		if(rule.enable_udp&&!udp_gro)
			mylog_unfiltered(log_info,"stats rule %d udp: sessions=%d total=%llu up_pkts=%llu up_bytes=%llu down_pkts=%llu down_bytes=%llu up_drop=%llu down_drop=%llu\n",
				rule.index,udp.lru.size(),udp.total,udp.pkts[0],udp.bytes[0],udp.pkts[1],udp.bytes[1],udp.drop[0],udp.drop[1]);
		if(rule.enable_udp&&udp_gro)//D42：只在 --udp-gro 时多这四项
			mylog_unfiltered(log_info,"stats rule %d udp: sessions=%d total=%llu up_pkts=%llu up_bytes=%llu down_pkts=%llu down_bytes=%llu up_drop=%llu down_drop=%llu up_gro=%llu down_gro=%llu up_gso_fallback=%llu down_gso_fallback=%llu\n",
				rule.index,udp.lru.size(),udp.total,udp.pkts[0],udp.bytes[0],udp.pkts[1],udp.bytes[1],udp.drop[0],udp.drop[1],
				udp.gro[0],udp.gro[1],udp.gso_fallback[0],udp.gso_fallback[1]);
	}
	int scratch=(tcp_scratch!=0);
	int pipe_scratch=(tcp_pipe_scratch.r>=0);
	mylog_unfiltered(log_info,"stats pool: bufs alloc=%d held=%d free=%d scratch=%d tcp_pairs slabs=%d free=%d udp_pairs slabs=%d free=%d pipes alloc=%d held=%d free=%d scratch=%d\n",
		tcp_buf_pool.alloc,held,tcp_buf_pool.free_bufs.cnt,scratch,
		tcp_pair_pool.slabs,tcp_pair_pool.free_objs.cnt,udp_pair_pool.slabs,udp_pair_pool.free_objs.cnt,
		tcp_pipe_pool.alloc,pipes_held,tcp_pipe_pool.free_cnt,pipe_scratch);
	//先写出再检查：DEBUG_ASSERT 构建里对不上时日志里留着这一组数
	fflush(stdout);
	DEBUG_ASSERT(tcp_buf_pool.alloc==held+tcp_buf_pool.free_bufs.cnt+scratch);
	DEBUG_ASSERT(tcp_pipe_pool.alloc==pipes_held+tcp_pipe_pool.free_cnt+pipe_scratch);
	DEBUG_ASSERT(tcp_pair_pool.slabs*obj_pool_slab_objs-tcp_pair_pool.free_objs.cnt==tcp_conns);
	DEBUG_ASSERT(udp_pair_pool.slabs*obj_pool_slab_objs-udp_pair_pool.free_objs.cnt==udp_conns);
	for(auto it=forward_rules.begin();it!=forward_rules.end();++it)
		DEBUG_ASSERT(it->udp_manager.sessions.cnt==it->udp_manager.lru.size());
}

void sigpipe_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigpipe, ignored");
}

void sigterm_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigterm, exit");
	myexit(0);
}

void sigint_cb(struct ev_loop *l, ev_signal *w, int revents)
{
	mylog(log_info, "got sigint, exit");
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

//U5：监听 socket 开 UDP_GRO。第一个开成功时给 udp_batch 挂上收 cmsg 的控制缓冲；第一个就失败（5.0 以前的内核）时整个特性关闭，
//这时还没有 socket 开着 UDP_GRO。之后的失败只记一行：那个监听 socket 收到的都是普通数据报
static void udp_gro_listen(forward_rule_t &rule)
{
	static int gro_socks=0;
	if(udp_gro_set(rule.local_listen_fd_udp)==0)
	{
		if(gro_socks++==0) udp_batch.attach_ctrl();
		return;
	}
	mylog(log_warn,"rule %d [udp] setsockopt UDP_GRO failed (%s): --udp-gro needs Linux 5.0 or later%s\n",
		rule.index,get_sock_error(),gro_socks==0?", UDP_GRO stays off":"");
	if(gro_socks==0) udp_gro=0;
}

static void start_forward_rule(struct ev_loop *loop, forward_rule_t &rule)
{
	assert(loop!=0);
	char listen_addr[max_addr_len];
	rule.local_addr.to_str(listen_addr);
	int yes=1;

	if(rule.enable_tcp)
	{
		rule.local_listen_fd_tcp=socket(rule.local_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
		if(rule.local_listen_fd_tcp<0)
		{
			mylog(log_fatal,"rule %d [tcp] create listen socket failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
			myexit(1);
		}

		setsockopt(rule.local_listen_fd_tcp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
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
		ev_io_start(loop, &rule.tcp_accept_watcher);
	}

	if(rule.enable_udp)
	{
		rule.local_listen_fd_udp=socket(rule.local_addr.get_type(), SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_UDP);
		if(rule.local_listen_fd_udp<0)
		{
			mylog(log_fatal,"rule %d [udp] create listen socket failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
			myexit(1);
		}

		setsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		set_udp_buf_size(rule.local_listen_fd_udp,listen_fd_buf_size);
		//内核保存的是请求值的 2 倍；没有 CAP_NET_ADMIN 时先被 rmem_max/wmem_max 截断（6.18 以前默认 212992）
		int rcv=0,snd=0;
		socklen_t opt_len=sizeof(rcv);
		getsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_RCVBUF, &rcv, &opt_len);
		opt_len=sizeof(snd);
		getsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_SNDBUF, &snd, &opt_len);
		if(rcv<2*listen_fd_buf_size||snd<2*listen_fd_buf_size)
			mylog(log_info,"rule %d [udp] listen socket buffers are rcv %d / snd %d bytes instead of %d: capped by net.core.rmem_max/wmem_max, raise them to at least %d or run with CAP_NET_ADMIN\n",
				rule.index,rcv,snd,2*listen_fd_buf_size,listen_fd_buf_size);
		if(udp_gro) udp_gro_listen(rule);

		if(::bind(rule.local_listen_fd_udp, (struct sockaddr*) &rule.local_addr.inner, rule.local_addr.get_len()) !=0)
		{
			mylog(log_fatal,"rule %d [udp] socket bind failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
			myexit(1);
		}

		ev_io_init(&rule.udp_accept_watcher, udp_accept_cb, rule.local_listen_fd_udp, EV_READ);
		rule.udp_accept_watcher.data=&rule;
		ev_io_start(loop, &rule.udp_accept_watcher);
	}
}


int event_loop()
{
	struct ev_loop * loop= ev_default_loop(0);
	assert(loop != NULL);
	mylog(log_info,"event backend: %s\n",ev_backend(loop)==EVBACKEND_EPOLL?"epoll":"unknown");
	unordered_map<address_t,int,address_t::hash_function> tcp_listen_rules;
	unordered_map<address_t,int,address_t::hash_function> udp_listen_rules;
	tcp_listen_rules.reserve(app_config.rules.size());
	udp_listen_rules.reserve(app_config.rules.size());


	int any_udp=0;
	forward_rules.clear();
	if(app_config.rules.empty())
	{
		mylog(log_fatal,"no forward rules configured\n");
		myexit(-1);
	}

	for(size_t i=0;i<app_config.rules.size();i++)
	{
		forward_rules.emplace_back();
		forward_rule_t &rule=forward_rules.back();
		forward_rule_config_t &rule_config=app_config.rules[i];
		rule.index=(int)i+1;
		rule.local_addr=rule_config.local_addr;
		rule.enable_tcp=rule_config.enable_tcp;
		rule.enable_udp=rule_config.enable_udp;
		rule.balance_strategy=rule_config.balance_strategy;
		rule.balance_weights=rule_config.balance_weights;
		assert(!rule_config.remote_targets.empty());
		rule.remote_targets.reserve(rule_config.remote_targets.size());
		my_time_t now=get_current_time();
		for(size_t j=0;j<rule_config.remote_targets.size();j++)
		{
			const remote_target_config_t &config_target=rule_config.remote_targets[j];
			remote_target_t target;
			target.addr=config_target.addr;
			target.is_domain=config_target.is_domain;
			snprintf(target.remote_str,sizeof(target.remote_str),"%s",config_target.remote_str);
			snprintf(target.host,sizeof(target.host),"%s",config_target.host);
			target.port=config_target.port;
			if(target.is_domain)
			{
				target.last_dns_refresh_time=now;
			}
			rule.remote_targets.push_back(target);
		}
		if(rule.balance_strategy!=balance_strategy_off)
		{
			assert(rule.balance_weights.size()==rule.remote_targets.size());
		}
		if(rule.balance_strategy==balance_strategy_roundrobin)
		{
			rule.rr_nodes.reserve(rule.remote_targets.size());
			for(size_t j=0;j<rule.remote_targets.size();j++)
			{
				int weight=rule.balance_weights[j];
				balance_rr_node_t node;
				node.current_weight=0;
				node.effective_weight=weight;
				node.weight=weight;
				rule.rr_nodes.push_back(node);
			}
		}
		if(rule.enable_tcp)
		{
			check_and_record_listen(tcp_listen_rules,rule,"tcp");
		}
		if(rule.enable_udp)
		{
			check_and_record_listen(udp_listen_rules,rule,"udp");
			any_udp=1;
		}
		start_forward_rule(loop,rule);
	}

	start_dns_worker(loop);

	struct ev_timer clear_timer;

	ev_timer_init(&clear_timer, clear_timer_cb, 0, timer_interval/1000.0);
	ev_timer_start(loop, &clear_timer);

	//清零等同 ev_init（同 T11 的 watcher），不用 ev_prepare_init 宏：不新增 strict-aliasing 告警
	struct ev_prepare udp_flush_watcher={};
	udp_flush_watcher.cb=udp_flush_cb;
	if(any_udp)
		ev_prepare_start(loop, &udp_flush_watcher);

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
	printf("                                          (UDP sessions: only a --sock-buf value is set past the cap)\n");
	printf("    --disable-tcp-nodelay                 do not set TCP_NODELAY on forwarded TCP connections (set on both sides by default)\n");
	printf("    --disable-splice                      forward TCP by recv/send copies only; by default a direction whose last read\n");
	printf("                                          was at least 16 KiB moves the next one with splice through a pipe\n");
	printf("    --udp-gro                             receive UDP with UDP_GRO and forward merged packets with UDP_SEGMENT (GSO),\n");
	printf("                                          Linux 5.0 or later, off by default\n");
	printf("    --log-level           <number>        0: never    1: fatal   2: error   3: warn \n");
	printf("                                          4: info (default)      5: debug   6: trace\n");
	printf("    --log-position                        enable file name, function name, line number in log\n");
	printf("    --disable-color                       disable log color\n");
	printf("    --enable-color                        enable log color, log color is enabled by default on most platforms\n");
	printf("    -h,--help                             print this help message\n");
	printf("\n");


	//printf("common options,these options must be same on both side\n");
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
		{"udp-gro", no_argument,    0, 1},
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
	for (i = 0; i < argc; i++)
	{
		if(strcmp(argv[i],"--log-level")==0)
		{
			if(i<argc -1)
			{
				sscanf(argv[i+1],"%d",&log_level);
				if(0<=log_level&&log_level<log_end)
				{
				}
				else
				{
					log_bare(log_fatal,"invalid log_level\n");
					myexit(-1);
				}
			}
		}
		if(strcmp(argv[i],"--disable-color")==0)
		{
			enable_log_color=0;
		}
		if(strcmp(argv[i],"--enable-color")==0)
		{
			enable_log_color=1;
		}
	}

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
			if(strcmp(long_options[option_index].name,"log-level")==0)
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
				int tmp=-1;
				sscanf(optarg,"%d",&tmp);
				if(10<=tmp&&tmp<=10*1024)
				{
					socket_buf_size=tmp*1024;
					sock_buf_explicit=1;
				}
				else
				{
					mylog(log_fatal,"sock-buf value must be between 1 and 10240 (kbyte) \n");
					myexit(-1);
				}
			}
			else if(strcmp(long_options[option_index].name,"udp-listen-buf")==0)
			{
				int tmp=-1;
				sscanf(optarg,"%d",&tmp);
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
			else if(strcmp(long_options[option_index].name,"udp-gro")==0)
			{
				udp_gro=1;
			}
			else
			{
				mylog(log_fatal,"unknown option\n");
				myexit(-1);
			}
			break;
		default:
			mylog(log_fatal,"unknown option <%x>", opt);
			myexit(-1);
		}
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
		rule.local_addr.from_str(rule.listen_str);
		rule.remote_targets.reserve(remote_args.size());
		char err[dns_error_len];
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
	test.from_str((char*)"[2001:19f0:7001:1111:00:ff:11:22]:443");
	printf("%s\n",test.get_str());
	printf("%d\n",hash(test));
	test.from_str((char*)"44.55.66.77:443");
	printf("%s\n",test.get_str());
	printf("%d\n",hash(test));

	return 0;
}

int main(int argc, char *argv[])
{
    struct ev_loop* loop=ev_default_loop(0);
    if(loop==NULL)
    {
        mylog(log_fatal,"failed to create epoll event loop\n");
        myexit(-1);
    }
    ev_signal signal_watcher_sigpipe;
    ev_signal_init(&signal_watcher_sigpipe, sigpipe_cb, SIGPIPE);
    ev_signal_start(loop, &signal_watcher_sigpipe);


    ev_signal signal_watcher_sigterm;
    ev_signal_init(&signal_watcher_sigterm, sigterm_cb, SIGTERM);
    ev_signal_start(loop, &signal_watcher_sigterm);

    ev_signal signal_watcher_sigint;
    ev_signal_init(&signal_watcher_sigint, sigint_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher_sigint);

    ev_signal signal_watcher_sigusr1;
    ev_signal_init(&signal_watcher_sigusr1, sigusr1_cb, SIGUSR1);
    ev_signal_start(loop, &signal_watcher_sigusr1);

	//unit_test();
	assert(sizeof(u64_t)==8);
	assert(sizeof(i64_t)==8);
	assert(sizeof(u32_t)==4);
	assert(sizeof(i32_t)==4);
	dup2(1, 2);		//redirect stderr to stdout
	int i, j, k;
	process_arg(argc,argv);

	event_loop();

	return 0;
}
