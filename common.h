/*
 * common.h
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#pragma once

//#ifndef COMMON_H_
//#define COMMON_H_
//#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<getopt.h>

#include<unistd.h>
#include<errno.h>
//#include <sys/epoll.h>
//#include <sys/wait.h>
//#include <sys/socket.h>    //for socket ofcourse
//#include <sys/types.h>
//#include <sys/stat.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
//#include <netinet/tcp.h>   //Provides declarations for tcp header
//#include <netinet/udp.h>
//#include <netinet/ip.h>    //Provides declarations for ip header
//#include <netinet/if_ether.h>
//#include <arpa/inet.h>
#include <fcntl.h>
//#include <byteswap.h>
//#include <linux/if_ether.h>
//#include <linux/filter.h>
#include <sys/time.h>
#include <time.h>
//#include <sys/timerfd.h>
//#include <sys/ioctl.h>
//#include <netinet/in.h>
//#include <net/if.h>
//#include <arpa/inet.h>
#include <stdarg.h>
#include <assert.h>

//热路径（每个事件、每个包、每个连接）上的不变式（T12）：只在定义了 ENABLE_DEBUG_ASSERT 的构建里检查（make test 用的 *-assert 变体，D20），
//make all / make release 不编入。sizeof 不对表达式求值，只让其中的变量算作用到：表达式不能有副作用（发布构建里不执行），也不能含 lambda
#ifdef ENABLE_DEBUG_ASSERT
#ifdef NDEBUG
#error "ENABLE_DEBUG_ASSERT 要求 assert() 生效：不要同时定义 NDEBUG（zig 在 -O1 及以上会隐式定义）"
#endif
#define DEBUG_ASSERT(x) assert(x)
#else
#define DEBUG_ASSERT(x) ((void)sizeof(!(x)))
#endif

#include <my_ev.h>

#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>


//#include <linux/if_packet.h>
//#include <linux/if_tun.h>

#include<unordered_map>
#include<unordered_set>
#include<map>
#include<list>
#include <memory>
#include <vector>
#include <deque>
//#include <pair>
using  namespace std;

char *get_sock_error();


typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;

typedef unsigned short u16_t;
typedef short i16_t;

typedef u64_t my_time_t;

//const int max_data_len=2200;
//const int buf_len=max_data_len+200;

const int max_addr_len=100;
const int max_domain_len=256;
const int max_remote_len=max_domain_len+16;
const int dns_error_len=200;
const int dns_max_result=16;

const int max_data_len_udp=65536;
const int max_data_len_tcp=65536;//一次 recv 最多读这么多，也是 TCP 缓冲池每块的大小（T11）

const u32_t conn_timeout_udp=180000;
const u32_t conn_timeout_tcp=360000;

const int max_conn_num=20000;

const int conn_clear_ratio=30;
const int conn_clear_min=1;

const u32_t conn_clear_interval=1000;

const u32_t timer_interval=400;//this should be smaller than heartbeat_interval and retry interval;

extern int about_to_exit;

extern int socket_buf_size;



struct not_copy_able_t
{
	not_copy_able_t()
	{

	}
	not_copy_able_t(const not_copy_able_t &other)
	{
		assert(0==1);
	}
	const not_copy_able_t & operator=(const not_copy_able_t &other)
	{
		assert(0==1);
		return other;
	}
};

struct tcp_info_t:not_copy_able_t
{
	int fd;
	ev_io ev;//ev.data 指向所属的 tcp_pair_t（T10）
	//epoll_event ev;
	//char * data;
	char *buf;//本侧读到、还没发完的数据所在的池缓冲：recv 读进 scratch，没发完就把这块整块留下（D17），排空后还回池；data_len 为 0 时为 0
	char * begin;
	int data_len;
	int eof;//本侧 recv 已返回 0：不再读本侧，对另一侧发 shutdown(SHUT_WR)
	int connected;//已确认连接建立（accept 得到、connect 返回 0，或建连中可写且无错误）；为 0 时 watcher 同时等读写、不收发，对建连中的 socket 调 shutdown 会中止 connect
	int nodelay_wait;//只用于上游（T15）：TCP_NODELAY 还没设时为 1（还没 send 过）或 2（已 send 过一次，下次 send 前要设）；已设或 --disable-tcp-nodelay 时为 0
	tcp_info_t()
	{
		//data=(char*)malloc(max_data_len_tcp+200);

		memset(&ev,0,sizeof(ev));//对 ev_io_stop 等价于 ev_init：slab 新切出的内存未初始化，ev_io_init 之前走到释放路径时 ev_io_stop 要读 active/pending（T11）
		buf=0;
		begin=0;
		data_len=0;
		eof=0;
		connected=0;
		nodelay_wait=0;

	}
	~tcp_info_t()
	{
		//if(data)
			//free(data);
	}
	/*
	void free_memory()
	{
		free(data);
		data=0;
		begin=0;
	}*/
};

u32_t djb2(unsigned char *str,int len);
u32_t sdbm(unsigned char *str,int len);


struct address_t  //TODO scope id
{
	struct hash_function
	{
	    u32_t operator()(const address_t &key) const
		{
	    	return sdbm((unsigned char*)&key.inner,sizeof(key.inner));
		}
	};

	union storage_t //sockaddr_storage is too huge, we dont use it.
	{
		sockaddr_in ipv4;
		sockaddr_in6 ipv6;
	};
	storage_t inner;

	address_t()
	{
		clear();
	}
	void clear()
	{
		memset(&inner,0,sizeof(inner));
	}
	int from_str(char * str);

	int from_sockaddr(sockaddr *,socklen_t);

	char* get_str();//静态缓冲：一次 mylog 调用里最多用一次，且只在事件循环线程调用
	void to_str(char *);//s 至少 max_addr_len 字节；不能改 errno：与 get_sock_error() 同在一次 mylog 时可能先求值

	inline u32_t get_type()
	{
		return ((sockaddr*)&inner)->sa_family;
	}

	inline u32_t get_len()
	{
		u32_t type=get_type();
		switch(type)
		{
			case AF_INET:
				return sizeof(sockaddr_in);
			case AF_INET6:
				return sizeof(sockaddr_in6);
			default:
				DEBUG_ASSERT(0==1);
		}
		return -1;
	}

    bool operator == (const address_t &b) const
    {
    	//return this->data==b.data;
        return memcmp(&this->inner,&b.inner,sizeof(this->inner))==0;
    }

    int new_connected_udp_fd();
};
int resolve_domain_addresses(const char *host,u32_t port,address_t *addrs,int max_addrs,int &addr_count,char *err,int err_len);
int parse_remote_target(const char *str,address_t &addr,char *remote_host,int remote_host_len,u32_t &remote_port,int &remote_is_domain,char *err,int err_len);


struct forward_rule_t;

struct lru_node_t//侵入式 LRU 节点：连接对象继承它，直接挂进所属规则的 lru_collector_t，不另外分配（T9）
{
	lru_node_t *prev,*next;//不在链表中时都为 0
	my_time_t ts;
	lru_node_t()
	{
		prev=next=0;
		ts=0;
	}
};

struct udp_pair_t:not_copy_able_t,lru_node_t
{
	address_t adress;
	int fd;
	ev_io ev;//ev.data 指向本对象（T10）
	forward_rule_t *owner;
	int remote_index;
	int batch_group;//入向这一批里本会话的组号（U3），批外恒为 -1
	//u64_t last_active_time;
	udp_pair_t()
	{
		memset(&ev,0,sizeof(ev));//同 tcp_info_t（T11）
		owner=0;
		remote_index=-1;
		batch_group=-1;
	}
	//int not_used=0;
};

struct tcp_pair_t:not_copy_able_t,lru_node_t
{
	tcp_info_t local;
	tcp_info_t remote;
	//u64_t last_active_time;
	forward_rule_t *owner;
	int remote_index;
	address_t addr;//客户端地址，记日志时才格式化（T7）
	//int not_used=0;
	tcp_pair_t()
	{
		owner=0;
		remote_index=-1;
	}
};

u64_t get_current_time();
u64_t pack_u64(u32_t a,u32_t b);
u32_t get_u64_h(u64_t a);
u32_t get_u64_l(u64_t a);

void write_u16(char *,u16_t a);
u16_t read_u16(char *);

void write_u32(char *,u32_t a);
u32_t read_u32(char *);

void write_u64(char *,u64_t a);
u64_t read_uu64(char *);

char * my_ntoa(u32_t ip);

void myexit(int a);
void init_random_number_fd();
u64_t get_fake_random_number_64();
u32_t get_fake_random_number();
u32_t get_fake_random_number_nz();
u64_t ntoh64(u64_t a);
u64_t hton64(u64_t a);
bool larger_than_u16(uint16_t a,uint16_t b);
bool larger_than_u32(u32_t a,u32_t b);
void setnonblocking(int sock);

int set_buf_size(int fd,int socket_buf_size);

void  signal_handler(int sig);

void get_fake_random_chars(char * s,int len);
int random_between(u32_t a,u32_t b);


int round_up_div(int a,int b);

int set_timer(int epollfd,int &timer_fd);

//#endif /* COMMON_H_ */
