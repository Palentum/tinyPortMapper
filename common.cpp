/*
 * comm.cpp
 *
 *  Created on: Jul 29, 2017
 *      Author: wangyu
 */

#include "common.h"
#include "log.h"



int about_to_exit=0;


int socket_buf_size=1024*1024;

#include <netdb.h>
char *get_sock_error()
{
	static char buf[1000];
	sprintf(buf, "%d:%s", errno,strerror(errno));
	return buf;
}


/*
struct random_fd_t
{
	int random_number_fd;
	random_fd_t()
	{
			random_number_fd=open("/dev/urandom",O_RDONLY);

			if(random_number_fd==-1)
			{
				mylog(log_fatal,"error open /dev/urandom\n");
				myexit(-1);
			}
			setnonblocking(random_number_fd);
	}
	int get_fd()
	{
		return random_number_fd;
	}
}random_fd;*/

/*
u64_t get_current_time()//ms
{
	//timespec tmp_time;
	//clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	//return ((u64_t)tmp_time.tv_sec)*1000llu+((u64_t)tmp_time.tv_nsec)/(1000*1000llu);
	return (u64_t)(ev_time()*1000);
}

u64_t get_current_time_us()
{
	//timespec tmp_time;
	//clock_gettime(CLOCK_MONOTONIC, &tmp_time);
	//return (uint64_t(tmp_time.tv_sec))*1000llu*1000llu+ (uint64_t(tmp_time.tv_nsec))/1000llu;
	return (u64_t)(ev_time()*1000*1000);
}
*/

//单调时钟，取默认 loop 本轮 epoll 返回时缓存的值，不再每次读时钟（T8）；墙钟跳变不影响超时（D16）。只能在事件循环线程、ev_default_loop() 之后调用
//mn_now 每轮才变，换算结果按它的位模式缓存：软浮点目标（mips24kc、arm）上 double 乘法与转换是库函数调用，每轮只做一次
u64_t get_current_time()
{
        static u64_t last_bits=~0ull,last_ms=0;//~0ull 是 NaN 的位模式，不会等于真实时间
        ev_tstamp now=my_ev_mono_now(EV_DEFAULT_UC);
        u64_t bits;
        memcpy(&bits,&now,sizeof(bits));
        if(bits!=last_bits)
        {
                last_bits=bits;
                last_ms=(u64_t)(now*1000);
        }
        return last_ms;
}


u64_t pack_u64(u32_t a,u32_t b)
{
	u64_t ret=a;
	ret<<=32u;
	ret+=b;
	return ret;
}
u32_t get_u64_h(u64_t a)
{
	return a>>32u;
}
u32_t get_u64_l(u64_t a)
{
	return (a<<32u)>>32u;
}

void write_u16(char * p,u16_t w)
{
	*(unsigned char*)(p + 1) = (w & 0xff);
	*(unsigned char*)(p + 0) = (w >> 8);
}
u16_t read_u16(char * p)
{
	u16_t res;
	res = *(const unsigned char*)(p + 0);
	res = *(const unsigned char*)(p + 1) + (res << 8);
	return res;
}

void write_u32(char * p,u32_t l)
{
	*(unsigned char*)(p + 3) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 0) = (unsigned char)((l >> 24) & 0xff);
}
u32_t read_u32(char * p)
{
	u32_t res;
	res = *(const unsigned char*)(p + 0);
	res = *(const unsigned char*)(p + 1) + (res << 8);
	res = *(const unsigned char*)(p + 2) + (res << 8);
	res = *(const unsigned char*)(p + 3) + (res << 8);
	return res;
}

void write_u64(char * s,u64_t a)
{
	assert(0==1);
}
u64_t read_u64(char * s)
{
	assert(0==1);
	return 0;
}


char * my_ntoa(u32_t ip)
{
	in_addr a;
	a.s_addr=ip;
	return inet_ntoa(a);
}
/*
u64_t get_true_random_number_64()
{
	u64_t ret;
	int size=read(random_fd.get_fd(),&ret,sizeof(ret));
	if(size!=sizeof(ret))
	{
		mylog(log_fatal,"get random number failed %d\n",size);

		myexit(-1);
	}

	return ret;
}
u32_t get_true_random_number()
{
	u32_t ret;
	int size=read(random_fd.get_fd(),&ret,sizeof(ret));
	if(size!=sizeof(ret))
	{
		mylog(log_fatal,"get random number failed %d\n",size);
		myexit(-1);
	}
	return ret;
}*/

/*
u32_t get_true_random_number_nz() //nz for non-zero
{
	u32_t ret=0;
	while(ret==0)
	{
		ret=get_true_random_number();
	}
	return ret;
}*/
/*
u64_t ntoh64(u64_t a)
{
	if(__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		return __bswap_64( a);
	}
	else return a;

}
u64_t hton64(u64_t a)
{
	if(__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		return __bswap_64( a);
	}
	else return a;

}*/

void setnonblocking(int sock) {
	int opts;
	opts = fcntl(sock, F_GETFL);

	if (opts < 0) {
    	mylog(log_fatal,"fcntl(sock,GETFL)\n");
		//perror("fcntl(sock,GETFL)");
		myexit(1);
	}
	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
    	mylog(log_fatal,"fcntl(sock,SETFL,opts)\n");
		//perror("fcntl(sock,SETFL,opts)");
		myexit(1);
	}
}

int set_buf_size(int fd,int socket_buf_size)
{
	if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &socket_buf_size, sizeof(socket_buf_size))<0)
	{
		mylog(log_fatal,"SO_SNDBUF fail  socket_buf_size=%d  errno=%s\n",socket_buf_size,get_sock_error());
		myexit(1);
	}
	if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &socket_buf_size, sizeof(socket_buf_size))<0)
	{
		mylog(log_fatal,"SO_RCVBUF fail  socket_buf_size=%d  errno=%s\n",socket_buf_size,get_sock_error());
		myexit(1);
	}
	return 0;
}

//UDP socket 的缓冲（U6）：*BUFFORCE 不受 net.core.rmem_max/wmem_max 截断，需要初始 user namespace 里的 CAP_NET_ADMIN
//（内核用 capable() 检查：主机上的 root 有，user namespace 里的 root 没有）。
//权限在进程运行期间不变，第一次失败（EPERM）后就只用普通选项，没有权限时每个新会话不多花 syscall
static int udp_buf_force=1;
//一个方向：force 时先试 *BUFFORCE；普通选项失败同 set_buf_size，退出
static void set_udp_buf_dir(int fd,int snd,int size,int force)
{
	if(force&&udp_buf_force)
	{
		if(setsockopt(fd, SOL_SOCKET, snd?SO_SNDBUFFORCE:SO_RCVBUFFORCE, &size, sizeof(size))==0)
			return;
		mylog(log_debug,"SO_SNDBUFFORCE/SO_RCVBUFFORCE failed (%s), UDP socket buffers are capped by net.core.rmem_max/wmem_max\n",get_sock_error());
		udp_buf_force=0;
	}
	if(setsockopt(fd, SOL_SOCKET, snd?SO_SNDBUF:SO_RCVBUF, &size, sizeof(size))<0)
	{
		mylog(log_fatal,"%s fail  socket_buf_size=%d  errno=%s\n",snd?"SO_SNDBUF":"SO_RCVBUF",size,get_sock_error());
		myexit(1);
	}
}
int set_udp_buf_size(int fd,int size)
{
	set_udp_buf_dir(fd,1,size,1);
	set_udp_buf_dir(fd,0,size,1);
	return 0;
}

void myexit(int a)
{
    if(enable_log_color)
   	 printf("%s\n",RESET);
   // clear_iptables_rule();
	//不走 exit()：析构静态对象时 detach 的 DNS 线程可能仍阻塞在 dns_cv 上，glibc 的 pthread_cond_destroy 会一直等它。_exit 不刷新 stdio，先 fflush
	fflush(stdout);
	_exit(a);
}
/*
void  signal_handler(int sig)
{
	about_to_exit=1;
    // myexit(0);
}*/

/*
void get_true_random_chars(char * s,int len)
{
	int size=read(random_fd.get_fd(),s,len);
	if(size!=len)
	{
		printf("get random number failed\n");
		exit(-1);
	}
}*/

/*
int random_between(u32_t a,u32_t b)
{
	if(a>b)
	{
		mylog(log_fatal,"min >max?? %d %d\n",a ,b);
		myexit(1);
	}
	if(a==b)return a;
	else return a+get_true_random_number()%(b+1-a);
}*/


int round_up_div(int a,int b)
{
	return (a+b-1)/b;
}
/*
int create_fifo(char * file)
{
	if(mkfifo (file, 0666)!=0)
	{
		if(errno==EEXIST)
		{
			mylog(log_warn,"warning fifo file %s exist\n",file);
		}
		else
		{
			mylog(log_fatal,"create fifo file %s failed\n",file);
			myexit(-1);
		}
	}
	int fifo_fd=open (file, O_RDWR);
	if(fifo_fd<0)
	{
		mylog(log_fatal,"create fifo file %s failed\n",file);
		myexit(-1);
	}
	struct stat st;
	if (fstat(fifo_fd, &st)!=0)
	{
		mylog(log_fatal,"fstat failed for fifo file %s\n",file);
		myexit(-1);
	}

	if(!S_ISFIFO(st.st_mode))
	{
		mylog(log_fatal,"%s is not a fifo\n",file);
		myexit(-1);
	}

	setnonblocking(fifo_fd);
	return fifo_fd;
}*/


int new_listen_socket(int &fd,u32_t ip,int port)
{
	fd =socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	int yes = 1;
	//setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	struct sockaddr_in local_me={0};

	socklen_t slen = sizeof(sockaddr_in);
	//memset(&local_me, 0, sizeof(local_me));
	local_me.sin_family = AF_INET;
	local_me.sin_port = htons(port);
	local_me.sin_addr.s_addr = ip;

	if (::bind(fd, (struct sockaddr*) &local_me, slen) == -1) {
		mylog(log_fatal,"socket bind error\n");
		//perror("socket bind error");
		myexit(1);
	}
	setnonblocking(fd);
    set_buf_size(fd,socket_buf_size);

    mylog(log_debug,"local_listen_fd=%d\n,",fd);

	return 0;
}
/*
int set_timer(int epollfd,int &timer_fd)
{
	int ret;
	epoll_event ev;

	itimerspec its;
	memset(&its,0,sizeof(its));

	if((timer_fd=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK)) < 0)
	{
		mylog(log_fatal,"timer_fd create error\n");
		myexit(1);
	}
	its.it_interval.tv_sec=(timer_interval/1000);
	its.it_interval.tv_nsec=(timer_interval%1000)*1000ll*1000ll;
	its.it_value.tv_nsec=1; //imidiately
	timerfd_settime(timer_fd,0,&its,0);
	setnonblocking(timer_fd);


	ev.events = EPOLLIN;
	ev.data.u64 = timer_fd;

	ret=epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_fd, &ev);
	if (ret < 0) {
		mylog(log_fatal,"epoll_ctl return %d\n", ret);
		myexit(-1);
	}
	return 0;
}*/

int address_t::from_str(char *str)
{
	clear();

	char ip_addr_str[100];u32_t port;
	mylog(log_info,"parsing address: %s\n",str);
	int is_ipv6=0;
	if(sscanf(str, "[%[^]]]:%u", ip_addr_str,&port)==2)
	{
		mylog(log_info,"its an ipv6 adress\n");
		inner.ipv6.sin6_family=AF_INET6;
		is_ipv6=1;
	}
	else if(sscanf(str, "%[^:]:%u", ip_addr_str,&port)==2)
	{
		mylog(log_info,"its an ipv4 adress\n");
		inner.ipv4.sin_family=AF_INET;
	}
	else
	{
		mylog(log_error,"failed to parse\n");
		myexit(-1);
	}

	mylog(log_info,"ip_address is {%s}, port is {%u}\n",ip_addr_str,port);

	if(port>65535)
	{
		mylog(log_error,"invalid port: %d\n",port);
		myexit(-1);
	}

	int ret=-100;
	if(is_ipv6)
	{
		ret=inet_pton(AF_INET6, ip_addr_str,&(inner.ipv6.sin6_addr));
		inner.ipv6.sin6_port=htons(port);
		if(ret==0)  // 0 if address type doesnt match
		{
			mylog(log_error,"ip_addr %s is not an ipv6 address, %d\n",ip_addr_str,ret);
			myexit(-1);
		}
		else if(ret==1) // inet_pton returns 1 on success
		{
			//okay
		}
		else
		{
			mylog(log_error,"ip_addr %s is invalid, %d\n",ip_addr_str,ret);
			myexit(-1);
		}
	}
	else
	{
		ret=inet_pton(AF_INET, ip_addr_str,&(inner.ipv4.sin_addr));
		inner.ipv4.sin_port=htons(port);

		if(ret==0)
		{
			mylog(log_error,"ip_addr %s is not an ipv4 address, %d\n",ip_addr_str,ret);
			myexit(-1);
		}
		else if(ret==1)
		{
			//okay
		}
		else
		{
			mylog(log_error,"ip_addr %s is invalid, %d\n",ip_addr_str,ret);
			myexit(-1);
		}
	}

	return 0;
}
static void set_err(char *err,int err_len,const char *fmt,...)
{
	if(err==0||err_len<=0)
	{
		return;
	}
	va_list ap;
	va_start(ap,fmt);
	vsnprintf(err,err_len,fmt,ap);
	va_end(ap);
	err[err_len-1]=0;
}

static int parse_port_str(const char *port_str,u32_t &port,char *err,int err_len)
{
	if(port_str==0||port_str[0]==0)
	{
		set_err(err,err_len,"empty port");
		return -1;
	}
	u32_t value=0;
	for(const char *p=port_str;*p;p++)
	{
		if(*p<'0'||*p>'9')
		{
			set_err(err,err_len,"invalid port");
			return -1;
		}
		value=value*10+(u32_t)(*p-'0');
		if(value>65535)
		{
			set_err(err,err_len,"invalid port");
			return -1;
		}
	}
	port=value;
	return 0;
}

static int copy_host_part(const char *begin,int len,char *host,int host_len,char *err,int err_len)
{
	if(len<=0)
	{
		set_err(err,err_len,"empty host");
		return -1;
	}
	if(len>=host_len||len>=max_domain_len)
	{
		set_err(err,err_len,"host too long");
		return -1;
	}
	memcpy(host,begin,len);
	host[len]=0;
	return 0;
}

int resolve_domain_addresses(const char *host,u32_t port,address_t *addrs,int max_addrs,int &addr_count,char *err,int err_len)
{
	addr_count=0;
	if(host==0||host[0]==0)
	{
		set_err(err,err_len,"empty host");
		return -1;
	}
	if(addrs==0||max_addrs<=0)
	{
		set_err(err,err_len,"invalid address buffer");
		return -1;
	}

	char service[16];
	snprintf(service,sizeof(service),"%u",port);
	addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=SOCK_STREAM;

	addrinfo *res=0;
	int ret=getaddrinfo(host,service,&hints,&res);
	if(ret!=0)
	{
		set_err(err,err_len,"%s",gai_strerror(ret));
		return -1;
	}

	for(addrinfo *p=res;p!=0&&addr_count<max_addrs;p=p->ai_next)
	{
		if(p->ai_family!=AF_INET&&p->ai_family!=AF_INET6)
		{
			continue;
		}
		addrs[addr_count].from_sockaddr(p->ai_addr,(socklen_t)p->ai_addrlen);
		if(addrs[addr_count].get_type()==AF_INET)
		{
			addrs[addr_count].inner.ipv4.sin_port=htons((u16_t)port);
		}
		else if(addrs[addr_count].get_type()==AF_INET6)
		{
			addrs[addr_count].inner.ipv6.sin6_port=htons((u16_t)port);
		}
		addr_count++;
	}

	freeaddrinfo(res);
	if(addr_count==0)
	{
		set_err(err,err_len,"no A or AAAA address found");
		return -1;
	}
	return 0;
}

int parse_remote_target(const char *str,address_t &addr,char *remote_host,int remote_host_len,u32_t &remote_port,int &remote_is_domain,char *err,int err_len)
{
	remote_is_domain=0;
	remote_port=0;
	if(remote_host!=0&&remote_host_len>0)
	{
		remote_host[0]=0;
	}
	if(str==0||str[0]==0)
	{
		set_err(err,err_len,"empty remote");
		return -1;
	}
	if(remote_host==0||remote_host_len<=0)
	{
		set_err(err,err_len,"invalid host buffer");
		return -1;
	}

	char host[max_domain_len];
	u32_t port=0;

	if(str[0]=='[')
	{
		const char *end=strchr(str,']');
		if(end==0)
		{
			set_err(err,err_len,"missing ']'");
			return -1;
		}
		if(end[1]!=':')
		{
			set_err(err,err_len,"missing ':'");
			return -1;
		}
		if(copy_host_part(str+1,(int)(end-str-1),host,sizeof(host),err,err_len)!=0)
		{
			return -1;
		}
		if(parse_port_str(end+2,port,err,err_len)!=0)
		{
			return -1;
		}
		addr.clear();
		addr.inner.ipv6.sin6_family=AF_INET6;
		int ret=inet_pton(AF_INET6,host,&addr.inner.ipv6.sin6_addr);
		if(ret!=1)
		{
			set_err(err,err_len,"invalid IPv6 address");
			return -1;
		}
		addr.inner.ipv6.sin6_port=htons((u16_t)port);
		remote_port=port;
		return 0;
	}

	const char *colon=strchr(str,':');
	if(colon==0)
	{
		set_err(err,err_len,"missing ':'");
		return -1;
	}
	if(strchr(colon+1,':')!=0)
	{
		set_err(err,err_len,"IPv6 address must be enclosed in []");
		return -1;
	}
	if(copy_host_part(str,(int)(colon-str),host,sizeof(host),err,err_len)!=0)
	{
		return -1;
	}
	if(strlen(host)>=(size_t)remote_host_len)
	{
		set_err(err,err_len,"host too long");
		return -1;
	}
	if(parse_port_str(colon+1,port,err,err_len)!=0)
	{
		return -1;
	}

	addr.clear();
	addr.inner.ipv4.sin_family=AF_INET;
	if(inet_pton(AF_INET,host,&addr.inner.ipv4.sin_addr)==1)
	{
		addr.inner.ipv4.sin_port=htons((u16_t)port);
		remote_port=port;
		return 0;
	}

	int ipv4_shaped=1;
	for(const char *p=host;*p;p++)
	{
		if(!((*p>='0'&&*p<='9')||*p=='.'))
		{
			ipv4_shaped=0;
			break;
		}
	}
	if(ipv4_shaped)
	{
		set_err(err,err_len,"invalid IPv4 address");
		return -1;
	}

	address_t addrs[dns_max_result];
	int addr_count=0;
	if(resolve_domain_addresses(host,port,addrs,dns_max_result,addr_count,err,err_len)!=0)
	{
		return -1;
	}
	strcpy(remote_host,host);
	remote_is_domain=1;
	remote_port=port;
	addr=addrs[0];
	return 0;
}


char * address_t::get_str()
{
	static char res[max_addr_len];
	to_str(res);
	return res;
}
static char *put_u32(char *p,u32_t v)
{
	char tmp[10];
	int n=0;
	do
	{
		tmp[n++]='0'+v%10;
		v/=10;
	}while(v);
	while(n) *p++=tmp[--n];
	return p;
}
static char *put_ipv4(char *p,const unsigned char *b)
{
	for(int i=0;i<4;i++)
	{
		if(i) *p++='.';
		p=put_u32(p,b[i]);
	}
	return p;
}
//地址只在记日志时格式化（T7），默认 info 级别下每个 TCP 连接 3 次；IPv4 与端口手写，不走 sprintf（每次约 100 ns → 15 ns）
void address_t::to_str(char * s)
{
	char *p=s;
	u32_t port=0;
	if(get_type()==AF_INET6)
	{
		*p++='[';
		if(IN6_IS_ADDR_V4MAPPED(&inner.ipv6.sin6_addr))//[::] 双栈监听上的 IPv4 客户端，输出与 glibc/musl 的 inet_ntop 相同
		{
			memcpy(p,"::ffff:",7);
			p=put_ipv4(p+7,(const unsigned char *)&inner.ipv6.sin6_addr+12);
		}
		else
		{
			if(inet_ntop(AF_INET6, &inner.ipv6.sin6_addr, p,INET6_ADDRSTRLEN)==0) //NULL on failure
			{
				mylog(log_error,"inet_ntop failed\n");
				myexit(-1);
			}
			p+=strlen(p);
		}
		*p++=']';
		port=inner.ipv6.sin6_port;
	}
	else if(get_type()==AF_INET)
	{
		p=put_ipv4(p,(const unsigned char *)&inner.ipv4.sin_addr);
		port=inner.ipv4.sin_port;
	}
	else
	{
		DEBUG_ASSERT(0==1);
	}
	*p++=':';
	p=put_u32(p,ntohs(port));
	*p=0;
}

int address_t::from_sockaddr(sockaddr * addr,socklen_t slen)
{
	memset(&inner,0,sizeof(inner));
	if(addr->sa_family==AF_INET6)
	{
		DEBUG_ASSERT(slen==sizeof(sockaddr_in6));
		inner.ipv6= *( (sockaddr_in6*) addr );

	}
	else if(addr->sa_family==AF_INET)
	{
		DEBUG_ASSERT(slen==sizeof(sockaddr_in));
		inner.ipv4= *( (sockaddr_in*) addr );
	}
	else
	{
		DEBUG_ASSERT(0==1);
	}
	return 0;
}

int address_t::new_connected_udp_fd()
{

	int new_udp_fd;
	new_udp_fd = socket(get_type(), SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_UDP);
	if (new_udp_fd < 0) {
		mylog(log_warn, "create udp_fd error\n");
		return -1;
	}
	//会话 socket 只在给了 --sock-buf 时才用 *BUFFORCE（D38 修订）：默认的 1 MiB 仍按 rmem_max/wmem_max 截断，
	//否则会话越多、持续过载时排队的内存与时延越大（反向 32 流满载 -13%，128 MB 路由器的 udp_mem[0] 约 11 MiB）。
	//--udp-gro 且监听缓冲更大时，发送缓冲取监听缓冲的大小、有权限时越过截断（D44）：一次入向回调可能读出监听队列里积压的
	//全部合并包交给这个会话，真实网卡到发完才释放 wmem，sndbuf 装不下就 EAGAIN 丢掉整组。代价是出口持续过载时这个会话在 qdisc
	//里常驻约 sndbuf 的数据（发送方向不计入 udp_mem）
	int snd=socket_buf_size,snd_force=sock_buf_explicit;
	if(udp_gro&&listen_fd_buf_size>socket_buf_size)
	{
		snd=listen_fd_buf_size;
		snd_force=1;
	}
	set_udp_buf_dir(new_udp_fd,1,snd,snd_force);
	set_udp_buf_dir(new_udp_fd,0,socket_buf_size,sock_buf_explicit);

	mylog(log_debug, "created new udp_fd %d\n", new_udp_fd);
	int ret = connect(new_udp_fd, (struct sockaddr *) &inner, get_len());
	if (ret != 0) {
		mylog(log_warn, "udp fd connect fail %d %s\n",ret,get_sock_error() );
		close(new_udp_fd);
		return -1;
	}

	return new_udp_fd;
}

u32_t djb2(unsigned char *str, int len) {
    u32_t hash = 5381;
    int c;
    for (int i=0; i<len ;i++) {
        c = *(str++);
        hash = ((hash << 5) + hash) ^ c; /* (hash * 33) ^ c */
    }

    hash = htonl(hash);
    return hash;
}

u32_t sdbm(unsigned char *str, int len) {
    u32_t hash = 0;
    int c;
    for (int i=0; i<len ;i++) {
        c = *(str++);
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    // hash=htonl(hash);
    return hash;
}
