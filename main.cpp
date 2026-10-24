#include "common.h"
#include "log.h"
#include "git_version.h"
#include "config.h"

#include <sys/stat.h>
#include <netinet/tcp.h>
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
int sock_buf_explicit=0;//给了 --sock-buf：TCP socket 才设 SO_SNDBUF/SO_RCVBUF，否则交给内核自动调优

int max_pending_packet=0;

static app_config_t app_config;

const int listen_fd_buf_size=2*1024*1024;
static const u32_t dns_refresh_interval=30000;
static const int max_accept_per_round=8;
//内核把 listen backlog 截断为所在网络命名空间的 net.core.somaxconn（5.4 起默认 4096，以前 128）。不用 SOMAXCONN：musl 与 glibc 2.31 以前都定义为 128；不超过 65535：4.1 以前 sk_max_ack_backlog 是 u16
static const int listen_backlog=65535;
static const my_time_t lru_move_interval=1000;

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
		assert(key->next!=0);

		my_time_t value=get_current_time();
		assert(value >=head.next->ts);
		//距上次挪动不到 lru_move_interval 就不挪：链表仍按 ts 有序，ts 最多比实际最后活动早这么多，超时最多提前这么多（T8）
		if(value-key->ts<lru_move_interval) return 0;
		key->ts=value;
		unlink(key);
		link_front(key);

		return 0;
	}
	int new_key(key_t key)
	{
		assert(key->next==0);

		my_time_t value=get_current_time();
		if(!empty())
		{
			assert(value >=head.next->ts);
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
		assert(!empty());
		key=head.prev;
		return key->ts;
	}
	void erase(key_t key)
	{
		assert(key->next!=0);
		unlink(key);
		key->prev=key->next=0;
		cnt--;
	}
};

struct conn_manager_udp_t
{
	unordered_map<address_t,udp_pair_t*,address_t::hash_function> adress_to_info;

	list<udp_pair_t> udp_pair_list;
	long long last_clear_time;
	lru_collector_t lru;
	int reserved;
	//list<udp_pair_t>::iterator clear_it;

	conn_manager_udp_t()
	{
		last_clear_time=0;
		reserved=0;
		//clear_it=udp_pair_list.begin();
	}
	int reserve()
	{
		if(!reserved)
		{
			adress_to_info.reserve(10007);
			reserved=1;
		}
		return 0;
	}

	int erase(list<udp_pair_t>::iterator &it)
	{
		struct ev_loop * loop= ev_default_loop (0);
		ev_io_stop(loop, &it->ev);

		mylog(log_info,"[udp]inactive connection {%s} cleared, udp connections=%d\n",it->adress.get_str(),(int)(udp_pair_list.size()-1));
		mylog(log_debug,"[udp] lru.size()=%d\n",(int)lru.size()-1);

		auto tmp_it=adress_to_info.find(it->adress);
		assert(tmp_it!=adress_to_info.end());
		adress_to_info.erase(tmp_it);

		close(it->fd);
		lru.erase(&*it);
		udp_pair_list.erase(it);

		return 0;
	}

	int clear_remote_index(int remote_index)
	{
		int cnt=0;
		for(auto it=udp_pair_list.begin();it!=udp_pair_list.end();)
		{
			auto current=it;
			it++;
			if(current->remote_index==remote_index)
			{
				erase(current);
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
		int size=udp_pair_list.size();
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

			erase( static_cast<udp_pair_t *>(key)->it  );

			cnt++;
		}
		return 0;
	}
};

struct conn_manager_tcp_t
{
	list<tcp_pair_t> tcp_pair_list;
	long long last_clear_time;
	lru_collector_t lru;
	conn_manager_tcp_t()
	{
		last_clear_time=0;
	}
	int erase(list<tcp_pair_t>::iterator &it)
	{
		//两侧都 stop 之后才能释放：watcher->data 直接指向本对象，ev_io_stop 同时清除本轮还没回调的事件，释放后不会再有它的回调。
		//close 后 fd 号可能被本轮后面 accept 的连接复用，它的 watcher 经 ev_io_init（EV__IOFDSET）重新登记进 epoll（T10）
		struct ev_loop * loop= ev_default_loop (0);
		ev_io_stop(loop, &it->local.ev);
		ev_io_stop(loop, &it->remote.ev);

		close(it->local.fd);
		close(it->remote.fd);
		mylog(log_info,"[tcp]inactive connection {%s} cleared, tcp connections=%d\n",it->addr.get_str(),(int)(tcp_pair_list.size()-1));
		mylog(log_debug,"[tcp] lru.size()=%d\n",(int)lru.size()-1);
		lru.erase(&*it);
		tcp_pair_list.erase(it);
		return 0;
	}
	int erase_closed(list<tcp_pair_t>::iterator &it)//just a copy of erase()
	{
		struct ev_loop * loop= ev_default_loop (0);
		ev_io_stop(loop, &it->local.ev);
		ev_io_stop(loop, &it->remote.ev);

		close(it->local.fd);
		close(it->remote.fd);
		mylog(log_info,"[tcp]closed connection {%s} cleared, tcp connections=%d\n",it->addr.get_str(),(int)(tcp_pair_list.size()-1));
		mylog(log_debug,"[tcp] lru.size()=%d\n",(int)lru.size()-1);
		lru.erase(&*it);
		tcp_pair_list.erase(it);
		return 0;
	}
	int clear_remote_index(int remote_index)
	{
		int cnt=0;
		for(auto it=tcp_pair_list.begin();it!=tcp_pair_list.end();)
		{
			auto current=it;
			it++;
			if(current->remote_index==remote_index)
			{
				erase_closed(current);
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
		int size=tcp_pair_list.size();
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

			erase( static_cast<tcp_pair_t *>(key)->it  );

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
	assert(remote_count>0);
	if(remote_count==1||rule.balance_strategy==balance_strategy_off)
	{
		return 0;
	}
	assert((int)rule.balance_weights.size()==remote_count);

	if(rule.balance_strategy==balance_strategy_roundrobin)
	{
		assert((int)rule.rr_nodes.size()==remote_count);
		int best=-1;
		int total=0;
		for(int i=0;i<remote_count;i++)
		{
			balance_rr_node_t &node=rule.rr_nodes[i];
			assert(node.weight>0);
			assert(node.effective_weight>0);
			node.current_weight+=node.effective_weight;
			total+=node.effective_weight;
			if(best==-1||node.current_weight>rule.rr_nodes[best].current_weight)
			{
				best=i;
			}
		}
		assert(best>=0);
		assert(total>0);
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
			assert(0==1);
		}
		u32_t hash=sdbm((unsigned char*)hash_data,hash_len);
		int total=0;
		for(int i=0;i<remote_count;i++)
		{
			assert(rule.balance_weights[i]>0);
			total+=rule.balance_weights[i];
		}
		assert(total>0);
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
		assert(0==1);
		return 0;
	}

	assert(0==1);
	return 0;
}

void tcp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	//mylog(log_info,"[tcp]tcp_cb called \n");
	tcp_pair_t &tcp_pair=*(tcp_pair_t *)watcher->data;
	assert(tcp_pair.owner!=0);
	conn_manager_tcp_t &conn_manager_tcp=tcp_pair.owner->tcp_manager;

	//epoll_ctl 失败（如 ADD 超过 fs.epoll.max_user_watches 的 ENOSPC、ENOMEM）：libev 的 fd_kill 已停掉这个 watcher，只释放这一对（C9）。
	//两侧都失败时，另一侧还没回调的 EV_ERROR 由 erase_closed 里的 ev_io_stop 清除
	if((revents&EV_ERROR) !=0)
	{
		mylog(log_warn,"[tcp]connection {%s} closed bc of EV_ERROR (epoll_ctl failed),fd=%d\n",tcp_pair.addr.get_str(),watcher->fd);
		conn_manager_tcp.erase_closed(tcp_pair.it);
		return;
	}

	tcp_info_t *my_info_p,*other_info_p;
	if(watcher==&tcp_pair.local.ev)
	{
		mylog(log_trace,"[tcp]watcher==&tcp_pair.local.ev\n");
		my_info_p=&tcp_pair.local;
		other_info_p=&tcp_pair.remote;
	}
	else if(watcher==&tcp_pair.remote.ev)
	{
		mylog(log_trace,"[tcp]watcher==&tcp_pair.remote.ev\n");
		my_info_p=&tcp_pair.remote;
		other_info_p=&tcp_pair.local;
	}
	else
	{
		assert(0==1);
	}
	tcp_info_t &my_info=*my_info_p;
	tcp_info_t &other_info=*other_info_p;

	int my_fd=my_info.fd;
	int other_fd=other_info.fd;

	assert(watcher->fd==my_fd);

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
				conn_manager_tcp.erase_closed(tcp_pair.it);
				return;
			}
		}
		my_info.connected=1;
		//OPEN：建连期间客户端读到的数据由写分支发出，EOF 由下面推迟的 shutdown 发出；都没有就不再等可写
		if(other_info.data_len==0&&!other_info.eof)
		{
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_WRITE;
			ev_io_init (&my_info.ev, tcp_cb, my_fd, my_info.ev.events);
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
		assert(other_info.eof);
		ev_io_stop(loop, &my_info.ev);
		my_info.ev.events&=~EV_WRITE;
		ev_io_init (&my_info.ev, tcp_cb, my_fd, my_info.ev.events);
		ev_io_start(loop, &my_info.ev);
		if(shutdown(my_fd,SHUT_WR)!=0)
		{
			mylog(log_info,"[tcp]shutdown failed,connection {%s} closed bc of %s\n",tcp_pair.addr.get_str(),get_sock_error());
			conn_manager_tcp.erase_closed(tcp_pair.it);
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
		assert(my_info.data_len==0);
		int recv_len=recv(my_fd,my_info.data,max_data_len_tcp,0);//use a larger buffer than udp
		mylog(log_trace,"fd=%d,recv_len=%d\n",my_fd,recv_len);
		if(recv_len==0)
		{
			if(other_info.eof)
			{
				mylog(log_info,"[tcp]recv_len=%d,connection {%s} closed bc of EOF\n",recv_len,tcp_pair.addr.get_str());
				conn_manager_tcp.erase_closed(tcp_pair.it);
				return;
			}
			//半关闭：只有缓冲为空时才 recv，所以本方向没有待发数据，直接把 EOF 转给另一侧；反方向照常转发
			conn_manager_tcp.lru.update(&(*tcp_pair.it));
			my_info.eof=1;
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_READ;
			ev_io_init (&my_info.ev, tcp_cb, my_fd, my_info.ev.events);
			ev_io_start(loop, &my_info.ev);
			if(other_info.connected)
			{
				mylog(log_debug,"[tcp]connection {%s} half-closed by fd=%d\n",tcp_pair.addr.get_str(),my_fd);
				if(shutdown(other_fd,SHUT_WR)!=0)
				{
					mylog(log_info,"[tcp]shutdown failed,connection {%s} closed bc of %s\n",tcp_pair.addr.get_str(),get_sock_error());
					conn_manager_tcp.erase_closed(tcp_pair.it);
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
			conn_manager_tcp.erase_closed(tcp_pair.it);
			return;
		}
		conn_manager_tcp.lru.update(&(*tcp_pair.it));
		//tcp_pair.last_active_time=get_current_time();

		my_info.data_len=recv_len;
		my_info.begin=my_info.data;

		//上游建连中不发：它本来就在等可写，数据留在缓冲里、停读本侧，连上后由写分支发出
		int send_len=0;
		if(other_info.connected)
		{
			assert((other_info.ev.events & EV_WRITE)==0);
			send_len=send(other_fd,my_info.begin,my_info.data_len,0);
		}

		if(send_len<=0)
		{
			//NOP
		}
		else
		{
			my_info.data_len-=send_len;
			my_info.begin+=send_len;
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
				ev_io_init (&other_info.ev, tcp_cb, other_fd, other_info.ev.events);
				ev_io_start(loop, &other_info.ev);
			}


			//ev=my_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, my_fd, &ev);
			//assert(ret==0);
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_READ;
			ev_io_init (&my_info.ev, tcp_cb, my_fd, my_info.ev.events);
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

		assert(other_info.data_len!=0);
		int send_len=send(my_fd,other_info.begin,other_info.data_len,0);
		if(send_len==0)
		{
			mylog(log_warn,"[tcp]send_len=%d,connection {%s} closed bc of send_len==0\n",send_len,tcp_pair.addr.get_str());
			conn_manager_tcp.erase_closed(tcp_pair.it);
			return;
		}
		if(send_len<0)
		{
			mylog(log_info,"[tcp]send_len=%d,connection {%s} closed bc of %s\n",send_len,tcp_pair.addr.get_str(),get_sock_error());
			conn_manager_tcp.erase_closed(tcp_pair.it);
			return;
		}
		conn_manager_tcp.lru.update(&(*tcp_pair.it));

		//tcp_pair.last_active_time=get_current_time();

		mylog(log_trace,"[tcp]fd=%d send len=%d\n",my_fd,send_len);
		other_info.data_len-=send_len;
		other_info.begin+=send_len;

		if(other_info.data_len==0)
		{

			//ev=my_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, my_fd, &ev);
			//assert(ret==0);
			ev_io_stop(loop, &my_info.ev);
			my_info.ev.events&=~EV_WRITE;
			ev_io_init (&my_info.ev, tcp_cb, my_fd, my_info.ev.events);
			ev_io_start(loop, &my_info.ev);

			assert((other_info.ev.events & EV_READ)==0);



			//ev=other_info.ev;
			//ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, other_fd, &ev);
			//assert(ret==0);
			ev_io_stop(loop, &other_info.ev);
			other_info.ev.events|=EV_READ;
			ev_io_init (&other_info.ev, tcp_cb, other_fd, other_info.ev.events);
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
	assert(rule!=0);
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
		if(err!=EINTR&&err!=ECONNABORTED)
		{
			//EMFILE/ENFILE/ENOMEM or an LSM denial: the connection stays in the backlog and the level-triggered watcher would fire again at once; clear_timer_cb restarts it
			ev_io_stop(loop,watcher);
		}
		return 0;
	}

	address_t tmp_addr;
	tmp_addr.from_sockaddr((sockaddr*)&tmp_sockaddr_in,tmp_len);

	if(int(conn_manager_tcp.tcp_pair_list.size())>=max_conn_num)
	{
		mylog(log_warn,"[tcp]new connection from {%s},but ignored,bc of max_conn_num reached\n",tmp_addr.get_str());
		close(new_fd);
		return 1;
		//continue;
	}
	int remote_index=select_remote_index(*rule,tmp_addr);
	address_t &remote_addr=rule->remote_targets[remote_index].addr;


	int new_remote_fd = socket(remote_addr.get_type(), SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	if(new_remote_fd<0)
	{
		mylog(log_warn,"[tcp]new connection from {%s},but create new_remote_fd failed,%s\n",tmp_addr.get_str(),get_sock_error());
		close(new_fd);
		return 1;
	}
	if(sock_buf_explicit)
		set_buf_size(new_remote_fd,socket_buf_size);
	if(!disable_tcp_nodelay)
	{
		int yes=1;
		setsockopt(new_remote_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	}

	ret=connect(new_remote_fd,(struct sockaddr*) &remote_addr.inner,remote_addr.get_len());
	if(ret!=0&&errno!=EINPROGRESS)
	{
		//立即失败（如无路由的 ENETUNREACH、本地端口耗尽的 EADDRNOTAVAIL）：不建连接对
		mylog(log_warn,"[tcp]new connection from {%s},but connect to remote {%s} failed,%s\n",tmp_addr.get_str(),rule->remote_targets[remote_index].remote_str,get_sock_error());
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

	conn_manager_tcp.tcp_pair_list.emplace_back();
	auto it=conn_manager_tcp.tcp_pair_list.end();
	it--;

	conn_manager_tcp.lru.new_key(&(*it));

	tcp_pair_t &tcp_pair=*it;
	tcp_pair.owner=rule;
	tcp_pair.remote_index=remote_index;
	tcp_pair.addr=tmp_addr;

	mylog(log_info,"[tcp]new_connection from {%s},fd1=%d,fd2=%d,tcp connections=%d\n",tcp_pair.addr.get_str(),new_fd,new_remote_fd,(int)conn_manager_tcp.tcp_pair_list.size());

	tcp_pair.local.connected=1;
	tcp_pair.remote.connected=(ret==0);

	tcp_pair.local.fd=new_fd;
	//tcp_pair.local.ev.events=EV_READ;
	tcp_pair.local.ev.data=&tcp_pair;

	tcp_pair.remote.fd=new_remote_fd;
	//tcp_pair.remote.ev.events=EV_READ;
	tcp_pair.remote.ev.data=&tcp_pair;

	conn_manager_tcp.lru.update(&(*it));
	//tcp_pair.last_active_time=get_current_time();
	tcp_pair.it=it;

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
	//stdout 不是终端时 log0 不逐行刷新，日志最多晚一个 timer_interval 写出（D3）
	fflush(stdout);
}
void udp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	int ret;
	udp_pair_t & udp_pair=*(udp_pair_t *)watcher->data;
	int udp_fd=udp_pair.fd;
	assert(udp_pair.owner!=0);
	conn_manager_udp_t &conn_manager_udp=udp_pair.owner->udp_manager;
	//同 tcp_cb：libev 已停掉这个 watcher，只释放这个会话（C9）；客户端的下一个包会新建会话
	if((revents&EV_ERROR) !=0)
	{
		mylog(log_warn,"[udp]connection {%s} closed bc of EV_ERROR (epoll_ctl failed),udp fd=%d\n",udp_pair.adress.get_str(),udp_fd);
		conn_manager_udp.erase(udp_pair.it);
		return;
	}
	//assert(conn_manager.exist_fd(udp_fd));
	//if(!conn_manager.exist_fd(udp_fd)) continue;

	/*
	if((events[idx].events & EPOLLERR) !=0 ||(events[idx].events & EPOLLHUP) !=0)
	{
		mylog(log_warn,"[udp]EPOLLERR or EPOLLHUP from udp_remote_fd events[idx].events=%x \n",events[idx].events);

	}*/

	char data[max_data_len_udp+200];
	int data_len =recv(udp_fd,data,max_data_len_udp+1,0);
	mylog(log_trace, "[udp]received data from udp fd %d, len=%d\n", udp_fd,data_len);

	if(data_len==max_data_len_udp+1)
	{
		mylog(log_warn,"huge packet from {%s}, data_len > %d,dropped\n",udp_pair.adress.get_str(),max_data_len_udp);
		return;
	}

	if(data_len<0)
	{
		mylog(log_warn,"[udp]recv failed %d ,udp_fd%d,errno:%s\n", data_len,udp_fd,get_sock_error());
		return;
	}

	conn_manager_udp.lru.update(&udp_pair);
	//udp_pair.last_active_time=get_current_time();
	int local_listen_fd_udp=udp_pair.local_listen_fd;
	ret = sendto(local_listen_fd_udp, data,data_len,0, (struct sockaddr *)&udp_pair.adress.inner,udp_pair.adress.get_len());
	if (ret < 0) {
		mylog(log_warn, "[udp]sento returned %d,%s\n", ret,get_sock_error());
		//perror("ret<0");
	}
}
void udp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	forward_rule_t *rule=(forward_rule_t *)watcher->data;
	assert(rule!=0);
	conn_manager_udp_t &conn_manager_udp=rule->udp_manager;

	if((revents&EV_ERROR) !=0)
	{
		//同 tcp_accept_cb：如启动时 ADD 监听 fd 失败；libev 已停掉这个 watcher，clear_timer_cb 下一跳重新 start（C9）
		mylog(log_warn,"[udp]accept watcher of listen fd %d got EV_ERROR\n",watcher->fd);
		return ;
	}
	/*if((events[idx].events & EPOLLERR) !=0 ||(events[idx].events & EPOLLHUP) !=0)
	{
		mylog(log_error,"[udp]EPOLLERR or EPOLLHUP from listen_fd events[idx].events=%x \n",events[idx].events);
		//if there is an error, we will eventually get it at recvfrom();
	}*/

	char data[max_data_len_udp+200];
	int data_len;

	socklen_t tmp_len = sizeof(address_t::storage_t);
	address_t::storage_t tmp_sockaddr_in={0};
	memset(&tmp_sockaddr_in,0,sizeof(tmp_sockaddr_in));

	int local_listen_fd_udp=watcher->fd;

	if ((data_len = recvfrom(local_listen_fd_udp, data, max_data_len_udp+1, 0,
			(struct sockaddr *) &tmp_sockaddr_in, &tmp_len)) == -1) //<--first packet from a new ip:port turple
	{
		mylog(log_debug,"[udp]recv_from error,errno %s,this shouldnt happen,but lets try to pretend it didnt happen",get_sock_error());
		//myexit(1);
		return;
	}

	address_t tmp_addr;
	tmp_addr.from_sockaddr((sockaddr*)&tmp_sockaddr_in,tmp_len);

	data[data_len] = 0; //for easier debug

	//每包都走这里：地址只在记日志时格式化（T7）
	mylog(log_trace, "[udp]received data from udp_listen_fd from {%s}, len=%d\n",tmp_addr.get_str(),data_len);

	if(data_len==max_data_len_udp+1)
	{
		mylog(log_warn,"huge packet from {%s}, data_len > %d,dropped\n",tmp_addr.get_str(),max_data_len_udp);
		return;
	}

	auto it=conn_manager_udp.adress_to_info.find(tmp_addr);
	if(it==conn_manager_udp.adress_to_info.end())
	{

		if(int(conn_manager_udp.udp_pair_list.size())>=max_conn_num)
		{
			mylog(log_info,"[udp]new connection from {%s},but ignored,bc of max_conv_num reached\n",tmp_addr.get_str());
			return;
		}
		int remote_index=select_remote_index(*rule,tmp_addr);
		address_t &remote_addr=rule->remote_targets[remote_index].addr;
		int new_udp_fd=remote_addr.new_connected_udp_fd();
		if(new_udp_fd==-1)
		{
			mylog(log_info,"[udp]new connection from {%s} ,but create udp fd failed\n",tmp_addr.get_str());
			return;
		}

		//struct epoll_event ev;
		//ev.events = EPOLLIN;
		//ev.data.u64 = fd64;

		//ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, new_udp_fd, &ev);
		//assert(ret==0);


		conn_manager_udp.udp_pair_list.emplace_back();
		auto list_it=conn_manager_udp.udp_pair_list.end();
		list_it--;
		conn_manager_udp.lru.new_key(&(*list_it));
		udp_pair_t &udp_pair=*list_it;
		udp_pair.owner=rule;
		udp_pair.remote_index=remote_index;

		udp_pair.fd=new_udp_fd;
		udp_pair.ev.data=&udp_pair;
		ev_io_init (&udp_pair.ev, udp_cb, new_udp_fd, EV_READ);
		ev_io_start(loop, &udp_pair.ev);


		mylog(log_info,"[udp]new connection from {%s},udp fd=%d,udp connections=%d\n",tmp_addr.get_str(),new_udp_fd,(int)conn_manager_udp.udp_pair_list.size());

		udp_pair.adress=tmp_addr;
		//udp_pair.last_active_time=get_current_time();
		udp_pair.it=list_it;
		udp_pair.local_listen_fd=local_listen_fd_udp;

		conn_manager_udp.adress_to_info[tmp_addr]=&udp_pair;
		it=conn_manager_udp.adress_to_info.find(tmp_addr);
		//it=adress_to_info.
	}

	assert(it!=conn_manager_udp.adress_to_info.end() );

	udp_pair_t &udp_pair=*(it->second);
	int udp_fd=udp_pair.fd;
	conn_manager_udp.lru.update(&udp_pair);
	//udp_pair.last_active_time=get_current_time();

	int ret;
	ret = send(udp_fd, data,data_len, 0);
	if (ret < 0) {
		mylog(log_warn, "[udp]send returned %d,%s\n", ret,get_sock_error() );
	}

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
		rule.udp_manager.reserve();
		rule.local_listen_fd_udp=socket(rule.local_addr.get_type(), SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_UDP);
		if(rule.local_listen_fd_udp<0)
		{
			mylog(log_fatal,"rule %d [udp] create listen socket failed on %s, %s\n",rule.index,listen_addr,get_sock_error());
			myexit(1);
		}

		setsockopt(rule.local_listen_fd_udp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		set_buf_size(rule.local_listen_fd_udp,listen_fd_buf_size);

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
		}
		start_forward_rule(loop,rule);
	}

	start_dns_worker(loop);

	struct ev_timer clear_timer;

	ev_timer_init(&clear_timer, clear_timer_cb, 0, timer_interval/1000.0);
	ev_timer_start(loop, &clear_timer);

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
	printf("    --disable-tcp-nodelay                 do not set TCP_NODELAY on forwarded TCP connections (set on both sides by default)\n");
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
		{"disable-tcp-nodelay", no_argument,    0, 1},
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
			else if(strcmp(long_options[option_index].name,"disable-tcp-nodelay")==0)
			{
				disable_tcp_nodelay=1;
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
