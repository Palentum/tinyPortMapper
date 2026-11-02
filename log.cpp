#include <common.h>
#include <log.h>

int log_level=log_info;

int enable_log_position=0;
int enable_log_color=1;
//文件作用域：main 之前、还是单线程时初始化（main() 补 0/1/2、dup2(1,2) 不改变 fd 1 是不是终端）。写成 log0 里的静态局部变量时
//首次初始化在先写日志的线程（可能是 worker）里，靠 __cxa_guard 互斥，glibc 2.34 以前静态链接（cross2、cross3）时 libstdc++ 可能认为没有线程、不加锁
static const int stdout_is_tty=isatty(1);


void log0(const char * file,const char * function,int line,int level,const char* str, ...) {

	//级别由调用它的宏判断：mylog 按 log_level 过滤，mylog_unfiltered 只排除 log_never
	if(level>log_trace||level<0) return ;


	//时间戳和各级别的"颜色[时间][级别]"前缀按秒缓存，每个线程一份（M2，L6：主线程与各 worker 线程都写日志，DNS 线程不写）。
	//用 localtime_r：glibc 的 localtime 每次调用都重新检查 /etc/localtime，每行多一次 stat。
	//enable_log_color 只在 process_arg 开头的预扫描里设置，之后不再改（在它之前只有 main() 里补 0/1/2 时打不开 /dev/null、ev_default_loop 失败会写一行，随即退出），不作为缓存的键
	static thread_local time_t time_buf_sec=-1;
	static thread_local char time_buf[100];
	static thread_local char prefix_buf[log_end][sizeof(log_color[0])+sizeof(time_buf)+sizeof(log_text[0])+4];//放得下最长的前缀，snprintf 不会截断
	static thread_local int prefix_len[log_end];//0：这一秒还没生成
	time_t timer=time(NULL);
	if(timer!=time_buf_sec)
	{
		struct tm tm_info;
		localtime_r(&timer,&tm_info);
		strftime(time_buf, 100, "%Y-%m-%d %H:%M:%S", &tm_info);
		time_buf_sec=timer;
		memset(prefix_len,0,sizeof(prefix_len));
	}

	//整行先拼进 line_buf，一次 fwrite
	const char *color=enable_log_color?log_color[level]:"";
	const char *reset=enable_log_color?RESET:"";
	int reset_len=strlen(reset);
	if(prefix_len[level]==0)
		prefix_len[level]=snprintf(prefix_buf[level],sizeof(prefix_buf[level]),"%s[%s][%s]",color,time_buf,log_text[level]);
	char line_buf[1024];
	int len=prefix_len[level];
	memcpy(line_buf,prefix_buf[level],len);
	if(enable_log_position)//file、function 是编译期常量（makefile 用相对路径，__FILE__ 如 main.cpp），合计不超过约 950 B 就不会写满 line_buf
		len+=snprintf(line_buf+len,sizeof(line_buf)-len,"[%s,func:%s,line:%d]",file,function,line);

	int room=(int)sizeof(line_buf)-len-reset_len;
	va_list vlist;
	va_start(vlist, str);
	int n=vsnprintf(line_buf+len,room,str,vlist);
	va_end(vlist);
	if(n>=0&&n<room)
	{
		memcpy(line_buf+len+n,reset,reset_len);
		fwrite(line_buf,1,len+n+reset_len,stdout);
	}
	else
	{
		//放不下（如很长的配置文件路径）：分几次写，不截断；锁住 stdout，别的线程的行不会插进来
		flockfile(stdout);
		fwrite(line_buf,1,len,stdout);
		va_start(vlist, str);
		vfprintf(stdout, str, vlist);
		va_end(vlist);
		fputs(reset,stdout);
		funlockfile(stdout);
	}

	//printf("\n");
	//if(enable_log_color)
		//printf(log_color[level]);
	//只有终端逐行刷新（stdio 对终端本就按 \n 刷新，这里把行尾的颜色复位码和不以 \n 结尾的行也写出）；
	//文件、管道、journald 等在缓冲写满时写出，其余由主线程的 main_timer_cb 每 timer_interval 刷新，myexit 退出前也会刷新
	if(stdout_is_tty)
		fflush(stdout);
}

void log_bare(int level,const char* str, ...)
{
	if(level>log_level) return ;
	if(level>log_trace||level<0) return ;
	if(enable_log_color)
		printf("%s",log_color[level]);
	va_list vlist;
	va_start(vlist, str);
	vfprintf(stdout, str, vlist);
	va_end(vlist);
	if(enable_log_color)
		printf("%s",RESET);
	fflush(stdout);

}
