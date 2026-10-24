#include <common.h>
#include <log.h>

int log_level=log_info;

int enable_log_position=0;
int enable_log_color=1;


void log0(const char * file,const char * function,int line,int level,const char* str, ...) {

	if(level>log_level) return ;
	if(level>log_trace||level<0) return ;


	//时间戳按秒缓存（不加锁：只有主线程写日志，DNS 线程不写）。
	//用 localtime_r：glibc 的 localtime 每次调用都重新检查 /etc/localtime，每行多一次 stat
	static time_t time_buf_sec=-1;
	static char time_buf[100];
	time_t timer=time(NULL);
	if(timer!=time_buf_sec)
	{
		struct tm tm_info;
		localtime_r(&timer,&tm_info);
		strftime(time_buf, 100, "%Y-%m-%d %H:%M:%S", &tm_info);
		time_buf_sec=timer;
	}

	//整行先拼进 line_buf，一次 fwrite
	const char *color=enable_log_color?log_color[level]:"";
	const char *reset=enable_log_color?RESET:"";
	int reset_len=strlen(reset);
	char line_buf[1024];
	int len=snprintf(line_buf,sizeof(line_buf),"%s[%s][%s]",color,time_buf,log_text[level]);
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
		//放不下（如很长的配置文件路径）：分几次写，不截断
		fwrite(line_buf,1,len,stdout);
		va_start(vlist, str);
		vfprintf(stdout, str, vlist);
		va_end(vlist);
		fputs(reset,stdout);
	}

	//printf("\n");
	//if(enable_log_color)
		//printf(log_color[level]);
	//只有终端逐行刷新（stdio 对终端本就按 \n 刷新，这里把行尾的颜色复位码和不以 \n 结尾的行也写出）；
	//文件、管道、journald 等在缓冲写满时写出，其余由 clear_timer_cb 每 timer_interval 刷新，myexit 退出前也会刷新
	static const int stdout_is_tty=isatty(1);
	if(stdout_is_tty)
		fflush(stdout);

	if(log_level==log_fatal)
	{
		about_to_exit=1;
	}
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
