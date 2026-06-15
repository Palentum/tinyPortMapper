#include "config.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <fstream>
#include <string>

using namespace std;


static void set_parse_error(char *err,int err_len,const char *msg)
{
	if(err!=0&&err_len>0)
	{
		snprintf(err,err_len,"%s",msg);
	}
}

static string trim_balance_token(const string &s)
{
	size_t begin=0;
	while(begin<s.size()&&isspace((unsigned char)s[begin])) begin++;
	size_t end=s.size();
	while(end>begin&&isspace((unsigned char)s[end-1])) end--;
	return s.substr(begin,end-begin);
}

int parse_remote_config_target(const char *str, remote_target_config_t &target, char *err, int err_len)
{
	remote_target_config_t clean;
	target=clean;
	if(str==0||str[0]==0)
	{
		set_parse_error(err,err_len,"empty remote");
		return -1;
	}
	if(strlen(str)>=max_remote_len)
	{
		set_parse_error(err,err_len,"remote address string is too long");
		return -1;
	}
	snprintf(target.remote_str,sizeof(target.remote_str),"%s",str);
	return parse_remote_target(target.remote_str,target.addr,target.host,sizeof(target.host),target.port,target.is_domain,err,err_len);
}

static int parse_balance_weight(const string &token,int &weight,char *err,int err_len)
{
	if(token.empty())
	{
		set_parse_error(err,err_len,"empty weight item");
		return -1;
	}
	for(size_t i=0;i<token.size();i++)
	{
		if(!isdigit((unsigned char)token[i]))
		{
			set_parse_error(err,err_len,"weight must contain only digits");
			return -1;
		}
	}
	errno=0;
	char *end=0;
	unsigned long value=strtoul(token.c_str(),&end,10);
	if(errno!=0||end==0||*end!=0||value<1||value>255)
	{
		set_parse_error(err,err_len,"weight must be between 1 and 255");
		return -1;
	}
	weight=(int)value;
	return 0;
}

int parse_balance_spec(const char *spec, int remote_count, balance_strategy_t &strategy, vector<int> &weights, char *err, int err_len)
{
	strategy=balance_strategy_off;
	weights.clear();
	if(remote_count<=0)
	{
		set_parse_error(err,err_len,"remote count must be positive");
		return -1;
	}

	string text=spec==0 ? string() : trim_balance_token(spec);
	if(text.empty())
	{
		if(remote_count==1)
		{
			return 0;
		}
		set_parse_error(err,err_len,"balance is required when multiple remotes are configured");
		return -1;
	}

	size_t colon=text.find(':');
	if(colon==string::npos)
	{
		set_parse_error(err,err_len,"missing ':' in balance spec");
		return -1;
	}
	string strategy_s=trim_balance_token(text.substr(0,colon));
	string weights_s=trim_balance_token(text.substr(colon+1));

	if(strategy_s=="off")
	{
		if(remote_count!=1)
		{
			set_parse_error(err,err_len,"off balance allows only one remote");
			return -1;
		}
		if(!weights_s.empty())
		{
			set_parse_error(err,err_len,"off balance does not accept weights");
			return -1;
		}
		return 0;
	}
	if(strategy_s=="roundrobin")
	{
		strategy=balance_strategy_roundrobin;
	}
	else if(strategy_s=="iphash")
	{
		strategy=balance_strategy_iphash;
	}
	else
	{
		set_parse_error(err,err_len,"unknown balance strategy");
		return -1;
	}

	if(weights_s.empty())
	{
		set_parse_error(err,err_len,"missing weight list");
		strategy=balance_strategy_off;
		return -1;
	}

	vector<int> parsed;
	size_t start=0;
	for(;;)
	{
		size_t comma=weights_s.find(',',start);
		string token;
		if(comma==string::npos)
		{
			token=trim_balance_token(weights_s.substr(start));
		}
		else
		{
			token=trim_balance_token(weights_s.substr(start,comma-start));
		}
		int weight=0;
		if(parse_balance_weight(token,weight,err,err_len)!=0)
		{
			strategy=balance_strategy_off;
			weights.clear();
			return -1;
		}
		parsed.push_back(weight);
		if(comma==string::npos)
		{
			break;
		}
		start=comma+1;
	}

	if((int)parsed.size()!=remote_count)
	{
		set_parse_error(err,err_len,"weight count must equal remote count");
		strategy=balance_strategy_off;
		weights.clear();
		return -1;
	}
	weights.swap(parsed);
	return 0;
}
namespace
{
	enum config_section_t
	{
		section_none,
		section_network,
		section_endpoint,
	};

	struct network_config_raw_t
	{
		int seen;
		int has_no_tcp;
		int has_use_udp;
		int line;
		bool no_tcp;
		bool use_udp;
		network_config_raw_t()
		{
			seen=0;
			has_no_tcp=0;
			has_use_udp=0;
			line=0;
			no_tcp=false;
			use_udp=false;
		}
	};

	struct endpoint_config_raw_t
	{
		int line;
		int has_listen;
		int has_remote;
		int has_extra_remotes;
		int has_balance;
		int has_no_tcp;
		int has_use_udp;
		int line_listen;
		int line_remote;
		int line_extra_remotes;
		int line_balance;
		int line_no_tcp;
		int line_use_udp;
		string listen;
		string remote;
		vector<string> extra_remotes;
		string balance;
		bool no_tcp;
		bool use_udp;
		endpoint_config_raw_t()
		{
			line=0;
			has_listen=0;
			has_remote=0;
			has_extra_remotes=0;
			has_balance=0;
			has_no_tcp=0;
			has_use_udp=0;
			line_listen=0;
			line_remote=0;
			line_extra_remotes=0;
			line_balance=0;
			line_no_tcp=0;
			line_use_udp=0;
			no_tcp=false;
			use_udp=false;
		}
	};

	static void config_fatal(const char *path,int line,const char *field,const char *reason)
	{
		mylog(log_fatal,"%s:%d: %s: %s\n",path,line,field,reason);
		myexit(-1);
	}

	static string trim(const string &s)
	{
		size_t begin=0;
		while(begin<s.size() && isspace((unsigned char)s[begin])) begin++;
		size_t end=s.size();
		while(end>begin && isspace((unsigned char)s[end-1])) end--;
		return s.substr(begin,end-begin);
	}

	static string strip_comment(const char *path,int line,const string &s)
	{
		string out;
		out.reserve(s.size());
		bool in_quote=false;
		for(size_t i=0;i<s.size();i++)
		{
			char c=s[i];
			if(c=='"')
			{
				in_quote=!in_quote;
				out.push_back(c);
				continue;
			}
			if(c=='#' && !in_quote)
			{
				break;
			}
			out.push_back(c);
		}
		if(in_quote)
		{
			config_fatal(path,line,"string","unterminated double quoted string");
		}
		return trim(out);
	}

	static size_t find_equal_outside_quote(const char *path,int line,const string &s)
	{
		bool in_quote=false;
		for(size_t i=0;i<s.size();i++)
		{
			char c=s[i];
			if(c=='"') in_quote=!in_quote;
			else if(c=='=' && !in_quote) return i;
		}
		config_fatal(path,line,"key","missing '=' after key");
		return string::npos;
	}

	static bool parse_bool_value(const char *path,int line,const char *field,const string &value)
	{
		if(value=="true") return true;
		if(value=="false") return false;
		config_fatal(path,line,field,"expected boolean literal true or false");
		return false;
	}

	static string parse_string_value(const char *path,int line,const char *field,const string &value)
	{
		if(value.size()<2 || value[0]!='"' || value[value.size()-1]!='"')
		{
			config_fatal(path,line,field,"expected double quoted string");
		}
		string result=value.substr(1,value.size()-2);
		for(size_t i=0;i<result.size();i++)
		{
			if(result[i]=='"')
			{
				config_fatal(path,line,field,"unexpected quote inside string");
			}
		}
		return result;
	}

	static vector<string> parse_string_array_value(const char *path,int line,const char *field,const string &value)
	{
		vector<string> result;
		size_t pos=0;
		size_t len=value.size();
		while(pos<len&&isspace((unsigned char)value[pos])) pos++;
		if(pos>=len||value[pos]!='[')
		{
			config_fatal(path,line,field,"expected inline string array");
		}
		pos++;
		while(pos<len&&isspace((unsigned char)value[pos])) pos++;
		if(pos<len&&value[pos]==']')
		{
			pos++;
			while(pos<len&&isspace((unsigned char)value[pos])) pos++;
			if(pos!=len)
			{
				config_fatal(path,line,field,"unexpected data after array");
			}
			return result;
		}
		for(;;)
		{
			while(pos<len&&isspace((unsigned char)value[pos])) pos++;
			if(pos>=len||value[pos]!='"')
			{
				config_fatal(path,line,field,"expected double quoted string array item");
			}
			pos++;
			string item;
			while(pos<len&&value[pos]!='"')
			{
				item.push_back(value[pos]);
				pos++;
			}
			if(pos>=len)
			{
				config_fatal(path,line,field,"unterminated double quoted string");
			}
			pos++;
			result.push_back(item);
			while(pos<len&&isspace((unsigned char)value[pos])) pos++;
			if(pos>=len)
			{
				config_fatal(path,line,field,"missing closing ']'");
			}
			if(value[pos]==',')
			{
				pos++;
				while(pos<len&&isspace((unsigned char)value[pos])) pos++;
				if(pos>=len||value[pos]==']')
				{
					config_fatal(path,line,field,"trailing comma or empty array item");
				}
				continue;
			}
			if(value[pos]==']')
			{
				pos++;
				while(pos<len&&isspace((unsigned char)value[pos])) pos++;
				if(pos!=len)
				{
					config_fatal(path,line,field,"unexpected data after array");
				}
				return result;
			}
			config_fatal(path,line,field,"missing comma between array items");
		}
	}

	static unsigned long parse_port(const char *path,int line,const char *field,const string &port_s)
	{
		if(port_s.empty())
		{
			config_fatal(path,line,field,"missing port");
		}
		for(size_t i=0;i<port_s.size();i++)
		{
			if(!isdigit((unsigned char)port_s[i]))
			{
				config_fatal(path,line,field,"port must contain only digits");
			}
		}
		errno=0;
		char *end=0;
		unsigned long port=strtoul(port_s.c_str(),&end,10);
		if(errno!=0 || end==0 || *end!=0 || port>65535)
		{
			config_fatal(path,line,field,"port must be between 0 and 65535");
		}
		return port;
	}

	static void validate_address_literal(const char *path,int line,const char *field,const string &value)
	{
		if(value.empty())
		{
			config_fatal(path,line,field,"empty address");
		}
		if(value[0]=='[')
		{
			size_t close=value.find("]:");
			if(close==string::npos)
			{
				config_fatal(path,line,field,"ipv6 address must use [ip]:port format");
			}
			string ip=value.substr(1,close-1);
			string port_s=value.substr(close+2);
			parse_port(path,line,field,port_s);
			if(ip.empty())
			{
				config_fatal(path,line,field,"empty ipv6 address");
			}
			in6_addr addr6;
			if(inet_pton(AF_INET6,ip.c_str(),&addr6)!=1)
			{
				config_fatal(path,line,field,"invalid ipv6 address literal");
			}
			return;
		}

		size_t colon=value.find(':');
		if(colon==string::npos)
		{
			config_fatal(path,line,field,"missing port separator ':'");
		}
		if(value.find(':',colon+1)!=string::npos)
		{
			config_fatal(path,line,field,"ipv6 address must be surrounded with []");
		}
		string ip=value.substr(0,colon);
		string port_s=value.substr(colon+1);
		parse_port(path,line,field,port_s);
		if(ip.empty())
		{
			config_fatal(path,line,field,"empty ipv4 address");
		}
		in_addr addr4;
		if(inet_pton(AF_INET,ip.c_str(),&addr4)!=1)
		{
			config_fatal(path,line,field,"invalid ipv4 address literal");
		}
	}

	static void parse_network_key(const char *path,int line,network_config_raw_t &network,const string &key,const string &value)
	{
		if(key=="no_tcp")
		{
			if(network.has_no_tcp) config_fatal(path,line,"no_tcp","duplicate key in [network]");
			network.no_tcp=parse_bool_value(path,line,"no_tcp",value);
			network.has_no_tcp=1;
			return;
		}
		if(key=="use_udp")
		{
			if(network.has_use_udp) config_fatal(path,line,"use_udp","duplicate key in [network]");
			network.use_udp=parse_bool_value(path,line,"use_udp",value);
			network.has_use_udp=1;
			return;
		}
		config_fatal(path,line,key.c_str(),"unknown key in [network]");
	}

	static void parse_endpoint_key(const char *path,int line,endpoint_config_raw_t &endpoint,const string &key,const string &value)
	{
		if(key=="listen")
		{
			if(endpoint.has_listen) config_fatal(path,line,"listen","duplicate key in [[endpoints]]");
			endpoint.listen=parse_string_value(path,line,"listen",value);
			endpoint.has_listen=1;
			endpoint.line_listen=line;
			return;
		}
		if(key=="remote")
		{
			if(endpoint.has_remote) config_fatal(path,line,"remote","duplicate key in [[endpoints]]");
			endpoint.remote=parse_string_value(path,line,"remote",value);
			endpoint.has_remote=1;
			endpoint.line_remote=line;
			return;
		}
		if(key=="extra_remotes")
		{
			if(endpoint.has_extra_remotes) config_fatal(path,line,"extra_remotes","duplicate key in [[endpoints]]");
			endpoint.extra_remotes=parse_string_array_value(path,line,"extra_remotes",value);
			endpoint.has_extra_remotes=1;
			endpoint.line_extra_remotes=line;
			return;
		}
		if(key=="balance")
		{
			if(endpoint.has_balance) config_fatal(path,line,"balance","duplicate key in [[endpoints]]");
			endpoint.balance=parse_string_value(path,line,"balance",value);
			endpoint.has_balance=1;
			endpoint.line_balance=line;
			return;
		}
		if(key=="no_tcp")
		{
			if(endpoint.has_no_tcp) config_fatal(path,line,"no_tcp","duplicate key in [[endpoints]]");
			endpoint.no_tcp=parse_bool_value(path,line,"no_tcp",value);
			endpoint.has_no_tcp=1;
			endpoint.line_no_tcp=line;
			return;
		}
		if(key=="use_udp")
		{
			if(endpoint.has_use_udp) config_fatal(path,line,"use_udp","duplicate key in [[endpoints]]");
			endpoint.use_udp=parse_bool_value(path,line,"use_udp",value);
			endpoint.has_use_udp=1;
			endpoint.line_use_udp=line;
			return;
		}
		config_fatal(path,line,key.c_str(),"unknown key in [[endpoints]]");
	}

	static void finalize_config(const char *path,int last_line,const network_config_raw_t &network,const vector<endpoint_config_raw_t> &endpoints,app_config_t &config)
	{
		config.rules.clear();
		if(endpoints.empty())
		{
			config_fatal(path,last_line+1,"endpoints","at least one [[endpoints]] section is required");
		}
		config.rules.reserve(endpoints.size());
		for(size_t i=0;i<endpoints.size();i++)
		{
			const endpoint_config_raw_t &endpoint=endpoints[i];
			if(!endpoint.has_listen)
			{
				config_fatal(path,endpoint.line,"listen","missing required endpoint key");
			}
			if(!endpoint.has_remote)
			{
				config_fatal(path,endpoint.line,"remote","missing required endpoint key");
			}
			if(endpoint.listen.size()>=max_addr_len)
			{
				config_fatal(path,endpoint.line_listen,"listen","address string is too long");
			}
			if(endpoint.remote.size()>=max_remote_len)
			{
				config_fatal(path,endpoint.line_remote,"remote","address string is too long");
			}
			if(endpoint.extra_remotes.size()+1>(size_t)max_remote_targets)
			{
				config_fatal(path,endpoint.line_extra_remotes,"extra_remotes","too many remote targets");
			}
			validate_address_literal(path,endpoint.line_listen,"listen",endpoint.listen);

			bool no_tcp=network.has_no_tcp ? network.no_tcp : false;
			bool use_udp=network.has_use_udp ? network.use_udp : false;
			if(endpoint.has_no_tcp) no_tcp=endpoint.no_tcp;
			if(endpoint.has_use_udp) use_udp=endpoint.use_udp;

			forward_rule_config_t rule;
			rule.enable_tcp=no_tcp ? 0 : 1;
			rule.enable_udp=use_udp ? 1 : 0;
			if(rule.enable_tcp==0 && rule.enable_udp==0)
			{
				config_fatal(path,endpoint.line,"no_tcp/use_udp","both tcp and udp are disabled for endpoint");
			}
			snprintf(rule.listen_str,sizeof(rule.listen_str),"%s",endpoint.listen.c_str());
			rule.local_addr.from_str(rule.listen_str);
			rule.remote_targets.reserve(1+endpoint.extra_remotes.size());
			char err[dns_error_len];
			remote_target_config_t target;
			if(parse_remote_config_target(endpoint.remote.c_str(),target,err,sizeof(err))!=0)
			{
				config_fatal(path,endpoint.line_remote,"remote",err);
			}
			rule.remote_targets.push_back(target);
			for(size_t j=0;j<endpoint.extra_remotes.size();j++)
			{
				const string &remote=endpoint.extra_remotes[j];
				if(remote.size()>=max_remote_len)
				{
					config_fatal(path,endpoint.line_extra_remotes,"extra_remotes","address string is too long");
				}
				if(parse_remote_config_target(remote.c_str(),target,err,sizeof(err))!=0)
				{
					config_fatal(path,endpoint.line_extra_remotes,"extra_remotes",err);
				}
				rule.remote_targets.push_back(target);
			}
			if(parse_balance_spec(endpoint.has_balance ? endpoint.balance.c_str() : 0,(int)rule.remote_targets.size(),rule.balance_strategy,rule.balance_weights,err,sizeof(err))!=0)
			{
				config_fatal(path,endpoint.has_balance ? endpoint.line_balance : endpoint.line,"balance",err);
			}
			config.rules.push_back(rule);
		}
	}
}

int load_config_file(const char *path, app_config_t &config)
{
	if(path==0 || path[0]==0)
	{
		config_fatal("<empty>",0,"path","config path is empty");
	}
	ifstream in(path);
	if(!in.is_open())
	{
		config_fatal(path,0,"path","failed to open config file");
	}

	network_config_raw_t network;
	vector<endpoint_config_raw_t> endpoints;
	config_section_t section=section_none;
	string line;
	int line_no=0;
	while(getline(in,line))
	{
		line_no++;
		string work=strip_comment(path,line_no,line);
		if(work.empty()) continue;
		if(work=="[network]")
		{
			if(network.seen)
			{
				config_fatal(path,line_no,"network","duplicate [network] section");
			}
			network.seen=1;
			network.line=line_no;
			section=section_network;
			continue;
		}
		if(work=="[[endpoints]]")
		{
			endpoints.emplace_back();
			endpoints.back().line=line_no;
			section=section_endpoint;
			continue;
		}
		if(work[0]=='[')
		{
			config_fatal(path,line_no,"section","unknown or unsupported section");
		}

		size_t eq=find_equal_outside_quote(path,line_no,work);
		string key=trim(work.substr(0,eq));
		string value=trim(work.substr(eq+1));
		if(key.empty())
		{
			config_fatal(path,line_no,"key","empty key");
		}
		if(section==section_network)
		{
			parse_network_key(path,line_no,network,key,value);
		}
		else if(section==section_endpoint)
		{
			parse_endpoint_key(path,line_no,endpoints.back(),key,value);
		}
		else
		{
			config_fatal(path,line_no,key.c_str(),"key appears outside [network] or [[endpoints]]");
		}
	}

	finalize_config(path,line_no,network,endpoints,config);
	return 0;
}
