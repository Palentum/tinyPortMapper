#include "config.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <fstream>
#include <string>

using namespace std;

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
		int has_no_tcp;
		int has_use_udp;
		int line_listen;
		int line_remote;
		int line_no_tcp;
		int line_use_udp;
		string listen;
		string remote;
		bool no_tcp;
		bool use_udp;
		endpoint_config_raw_t()
		{
			line=0;
			has_listen=0;
			has_remote=0;
			has_no_tcp=0;
			has_use_udp=0;
			line_listen=0;
			line_remote=0;
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
			snprintf(rule.remote_str,sizeof(rule.remote_str),"%s",endpoint.remote.c_str());
			rule.local_addr.from_str(rule.listen_str);
			char err[dns_error_len];
			if(parse_remote_target(rule.remote_str,rule.remote_addr,rule.remote_host,sizeof(rule.remote_host),rule.remote_port,rule.remote_is_domain,err,sizeof(err))!=0)
			{
				config_fatal(path,endpoint.line_remote,"remote",err);
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
