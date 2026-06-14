#pragma once

#include "common.h"

struct forward_rule_config_t
{
	address_t local_addr;
	address_t remote_addr;
	int enable_tcp;
	int enable_udp;
	char listen_str[max_addr_len];
	char remote_str[max_addr_len];
	forward_rule_config_t()
	{
		enable_tcp=0;
		enable_udp=0;
		listen_str[0]=0;
		remote_str[0]=0;
	}
};

struct app_config_t
{
	vector<forward_rule_config_t> rules;
};

int load_config_file(const char *path, app_config_t &config);
