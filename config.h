#pragma once

#include "common.h"

const int max_remote_targets = 255;

enum balance_strategy_t
{
	balance_strategy_off,
	balance_strategy_roundrobin,
	balance_strategy_iphash,
};

struct remote_target_config_t
{
	address_t addr;
	int is_domain;
	char remote_str[max_remote_len];
	char host[max_domain_len];
	u32_t port;
	remote_target_config_t()
	{
		is_domain=0;
		remote_str[0]=0;
		host[0]=0;
		port=0;
	}
};

//规则配置里 worker 的运行时也要的部分：main.cpp 的 forward_rule_t 继承它，worker_add_rule 整体复制
struct forward_rule_base_t
{
	address_t local_addr;
	int enable_tcp;
	int enable_udp;
	balance_strategy_t balance_strategy;
	vector<int> balance_weights;
	forward_rule_base_t()
	{
		enable_tcp=0;
		enable_udp=0;
		balance_strategy=balance_strategy_off;
	}
};

struct forward_rule_config_t:forward_rule_base_t
{
	vector<remote_target_config_t> remote_targets;
};

struct app_config_t
{
	vector<forward_rule_config_t> rules;
};

int parse_remote_config_target(const char *str, remote_target_config_t &target, char *err, int err_len);
int parse_balance_spec(const char *spec, int remote_count, balance_strategy_t &strategy, vector<int> &weights, char *err, int err_len);
void load_config_file(const char *path, app_config_t &config);//出错时写 fatal 日志并退出，不返回
