# tinyPortMapper (or tinyPortForwarder)
A Lightweight High-Performance Port Mapping/Forwarding Utility using epoll, Supports both TCP and UDP 

# Supported Platforms
Linux host (including desktop Linux,Android phone/tablet, OpenWRT router, or Raspberry PI). Binaries of `amd64` `x86` `mips_be` `mips_le` `arm` are provided.

# Getting Started

### Installing

Download binary release from https://github.com/wangyu-/tinyPortMapper/releases

### Running
Assume you want to map/forward local port 1234 to 10.222.2.1:443
```
# for both TCP and UDP
./tinymapper_amd64 -l0.0.0.0:1234 -r10.222.2.1:443 -t -u

# for TCP only
./tinymapper_amd64 -l0.0.0.0:1234 -r10.222.2.1:443 -t

# for TCP with a hostname remote
./tinymapper_amd64 -l0.0.0.0:1234 -rexample.com:443 -t

# for UDP only
./tinymapper_amd64 -l0.0.0.0:1234 -r10.222.2.1:443 -u

# for ipv6, both TCP and UDP
# ipv6 address must be surrounded with `[]`, ipv4 address must NOT be surrounded with `[]`
./tinymapper_amd64 -l[::]:1234 -r[2001:19f0:7001:1111:00:ff:11:22]:443 -t -u
```

You can also start multiple forwarding rules in one process with a config file:
```toml
[[endpoints]]
listen = "0.0.0.0:1234"
remote = "10.222.2.1:443"

[[endpoints]]
listen = "0.0.0.0:1235"
remote = "10.222.2.2:443"

[[endpoints]]
listen = "0.0.0.0:1236"
remote = "example.com:443"

[[endpoints]]
listen = "0.0.0.0:1237"
remote = "10.222.2.1:443"
extra_remotes = ["10.222.2.2:443", "example.com:443"]
balance = "roundrobin: 2, 1, 1"
```
```sh
./tinymapper_amd64 -c mapper.toml
```

The config parser supports only this project's minimal TOML subset: optional `[network]`
defaults with `no_tcp` / `use_udp`, plus `[[endpoints]]` entries with `listen`,
`remote`, `extra_remotes`, `balance`, `no_tcp`, and `use_udp`. `listen` remains
an IP literal. `remote` and `extra_remotes` support `ipv4:port`, `[ipv6]:port`,
and `hostname:port`; hostnames are resolved at startup and refreshed every
30 seconds. `extra_remotes` is a Realm-style inline string array. `balance`
supports `roundrobin` and `iphash`; the weight count must equal the total number
of `remote` plus `extra_remotes` targets. When an active resolved address
disappears from DNS results, only connections that selected that target are
closed and new connections use the new address. JSON config, recursive directory
loading, Realm transports, and proxy protocol settings are not supported.

##### NOTE
```
# local port and remote port can be the same
./tinymapper_amd64 -l0.0.0.0:443 -r10.222.2.1:443 -u

# you can also use 6-to-4 or 4-to-6 forward
./tinymapper_amd64 -l0.0.0.0:1234 -r[2001:19f0:7001:1111:00:ff:11:22]:443 -t -u
./tinymapper_amd64 -l[::]:1234 -r44.55.66.77:443 -t -u

# you can also use ipv4-mapped ipv6 address
# this is especially useful if you want to play with ipv6 and you dont have a real ipv6 address
./tinymapper_amd64 -l[::]:4433 -r[::ffff:10.222.2.1]:443 -t -u
./tinymapper_amd64 -l[::ffff:0.0.0.0]:4433 -r[::ffff:10.222.2.1]:443 -t -u
```
# Options
```
tinyPortMapper
git version:25ea4ec047    build date:Nov  4 2017 22:55:23
repository: https://github.com/wangyu-/tinyPortMapper

usage:
    ./this_program  -l <listen_ip>:<listen_port> -r <remote_ip_or_domain>:<remote_port> [-r <remote_ip_or_domain>:<remote_port> ...] [options]
    ./this_program  -c <config_file>  [options]

main options:
    -c, --config <path>                 use config file
    -l <listen_ip>:<listen_port>        listen address
    -r <remote_ip_or_domain>:<remote_port> remote target, can be repeated
    --balance <strategy: weights>       load balance repeated -r remotes, strategies: roundrobin, iphash
    -t                                  enable TCP forwarding/mapping
    -u                                  enable UDP forwarding/mapping
    remote supports IPv4, [IPv6], or hostname; hostname is refreshed every 30s

other options:
    --sock-buf            <number>        buf size for socket, >=10 and <=10240, unit: kbyte, default: 1024
    --log-level           <number>        0: never    1: fatal   2: error   3: warn
                                          4: info (default)      5: debug   6: trace
    --log-position                        enable file name, function name, line number in log
    --disable-color                       disable log color
    -h,--help                             print this help message
```

# Peformance Test
```
root@debian9:~# iperf3 -c 127.0.0.1 -p5202
Connecting to host 127.0.0.1, port 5202
[  4] local 127.0.0.1 port 37604 connected to 127.0.0.1 port 5202
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec   696 MBytes  5.84 Gbits/sec    0    639 KBytes
[  4]   1.00-2.00   sec   854 MBytes  7.17 Gbits/sec    0    639 KBytes
[  4]   2.00-3.00   sec   727 MBytes  6.10 Gbits/sec    0    639 KBytes
[  4]   3.00-4.00   sec   670 MBytes  5.62 Gbits/sec    0    639 KBytes
[  4]   4.00-5.00   sec   644 MBytes  5.40 Gbits/sec    0    639 KBytes
[  4]   5.00-6.00   sec   957 MBytes  8.03 Gbits/sec    0    639 KBytes
[  4]   6.00-7.00   sec   738 MBytes  6.19 Gbits/sec    0    639 KBytes
[  4]   7.00-8.00   sec   714 MBytes  5.99 Gbits/sec    0    639 KBytes
[  4]   8.00-9.00   sec   817 MBytes  6.85 Gbits/sec    0    639 KBytes
[  4]   9.00-10.00  sec   619 MBytes  5.19 Gbits/sec    0    639 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bandwidth       Retr
[  4]   0.00-10.00  sec  7.26 GBytes  6.24 Gbits/sec    0             sender
[  4]   0.00-10.00  sec  7.26 GBytes  6.24 Gbits/sec                  receiver

```

#### Details and more test results at:

https://github.com/wangyu-/tinyPortMapper/wiki/Performance-Test
