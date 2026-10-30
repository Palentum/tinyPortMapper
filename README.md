# tinyPortMapper (or tinyPortForwarder)
A Lightweight High-Performance Port Mapping/Forwarding Utility using epoll, Supports both TCP and UDP 

# Supported Platforms
Linux only (including desktop/server Linux, Android phone/tablet, OpenWRT router, or Raspberry PI). Windows, macOS, FreeBSD and Cygwin builds are not supported. Binaries of `amd64` `x86` `mips_be` `mips_le` `arm` are provided.

Build with `make all` on Linux. On a non-Linux development machine, `docker/build.sh` builds the same binaries inside Linux containers.

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
    --sock-buf            <number>        buf size for socket, >=10 and <=10240, unit: kbyte
                                          TCP: kernel autotuning if not set; setting it disables autotuning
                                          and is capped by net.core.rmem_max/wmem_max; UDP sessions: default 1024
    --udp-listen-buf      <number>        buf size for UDP listen sockets, >=10 and <=10240, unit: kbyte, default 2048
                                          UDP buffers are capped by net.core.rmem_max/wmem_max unless running with CAP_NET_ADMIN
                                          (UDP sessions: only a --sock-buf value is set past the cap)
    --disable-tcp-nodelay                 do not set TCP_NODELAY on forwarded TCP connections (set on both sides by default)
    --disable-splice                      forward TCP by recv/send copies only; by default a direction whose last read
                                          was at least 16 KiB moves the next one with splice through a pipe
    --udp-gro                             receive UDP with UDP_GRO and forward merged packets with UDP_SEGMENT (GSO),
                                          Linux 5.0 or later, off by default
    --log-level           <number>        0: never    1: fatal   2: error   3: warn
                                          4: info (default)      5: debug   6: trace
    --log-position                        enable file name, function name, line number in log
    --disable-color                       disable log color
    -h,--help                             print this help message
```

TCP socket buffers are left to kernel autotuning by default. `--sock-buf` turns autotuning off for TCP, and the kernel caps the value at `net.core.rmem_max`/`wmem_max` (212992 before Linux 6.18), so setting it can lower throughput on high-latency paths. `--sock-buf 1024` restores the fixed TCP buffers of earlier versions.

UDP sockets keep explicit buffer sizes: 2048 KiB for each UDP listen socket (`--udp-listen-buf`) and 1024 KiB for each UDP session socket (`--sock-buf`). The kernel caps the value at `net.core.rmem_max`/`wmem_max` and then doubles it; before Linux 6.18 these default to 212992, so on an untuned host every UDP socket gets 416 KiB, and tinymapper logs an info line at startup when a listen socket is capped. With `CAP_NET_ADMIN` in the initial user namespace (root on the host has it; root in a container with Docker's default capabilities, in a rootless or unprivileged container, or in another user namespace does not), tinymapper sets the listen sockets with `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` and gets the full 4 MiB in each direction, which is what Linux 6.18 and later give without it. Session sockets are set past the cap only when `--sock-buf` is given, because their buffers add up with the number of sessions. For a dedicated user, setting `net.core.rmem_max` and `wmem_max` to 4194304 has the same effect on the listen sockets without granting `CAP_NET_ADMIN`, which also allows changing interfaces, routes and firewall rules (`AmbientCapabilities=` needs Linux 4.3 or later; `setcap cap_net_admin+ep` works on older kernels); it also raises the session buffers to 2 MiB.

Larger buffers let a burst, or a pause of tinymapper while other processes use the CPU, queue instead of being dropped: with tinymapper getting a third of a CPU and senders at 40–80% of what it could forward, 416 KiB listen buffers lost 8–38% of the packets and 4 MiB ones practically none. When tinymapper is CPU-bound the queue stays full and every packet waits behind it: a full 4 MiB listen socket holds about 4400 small or 1800 MTU-sized packets, 3 ms at 1.2 million packets per second and tens of milliseconds on a small router. Queued packets are kernel memory, and the receive queues of all UDP sockets on the host share one limit, the first value of `net.ipv4.udp_mem` (about 9% of RAM by default, about 11 MiB on a 128 MB router); once it is used up, every UDP socket on the host, dnsmasq for example, can queue only 4 KiB and drops the rest (`nstat -az UdpMemErrors` on Linux 5.15 and later). On routers with little memory that run tinymapper as root, or when latency under overload matters more than absorbing bursts, use a smaller `--udp-listen-buf` such as 512; `--udp-listen-buf 208` restores the 416 KiB listen buffers of earlier versions.

`--udp-gro` lets the kernel hand tinymapper a burst of UDP packets of one flow as a single merged buffer (`UDP_GRO`, Linux 5.0 or later) and sends it on as one buffer that the kernel or the network card splits back into the same packets (`UDP_SEGMENT`), instead of handling every packet on its own. Packet boundaries, sizes, order and content are unchanged. Merging happens only for packets that arrive through a network interface that does GRO (most physical and virtio NICs do by default), in bursts of the same flow, so it pays off for bulk UDP such as QUIC downloads or VPN tunnels; plain packets over loopback are never merged (only a local program that itself sends with `UDP_SEGMENT` reaches tinymapper merged), and small request/response traffic sees no difference. It is off by default because turning `UDP_GRO` on for any socket makes the kernel look up the destination socket for every UDP packet the host receives in the GRO stage, including traffic of other programs; with a wildcard listen address (`0.0.0.0` or `[::]`) on a router, routed UDP traffic to the same port (for example QUIC on 443 or WireGuard on 51820) is then merged on the way in and split again on the way out, so listen on a specific address there. On Linux 5.0–5.14, IPv4 clients of a `[::]` listener are merged only if the host also has an IPv4 socket with `UDP_GRO`.

Before Linux 6.11, segmentation needs TX checksum offload on the outgoing interface (`ethtool -k <dev> | grep tx-checksumming`), and merged packets whose segments do not fit the outgoing path MTU (for example 4-to-6 forwarding on 1500-byte links, or a client behind PPPoE) cannot be sent merged either. tinymapper then sends that session's merged packets one by one in that direction from then on, counts it in `up_gso_fallback`/`down_gso_fallback`, and logs an info line for the first such session of each rule and direction (later ones, whatever the error, at debug level). Merged packets make tinymapper use its whole 4 MiB UDP receive area, which otherwise only packets larger than 2 KiB touch, and one pass of the event loop can then move up to 4 MiB in each direction instead of 64 packets. A backend on the same host gets each merged packet as up to 64 datagrams queued at once, so give it a receive buffer that holds such bursts.

A merged burst read from the listen socket is sent to the upstream at once, and the session socket's send buffer must hold it until the network card has sent it. With `--udp-gro`, a session socket's send buffer therefore takes the size of `--udp-listen-buf` when that is larger than `--sock-buf` (past `net.core.wmem_max` with `CAP_NET_ADMIN`), so bursts that the listen buffer absorbs are not dropped on the way out. The price is that a session whose outgoing link stays overloaded keeps up to that much data queued in the interface's queue: about 34 ms behind a 1 Gbit/s link and 340 ms behind 100 Mbit/s with the default 4 MiB, in front of all other traffic of that interface with a plain FIFO qdisc (`fq_codel`, the default on most distributions and OpenWrt, keeps other flows apart). A smaller `--udp-listen-buf` lowers both. Without `CAP_NET_ADMIN`, raise `net.core.wmem_max` together with `rmem_max`; replies of several sessions bursting at once can still exceed the listen socket's send buffer and are counted in `down_drop`.

The TCP listen backlog follows `net.core.somaxconn` (4096 by default since Linux 5.4, 128 on older kernels, at most 65535); earlier tinymapper versions used a fixed 512. Raise it if bursts of new connections overflow the accept queue (`nstat -az TcpExtListenOverflows`). On routers with little memory, consider lowering it to 512–1024: connections waiting in the queue hold kernel memory until tinymapper accepts them, for example while it is out of file descriptors.

An idle TCP connection uses about 0.3 KB of tinymapper's memory (earlier versions reserved about 33 KB per connection). Data that the destination cannot take yet is kept in a 64 KiB buffer until it is sent, so a connection whose receiver is slower than its sender uses up to 64 KiB per direction: measured with 1000 slow clients, about 63 KB per connection when one side is slow and 109 KB when both are (earlier versions: 20 and 33 KB). On routers with little memory, account for this when many slow clients download through tinymapper. After such a burst, up to 64 free buffers (4 MiB) are kept for reuse.

Bulk TCP data is forwarded with `splice()` through a pipe, so it is not copied into tinymapper's memory and back: each time a direction reads at least 16 KiB, its next read goes through a pipe, and a smaller read sends it back to `recv`/`send`, which costs less for small messages, so interactive and request/response traffic is not affected. When tinymapper is busy and a source has more data waiting, one turn moves up to 256 KiB of it (four pipe loads) before serving other connections; this raised loopback throughput with eight streams by a third, while a small request on another connection waited about 0.3 ms instead of 0.1 ms for its turn. Pipes are pooled like the 64 KiB buffers: a direction holds one only while its destination cannot take the data yet (that data, at most 64 KiB as with a buffer, then waits in kernel memory instead), and up to 64 free pipes are kept for reuse. Each pipe uses two file descriptors: besides two per connection, every direction that is waiting for its destination holds two more (up to six per connection), and the free pipes plus the shared one keep up to 130 open. tinymapper never lets pipes take the last quarter of the open-file limit (`ulimit -n`, `LimitNOFILE=`), and when accepting a client or connecting to the remote fails for lack of file descriptors it closes the free pipes and tries again; pipes held by waiting directions stay open, so set the limit to at least four descriptors per expected connection, six if many connections stall in both directions at once. If the host runs short of TCP memory (`net.ipv4.tcp_mem`), the kernel shrinks socket send buffers; when that leaves a destination with very large segments (a loopback backend such as 127.0.0.1) room for fewer than two of them, tinymapper fixes that connection's send buffer at four segments (256 KiB on loopback), because otherwise each such connection waits for delayed acknowledgements; that connection then no longer grows its buffer. Destinations reached over a normal network are not affected, and with `--sock-buf` the buffers are left as set. A user without `CAP_SYS_RESOURCE` (root in a container with Docker's default capabilities lacks it too) gets small pipes once all its pipes together use `fs.pipe-user-pages-soft` pages (16384 by default, 1024 pipes); when no usable pipe can be created, for that reason or because file descriptors run out, tinymapper forwards by copy for the next 400 ms, logs an info line the first time, and counts those reads in `splice_fallback`. If `splice()` itself is not allowed (for example by a seccomp filter), tinymapper logs a warning and forwards all TCP data by copy from then on. `--disable-splice` forwards all TCP data by copy as earlier versions did.

When stdout is not a terminal (a file, a pipe, or the journal under systemd/procd), log lines are buffered and written every 400 ms, or when the stdio buffer fills up (4 KiB with glibc, 1 KiB with musl), instead of one write per line, so a line can appear up to 400 ms late, and lines written just before a crash, an unhandled signal such as SIGHUP, or a SIGKILL can be lost; on a terminal every line is written immediately. The time zone of log timestamps is read once at startup.

Send `SIGUSR1` (`kill -USR1 <pid>`) to write counters to the log; earlier versions exited on SIGUSR1. The lines are written at every `--log-level` except 0 and flushed at once:
```
stats rule 1 tcp: conns=12 total=34567 half_closed=1 up_bytes=123456789 down_bytes=987654321 up_splice=100663296 down_splice=964689920 splice_fallback=0
stats rule 1 udp: sessions=3 total=120 up_pkts=5000 up_bytes=320000 down_pkts=4990 down_bytes=319360 up_drop=0 down_drop=10
stats pool: bufs alloc=13 held=2 free=10 scratch=1 tcp_pairs slabs=1 free=52 udp_pairs slabs=1 free=61 pipes alloc=5 held=1 free=3 scratch=1
```
Each rule gets a `tcp` and/or a `udp` line: current connections or sessions, the number created since startup, TCP connections that one side has half-closed, and the bytes (UDP: packets and bytes) sent client→remote (`up_`) and remote→client (`down_`) since startup. `up_splice`/`down_splice` are the part of those TCP bytes that went through a pipe, and `splice_fallback` counts reads that would have used a pipe but were copied because none could be created. `up_drop`/`down_drop` count UDP packets dropped because sending failed, e.g. with EAGAIN when the socket buffer was full; packets that a full network interface queue drops are counted as sent (`nstat -az UdpSndbufErrors`, `tc -s qdisc`), which is more likely with large send buffers. Packets are counted one by one also when they were received or sent merged with `--udp-gro`; with that option the `udp` line ends with four more counters: `up_gro`/`down_gro`, the packets that arrived merged, and `up_gso_fallback`/`down_gso_fallback`, how many sessions had to stop sending merged packets in that direction. An unreachable UDP remote is not counted there: the packets are sent, the ICMP error is reported as a `recv failed` warning, and `up_pkts` grows while `down_pkts` does not. The `pool` line shows the 64 KiB TCP buffers (`alloc` = `held` by connections with unsent data + `free` for reuse + the shared receive buffer `scratch`) the slabs of 64 connection objects, which are never freed, and the pipes (`alloc` = `held` by directions with unsent data + `free` for reuse + the shared `scratch` pipe that reads go into).

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
