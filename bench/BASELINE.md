# tinyPortMapper 基准基线

两套基线：

- **loopback**（Docker VM，开发期回归用）：三个角色在同一容器里，全部走 127.0.0.1。转发器替对端付了约三分之一的内核成本，VM 的跨核唤醒也偏贵，所以只用来比较前后版本。
- **主机**（P0.7，发布门槛用）：客户端、转发器、后端分别在不同主机上，流量经真实网卡。待测，见第 4 节。

## 1. loopback 环境

| 项 | 值 |
|---|---|
| 宿主 | Apple M4 / macOS，colima VM：6 vCPU，8 GB，Linux 6.8.0-117-generic aarch64 |
| 容器 | `ubuntu:24.04`，`--network none --init --ulimit nofile=65536:65536`，`--sysctl net.ipv4.tcp_tw_reuse=1`，`--sysctl net.ipv4.ip_local_port_range="21000 65535"` |
| 绑核 | 转发器 CPU0（realm-2c 为 CPU0-1），客户端 CPU2-3，后端（`iperf3 -s :5201`、`fwdbench server :9000`）CPU4-5 |
| tinymapper | `4acc876`，`make all`（静态 glibc，`-O2`），运行参数 `-t -u --log-level 3` |
| tinymapper-musl | `4acc876`，Alpine 3.22 中 `make all`（静态 musl）。libev 在 musl 下没有 epoll，走 poll |
| rinetd | 0.73，release tarball，`-O2`，select 循环 |
| realm | 2.9.6 官方 `aarch64-unknown-linux-gnu`，`-u`，Linux 下 TCP 走 splice |
| 负载工具 | iperf3 3.16；`bench/fwdbench`（Go：echo server / rr / crr / hold） |
| 方法 | 每项 10 s（rr/crr 另有 1 s 预热，iperf3 `-O 1`），3 轮；同一测试项内各转发器交替执行；取中位数 |

基线数据来自迁移前的 `docs/bench`（tinymapper 编进镜像）；tinymapper-musl 各行取自迁移后的 `bench/results/20261023-182344`（与 glibc 交替执行，3 轮中位数）。迁移后在同一 VM 上做过对照：`tcp_rr_64` 两轮，新脚本 tinymapper 244.2k / 242.9k、realm-1c 204.1k / 205.1k ops/s，旧脚本 243.2k / 244.0k、204.4k / 203.2k ops/s。

## 2. loopback 基线（3 轮中位数）

单核类转发器（tinymapper、rinetd、realm-1c）在所有测试中 CPU 都是 96–100%，即转发器是瓶颈。

### TCP 吞吐（Gbit/s；括号内为转发器 CPU%）

| 转发器 | tcp_bw_1（单流） | tcp_bw_8（8 流） |
|---|---|---|
| direct（不经转发器） | 143.5 | 267.4 |
| tinymapper `4acc876` | 46.4（98） | 32.0（99） |
| tinymapper-musl `4acc876` | 42.2（99） | 30.7（99） |
| rinetd 0.73 | 39.8（99） | 30.4（99） |
| realm-1c | 144.4（98） | 143.9（100） |
| realm-2c | 137.6（98） | 193.2（190） |

### TCP 往返（ops/s；括号内为 p50 / p99 / p99.9 µs）

| 转发器 | tcp_rr_64 | tcp_rr_1000 | tcp_crr_32（每秒新建连接） |
|---|---|---|---|
| direct | 516,229（100 / 305 / 3,190） | 553,550（1,572 / 5,384 / 6,295） | 24,743（359 / 16,902 / 28,278） |
| tinymapper `4acc876` | 246,649（234 / 515 / 815） | 165,235（5,907 / 7,937 / 12,220） | 50,541（611 / 1,214 / 1,839） |
| tinymapper-musl `4acc876` | 225,444（263 / 549 / 621） | 159,281（6,224 / 7,858 / 12,358） | 41,158（758 / 1,239 / 1,863） |
| rinetd 0.73 | 231,865（262 / 554 / 868） | 181,724（5,461 / 7,527 / 10,298） | 50,187（618 / 1,183 / 2,580） |
| realm-1c | 206,621（308 / 406 / 980） | 161,160（1,253 / 129,052 / 134,829） | 34,459（936 / 1,317 / 2,510） |
| realm-2c（CPU 178–193%） | 391,220（151 / 392 / 684） | 315,301（1,163 / 13,456 / 17,164） | 53,899（541 / 1,502 / 3,237） |

direct 的 CRR 不是上限：TIME_WAIT 表打满，单目的端口的临时端口分配受限。

### UDP（iperf3 `-b 0` 不限速）

| 转发器 | udp_bw_1400 实收 Gbit/s | udp_bw_1400 实收 / 发送 kpps | udp_pps_64 实收 / 发送 kpps | udp_pps_64 丢包 % |
|---|---|---|---|---|
| direct | 6.64 | 593 / 616 | 1,148 / 1,148 | 0.1 |
| tinymapper `4acc876` | 4.12 | 368 / 1,221 | 421 / 1,290 | 67.5 |
| tinymapper-musl `4acc876` | 3.44 | 307 / 1,216 | 351 / 1,318 | 73.8 |
| rinetd 0.73 | 4.26 | 380 / 1,244 | 440 / 1,300 | 66.4 |
| realm-1c | 10.45 | 933 / 971 | 1,173 / 1,189 | 0.7 |
| realm-2c（CPU 137–144%） | 4.64 | 415 / 610 | 500 / 708 | 29.0 |

### 连接内存（tcp_mem_5000：5000 条连接各收发 32 KB 一次后保持）

| 转发器 | 建立连接数 | 空闲 RSS KB | 5000 连接 RSS KB | KB/连接 | 线程数 |
|---|---|---|---|---|---|
| tinymapper `4acc876` | 5,000 | 1,768 | 167,008 | 33.05 | 1 |
| tinymapper-musl `4acc876` | 5,000 | 992 | 185,832 | 36.97 | 1 |
| rinetd 0.73 | 4,998 | 1,688 | 164,784 | 32.63 | 1 |
| realm-1c | 5,000 | 4,516 | 49,664 | 9.03 | 2 |
| realm-2c | 5,000 | 4,576 | 49,708 | 9.02 | 3 |

rinetd 在 200 并发建连突发下有 2–49 个连接失败（listen backlog 硬编码为 128）。

## 3. 每单位 syscall 次数（loopback，`perf stat`）

单位：rr = 每个请求/响应对，crr = 每个连接，udp = 转发器发出的每个包，bw = 每 GB。计数窗口覆盖客户端整个生命周期。"不含等待" = 总计减去 epoll_pwait 与 poll/select；等待类调用随负载变化（perf 计数本身让吞吐下降 0–12%），其余是结构性次数，适合做回归门槛（§8.2）。`ret<0` 是失败返回（EAGAIN、connect 的 EINPROGRESS）。

| fwd | workload | 单位 | 吞吐 | **总计/单位** | 不含等待/单位 | recv* | send* | splice | epoll_pwait | epoll_ctl | accept* | connect | socket | set/getsockopt | fcntl | close | shutdown | pipe2 | 其他 | ret<0/单位 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| tinymapper `4acc876` | tcp_rr_64 | op | 245,612 | **4.035** | 4.000 | 2.000 | 2.000 | 0 | 0.035 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 0 | 0.000 |
| tinymapper `4acc876` | tcp_rr_1000 | op | 179,211 | **4.014** | 4.011 | 2.001 | 2.000 | 0 | 0.003 | 0.001 | 0.001 | 0.001 | 0.001 | 0.003 | 0.003 | 0.001 | 0 | 0 | 0.000 | 0.001 |
| tinymapper `4acc876` | tcp_crr_32 | conn | 49,034 | **21.004** | 20.004 | 3.000 | 2.000 | 0 | 1.000 | 2.000 | 1.000 | 1.000 | 1.000 | 4.000 | 4.000 | 2.000 | 0 | 0 | 0.004 | 1.000 |
| tinymapper `4acc876` | udp_pps_64 | pkt | 406,924 | **3.000** | 2.000 | 1.000 | 1.000 | 0 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 0.000 | 0.000 |
| tinymapper `4acc876` | tcp_bw_8 | GB | 31.2 Gbit/s | **129,718** | 122,086 | 61,041 | 61,040 | 0 | 7,631 | 1.213 | 0.287 | 0.287 | 0.287 | 1.149 | 1.149 | 0.575 | 0 | 0 | 0 | 0.543 |
| tinymapper-musl `4acc876` | tcp_rr_64 | op | 218,502 | **4.034** | 4.001 | 2.000 | 2.000 | 0 | 0.034（ppoll） | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 0.000 | 0.000 |
| tinymapper-musl `4acc876` | tcp_rr_1000 | op | 157,521 | **4.014** | 4.011 | 2.001 | 2.000 | 0 | 0.003（ppoll） | 0 | 0.001 | 0.001 | 0.001 | 0.003 | 0.003 | 0.002 | 0 | 0 | 0.000 | 0.001 |
| tinymapper-musl `4acc876` | tcp_crr_32 | conn | 38,021 | **21.001** | 20.000 | 3.000 | 2.000 | 0 | 1.000（ppoll） | 0 | 1.000 | 1.000 | 1.000 | 4.000 | 4.000 | 2.000 | 0 | 0 | 2.000 | 1.000 |
| tinymapper-musl `4acc876` | udp_pps_64 | pkt | 338,190 | **3.000** | 2.000 | 1.000 | 1.000 | 0 | 1.000（ppoll） | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.000 | 0.000 |
| tinymapper-musl `4acc876` | tcp_bw_8 | GB | 29.8 Gbit/s | **129,717** | 122,086 | 61,041 | 61,041 | 0 | 7,632（ppoll） | 0 | 0.301 | 0.301 | 0.301 | 1.203 | 1.203 | 0.601 | 0 | 0 | 0.668 | 0.568 |
| realm-1c | tcp_rr_64 | op | 197,026 | **6.055** | 6.001 | 0 | 0.000 | 6.000 | 0.054 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 2.000 |
| realm-1c | tcp_crr_32 | conn | 33,826 | **36.333** | 36.198 | 0 | 0.107 | 7.000 | 0.135 | 4.000 | 1.090 | 1.000 | 1.000 | 12.000 | 0 | 6.000 | 1.000 | 2.000 | 1.002 | 3.090 |
| realm-1c | udp_pps_64 | pkt | 1,281,198 | **0.221** | 0.219 | 0.110 (recvmmsg) | 0.110 (sendmmsg) | 0.000 | 0.002 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

musl 构建的 libev 没有 epoll（`libev/ev.c:302` 只在 glibc 下启用），epoll_pwait 一列实际是 ppoll，也没有 epoll_ctl；crr 的"其他"2.000 是每连接一次 mmap + munmap（推断：musl mallocng 给约 33 KB 的 `tcp_pair_t` 单独映射一组内存，释放即归还）。

失败返回明细：tinymapper crr 是 connect EINPROGRESS 1.000/conn；tinymapper bw 是 sendto EAGAIN 0.255/GB；realm rr 是 splice EAGAIN 2.000/op；realm crr 是 splice EAGAIN 2.000、accept4 EAGAIN 0.090、connect 1.000/conn；realm crr 的"其他"是 getpeername 1.000/conn。tinymapper 每个 TCP 连接的 4 次 setsockopt 来自 `set_buf_size()`（两个 fd 各设 SO_SNDBUF、SO_RCVBUF），4 次 fcntl 来自 `setnonblocking()`（两个 fd 各一次 F_GETFL + F_SETFL）。

### 3.1 迁移后复现与 P0.5 回归检查（2026-10-23）

同一 VM，迁移后的 `bench/run.sh`，3 轮中位数。`4acc876` 与工作区（P0.5 平台收敛后）在同一轮内交替执行（`bench/results/20261023-182344`）；"全量"列是 6 个转发器的完整运行（`bench/results/20261023-174915`，工作区构建）。

| 指标 | 第 2 节基线 `4acc876` | 复现 `4acc876` | 偏差 | 工作区 | 相对 `4acc876` | 全量（工作区） | musl `4acc876` | musl 工作区 |
|---|---|---|---|---|---|---|---|---|
| tcp_bw_1 Gbit/s | 46.4 | 47.1 | +1.5% | 47.1 | 0% | 46.9 | 42.2 | 41.4 |
| tcp_bw_8 Gbit/s | 32.0 | 31.7 | −0.9% | 31.7 | 0% | 31.4 | 30.7 | 30.5 |
| tcp_rr_64 ops/s | 246,649 | 245,620 | −0.4% | 245,932 | +0.1% | 247,672 | 225,444 | 225,383 |
| tcp_rr_1000 ops/s | 165,235 | 167,622 | +1.4% | 164,322 | −2.0% | 164,980 | 159,281 | 162,407 |
| tcp_crr_32 连接/s | 50,541 | 50,095 | −0.9% | 50,170 | +0.1% | 50,885 | 41,158 | 41,025 |
| udp_bw_1400 Gbit/s | 4.12 | 4.09 | −0.7% | 4.06 | −0.7% | 4.07 | 3.44 | 3.43 |
| udp_pps_64 kpps | 421 | 417 | −1.0% | 414 | −0.7% | 411 | 351 | 348 |
| KB/连接 | 33.05 | 33.05 | 0% | 33.05 | 0% | 33.05 | 36.97 | 36.97 |
| syscall/op（rr_64 / rr_1000 / crr / udp） | 4.035 / 4.014 / 21.004 / 3.000 | 4.035 / 4.015 / 21.004 / 3.000 | ≤ 0.001 | 4.035 / 4.014 / 21.005 / 3.000 | ≤ 0.001 | — | 4.034 / 4.014 / 21.001 / 3.000 | — |

结论：迁移后的脚本复现第 2 节基线，偏差 ≤ 1.5%（门槛 ±5%）；P0.5 前后差异在 ±2% 内，与轮间波动同级（rr_1000 的轮间范围本身是 161k–170k）；syscall/op 完全一致。全量运行中 rinetd、realm 各项与第 2 节的偏差也都在 ±5% 内。musl 构建比 glibc 慢：CRR −18%，UDP 64B −16%，tcp_rr_64 −8%。

## 4. 主机基线（P0.7，待测）

环境要求见优化指导 §8.3：3 台主机（客户端 → 转发器 → 服务端），10/25 GbE；只有 2 台时客户端和服务端放同一台。tinymapper 与 realm 同机、同核数、同负载对比；网卡跑满线速时，大流量比较每 Gbit/s 的 CPU 占用。

### 4.1 环境（待填，取自结果目录的 `env.txt`）

| 角色 | 主机型号 / CPU | 内核 | 网卡 / 驱动 / 队列数 | 绑核 |
|---|---|---|---|---|
| 客户端 | | | | |
| 转发器 | | | | |
| 后端 | | | | |

### 4.2 结果（待填，取自 `summary.md`）

| 转发器 | tcp_bw_1 Gbit/s（CPU%） | tcp_bw_8 Gbit/s（CPU%） | tcp_rr_64 ops/s（p99 µs） | tcp_rr_1000 ops/s（p99 µs） | tcp_crr_32 连接/s | udp_bw_1400 实收 Gbit/s | udp_pps_64 实收 kpps | KB/连接 |
|---|---|---|---|---|---|---|---|---|
| direct | | | | | | | | |
| tinymapper `4acc876` | | | | | | | | |
| realm-1c | | | | | | | | |
| realm-2c | | | | | | | | |

### 4.3 syscall 与剖析（待填，取自 `syscalls.md`、`profile.md`）

| fwd | workload | 总计/单位 | 不含等待/单位 | 用户态扣除 svc 落点 % | net_rx_action % | __wake_up_sync_key % | sched_waking/单位 |
|---|---|---|---|---|---|---|---|
| tinymapper `4acc876` | tcp_rr_64 | | | | | | |
| tinymapper `4acc876` | tcp_crr_32 | | | | | | |
| tinymapper `4acc876` | udp_pps_64 | | | | | | |
| tinymapper `4acc876` | tcp_bw_8 | | | | | | |

### 4.4 测量步骤

1. 准备主机：客户端和后端装好 `iperf3`；转发器主机装与内核匹配的 `perf`（Ubuntu：`linux-tools-$(uname -r)`）。开发机能用密钥免密 ssh 登录三台主机（`BatchMode`）；非 root 时需要免密 sudo，并设 `SUDO=sudo`。
2. 准备转发器主机架构的 tinymapper 静态二进制，文件名同 `build/`（`tinymapper-glibc-4acc876`）。架构与 Docker VM 相同时用 `REF=4acc876 docker/build.sh glibc`；不同时在该架构上 `git checkout 4acc876 && make all`，把产物放进一个目录，用 `BIN_DIR` 指定。realm 由脚本按转发器主机架构下载官方 2.9.6 并校验 sha256。
3. 内核参数：三台主机都要 `net.ipv4.tcp_tw_reuse=1`、`net.ipv4.ip_local_port_range="21000 65535"`，否则 CRR 会耗尽临时端口。可以手工按 §10.1 设置，也可以加 `APPLY_SYSCTL=1` 让脚本临时设置（不持久化）。
4. 运行（3 主机）：
   ```sh
   CLI_HOST=root@client FWD_HOST=root@fwd SRV_HOST=root@server \
   FWD_IP=10.0.0.2 SRV_IP=10.0.0.3 \
   CLI_CPUS=2-5 FWD_CPUS=2 FWD_CPUS2=2,3 SRV_CPUS=2-5 \
   FWDS="direct tinymapper@4acc876 realm-1c realm-2c" SC_FWDS="tinymapper@4acc876 realm-1c" \
   PROF_RUNS="tinymapper@4acc876:tcp_rr_64,tcp_rr_1000,tcp_crr_32,udp_pps_64,tcp_bw_8" \
   bench/host.sh
   ```
   2 主机：`SRV_HOST` 设成客户端主机，`SRV_IP` 设成客户端主机的数据面地址，`CLI_CPUS` 与 `SRV_CPUS` 不要重叠。绑核避开网卡中断所在的 CPU（`/proc/interrupts`）。
5. 结果在 `bench/results/host-<时间戳>/`：`raw.jsonl`、`summary.md`、`syscalls.{md,json}`、`profile.md`、`env.txt`、`run.log`；perf.data 留在转发器主机的 `$WORK`（默认 `/tmp/tpm-bench`）。把数字填入 4.1–4.3，并按剖析结果复核优化指导 §2 的收益估算。

## 5. 复现命令

```sh
bench/run.sh                                                   # loopback 全量：3 轮 × 8 项 × 6 个转发器，再做 syscall 计数，约 35 分钟
QUICK=1 bench/run.sh                                           # 冒烟：1 轮，每项 3 秒
FWDS="tinymapper@4acc876 tinymapper" bench/run.sh              # 基线提交与工作区前后对比（缺失的二进制自动编译）
STAGES=syscount SC_FWDS="tinymapper@4acc876 realm-1c" bench/run.sh   # 只做 syscall 计数（第 3 节）
STAGES=prof bench/run.sh                                       # CPU 剖析：clean / stat / rec / ipi 四个阶段
FWDS="tinymapper tinymapper+gro" bench/run.sh                  # 同一二进制不加 / 加 --udp-gro（U5），同一批交替
TOPO=veth TESTS="udp_bw_1400 udp_bw_1400_r udp_pps_64" FWDS="direct tinymapper tinymapper+gro" \
  SC_FWDS="tinymapper tinymapper+gro" SC_TESTS="udp_bw_1400 udp_bw_1400_r udp_pps_64" bench/run.sh   # veth 三命名空间拓扑（第 6 节）
python3 -I bench/summarize.py bench/results/<时间戳>/raw.jsonl     # 重新汇总
```

`REPS`、`DUR`、`TESTS`、`FWDS`、`SC_*`、`PROF_*` 等环境变量见 `bench/run.sh` 头部注释。各阶段的 tinymapper 默认都没有 `CAP_NET_ADMIN`（syscount/prof 容器是 `--privileged`，由 `TM_NOCAP` 去掉这一项），UDP socket 缓冲按 `rmem_max` 截断为 416 KiB，与本文的数据可比；`CAP_ADD=NET_ADMIN` 时各阶段统一带这项能力（U6：UDP 缓冲用 `SO_*BUFFORCE` 设，监听 4 MiB、会话 2 MiB），转发器名加 `+nocap` 后缀的同一二进制仍去掉它，可在同一批里对照。工具镜像 `tinymapper-bench:2`（U5 起加 iproute2、ethtool，152 → 159 MB；剖析镜像 `tinymapper-bench-prof:2` 254 → 261 MB）不含 tinymapper，二进制在运行时从 `build/` 挂载，改源码不需要重建镜像。

## 6. veth 三命名空间拓扑（`TOPO=veth`，U5）

loopback 的包不经过 NAPI，内核不做 GRO，`--udp-gro` 在那里只有开销、没有合并包。`TOPO=veth` 在同一个容器里（bench、syscount、prof 各阶段都是 `--privileged`）建三个网络命名空间，经两对 veth 相连，转发器一侧的两个 veth 模拟开了 GRO 和中断合并的网卡。绑核同 loopback；tinymapper 同 syscount 阶段去掉 `CAP_NET_ADMIN`（`TM_NOCAP=1`，UDP 缓冲 416 KiB，与 loopback 可比）。

```
 tpm-cli（CPU2-3）              tpm-fwd（CPU0）                                      tpm-srv（CPU4-5）
 iperf3 -c / fwdbench           tinymapper -l10.201.1.2:20000 -r10.201.2.2:<端口>      iperf3 -s :5201 / fwdbench server :9000
 c0 10.201.1.1 ──── veth ──── f0 10.201.1.2                 f1 10.201.2.1 ──── veth ──── s0 10.201.2.2
 tso off，gro off（默认）        gro on，gro_flush_timeout 50000 ns，napi_defer_hard_irqs 2（f0、f1 相同）   tso off，gro off
 默认路由 → 10.201.1.2           ip_forward=1（direct = 内核转发）                                       默认路由 → 10.201.2.1
```

| 设置 | 机制 | 目的 |
|---|---|---|
| f0、f1 `ethtool -K gro on` | veth 默认关 GRO；接收端请求 GRO 后才建 NAPI，`veth_xmit` 把包放进对端的 ptr_ring 再调度 NAPI | 入口走 NAPI + GRO |
| f0、f1 `gro_flush_timeout` 50000、`napi_defer_hard_irqs` 2（`VETH_FLUSH_NS`、`VETH_DEFER` 可改） | 一轮轮询结束后不重新"开中断"，挂 50 µs 定时器再轮询，连续 2 轮空才结束 | 模拟网卡中断合并：每轮积累一批包。只开 `gro on` 时发送方每次 send 返回前 softirq 就地轮询，每轮 1 个包，没有可合并的（探针：0 个合并包） |
| c0、s0 `ethtool -K tso off` | `veth_skb_is_eligible_for_gro()`：发送端没有 TSO，或接收端开 `rx-udp-gro-forwarding`/`rx-gro-list`，veth 才走 NAPI | 让到达 f0、f1 的 UDP 包进 GRO |
| 不开 `rx-udp-gro-forwarding` | 它让 GRO 在没有查到开 `UDP_GRO` 的 socket 时也聚合（全局 static key 关着时根本不查 socket），交给普通 socket 前再拆开 | 真实网卡没有这个行为；不开时只有 tinymapper `--udp-gro` 的 socket 收到合并包，开/关对照干净 |
| fwd 命名空间 `ip_forward=1`，cli、srv 默认路由指向它 | `direct` 成为内核 IP 转发 | 给出发送端与路径的上限 |
| 每个命名空间 `tcp_tw_reuse=1`、`ip_local_port_range 21000 65535` | 容器的 `--sysctl` 只作用于容器自己的命名空间 | 与 loopback 相同 |

拓扑核对（各接口的 offload 开关、定时器参数、MTU）写入各阶段的 `topo.txt`，不符时阶段失败。

**softirq 落点**（选择与理由）：veth 的 NAPI 在调度它的 CPU 上轮询，推迟用的定时器（`HRTIMER_MODE_REL_PINNED`）也挂在上一轮轮询的 CPU 上。
- 转发器的入向收包（GRO、IP/UDP 收包、入 socket 队列、唤醒转发器）在发送方的 CPU：正向在客户端 CPU2-3，回程在后端 CPU4-5。冒烟（udp_bw_1400，3.5 s）：NET_RX softirq CPU2 55k 次、CPU3 5.7k 次（约 17k 次/s，即每 50 µs 一轮），CPU4-5 约 0。
- 转发器发出的包：c0、s0 没开 GRO、没有 NAPI，`veth_xmit` 经 `netif_rx` 进 CPU0 的 backlog，在转发器 `sendmmsg` 的 `local_bh_enable` 里就地完成对端命名空间的收包（GSO 包交给普通 socket 时的 `udp_rcv_segment` 分段也在这里）。冒烟：不开 `--udp-gro` 时 CPU0 NET_RX 2.79M 次（每个包一次），开时 69k 次（每个 GSO 包一次）。
- 没用 threaded NAPI：`napi/f0-*` 内核线程在容器的 PID 命名空间里看不见，绑核要 `--pid=host`，在多人共用的 Docker VM 上让基准容器看见并能给所有进程发信号，代价大于收益。没用 RPS：它只把 GRO 之后的协议处理挪到别的 CPU，多一次 IPI 与 backlog 排队，也不像网卡。
- 后果：CPU0 替接收方付了它的收包开销（同 loopback），却不付转发器自己的入向收包开销（真实主机上在网卡中断所在的 CPU）；入向开销与负载工具挤在同一组 CPU 上，GRO 省下的 softirq 会让发送方发得更快。所以主指标是每 Gbit/s 的 CPU（进程 CPU% 与 CPU0 忙碌%），吞吐只作参考；发送方 CPU 的 softirq% 单独记录，用来看入向省了多少。

**CPU 与统计字段**（每行 `raw.jsonl`，两种拓扑都有）：
- `cpus`：客户端运行期间 `/proc/stat` 的差值，`fwd`（转发器所在 CPU）、`cli`、`srv` 各组的 busy（user+nice+system+irq+softirq）、usr、sys、softirq 百分比，组内相加。这个 VM 内核按 tick 采样记 softirq：在转发器上下文里执行的 softirq 同时记入进程的 stime 和 CPU0 的 softirq，所以进程 CPU%（`fwd_cpu_pct`）≈ CPU0 忙碌%（冒烟 94.8 / 95.2，其中 softirq 26.6）。`cli`、`srv` 的 busy 含 iperf3 自身（3.16 的接收方两个核都接近满），只看它们的 softirq。
- `fwd_win_s`：CPU 统计窗口的秒数。`fwd_cpu_pct × fwd_win_s ÷ (up_pkts + down_pkts)` 是每个转发的数据报的 CPU 时间，分母是转发器实际发出的数据报，不受接收端丢包影响（`docs/bench/u5/ab.py` 的"ns/数据报"列）。
- `tm_udp`：UDP 负载结束后给 tinymapper 发一次 SIGUSR1（只对含统计代码的二进制发，旧二进制收到会退出），记 `stats rule 1 udp:` 行；`--udp-gro` 时有 `up_gro`/`down_gro`（以合并包到达的数据报数）与 `up_gso_fallback`/`down_gso_fallback`。
- `summary.md` 的 UDP 表在有这些字段时多出"所在 CPU 忙碌%（softirq）"、udp_bw 的"CPU% 每 Gbit/s（进程 / 所在 CPU）"与"合并%"。
- syscount 的 UDP 单位：被测的是 tinymapper 时改用 perf 窗口前后两次 SIGUSR1 统计的 `up_pkts+down_pkts` 增量。GSO 一次发出多个数据报时 `OutDatagrams` 只加 1（`udp_send_skb`；实测 10 段的 GSO +1），veth 下开 `--udp-gro` 时 OutDatagrams 只有数据报数的约 1/46；loopback 下两者只差 2 个包。OutDatagrams 的换算仍记在 `syscalls.json` 的 `snmp_units`。

**限制**：
- iperf3 3.16 单流两端都是上限：1400 B 发送约 0.9–1.2 Mpps，接收约 0.86–0.98 Mpps（direct 也丢 15–26%）。转发器开 `--udp-gro` 后 CPU 有富余（冒烟约 45%），它转发的全部数据报（`up_drop`/`down_drop` 为 0）里有一部分在接收端 socket 丢掉，所以开/关之间的实收吞吐与丢包率不作主指标，每 Gbit/s（受接收端丢包影响）与每个数据报的 CPU 才是。
- 每个 veth 一个接收队列（一个 NAPI）；ptr_ring 256 个包（`VETH_RING_SIZE`），50 µs 内积压超过 256 个才会在 veth 上丢包（1.2 Mpps 时约 60 个）。
- MTU 1500：1400 B 每个合并包至多 46 个数据报（64 KiB），64 B 至多 64 个（`UDP_GRO_CNT_MAX`）。
- 剖析阶段（`STAGES=prof`）可在 veth 拓扑下跑，但 `summarize_prof.py` 的每包换算仍用 OutDatagrams，开 `--udp-gro` 时偏大。
- Docker VM 共用宿主 CPU；U5 能否默认开启以优化指导 §8.4 的主机门槛（真实网卡）为准。
