# bench.sh、syscount.sh、prof/prof.sh 共用：角色执行、后端与转发器启停、计数阶段（由各脚本 source）
#
# 三个角色：cli = 负载客户端（iperf3 / fwdbench），fwd = 被测转发器，srv = 后端（iperf3 -s、fwdbench echo）。
# 角色主机（CLI_HOST / FWD_HOST / SRV_HOST）为空时在本机执行：loopback 模式，容器内三个角色同机，地址都是 127.0.0.1；
# 这时 TOPO=veth 让三个角色各在一个网络命名空间里、经两对 veth 相连（topo_up，容器需 --privileged）；
# 非空时经 RSH 在该主机执行：主机模式，由 bench/host.sh 设置。主机模式在 macOS 上编排，脚本需兼容 bash 3.2。

RSH=${RSH:-ssh}                  # 远程执行：$RSH <主机> '<sh 命令>'；RSH=docker 表示 docker exec <容器> sh -c
WORK=${WORK:-/tmp/tpm-bench}     # 各角色主机上放日志与临时文件的目录
CLI_HOST=${CLI_HOST:-}; FWD_HOST=${FWD_HOST:-}; SRV_HOST=${SRV_HOST:-}
FWD_IP=${FWD_IP:-127.0.0.1}      # 客户端访问转发器的地址
SRV_IP=${SRV_IP:-127.0.0.1}      # 转发器（direct 时为客户端）访问后端的地址
CLI_CPUS=${CLI_CPUS:-2,3}; SRV_CPUS=${SRV_CPUS:-4,5}
FWD_CPUS=${FWD_CPUS:-0}; FWD_CPUS2=${FWD_CPUS2:-0,1}   # 单核转发器 / realm-2c
BIN=${BIN:-/build}               # fwd 上 tinymapper-{glibc,musl}[-后缀] 所在目录
TM_LOG_LEVEL=${TM_LOG_LEVEL:-3}  # tinymapper 的 --log-level；4 为默认级别 info，CRR 每连接写 3 行日志
FWDBENCH=${FWDBENCH:-fwdbench}; IPERF3=${IPERF3:-iperf3}; REALM=${REALM:-realm}; RINETD=${RINETD:-rinetd}
PERF=${PERF:-perf}; SUDO=${SUDO:-}   # fwd 上的 perf 与提权前缀
TOPO=${TOPO:-loopback}           # loopback | veth（见 topo_up）
VETH_FLUSH_NS=${VETH_FLUSH_NS:-50000}; VETH_DEFER=${VETH_DEFER:-2}   # veth 拓扑转发器一侧的 gro_flush_timeout / napi_defer_hard_irqs
FPORT=20000; IPERF_PORT=5201; ECHO_PORT=9000; SINK_PORT=9001
FWD_UID=${FWD_UID:-4242}         # +nonroot 转发器的 uid/gid（专用、不与其他进程共用，pipe-user-pages-soft 按 uid 计）
BULK_SNDBUF=${BULK_SNDBUF:-32768}; BULK_STALL=${BULK_STALL:-1}   # tcp_bulk_*：客户端 SO_SNDBUF（字节）、_stall 时 sink 的停顿（秒）
FWD_PID=""; FWD_NAME=""; FWD_SET=""; SRV_PIDS=""; TARGET_IP=""; TARGET_PORT=""
CLI_NS=""; FWD_NS=""; SRV_NS=""  # veth 拓扑下各角色的网络命名空间

log() { echo "[$(date +%T)] $*" >&2; }

# on <角色> <命令>：在角色所在主机（veth 拓扑下为角色的网络命名空间）用 sh 执行
on() {
  local h n
  case $1 in cli) h=$CLI_HOST n=$CLI_NS ;; fwd) h=$FWD_HOST n=$FWD_NS ;; srv) h=$SRV_HOST n=$SRV_NS ;; esac
  shift
  if [ -n "$n" ]; then ip netns exec "$n" sh -c "$*"
  elif [ -z "$h" ]; then sh -c "$*"
  elif [ "$RSH" = docker ]; then docker exec "$h" sh -c "$*"
  else $RSH "$h" "$*"; fi </dev/null
}

# topo_up [检查结果文件]：TOPO=veth 时建三命名空间拓扑并改用其地址；loopback 时什么都不做。
#   tpm-cli                 tpm-fwd                                   tpm-srv
#   c0 10.201.1.1 ─ veth ─ f0 10.201.1.2 [转发器] f1 10.201.2.1 ─ veth ─ s0 10.201.2.2
# 绑核同 loopback。转发器一侧的 f0（正向入口）、f1（回程入口）模拟有中断合并的网卡：gro on，gro_flush_timeout 与
# napi_defer_hard_irqs 让 NAPI 推迟到定时器、每轮处理一批；对端 c0、s0 关 TSO，满足 veth_skb_is_eligible_for_gro（发送端没有 TSO）。
# 不开 rx-udp-gro-forwarding：它在没有 socket 开 UDP_GRO 时也聚合（真实网卡不这样），这里只有开了 UDP_GRO 的 socket 收到合并包。
# softirq 落点：veth 的 NAPI 在发送方的 CPU 上轮询，转发器的入向收包（GRO、IP/UDP、入队、唤醒）正向在客户端 CPU、回程在后端 CPU；
# c0、s0 没有 NAPI，转发器发出的包由 netif_rx 在 CPU0 的 softirq 里完成对端的收包（GSO 包到普通 socket 时在这里分段）。
# fwd 命名空间开 ip_forward，cli、srv 的默认路由指向它，direct 即内核转发。命名空间随容器退出销毁。
topo_up() {
  local n d t
  [ "$TOPO" = veth ] || return 0
  [ -z "$CLI_HOST$FWD_HOST$SRV_HOST" ] || { log "TOPO=veth 只用于 loopback 容器"; return 1; }
  {
    for n in cli fwd srv; do
      ip netns add tpm-$n && ip -n tpm-$n link set lo up &&
        ip netns exec tpm-$n sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="21000 65535" || return 1
    done
    ip link add c0 netns tpm-cli type veth peer name f0 netns tpm-fwd &&
      ip link add s0 netns tpm-srv type veth peer name f1 netns tpm-fwd &&
      ip -n tpm-cli addr add 10.201.1.1/24 dev c0 && ip -n tpm-fwd addr add 10.201.1.2/24 dev f0 &&
      ip -n tpm-fwd addr add 10.201.2.1/24 dev f1 && ip -n tpm-srv addr add 10.201.2.2/24 dev s0 &&
      ip netns exec tpm-cli ethtool -K c0 tso off && ip netns exec tpm-srv ethtool -K s0 tso off || return 1
    for d in f0 f1; do
      ip netns exec tpm-fwd sh -c "ethtool -K $d gro on && echo $VETH_FLUSH_NS > /sys/class/net/$d/gro_flush_timeout &&
        echo $VETH_DEFER > /sys/class/net/$d/napi_defer_hard_irqs" || return 1
    done
    ip -n tpm-cli link set c0 up && ip -n tpm-srv link set s0 up && ip -n tpm-fwd link set f0 up && ip -n tpm-fwd link set f1 up &&
      ip -n tpm-cli route add default via 10.201.1.2 && ip -n tpm-srv route add default via 10.201.2.1 &&
      ip netns exec tpm-fwd sysctl -qw net.ipv4.ip_forward=1 || return 1
  } >&2
  # 核对并记录（写入参数给出的文件）：f0/f1 gro on、rx-udp-gro-forwarding 与 rx-gro-list off、定时器参数；c0/s0 tso off
  t=$({
    for d in f0 f1; do
      ip netns exec tpm-fwd sh -c "echo $d \$(ethtool -k $d | grep -E '^(generic-receive-offload|rx-udp-gro-forwarding|rx-gro-list|tcp-segmentation-offload):' | tr '\n' ' ')\
gro_flush_timeout: \$(cat /sys/class/net/$d/gro_flush_timeout) napi_defer_hard_irqs: \$(cat /sys/class/net/$d/napi_defer_hard_irqs) mtu: \$(cat /sys/class/net/$d/mtu)"
    done
    ip netns exec tpm-cli sh -c "echo c0 \$(ethtool -k c0 | grep -E '^(generic-receive-offload|tcp-segmentation-offload):' | tr '\n' ' ')"
    ip netns exec tpm-srv sh -c "echo s0 \$(ethtool -k s0 | grep -E '^(generic-receive-offload|tcp-segmentation-offload):' | tr '\n' ' ')"
  })
  echo "$t" >&2
  [ -z "${1:-}" ] || echo "$t" > "$1"
  echo "$t" | grep '^f' | grep -v -q 'generic-receive-offload: on' && { log "f0/f1 没有开 GRO"; return 1; }
  echo "$t" | grep '^f' | grep -q -E '(rx-udp-gro-forwarding|rx-gro-list): on' && { log "f0/f1 开了 rx-udp-gro-forwarding 或 rx-gro-list"; return 1; }
  echo "$t" | grep -E '^[cs]0' | grep -v -q 'tcp-segmentation-offload: off' && { log "c0/s0 没有关 TSO"; return 1; }
  CLI_NS=tpm-cli; FWD_NS=tpm-fwd; SRV_NS=tpm-srv; FWD_IP=10.201.1.2; SRV_IP=10.201.2.2
}

# spawn <角色> <日志名> <命令>：后台启动并脱离会话，输出 PID
spawn() {
  local r=$1 f=$2; shift 2
  on "$r" "mkdir -p $WORK; ulimit -n 65536 2>/dev/null || ulimit -n \$(ulimit -Hn); nohup $* >$WORK/$f 2>&1 </dev/null & echo \$!"
}

# stop_pid <角色> <PID>：SIGTERM 后最多等 5 秒，仍未退出则 SIGKILL
stop_pid() {
  on "$1" "kill $2 2>/dev/null; for i in \$(seq 50); do kill -0 $2 2>/dev/null || exit 0; sleep 0.1; done; kill -9 $2 2>/dev/null; true"
}

# hp <地址> <端口>：IPv6 地址加方括号
hp() { case $1 in *:*) echo "[$1]:$2" ;; *) echo "$1:$2" ;; esac; }

# wait_listen <角色> <端口> [PID]：等端口进入 LISTEN，最多 5 秒；给出的 PID 退出则立即失败
wait_listen() {
  local hex; hex=$(printf '%04X' "$2")
  on "$1" "for i in \$(seq 50); do grep -q ':$hex [0-9A-F]*:0000 0A' /proc/net/tcp /proc/net/tcp6 2>/dev/null && exit 0; ${3:+kill -0 $3 2>/dev/null || exit 1;} sleep 0.1; done; exit 1" ||
    { log "端口 $2 未进入监听"; return 1; }
}

start_backends() {
  SRV_PIDS="$(spawn srv iperf3-server.log "taskset -c $SRV_CPUS $IPERF3 -s -p $IPERF_PORT")"
  SRV_PIDS="$SRV_PIDS $(spawn srv echo-server.log "taskset -c $SRV_CPUS $FWDBENCH server -l $(hp "$SRV_IP" $ECHO_PORT)")"
  SRV_PIDS="$SRV_PIDS $(spawn srv sink.log "taskset -c $SRV_CPUS $FWDBENCH sink -l $(hp "$SRV_IP" $SINK_PORT)")"
  wait_listen srv $IPERF_PORT && wait_listen srv $ECHO_PORT && wait_listen srv $SINK_PORT
}

stop_backends() { local p; for p in $SRV_PIDS; do stop_pid srv "$p"; done; SRV_PIDS=""; }

backend_for() { case $1 in udp_rr_*) echo $ECHO_PORT ;; tcp_bw_*|udp_*) echo $IPERF_PORT ;; tcp_bulk_*) echo $SINK_PORT ;; *) echo $ECHO_PORT ;; esac; }

# bulk_args <负载> <秒数> <预热秒数>：tcp_bulk_<N>[_stall] 的 fwdbench bulk 参数。N 条连接各自持续写 64 KiB 的块，经转发器到
# fwdbench sink（读完丢弃并逐字节核对，结束时把收到的字节数报回客户端）；客户端 SO_SNDBUF 固定为 BULK_SNDBUF：loopback 上
# 三方的 socket 共用一份 tcp_mem（这台 VM 约 735 MB），2000 条连接时自动调大的客户端发送队列会把它占满、触发丢包。
# _stall：sink 在每条连接上先停顿 BULK_STALL 秒再读，所有方向同时积压在转发器里，非 root 时 pipe 达到 pipe-user-pages-soft，
# 回退计数必然出现；预热相应加长，测量窗口从停顿结束 1 秒后开始。停顿越长，零窗口探测的退避越长（200 ms 起倍增），
# 停顿结束后个别连接要等下一次探测才恢复，所以默认只停 1 秒（2 秒时收尾偶尔要 4–6 秒）。
# 这台 Docker VM（8 GB）的 tcp_mem 上限约 735 MB，2000 条连接时三方的 socket 会进入内存压力（RcvQDrop、RTO 超时），吞吐波动大，
# 这个负载主要看错误数与回退计数
bulk_args() {
  local n=${1#tcp_bulk_} st=""
  case $n in *_stall) n=${n%_stall}; st=" -stall ${BULK_STALL}s" ;; esac
  echo "bulk -c $(hp "$TARGET_IP" "$TARGET_PORT") -n $n -s 65536 -sndbuf $BULK_SNDBUF -d ${2}s -w ${3}s$st"
}

# iperf_udp <负载>：udp_{bw,pps}_<包长>[_p<N>][_r] 的 iperf3 参数。_p<N> 为 N 条流（iperf3 -P N），每条流是转发器里的一个会话；
# _r 为反向（-R）：后端发、客户端收，数据走转发器的回程。iperf3 3.16 加 -R 时 end.sum_sent 仍是发送方（后端）、
# end.sum_received 仍是接收方（客户端），所以各指标与正向含义相同
iperf_udp() {
  local w=${1%_r} len par=1 r=""
  [ "$w" = "$1" ] || r=" -R"
  len=${w#udp_*_}
  case $w in *_p[0-9]*) par=${w##*_p}; len=${len%_p*} ;; esac
  echo "-u -b 0 -l $len -P $par$r"
}

# 转发器名：direct（不经转发器）| tinymapper[-musl][@后缀][+gro][+nocap][+nosplice][+nonroot] | rinetd | realm-1c | realm-2c
# tinymapper@<后缀> 对应 $BIN/tinymapper-glibc-<后缀>，即 `REF=<后缀> docker/build.sh` 的产物；+ 开头的标记顺序任意，可组合：
# +gro：同一二进制加 --udp-gro 启动（U5），同一批里对照开/关；
# +nosplice：同一二进制加 --disable-splice 启动（B2），同一批里对照 splice 开/关；
# +nocap：同一二进制经 setpriv 去掉 CAP_NET_ADMIN 后启动，在加了 NET_ADMIN 的容器里（run.sh 的 CAP_ADD）对照不带该权限的部署；
# TM_NOCAP=1 时所有 tinymapper 都这样启动（run.sh 给 --privileged 的 syscount/prof 阶段与 veth 拓扑设置）；
# +nonroot（各转发器都可加，如 realm-1c+nonroot）：经 setpriv 以专用 uid/gid FWD_UID 启动，没有任何 capability，
# fs.pipe-user-pages-soft 按这个 uid 计（容器里的 root 与 VM 里所有 root 进程同一 uid，--privileged 时还不受该限额约束）；
# 只用于 loopback 容器（脚本以 root 运行）
tm_file() {
  local n=${1%%+*} v s=""
  v=${n%%@*}
  case $n in *@*) s=-${n#*@} ;; esac
  [ "$v" = tinymapper ] && v=tinymapper-glibc
  echo "$v$s"
}

# start_fwd <转发器> <后端端口>：启动转发器，设置 FWD_PID、FWD_NAME、所在 CPU FWD_SET 与客户端目标 TARGET_IP:TARGET_PORT
start_fwd() {
  local fwd=$1 bp=$2 l r c u=""
  FWD_PID=""; FWD_NAME=$fwd; FWD_SET=$FWD_CPUS; TARGET_IP=$FWD_IP; TARGET_PORT=$FPORT
  l=$(hp "$FWD_IP" $FPORT); r=$(hp "$SRV_IP" "$bp")
  case "$fwd+" in *+nonroot+*) u="setpriv --reuid=$FWD_UID --regid=$FWD_UID --clear-groups " ;; esac
  case ${fwd%%+*} in
    direct) TARGET_IP=$SRV_IP; TARGET_PORT=$bp; return 0 ;;
    tinymapper*)
      c="taskset -c $FWD_CPUS $u"
      [ -n "$u" ] || case "${TM_NOCAP:-}:$fwd+" in 1:*|*+nocap+*) c="$c setpriv --inh-caps=-net_admin --bounding-set=-net_admin" ;; esac
      c="$c $BIN/$(tm_file "$fwd") -l$l -r$r -t -u --log-level $TM_LOG_LEVEL"
      case "$fwd+" in *+gro+*) c="$c --udp-gro" ;; esac
      case "$fwd+" in *+nosplice+*) c="$c --disable-splice" ;; esac ;;
    rinetd)
      on fwd "mkdir -p $WORK; printf '%s %s %s %s\n%s %s/udp %s %s/udp\n' $FWD_IP $FPORT $SRV_IP $bp $FWD_IP $FPORT $SRV_IP $bp >$WORK/rinetd.conf"
      c="taskset -c $FWD_CPUS $u$RINETD -f -c $WORK/rinetd.conf" ;;
    realm-1c) c="taskset -c $FWD_CPUS $u$REALM -l $l -r $r -u" ;;
    realm-2c) c="taskset -c $FWD_CPUS2 $u$REALM -l $l -r $r -u"; FWD_SET=$FWD_CPUS2 ;;
    *) log "未知转发器：$fwd"; return 1 ;;
  esac
  FWD_PID=$(spawn fwd fwd.log "$c")
  wait_listen fwd $FPORT "$FWD_PID" && sleep 0.5
}

stop_fwd() { [ -n "$FWD_PID" ] && stop_pid fwd "$FWD_PID"; FWD_PID=""; sleep 1; }

fwd_alive() { [ -z "$FWD_PID" ] || on fwd "kill -0 $FWD_PID 2>/dev/null"; }

# fwd_stat：转发器 utime+stime（tick）、/proc/uptime（秒）、VmRSS（KB）、线程数；direct 时全为 0
fwd_stat() {
  [ -n "$FWD_PID" ] || { echo "0 0 0 0"; return; }
  on fwd "awk 'FILENAME ~ /stat\$/ {c = \$14 + \$15} FILENAME == \"/proc/uptime\" {u = \$1} /^VmRSS/ {r = \$2} /^Threads/ {t = \$2}
    END {printf \"%d %s %d %d\n\", c, (u == \"\" ? \"0\" : u), r, t}' /proc/$FWD_PID/stat /proc/uptime /proc/$FWD_PID/status 2>/dev/null"
}

# cpu_snap：fwd 主机 /proc/stat 里每个 CPU 一行：cpuN user nice system idle iowait irq softirq steal（USER_HZ）
cpu_snap() { on fwd "grep '^cpu[0-9]' /proc/stat"; }

# cpu_json <前> <后>（两次 cpu_snap）：转发器所在 CPU（fwd = FWD_SET），以及与转发器同机时客户端（cli）、后端（srv）各组 CPU 的
# 占用百分比 JSON：busy = user+nice+system+irq+softirq，另列 usr（user+nice）、sys、softirq；组内各 CPU 相加，满 = 100 × CPU 数。
# softirq 在哪个 CPU 上执行就记在哪个 CPU（含 ksoftirqd）。进程的 utime+stime（fwd_cpu_pct）是否也含在它上下文里执行的 softirq
# 取决于内核：没有 IRQ 时间统计时按 tick 采样记给当时的进程（Docker VM 6.8 即如此，进程 CPU% ≈ 所在 CPU 忙碌%）
cpu_json() {
  local sets="fwd:$FWD_SET"
  [ "$CLI_HOST" = "$FWD_HOST" ] && sets="$sets cli:$CLI_CPUS"
  [ "$SRV_HOST" = "$FWD_HOST" ] && sets="$sets srv:$SRV_CPUS"
  printf '%s\n%s\n' "$1" "$2" | awk -v sets="$sets" '
    function expand(spec, C,   p, np, i, r, a, m) {
      m = 0; np = split(spec, p, ",")
      for (i = 1; i <= np; i++) if (split(p[i], r, "-") == 2) { for (a = r[1] + 0; a <= r[2] + 0; a++) C[++m] = a } else C[++m] = p[i] + 0
      return m
    }
    { k = substr($1, 4) + 0; n[k]++; for (i = 2; i <= 9; i++) v[k, n[k], i] = $i }
    END {
      ns = split(sets, S, " "); printf "{"
      for (s = 1; s <= ns; s++) {
        split(S[s], kv, ":"); m = expand(kv[2], C); busy = usr = sys = sirq = 0
        for (j = 1; j <= m; j++) {
          c = C[j]; t = 0
          for (i = 2; i <= 9; i++) { d[i] = v[c, 2, i] - v[c, 1, i]; t += d[i] }
          if (t <= 0) continue
          usr += 100 * (d[2] + d[3]) / t; sys += 100 * d[4] / t; sirq += 100 * d[8] / t
          busy += 100 * (d[2] + d[3] + d[4] + d[7] + d[8]) / t
        }
        printf "%s\"%s\":{\"busy\":%.1f,\"usr\":%.1f,\"sys\":%.1f,\"softirq\":%.1f}", (s > 1 ? "," : ""), kv[1], busy, usr, sys, sirq
      }
      print "}"
    }'
}

# tm_stats：被测 tinymapper 支持 SIGUSR1 统计（O1 起）时让它输出一次，打印其中（单规则）`stats rule N tcp:`、`stats rule N udp:`、
# `stats pool:` 各一行，行首为 tcp / udp / pool，后面是原样的字段（去掉颜色码），如 `udp sessions=1 total=1 up_pkts=…`、
# `pool bufs alloc=64 held=0 … pipes alloc=…`；其他转发器、没有统计的旧二进制（收到 SIGUSR1 会退出）与 --log-level 0 时不输出。
# 等到 `stats pool:` 行写出（sigusr1_cb 最后 fflush）
tm_stats() {
  case $FWD_NAME in tinymapper*) ;; *) return 0 ;; esac
  [ -n "$FWD_PID" ] && [ "$TM_LOG_LEVEL" != 0 ] || return 0
  on fwd "f=$WORK/fwd.log; LC_ALL=C grep -aq 'stats rule' $BIN/$(tm_file "$FWD_NAME") || exit 0
    n=\$(grep -ac 'stats pool:' \$f); kill -USR1 $FWD_PID 2>/dev/null || exit 0
    for i in \$(seq 100); do [ \$(grep -ac 'stats pool:' \$f) -gt \$n ] && break; sleep 0.02; done
    for k in 'rule [0-9]* tcp' 'rule [0-9]* udp' pool; do
      grep -a \"stats \$k:\" \$f | tail -1 | sed 's/.*stats \(rule [0-9]* \)*\([a-z]*\): /\2 /; s/\x1b\[[0-9;]*m//g'
    done"
}

# stats_json <tcp|udp|pool>：从 tm_stats 的输出里取该行转为 JSON 对象，没有时输出 null。pool 行里不带 = 的词（bufs、tcp_pairs、
# udp_pairs、pipes）作为其后字段的前缀：{"bufs_alloc":…, "pipes_held":…}
stats_json() {
  awk -v k="$1" '$1 == k {for (i = 2; i <= NF; i++) if (split($i, kv, "=") == 2) printf "%s\"%s%s\":%s", (n++ ? "," : "{"), p, kv[1], kv[2]; else p = $i "_"}
    END {print (n ? "}" : "null")}'
}

# client <负载> <秒数>：在 cli 上跑一次负载并覆盖整个客户端生命周期（fwdbench -w 0s，iperf3 不跳过首秒），输出一行 JSON
client() {
  local w=$1 d=$2 c="taskset -c $CLI_CPUS" t
  t=$(hp "$TARGET_IP" "$TARGET_PORT")
  case $w in
    tcp_rr_*)  on cli "$c $FWDBENCH rr -c $t -n ${w##*_} -s 64 -d ${d}s -w 0s" ;;
    tcp_crr_*) on cli "$c $FWDBENCH crr -c $t -n ${w##*_} -s 64 -d ${d}s -w 0s" ;;
    udp_rr_*)  on cli "$c $FWDBENCH udp-rr -c $t -n ${w##*_} -s 64 -d ${d}s -w 0s" ;;
    tcp_bulk_*) on cli "$c $FWDBENCH $(bulk_args "$w" "$d" 0)" ;;
    udp_*)
      # sent_pkts 是发送方的发包数：正向为客户端，_r 为后端
      on cli "$c $IPERF3 -c $TARGET_IP -p $TARGET_PORT $(iperf_udp "$w") -t $d -J" | jq -c '{sent_pkts: .end.sum_sent.packets,
        recv_pkts: (.end.sum_received.packets - .end.sum_received.lost_packets), seconds: .end.sum_received.seconds,
        recv_kpps: ((.end.sum_received.packets - .end.sum_received.lost_packets) / .end.sum_received.seconds / 1e3),
        lost_pct: .end.sum_received.lost_percent, err: .error}' ;;
    tcp_bw_*)
      on cli "$c $IPERF3 -c $TARGET_IP -p $TARGET_PORT -P ${w##*_} -t $d -J" | jq -c '{bytes: .end.sum_received.bytes,
        seconds: .end.sum_received.seconds, gbps: (.end.sum_received.bits_per_second / 1e9), retrans: .end.sum_sent.retransmits, err: .error}' ;;
  esac
}

# snmp_udp：fwd 上 /proc/net/snmp 的 Udp 计数（veth 拓扑下是 fwd 命名空间的），前面两行标记客户端、后端是否与转发器同机且同一网络
# 命名空间（是则它们的发包也计入 OutDatagrams）
snmp_udp() {
  [ "$CLI_HOST:$CLI_NS" = "$FWD_HOST:$FWD_NS" ] && echo "# cli_on_fwd=1" || echo "# cli_on_fwd=0"
  [ "$SRV_HOST:$SRV_NS" = "$FWD_HOST:$FWD_NS" ] && echo "# srv_on_fwd=1" || echo "# srv_on_fwd=0"
  on fwd "grep '^Udp:' /proc/net/snmp"
}

# count_phase <阶段名> <perf 事件参数> <输出前缀> <负载> <秒数>：perf stat 计数 fwd 进程，窗口覆盖客户端整个生命周期
# 输出 <前缀>.<阶段>.csv / .client.json / .snmp.txt；UDP 的计数单位取 fwd 上 /proc/net/snmp 的 OutDatagrams 增量。
# udp_bw/udp_pps、tcp_bw/tcp_bulk 且被测的是 tinymapper 时，perf 窗口前后各取一次 SIGUSR1 统计写入 .stats.txt：GSO 一次发多个数据报，
# OutDatagrams 每次发送只加 1（udp_send_skb），syscount.py 有它时改用 up_pkts+down_pkts 的增量；TCP 由它算 splice 写出的字节占比与回退次数
count_phase() {
  local ph=$1 ev=$2 pre=$3 pp st=""
  case $4 in udp_bw_*|udp_pps_*|tcp_bw_*|tcp_bulk_*) st=$pre.$ph.stats.txt ;; esac
  snmp_udp > "$pre.$ph.snmp.txt"
  [ -z "$st" ] || tm_stats > "$st"
  pp=$(spawn fwd perf-$ph.log "$SUDO $PERF stat -x, -o $WORK/$ph.csv $ev -p $FWD_PID")
  sleep 1
  client "$4" "$5" > "$pre.$ph.client.json"
  on fwd "$SUDO kill -INT $pp; while $SUDO kill -0 $pp 2>/dev/null; do sleep 0.1; done; cat $WORK/$ph.csv" > "$pre.$ph.csv"
  snmp_udp | grep -v '^#' >> "$pre.$ph.snmp.txt"
  [ -z "$st" ] || { tm_stats >> "$st"; [ -s "$st" ] || rm -f "$st"; }
}

EXIT_EV="recvfrom sendto splice accept accept4 connect read write recvmsg sendmsg recvmmsg sendmmsg"
# syscall 计数事件：总数、各 syscall 进入次数、主要收发/连接调用的失败返回（ret < 0）
stat_events() {
  local ev="-e raw_syscalls:sys_enter -e 'syscalls:sys_enter_*'" s
  for s in $EXIT_EV; do ev="$ev -e syscalls:sys_exit_$s --filter 'ret < 0'"; done
  echo "$ev -e context-switches -e cpu-migrations -e task-clock"
}

# summarize_dir <结果目录>：生成 summary.md、syscalls.{md,json}、profile.md（在开发机上执行）
summarize_dir() {
  local R=$1 B; B=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if [ -s "$R/raw.jsonl" ]; then python3 -I "$B/summarize.py" "$R/raw.jsonl" > "$R/summary.md"; fi
  if [ -d "$R/syscount" ]; then python3 -I "$B/syscount.py" "$R/syscount" --json "$R/syscalls.json" > "$R/syscalls.md"; fi
  if [ -d "$R/prof" ]; then python3 -I "$B/prof/summarize_prof.py" "$R/prof" > "$R/profile.md"; fi
}
