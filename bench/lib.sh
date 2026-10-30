# bench.sh、syscount.sh、prof/prof.sh 共用：角色执行、后端与转发器启停、计数阶段（由各脚本 source）
#
# 三个角色：cli = 负载客户端（iperf3 / fwdbench），fwd = 被测转发器，srv = 后端（iperf3 -s、fwdbench echo）。
# 角色主机（CLI_HOST / FWD_HOST / SRV_HOST）为空时在本机执行：loopback 模式，容器内三个角色同机，地址都是 127.0.0.1；
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
FPORT=20000; IPERF_PORT=5201; ECHO_PORT=9000
FWD_PID=""; SRV_PIDS=""; TARGET_IP=""; TARGET_PORT=""

log() { echo "[$(date +%T)] $*" >&2; }

# on <角色> <命令>：在角色所在主机用 sh 执行
on() {
  local h
  case $1 in cli) h=$CLI_HOST ;; fwd) h=$FWD_HOST ;; srv) h=$SRV_HOST ;; esac
  shift
  if [ -z "$h" ]; then sh -c "$*"
  elif [ "$RSH" = docker ]; then docker exec "$h" sh -c "$*"
  else $RSH "$h" "$*"; fi </dev/null
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
  wait_listen srv $IPERF_PORT && wait_listen srv $ECHO_PORT
}

stop_backends() { local p; for p in $SRV_PIDS; do stop_pid srv "$p"; done; SRV_PIDS=""; }

backend_for() { case $1 in udp_rr_*) echo $ECHO_PORT ;; tcp_bw_*|udp_*) echo $IPERF_PORT ;; *) echo $ECHO_PORT ;; esac; }

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

# 转发器名：direct（不经转发器）| tinymapper[-musl][@后缀][+nocap] | rinetd | realm-1c | realm-2c
# tinymapper@<后缀> 对应 $BIN/tinymapper-glibc-<后缀>，即 `REF=<后缀> docker/build.sh` 的产物；
# +nocap：同一二进制经 setpriv 去掉 CAP_NET_ADMIN 后启动，在加了 NET_ADMIN 的容器里（run.sh 的 CAP_ADD）对照不带该权限的部署；
# TM_NOCAP=1 时所有 tinymapper 都这样启动（run.sh 给 --privileged 的 syscount/prof 阶段设置）
tm_file() {
  local n=${1%+nocap} v s=""
  v=${n%%@*}
  case $n in *@*) s=-${n#*@} ;; esac
  [ "$v" = tinymapper ] && v=tinymapper-glibc
  echo "$v$s"
}

# start_fwd <转发器> <后端端口>：启动转发器，设置 FWD_PID 与客户端目标 TARGET_IP:TARGET_PORT
start_fwd() {
  local fwd=$1 bp=$2 l r c
  FWD_PID=""; TARGET_IP=$FWD_IP; TARGET_PORT=$FPORT
  l=$(hp "$FWD_IP" $FPORT); r=$(hp "$SRV_IP" "$bp")
  case $fwd in
    direct) TARGET_IP=$SRV_IP; TARGET_PORT=$bp; return 0 ;;
    tinymapper*)
      c="taskset -c $FWD_CPUS"
      if [ "${TM_NOCAP:-}" = 1 ] || [ "$fwd" != "${fwd%+nocap}" ]; then c="$c setpriv --inh-caps=-net_admin --bounding-set=-net_admin"; fi
      c="$c $BIN/$(tm_file "$fwd") -l$l -r$r -t -u --log-level $TM_LOG_LEVEL" ;;
    rinetd)
      on fwd "mkdir -p $WORK; printf '%s %s %s %s\n%s %s/udp %s %s/udp\n' $FWD_IP $FPORT $SRV_IP $bp $FWD_IP $FPORT $SRV_IP $bp >$WORK/rinetd.conf"
      c="taskset -c $FWD_CPUS $RINETD -f -c $WORK/rinetd.conf" ;;
    realm-1c) c="taskset -c $FWD_CPUS $REALM -l $l -r $r -u" ;;
    realm-2c) c="taskset -c $FWD_CPUS2 $REALM -l $l -r $r -u" ;;
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

# client <负载> <秒数>：在 cli 上跑一次负载并覆盖整个客户端生命周期（fwdbench -w 0s，iperf3 不跳过首秒），输出一行 JSON
client() {
  local w=$1 d=$2 c="taskset -c $CLI_CPUS" t
  t=$(hp "$TARGET_IP" "$TARGET_PORT")
  case $w in
    tcp_rr_*)  on cli "$c $FWDBENCH rr -c $t -n ${w##*_} -s 64 -d ${d}s -w 0s" ;;
    tcp_crr_*) on cli "$c $FWDBENCH crr -c $t -n ${w##*_} -s 64 -d ${d}s -w 0s" ;;
    udp_rr_*)  on cli "$c $FWDBENCH udp-rr -c $t -n ${w##*_} -s 64 -d ${d}s -w 0s" ;;
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

# snmp_udp：fwd 上 /proc/net/snmp 的 Udp 计数，前面两行标记客户端、后端是否与转发器同机（同机时它们的发包也计入 OutDatagrams）
snmp_udp() {
  [ "$CLI_HOST" = "$FWD_HOST" ] && echo "# cli_on_fwd=1" || echo "# cli_on_fwd=0"
  [ "$SRV_HOST" = "$FWD_HOST" ] && echo "# srv_on_fwd=1" || echo "# srv_on_fwd=0"
  on fwd "grep '^Udp:' /proc/net/snmp"
}

# count_phase <阶段名> <perf 事件参数> <输出前缀> <负载> <秒数>：perf stat 计数 fwd 进程，窗口覆盖客户端整个生命周期
# 输出 <前缀>.<阶段>.csv / .client.json / .snmp.txt；UDP 的计数单位取 fwd 上 /proc/net/snmp 的 OutDatagrams 增量
count_phase() {
  local ph=$1 ev=$2 pre=$3 pp
  snmp_udp > "$pre.$ph.snmp.txt"
  pp=$(spawn fwd perf-$ph.log "$SUDO $PERF stat -x, -o $WORK/$ph.csv $ev -p $FWD_PID")
  sleep 1
  client "$4" "$5" > "$pre.$ph.client.json"
  on fwd "$SUDO kill -INT $pp; while $SUDO kill -0 $pp 2>/dev/null; do sleep 0.1; done; cat $WORK/$ph.csv" > "$pre.$ph.csv"
  snmp_udp | grep -v '^#' >> "$pre.$ph.snmp.txt"
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
