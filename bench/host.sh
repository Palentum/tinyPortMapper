#!/usr/bin/env bash
# 主机模式基准（P0.7）：客户端、转发器、后端直接运行在各自主机上（不用容器），由本机经 RSH 编排，
# 依次执行吞吐/延迟基准（bench.sh）、syscall 计数（syscount.sh）、转发器剖析（prof/prof.sh），
# 结果格式与 loopback 相同，写入 bench/results/host-<时间戳>/。
#
# 3 主机：CLI_HOST=root@c FWD_HOST=root@f SRV_HOST=root@s FWD_IP=10.0.0.2 SRV_IP=10.0.0.3 bench/host.sh
# 2 主机：客户端与后端同机，令 SRV_HOST=$CLI_HOST、SRV_IP=客户端主机的数据面地址（流量在转发器网卡上进出）
# 容器冒烟：bench/host-smoke.sh
#
# 环境变量（括号内为默认值）：
#   CLI_HOST FWD_HOST SRV_HOST   RSH 目标（必填）
#   FWD_IP SRV_IP                数据面地址（必填）：客户端连 FWD_IP，转发器连 SRV_IP
#   CLI_CPUS(2,3) SRV_CPUS(4,5) FWD_CPUS(0) FWD_CPUS2(0,1)   各主机上的绑核，建议避开网卡中断所在 CPU
#   STAGES("bench syscount prof")
#   FWDS("direct tinymapper realm-1c realm-2c") TESTS(全部 8 项) REPS(3) DUR(10)
#   SC_FWDS("tinymapper realm-1c") SC_TESTS(5 个负载) SC_DUR(8)
#   PROF_RUNS(tinymapper 的 5 个负载) PROF_DUR(8) PHASES("clean stat rec ipi")
#   BIN_DIR(build)   本机上与转发器主机同架构的 tinymapper-{glibc,musl}[-后缀]
#   REALM_BIN        本机上的 realm 二进制；未设时按转发器主机架构下载官方 2.9.6（sha256 取自 bench/Dockerfile，缓存在 build/）
#   RINETD(rinetd) IPERF3(iperf3)   远端已安装的命令（rinetd 仅 FWDS 含 rinetd 时需要）
#   PERF(perf) SUDO()   转发器主机上的 perf 与提权前缀（非 root 登录时 SUDO=sudo，需免密）
#   APPLY_SYSCTL=1   在各主机上 sysctl -w tcp_tw_reuse=1 与 ip_local_port_range="21000 65535"（不持久化）
#   WORK(/tmp/tpm-bench)   各主机上的工作目录（二进制、日志、perf.data）
#   RSH RCP          远程执行与复制（默认带连接复用的 ssh / scp）；RSH=docker RCP="docker cp" 用于容器冒烟
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SSH_OPTS="-o BatchMode=yes -o ControlMaster=auto -o ControlPath=/tmp/tpm-ssh-%C -o ControlPersist=120"
RSH=${RSH:-ssh $SSH_OPTS}
RCP=${RCP:-scp -q $SSH_OPTS}
. "$ROOT/bench/lib.sh"

: "${CLI_HOST:?需要 CLI_HOST}" "${FWD_HOST:?需要 FWD_HOST}" "${SRV_HOST:?需要 SRV_HOST}"
[ "$FWD_IP" != 127.0.0.1 ] && [ "$SRV_IP" != 127.0.0.1 ] || { echo "需要设置数据面地址 FWD_IP 与 SRV_IP" >&2; exit 2; }
STAGES=${STAGES:-bench syscount prof}
FWDS=${FWDS:-direct tinymapper realm-1c realm-2c}
TESTS=${TESTS:-tcp_bw_1 tcp_bw_8 tcp_rr_64 tcp_rr_1000 tcp_crr_32 udp_bw_1400 udp_pps_64 tcp_mem_5000}
REPS=${REPS:-3}; DUR=${DUR:-10}
SC_FWDS=${SC_FWDS:-tinymapper realm-1c}
SC_TESTS=${SC_TESTS:-tcp_rr_64 tcp_rr_1000 tcp_crr_32 udp_pps_64 tcp_bw_8}
SC_DUR=${SC_DUR:-8}
PROF_RUNS=${PROF_RUNS:-tinymapper:tcp_rr_64,tcp_rr_1000,tcp_crr_32,udp_pps_64,tcp_bw_8}
PROF_DUR=${PROF_DUR:-8}
BIN_DIR=${BIN_DIR:-$ROOT/build}
R=$ROOT/bench/results/host-$(date +%Y%m%d-%H%M%S)
mkdir -p "$R"
exec > >(tee -a "$R/run.log") 2>&1

push() { $RCP "$2" "$(host_of "$1"):$WORK/$3"; }
host_of() { case $1 in cli) echo "$CLI_HOST" ;; fwd) echo "$FWD_HOST" ;; srv) echo "$SRV_HOST" ;; esac; }
goarch() { case $1 in aarch64|arm64) echo arm64 ;; x86_64|amd64) echo amd64 ;; *) echo "$1" ;; esac; }

# 1. 各主机架构与二进制：fwdbench 按客户端/后端架构交叉编译；tinymapper、realm 推到转发器主机
for r in cli srv fwd; do on $r "mkdir -p $WORK"; done
for r in cli srv; do
  ga=$(goarch "$(on $r 'uname -m')")
  (cd "$ROOT/bench/fwdbench" && CGO_ENABLED=0 GOOS=linux GOARCH=$ga go build -trimpath -o "$ROOT/build/fwdbench-linux-$ga" .)
  push $r "$ROOT/build/fwdbench-linux-$ga" fwdbench
done
fa=$(on fwd 'uname -m')
all="$FWDS $SC_FWDS $(echo "$PROF_RUNS" | tr ' ' '\n' | sed 's/:.*//')"
for f in $(echo $all | tr ' ' '\n' | grep '^tinymapper' | sort -u); do
  b=$(tm_file "$f")
  [ -f "$BIN_DIR/$b" ] || { echo "缺少 ${BIN_DIR}/${b}（需要 ${fa} 架构的静态二进制）" >&2; exit 1; }
  push fwd "$BIN_DIR/$b" "$b"
done
if echo "$all" | grep -q realm; then
  if [ -z "${REALM_BIN:-}" ]; then
    REALM_BIN=$ROOT/build/realm-2.9.6-$fa
    if [ ! -x "$REALM_BIN" ]; then
      sum=$(sed -n "s/^ARG REALM_SHA256_$fa=//p" "$ROOT/bench/Dockerfile")
      [ -n "$sum" ] || { echo "bench/Dockerfile 中没有 $fa 架构的 realm sha256" >&2; exit 1; }
      dl=$(mktemp -d)
      curl -fsSL -o "$dl/realm.tar.gz" "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-$fa-unknown-linux-gnu.tar.gz"
      echo "$sum  $dl/realm.tar.gz" | shasum -a 256 -c - >/dev/null
      tar xzf "$dl/realm.tar.gz" -C "$dl" realm && mv "$dl/realm" "$REALM_BIN" && rm -rf "$dl"
    fi
  fi
  push fwd "$REALM_BIN" realm
fi
on fwd "chmod +x $WORK/tinymapper-* $WORK/realm 2>/dev/null; true"
on cli "chmod +x $WORK/fwdbench"; on srv "chmod +x $WORK/fwdbench"
bad=$(on fwd "cd $WORK && for f in tinymapper-* realm; do [ -e \$f ] || continue; ./\$f --help >/dev/null 2>&1; [ \$? -lt 126 ] || echo \$f; done")
[ -z "$bad" ] || { echo "转发器主机（${fa}）无法执行：${bad}，检查 BIN_DIR / REALM_BIN 的架构" >&2; exit 1; }

# 2. 环境记录与预检（只读；APPLY_SYSCTL=1 时才改 sysctl）
if [ "${APPLY_SYSCTL:-}" = 1 ]; then
  for r in cli srv fwd; do on $r "$SUDO sysctl -q -w net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range='21000 65535'"; done
fi
{
  echo "时间：$(date '+%F %T %z')；源码：$(git -C "$ROOT" describe --always --dirty)"
  echo "拓扑：cli=${CLI_HOST} fwd=${FWD_HOST}（${FWD_IP}）srv=${SRV_HOST}（${SRV_IP}）；绑核 cli=${CLI_CPUS} fwd=${FWD_CPUS}/${FWD_CPUS2} srv=${SRV_CPUS}"
  echo "参数：STAGES=$STAGES REPS=$REPS DUR=$DUR FWDS=$FWDS TESTS=$TESTS SC_FWDS=$SC_FWDS SC_TESTS=$SC_TESTS PROF_RUNS=$PROF_RUNS"
  for r in cli fwd srv; do
    echo "== ${r}（$(host_of $r)）"
    on $r "uname -srm; nproc; (lscpu 2>/dev/null | grep -E '^(Model name|NUMA node\(s\))') || true; grep MemTotal /proc/meminfo
      for k in net.ipv4.tcp_tw_reuse net.ipv4.ip_local_port_range net.core.somaxconn net.core.rmem_max net.core.wmem_max; do echo \"\$k = \$(sysctl -n \$k 2>/dev/null)\"; done
      echo \"nofile 硬上限 = \$(ulimit -Hn)\"; (ip -br addr 2>/dev/null || true)"
  done
  echo "== 版本"
  on cli "$IPERF3 --version | head -1"
  on fwd "cd $WORK && sha256sum tinymapper-* 2>/dev/null; [ -x realm ] && ./realm --version; $PERF --version 2>/dev/null || echo 'perf 不可用'"
} > "$R/env.txt" 2>&1
cat "$R/env.txt"
case " $STAGES " in *" syscount "*|*" prof "*)
  on fwd "$SUDO $PERF stat -e raw_syscalls:sys_enter -- true >/dev/null 2>&1" || { echo "转发器主机上 perf 无法计数 tracepoint（检查 PERF / SUDO / perf_event_paranoid）" >&2; exit 1; } ;;
esac
if grep 'tcp_tw_reuse = ' "$R/env.txt" | grep -qv '= 1$'; then
  log "警告：有主机 tcp_tw_reuse != 1，CRR 可能耗尽临时端口（可设 APPLY_SYSCTL=1）"
fi

# 3. 各阶段：脚本在本机执行，经 RSH 操作三台主机
export RSH WORK CLI_HOST FWD_HOST SRV_HOST FWD_IP SRV_IP CLI_CPUS SRV_CPUS FWD_CPUS FWD_CPUS2 IPERF3 RINETD PERF SUDO
export BIN=$WORK FWDBENCH=$WORK/fwdbench REALM=$WORK/realm
for s in $STAGES; do
  log "阶段 $s"
  case $s in
    bench) REPS=$REPS DUR=$DUR FWDS=$FWDS TESTS=$TESTS OUT=$R/raw.jsonl bash "$ROOT/bench/bench.sh" ;;
    syscount) DUR=$SC_DUR FWDS=$SC_FWDS TESTS=$SC_TESTS OUT=$R/syscount bash "$ROOT/bench/syscount.sh" ;;
    prof) DUR=$PROF_DUR RUNS=$PROF_RUNS OUT=$R/prof bash "$ROOT/bench/prof/prof.sh" ;;
    *) log "未知阶段：$s"; exit 2 ;;
  esac || { rc=$?; log "阶段 ${s} 失败（退出码 ${rc}），结果目录：${R}"; exit $rc; }
done

# 4. 汇总（perf.data 留在转发器主机的 $WORK 下）
summarize_dir "$R"
for f in summary.md syscalls.md; do [ -f "$R/$f" ] && { echo; echo "## $f"; cat "$R/$f"; }; done
log "结果目录：$R"
