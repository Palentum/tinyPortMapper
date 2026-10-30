#!/usr/bin/env bash
# loopback 基准，一条命令出全部结果：编译 tinymapper（docker/build.sh）→ 交叉编译 fwdbench → 构建工具镜像
# → 吞吐/延迟/内存基准 → syscall 计数 → 汇总。结果写入 bench/results/<时间戳>/。
#
# 用法：bench/run.sh
#   QUICK=1 bench/run.sh                                   冒烟（REPS=1 DUR=3 SC_DUR=3）
#   FWDS="tinymapper@4acc876 tinymapper" bench/run.sh      基线提交与工作区前后对比
#   STAGES=syscount SC_FWDS=tinymapper@4acc876 bench/run.sh 只做 syscall 计数
#   STAGES=prof bench/run.sh                               CPU 剖析（bench/prof/prof.sh）
#   TOPO=veth TESTS="udp_bw_1400 udp_bw_1400_r udp_pps_64" FWDS="tinymapper tinymapper+gro" bench/run.sh   veth 三命名空间拓扑
# 环境变量：
#   STAGES   要执行的阶段：bench syscount prof（默认 "bench syscount"）
#   FWDS     转发器，默认 "direct tinymapper tinymapper-musl rinetd realm-1c realm-2c"；
#            tinymapper[-musl]@<后缀> 使用 build/tinymapper-{glibc,musl}-<后缀>，缺失时以 REF=<后缀> 自动编译；
#            加 +gro 后缀（tinymapper+gro、tinymapper-musl@<后缀>+gro，可与 +nocap 组合）为同一二进制加 --udp-gro 启动（U5）
#   TESTS    测试项，默认全部 8 项；REPS 轮数（3）；DUR 每项秒数（10）
#            另有不在默认列表里的 UDP 负载（TESTS / SC_TESTS 里显式指定）：
#              udp_pps_64_p<N>  N 条流（iperf3 -P N），每条流是转发器里的一个会话
#              <UDP 负载>_r     反向（iperf3 -R）：后端发、客户端收，数据走转发器回程；udp_pps_64_r、udp_pps_64_p<N>_r、udp_bw_1400_r
#              udp_rr_<N>       fwdbench udp-rr：N 个会话各一个 64 B 请求在途，后端是 fwdbench server 的 UDP 回显；
#                               udp_rr_1 测低负载延迟，udp_rr_64 测多会话回程；超时 200 ms 未回记为丢失
#            syscall 计数单位：udp_rr 为每个往返，_r 为转发器发出的每个包
#   SC_FWDS / SC_TESTS / SC_DUR  syscall 计数的转发器（默认 FWDS 去掉 direct、realm-2c）、负载（5 个）、秒数（8）
#   PROF_RUNS / PROF_DUR / PHASES 剖析范围（格式见 bench/prof/prof.sh）
#   SKIP_BUILD=1  不重新编译工作区的 tinymapper（缺失的二进制仍会编译）
#   TM_LOG_LEVEL  tinymapper 的 --log-level（默认 3）；TM_LOG_LEVEL=4 测默认日志级别下的性能
#   CAP_ADD       给 bench 等阶段的容器另加的 capability（空格分隔，默认无，与 BASELINE.md 可比）。CAP_ADD=NET_ADMIN 时容器里
#                 root 运行的 tinymapper 能用 SO_{SND,RCV}BUFFORCE（UDP 缓冲不受 rmem_max 截断，U6）；FWDS 里同一二进制
#                 加 +nocap 后缀（tinymapper+nocap、tinymapper-musl@<后缀>+nocap）在同一批里对照不带该权限的运行。
#                 syscount、prof 阶段是 --privileged（root 带 CAP_NET_ADMIN）：CAP_ADD 不含 NET_ADMIN 时这两个阶段的 tinymapper
#                 也去掉该权限启动（TM_NOCAP=1），同一次运行的各阶段 UDP 缓冲一致，也与 U6 以前的 syscall 计数可比
#   TOPO     loopback（默认）| veth。veth：bench、syscount、prof 各阶段的容器内建三个网络命名空间（客户端、转发器、后端），
#            经两对 veth 相连，绑核同 loopback；转发器一侧的两个 veth 开 GRO 并以 gro_flush_timeout=VETH_FLUSH_NS（50000 ns）、
#            napi_defer_hard_irqs=VETH_DEFER（2）模拟网卡中断合并，对端关 TSO，开了 UDP_GRO 的 socket 才收到 GRO 合并包。
#            容器为 --privileged（bench 阶段也是），tinymapper 同 syscount 阶段去掉 CAP_NET_ADMIN。softirq 落点与限制见
#            lib.sh 的 topo_up 与 BASELINE.md 第 6 节。结果每行多 topo 字段，拓扑核对写入各阶段的 topo.txt
#   CNAME    容器名前缀（默认不命名）：各阶段容器名为 <CNAME>-<阶段>，便于识别与只停自己的容器
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/bench/lib.sh"

STAGES=${STAGES:-bench syscount}
if [ "${QUICK:-}" = 1 ]; then REPS=${REPS:-1}; DUR=${DUR:-3}; SC_DUR=${SC_DUR:-3}; PROF_DUR=${PROF_DUR:-3}; fi
REPS=${REPS:-3}; DUR=${DUR:-10}
FWDS=${FWDS:-direct tinymapper tinymapper-musl rinetd realm-1c realm-2c}
TESTS=${TESTS:-tcp_bw_1 tcp_bw_8 tcp_rr_64 tcp_rr_1000 tcp_crr_32 udp_bw_1400 udp_pps_64 tcp_mem_5000}
SC_FWDS=${SC_FWDS:-$(echo $FWDS | tr ' ' '\n' | grep -vx -e direct -e realm-2c | tr '\n' ' ')}
SC_TESTS=${SC_TESTS:-tcp_rr_64 tcp_rr_1000 tcp_crr_32 udp_pps_64 tcp_bw_8}
SC_DUR=${SC_DUR:-8}
PROF_RUNS=${PROF_RUNS:-tinymapper:tcp_rr_64,tcp_rr_1000,tcp_crr_32,udp_pps_64,tcp_bw_8 realm-1c:tcp_rr_64,tcp_crr_32,udp_pps_64}
PROF_DUR=${PROF_DUR:-8}
PHASES=${PHASES:-clean stat rec ipi}
TOPO=${TOPO:-loopback}
case $TOPO in loopback|veth) ;; *) echo "未知 TOPO：$TOPO（loopback | veth）"; exit 2 ;; esac
IMG=tinymapper-bench:2
PIMG=tinymapper-bench-prof:2
R=$ROOT/bench/results/$(date +%Y%m%d-%H%M%S)
mkdir -p "$R"
exec > >(tee -a "$R/run.log") 2>&1

# 1. tinymapper：各阶段用到的 tinymapper 变体
need=""
for s in $STAGES; do
  case $s in
    bench) need="$need $FWDS" ;;
    syscount) need="$need $SC_FWDS" ;;
    prof) need="$need $(echo "$PROF_RUNS" | tr ' ' '\n' | sed 's/:.*//')" ;;
  esac
done
for f in $(echo $need | tr ' ' '\n' | grep '^tinymapper' | sed 's/+.*$//' | sort -u); do
  file=$(tm_file "$f"); v=${file#tinymapper-}; v=${v%%-*}
  case $f in
    *@*) [ -x "$ROOT/build/$file" ] || REF=${f#*@} "$ROOT/docker/build.sh" "$v" ;;
    *) [ "${SKIP_BUILD:-}" = 1 ] && [ -x "$ROOT/build/$file" ] || "$ROOT/docker/build.sh" "$v" ;;
  esac
done

# 2. fwdbench：交叉编译为 Docker 服务端架构
ARCH=$(docker version -f '{{.Server.Arch}}')
(cd "$ROOT/bench/fwdbench" && CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -o "$ROOT/build/fwdbench-linux-$ARCH" .)

# 3. 镜像（无构建上下文；未改动时命中缓存）
build_image() {
  local tag=$1 file=$2 o; shift 2
  o=$(docker build -q "$@" -t "$tag" - < "$file" 2>&1) || { echo "$o"; exit 1; }
}
build_image $IMG "$ROOT/bench/Dockerfile"
case " $STAGES " in *" syscount "*|*" prof "*)
  build_image $PIMG "$ROOT/bench/prof/Dockerfile" --build-arg KVER="$(docker info -f '{{.KernelVersion}}')" ;;
esac

{
  echo "时间：$(date '+%F %T %z')"
  echo "源码：$(git -C "$ROOT" describe --always --dirty)"
  echo "Docker VM：$(docker info -f '{{.KernelVersion}} {{.Architecture}} {{.NCPU}} vCPU {{.MemTotal}} B')"
  echo "拓扑：$TOPO$([ "$TOPO" = veth ] && echo "（VETH_FLUSH_NS=${VETH_FLUSH_NS:-50000} VETH_DEFER=${VETH_DEFER:-2}）")"
  echo "参数：STAGES=$STAGES TM_LOG_LEVEL=$TM_LOG_LEVEL CAP_ADD=${CAP_ADD:-} REPS=$REPS DUR=$DUR FWDS=$FWDS TESTS=$TESTS SC_FWDS=$SC_FWDS SC_TESTS=$SC_TESTS SC_DUR=$SC_DUR"
  echo "二进制 sha256："
  (cd "$ROOT/build" && shasum -a 256 tinymapper-* "fwdbench-linux-$ARCH" || true)
  docker run --rm ${CNAME:+--name "$CNAME-env"} $IMG sh -c 'iperf3 --version | head -1; realm --version; rinetd --version; ip -V; ethtool --version'
} > "$R/env.txt"

# 4. 各阶段：容器内只有 loopback（TOPO=veth 时脚本在容器里另建命名空间），绑核与 sysctl 同 bench.sh 注释
COMMON=(--rm --init --network none --ulimit nofile=65536:65536
  --sysctl net.ipv4.tcp_tw_reuse=1 --sysctl net.ipv4.ip_local_port_range="21000 65535"
  -v "$ROOT/build:/build:ro" -v "$ROOT/bench:/bench:ro" -v "$R:/results"
  -e FWDBENCH="/build/fwdbench-linux-$ARCH" -e TM_LOG_LEVEL="$TM_LOG_LEVEL" -e TOPO="$TOPO")
[ -z "${VETH_FLUSH_NS:-}" ] || COMMON+=(-e VETH_FLUSH_NS="$VETH_FLUSH_NS")
[ -z "${VETH_DEFER:-}" ] || COMMON+=(-e VETH_DEFER="$VETH_DEFER")
for c in ${CAP_ADD:-}; do COMMON+=(--cap-add "$c"); done
PRIV=(--privileged); case " ${CAP_ADD:-} " in *" NET_ADMIN "*) ;; *) PRIV+=(-e TM_NOCAP=1) ;; esac
BPRIV=(); [ "$TOPO" = veth ] && BPRIV=("${PRIV[@]}")   # bench 阶段只在 veth 时 --privileged
for s in $STAGES; do
  log "阶段 $s"
  N=(); [ -z "${CNAME:-}" ] || N=(--name "$CNAME-$s")
  case $s in
    bench) docker run ${N[@]+"${N[@]}"} "${COMMON[@]}" ${BPRIV[@]+"${BPRIV[@]}"} -e REPS="$REPS" -e DUR="$DUR" -e TESTS="$TESTS" -e FWDS="$FWDS" -e OUT=/results/raw.jsonl \
      $IMG bash /bench/bench.sh ;;
    syscount) docker run ${N[@]+"${N[@]}"} "${COMMON[@]}" "${PRIV[@]}" -e DUR="$SC_DUR" -e TESTS="$SC_TESTS" -e FWDS="$SC_FWDS" -e OUT=/results/syscount \
      $PIMG bash /bench/syscount.sh ;;
    prof) docker run ${N[@]+"${N[@]}"} "${COMMON[@]}" "${PRIV[@]}" -e DUR="$PROF_DUR" -e RUNS="$PROF_RUNS" -e PHASES="$PHASES" -e OUT=/results/prof \
      $PIMG bash /bench/prof/prof.sh ;;
    *) log "未知阶段：$s"; exit 2 ;;
  esac || { rc=$?; log "阶段 ${s} 失败（退出码 ${rc}），结果目录：${R}"; exit $rc; }
done

# 5. 汇总
summarize_dir "$R"
for f in summary.md syscalls.md; do [ -f "$R/$f" ] && { echo; echo "## $f"; cat "$R/$f"; }; done
log "结果目录：$R"
