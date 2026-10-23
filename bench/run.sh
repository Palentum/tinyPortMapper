#!/usr/bin/env bash
# loopback 基准，一条命令出全部结果：编译 tinymapper（docker/build.sh）→ 交叉编译 fwdbench → 构建工具镜像
# → 吞吐/延迟/内存基准 → syscall 计数 → 汇总。结果写入 bench/results/<时间戳>/。
#
# 用法：bench/run.sh
#   QUICK=1 bench/run.sh                                   冒烟（REPS=1 DUR=3 SC_DUR=3）
#   FWDS="tinymapper@4acc876 tinymapper" bench/run.sh      基线提交与工作区前后对比
#   STAGES=syscount SC_FWDS=tinymapper@4acc876 bench/run.sh 只做 syscall 计数
#   STAGES=prof bench/run.sh                               CPU 剖析（bench/prof/prof.sh）
# 环境变量：
#   STAGES   要执行的阶段：bench syscount prof（默认 "bench syscount"）
#   FWDS     转发器，默认 "direct tinymapper tinymapper-musl rinetd realm-1c realm-2c"；
#            tinymapper[-musl]@<后缀> 使用 build/tinymapper-{glibc,musl}-<后缀>，缺失时以 REF=<后缀> 自动编译
#   TESTS    测试项，默认全部 8 项；REPS 轮数（3）；DUR 每项秒数（10）
#   SC_FWDS / SC_TESTS / SC_DUR  syscall 计数的转发器（默认 FWDS 去掉 direct、realm-2c）、负载（5 个）、秒数（8）
#   PROF_RUNS / PROF_DUR / PHASES 剖析范围（格式见 bench/prof/prof.sh）
#   SKIP_BUILD=1  不重新编译工作区的 tinymapper（缺失的二进制仍会编译）
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
IMG=tinymapper-bench:1
PIMG=tinymapper-bench-prof:1
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
for f in $(echo $need | tr ' ' '\n' | grep '^tinymapper' | sort -u); do
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
  echo "参数：STAGES=$STAGES REPS=$REPS DUR=$DUR FWDS=$FWDS TESTS=$TESTS SC_FWDS=$SC_FWDS SC_TESTS=$SC_TESTS SC_DUR=$SC_DUR"
  echo "二进制 sha256："
  (cd "$ROOT/build" && shasum -a 256 tinymapper-* "fwdbench-linux-$ARCH" || true)
  docker run --rm $IMG sh -c 'iperf3 --version | head -1; realm --version; rinetd --version'
} > "$R/env.txt"

# 4. 各阶段：容器内只有 loopback，绑核与 sysctl 同 bench.sh 注释
COMMON=(--rm --init --network none --ulimit nofile=65536:65536
  --sysctl net.ipv4.tcp_tw_reuse=1 --sysctl net.ipv4.ip_local_port_range="21000 65535"
  -v "$ROOT/build:/build:ro" -v "$ROOT/bench:/bench:ro" -v "$R:/results"
  -e FWDBENCH="/build/fwdbench-linux-$ARCH")
for s in $STAGES; do
  log "阶段 $s"
  case $s in
    bench) docker run "${COMMON[@]}" -e REPS="$REPS" -e DUR="$DUR" -e TESTS="$TESTS" -e FWDS="$FWDS" -e OUT=/results/raw.jsonl \
      $IMG bash /bench/bench.sh ;;
    syscount) docker run "${COMMON[@]}" --privileged -e DUR="$SC_DUR" -e TESTS="$SC_TESTS" -e FWDS="$SC_FWDS" -e OUT=/results/syscount \
      $PIMG bash /bench/syscount.sh ;;
    prof) docker run "${COMMON[@]}" --privileged -e DUR="$PROF_DUR" -e RUNS="$PROF_RUNS" -e PHASES="$PHASES" -e OUT=/results/prof \
      $PIMG bash /bench/prof/prof.sh ;;
    *) log "未知阶段：$s"; exit 2 ;;
  esac || { rc=$?; log "阶段 ${s} 失败（退出码 ${rc}），结果目录：${R}"; exit $rc; }
done

# 5. 汇总
summarize_dir "$R"
for f in summary.md syscalls.md; do [ -f "$R/$f" ] && { echo; echo "## $f"; cat "$R/$f"; }; done
log "结果目录：$R"
