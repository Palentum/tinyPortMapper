#!/usr/bin/env bash
# syscall 计数（P0.3，剖析 stat 阶段的独立版本）：每个 (转发器, 负载) 启动一个新转发器进程，perf stat 统计它在
# 客户端整个生命周期内的 syscall（总数、各 syscall 分项、主要收发/连接调用的失败返回），原始数据写入 OUT，
# 由 syscount.py 换算为每单位次数。需要 perf：loopback 在 tinymapper-bench-prof 镜像（--privileged）内运行（TOPO=veth 时在 veth 拓扑里），
# 主机模式在 fwd 主机上执行
set -u
. "$(dirname "$0")/lib.sh"

OUT=${OUT:-/results/syscount}
DUR=${DUR:-8}
FWDS=${FWDS:-"tinymapper realm-1c"}
TESTS=${TESTS:-"tcp_rr_64 tcp_rr_1000 tcp_crr_32 udp_pps_64 tcp_bw_8"}

trap 'stop_fwd; stop_backends' EXIT
trap 'exit 130' INT TERM
mkdir -p "$OUT"
topo_up "$OUT/topo.txt" || exit 1
start_backends || exit 1
for fwd in $FWDS; do
  [ "$fwd" = direct ] && continue
  for w in $TESTS; do
    log "syscall 计数 fwd=$fwd wl=$w"
    if start_fwd "$fwd" "$(backend_for "$w")"; then
      count_phase stat "$(stat_events)" "$OUT/$fwd.$w" "$w" "$DUR"
      fwd_alive || log "转发器中途退出：fwd=$fwd wl=$w"
    fi
    stop_fwd
  done
done
log 完成
