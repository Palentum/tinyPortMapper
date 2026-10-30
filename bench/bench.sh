#!/usr/bin/env bash
# 端口转发吞吐/延迟/内存基准：每个 (轮次, 测试, 转发器) 启动一个新转发器进程，输出一行 JSON 到 OUT
# loopback：在 tinymapper-bench 镜像内运行（bench/run.sh 调用），转发器 CPU0（realm-2c 为 CPU0-1），客户端 CPU2-3，后端 CPU4-5；
# TOPO=veth 时三个角色各在一个网络命名空间（lib.sh 的 topo_up），绑核相同
# 每行另记 cpus（客户端运行期间转发器所在 CPU 与客户端、后端 CPU 的占用，含 softirq，见 lib.sh 的 cpu_json），
# UDP 负载且被测的是 tinymapper 时记 tm_udp（运行结束后 SIGUSR1 统计的 udp 行，--udp-gro 时含 up_gro/down_gro），
# fwd_win_s 是 CPU 统计窗口的秒数（fwd_cpu_pct × fwd_win_s ÷ 转发的数据报数 = 每个数据报的 CPU 时间，不受接收端丢包影响）
# 主机模式：bench/host.sh 在开发机上调用，三个角色经 RSH 在各自主机执行（见 lib.sh）
set -u
. "$(dirname "$0")/lib.sh"

REPS=${REPS:-3}
DUR=${DUR:-10}
FWDS=${FWDS:-"direct tinymapper tinymapper-musl rinetd realm-1c realm-2c"}
TESTS=${TESTS:-"tcp_bw_1 tcp_bw_8 tcp_rr_64 tcp_rr_1000 tcp_crr_32 udp_bw_1400 udp_pps_64 tcp_mem_5000"}
OUT=${OUT:-/results/raw.jsonl}
CLI="taskset -c $CLI_CPUS"

# 每个测试输出一行 JSON 指标
run_test() {
  local t=$1 j
  case $t in
    tcp_bw_1|tcp_bw_8)
      j=$(on cli "$CLI $IPERF3 -c $TARGET_IP -p $TARGET_PORT -t $DUR -O 1 -P ${t##*_} -J")
      echo "$j" | jq -c '{gbps: (.end.sum_received.bits_per_second/1e9), retrans: .end.sum_sent.retransmits, err: .error}' ;;
    udp_rr_*)
      on cli "$CLI $FWDBENCH udp-rr -c $(hp "$TARGET_IP" "$TARGET_PORT") -n ${t##*_} -s 64 -d ${DUR}s -w 1s" ;;
    udp_bw_*|udp_pps_*)
      j=$(on cli "$CLI $IPERF3 -c $TARGET_IP -p $TARGET_PORT $(iperf_udp "$t") -t $DUR -O 1 -J")
      echo "$j" | jq -c '{gbps: (.end.sum_received.bits_per_second/1e9), kpps: ((.end.sum_received.packets - .end.sum_received.lost_packets)/.end.sum_received.seconds/1e3), sent_kpps: (.end.sum_sent.packets/.end.sum_sent.seconds/1e3), lost_pct: .end.sum_received.lost_percent, err: .error}' ;;
    tcp_rr_64|tcp_rr_1000)
      on cli "$CLI $FWDBENCH rr -c $(hp "$TARGET_IP" "$TARGET_PORT") -n ${t##*_} -s 64 -d ${DUR}s -w 1s" ;;
    tcp_crr_*)
      on cli "$CLI $FWDBENCH crr -c $(hp "$TARGET_IP" "$TARGET_PORT") -n ${t##*_} -s 64 -d ${DUR}s -w 1s" ;;
  esac
}

one() {
  local rep=$1 t=$2 fwd=$3 res a b c0 u0 r0 c1 u1 r1 thr hpid cpu win sa sb cpus st=null
  if ! start_fwd "$fwd" "$(backend_for "$t")"; then
    jq -nc --arg fwd "$fwd" --arg t "$t" --argjson rep "$rep" '{rep: $rep, test: $t, fwd: $fwd, err: "start failed"}' | tee -a "$OUT"
    stop_fwd; return
  fi
  if [ "$t" = tcp_mem_5000 ]; then
    a=$(fwd_stat)
    hpid=$(spawn cli hold.out "$CLI $FWDBENCH hold -c $(hp "$TARGET_IP" "$TARGET_PORT") -n 5000 -s 32768 -d 6s")
    for _ in $(seq 1 100); do on cli "grep -q '^{' $WORK/hold.out" && break; sleep 0.1; done
    sleep 1
    b=$(fwd_stat)
    on cli "while kill -0 $hpid 2>/dev/null; do sleep 0.2; done"
    read -r c0 u0 r0 _ <<< "$a"; read -r c1 u1 r1 thr <<< "$b"
    res=$(on cli "grep -m1 '^{' $WORK/hold.out" | jq -c --argjson r0 "${r0:-0}" --argjson r1 "${r1:-0}" \
      '. + {rss_idle_kb: $r0, rss_hold_kb: $r1, kb_per_conn: (if .established > 0 then (($r1 - $r0) / .established) else null end)}')
  else
    a=$(fwd_stat); sa=$(cpu_snap)
    res=$(run_test "$t")
    b=$(fwd_stat); sb=$(cpu_snap)
    read -r c0 u0 _ _ <<< "$a"; read -r c1 u1 r1 thr <<< "$b"
    cpus=$(cpu_json "$sa" "$sb")
    case $t in udp_*) st=$(tm_stats | stats_json) ;; esac
  fi
  cpu=$(awk -v a="${c0:-0}" -v b="${c1:-0}" -v s="${u0:-0}" -v e="${u1:-0}" 'BEGIN{printf "%.1f", (e > s ? (b-a)/(e-s) : 0)}')
  win=$(awk -v s="${u0:-0}" -v e="${u1:-0}" 'BEGIN{printf "%.2f", e - s}')
  [ -z "$res" ] && res='{"err":"no output"}'
  if ! fwd_alive; then
    res=$(echo "$res" | jq -c '. + {err: "forwarder exited"}')
  fi
  echo "$res" | jq -c --arg fwd "$fwd" --arg t "$t" --argjson rep "$rep" \
    --argjson cpu "$cpu" --argjson rss "${r1:-0}" --argjson thr "${thr:-0}" --argjson cpus "${cpus:-null}" --argjson st "$st" --argjson win "$win" --arg topo "$TOPO" \
    '{rep: $rep, test: $t, fwd: $fwd} + (if $topo != "loopback" then {topo: $topo} else {} end) + . + {fwd_cpu_pct: (if $fwd == "direct" then null else $cpu end), fwd_rss_kb: (if $fwd == "direct" then null else $rss end), fwd_threads: (if $fwd == "direct" then null else $thr end)}
      + (if $fwd == "direct" then {} else {fwd_win_s: $win} end) + (if $cpus then {cpus: $cpus} else {} end) + (if $st then {tm_udp: $st} else {} end)' | tee -a "$OUT"
  stop_fwd
}

trap 'stop_fwd; stop_backends' EXIT
trap 'exit 130' INT TERM
mkdir -p "$(dirname "$OUT")"
topo_up "$(dirname "$OUT")/topo.txt" || exit 1
start_backends || exit 1
for rep in $(seq 1 "$REPS"); do
  for t in $TESTS; do
    for fwd in $FWDS; do
      log "rep=$rep test=$t fwd=$fwd"
      one "$rep" "$t" "$fwd"
    done
  done
done
log 完成
