#!/usr/bin/env bash
# 端口转发吞吐/延迟/内存基准：每个 (轮次, 测试, 转发器) 启动一个新转发器进程，输出一行 JSON 到 OUT
# loopback：在 tinymapper-bench 镜像内运行（bench/run.sh 调用），转发器 CPU0（realm-2c 为 CPU0-1），客户端 CPU2-3，后端 CPU4-5；
# TOPO=veth 时三个角色各在一个网络命名空间（lib.sh 的 topo_up），绑核相同
# 每行另记 cpus（客户端运行期间转发器所在 CPU 与客户端、后端 CPU 的占用，含 softirq，见 lib.sh 的 cpu_json），
# 被测的是 tinymapper 时记运行结束后 SIGUSR1 统计（lib.sh 的 tm_stats）：TCP 负载记 tm_tcp（tcp 行：conns、total、up_bytes、down_bytes，
# B2 起含 up_splice/down_splice/splice_fallback），UDP 负载记 tm_udp（udp 行，--udp-gro 时含 up_gro/down_gro），两者都另记 tm_pool
# （pool 行，bufs_*、tcp_pairs_*、udp_pairs_*，B2 起含 pipes_*）；tcp_bulk_* 另记测量窗口中点的 tm_tcp_mid/tm_pool_mid，
# _stall 时还有 sink 停顿中途的 tm_tcp_stall/tm_pool_stall（这时所有方向都积压在转发器里），
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

# tm_json <tm_stats 的输出> <键后缀> <行种类...>：各种类（tcp、udp、pool）的行转为 "tm_<种类><键后缀>": {…}，合成一个 JSON 对象；
# 没有统计时为 {}
tm_json() {
  local s=$1 x=$2 k o='{}'; shift 2
  for k in "$@"; do
    o=$(echo "$s" | stats_json "$k" | jq -c --argjson o "$o" --arg k "tm_$k$x" 'if . == null then $o else $o + {($k): .} end')
  done
  echo "$o"
}

# tcp_bulk_*（由 one 调用，设置 one 的 res、a、b、sa、sb、ex）：客户端在后台运行（lib.sh 的 bulk_args），输出里出现 streaming 即
# 全部连接已建立、开始发送；_stall 时在 sink 停顿中途取一次统计，之后等到测量窗口开始取 CPU 起点，窗口中点取一次统计，
# 窗口结束取 CPU 终点（各次统计的耗时让这个窗口与客户端的测量窗口有零点几秒的错位），再等客户端收尾退出
bulk_test() {
  local t=$1 w=1 p h
  case $t in *_stall) w=$((BULK_STALL + 1)) ;; esac
  h=$(awk -v d="$DUR" 'BEGIN {print d / 2}')
  on cli "rm -f $WORK/bulk.out"   # 上一次运行的 streaming 行不能算数
  p=$(spawn cli bulk.out "$CLI $FWDBENCH $(bulk_args "$t" "$DUR" "$w")")
  for _ in $(seq 1 300); do on cli "grep -q streaming $WORK/bulk.out" && break; sleep 0.1; done
  case $t in
    *_stall)
      sleep "$(awk -v s="$BULK_STALL" 'BEGIN {print s / 2}')"
      ex=$(tm_json "$(tm_stats)" _stall tcp pool)
      sleep "$(awk -v s="$BULK_STALL" -v w="$w" 'BEGIN {print w - s / 2}')" ;;
    *) sleep "$w" ;;
  esac
  a=$(fwd_stat); sa=$(cpu_snap)
  sleep "$h"
  ex=$(echo "$ex" | jq -c --argjson m "$(tm_json "$(tm_stats)" _mid tcp pool)" '. + $m')
  sleep "$h"
  b=$(fwd_stat); sb=$(cpu_snap)
  on cli "while kill -0 $p 2>/dev/null; do sleep 0.2; done"
  res=$(on cli "grep -m1 '^{' $WORK/bulk.out")
}

one() {
  local rep=$1 t=$2 fwd=$3 res a b c0 u0 r0 c1 u1 r1 thr hpid cpu win sa sb cpus ex='{}'
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
    if [ "${t#tcp_bulk_}" != "$t" ]; then
      bulk_test "$t"
    else
      a=$(fwd_stat); sa=$(cpu_snap)
      res=$(run_test "$t")
      b=$(fwd_stat); sb=$(cpu_snap)
    fi
    read -r c0 u0 _ _ <<< "$a"; read -r c1 u1 r1 thr <<< "$b"
    cpus=$(cpu_json "$sa" "$sb")
    case $t in
      tcp_*) ex=$(echo "$ex" | jq -c --argjson f "$(tm_json "$(tm_stats)" "" tcp pool)" '. + $f') ;;
      udp_*) ex=$(tm_json "$(tm_stats)" "" udp pool) ;;
    esac
  fi
  cpu=$(awk -v a="${c0:-0}" -v b="${c1:-0}" -v s="${u0:-0}" -v e="${u1:-0}" 'BEGIN{printf "%.1f", (e > s ? (b-a)/(e-s) : 0)}')
  win=$(awk -v s="${u0:-0}" -v e="${u1:-0}" 'BEGIN{printf "%.2f", e - s}')
  [ -z "$res" ] && res='{"err":"no output"}'
  if ! fwd_alive; then
    res=$(echo "$res" | jq -c '. + {err: "forwarder exited"}')
  fi
  echo "$res" | jq -c --arg fwd "$fwd" --arg t "$t" --argjson rep "$rep" \
    --argjson cpu "$cpu" --argjson rss "${r1:-0}" --argjson thr "${thr:-0}" --argjson cpus "${cpus:-null}" --argjson ex "$ex" --argjson win "$win" --arg topo "$TOPO" \
    '{rep: $rep, test: $t, fwd: $fwd} + (if $topo != "loopback" then {topo: $topo} else {} end) + . + {fwd_cpu_pct: (if $fwd == "direct" then null else $cpu end), fwd_rss_kb: (if $fwd == "direct" then null else $rss end), fwd_threads: (if $fwd == "direct" then null else $thr end)}
      + (if $fwd == "direct" then {} else {fwd_win_s: $win} end) + (if $cpus then {cpus: $cpus} else {} end) + $ex' | tee -a "$OUT"
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
