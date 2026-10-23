#!/usr/bin/env bash
# 转发器 CPU 剖析：每个 (转发器, 负载) 启动一个新转发器进程，依次执行 PHASES 中的阶段，原始数据写入 OUT
#   clean：不挂工具，前后读 /proc：进程 utime/stime 与转发器所在 CPU（FWD_CPUS 第一个）的 user/sys/softirq 拆分
#   stat ：syscall 计数（同 syscount.sh）
#   rec  ：perf record cpu-clock 采样（帧指针调用栈），客户端运行 DUR+1 秒中的第 2~7 秒；报告在 fwd 上生成后取回文本
#   ipi  ：唤醒 / IPI / 发包计数（只挂内核支持的 tracepoint）
# 汇总：python3 -I bench/prof/summarize_prof.py OUT。loopback 由 `STAGES=prof bench/run.sh` 调用，主机模式由 bench/host.sh 调用
set -u
. "$(dirname "$0")/../lib.sh"

OUT=${OUT:-/results/prof}
DUR=${DUR:-8}
RUNS=${RUNS:-"tinymapper:tcp_rr_64,tcp_rr_1000,tcp_crr_32,udp_pps_64,tcp_bw_8 realm-1c:tcp_rr_64,tcp_crr_32,udp_pps_64"}
PHASES=${PHASES:-"clean stat rec ipi"}
CPU=${FWD_CPUS%%[,-]*}
# perf.data 留在 fwd 上：loopback 时与文本报告同目录，主机模式在 fwd 的 WORK 下
PDIR=$([ -z "$FWD_HOST" ] && echo "$OUT" || echo "$WORK")

# 时间戳 进程utime 进程stime | cpuN: user nice system idle iowait irq softirq steal（单位 USER_HZ）
snap() {
  on fwd "awk '{printf \"%s \", \$1}' /proc/uptime; awk '{printf \"%s %s \", \$14, \$15}' /proc/$FWD_PID/stat; awk '/^cpu$CPU /{print \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9}' /proc/stat"
}

report() { local f=$1; shift; on fwd "$SUDO $PERF report -i $f $* --stdio 2>/dev/null"; }

trap 'stop_fwd; stop_backends' EXIT
trap 'exit 130' INT TERM
mkdir -p "$OUT"
on fwd "mkdir -p $PDIR"
IPI_EV=""
for e in sched:sched_waking ipi:ipi_raise ipi:ipi_send_cpu ipi:ipi_send_cpumask net:net_dev_xmit; do
  on fwd "$SUDO $PERF stat -e $e -- true >/dev/null 2>&1" && IPI_EV="$IPI_EV -e $e"
done
start_backends || exit 1

for spec in $RUNS; do
  fwd=${spec%%:*}
  case $fwd in
    tinymapper*) dso=$(tm_file "$fwd") ;;
    realm*) dso=realm ;;
    *) dso=$fwd ;;
  esac
  for w in $(echo "${spec#*:}" | tr , ' '); do
    pre=$OUT/$fwd.$w
    log "剖析 fwd=$fwd wl=$w"
    start_fwd "$fwd" "$(backend_for "$w")" || { stop_fwd; continue; }
    for ph in $PHASES; do
      case $ph in
        clean)
          { echo "# ts utime stime | cpu$CPU user nice system idle iowait irq softirq steal"; snmp_udp; snap; } > "$pre.clean.txt"
          client "$w" "$DUR" > "$pre.clean.client.json"
          { snap; snmp_udp | grep -v '^#'; } >> "$pre.clean.txt" ;;
        stat) count_phase stat "$(stat_events)" "$pre" "$w" "$DUR" ;;
        rec)
          pd=$PDIR/$fwd.$w.perf.data
          client "$w" $((DUR + 1)) > "$pre.rec.client.json" &
          cp=$!
          sleep 2
          on fwd "$SUDO $PERF record -e cpu-clock -F 1999 -g -p $FWD_PID -o $pd -- sleep 5" > "$pre.rec.log" 2>&1
          wait $cp
          report "$pd" --no-children --sort dso -g none > "$pre.dso.txt"
          report "$pd" --no-children --sort dso,sym -g none --percent-limit 0.2 > "$pre.self.txt"
          report "$pd" --children --sort sym -g none --percent-limit 0.5 > "$pre.children.txt"
          report "$pd" --no-children --dsos "'$dso,[vdso],libc.so.6'" --sort dso,sym -g none --percentage absolute --percent-limit 0.01 > "$pre.user.txt" ;;
        ipi)
          client "$w" 2 > /dev/null   # 预热
          sleep 1
          count_phase ipi "$IPI_EV -e context-switches -e task-clock" "$pre" "$w" "$DUR" ;;
      esac
      sleep 2
    done
    stop_fwd
  done
done
log 完成
