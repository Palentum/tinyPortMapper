#!/usr/bin/env python3
"""汇总 bench/prof/prof.sh 输出目录中的 perf stat / perf report / 客户端输出，打印 Markdown 表格。

用法：python3 -I bench/prof/summarize_prof.py <主数据目录> [<重复数据目录>] [<ipi 数据目录>]
ipi 数据目录缺省为主数据目录（其中有 *.ipi.csv 时）；syscall 表由 bench/syscount.py 生成。
"""
import json
import re
import subprocess
import sys
from pathlib import Path

MAIN = Path(sys.argv[1])
REP = Path(sys.argv[2]) if len(sys.argv) > 2 else None
IPI = Path(sys.argv[3]) if len(sys.argv) > 3 else (MAIN if any(MAIN.glob("*.ipi.csv")) else None)
HZ = 100
# (转发器, 负载)：按各阶段文件的修改时间排序，即采集顺序
RUNS = []
for _p in sorted([p for g in ("*.clean.txt", "*.stat.csv", "*.dso.txt") for p in MAIN.glob(g)], key=lambda p: p.stat().st_mtime):
    _run = tuple(re.sub(r"\.(clean\.txt|stat\.csv|dso\.txt)$", "", _p.name).rsplit(".", 1))
    if _run not in RUNS:
        RUNS.append(_run)
TM_RUNS = [r for r in RUNS if r[0].startswith("tinymapper")]
KSYS = ["sendto", "recvfrom", "sendmmsg", "recvmmsg", "splice", "epoll_pwait", "epoll_ctl",
        "accept", "accept4", "connect", "socket", "close", "setsockopt", "fcntl", "pipe2", "shutdown"]
KINCL = ["net_rx_action", "__wake_up_sync_key", "tcp_sendmsg", "udp_sendmsg", "tcp_recvmsg", "udp_recvmsg",
         "__arch_copy_to_user", "__arch_copy_from_user", "arch_counter_get_cntvct", "do_epoll_wait",
         "__tcp_close", "tcp_v4_connect"]
# cpu-clock 无 PMU：关中断区间的样本落到开中断点；libc 包装函数的样本落在 svc 指令及其下一条
SINKS = {
    "__wake_up_sync_key": "唤醒对端：spin_lock_irqsave 区间（含跨 CPU 唤醒/IPI）的样本在开中断后落于 +0x68",
    "el0_svc": "syscall 进出关中断区间的落点",
    "__local_bh_enable_ip": "softirq 结束开中断落点",
    "_raw_spin_unlock_irqrestore": "开中断落点",
    "arch_local_irq_save": "关中断落点",
    "handle_softirqs": "softirq 循环",
    "arch_counter_get_cntvct": "内核读计数器（ktime/skb 时间戳）",
    "net_rx_action": "loopback 收包 softirq（对端收包路径在本 CPU 执行）",
}
USER_CATS = [
    ("syscall 包装函数（svc 落点，实为内核进出）", re.compile(
        r"^(__libc_\w+|epoll_pwait|epoll_ctl|__socket|__setsockopt|__fcntl64_nocancel_adjusted|__libc_fcntl64|__close\w*|__GI_\w+)$")),
    ("时钟：vDSO clock_gettime / ev_time / get_current_time", re.compile(
        r"^(0x[0-9a-f]+|__clock_gettime|__kernel_clock_gettime|ev_time|get_current_time\(\)|get_current_time_us\(\)|time_update\(.*)$")),
    ("address_t::to_str → sprintf/inet_ntop", re.compile(
        r"^(__printf_buffer\w*|_itoa_word|__strchrnul|__vsprintf_internal|__sprintf_chk|inet_ntop4|address_t::to_str\(.*|__memcpy_generic|strcpy|__strlen_asimd|\.plt)$")),
    ("libev 事件循环", re.compile(
        r"^(ev_run\.part\.0|ev_run|ev_invoke_pending|ev_feed_event|epoll_poll\(.*|ev_io_start|ev_io_stop|epoll_modify\(.*|fd_reify\(.*|fd_change\(.*|wlist_\w+\(.*|timers_reify\(.*|queue_events\(.*|fd_event\(.*|ev_now_update)$")),
    ("unordered_map / list（fd_manager、LRU、adress_to_info）", re.compile(
        r"^(std::_Hashtable.*|std::__detail::.*|sdbm\(.*|address_t::hash_function.*|address_t::operator==.*|address_t::equal.*|fd_manager_t::.*)$")),
    ("malloc/free/new/delete", re.compile(
        r"^(malloc|free|cfree|_int_malloc|_int_free\w*|malloc_consolidate|unlink_chunk.*|tcache\w*|operator new.*|operator delete.*)$")),
    ("转发回调本体（含内联的 lru.update/assert）", re.compile(
        r"^(tcp_cb\(.*|udp_cb\(.*|udp_accept_cb\(.*|tcp_accept_cb\(.*|select_remote_index\(.*|address_t::from_sockaddr\(.*|set_buf_size\(.*|setnonblocking\(.*)$")),
    ("日志 log0 / strerror（被过滤的 mylog 仍会调用）", re.compile(
        r"^(log0\(.*|__dcigettext|__get_errlist|strerror\w*|__strerror_r|get_sock_error\(.*|__pthread_rwlock_\w+)$")),
]


def load_stat(p):
    ev = {}
    for line in p.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split(",")
        try:
            ev[f[2]] = float(f[0])
        except ValueError:
            ev[f[2]] = None
        if f[2] == "task-clock":
            ev["_window_s"] = float(f[3]) / 1e9
    return ev


def snmp_pairs(text):
    rows = [l.split()[1:] for l in text.splitlines() if l.startswith("Udp:")]
    return [dict(zip(rows[i], map(int, rows[i + 1]))) for i in range(0, len(rows), 2)]


def kname(ch, arm64, x86):
    """内核符号名按架构取值（arm64 / x86_64）。"""
    return ch.get(arm64, ch.get(x86))


def load_children(p):
    res = {}
    if p.exists():
        for line in p.read_text().splitlines():
            m = re.match(r"\s+([\d.]+)%\s+([\d.]+)%\s+\[(.)\]\s+(.*\S)", line)
            if m:
                res.setdefault(m.group(4), float(m.group(1)))
    return res


def load_self(p):
    res = []
    if p.exists():
        for line in p.read_text().splitlines():
            m = re.match(r"\s+([\d.]+)%\s+(\S+)\s+\[(.)\]\s+(.*\S)", line)
            if m:
                res.append((float(m.group(1)), m.group(2), m.group(3), m.group(4)))
    return res


def load_dso(p):
    res = {}
    for line in p.read_text().splitlines():
        m = re.match(r"\s+([\d.]+)%\s+(\S+)", line)
        if m:
            res[m.group(2)] = float(m.group(1))
    return res


def per_unit(d, fwd, wl, phase="stat"):
    pre = d / f"{fwd}.{wl}"
    client = json.loads(Path(f"{pre}.{phase}.client.json").read_text())
    if wl.startswith(("tcp_rr", "tcp_crr", "udp_rr")):
        return client["ops"], "conn" if wl.startswith("tcp_crr") else "op", client["ops_per_sec"], client
    if wl.startswith("udp"):
        text = Path(f"{pre}.{phase}.snmp.txt").read_text()
        b, a = snmp_pairs(text)
        # 发送方（正向为客户端，_r 为后端）与转发器同机（loopback）时，OutDatagrams 也包含它的发包
        sender = "srv" if wl.endswith("_r") else "cli"
        fwd_tx = (a["OutDatagrams"] - b["OutDatagrams"]) - (0 if f"# {sender}_on_fwd=0" in text else client["sent_pkts"])
        return fwd_tx, "pkt", client["recv_kpps"] * 1e3, client
    return client["bytes"] / 1e9, "GB", client["gbps"], client


def fmt(x, nd=3):
    if x is None:
        return "-"
    if x == 0:
        return "0"
    if abs(x) >= 100:
        return f"{x:,.0f}"
    return f"{x:.{nd}f}"


def short(sym, n=70):
    sym = re.sub(r"std::pair<([^<>]|<[^<>]*>)*>", "pair<…>", sym)
    return sym if len(sym) <= n else sym[: n - 1] + "…"


def syscall_table():
    print("### syscalls / 单位（主数据，bench/syscount.py）\n")
    tool = Path(__file__).resolve().parent.parent / "syscount.py"
    print(subprocess.run([sys.executable, "-I", str(tool), str(MAIN)], check=True, capture_output=True, text=True).stdout)


def cpu_table():
    print("\n### CPU 拆分（主数据；clean 阶段 /proc 统计 + rec 阶段 perf 采样）\n")
    hdr = ["fwd", "workload", "clean 吞吐", "进程 CPU%", "utime%", "stime%", "绑定 CPU user%", "绑定 CPU sys%", "绑定 CPU softirq%",
           "perf 用户态%", "perf 内核%", "其中 net_rx_action（含）%", "其中 __wake_up_sync_key%", "用户态中 svc 落点%", "用户态扣除 svc 落点%"]
    if REP:
        hdr.append("重复运行 perf 用户态%")
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for fwd, wl in RUNS:
        pre = MAIN / f"{fwd}.{wl}"
        if not (Path(f"{pre}.clean.txt").exists() and Path(f"{pre}.dso.txt").exists()):
            continue
        snaps = [l.split() for l in Path(f"{pre}.clean.txt").read_text().splitlines() if re.match(r"^\d", l)]
        a, b = [list(map(float, s)) for s in snaps]
        wall = b[0] - a[0]
        ut, st = b[1] - a[1], b[2] - a[2]
        c = [b[i] - a[i] for i in range(3, 11)]
        ctot = sum(c)
        cj = json.loads(Path(f"{pre}.clean.client.json").read_text())
        if "ops_per_sec" in cj:
            thr = f"{cj['ops_per_sec']:,.0f} ops/s"
        elif "recv_kpps" in cj:
            thr = f"{cj['recv_kpps']:.0f} kpps"
        else:
            thr = f"{cj['gbps']:.1f} Gbit/s"
        dso = load_dso(Path(f"{pre}.dso.txt"))
        kern = dso.get("[kernel.kallsyms]", 0)
        ch = load_children(Path(f"{pre}.children.txt"))
        se = load_self(Path(f"{pre}.self.txt"))
        sink = sum(p for p, d, m, s in se if m == "." and USER_CATS[0][1].match(s)) + sum(
            p for p, d, m, s in se if d == "libc.so.6" and s in ("splice", "setsockopt", "sendmmsg", "recvmmsg", "epoll_wait", "close", "connect", "accept4", "socket"))
        wk = ch.get("__wake_up_sync_key", 0)
        row = [fwd, wl, thr, f"{(ut + st) / HZ / wall * 100:.1f}", f"{ut / (ut + st) * 100:.1f}", f"{st / (ut + st) * 100:.1f}",
               f"{(c[0] + c[1]) / ctot * 100:.1f}", f"{c[2] / ctot * 100:.1f}", f"{c[6] / ctot * 100:.1f}",
               f"{100 - kern:.1f}", f"{kern:.1f}", f"{ch.get('net_rx_action', 0):.1f}", f"{wk:.1f}", f"{sink:.1f}", f"{100 - kern - sink:.1f}"]
        if REP:
            row.append(f"{100 - load_dso(REP / f'{fwd}.{wl}.dso.txt').get('[kernel.kallsyms]', 0):.1f}")
        print("| " + " | ".join(row) + " |")


def ksys_table():
    print("\n### 各 syscall 的含子调用 CPU 占比（perf children，主数据）\n")
    print("| fwd | workload | el0_svc / do_syscall_64（全部 syscall） | " + " | ".join(KSYS) + " |")
    print("|" + "---|" * (len(KSYS) + 3))
    for fwd, wl in RUNS:
        ch = load_children(MAIN / f"{fwd}.{wl}.children.txt")
        print(f"| {fwd} | {wl} | {fmt(kname(ch, 'el0_svc', 'do_syscall_64'), 1)} | "
              + " | ".join(fmt(kname(ch, f'__arm64_sys_{k}', f'__x64_sys_{k}'), 1) for k in KSYS) + " |")
    print("\n### 关键内核函数含子调用占比（perf children，主数据；`-` 表示低于 0.5% 报告阈值）\n")
    print("| fwd | workload | " + " | ".join(KINCL) + " |")
    print("|" + "---|" * (len(KINCL) + 2))
    for fwd, wl in RUNS:
        ch = load_children(MAIN / f"{fwd}.{wl}.children.txt")
        print(f"| {fwd} | {wl} | " + " | ".join(fmt(ch.get(k), 1) for k in KINCL) + " |")


def ipi_table():
    if not IPI:
        return
    print("\n### 唤醒 / IPI / loopback 发包（单独一轮 perf stat，每个事件计数开销可忽略）\n")
    print("| fwd | workload | 单位 | 吞吐 | sched_waking/单位 | ipi_send_cpu/单位 | net_dev_xmit/单位 | ctx-sw/单位 |")
    print("|---|---|---|---|---|---|---|---|")
    for fwd, wl in RUNS:
        pre = IPI / f"{fwd}.{wl}"
        if not Path(f"{pre}.ipi.csv").exists():
            continue
        ev = load_stat(Path(f"{pre}.ipi.csv"))
        n, unit, rate, _ = per_unit(IPI, fwd, wl, "ipi")
        per = lambda k: fmt(ev[k] / n) if ev.get(k) is not None else "-"
        print(f"| {fwd} | {wl} | {unit} | {fmt(rate, 1)} | {per('sched:sched_waking')} | {per('ipi:ipi_send_cpu')} | "
              f"{per('net:net_dev_xmit')} | {fmt(ev['context-switches'] / n, 4)} |")


def top_tables():
    print("\n### tinymapper 各 workload 自身占比 Top 15（perf self，主数据）\n")
    for fwd, wl in TM_RUNS:
        se = load_self(MAIN / f"{fwd}.{wl}.self.txt")
        print(f"\n**{fwd} {wl}**\n")
        print("| # | self% | 空间 | 符号 | 备注 |")
        print("|---|---|---|---|---|")
        for i, (p, dso, m, s) in enumerate(se[:15], 1):
            space = "内核" if m == "k" else ("vDSO" if dso == "[vdso]" else "用户")
            note = SINKS.get(s, "")
            if m == "." and USER_CATS[0][1].match(s):
                note = "libc 包装函数：样本落在 svc 指令/其后一条，实为内核进出"
            elif dso == "[vdso]":
                note = "vDSO clock_gettime 读计数器"
            print(f"| {i} | {p:.2f} | {space} | `{short(s)}` | {note} |")


def user_table():
    print("\n### tinymapper 用户态样本按类别归并（占全部样本 %，主数据）\n")
    runs = [r for r in TM_RUNS if (MAIN / f"{r[0]}.{r[1]}.user.txt").exists()]
    print("| 类别 | " + " | ".join(f"{fwd} {wl}" for fwd, wl in runs) + " |")
    print("|---|" + "---|" * len(runs))
    data = {}
    for fwd, wl in runs:
        cats = {c: 0.0 for c, _ in USER_CATS}
        cats["其他"] = 0.0
        for line in (MAIN / f"{fwd}.{wl}.user.txt").read_text().splitlines():
            m = re.match(r"\s+([\d.]+)%\s+(\S+)\s+\[(.)\]\s+(.*\S)", line)
            if not m:
                continue
            p, sym = float(m.group(1)), m.group(4)
            for c, rx in USER_CATS:
                if rx.match(sym):
                    cats[c] += p
                    break
            else:
                cats["其他"] += p
        data[fwd, wl] = cats
    for c in [c for c, _ in USER_CATS] + ["其他"]:
        print(f"| {c} | " + " | ".join(f"{data[r][c]:.2f}" for r in runs) + " |")
    print("| **用户态合计** | " + " | ".join(f"{sum(data[r].values()):.2f}" for r in runs) + " |")


if __name__ == "__main__":
    syscall_table()
    cpu_table()
    ksys_table()
    ipi_table()
    user_table()
    top_tables()
