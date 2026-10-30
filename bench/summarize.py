#!/usr/bin/env python3
# 汇总 bench.sh 输出的 raw.jsonl：每个 (test, fwd) 取多轮中位数，输出 markdown 表格
# 用法：python3 -I bench/summarize.py bench/results/<时间戳>/raw.jsonl；转发器按首次出现的顺序排列，缺失的测试项不输出；
# 名字不固定的 UDP 负载（udp_pps_64_p<N>、*_r、udp_rr_<N>）按首次出现的顺序接在同类固定项之后；
# UDP iperf3 表在数据里有 cpus / tm_udp 的 up_gro 时多出：转发器所在 CPU 忙碌%（含 softirq）、udp_bw 的每 Gbit/s CPU%、合并%
import json
import statistics
import sys
from collections import defaultdict

path = sys.argv[1]
rows = defaultdict(list)
FWDS = []
TESTS = []
for line in open(path):
    line = line.strip()
    if line.startswith("{"):
        r = json.loads(line)
        rows[(r["test"], r["fwd"])].append(r)
        if r["fwd"] not in FWDS:
            FWDS.append(r["fwd"])
        if r["test"] not in TESTS:
            TESTS.append(r["test"])


def med(rs, k):
    v = [r[k] for r in rs if r.get(k) is not None]
    return statistics.median(v) if v else None


def rng(rs, k, fmt):
    v = [r[k] for r in rs if r.get(k) is not None]
    return f"{fmt(min(v))}–{fmt(max(v))}" if v else "-"


def f(x, nd=1):
    return "-" if x is None else f"{x:,.{nd}f}"


def table(test, cols):
    if not any(t == test for t, _ in rows):
        return
    print(f"\n### {test}\n")
    print("| 目标 | " + " | ".join(c[0] for c in cols) + " | 错误 |")
    print("|---" * (len(cols) + 2) + "|")
    for fwd in FWDS:
        rs = rows.get((test, fwd))
        if not rs:
            continue
        cells = [c[1](rs) for c in cols]
        errs = sorted({str(r.get("err")) for r in rs if r.get("err")} |
                      {f"errors={r['errors']}" for r in rs if r.get("errors")})
        print(f"| {fwd} | " + " | ".join(cells) + f" | {', '.join(errs) or '0'} |")


def cpu(rs):
    return f(med(rs, "fwd_cpu_pct"), 0)


def per_core(k, scale=1.0):
    def g(rs):
        c, v = med(rs, "fwd_cpu_pct"), med(rs, k)
        return "-" if not c or v is None else f(v * scale / (c / 100), 1)
    return g


for t in ["tcp_bw_1", "tcp_bw_8"]:
    table(t, [
        ("吞吐 Gbit/s（中位）", lambda rs: f(med(rs, "gbps"))),
        ("范围", lambda rs: rng(rs, "gbps", lambda x: f"{x:.1f}")),
        ("转发器 CPU%", cpu),
        ("Gbit/s 每核", per_core("gbps")),
    ])

for t in ["tcp_rr_64", "tcp_rr_1000", "tcp_crr_32"]:
    table(t, [
        ("ops/s（中位）", lambda rs: f(med(rs, "ops_per_sec"), 0)),
        ("范围", lambda rs: rng(rs, "ops_per_sec", lambda x: f"{x/1e3:.0f}k")),
        ("p50 µs", lambda rs: f(med(rs, "p50_us"), 0)),
        ("p99 µs", lambda rs: f(med(rs, "p99_us"), 0)),
        ("p99.9 µs", lambda rs: f(med(rs, "p999_us"), 0)),
        ("转发器 CPU%", cpu),
        ("kops/s 每核", per_core("ops_per_sec", 1e-3)),
    ])

def fwd_cpu(r, k):
    return ((r.get("cpus") or {}).get("fwd") or {}).get(k)


def mv(v):
    v = [x for x in v if x is not None]
    return statistics.median(v) if v else None


def fwd_busy(rs):
    b = mv([fwd_cpu(r, "busy") for r in rs])
    return "-" if b is None else f"{b:.0f}（{mv([fwd_cpu(r, 'softirq') for r in rs]):.0f}）"


def per_gbit(rs):
    p = mv([r["fwd_cpu_pct"] / r["gbps"] for r in rs if r.get("fwd_cpu_pct") is not None and r.get("gbps")])
    b = mv([fwd_cpu(r, "busy") / r["gbps"] for r in rs if fwd_cpu(r, "busy") is not None and r.get("gbps")])
    return f"{f(p, 1)} / {f(b, 1)}"


# 合并%：tm_udp 里同方向（正向 up，_r 为 down）以 GRO 合并包到达的数据报占转发与丢弃之和的比例
def merged(rs):
    v = []
    for r in rs:
        u, d = r.get("tm_udp") or {}, "down" if r["test"].endswith("_r") else "up"
        if f"{d}_gro" in u:
            tot = u[f"{d}_pkts"] + u[f"{d}_drop"]
            v.append(100 * u[f"{d}_gro"] / tot if tot else 0)
    return f(mv(v), 0)


UDP_FIXED = ["udp_bw_1400", "udp_pps_64"]
for t in UDP_FIXED + [t for t in TESTS if t.startswith(("udp_bw_", "udp_pps_")) and t not in UDP_FIXED]:
    rs_t = [r for (tt, _), rs in rows.items() if tt == t for r in rs]
    extra = []
    if any(r.get("cpus") for r in rs_t):
        extra.append(("所在 CPU 忙碌%（softirq）", fwd_busy))
        if t.startswith("udp_bw_"):
            extra.append(("CPU% 每 Gbit/s（进程 / 所在 CPU）", per_gbit))
    if any("up_gro" in (r.get("tm_udp") or {}) for r in rs_t):
        extra.append(("合并%", merged))
    table(t, [
        ("收到 Gbit/s（中位）", lambda rs: f(med(rs, "gbps"), 2)),
        ("收到 kpps", lambda rs: f(med(rs, "kpps"), 0)),
        ("范围 kpps", lambda rs: rng(rs, "kpps", lambda x: f"{x:.0f}")),
        ("发送 kpps", lambda rs: f(med(rs, "sent_kpps"), 0)),
        ("丢包 %", lambda rs: f(med(rs, "lost_pct"), 1)),
        ("转发器 CPU%", cpu),
        ("收到 kpps 每核", per_core("kpps")),
    ] + extra)

# udp_rr_<N>：fwdbench udp-rr，丢失 = 超时（默认 200 ms）没收到回显的请求
for t in [t for t in TESTS if t.startswith("udp_rr_")]:
    table(t, [
        ("ops/s（中位）", lambda rs: f(med(rs, "ops_per_sec"), 0)),
        ("范围", lambda rs: rng(rs, "ops_per_sec", lambda x: f"{x/1e3:.1f}k")),
        ("p50 µs", lambda rs: f(med(rs, "p50_us"), 0)),
        ("p99 µs", lambda rs: f(med(rs, "p99_us"), 0)),
        ("p99 范围", lambda rs: rng(rs, "p99_us", lambda x: f"{x:.0f}")),
        ("p99.9 µs", lambda rs: f(med(rs, "p999_us"), 0)),
        ("丢失 %", lambda rs: f(med(rs, "lost_pct"), 3)),
        ("转发器 CPU%", cpu),
        ("kops/s 每核", per_core("ops_per_sec", 1e-3)),
    ])

table("tcp_mem_5000", [
    ("建立连接数", lambda rs: f(med(rs, "established"), 0)),
    ("空闲 RSS KB", lambda rs: f(med(rs, "rss_idle_kb"), 0)),
    ("5000 连接 RSS KB", lambda rs: f(med(rs, "rss_hold_kb"), 0)),
    ("KB/连接", lambda rs: f(med(rs, "kb_per_conn"), 2)),
    ("线程数", lambda rs: f(med(rs, "fwd_threads"), 0)),
])
