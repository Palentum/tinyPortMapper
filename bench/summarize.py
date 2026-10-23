#!/usr/bin/env python3
# 汇总 bench.sh 输出的 raw.jsonl：每个 (test, fwd) 取多轮中位数，输出 markdown 表格
# 用法：python3 -I bench/summarize.py bench/results/<时间戳>/raw.jsonl；转发器按首次出现的顺序排列，缺失的测试项不输出
import json
import statistics
import sys
from collections import defaultdict

path = sys.argv[1]
rows = defaultdict(list)
FWDS = []
for line in open(path):
    line = line.strip()
    if line.startswith("{"):
        r = json.loads(line)
        rows[(r["test"], r["fwd"])].append(r)
        if r["fwd"] not in FWDS:
            FWDS.append(r["fwd"])


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

for t in ["udp_bw_1400", "udp_pps_64"]:
    table(t, [
        ("收到 Gbit/s（中位）", lambda rs: f(med(rs, "gbps"), 2)),
        ("收到 kpps", lambda rs: f(med(rs, "kpps"), 0)),
        ("范围 kpps", lambda rs: rng(rs, "kpps", lambda x: f"{x:.0f}")),
        ("发送 kpps", lambda rs: f(med(rs, "sent_kpps"), 0)),
        ("丢包 %", lambda rs: f(med(rs, "lost_pct"), 1)),
        ("转发器 CPU%", cpu),
        ("收到 kpps 每核", per_core("kpps")),
    ])

table("tcp_mem_5000", [
    ("建立连接数", lambda rs: f(med(rs, "established"), 0)),
    ("空闲 RSS KB", lambda rs: f(med(rs, "rss_idle_kb"), 0)),
    ("5000 连接 RSS KB", lambda rs: f(med(rs, "rss_hold_kb"), 0)),
    ("KB/连接", lambda rs: f(med(rs, "kb_per_conn"), 2)),
    ("线程数", lambda rs: f(med(rs, "fwd_threads"), 0)),
])
