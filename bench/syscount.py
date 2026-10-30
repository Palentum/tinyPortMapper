#!/usr/bin/env python3
"""syscall 计数汇总（P0.3）：读取 syscount.sh / prof.sh stat 阶段的原始数据，换算为每单位 syscall 次数。

"不含等待" = 总计减去 epoll_pwait 与 poll/select：等待类调用次数随负载变化，其余都是结构性次数，适合做回归门槛。
单位：rr = 每个请求/响应对（tcp_rr、udp_rr 都取客户端报告的 ops），crr = 每个连接，udp = 转发器发出的每个包
（fwd 上 /proc/net/snmp 的 OutDatagrams 增量，发送方与转发器同机且同一网络命名空间时再减去发送方的发包数；发送方正向为客户端，
_r 为后端），bw = 每 GB（iperf3 服务端收到的 1e9 字节；tcp_bulk 为 fwdbench bulk 发出、sink 核对过的字节）。
udp 有 <前缀>.stat.stats.txt（被测的是 tinymapper，lib.sh 的 count_phase 在 perf 窗口前后各取一次 SIGUSR1 统计）时单位改用
up_pkts+down_pkts 的增量：tinymapper 按数据报计，而 GSO 一次发出多个数据报时 OutDatagrams 只加 1（udp_send_skb）；
OutDatagrams 的换算仍记在 JSON 的 snmp_units 里，两者相差超过 0.5% 时在明细里注明。
tcp_bw / tcp_bulk 有统计（B2 起 tcp 行含 up_splice）时 JSON 另记 splice_pct（splice 写出的字节占 up_bytes+down_bytes 增量的 %）与
splice_fallback（增量），明细里注明。

用法：python3 -I bench/syscount.py <目录> [--json <输出.json>]   # markdown 表格打印到标准输出
JSON 每个 (转发器, 负载) 一行、键序固定，便于 diff。
"""
import json
import sys
from pathlib import Path

GROUPS = [
    ("recv*", ["recvfrom", "recvmmsg", "recvmsg", "read"]),
    ("send*", ["sendto", "sendmmsg", "sendmsg", "write"]),
    ("splice", ["splice"]),
    ("epoll_pwait", ["epoll_pwait", "epoll_wait", "epoll_pwait2"]),
    ("poll/select", ["poll", "ppoll", "select", "pselect6"]),
    ("epoll_ctl", ["epoll_ctl"]),
    ("accept*", ["accept", "accept4"]),
    ("connect", ["connect"]),
    ("socket", ["socket"]),
    ("set/getsockopt", ["setsockopt", "getsockopt"]),
    ("fcntl", ["fcntl"]),
    ("close", ["close"]),
    ("shutdown", ["shutdown"]),
    ("pipe2", ["pipe2"]),
]


def load_stat(p):
    ev = {}
    for line in p.read_text().splitlines():
        f = line.split(",")
        if line.startswith("#") or len(f) < 3:
            continue
        try:
            ev[f[2]] = float(f[0])
        except ValueError:
            ev[f[2]] = None
    return ev


def snmp(p):
    """返回 (前后两次 Udp 计数, {"cli": 客户端是否与转发器同机, "srv": 后端是否与转发器同机})；旧数据没有标记行，按同机处理。"""
    text = p.read_text()
    rows = [l.split()[1:] for l in text.splitlines() if l.startswith("Udp:")]
    pairs = [dict(zip(rows[i], map(int, rows[i + 1]))) for i in range(0, len(rows), 2)]
    return pairs, {r: f"# {r}_on_fwd=0" not in text for r in ("cli", "srv")}


def tm_pkts(p):
    """tinymapper SIGUSR1 统计前后两行的 up_pkts+down_pkts 增量；文件缺失或不足两行时返回 None。"""
    if not p.exists():
        return None
    rows = [dict(kv.split("=", 1) for kv in l.split() if "=" in kv) for l in p.read_text().splitlines() if "up_pkts=" in l]
    if len(rows) < 2:
        return None
    return sum(int(rows[-1][k]) - int(rows[0][k]) for k in ("up_pkts", "down_pkts"))


def tm_splice(p):
    """统计前后两次 tcp 行的增量：splice 写出的字节占比与回退次数；没有文件、不足两行或没有 up_splice（B2 以前）时返回 {}。"""
    if not p.exists():
        return {}
    rows = [dict(kv.split("=", 1) for kv in l.split() if "=" in kv) for l in p.read_text().splitlines() if l.startswith("tcp ")]
    if len(rows) < 2 or "up_splice" not in rows[-1]:
        return {}
    d = lambda k: int(rows[-1][k]) - int(rows[0][k])
    b = d("up_bytes") + d("down_bytes")
    return {"splice_pct": round(100 * (d("up_splice") + d("down_splice")) / b, 2) if b else None, "splice_fallback": d("splice_fallback")}


def per_unit(pre, wl, phase="stat"):
    """返回 (单位数, 单位名, 吞吐, 附加字段)。"""
    c = json.loads(Path(f"{pre}.{phase}.client.json").read_text())
    if wl.startswith(("tcp_rr", "tcp_crr", "udp_rr")):
        return c["ops"], "conn" if wl.startswith("tcp_crr") else "op", c["ops_per_sec"], {}
    if wl.startswith("udp"):
        (b, a), same = snmp(Path(f"{pre}.{phase}.snmp.txt"))
        sender = "srv" if wl.endswith("_r") else "cli"
        n = a["OutDatagrams"] - b["OutDatagrams"] - (c["sent_pkts"] if same[sender] else 0)
        tm = tm_pkts(Path(f"{pre}.{phase}.stats.txt"))
        if tm:
            return tm, "pkt", c["recv_kpps"] * 1e3, {"units_src": "tm_stats", "snmp_units": n}
        return n, "pkt", c["recv_kpps"] * 1e3, {}
    return c["bytes"] / 1e9, "GB", c["gbps"], {}


def analyze(d, fwd, wl):
    pre = d / f"{fwd}.{wl}"
    ev = load_stat(Path(f"{pre}.stat.csv"))
    if not ev.get("raw_syscalls:sys_enter"):
        return None
    n, unit, rate, extra = per_unit(pre, wl)
    enter = {k.split("sys_enter_")[1]: v for k, v in ev.items() if "sys_enter_" in k and v}
    fails = {k.split("sys_exit_")[1]: v for k, v in ev.items() if "sys_exit_" in k and v}
    used = {x for _, names in GROUPS for x in names}
    other = {k: v for k, v in enter.items() if k not in used}
    r = lambda x: round(x / n, 4)
    groups = {g: r(sum(enter.get(x, 0) for x in names)) for g, names in GROUPS}
    return {
        "fwd": fwd, "workload": wl, "unit": unit, "units": round(n, 3), "rate": round(rate, 1),
        "total": r(ev["raw_syscalls:sys_enter"]),
        "nowait": round(r(ev["raw_syscalls:sys_enter"]) - groups["epoll_pwait"] - groups["poll/select"], 4),
        "groups": groups,
        "other": r(sum(other.values())), "other_detail": {k: r(v) for k, v in sorted(other.items())},
        "fail": r(sum(fails.values())), "fail_detail": {k: r(v) for k, v in sorted(fails.items())},
        "ctx_sw": round(ev["context-switches"] / n, 5),
        **extra,
        **(tm_splice(Path(f"{pre}.stat.stats.txt")) if wl.startswith("tcp") else {}),
    }


def fmt(x, nd=3):
    if x == 0:
        return "0"
    if abs(x) >= 100:
        return f"{x:,.0f}"
    return f"{x:.{nd}f}"


def main():
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    d = Path(args[0])
    # 按文件修改时间排序，即与采集顺序一致（转发器在外层、负载在内层）
    files = sorted(d.glob("*.stat.csv"), key=lambda p: p.stat().st_mtime)
    names = [p.name[: -len(".stat.csv")] for p in files]
    runs = [analyze(d, *n.rsplit(".", 1)) for n in names]
    bad = [n for n, x in zip(names, runs) if x is None]
    runs = [x for x in runs if x]

    hdr = ["fwd", "workload", "单位", "单位数", "吞吐", "**总计/单位**", "不含等待/单位"] + [g for g, _ in GROUPS] + ["其他", "ret<0/单位", "ctx-sw/单位"]
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for x in runs:
        rate = f"{x['rate']:.1f} Gbit/s" if x["unit"] == "GB" else f"{x['rate']:,.0f}"
        cells = [x["fwd"], x["workload"], x["unit"], fmt(x["units"], 2), rate, f"**{fmt(x['total'])}**", fmt(x["nowait"])]
        cells += [fmt(x["groups"][g]) for g, _ in GROUPS] + [fmt(x["other"]), fmt(x["fail"]), f"{x['ctx_sw']:.5f}"]
        print("| " + " | ".join(cells) + " |")
    print()
    for x in runs:
        detail = ", ".join(f"{k}={v:.3f}" for k, v in x["fail_detail"].items()) or "无"
        other = ", ".join(f"{k}={v:.4f}" for k, v in x["other_detail"].items())
        units = ""
        if x.get("units_src") == "tm_stats" and abs(x["snmp_units"] - x["units"]) > 0.005 * x["units"]:
            units = f"；单位取 SIGUSR1 统计 {x['units']:,.0f} 个数据报，OutDatagrams 增量 {x['snmp_units']:,.0f}（GSO 每次发送只计 1）"
        if x.get("splice_pct") is not None:
            units += f"；splice 写出 {fmt(x['splice_pct'], 2)}% 字节，回退 {x['splice_fallback']} 次"
        print(f"- `{x['fwd']}.{x['workload']}`：失败返回明细 {detail}" + (f"；其他 syscall：{other}" if other else "") + units)
    for n in bad:
        print(f"- `{n}`：没有有效的 perf 计数（见转发器主机上的 perf-stat.log）")

    if out_json:
        with open(out_json, "w") as f:
            f.write('{"runs": [\n' + ",\n".join(json.dumps(x, ensure_ascii=False) for x in runs) + "\n]}\n")


if __name__ == "__main__":
    main()
