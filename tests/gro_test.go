// U5（D41–D43）：--udp-gro 的功能测试。
//
// 给了 --udp-gro 时 UDP 监听 socket 与会话 socket 都开 UDP_GRO；收到的 GRO 合并包（带 UDP_GRO cmsg）整包带同样段长的 UDP_SEGMENT
// cmsg 发出：入向发往会话 socket，回程从规则的监听 socket 发给客户端；多于 64 段的拆成每次至多 64 段，只剩 1 段的不带 cmsg；普通
// 数据报照旧。GSO 发送返回 EIO/EINVAL/EMSGSIZE 时那个 socket 此后不再用 GSO（会话 socket 只影响该会话，监听 socket 影响该规则全部
// 回程），计数 up_gso_fallback/down_gso_fallback 加一、记一行 info，这个包按段逐个重发；其他错误（ECONNREFUSED 等）不关 GSO、
// 不计回退，这个包再发一次（实现按至多 64 段一块重发，仍失败就按数据报计入丢包）；EAGAIN 丢掉该组剩下的包。pkts/bytes/drop 始终
// 按数据报计，up_gro/down_gro 为以合并包形式收到的数据报数，这四项只在 --udp-gro 时出现在统计行末尾。
//
// loopback 上的做法（D43）：客户端或后端经 lo 用 UDP_SEGMENT 发出，开了 UDP_GRO 的 socket 原样收到整个 GSO 包，与网卡 GRO 聚合出的
// 合并包相同；lo 不聚合普通数据报。接收端不开 UDP_GRO 时逐个数据报核对内容与边界，开时核对消息与段长（证明 tinymapper 真的用了 GSO）。
// tun 设备没有 TX 校验和 offload，6.11 以前经它出去的 GSO 发送返回 EIO、段长超过 MTU 时返回 EMSGSIZE（这个内核；原版 ≤6.13 为
// EINVAL），用来走回退路径。
package tests

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// gsoSpec 是 {字节数, 段长}，段长 0 为普通数据报
type gsoSpec [2]int

// gsoPktsOf 按 specs 生成一串发送，内容随 seed 与下标变化；reverse 时倒序（第二轮让各槽换一种包：上一轮收普通数据报的槽这轮收合并包，
// 收包前没把内核改写的 msg_controllen 恢复时 cmsg 放不下、合并包被当成一个大数据报）
func gsoPktsOf(specs []gsoSpec, seed int, reverse bool) []gsoPkt {
	out := make([]gsoPkt, len(specs))
	for j, s := range specs {
		out[j] = gsoPkt{gsoData(seed*100+j, s[0]), s[1]}
	}
	if reverse {
		slices.Reverse(out)
	}
	return out
}

// interleaveGSO 按轮转交错各客户端的发送：第 j 轮依次取每个客户端的第 j 个（已发完的跳过）
func interleaveGSO(lists [][]gsoPkt, send func(client int, p gsoPkt)) {
	for j := 0; ; j++ {
		more := false
		for i, l := range lists {
			if j < len(l) {
				send(i, l[j])
				more = true
			}
		}
		if !more {
			return
		}
	}
}

// expectNoWarn 要求日志里没有 warn（统计输出时已 fflush）
func expectNoWarn(t testing.TB, m *mapper) {
	t.Helper()
	data, _ := os.ReadFile(m.logPath)
	var warns []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.Contains(l, "[WARN]") {
			warns = append(warns, l)
		}
	}
	if len(warns) != 0 {
		t.Errorf("日志里有 %d 行 warn，期望没有，前几行：\n%s", len(warns), strings.Join(warns[:min(len(warns), 3)], "\n"))
	}
}

// gsoFallbackLines 返回日志里 kind（"session" 入向或 "listen" 回程）的 GSO 回退行
func gsoFallbackLines(m *mapper, kind string) []string {
	data, _ := os.ReadFile(m.logPath)
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.Contains(l, "[udp]GSO send ") && strings.Contains(l, "} on "+kind+" fd ") {
			out = append(out, l)
		}
	}
	return out
}

// GSO 回退行（审查 L3）：[udp]GSO send from|to {客户端} on session|listen fd N failed (errno:strerror), ...。get_sock_error() 写
// "errno:strerror"，按 errno 比较（musl 与 glibc 的 strerror 措辞不同，如 EIO 为 "I/O error"）
var gsoFallbackRE = regexp.MustCompile(`\[(INFO|DEBUG)\]\[udp\]GSO send (from|to) \{([^}]*)\} on (session|listen) fd (\d+) failed \((\d+):[^)]*\), sending its GRO packets datagram by datagram from now on$`)

// expectGSOFallbackLines 等到日志里 kind 的 GSO 回退行与 clients（各会话的客户端地址，按回退的先后）一一对应：每条规则每个方向只有
// 第一次是 info，之后的会话是 debug（审查 L3，要 --log-level 5 才看得到），入向写 from、回程写 to，errno 是 errs 之一
func expectGSOFallbackLines(t testing.TB, m *mapper, kind string, clients []string, errs ...syscall.Errno) {
	t.Helper()
	var lines []string
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if lines = gsoFallbackLines(m, kind); len(lines) < len(clients) {
			return fmt.Errorf("日志里有 %d 行 %s socket 的 GSO 回退，期望 %d", len(lines), kind, len(clients))
		}
		return nil
	})
	if len(lines) != len(clients) {
		t.Errorf("日志里有 %d 行 %s socket 的 GSO 回退，期望 %d（每个会话只在第一次失败时记一行）：\n%s", len(lines), kind, len(clients), strings.Join(lines, "\n"))
	}
	for i, l := range lines {
		sm := gsoFallbackRE.FindStringSubmatch(l)
		if sm == nil {
			t.Errorf("GSO 回退行格式不符：%q", l)
			continue
		}
		level, dir := map[bool]string{true: "INFO", false: "DEBUG"}[i == 0], map[string]string{"session": "from", "listen": "to"}[kind]
		if sm[1] != level || sm[2] != dir {
			t.Errorf("第 %d 行 GSO 回退为 [%s] %s，期望 [%s] %s（每条规则每个方向只有第一次写 info）：%q", i+1, sm[1], sm[2], level, dir, l)
		}
		if i < len(clients) && sm[3] != clients[i] {
			t.Errorf("第 %d 行 GSO 回退的客户端为 %s，期望 %s：%q", i+1, sm[3], clients[i], l)
		}
		if !slices.ContainsFunc(errs, func(e syscall.Errno) bool { return fmt.Sprint(int(e)) == sm[6] }) {
			t.Errorf("GSO 回退行的 errno 为 %s，期望 %v 之一：%q", sm[6], errs, l)
		}
	}
}

// 用例前提：内核与测试设施的行为与探针一致（build/u5/probe/）。lo 上的 GSO 发送到开了 UDP_GRO 的 socket 整包收到、带 int 段长，
// 普通 socket 收到切开的数据报；单段的 GSO 发送收到的是普通数据报；129 段 EINVAL（内核上限 128，这个内核已回移）。tun 上 GSO 发送
// EIO（单段也是），段长超过 MTU 时 EMSGSIZE（原版 ≤6.13 为 EINVAL），普通包超过 MTU 时分片、重组后与原包相同；写进 tun 的自造包
// 送到本机 socket，源地址为 tun 子网里的对端
func TestUDPGROKernel(t *testing.T) {
	t.Parallel()
	t.Run("lo", func(t *testing.T) {
		t.Parallel()
		gro := newGRORecorder(t, loopback4(t), true)
		plain := newGRORecorder(t, loopback4(t), false)
		p := gsoPkt{gsoData(1, 14500), 1400}
		single := gsoPkt{gsoData(2, 700), 1400}
		for _, be := range []*groRecorder{gro, plain} {
			c := udpDial(t, "", be.addr)
			for _, q := range []gsoPkt{p, single} {
				if err := sendGSO(c, nil, q.data, q.gso); err != nil {
					t.Fatalf("GSO 发送 %d 字节（gso %d）失败：%v", len(q.data), q.gso, err)
				}
			}
		}
		expectMsgsBySource(t, gro.msgsBySource(t, 12), [][]groMsg{{{p.data, 1400}, {single.data, 0}}})
		got, _, _ := plain.bySource(t, 12)
		expectBySource(t, got, [][][]byte{append(p.segs(), single.data)})
		c := udpDial(t, "", gro.addr)
		if err := sendGSO(c, nil, make([]byte, 129*100), 100); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("129 段的 GSO 发送返回 %v，期望 EINVAL", err)
		}
	})
	t.Run("tun", func(t *testing.T) {
		t.Parallel()
		d := newTun(t, 1500)
		c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.peer(2), 9)))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := sendGSO(c, nil, make([]byte, 5000), 1000); !errors.Is(err, syscall.EIO) {
			t.Errorf("经 tun 的 5×1000 GSO 发送返回 %v，期望 EIO（6.11 以前没有校验和 offload 的出口）", err)
		}
		if err := sendGSO(c, nil, make([]byte, 1000), 1000); !errors.Is(err, syscall.EIO) {
			t.Errorf("经 tun 的单段 GSO 发送返回 %v，期望 EIO", err)
		}
		want := gsoData(3, 1000)
		if err := sendGSO(c, nil, want, 0); err != nil {
			t.Fatal(err)
		}
		dg, _ := d.datagrams(t, 1)
		if !bytes.Equal(dg[0].data, want) || dg[0].dst != netip.AddrPortFrom(d.peer(2), 9) || dg[0].src.Addr() != d.local {
			t.Errorf("tun 上收到 %s → %s 的 %d 字节，期望 %s → %s:9 的 1000 字节原样", dg[0].src, dg[0].dst, len(dg[0].data), d.local, d.peer(2))
		}
		// 自造包写进 tun，本机 socket 收到
		ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: d.local.AsSlice()})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		src := netip.AddrPortFrom(d.peer(7), 40007)
		in := gsoData(4, 1200)
		d.writeUDP(t, src, netip.MustParseAddrPort(ln.LocalAddr().String()), in)
		ln.SetReadDeadline(time.Now().Add(ioTimeout))
		buf := make([]byte, 2000)
		n, from, err := ln.ReadFromUDPAddrPort(buf)
		if err != nil || !bytes.Equal(buf[:n], in) || from != src {
			t.Errorf("写进 tun 的包：收到 %d 字节来自 %s（%v），期望 1200 字节来自 %s", n, from, err, src)
		}
	})
	t.Run("tun-mtu", func(t *testing.T) {
		t.Parallel()
		d := newTun(t, 1280)
		c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.peer(2), 9)))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := sendGSO(c, nil, make([]byte, 4200), 1400); !errors.Is(err, syscall.EMSGSIZE) && !errors.Is(err, syscall.EINVAL) {
			t.Errorf("段长 1400 > MTU 1280 的 GSO 发送返回 %v，期望 EMSGSIZE（6.14 起与这个内核）或 EINVAL", err)
		}
		want := gsoData(5, 1400)
		if err := sendGSO(c, nil, want, 0); err != nil {
			t.Fatal(err)
		}
		dg, frags := d.datagrams(t, 1)
		if !bytes.Equal(dg[0].data, want) || dg[0].frags != 2 || frags != 2 {
			t.Errorf("tun 上重组出 %d 字节（%d 个分片，共收到 %d 个分片），期望 1400 字节原样、2 个分片", len(dg[0].data), dg[0].frags, frags)
		}
	})
}

// 入向每个客户端一轮的发送（D41；单个合并包都不超过 64400 字节，见 gsoPkt.merged）：
//   - 0：10×1400+500；0 字节；64×1000（恰好一次 GSO 的上限）；1472
//   - 1：100×100（拆成 64+36）；1 字节；5×2000（段长接近 2 KiB 的槽）；9000；65×100（拆成 64 段加 1 段，最后一组不带 cmsg）
//   - 2：4×3000+1000（第一段跨过槽边界，之后各段都在溢出区）；300；2×2048+100（段边界恰好在槽边界）；单段的 GSO 700/1400（收到的
//     是普通数据报）；65507；3×700（第 3 段 1400–2099 跨过槽边界）
var groInboundMix = [][]gsoSpec{
	{{14500, 1400}, {0, 0}, {64000, 1000}, {1472, 0}},
	{{10000, 100}, {1, 0}, {10000, 2000}, {9000, 0}, {6500, 100}},
	{{13000, 3000}, {300, 0}, {4196, 2048}, {700, 1400}, {65507, 0}, {2100, 700}},
}

// U5：入向的 GRO 合并包与普通数据报混在一批里。暂停期间 3 个客户端按轮转交错排好 groInboundMix（15 个条目，一次 recvmmsg），恢复后
// 一起转发；第二轮各客户端倒序再来一次（槽位换成另一种包）。plain-backend 的后端不开 UDP_GRO：按源地址逐个数据报核对内容、边界与
// 顺序；gro-backend 的后端开 UDP_GRO：每个合并包必须以同样的段长整包到达（100 段的为 64+36，65 段的为 64 段加 1 个普通数据报），
// 证明 tinymapper 用了 GSO。up_pkts/up_bytes 按数据报精确，up_gro 为合并包里的数据报数，没有回退、丢包与 warn
func TestUDPGROInbound(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name       string
		groBackend bool
	}{{"plain-backend", false}, {"gro-backend", true}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := newGRORecorder(t, loopback4(t), c.groBackend)
			listen := loopback4(t)
			m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u", "--udp-gro")
			conns := make([]*net.UDPConn, len(groInboundMix))
			for i := range conns {
				conns[i] = udpDial(t, "", listen)
			}
			all := make([][]gsoPkt, len(conns))
			for round := range 2 {
				cur := make([][]gsoPkt, len(conns))
				for i := range conns {
					cur[i] = gsoPktsOf(groInboundMix[i], i*10+round, round == 1)
					all[i] = append(all[i], cur[i]...)
				}
				var sends []gsoSend
				interleaveGSO(cur, func(i int, p gsoPkt) { sends = append(sends, gsoSend{conns[i], nil, p}) })
				m.pause(t)
				queueGSO(t, m, listen, sends)
				m.resume(t)
				n, _, _ := gsoTotals(all...)
				if c.groBackend {
					want := make([][]groMsg, len(all))
					for i := range all {
						want[i] = pktsForwarded(all[i])
					}
					expectMsgsBySource(t, be.msgsBySource(t, int(n)), want)
				} else {
					want := make([][][]byte, len(all))
					for i := range all {
						want[i] = pktsSegs(all[i])
					}
					got, _, _ := be.bySource(t, int(n))
					expectBySource(t, got, want)
				}
				if t.Failed() {
					t.FailNow()
				}
			}
			n, nbytes, merged := gsoTotals(all...)
			s := m.statsAfterSignal(t).udp[1]
			if s.upPkts != n || s.upBytes != nbytes || s.upGRO != merged || s.upDrop != 0 || s.upGSOFallback != 0 {
				t.Errorf("统计 up_pkts=%d up_bytes=%d up_gro=%d up_drop=%d up_gso_fallback=%d，期望 %d/%d/%d/0/0",
					s.upPkts, s.upBytes, s.upGRO, s.upDrop, s.upGSOFallback, n, nbytes, merged)
			}
			if s.sessions != len(conns) || s.downPkts != 0 || s.downGRO != 0 || s.downGSOFallback != 0 {
				t.Errorf("统计 sessions=%d down_pkts=%d down_gro=%d down_gso_fallback=%d，期望 %d/0/0/0", s.sessions, s.downPkts, s.downGRO, s.downGSOFallback, len(conns))
			}
			expectNoWarn(t, m)
		})
	}
}

// 回程每个会话一轮的回包：合并包（含 65 段拆成 64+1、跨槽边界的段长 700/2048/3000）、0 字节与 1472 字节的普通数据报、单段 GSO
var groReturnMix = []gsoSpec{{14500, 1400}, {0, 0}, {30000, 1000}, {1472, 0}, {6500, 100}, {2100, 700}, {700, 1400}, {4196, 2048}, {13000, 3000}}

// U5：回程的合并包。两条 UDP 规则（配置文件 + 命令行 --udp-gro），规则 1 三个客户端、规则 2 两个，每条规则各有一个开了 UDP_GRO 的
// 客户端。暂停期间后端把回包（GSO 发送，会话 socket 开着 UDP_GRO 时整包入队）按轮转交错排进 5 个会话 socket（45 个条目，一次发出），
// 恢复后同一轮里收进回程批、按规则从各自的监听 socket 发出；第二轮倒序再来一次。普通客户端逐个数据报核对，GRO 客户端核对消息与段长
// （证明监听 socket 用了 GSO、目的地址与段长对得上）且都来自本规则的监听地址。每条规则的 down_pkts/down_bytes/down_gro 精确，没有回退
func TestUDPGROReturn(t *testing.T) {
	t.Parallel()
	type client struct {
		rule    int
		plain   *net.UDPConn
		gro     *groClient
		session string
		want    []gsoPkt
	}
	listens := []string{loopback4(t), loopback4(t)}
	bes := []*groRecorder{newGRORecorder(t, loopback4(t), false), newGRORecorder(t, loopback4(t), false)}
	var cfg strings.Builder
	var wait []listenPoint
	for r := range listens {
		fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", listens[r], bes[r].addr)
		wait = append(wait, listenPoints("u", portOf(listens[r]))...)
	}
	m := startMapper(t, wait, "-c", writeConfig(t, cfg.String()), "--udp-gro")
	var clients []*client
	for ci, spec := range []struct {
		rule int
		gro  bool
	}{{0, false}, {1, true}, {0, true}, {1, false}, {0, false}} {
		cl := &client{rule: spec.rule}
		hello := fmt.Appendf(nil, "hello-%d", ci)
		if spec.gro {
			cl.gro = newGROClient(t, "127.0.0.1", listens[spec.rule])
			cl.session = helloGRO(t, bes[spec.rule], hello, func(b []byte) error { return cl.gro.send(gsoPkt{b, 0}) })
		} else {
			cl.plain = udpDial(t, "", listens[spec.rule])
			forceRcvBuf(cl.plain) // 回程的 GSO 包在普通客户端 socket 上被切开入队
			cl.session = helloGRO(t, bes[spec.rule], hello, func(b []byte) error { _, err := cl.plain.Write(b); return err })
		}
		clients = append(clients, cl)
	}
	for round := range 2 {
		cur := make([][]gsoPkt, len(clients))
		for ci, cl := range clients {
			specs := slices.Clone(groReturnMix)
			r := ci % len(specs)
			specs = append(specs[r:], specs[:r]...)
			cur[ci] = gsoPktsOf(specs, 50+ci*10+round, round == 1)
			cl.want = append(cl.want, cur[ci]...)
		}
		var replies []gsoReply
		interleaveGSO(cur, func(ci int, p gsoPkt) {
			replies = append(replies, gsoReply{bes[clients[ci].rule], clients[ci].session, p})
		})
		m.pause(t)
		queueGSOReplies(t, m, replies)
		m.resume(t)
		for ci, cl := range clients {
			who := fmt.Sprintf("第 %d 轮规则 %d 的客户端 %d ", round+1, cl.rule+1, ci)
			if cl.gro != nil {
				cl.gro.expect(t, pktsForwarded(cur[ci]), who)
			} else {
				expectReplies(t, cl.plain, pktsSegs(cur[ci]), who)
			}
		}
	}
	d := m.statsAfterSignal(t)
	for r := range listens {
		var want []gsoPkt
		for _, cl := range clients {
			if cl.rule == r {
				want = append(want, cl.want...)
			}
		}
		n, nbytes, merged := gsoTotals(want)
		s := d.udp[r+1]
		if s.downPkts != n || s.downBytes != nbytes || s.downGRO != merged || s.downDrop != 0 || s.downGSOFallback != 0 {
			t.Errorf("规则 %d 统计 down_pkts=%d down_bytes=%d down_gro=%d down_drop=%d down_gso_fallback=%d，期望 %d/%d/%d/0/0",
				r+1, s.downPkts, s.downBytes, s.downGRO, s.downDrop, s.downGSOFallback, n, nbytes, merged)
		}
		if s.upPkts != uint64(bes[r].count()) || s.upGRO != 0 || s.upGSOFallback != 0 {
			t.Errorf("规则 %d 统计 up_pkts=%d up_gro=%d up_gso_fallback=%d，期望 %d/0/0（hello）", r+1, s.upPkts, s.upGRO, s.upGSOFallback, bes[r].count())
		}
	}
	expectNoWarn(t, m)
	m.expectIdleCPU(t, "GRO 回程批发出之后")
}

// U5：入向与回程的合并包在同一轮循环里（同 TestUDPReturnWithInbound 的两种回调顺序，由 trace 行确认）。收 cmsg 的控制缓冲按槽号
// 由入向与回程共用，入向收包前先发出回程批；两个方向用不同的段长，哪个包用错了别的槽的段长，切出的数据报边界就不对。客户端与后端都不开
// UDP_GRO，逐个数据报核对两个方向的内容与边界；计数精确
func TestUDPGROReturnWithInbound(t *testing.T) {
	t.Parallel()
	upMix := []gsoSpec{{5001, 1000}, {64, 0}, {9000, 3000}, {2049, 0}, {2100, 300}}
	downMix := []gsoSpec{{2047, 0}, {6007, 1500}, {0, 0}, {12000, 2000}, {1107, 123}}
	for _, c := range []struct {
		name          string
		listenerFirst bool
	}{{"sessions-cb-first", true}, {"listener-cb-first", false}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			const n = 3
			be := newGRORecorder(t, loopback4(t), false)
			listen := loopback4(t)
			m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u", "--udp-gro", "--log-level", "6")
			conns := make([]*net.UDPConn, n)
			sessions := make([]string, n)
			for i := range conns {
				conns[i] = udpDial(t, "", listen)
				forceRcvBuf(conns[i])
				sessions[i] = helloGRO(t, be, fmt.Appendf(nil, "hello-%d", i), func(b []byte) error { _, err := conns[i].Write(b); return err })
			}
			up, down := make([][]gsoPkt, n), make([][]gsoPkt, n)
			for i := range n {
				r := i % len(upMix)
				up[i] = gsoPktsOf(append(slices.Clone(upMix[r:]), upMix[:r]...), 10+i, false)
				down[i] = gsoPktsOf(append(slices.Clone(downMix[r:]), downMix[:r]...), 20+i, false)
			}
			var sends []gsoSend
			interleaveGSO(up, func(i int, p gsoPkt) { sends = append(sends, gsoSend{conns[i], nil, p}) })
			var replies []gsoReply
			interleaveGSO(down, func(i int, p gsoPkt) { replies = append(replies, gsoReply{be, sessions[i], p}) })
			hellos := be.count()
			eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
				if got := len(recvTraces(m)); got < hellos {
					return fmt.Errorf("日志里有 %d 行收包 trace，期望至少 %d（hello）", got, hellos)
				}
				return nil
			})
			time.Sleep(500 * time.Millisecond)
			before := len(recvTraces(m))
			m.pause(t)
			if c.listenerFirst {
				queueGSO(t, m, listen, sends)
				queueGSOReplies(t, m, replies)
			} else {
				queueGSOReplies(t, m, replies)
				queueGSO(t, m, listen, sends)
			}
			m.resume(t)

			for i, cn := range conns {
				expectReplies(t, cn, pktsSegs(down[i]), fmt.Sprintf("客户端 %d ", i))
			}
			upN, upBytes, upMerged := gsoTotals(up...)
			got, _, _ := be.bySource(t, hellos+int(upN))
			for src, g := range got {
				got[src] = slices.DeleteFunc(g, func(p []byte) bool { return bytes.HasPrefix(p, []byte("hello-")) })
			}
			want := make([][][]byte, n)
			for i := range n {
				want[i] = pktsSegs(up[i])
			}
			srcs := expectBySource(t, got, want)
			for i := range n {
				if srcs[i] != "" && srcs[i] != sessions[i] {
					t.Errorf("客户端 %d 的入向包来自源地址 %s，hello 来自 %s：没有命中既有会话", i, srcs[i], sessions[i])
				}
			}
			downN, downBytes, downMerged := gsoTotals(down...)
			s := m.statsAfterSignal(t).udp[1]
			if s.upPkts != upN+uint64(hellos) || s.upBytes != upBytes+uint64(n*len("hello-0")) || s.upGRO != upMerged || s.upDrop != 0 {
				t.Errorf("统计 up_pkts=%d up_bytes=%d up_gro=%d up_drop=%d，期望 %d/%d/%d/0", s.upPkts, s.upBytes, s.upGRO, s.upDrop,
					upN+uint64(hellos), upBytes+uint64(n*len("hello-0")), upMerged)
			}
			if s.downPkts != downN || s.downBytes != downBytes || s.downGRO != downMerged || s.downDrop != 0 || s.upGSOFallback != 0 || s.downGSOFallback != 0 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_gro=%d down_drop=%d up/down_gso_fallback=%d/%d，期望 %d/%d/%d/0/0/0",
					s.downPkts, s.downBytes, s.downGRO, s.downDrop, s.upGSOFallback, s.downGSOFallback, downN, downBytes, downMerged)
			}
			// 用例前提：这一轮里先收包的一方（每个 recvmmsg 条目一行 trace）
			var traces []string
			eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
				if traces = recvTraces(m); len(traces) < before+len(sends)+len(replies) {
					return fmt.Errorf("日志里恢复后有 %d 行收包 trace，期望 %d", len(traces)-before, len(sends)+len(replies))
				}
				return nil
			})
			first := traces[before]
			t.Logf("恢复后第一行收包 trace：%s", first)
			if strings.Contains(first, "received data from udp fd") != c.listenerFirst {
				t.Errorf("恢复后第一行收包 trace 为 %q：用例前提不成立（期望先回调%s）", first, map[bool]string{true: "会话", false: "监听"}[c.listenerFirst])
			}
		})
	}
}

// U5：各地址族。ipv6、dualstack（[::] 监听同批收到 v4 映射与 IPv6 客户端的合并包，回程经 AF_INET6 监听 socket 向 v4 映射地址发 GSO）、
// 4to6、6to4（段长原样跨族转发）。客户端与后端都开 UDP_GRO：入向一批（暂停期间排队）由后端核对消息与段长，回程一批（暂停期间排进
// 会话 socket）由客户端核对；lo 的 MTU 为 65536，不应有回退。两个方向的 pkts/bytes/gro 精确
func TestUDPGROFamilies(t *testing.T) {
	t.Parallel()
	mix := []gsoSpec{{14500, 1400}, {1, 0}, {6500, 100}, {4196, 2048}, {1452, 0}, {3000, 1000}}
	for _, c := range []struct {
		name    string
		listen  string
		clients []string
		backend string
	}{
		{"ipv6", "::1", []string{"::1", "::1"}, "::1"},
		{"dualstack", "::", []string{"127.0.0.1", "::1"}, "127.0.0.1"},
		{"4to6", "127.0.0.1", []string{"127.0.0.1", "127.0.0.1"}, "::1"},
		{"6to4", "::1", []string{"::1", "::1"}, "127.0.0.1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := newGRORecorder(t, hostPort(c.backend, freePort(t)), true)
			lport := freePort(t)
			m := startMapper(t, listenPoints("u", lport), "-l", hostPort(c.listen, lport), "-r", be.addr, "-u", "--udp-gro")
			clients := make([]*groClient, len(c.clients))
			up, down := make([][]gsoPkt, len(clients)), make([][]gsoPkt, len(clients))
			for i, ip := range c.clients {
				clients[i] = newGROClient(t, ip, hostPort(ip, lport))
				up[i] = gsoPktsOf(mix, 10+i, i == 1)
				down[i] = gsoPktsOf(mix, 20+i, i == 0)
			}
			var sends []gsoSend
			interleaveGSO(up, func(i int, p gsoPkt) { sends = append(sends, gsoSend{clients[i].c, clients[i].listen, p}) })
			m.pause(t)
			queueGSO(t, m, hostPort(c.listen, lport), sends)
			m.resume(t)
			upN, upBytes, upMerged := gsoTotals(up...)
			want := make([][]groMsg, len(up))
			for i := range up {
				want[i] = pktsForwarded(up[i])
			}
			srcs := expectMsgsBySource(t, be.msgsBySource(t, int(upN)), want)
			if t.Failed() {
				t.FailNow()
			}
			var replies []gsoReply
			interleaveGSO(down, func(i int, p gsoPkt) { replies = append(replies, gsoReply{be, srcs[i], p}) })
			m.pause(t)
			queueGSOReplies(t, m, replies)
			m.resume(t)
			for i, cl := range clients {
				cl.expect(t, pktsForwarded(down[i]), fmt.Sprintf("客户端 %d（%s）", i, c.clients[i]))
			}
			downN, downBytes, downMerged := gsoTotals(down...)
			s := m.statsAfterSignal(t).udp[1]
			if s.upPkts != upN || s.upBytes != upBytes || s.upGRO != upMerged || s.downPkts != downN || s.downBytes != downBytes || s.downGRO != downMerged {
				t.Errorf("统计 up_pkts=%d up_bytes=%d up_gro=%d down_pkts=%d down_bytes=%d down_gro=%d，期望 %d/%d/%d/%d/%d/%d",
					s.upPkts, s.upBytes, s.upGRO, s.downPkts, s.downBytes, s.downGRO, upN, upBytes, upMerged, downN, downBytes, downMerged)
			}
			if s.upDrop != 0 || s.downDrop != 0 || s.upGSOFallback != 0 || s.downGSOFallback != 0 || s.sessions != len(clients) {
				t.Errorf("统计 up/down_drop=%d/%d up/down_gso_fallback=%d/%d sessions=%d，期望 0/0/0/0/%d", s.upDrop, s.downDrop, s.upGSOFallback, s.downGSOFallback, s.sessions, len(clients))
			}
			expectNoWarn(t, m)
		})
	}
}

// expectTunFlows 要求 tun 上的数据报按 key 分组后与 want 一一对应（每组内容、边界、顺序都相同），返回各组的键
func expectTunFlows(t testing.TB, got map[netip.AddrPort][][]byte, want [][][]byte, what string) []netip.AddrPort {
	t.Helper()
	keys := make([]netip.AddrPort, len(want))
	used := map[netip.AddrPort]bool{}
	ok := len(got) == len(want)
	if !ok {
		t.Errorf("tun 上看到 %d 个%s，期望 %d 个", len(got), what, len(want))
	}
	for i, w := range want {
		for k, g := range got {
			if !used[k] && slices.EqualFunc(g, w, bytes.Equal) {
				used[k], keys[i] = true, k
				break
			}
		}
		if !keys[i].IsValid() {
			ok = false
			t.Errorf("第 %d 组数据报（%s）没有原样、按序、完整地出现在 tun 上", i, describePkts(w))
		}
	}
	if !ok {
		for k, g := range got {
			t.Logf("tun 上 %s %s：%s", what, k, describePkts(g))
		}
	}
	return keys
}

// U5：GSO 发送 EIO 时回退（6.11 以前出口没有 TX 校验和 offload；tun 设备 MTU 9000，段长都不超过 MTU，失败的原因只有校验和）。
//
// up：上游地址在 tun 子网里（没人应答，用例读 tun）。两个客户端经 lo 发合并包：第一轮暂停期间交错排好（客户端 0 的组以合并包开头，
// sendmmsg 第一个条目就失败；客户端 1 的组以普通数据报开头，第一次 sendmmsg 发出 1 个后停在合并包上），段长 700/1000/1400/2048/3000，
// 回退重发时切出的段有的跨过 2 KiB 槽边界、有的整段在溢出区；第二轮不暂停逐个发，此时 GSO 已关，合并包直接逐个数据报发。tun 上每个会话
// 的数据报内容、边界、顺序都与逐个数据报发送相同，up_gso_fallback 为 2（每个会话恰好一次），没有丢包；日志（--log-level 5）里第一个
// 会话一行 info、第二个一行 debug（审查 L3），都带各自的客户端地址与 EIO。
//
// down：客户端在 tun 子网里（用例向 tun 写入自造的 UDP 包，tinymapper 监听 tun 的本端地址），后端在 lo 上用 GSO 回包。回程的回退按
// 客户端会话（D45）：客户端 1 的回包（暂停期间排好、一次发出）触发回退并逐个重发；之后客户端 2 的回包仍先试 GSO、同样失败回退一次。
// down_gso_fallback 为 2，监听 socket 一行 info、一行 debug
func TestUDPGROFallbackEIO(t *testing.T) {
	t.Parallel()
	eio := []syscall.Errno{syscall.EIO}
	t.Run("up", func(t *testing.T) {
		t.Parallel()
		d := newTun(t, 9000)
		remote := netip.AddrPortFrom(d.peer(2), 9)
		listen := loopback4(t)
		m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", remote.String(), "-u", "--udp-gro", "--log-level", "5")
		conns := []*net.UDPConn{udpDial(t, "", listen), udpDial(t, "", listen)}
		specs := [][]gsoSpec{
			{{5300, 1000}, {100, 0}, {9000, 3000}, {4101, 2048}, {2100, 700}, {14500, 1400}},
			{{100, 0}, {14500, 1400}, {2100, 700}, {4101, 2048}, {9000, 3000}, {5300, 1000}},
		}
		all := make([][]gsoPkt, len(conns))
		first := make([][]gsoPkt, len(conns))
		for i := range conns {
			first[i] = gsoPktsOf(specs[i], 10+i, false)
			all[i] = append(all[i], first[i]...)
		}
		var sends []gsoSend
		interleaveGSO(first, func(i int, p gsoPkt) { sends = append(sends, gsoSend{conns[i], nil, p}) })
		m.pause(t)
		queueGSO(t, m, listen, sends)
		m.resume(t)
		n1, _, _ := gsoTotals(all...)
		d.datagrams(t, int(n1))
		for i, c := range conns {
			for j, p := range gsoPktsOf([]gsoSpec{{7000, 1000}, {1000, 0}, {3500, 700}}, 20+i, false) {
				if err := sendGSO(c, nil, p.data, p.gso); err != nil {
					t.Fatalf("客户端 %d 第二轮第 %d 个包发送失败：%v", i, j, err)
				}
				all[i] = append(all[i], p)
				time.Sleep(20 * time.Millisecond) // 不暂停时逐个转发：每个包单独一批
			}
		}
		n, nbytes, merged := gsoTotals(all...)
		dg, frags := d.datagrams(t, int(n))
		want := make([][][]byte, len(all))
		for i := range all {
			want[i] = pktsSegs(all[i])
		}
		for _, k := range expectTunFlows(t, tunBySource(dg, remote.Port()), want, "会话源地址") {
			if k.IsValid() && k.Addr() != d.local {
				t.Errorf("会话的源地址 %s 不是 tun 的本端地址 %s", k, d.local)
			}
		}
		if frags != 0 {
			t.Errorf("tun 上有 %d 个 IP 分片，期望 0（MTU 9000）", frags)
		}
		s := m.statsAfterSignal(t).udp[1]
		if s.upGSOFallback != 2 || s.downGSOFallback != 0 {
			t.Errorf("统计 up_gso_fallback=%d down_gso_fallback=%d，期望 2/0（每个会话 socket 一次）", s.upGSOFallback, s.downGSOFallback)
		}
		if s.upPkts != n || s.upBytes != nbytes || s.upGRO != merged || s.upDrop != 0 {
			t.Errorf("统计 up_pkts=%d up_bytes=%d up_gro=%d up_drop=%d，期望 %d/%d/%d/0", s.upPkts, s.upBytes, s.upGRO, s.upDrop, n, nbytes, merged)
		}
		// 第一轮里客户端 0 的组先发（组按会话在批里首次出现的顺序），所以它先回退
		expectGSOFallbackLines(t, m, "session", []string{conns[0].LocalAddr().String(), conns[1].LocalAddr().String()}, eio...)
		expectGSOFallbackLines(t, m, "listen", nil)
	})
	t.Run("down", func(t *testing.T) {
		t.Parallel()
		d := newTun(t, 9000)
		be := newGRORecorder(t, loopback4(t), false)
		lport := freePort(t)
		listen := netip.AddrPortFrom(d.local, uint16(lport))
		m := startMapper(t, listenPoints("u", lport), "-l", listen.String(), "-r", be.addr, "-u", "--udp-gro", "--log-level", "5")
		clients := []netip.AddrPort{netip.AddrPortFrom(d.peer(2), 40001), netip.AddrPortFrom(d.peer(3), 40002)}
		hello := func(i int) string {
			return helloGRO(t, be, fmt.Appendf(nil, "hello-%d", i), func(b []byte) error { d.writeUDP(t, clients[i], listen, b); return nil })
		}
		specs := []gsoSpec{{14500, 1400}, {100, 0}, {9000, 3000}, {4101, 2048}, {2100, 700}, {5300, 1000}}
		down := [][]gsoPkt{gsoPktsOf(specs, 30, false), gsoPktsOf(specs, 31, true)}
		s1 := hello(0)
		var replies []gsoReply
		for _, p := range down[0] {
			replies = append(replies, gsoReply{be, s1, p})
		}
		m.pause(t)
		queueGSOReplies(t, m, replies)
		m.resume(t)
		n1, _, _ := gsoTotals(down[0])
		d.datagrams(t, int(n1))
		s2 := hello(1)
		for _, p := range down[1] {
			be.sendTo(t, s2, p)
		}
		n, nbytes, merged := gsoTotals(down...)
		dg, frags := d.datagrams(t, int(n))
		byDst := map[netip.AddrPort][][]byte{}
		for _, g := range dg {
			if g.src != listen {
				t.Errorf("tun 上有 %s → %s 的数据报，期望都来自监听地址 %s", g.src, g.dst, listen)
			}
			byDst[g.dst] = append(byDst[g.dst], g.data)
		}
		keys := expectTunFlows(t, byDst, [][][]byte{pktsSegs(down[0]), pktsSegs(down[1])}, "客户端")
		for i, k := range keys {
			if k.IsValid() && k != clients[i] {
				t.Errorf("客户端 %d 的回包发往 %s，期望 %s", i, k, clients[i])
			}
		}
		if frags != 0 {
			t.Errorf("tun 上有 %d 个 IP 分片，期望 0（MTU 9000）", frags)
		}
		s := m.statsAfterSignal(t).udp[1]
		if s.downGSOFallback != 2 || s.upGSOFallback != 0 {
			t.Errorf("统计 down_gso_fallback=%d up_gso_fallback=%d，期望 2/0（回程按客户端会话各回退一次，D45）", s.downGSOFallback, s.upGSOFallback)
		}
		if s.downPkts != n || s.downBytes != nbytes || s.downGRO != merged || s.downDrop != 0 {
			t.Errorf("统计 down_pkts=%d down_bytes=%d down_gro=%d down_drop=%d，期望 %d/%d/%d/0", s.downPkts, s.downBytes, s.downGRO, s.downDrop, n, nbytes, merged)
		}
		expectGSOFallbackLines(t, m, "listen", []string{clients[0].String(), clients[1].String()}, eio...)
		expectGSOFallbackLines(t, m, "session", nil)
	})
}

// expectFirstSessionCB 是用例前提：日志（--log-level 6）里第一行回程收包 trace（"[udp]received data from udp fd N"）属于客户端
// client 的会话，即这一轮里它的会话回调最先执行、它的回包排在回程批的最前面。会话 fd 取自 "[udp]new connection from {client},udp fd=N"
func expectFirstSessionCB(t testing.TB, m *mapper, client string) {
	t.Helper()
	var fd, first string
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		data, _ := os.ReadFile(m.logPath)
		if sm := regexp.MustCompile(`\[udp\]new connection from \{` + regexp.QuoteMeta(client) + `\},udp fd=(\d+),`).FindSubmatch(data); sm != nil {
			fd = string(sm[1])
		}
		if sm := regexp.MustCompile(`\[udp\]received data from udp fd (\d+),`).FindSubmatch(data); sm != nil {
			first = string(sm[1])
		}
		if fd == "" || first == "" {
			return fmt.Errorf("日志里还没有客户端 %s 的会话 fd（%q）或回程收包 trace（%q）", client, fd, first)
		}
		return nil
	})
	if first != fd {
		t.Errorf("第一行回程收包 trace 属于 fd %s，客户端 %s 的会话 fd 为 %s：用例前提不成立（期望它的回调最先执行）", first, client, fd)
	}
}

// U5（D45，审查 mix.sh 的场景）：回程的 GSO 回退只影响失败的那个客户端。规则 1 监听 0.0.0.0，客户端 A 在 tun 子网里，客户端 B 在 lo
// 上、开着 UDP_GRO；规则 2 监听 127.0.0.1，客户端 C 在 lo 上、开着 UDP_GRO。eio：tun MTU 9000，经 tun 出去的 GSO 因没有校验和 offload
// 返回 EIO；mtu：tun MTU 1280，A 的第一个合并包段长 1400 超过 MTU，返回 EMSGSIZE（原版 ≤6.13 为 EINVAL），之后逐个数据报发、大于 MTU
// 的在 tun 上分片。两轮，每轮暂停期间后端给 A、B、C 各排几个回包（含多个合并包），恢复后在同一次发出里：批里依次是 A、B、C 的回包
// （由 trace 确认 A 的会话回调最先执行），A 的第一个合并包失败后 A 关 GSO，规则 1 组里 A 后面的合并包也直接逐个数据报发（不再失败一次），
// 排在其后的 B 照常带 GSO，规则 2 的 C 也照常；第二轮 A 收包时已带着关 GSO 的标记，直接逐个数据报发、不再回退。tun 上 A 的数据报（分片
// 已重组）逐个按序到达、来自监听端口，B、C 收到同样段长的合并包；规则 1 的 down_gso_fallback 为 1、规则 2 为 0，恰好一行 info
// （客户端 A、listen fd），没有 debug 行
func TestUDPGROFallbackPerClient(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		mtu   int
		specs []gsoSpec
		errs  []syscall.Errno
	}{
		{"eio", 9000, []gsoSpec{{14500, 1400}, {100, 0}, {5300, 1000}, {4101, 2048}, {2100, 700}}, []syscall.Errno{syscall.EIO}},
		{"mtu", 1280, []gsoSpec{{14500, 1400}, {100, 0}, {7000, 1400}, {2100, 700}, {3000, 1000}}, []syscall.Errno{syscall.EMSGSIZE, syscall.EINVAL}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newTun(t, c.mtu)
			be := newGRORecorder(t, loopback4(t), false)
			lport, lport2 := freePort(t), freePort(t)
			cfg := fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n",
				hostPort("0.0.0.0", lport), be.addr, hostPort("127.0.0.1", lport2), be.addr)
			m := startMapper(t, append(listenPoints("u", lport), listenPoints("u", lport2)...), "-c", writeConfig(t, cfg), "--udp-gro", "--log-level", "6")
			a := netip.AddrPortFrom(d.peer(2), 40001)
			sa := helloGRO(t, be, []byte("hello-a"), func(b []byte) error {
				d.writeUDP(t, a, netip.AddrPortFrom(d.local, uint16(lport)), b)
				return nil
			})
			b := newGROClient(t, "127.0.0.1", hostPort("127.0.0.1", lport))
			sb := helloGRO(t, be, []byte("hello-b"), func(p []byte) error { return b.send(gsoPkt{p, 0}) })
			cc := newGROClient(t, "127.0.0.1", hostPort("127.0.0.1", lport2)) // 规则 2
			sc := helloGRO(t, be, []byte("hello-c"), func(p []byte) error { return cc.send(gsoPkt{p, 0}) })
			var allA, allB, allC []gsoPkt
			for round := range 2 {
				// A 的第一轮以段长 1400 的合并包开头（mtu 组里先报 EMSGSIZE）；第二轮倒序
				pa, pb, pc := gsoPktsOf(c.specs, 140+round, round == 1), gsoPktsOf(c.specs, 150+round, round == 0), gsoPktsOf(c.specs, 160+round, round == 1)
				allA, allB, allC = append(allA, pa...), append(allB, pb...), append(allC, pc...)
				// 回程批按会话回调的顺序排（每个会话一次收完），回调顺序与会话 socket 变为就绪的先后相反：C、B、A 依次收到第一个回包，
				// 批里就是 A、B、C。规则 1 的组里 B 的合并包排在 A 失败的那一条之后，规则 2 的组（C）在批里的槽号与组内下标不同
				var replies []gsoReply
				interleaveGSO([][]gsoPkt{pc, pb, pa}, func(i int, p gsoPkt) { replies = append(replies, gsoReply{be, []string{sc, sb, sa}[i], p}) })
				m.pause(t)
				queueGSOReplies(t, m, replies)
				m.resume(t)
				b.expect(t, pktsForwarded(pb), fmt.Sprintf("第 %d 轮客户端 B", round+1))
				cc.expect(t, pktsForwarded(pc), fmt.Sprintf("第 %d 轮规则 2 的客户端 C", round+1))
				if round == 0 {
					expectFirstSessionCB(t, m, a.String())
				}
				na, _, _ := gsoTotals(allA)
				dg, _ := d.datagrams(t, int(na))
				byDst := map[netip.AddrPort][][]byte{}
				for i, g := range dg {
					if g.src != netip.AddrPortFrom(d.local, uint16(lport)) {
						t.Errorf("tun 上有 %s → %s 的数据报，期望来自 %s:%d", g.src, g.dst, d.local, lport)
					}
					if want := map[bool]int{true: 2, false: 0}[len(g.data)+28 > c.mtu]; g.frags != want {
						t.Errorf("tun 上第 %d 个数据报（%d 字节）有 %d 个 IP 分片，期望 %d（MTU %d）", i, len(g.data), g.frags, want, c.mtu)
					}
					byDst[g.dst] = append(byDst[g.dst], g.data)
				}
				if keys := expectTunFlows(t, byDst, [][][]byte{pktsSegs(allA)}, "客户端"); keys[0].IsValid() && keys[0] != a {
					t.Errorf("客户端 A 的回包发往 %s，期望 %s", keys[0], a)
				}
				if t.Failed() {
					t.FailNow()
				}
			}
			dump := m.statsAfterSignal(t)
			for r, want := range [][][]gsoPkt{{allA, allB}, {allC}} {
				n, nbytes, merged := gsoTotals(want...)
				s, fallback := dump.udp[r+1], uint64(1-r) // 只有规则 1 的客户端 A 回退，且只一次
				if s.downGSOFallback != fallback || s.upGSOFallback != 0 {
					t.Errorf("规则 %d 统计 down_gso_fallback=%d up_gso_fallback=%d，期望 %d/0", r+1, s.downGSOFallback, s.upGSOFallback, fallback)
				}
				if s.downPkts != n || s.downBytes != nbytes || s.downGRO != merged || s.downDrop != 0 {
					t.Errorf("规则 %d 统计 down_pkts=%d down_bytes=%d down_gro=%d down_drop=%d，期望 %d/%d/%d/0", r+1, s.downPkts, s.downBytes, s.downGRO, s.downDrop, n, nbytes, merged)
				}
			}
			expectGSOFallbackLines(t, m, "listen", []string{a.String()}, c.errs...)
		})
	}
}

// U5：段长超过出口 MTU 时回退。tun MTU 1280，上游在 tun 子网里，客户端的合并包段长 1400：GSO 发送返回 EMSGSIZE（这个内核；原版 ≤6.13
// 为 EINVAL，先于校验和检查），会话 socket 关 GSO、逐个数据报重发，每个 1400 字节的数据报在 tun 上分成 2 个 IP 分片。重组后内容、边界、
// 顺序都对，up_gso_fallback 为 1，恰好一行 info
func TestUDPGROFallbackMTU(t *testing.T) {
	t.Parallel()
	d := newTun(t, 1280)
	remote := netip.AddrPortFrom(d.peer(2), 9)
	listen := loopback4(t)
	m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", remote.String(), "-u", "--udp-gro")
	c := udpDial(t, "", listen)
	pkts := gsoPktsOf([]gsoSpec{{7300, 1400}, {200, 0}, {4200, 1400}}, 40, false)
	for _, p := range pkts {
		if err := sendGSO(c, nil, p.data, p.gso); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, nbytes, merged := gsoTotals(pkts)
	dg, frags := d.datagrams(t, int(n))
	expectTunFlows(t, tunBySource(dg, remote.Port()), [][][]byte{pktsSegs(pkts)}, "会话源地址")
	for i, g := range dg {
		if want := map[bool]int{true: 2, false: 0}[len(g.data) == 1400]; g.frags != want {
			t.Errorf("tun 上第 %d 个数据报（%d 字节）有 %d 个 IP 分片，期望 %d", i, len(g.data), g.frags, want)
		}
	}
	t.Logf("tun 上 %d 个数据报，%d 个 IP 分片", len(dg), frags)
	s := m.statsAfterSignal(t).udp[1]
	if s.upGSOFallback != 1 || s.upPkts != n || s.upBytes != nbytes || s.upGRO != merged || s.upDrop != 0 {
		t.Errorf("统计 up_gso_fallback=%d up_pkts=%d up_bytes=%d up_gro=%d up_drop=%d，期望 1/%d/%d/%d/0", s.upGSOFallback, s.upPkts, s.upBytes, s.upGRO, s.upDrop, n, nbytes, merged)
	}
	expectGSOFallbackLines(t, m, "session", []string{c.LocalAddr().String()}, syscall.EMSGSIZE, syscall.EINVAL)
}

// U5：EAGAIN 时按数据报计丢包。seccomp 让会话 socket（up）或监听 socket（down）的发送一律返回 EAGAIN：暂停期间排好的一批里有合并包
// （含要拆成 64+36 的 100 段、64+1 的 65 段；有的组以要拆开发的包开头，EAGAIN 出在拆分发送里，这个包剩下的段与组里其余的包一起
// 丢）与普通数据报，每个会话（up）或这条规则（down）一次调用就丢掉整组。up_drop/down_drop 等于这些包的数据报
// 总数（不是条目数），日志报告的丢包数之和与之相同、每组一行；EAGAIN 不是 GSO 的错误，不回退；up_gro/down_gro 照样按收到的合并包计
func TestUDPGROEAGAIN(t *testing.T) {
	t.Parallel()
	t.Run("up", func(t *testing.T) {
		t.Parallel()
		be := newGRORecorder(t, loopback4(t), false)
		listen := loopback4(t)
		wait := listenPoints("u", portOf(listen))
		args := []string{"-l", listen, "-r", be.addr, "-u", "--udp-gro"}
		n := startupFDs(t, wait, args...)
		m := startMapperSendtoFail(t, n, 0, wait, args...)
		conns := []*net.UDPConn{udpDial(t, "", listen), udpDial(t, "", listen)}
		pkts := [][]gsoPkt{
			gsoPktsOf([]gsoSpec{{14500, 1400}, {10, 0}, {64000, 1000}, {10000, 100}}, 60, false),
			gsoPktsOf([]gsoSpec{{6500, 100}, {20, 0}, {10000, 2000}}, 61, false), // 组首要拆开发：EAGAIN 出在拆分发送里
		}
		var sends []gsoSend
		interleaveGSO(pkts, func(i int, p gsoPkt) { sends = append(sends, gsoSend{conns[i], nil, p}) })
		m.pause(t)
		queueGSO(t, m, listen, sends)
		m.resume(t)
		total, _, merged := gsoTotals(pkts...)
		var s udpStat
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			if s = m.statsAfterSignal(t).udp[1]; s.upDrop < total {
				return fmt.Errorf("up_drop=%d，期望 %d", s.upDrop, total)
			}
			return nil
		})
		if s.upDrop != total || s.upPkts != 0 || s.upBytes != 0 || s.upGRO != merged || s.upGSOFallback != 0 || s.sessions != 2 {
			t.Errorf("统计 up_drop=%d up_pkts=%d up_bytes=%d up_gro=%d up_gso_fallback=%d sessions=%d，期望 %d/0/0/%d/0/2（按数据报计丢包，EAGAIN 不回退）",
				s.upDrop, s.upPkts, s.upBytes, s.upGRO, s.upGSOFallback, s.sessions, total, merged)
		}
		eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
			if drops, lines := loggedUpDrops(m); uint64(drops) != total || lines != 2 {
				return fmt.Errorf("日志里 %d 行上行发送失败的 warn 共报告丢 %d 个包，期望 2 行（每个会话一行）、%d 个（按数据报计）", lines, drops, total)
			}
			return nil
		})
		if l := gsoFallbackLines(m, "session"); len(l) != 0 {
			t.Errorf("EAGAIN 却记了 GSO 回退：%q", l)
		}
	})
	t.Run("down", func(t *testing.T) {
		t.Parallel()
		be := newGRORecorder(t, loopback4(t), false)
		listen := loopback4(t)
		wait := listenPoints("u", portOf(listen))
		args := []string{"-l", listen, "-r", be.addr, "-u", "--udp-gro"}
		probe := startMapper(t, wait, args...)
		fd := listenFD(probe.pid(), "udp", portOf(listen))
		probe.stop(t, false)
		if fd < 0 {
			t.Fatal("探测时没有找到 UDP 监听 socket")
		}
		m := startMapperSendtoFail(t, fd, fd+1, wait, args...)
		var sessions []string
		for i := range 2 {
			c := udpDial(t, "", listen)
			sessions = append(sessions, helloGRO(t, be, fmt.Appendf(nil, "hello-%d", i), func(b []byte) error { _, err := c.Write(b); return err }))
		}
		pkts := [][]gsoPkt{
			gsoPktsOf([]gsoSpec{{6500, 100}, {5, 0}, {14500, 1400}, {3000, 1000}}, 70, false), // 组首要拆开发
			gsoPktsOf([]gsoSpec{{3000, 1000}, {5, 0}, {6500, 100}, {14500, 1400}}, 71, false),
		}
		var replies []gsoReply
		interleaveGSO(pkts, func(i int, p gsoPkt) { replies = append(replies, gsoReply{be, sessions[i], p}) })
		m.pause(t)
		queueGSOReplies(t, m, replies)
		m.resume(t)
		total, _, merged := gsoTotals(pkts...)
		var s udpStat
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			if s = m.statsAfterSignal(t).udp[1]; s.downDrop < total {
				return fmt.Errorf("down_drop=%d，期望 %d", s.downDrop, total)
			}
			return nil
		})
		if s.downDrop != total || s.downPkts != 0 || s.downBytes != 0 || s.downGRO != merged || s.downGSOFallback != 0 {
			t.Errorf("统计 down_drop=%d down_pkts=%d down_bytes=%d down_gro=%d down_gso_fallback=%d，期望 %d/0/0/%d/0",
				s.downDrop, s.downPkts, s.downBytes, s.downGRO, s.downGSOFallback, total, merged)
		}
		eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
			if drops, lines, _ := loggedDownDrops(m); uint64(drops) != total || lines != 1 {
				return fmt.Errorf("日志里 %d 行回程发送失败的 warn 共报告丢 %d 个包，期望 1 行（这条规则的一组）、%d 个（按数据报计）", lines, drops, total)
			}
			return nil
		})
		if l := gsoFallbackLines(m, "listen"); len(l) != 0 {
			t.Errorf("EAGAIN 却记了 GSO 回退：%q", l)
		}
		m.expectIdleCPU(t, "GRO 回程 EAGAIN 之后")
	})
}

// U5：GSO 发送遇到不是 GSO 本身的错误（EIO/EINVAL/EMSGSIZE 以外）时不关 GSO。seccomp 让会话 socket（up，ECONNREFUSED：连上的
// socket 取走 ICMP 端口不可达的错误）或监听 socket（down，EPERM：如 netfilter 拒绝）的发送一律失败：合并包重发一次仍失败、按数据报
// 计入丢包，up_gso_fallback/down_gso_fallback 保持 0、没有回退的 info 行。日志报告的丢包数之和与 drop 相同
func TestUDPGROSendError(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		errno syscall.Errno
	}{{"up", syscall.ECONNREFUSED}, {"down", syscall.EPERM}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := newGRORecorder(t, loopback4(t), false)
			listen := loopback4(t)
			wait := listenPoints("u", portOf(listen))
			args := []string{"-l", listen, "-r", be.addr, "-u", "--udp-gro"}
			pkts := [][]gsoPkt{
				gsoPktsOf([]gsoSpec{{14500, 1400}, {10, 0}, {5000, 1000}, {6500, 100}}, 130, false),
				gsoPktsOf([]gsoSpec{{3000, 1000}, {6500, 100}}, 131, false),
			}
			var m *mapper
			conns := []*net.UDPConn{udpDial(t, "", listen), udpDial(t, "", listen)}
			if c.name == "up" {
				m = startMapperSendFail(t, startupFDs(t, wait, args...), 0, c.errno, wait, args...)
				var sends []gsoSend
				interleaveGSO(pkts, func(i int, p gsoPkt) { sends = append(sends, gsoSend{conns[i], nil, p}) })
				m.pause(t)
				queueGSO(t, m, listen, sends)
				m.resume(t)
			} else {
				probe := startMapper(t, wait, args...)
				fd := listenFD(probe.pid(), "udp", portOf(listen))
				probe.stop(t, false)
				if fd < 0 {
					t.Fatal("探测时没有找到 UDP 监听 socket")
				}
				m = startMapperSendFail(t, fd, fd+1, c.errno, wait, args...)
				var replies []gsoReply
				for i, cn := range conns {
					session := helloGRO(t, be, fmt.Appendf(nil, "hello-%d", i), func(b []byte) error { _, err := cn.Write(b); return err })
					for _, p := range pkts[i] {
						replies = append(replies, gsoReply{be, session, p})
					}
				}
				m.pause(t)
				queueGSOReplies(t, m, replies)
				m.resume(t)
			}
			total, _, merged := gsoTotals(pkts...)
			var s udpStat
			eventually(t, ioTimeout, 50*time.Millisecond, func() error {
				s = m.statsAfterSignal(t).udp[1]
				if drop := map[string]uint64{"up": s.upDrop, "down": s.downDrop}[c.name]; drop < total {
					return fmt.Errorf("%s_drop=%d，期望 %d", c.name, drop, total)
				}
				return nil
			})
			got := map[string][4]uint64{"up": {s.upDrop, s.upPkts, s.upGRO, s.upGSOFallback}, "down": {s.downDrop, s.downPkts, s.downGRO, s.downGSOFallback}}[c.name]
			if want := [4]uint64{total, 0, merged, 0}; got != want {
				t.Errorf("统计 %s_drop/pkts/gro/gso_fallback=%v，期望 %v（按数据报计丢包；不是 GSO 本身的错误，不回退）", c.name, got, want)
			}
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				drops, lines := loggedUpDrops(m)
				if c.name == "down" {
					drops, lines, _ = loggedDownDrops(m)
				}
				if uint64(drops) != total {
					return fmt.Errorf("日志里 %d 行发送失败的 warn 共报告丢 %d 个包，期望 %d", lines, drops, total)
				}
				return nil
			})
			if l := append(gsoFallbackLines(m, "session"), gsoFallbackLines(m, "listen")...); len(l) != 0 {
				t.Errorf("%v 不是 GSO 本身的错误，却记了 GSO 回退：%q", c.errno, l)
			}
		})
	}
}

// U5（D44，审查 H1）：给了 --udp-gro 且 --udp-listen-buf 大于会话缓冲（--sock-buf，默认 1 MiB）时，会话 socket 的 SO_SNDBUF 取监听
// 缓冲的大小、用 FORCE（有 CAP_NET_ADMIN 时不受 wmem_max 截断）：一次入向回调可能把监听队列里积压的合并包全交给一个会话，sndbuf 装不下
// 就 EAGAIN 丢掉整组。SO_RCVBUF 不变（D38：只有给了 --sock-buf 才 FORCE）。没给 --udp-gro，或监听缓冲不大于会话缓冲（含相等的边界）时
// 与 U6 相同。cap/nocap × 各组参数，经 sock_diag 查 2 个会话 socket 的 rcvbuf/sndbuf；nocap 下 FORCE 失败的 debug 行仍只有一行
func TestUDPGROSessionSndBuf(t *testing.T) {
	t.Parallel()
	const sessions = 2
	for _, mode := range udpBufModes {
		for _, c := range []struct {
			name     string
			extra    []string
			gro      bool
			session  int  // 会话缓冲请求（--sock-buf 或默认 1 MiB）
			explicit bool // 给了 --sock-buf
			snd      int  // 期望的会话 SO_SNDBUF 请求
			sndForce bool // 期望 SO_SNDBUF 用 FORCE
		}{
			{"nogro-default", nil, false, 1 << 20, false, 1 << 20, false},
			{"nogro-listen-3000", []string{"--udp-listen-buf", "3000"}, false, 1 << 20, false, 1 << 20, false},
			{"nogro-sock-buf-40", []string{"--sock-buf", "40"}, false, 40 << 10, true, 40 << 10, true},
			{"gro-default", nil, true, 1 << 20, false, 2048 << 10, true},
			{"gro-listen-3000", []string{"--udp-listen-buf", "3000"}, true, 1 << 20, false, 3000 << 10, true},
			{"gro-listen-1024", []string{"--udp-listen-buf", "1024"}, true, 1 << 20, false, 1 << 20, false},
			{"gro-listen-512", []string{"--udp-listen-buf", "512"}, true, 1 << 20, false, 1 << 20, false},
			{"gro-sock-buf-40", []string{"--sock-buf", "40"}, true, 40 << 10, true, 2048 << 10, true},
			{"gro-sock-buf-3000", []string{"--sock-buf", "3000"}, true, 3000 << 10, true, 3000 << 10, true},
		} {
			t.Run(mode.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				be := serveUDP(t, loopback4(t), "")
				listen := loopback4(t)
				args := append([]string{"-l", listen, "-r", be.addr, "-u", "--log-level", "5"}, c.extra...)
				if c.gro {
					args = append(args, "--udp-gro")
				}
				m := startUDPBufMapper(t, mode.netAdmin, listenPoints("u", portOf(listen)), args...)
				for range sessions {
					udpReplyFrom(t, udpDial(t, "", listen), "udp")
				}
				peers := be.peerList()
				if len(peers) != sessions {
					t.Fatalf("后端看到的源地址为 %v，期望恰好 %d 个（tinymapper 的会话 socket）", peers, sessions)
				}
				if s := m.statsAfterSignal(t).udp[1]; s.sessions != sessions {
					t.Fatalf("统计 sessions=%d，期望 %d", s.sessions, sessions)
				}
				want := sockBuf{rcv: setBuf(t, c.session).rcv, snd: setBuf(t, c.snd).snd}
				if mode.netAdmin && c.explicit {
					want.rcv = uint32(2 * c.session)
				}
				if mode.netAdmin && c.sndForce {
					want.snd = uint32(2 * c.snd)
				}
				for i, p := range peers {
					got := lookupSockBuf(t, m.pid(), syscall.IPPROTO_UDP, fmt.Sprintf("UDP 会话 socket %d", i+1), p, be.addr)
					if got.rcv != want.rcv || got.snd != want.snd {
						t.Errorf("会话 socket %d rcvbuf=%d sndbuf=%d，期望 %d、%d（--udp-gro %v，会话请求 %d，SO_SNDBUF 请求 %d，CAP_NET_ADMIN=%v）",
							i+1, got.rcv, got.snd, want.rcv, want.snd, c.gro, c.session, c.snd, mode.netAdmin)
					}
				}
				wantDebug := map[bool]int{true: 0, false: 1}[mode.netAdmin]
				if n := m.logLines(udpBufForceFailed); n != wantDebug {
					t.Errorf("日志中有 %d 行 %q，期望 %d 行（失败缓存）", n, udpBufForceFailed, wantDebug)
				}
			})
		}
	}
}

// U5：不给 --udp-gro 时行为不变。tinymapper 的 socket 不开 UDP_GRO：客户端经 lo 的 GSO 发送在监听 socket 上被切成数据报，逐个转发，
// 开了 UDP_GRO 的后端收到的都没有 cmsg（lo 不聚合普通数据报）；后端的 GSO 回包同样在会话 socket 上被切开，开了 UDP_GRO 的客户端
// 收到的也都没有 cmsg；统计行与 U5 之前逐字节相同（statsAfterSignal 核对）。tcp：给了 --udp-gro 时 TCP 照常、计数精确，UDP 行带
// GRO 计数
func TestUDPGRODisabled(t *testing.T) {
	t.Parallel()
	t.Run("udp", func(t *testing.T) {
		t.Parallel()
		be := newGRORecorder(t, loopback4(t), true)
		listen := loopback4(t)
		m := forward(t, "u", listen, be.addr)
		cl := newGROClient(t, "127.0.0.1", listen)
		up := gsoPktsOf([]gsoSpec{{14500, 1400}, {300, 0}, {6500, 100}, {4196, 2048}}, 80, false)
		for _, p := range up {
			if err := cl.send(p); err != nil {
				t.Fatal(err)
			}
		}
		n, nbytes, _ := gsoTotals(up)
		plainMsgs := func(pkts []gsoPkt) []groMsg {
			var out []groMsg
			for _, s := range pktsSegs(pkts) {
				out = append(out, groMsg{data: s})
			}
			return out
		}
		srcs := expectMsgsBySource(t, be.msgsBySource(t, int(n)), [][]groMsg{plainMsgs(up)})
		if t.Failed() {
			t.FailNow()
		}
		down := gsoPktsOf([]gsoSpec{{14500, 1400}, {3000, 1000}, {7, 0}}, 81, false)
		for _, p := range down {
			be.sendTo(t, srcs[0], p)
		}
		cl.expect(t, plainMsgs(down), "客户端")
		dn, dbytes, _ := gsoTotals(down)
		s := m.statsAfterSignal(t).udp[1]
		if s.upPkts != n || s.upBytes != nbytes || s.downPkts != dn || s.downBytes != dbytes || s.upDrop != 0 || s.downDrop != 0 {
			t.Errorf("统计 up_pkts=%d up_bytes=%d down_pkts=%d down_bytes=%d up/down_drop=%d/%d，期望 %d/%d/%d/%d/0/0",
				s.upPkts, s.upBytes, s.downPkts, s.downBytes, s.upDrop, s.downDrop, n, nbytes, dn, dbytes)
		}
		if n := m.logLines("UDP_GRO"); n != 0 {
			t.Errorf("没给 --udp-gro，日志里却有 %d 行提到 UDP_GRO", n)
		}
	})
	t.Run("tcp", func(t *testing.T) {
		t.Parallel()
		remote := loopback4(t)
		serveTCP(t, remote, streamHandler)
		be := newGRORecorder(t, remote, false)
		listen := loopback4(t)
		m := startMapper(t, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--udp-gro")
		const up, down = 100 << 10, 300 << 10
		if err := transfer(listen, up, down, 4096, 2); err != nil {
			t.Fatal(err)
		}
		c := udpDial(t, "", listen)
		p := gsoPkt{gsoData(90, 5000), 1000}
		if err := sendGSO(c, nil, p.data, p.gso); err != nil {
			t.Fatal(err)
		}
		be.wait(t, 5)
		d := m.statsAfterSignal(t)
		if s := d.tcp[1]; s.total != 1 || s.upBytes != up+streamHeaderLen || s.downBytes != down+64 {
			t.Errorf("tcp 统计 total=%d up_bytes=%d down_bytes=%d，期望 1/%d/%d", s.total, s.upBytes, s.downBytes, up+streamHeaderLen, down+64)
		}
		if s := d.udp[1]; s.upPkts != 5 || s.upGRO != 5 {
			t.Errorf("udp 统计 up_pkts=%d up_gro=%d，期望 5/5", s.upPkts, s.upGRO)
		}
		m.expectIdleCPU(t, "--udp-gro 下 TCP 传输之后")
	})
}

// U5：选项解析。--udp-gro 只有命令行（D41 lead 另定，同 --sock-buf）：帮助文本里有它；与 -c 一起用时对配置里的每条 UDP 规则生效
// （IPv4、IPv6 两条规则各收一个合并包，后端看到同样段长的合并包，各规则的 up_gro 精确）；TOML 的 [network] 里没有对应的键；
// 它不带参数（--udp-gro=1 被拒绝）
func TestUDPGROOptions(t *testing.T) {
	t.Parallel()
	t.Run("help", func(t *testing.T) {
		t.Parallel()
		out, err := exec.Command(mapperBin, "-h").Output()
		if err != nil {
			t.Fatalf("-h 退出状态异常：%v", err)
		}
		if !strings.Contains(string(out), "--udp-gro") {
			t.Errorf("帮助文本里没有 --udp-gro：\n%s", out)
		}
	})
	t.Run("config", func(t *testing.T) {
		t.Parallel()
		hosts := []string{"127.0.0.1", "::1"}
		var cfg strings.Builder
		var wait []listenPoint
		var listens []string
		var bes []*groRecorder
		for _, h := range hosts {
			be := newGRORecorder(t, hostPort(h, freePort(t)), true)
			l := hostPort(h, freePort(t))
			fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", l, be.addr)
			wait = append(wait, listenPoints("u", portOf(l))...)
			listens, bes = append(listens, l), append(bes, be)
		}
		m := startMapper(t, wait, "--udp-gro", "-c", writeConfig(t, cfg.String()))
		for r := range hosts {
			p := gsoPkt{gsoData(100+r, 3000+r*500), 1000}
			if err := sendGSO(udpDial(t, "", listens[r]), nil, p.data, p.gso); err != nil {
				t.Fatal(err)
			}
			expectMsgsBySource(t, bes[r].msgsBySource(t, len(p.segs())), [][]groMsg{p.forwarded()})
		}
		d := m.statsAfterSignal(t)
		for r := range hosts {
			if s := d.udp[r+1]; s.upGRO != uint64(3+r) || s.upPkts != uint64(3+r) {
				t.Errorf("规则 %d 统计 up_gro=%d up_pkts=%d，期望 %d/%d", r+1, s.upGRO, s.upPkts, 3+r, 3+r)
			}
		}
	})
	t.Run("toml-key", func(t *testing.T) {
		t.Parallel()
		cfg := writeConfig(t, fmt.Sprintf("[network]\nudp_gro = true\n\n[[endpoints]]\nlisten = %q\nremote = %q\nuse_udp = true\n", loopback4(t), loopback4(t)))
		if out := runExpectFail(t, 5*time.Second, "-c", cfg); !strings.Contains(out, "unknown key in [network]") {
			t.Errorf("[network] udp_gro 的报错不符：\n%s", out)
		}
	})
	t.Run("argument", func(t *testing.T) {
		t.Parallel()
		out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-u", "--udp-gro=1")
		if !strings.Contains(out, "udp-gro") {
			t.Errorf("--udp-gro=1 的报错没有提到这个选项：\n%s", out)
		}
	})
}

// ---- seccomp setsockopt(UDP_GRO) 故障注入（5.0 以前的内核开不了 UDP_GRO）----
//
// TPM_GRO_FAIL="lo hi" 存在时，init() 在重新执行的测试二进制里装 seccomp 过滤器后 exec tinymapper：fd 在 [lo, hi) 内的
// setsockopt(fd, SOL_UDP, UDP_GRO, ...) 返回 ENOPROTOOPT（5.0 以前的内核对未知的 UDP 选项就返回它），其他系统调用不受影响。
// 与 TPM_SENDTO_FAIL、TPM_EPOLL_ADD_FAIL 同一套路，各认各的环境变量
const groFailEnv = "TPM_GRO_FAIL"

func init() {
	if spec := os.Getenv(groFailEnv); spec != "" {
		execGROFail(spec)
	}
}

// groFailFilter 返回 BPF 程序：arch 相符、nr 为 setsockopt、args[1] 为 SOL_UDP、args[2] 为 UDP_GRO、lo ≤ args[0] < hi 时返回
// SECCOMP_RET_ERRNO|ENOPROTOOPT，否则放行。只支持小端架构（参数取 u64 的低 32 位）
func groFailFilter(arch, lo, hi uint32) []syscall.SockFilter {
	const (
		ld   = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS
		jeq  = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		jge  = syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K
		ret  = syscall.BPF_RET | syscall.BPF_K
		nr   = 0 // struct seccomp_data：int nr; u32 arch; u64 ip; u64 args[6]
		arg0 = 16 + 0
		arg1 = 16 + 8
		arg2 = 16 + 16
	)
	stmt := func(code uint16, k uint32) syscall.SockFilter { return syscall.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) syscall.SockFilter {
		return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	// 跳转偏移相对下一条指令；索引 12 为放行
	return []syscall.SockFilter{
		stmt(ld, 4),            // 0：arch
		jump(jeq, arch, 0, 10), // 1
		stmt(ld, nr),           // 2
		jump(jeq, uint32(syscall.SYS_SETSOCKOPT), 0, 8), // 3
		stmt(ld, arg1),             // 4：level
		jump(jeq, solUDP, 0, 6),    // 5
		stmt(ld, arg2),             // 6：optname
		jump(jeq, udpGROOpt, 0, 4), // 7
		stmt(ld, arg0),             // 8：fd
		jump(jge, lo, 0, 2),        // 9：fd<lo → 放行
		jump(jge, hi, 1, 0),        // 10：fd≥hi → 放行
		stmt(ret, 0x00050000|uint32(syscall.ENOPROTOOPT)), // 11：SECCOMP_RET_ERRNO|ENOPROTOOPT
		stmt(ret, 0x7fff0000),                             // 12：SECCOMP_RET_ALLOW
	}
}

// execGROFail 在重新执行的测试二进制里运行：os.Args[1:] 是 tinymapper 的 argv。成功时不返回
func execGROFail(spec string) {
	const (
		prSetSeccomp      = 22
		prSetNoNewPrivs   = 38
		seccompModeFilter = 2
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "UDP_GRO 故障注入启动失败："+format+"\n", a...)
		os.Exit(127)
	}
	var lo, hi uint32
	if _, err := fmt.Sscan(spec, &lo, &hi); err != nil || len(os.Args) < 2 {
		fail("%s=%q 或参数 %q 无效", groFailEnv, spec, os.Args)
	}
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		fail("不支持 %s", runtime.GOARCH)
	}
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		fail("prctl(PR_SET_NO_NEW_PRIVS)：%v", e)
	}
	filter := groFailFilter(arch, lo, hi)
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); e != 0 {
		fail("prctl(PR_SET_SECCOMP)：%v", e)
	}
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	fail("exec %s：%v", os.Args[1], err)
}

// startMapperGROFail 同 startMapper，但 tinymapper 里 fd 在 [lo, hi) 内的 setsockopt(SOL_UDP, UDP_GRO) 返回 ENOPROTOOPT；hi 为 0 表示不设上限
func startMapperGROFail(t testing.TB, lo, hi int, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	if _, ok := auditArch[runtime.GOARCH]; !ok {
		t.Skipf("seccomp 故障注入只支持 amd64、arm64，当前为 %s", runtime.GOARCH)
	}
	if hi == 0 {
		hi = 1<<32 - 1
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(self, append([]string{mapperBin, "--disable-color"}, args...)...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d %d", groFailEnv, lo, hi))
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}

// groSetFailWarn 是监听 socket 开不了 UDP_GRO 的 warn 行里固定的部分（规则号在前，errno 按数字比较）
var groSetFailWarn = fmt.Sprintf("[udp] setsockopt UDP_GRO failed (%d:", int(syscall.ENOPROTOOPT))

const groSetFailHint = "--udp-gro needs Linux 5.0 or later"

// U5：开不了 UDP_GRO（5.0 以前的内核；用 seccomp 让 setsockopt 返回 ENOPROTOOPT）。两条 UDP 规则，--log-level 5：
//   - first-listen：所有 socket 都开不了：规则 1 的监听 socket 记一行 warn（带 "UDP_GRO stays off"），整个特性关闭，规则 2 与会话
//     socket 不再尝试（没有第二行 warn，也没有会话的 debug 行）；统计行不带 GRO 计数；客户端的 GSO 发送照常逐个数据报转发
//   - second-listen：只有规则 2 的监听 socket 开不了：只记规则 2 一行 warn，特性仍开着：规则 1 的合并包照常带 GSO 转发、计入 up_gro，
//     规则 2 收到的是切开的数据报（up_gro 为 0），它的会话 socket 仍开着 UDP_GRO，回程合并包照常计入 down_gro
//   - session：只有会话 socket 开不了：每个会话一行 debug，入向合并包照常；后端的 GSO 回包在会话 socket 上被切开，down_gro 为 0，
//     客户端逐个数据报收到
func TestUDPGROSetsockoptFail(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"first-listen", "second-listen", "session"} {
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			listens := []string{loopback4(t), loopback4(t)}
			bes := []*groRecorder{newGRORecorder(t, loopback4(t), true), newGRORecorder(t, loopback4(t), true)}
			var cfg strings.Builder
			var wait []listenPoint
			for r := range listens {
				fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", listens[r], bes[r].addr)
				wait = append(wait, listenPoints("u", portOf(listens[r]))...)
			}
			args := []string{"-c", writeConfig(t, cfg.String()), "--udp-gro", "--log-level", "5"}
			lo, hi := 0, 0
			switch c {
			case "second-listen":
				probe := startMapper(t, wait, args...)
				lo = listenFD(probe.pid(), "udp", portOf(listens[1]))
				probe.stop(t, false)
				if lo < 0 {
					t.Fatal("探测时没有找到规则 2 的 UDP 监听 socket")
				}
				hi = lo + 1
			case "session":
				lo = startupFDs(t, wait, args...)
			}
			m := startMapperGROFail(t, lo, hi, wait, args...)
			m.groOff = c == "first-listen"
			// 每条规则一个开了 UDP_GRO 的客户端：发一个合并包，后端再回一个合并包
			for r := range listens {
				cl := newGROClient(t, "127.0.0.1", listens[r])
				up := gsoPkt{gsoData(110+r, 5500), 1000}
				if err := cl.send(up); err != nil {
					t.Fatal(err)
				}
				wantUp := up.forwarded() // 监听 socket 开着 UDP_GRO 时整包收到、带 GSO 转发
				if c == "first-listen" || (c == "second-listen" && r == 1) {
					wantUp = nil
					for _, s := range up.segs() {
						wantUp = append(wantUp, groMsg{data: s})
					}
				}
				srcs := expectMsgsBySource(t, bes[r].msgsBySource(t, len(up.segs())), [][]groMsg{wantUp})
				if t.Failed() {
					t.FailNow()
				}
				down := gsoPkt{gsoData(120+r, 4500), 1000}
				bes[r].sendTo(t, srcs[0], down)
				wantDown := down.forwarded()
				if c != "second-listen" {
					wantDown = nil
					for _, s := range down.segs() {
						wantDown = append(wantDown, groMsg{data: s})
					}
				}
				cl.expect(t, wantDown, fmt.Sprintf("规则 %d 的客户端", r+1))
			}
			d := m.statsAfterSignal(t)
			if c != "first-listen" {
				wantGRO := map[string][2][2]uint64{"second-listen": {{6, 5}, {0, 5}}, "session": {{6, 0}, {6, 0}}}[c]
				for r := range listens {
					if s := d.udp[r+1]; s.upGRO != wantGRO[r][0] || s.downGRO != wantGRO[r][1] || s.upPkts != 6 || s.downPkts != 5 {
						t.Errorf("规则 %d 统计 up_gro=%d down_gro=%d up_pkts=%d down_pkts=%d，期望 %d/%d/6/5", r+1, s.upGRO, s.downGRO, s.upPkts, s.downPkts, wantGRO[r][0], wantGRO[r][1])
					}
				}
			}
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				want := map[string]int{"first-listen": 1, "second-listen": 1, "session": 0}[c]
				if n := m.logLines(groSetFailWarn, groSetFailHint); n != want {
					return fmt.Errorf("日志里有 %d 行监听 socket 开 UDP_GRO 失败的 warn，期望 %d", n, want)
				}
				return nil
			})
			switch c {
			case "first-listen":
				if n := m.logLines("rule 1 "+groSetFailWarn, groSetFailHint+", UDP_GRO stays off"); n != 1 {
					t.Errorf("规则 1 的 warn 行（带 UDP_GRO stays off）有 %d 行，期望 1", n)
				}
			case "second-listen":
				if n := m.logLines("rule 2 "+groSetFailWarn, groSetFailHint); n != 1 || m.logLines("UDP_GRO stays off") != 0 {
					t.Errorf("规则 2 的 warn 行有 %d 行（期望 1），或者错误地说特性关闭了", n)
				}
			}
			wantSession := map[string]int{"first-listen": 0, "second-listen": 0, "session": 2}[c]
			if n := m.logLines("[udp]setsockopt UDP_GRO failed on udp fd"); n != wantSession {
				t.Errorf("日志里有 %d 行会话 socket 开 UDP_GRO 失败的 debug，期望 %d", n, wantSession)
			}
		})
	}
}
