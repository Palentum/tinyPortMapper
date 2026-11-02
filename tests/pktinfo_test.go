// 通配 UDP 监听的回包源地址（D87–D91，审查 Medium #3）。
//
// 规则监听 0.0.0.0、[::]（不设 IPV6_V6ONLY，容器里 bindv6only=0，是双栈）或 [::ffff:0.0.0.0] 时，监听 socket 开 IP_PKTINFO（AF_INET）
// 或 IPV6_RECVPKTINFO（AF_INET6；D88：[::] 只开它），每个入向包都把客户端发往的本机地址记到会话上（D89：以最后一个包为准）；回包经
// 监听 socket 发出时以它作源（IPv4 与 v4 映射客户端用 IP_PKTINFO 的 ipi_spec_dst，IPv6 客户端用 IPV6_PKTINFO），客户端 connect 过的
// socket、NAT、有状态防火墙才认得回包。绑具体地址的规则不变（D87：通配监听默认开，没有选项）。修复前回包的源地址由路由选，客户端发往的
// 不是路由首选地址时 connect 过的 socket 收不到回包，tinymapper 照样记 down_pkts、没有任何日志（build/pktinfo/results.md 的 R1–R4）。
//
// D90：带着记下的源地址发送失败（EINVAL / ENETUNREACH / ENODEV / EADDRNOTAVAIL：地址已删、IPv4 广播目的等）时，去掉源地址把这个回包
// 原地重发一次（内核选源，GSO 照旧），清掉会话记下的地址直到客户端再发包，每条规则第一次记一行 info、之后 debug；重发的回包计入
// down_pkts/down_bytes，不计 down_drop，也不算 GSO 回退。开不了这两个选项时每条规则一行 warn，该规则照旧由内核选源。
//
// 做法：lo 上 127.0.0.0/8 都是本机地址，IPv4 客户端从 127.0.0.1 发往 127.0.0.2/.3/.4，内核给 127.0.0.1 选的源是它自己；IPv6 在 lo 上
// 加 fd00:7470::/32 里的 /128 地址（newLoAddrs6）。没有 connect 的客户端读出每个回包的源地址，connect 过的客户端证明回包真能送达。
package tests

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// pktinfoFlow 是一个客户端：绑定 local，发往 tinymapper 的本机地址 target；"$1"、"$2" 换成用例在 lo 上加的 IPv6 地址（lo6Sub）
type pktinfoFlow struct{ local, target string }

// 行为 1、2：各类监听地址下，每个客户端的回包都来自它发往的地址。每个 flow 两个客户端：没有 connect 的读出回显的源地址，connect 到 target
// 的证明回包送达（源地址不对时内核丢掉回包，客户端只会超时）。ipv4：0.0.0.0 监听，从 127.0.0.1 发往 .2/.3/.1，从 .2 发往 .4；
// dualstack-v4 / dualstack-v6 / dualstack-mixed：[::] 监听的 v4 映射客户端、IPv6 客户端（fd00 地址之间、::1 发往 fd00 地址）与两者混在
// 一条规则里；v4mapped-any：[::ffff:0.0.0.0] 监听；specific-v4 / specific-v6：绑具体地址的对照组，修复前后都通过。统计：每个客户端一个
// 会话，回包数等于后端回显数，没有丢包与 warn
func TestUDPPktinfoSource(t *testing.T) {
	t.Parallel()
	v4 := []pktinfoFlow{{"127.0.0.1", "127.0.0.2"}, {"127.0.0.1", "127.0.0.3"}, {"127.0.0.1", "127.0.0.1"}, {"127.0.0.2", "127.0.0.4"}}
	v6 := []pktinfoFlow{{"$1", "$2"}, {"::1", "$2"}, {"::1", "::1"}, {"$2", "$1"}}
	for _, c := range []struct {
		name, listen, backend string
		lo6                   int
		flows                 []pktinfoFlow
	}{
		{"ipv4", "0.0.0.0", "127.0.0.1", 0, v4},
		{"dualstack-v4", "::", "127.0.0.1", 0, v4},
		{"dualstack-v6", "::", "::1", 2, v6},
		{"dualstack-mixed", "::", "127.0.0.1", 2, append(slices.Clone(v6[:2]), v4[:2]...)},
		{"v4mapped-any", "::ffff:0.0.0.0", "127.0.0.1", 0, v4},
		{"specific-v4", "127.0.0.2", "127.0.0.1", 0, []pktinfoFlow{{"127.0.0.1", "127.0.0.2"}, {"127.0.0.3", "127.0.0.2"}}},
		{"specific-v6", "$2", "::1", 2, []pktinfoFlow{{"::1", "$2"}, {"$1", "$2"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			sub := lo6Sub(t, c.lo6)
			be := recordUDP(t, hostPort(c.backend, freePort(t)))
			lport := freePort(t)
			m := forward(t, "u", hostPort(sub(c.listen), lport), be.addr)
			for i, f := range c.flows {
				local := sub(f.local)
				target := netip.AddrPortFrom(netip.MustParseAddr(sub(f.target)), uint16(lport))
				who := fmt.Sprintf("客户端 %d（%s → %s）", i, local, target)
				from, err := echoVia(srcClient(t, local), target, fmt.Appendf(nil, "flow-%d-unconnected", i))
				switch {
				case err != nil:
					t.Errorf("%s没有 connect 的 socket 收不到回显：%v", who, err)
				case from != target:
					t.Errorf("%s的回包来自 %s，期望来自它发往的 %s", who, from, target)
				}
				if _, err := echoVia(udpDial(t, local, target.String()), netip.AddrPort{}, fmt.Appendf(nil, "flow-%d-connected", i)); err != nil {
					t.Errorf("%s connect 过的 socket 收不到回显（回包的源地址不是 %s）：%v", who, target, err)
				}
			}
			n := 2 * len(c.flows)
			var s udpStat
			eventually(t, ioTimeout, 50*time.Millisecond, func() error {
				s = m.statsAfterSignal(t).udp[1]
				if s.upPkts != uint64(be.count()) || s.downPkts != s.upPkts {
					return fmt.Errorf("统计 up_pkts=%d down_pkts=%d，期望都等于后端收到并回显的 %d 个", s.upPkts, s.downPkts, be.count())
				}
				return nil
			})
			if s.sessions != n || int(s.total) != n || s.upDrop != 0 || s.downDrop != 0 {
				t.Errorf("统计 sessions=%d total=%d up_drop=%d down_drop=%d，期望 %d/%d/0/0", s.sessions, s.total, s.upDrop, s.downDrop, n, n)
			}
			expectNoWarn(t, m)
		})
	}
}

// 行为 3：--udp-gro 时通配监听上的合并包。收包的控制缓冲要同时放下 UDP_GRO 与 PKTINFO（放不下时内核置 MSG_CTRUNC，tinymapper 丢包并
// 记 warn），回程合并包的条目同时带 UDP_SEGMENT 与 PKTINFO。每个族两个开了 UDP_GRO、没有 connect 的客户端，各自发往一个非首选的本机地址：
// 入向的合并包与普通数据报由开 UDP_GRO 的后端核对消息与段长，后端的合并回包由客户端核对消息、段长与源地址。live 不暂停、逐个发；batch
// 在暂停期间交错排进监听 socket 与会话 socket（会话在批内新建；一次 recvmmsg、一次回程发出）。两轮，第二轮倒序（同 TestUDPGROInbound：
// 收包前没把内核改写的 msg_controllen 恢复时，上一轮收普通数据报的槽这轮放不下合并包的 cmsg）。计数精确，没有回退、丢包与 warn
func TestUDPPktinfoGRO(t *testing.T) {
	t.Parallel()
	upMix := []gsoSpec{{14500, 1400}, {300, 0}, {6000, 1000}, {1472, 0}, {4196, 2048}}
	downMix := []gsoSpec{{13000, 1300}, {0, 0}, {6500, 100}, {1452, 0}, {3000, 1000}}
	for _, c := range []struct {
		name, listen, backend, local string
		lo6                          int
		targets                      []string
	}{
		{"ipv4", "0.0.0.0", "127.0.0.1", "127.0.0.1", 0, []string{"127.0.0.2", "127.0.0.3"}},
		{"dualstack-v4", "::", "127.0.0.1", "127.0.0.1", 0, []string{"127.0.0.2", "127.0.0.3"}},
		{"dualstack-v6", "::", "::1", "$1", 3, []string{"$2", "$3"}},
	} {
		for _, mode := range []string{"live", "batch"} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				batch := mode == "batch"
				if batch {
					singleWorkerOnly(t, "暂停期间排进监听 socket 的包按队列里的位置分批（queueGSO）")
				}
				sub := lo6Sub(t, c.lo6)
				be := newGRORecorder(t, hostPort(c.backend, freePort(t)), true)
				lport := freePort(t)
				listen := hostPort(c.listen, lport)
				m := startMapper(t, listenPoints("u", lport), "-l", listen, "-r", be.addr, "-u", "--udp-gro")
				n := len(c.targets)
				clients := make([]*groClient, n)
				for i, tg := range c.targets {
					clients[i] = newGROClient(t, sub(c.local), hostPort(sub(tg), lport)) // expect 核对回包来自 listen（这里是它发往的地址）
				}
				wantUp := make([][]groMsg, n)
				var upAll, downAll []gsoPkt
				for round := range 2 {
					up, down := make([][]gsoPkt, n), make([][]gsoPkt, n)
					for i := range n {
						r := (i + round) % len(upMix)
						up[i] = gsoPktsOf(append(slices.Clone(upMix[r:]), upMix[:r]...), 10+10*round+i, round == 1)
						down[i] = gsoPktsOf(append(slices.Clone(downMix[r:]), downMix[:r]...), 50+10*round+i, round == 1)
						wantUp[i] = append(wantUp[i], pktsForwarded(up[i])...)
						upAll = append(upAll, up[i]...)
						downAll = append(downAll, down[i]...)
					}
					var sends []gsoSend
					interleaveGSO(up, func(i int, p gsoPkt) { sends = append(sends, gsoSend{clients[i].c, clients[i].listen, p}) })
					if batch {
						m.pause(t)
						queueGSO(t, m, listen, sends)
						m.resume(t)
					} else {
						for _, s := range sends {
							if err := sendGSO(s.c, s.to, s.p.data, s.p.gso); err != nil {
								t.Fatalf("发往 %s 的 %d 字节（gso %d）发送失败：%v", s.to, len(s.p.data), s.p.gso, err)
							}
						}
					}
					upN, _, _ := gsoTotals(upAll)
					srcs := expectMsgsBySource(t, be.msgsBySource(t, int(upN)), wantUp)
					if t.Failed() {
						t.FailNow()
					}
					var replies []gsoReply
					interleaveGSO(down, func(i int, p gsoPkt) { replies = append(replies, gsoReply{be, srcs[i], p}) })
					if batch {
						m.pause(t)
						queueGSOReplies(t, m, replies)
						m.resume(t)
					} else {
						for _, r := range replies {
							r.be.sendTo(t, r.session, r.p)
						}
					}
					for i, cl := range clients {
						cl.expect(t, pktsForwarded(down[i]), fmt.Sprintf("第 %d 轮发往 %s 的客户端", round+1, cl.listen))
					}
				}
				upN, upBytes, upMerged := gsoTotals(upAll)
				downN, downBytes, downMerged := gsoTotals(downAll)
				s := m.statsAfterSignal(t).udp[1]
				if s.upPkts != upN || s.upBytes != upBytes || s.upGRO != upMerged || s.downPkts != downN || s.downBytes != downBytes || s.downGRO != downMerged {
					t.Errorf("统计 up_pkts=%d up_bytes=%d up_gro=%d down_pkts=%d down_bytes=%d down_gro=%d，期望 %d/%d/%d/%d/%d/%d",
						s.upPkts, s.upBytes, s.upGRO, s.downPkts, s.downBytes, s.downGRO, upN, upBytes, upMerged, downN, downBytes, downMerged)
				}
				if s.upDrop != 0 || s.downDrop != 0 || s.upGSOFallback != 0 || s.downGSOFallback != 0 || s.sessions != n {
					t.Errorf("统计 up/down_drop=%d/%d up/down_gso_fallback=%d/%d sessions=%d，期望 0/0/0/0/%d", s.upDrop, s.downDrop, s.upGSOFallback, s.downGSOFallback, s.sessions, n)
				}
				if l := phraseLines(m, "MSG_CTRUNC"); len(l) != 0 {
					t.Errorf("日志里有 %d 行 MSG_CTRUNC：收包的控制缓冲放不下 UDP_GRO 与 PKTINFO，第一行 %q", len(l), l[0])
				}
				expectNoWarn(t, m)
			})
		}
	}
}

// D89：同一个客户端（同一 ip:port）先后发往 127.0.0.2 与 127.0.0.3（同一条 0.0.0.0 规则），始终是一个会话，回包的源地址是它最近一个包的
// 目的地址。--threads 1：多个 worker 时 reuseport 的哈希含目的地址，发往两个地址的包本来就可能落到不同 worker、各建一个会话。sequential：
// 逐个发，后端（不回显）在每次切换后回包，到客户端再次切换之前的回包都来自新地址；batch：暂停期间同一批里先发往 .2 再发往 .3（会话在批内
// 新建、随即改写），恢复后的回包来自 .3，下一批先 .3 后 .2，回包来自 .2。统计 sessions=total=1，后端只看到一个源地址
func TestUDPPktinfoLatestDst(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"sequential", "batch"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			if mode == "batch" {
				singleWorkerOnly(t, "暂停期间排进监听 socket 的包按队列里的位置分批（queueListen）")
			}
			be := quietUDP(t, loopback4(t))
			lport := freePort(t)
			listen := hostPort("0.0.0.0", lport)
			m := startMapper(t, listenPoints("u", lport), "-l", listen, "-r", be.addr, "-u", "--threads", "1")
			c := srcClient(t, "127.0.0.1")
			dst := func(last byte) netip.AddrPort {
				return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, last}), uint16(lport))
			}
			session := ""
			sameSession := func(s string) {
				t.Helper()
				if session == "" {
					session = s
				} else if s != session {
					t.Errorf("客户端换了目的地址之后后端看到新的源地址 %s（原来是 %s）：新建了会话", s, session)
				}
			}
			var replies [][]byte
			reply := func(k int, from netip.AddrPort, who string) {
				t.Helper()
				var want [][]byte
				for range k {
					msg := fmt.Appendf(nil, "reply-%02d", len(replies))
					be.sendTo(t, session, msg)
					replies = append(replies, msg)
					want = append(want, msg)
				}
				expectFrom(t, c, want, from, who)
			}
			if mode == "sequential" {
				for i, step := range []struct {
					last    byte
					replies int
				}{{2, 1}, {3, 2}, {2, 1}, {3, 1}} {
					sameSession(helloSession(t, be, fmt.Appendf(nil, "to-%d-%d", step.last, i), sendTo(c, dst(step.last))))
					reply(step.replies, dst(step.last), fmt.Sprintf("第 %d 次改发往 %s 之后的客户端", i+1, dst(step.last)))
				}
			} else {
				for i, order := range [][]byte{{2, 3}, {3, 2}} {
					msgs := make([][]byte, len(order))
					for j, last := range order {
						msgs[j] = fmt.Appendf(nil, "batch-%d-to-%d", i, last)
					}
					m.pause(t)
					queueListen(t, m, listen, len(order), func(j int) int { return len(msgs[j]) }, func(j int) error {
						_, err := c.WriteToUDPAddrPort(msgs[j], dst(order[j]))
						return err
					})
					m.resume(t)
					for _, msg := range msgs {
						sameSession(sessionOf(t, be, msg))
					}
					last := dst(order[len(order)-1])
					reply(2, last, fmt.Sprintf("第 %d 批（%v）之后的客户端", i+1, order))
				}
			}
			s := m.statsAfterSignal(t).udp[1]
			if s.sessions != 1 || s.total != 1 {
				t.Errorf("统计 sessions=%d total=%d，期望 1/1（同一个客户端发往两个本机地址仍是一个会话）", s.sessions, s.total)
			}
			if s.downPkts != uint64(len(replies)) || s.downBytes != totalLen(replies) || s.downDrop != 0 || s.upPkts != uint64(be.count()) || s.upDrop != 0 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d up_pkts=%d up_drop=%d，期望 %d/%d/0/%d/0",
					s.downPkts, s.downBytes, s.downDrop, s.upPkts, s.upDrop, len(replies), totalLen(replies), be.count())
			}
			if got, _, _ := be.bySource(t, be.count()); len(got) != 1 {
				t.Errorf("后端看到 %d 个源地址，期望 1 个（一个会话）", len(got))
			}
			expectNoWarn(t, m)
		})
	}
}

// 行为 7：一次回程发出里有多个客户端、多条规则。规则 1 监听 0.0.0.0，客户端发往 127.0.0.2/.3/.4/.1；规则 2 监听 [::]，v4 映射客户端发往
// .3/.4、IPv6 客户端从 ::1 发往 lo 上加的 fd00 地址与 ::1；规则 3 绑具体地址 127.0.0.5（对照）。暂停期间三个后端交错给 10 个会话各排 6 个
// 长度各异的回包（60 个，一次发出，按规则分组），恢复后每个客户端按序、逐字节收到自己的回包，都来自它发往的地址；每条规则的 down_pkts、
// down_bytes 精确，没有丢包、warn 与回退行。hello-sequential 逐个建会话；hello-batched 在暂停期间把各规则的 hello 排进各自的监听
// socket，会话都在一批里新建（规则 2 的批里 v4 映射与 IPv6 客户端混在一起），每个会话记下的是它自己那个槽的目的地址
func TestUDPPktinfoMultiFlush(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"hello-sequential", "hello-batched"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			batched := mode == "hello-batched"
			if batched {
				singleWorkerOnly(t, "暂停期间排进监听 socket 的包按队列里的位置分批（queueListen）")
			}
			sub := lo6Sub(t, 1)
			type rule struct {
				listen string
				be     *udpRecorder
			}
			rules := []rule{
				{hostPort("0.0.0.0", freePort(t)), quietUDP(t, loopback4(t))},
				{hostPort("::", freePort(t)), quietUDP(t, hostPort("::1", freePort(t)))},
				{hostPort("127.0.0.5", freePort(t)), quietUDP(t, loopback4(t))},
			}
			var cfg strings.Builder
			var wait []listenPoint
			for _, r := range rules {
				fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", r.listen, r.be.addr)
				wait = append(wait, listenPoints("u", portOf(r.listen))...)
			}
			m := startMapper(t, wait, "-c", writeConfig(t, cfg.String()))

			type client struct {
				rule    int
				c       *net.UDPConn
				target  netip.AddrPort
				hello   []byte
				session string
				want    [][]byte
			}
			var clients []*client
			for ci, s := range []struct {
				rule          int
				local, target string
			}{
				{0, "127.0.0.1", "127.0.0.2"}, {0, "127.0.0.1", "127.0.0.3"}, {0, "127.0.0.1", "127.0.0.4"}, {0, "127.0.0.1", "127.0.0.1"},
				{1, "127.0.0.1", "127.0.0.3"}, {1, "::1", "$1"}, {1, "127.0.0.1", "127.0.0.4"}, {1, "::1", "::1"},
				{2, "127.0.0.1", "127.0.0.5"}, {2, "127.0.0.3", "127.0.0.5"},
			} {
				clients = append(clients, &client{
					rule:   s.rule,
					c:      srcClient(t, sub(s.local)),
					target: netip.AddrPortFrom(netip.MustParseAddr(sub(s.target)), uint16(portOf(rules[s.rule].listen))),
					hello:  fmt.Appendf(nil, "hello-r%d-c%d", s.rule, ci),
				})
			}
			if batched {
				m.pause(t)
				for r, rl := range rules {
					var mine []*client
					for _, cl := range clients {
						if cl.rule == r {
							mine = append(mine, cl)
						}
					}
					queueListen(t, m, rl.listen, len(mine), func(i int) int { return len(mine[i].hello) }, func(i int) error {
						_, err := mine[i].c.WriteToUDPAddrPort(mine[i].hello, mine[i].target)
						return err
					})
				}
				m.resume(t)
				for _, cl := range clients {
					cl.session = sessionOf(t, rules[cl.rule].be, cl.hello)
				}
			} else {
				for _, cl := range clients {
					cl.session = helloSession(t, rules[cl.rule].be, cl.hello, sendTo(cl.c, cl.target))
				}
			}
			var replies []udpReply
			for seq := range 6 {
				for ci, cl := range clients {
					msg := fmt.Appendf(nil, "r%d-c%02d-s%d-", cl.rule, ci, seq)
					for j := range (ci*7 + seq*11) % 40 {
						msg = append(msg, byte('a'+(ci+j)%26))
					}
					replies = append(replies, udpReply{rules[cl.rule].be, cl.session, msg})
					cl.want = append(cl.want, msg)
				}
			}
			m.pause(t)
			queueReplies(t, m, replies)
			m.resume(t)
			for ci, cl := range clients {
				expectFrom(t, cl.c, cl.want, cl.target, fmt.Sprintf("规则 %d 发往 %s 的客户端 %d ", cl.rule+1, cl.target, ci))
			}
			d := m.statsAfterSignal(t)
			for r, rl := range rules {
				var want [][]byte
				nc := 0
				for _, cl := range clients {
					if cl.rule == r {
						want = append(want, cl.want...)
						nc++
					}
				}
				s := d.udp[r+1]
				if s.sessions != nc || int(s.total) != nc {
					t.Errorf("规则 %d 统计 sessions=%d total=%d，期望 %d/%d", r+1, s.sessions, s.total, nc, nc)
				}
				if s.downPkts != uint64(len(want)) || s.downBytes != totalLen(want) || s.downDrop != 0 {
					t.Errorf("规则 %d 统计 down_pkts=%d down_bytes=%d down_drop=%d，期望 %d/%d/0", r+1, s.downPkts, s.downBytes, s.downDrop, len(want), totalLen(want))
				}
				if s.upPkts != uint64(rl.be.count()) || s.upDrop != 0 {
					t.Errorf("规则 %d 统计 up_pkts=%d up_drop=%d，期望 %d/0（hello）", r+1, s.upPkts, s.upDrop, rl.be.count())
				}
			}
			if l := phraseLines(m, pktinfoFallbackPhrase); len(l) != 0 {
				t.Errorf("日志里有 %d 行源地址回退，期望没有：%q", len(l), l[0])
			}
			expectNoWarn(t, m)
		})
	}
}

// D90，真实内核的 EINVAL：[::] 监听，客户端从 lo 上的 fd00 地址 cli 发往另一个 fd00 地址 srv。地址还在时回包来自 srv；暂停期间后端排好
// 两个回包、测试删掉 srv，恢复后带 IPV6_PKTINFO{srv} 的发送报 EINVAL，tinymapper 去掉源地址重发，没有 connect 的客户端照样收到（源地址由
// 内核选，不再是 srv），恰好一行 info。会话记下的地址随之清掉：客户端再发包之前后端的回包直接由内核选源，不再失败（回退行数不变）。加回 srv、
// 客户端再发往它之后，回包又来自 srv。统计 down_pkts=5、down_drop=0，没有 warn
func TestUDPPktinfoFallbackAddrRemoved(t *testing.T) {
	t.Parallel()
	addrs := newLoAddrs6(t, 2)
	cli, srv := addrs[0], addrs[1]
	be := quietUDP(t, hostPort("::1", freePort(t)))
	lport := freePort(t)
	m := startMapper(t, listenPoints("u", lport), "-l", hostPort("::", lport), "-r", be.addr, "-u", "--log-level", "5")
	c := srcClient(t, cli.String())
	target := netip.AddrPortFrom(srv, uint16(lport))
	session := helloSession(t, be, []byte("hello"), sendTo(c, target))
	var sent [][]byte
	reply := func(i int) []byte {
		msg := fmt.Appendf(nil, "reply-%d", i)
		sent = append(sent, msg)
		return msg
	}
	expectKernelSrc := func(want []byte, who string) {
		t.Helper()
		got, from := readReply(t, c, who)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s收到 %q，期望 %q", who, got, want)
		}
		if from.Addr() == srv || from.Port() != uint16(lport) {
			t.Errorf("%s的回包 %q 来自 %s，期望来自端口 %d、源地址由内核选（%s 已删）", who, want, from, lport, srv)
		}
		t.Logf("%s的回包 %q 来自 %s", who, want, from)
	}

	r0 := reply(0)
	be.sendTo(t, session, r0)
	expectFrom(t, c, [][]byte{r0}, target, "删地址之前的客户端")
	if t.Failed() {
		t.FailNow()
	}
	m.pause(t)
	r1, r2 := reply(1), reply(2)
	queueReplies(t, m, []udpReply{{be, session, r1}, {be, session, r2}})
	if err := setLoAddr6(false, srv); err != nil {
		t.Fatalf("删掉 lo 上的 %s 失败：%v", srv, err)
	}
	m.resume(t)
	expectKernelSrc(r1, "删地址之后的客户端")
	expectKernelSrc(r2, "删地址之后的客户端")
	m.statsAfterSignal(t)
	n1 := expectFallbackLog(t, m, 1)

	r3 := reply(3)
	be.sendTo(t, session, r3)
	expectKernelSrc(r3, "客户端再发包之前")
	m.statsAfterSignal(t)
	if n := len(phraseLines(m, pktinfoFallbackPhrase)); n != n1 {
		t.Errorf("客户端再发包之前的回包又走了 %d 次回退：会话记下的地址没有清掉", n-n1)
	}

	if err := setLoAddr6(true, srv); err != nil {
		t.Fatalf("把 %s 加回 lo 失败：%v", srv, err)
	}
	waitLoAddr6(t, srv)
	if s := helloSession(t, be, []byte("hello-again"), sendTo(c, target)); s != session {
		t.Errorf("客户端再发包时后端看到新的源地址 %s（原来是 %s）：新建了会话", s, session)
	}
	r4 := reply(4)
	be.sendTo(t, session, r4)
	expectFrom(t, c, [][]byte{r4}, target, "地址加回、客户端再发包之后")

	s := m.statsAfterSignal(t).udp[1]
	if s.sessions != 1 || s.total != 1 || s.downPkts != uint64(len(sent)) || s.downBytes != totalLen(sent) || s.downDrop != 0 {
		t.Errorf("统计 sessions=%d total=%d down_pkts=%d down_bytes=%d down_drop=%d，期望 1/1/%d/%d/0（重发的回包计入 down_pkts，不计 down_drop）",
			s.sessions, s.total, s.downPkts, s.downBytes, s.downDrop, len(sent), totalLen(sent))
	}
	if s.upPkts != uint64(be.count()) || s.upDrop != 0 {
		t.Errorf("统计 up_pkts=%d up_drop=%d，期望 %d/0", s.upPkts, s.upDrop, be.count())
	}
	expectFallbackLog(t, m, 1)
	expectNoWarn(t, m)
}

// D88 + D90，IPv4 广播目的：tun 设备（10.55.n.1/24，子网广播路由由内核自动加）上，客户端开 SO_BROADCAST 发往 10.55.n.255，本机发出的
// 广播经 ip_mc_output 回环一份给本机的通配监听。dualstack：[::] 只开 IPV6_RECVPKTINFO，v4 包的 ipi6_addr 是目的地址（广播地址）而不是
// spec_dst，以它作源发送报 ENETUNREACH（5.4 起；更早为 EINVAL），走回退，客户端收到来自 10.55.n.1 的回包，恰好一行 info；ipv4：0.0.0.0 用
// ipi_spec_dst（10.55.n.1），回包直接来自它，没有回退行。广播交给 reuseport 组里的每个 socket（__udp4_lib_mcast_deliver 不按哈希选），
// 所以 --threads 1。两个广播都要收到回显，统计 sessions=total=1、down_drop=0
func TestUDPPktinfoFallbackBroadcast(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, listen string
		fallback     bool
	}{{"dualstack", "::", true}, {"ipv4", "0.0.0.0", false}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newTun(t, 1500)
			be := recordUDP(t, loopback4(t))
			lport := freePort(t)
			m := startMapper(t, listenPoints("u", lport), "-l", hostPort(c.listen, lport), "-r", be.addr, "-u", "--threads", "1", "--log-level", "5")
			cl, err := net.ListenUDP("udp4", &net.UDPAddr{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cl.Close() })
			setBroadcast(t, cl)
			bcast := netip.AddrPortFrom(d.peer(255), uint16(lport))
			want := netip.AddrPortFrom(d.local, uint16(lport))
			for i := range 2 {
				from, err := echoVia(cl, bcast, fmt.Appendf(nil, "bcast-%d", i))
				if err != nil {
					t.Fatalf("发往 %s 的第 %d 个广播没有回显：%v", bcast, i, err)
				}
				if from != want {
					t.Errorf("第 %d 个广播的回包来自 %s，期望来自 %s", i, from, want)
				}
			}
			var s udpStat
			eventually(t, ioTimeout, 50*time.Millisecond, func() error {
				s = m.statsAfterSignal(t).udp[1]
				if s.upPkts != uint64(be.count()) || s.downPkts != s.upPkts {
					return fmt.Errorf("统计 up_pkts=%d down_pkts=%d，期望都等于后端收到并回显的 %d 个", s.upPkts, s.downPkts, be.count())
				}
				return nil
			})
			if s.sessions != 1 || s.total != 1 || s.upDrop != 0 || s.downDrop != 0 {
				t.Errorf("统计 sessions=%d total=%d up_drop=%d down_drop=%d，期望 1/1/0/0", s.sessions, s.total, s.upDrop, s.downDrop)
			}
			if c.fallback {
				expectFallbackLog(t, m, 1)
			} else if l := phraseLines(m, pktinfoFallbackPhrase); len(l) != 0 {
				t.Errorf("0.0.0.0 监听应以 ipi_spec_dst 作源、不走回退，日志里却有 %d 行：%q", len(l), l[0])
			}
			expectNoWarn(t, m)
		})
	}
}

// D90，注入的 EINVAL：0.0.0.0 监听，客户端从 127.0.0.1 发往 127.0.0.2。seccomp 用户态通知让监听 socket 上的第一次发送（带 PKTINFO 的
// 回包）返回 EINVAL，之后照常：tinymapper 去掉源地址重发，客户端收到来自 127.0.0.1（内核选的源）的回包；会话记下的地址清掉，客户端再发包
// 之前的回包也来自 127.0.0.1、不再走回退；客户端再发往 .2 之后回包又来自 .2。gro：失败的是带 UDP_SEGMENT 与 PKTINFO 的合并回包（5 段），
// 重发仍是同样段长的合并包，down_gso_fallback=0（修复前 EINVAL 被当成 GSO 本身的错误，关掉 GSO 逐个数据报重发）。恰好一行 info 的回退行，
// 没有 GSO 回退行与 warn，down_drop=0
func TestUDPPktinfoFallbackInjected(t *testing.T) {
	t.Parallel()
	for _, gro := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "gro"}[gro], func(t *testing.T) {
			t.Parallel()
			be := newGRORecorder(t, loopback4(t), gro)
			lport := freePort(t)
			args := []string{"-l", hostPort("0.0.0.0", lport), "-r", be.addr, "-u", "--log-level", "5"}
			if gro {
				args = append(args, "--udp-gro")
			}
			m, n := startMapperSendNotify(t, listenPoints("u", lport), args...)
			lo, hi := listenFDRange(t, m.pid(), "udp", lport)
			target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(lport))
			kernelSrc := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(lport))
			cl := newGROClient(t, "127.0.0.1", target.String())
			send := func(b []byte) error { return cl.send(gsoPkt{b, 0}) }
			session := helloGRO(t, be, []byte("hello"), send)

			var injected atomic.Int32
			n.setDecide(func(c notifyCall) syscall.Errno {
				if isSendNR(c.nr) && c.fd(0) >= lo && c.fd(0) < hi && injected.CompareAndSwap(0, 1) {
					return syscall.EINVAL
				}
				return 0
			})
			r1 := gsoPkt{[]byte("reply-1"), 0}
			if gro {
				r1 = gsoPkt{gsoData(1, 4500), 1000}
			}
			r2, r3 := gsoPkt{[]byte("reply-2-before-client-sends"), 0}, gsoPkt{[]byte("reply-3-after-client-sends"), 0}
			be.sendTo(t, session, r1)
			expectGROFrom(t, cl.c, r1.forwarded(), kernelSrc, "注入 EINVAL 之后的客户端")
			if v := injected.Load(); v != 1 {
				t.Fatalf("监听 socket 上的发送注入了 %d 次 EINVAL，期望 1 次（用例前提）", v)
			}
			be.sendTo(t, session, r2)
			expectGROFrom(t, cl.c, r2.forwarded(), kernelSrc, "客户端再发包之前")
			if s := helloGRO(t, be, []byte("hello-again"), send); s != session {
				t.Errorf("客户端再发包时后端看到新的源地址 %s（原来是 %s）：新建了会话", s, session)
			}
			be.sendTo(t, session, r3)
			expectGROFrom(t, cl.c, r3.forwarded(), target, "客户端再发包之后")

			downN, downBytes, downMerged := gsoTotals([]gsoPkt{r1, r2, r3})
			s := m.statsAfterSignal(t).udp[1]
			if s.downPkts != downN || s.downBytes != downBytes || s.downDrop != 0 || s.sessions != 1 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d sessions=%d，期望 %d/%d/0/1（重发的回包计入 down_pkts，不计 down_drop）",
					s.downPkts, s.downBytes, s.downDrop, s.sessions, downN, downBytes)
			}
			if s.upPkts != uint64(be.count()) || s.upDrop != 0 {
				t.Errorf("统计 up_pkts=%d up_drop=%d，期望 %d/0", s.upPkts, s.upDrop, be.count())
			}
			if gro && (s.downGRO != downMerged || s.downGSOFallback != 0 || s.upGSOFallback != 0) {
				t.Errorf("统计 down_gro=%d down_gso_fallback=%d up_gso_fallback=%d，期望 %d/0/0（PKTINFO 的 EINVAL 不是 GSO 本身的错误）",
					s.downGRO, s.downGSOFallback, s.upGSOFallback, downMerged)
			}
			if total := expectFallbackLog(t, m, 1); total != 1 {
				t.Errorf("日志里有 %d 行源地址回退，期望 1 行：只有注入的那次失败，之后的回包不带 PKTINFO 或已经成功", total)
			}
			if l := gsoFallbackLines(m, "listen"); len(l) != 0 {
				t.Errorf("日志里有 %d 行监听 socket 的 GSO 回退：%q", len(l), l[0])
			}
			expectNoWarn(t, m)
		})
	}
}

// 行为 6：开不了 IP_PKTINFO / IPV6_RECVPKTINFO（seccomp 让 setsockopt 返回 ENOPROTOOPT）时每条规则一行 warn，该规则照旧由内核选源、照常
// 转发。三条规则：0.0.0.0、[::]（v4 映射客户端）与绑具体地址的 127.0.0.5，客户端从 127.0.0.1 发往 .2、.3、.5。all：两条通配规则的每个
// 监听 socket 都失败，两行 warn（M2：每个 worker 一个监听 socket，仍是每条规则一行），它们的回包来自 127.0.0.1；second-rule：只有规则 2
// 的失败，一行 warn，规则 1 的回包照常来自 .2。规则 3 不设这两个选项，始终来自 .5。没有回退行
func TestUDPPktinfoSetsockoptFail(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"all", "second-rule"} {
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			type rule struct {
				listen        string
				be            *udpRecorder
				local, target string
			}
			rules := []rule{
				{hostPort("0.0.0.0", freePort(t)), recordUDP(t, loopback4(t)), "127.0.0.1", "127.0.0.2"},
				{hostPort("::", freePort(t)), recordUDP(t, loopback4(t)), "127.0.0.1", "127.0.0.3"},
				{hostPort("127.0.0.5", freePort(t)), recordUDP(t, loopback4(t)), "127.0.0.1", "127.0.0.5"},
			}
			var cfg strings.Builder
			var wait []listenPoint
			for _, r := range rules {
				fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", r.listen, r.be.addr)
				wait = append(wait, listenPoints("u", portOf(r.listen))...)
			}
			args := []string{"-c", writeConfig(t, cfg.String())}
			lo, hi := 0, 0
			failing := []bool{true, true, false}
			if c == "second-rule" {
				probe := startMapper(t, wait, args...)
				lo, hi = listenFDRange(t, probe.pid(), "udp", portOf(rules[1].listen)) // M2：规则 2 在每个 worker 上的监听 socket 都失败
				probe.stop(t, false)
				failing = []bool{false, true, false}
			}
			m := startMapperPktinfoFail(t, lo, hi, wait, args...)
			nFail := 0
			for r, rl := range rules {
				target := netip.AddrPortFrom(netip.MustParseAddr(rl.target), uint16(portOf(rl.listen)))
				want := target
				if failing[r] {
					nFail++
					want = netip.AddrPortFrom(netip.MustParseAddr(rl.local), target.Port())
				}
				from, err := echoVia(srcClient(t, rl.local), target, fmt.Appendf(nil, "rule-%d", r+1))
				switch {
				case err != nil:
					t.Errorf("规则 %d（%s → %s）不转发了：%v", r+1, rl.local, target, err)
				case from != want:
					t.Errorf("规则 %d（%s → %s）的回包来自 %s，期望来自 %s", r+1, rl.local, target, from, want)
				}
			}
			d := m.statsAfterSignal(t)
			for r := range rules {
				if s := d.udp[r+1]; s.sessions != 1 || s.upDrop != 0 || s.downDrop != 0 {
					t.Errorf("规则 %d 统计 sessions=%d up_drop=%d down_drop=%d，期望 1/0/0", r+1, s.sessions, s.upDrop, s.downDrop)
				}
			}
			var lines []string
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				if lines = phraseLines(m, pktinfoSetFailPhrase); len(lines) < nFail {
					return fmt.Errorf("日志里有 %d 行开不了 PKTINFO 的 warn，期望 %d", len(lines), nFail)
				}
				return nil
			})
			if len(lines) != nFail {
				t.Errorf("日志里有 %d 行开不了 PKTINFO 的 warn，期望 %d（每条失败的规则一行）：\n%s", len(lines), nFail, strings.Join(lines, "\n"))
			}
			for _, l := range lines {
				if !strings.Contains(l, "[WARN]") {
					t.Errorf("开不了 PKTINFO 的行不是 warn：%q", l)
				}
			}
			if l := phraseLines(m, pktinfoFallbackPhrase); len(l) != 0 {
				t.Errorf("日志里有 %d 行源地址回退，期望没有：%q", len(l), l[0])
			}
		})
	}
}
