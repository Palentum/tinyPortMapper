package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// 各种包长（含大于 MTU 的包）原样往返
func TestUDPSizes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		host  string
		sizes []int
	}{
		{"127.0.0.1", []int{1, 64, 1472, 9000, 65507}},
		{"::1", []int{1, 64, 1452, 9000, 65527}},
	} {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			be := serveUDP(t, hostPort(c.host, freePort(t)), "")
			listen := hostPort(c.host, freePort(t))
			forward(t, "u", listen, be.addr)
			conn := udpDial(t, "", listen)
			for _, size := range c.sizes {
				msg := bytes.Repeat([]byte{byte(size)}, size)
				for i := range msg {
					msg[i] ^= byte(i * 31)
				}
				got, err := udpRoundTrip(conn, msg)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, msg) {
					t.Fatalf("%d 字节包回包不一致（收到 %d 字节）", size, len(got))
				}
			}
		})
	}
}

// 多客户端并发收发：每个客户端只收到自己的回包，上游为每个客户端建立独立会话
func TestUDPSessionIsolation(t *testing.T) {
	t.Parallel()
	const clients, packets = 16, 50
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	forward(t, "u", listen, be.addr)
	conns := make([]*net.UDPConn, clients)
	for i := range conns {
		conns[i] = udpDial(t, "", listen)
	}
	errs := make([]error, clients)
	parallelFor(clients, clients, func(i int) {
		for j := range packets {
			msg := fmt.Appendf(nil, "client-%02d-seq-%03d", i, j)
			got, err := udpRoundTrip(conns[i], msg)
			if err == nil && !bytes.Equal(got, msg) {
				err = fmt.Errorf("收到 %q，期望 %q", got, msg)
			}
			if err != nil {
				errs[i] = fmt.Errorf("客户端 %d 第 %d 个包：%w", i, j, err)
				return
			}
		}
	})
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if peers := be.peerList(); len(peers) != clients {
		t.Errorf("上游看到 %d 个源地址，期望每个客户端一个（%d）：%v", len(peers), clients, peers)
	}
}

// 上游端口无人监听（T14）：会话 socket 是 connect 过的 UDP socket，收到 ICMP 端口不可达后内核置 sk_err，epoll 只报 EPOLLERR（会话只登记了读，
// 接收队列为空，没有 EPOLLIN）。libev 的 epoll_poll 要把它当作 fd 想要的读事件交给 udp_cb，由 recv 取走错误；丢了 ERR/HUP 的映射时回调不会
// 被调用，水平触发的 EPOLLERR 每轮都报，事件循环空转到下一次 sendto 取走错误为止（那个包随之丢掉）。TCP 测不出这一映射：tcp_done 把
// sk_shutdown 置为 SHUTDOWN_MASK，此后 tcp_poll 报 ERR/HUP 时总同时报 EPOLLIN 与 EPOLLOUT，登记过的那一位照常到达。
// 之后上游开始监听，同一会话照常转发
func TestUDPRemoteRefused(t *testing.T) {
	t.Parallel()
	remote, listen := loopback4(t), loopback4(t)
	m := forward(t, "u", listen, remote)
	c := udpDial(t, "", listen)
	probe := []byte("to-closed-port")
	if _, err := c.Write(probe); err != nil {
		t.Fatal(err)
	}
	// 日志最多晚一个 timer_interval（400 ms）写出；每次没查到就再发一个（ICMP 有全局限速，偶尔会被丢）
	eventually(t, ioTimeout, 500*time.Millisecond, func() error {
		if m.logLines("[udp]recv failed", "Connection refused") != 0 {
			return nil
		}
		c.Write(probe)
		return errors.New("日志里没有会话 socket 的 recv 失败（ECONNREFUSED）：EPOLLERR 没有交给 udp_cb")
	})
	m.expectIdleCPU(t, "会话 socket 收到 ICMP 端口不可达之后（EPOLLERR）")
	serveUDP(t, remote, "late:")
	if prefix := udpReplyFrom(t, c, "after-listen"); prefix != "late:" {
		t.Fatalf("回包前缀 %q，期望 %q", prefix, "late:")
	}
}

// 空闲超过 conn_timeout_udp（180 s）的会话被清理，期间保持活跃的会话不受影响；
// 被清理的客户端再发包时，tinymapper 为它新建会话，上游看到新的源地址。
// 清理每轮最多关 1 条、约 1.2 s 一轮：活跃会话若也超时了（LRU 没把它挪到队首，或挪动时没刷新时间戳），
// 可能比空闲会话晚一轮才被清理，所以空闲会话被清理后再等 5 s 才检查活跃会话。
// 约 60 s 保活后再建一个之后不发包的会话 late：LRU 若把新会话挂在表尾，它会挡住空闲会话，直到它自己也超时（约 240 s）。
// 建 late 之后不再保活（活跃会话检查时空闲约 125 s，仍未超时）：否则活跃会话挪到 late 前面，
// 挪动时不刷新时间戳的错误实现里活跃会话的过期会被 late 挡住
func TestUDPSessionTimeout(t *testing.T) {
	t.Parallel()
	slow(t)
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	m := forward(t, "u", listen, be.addr)
	idle := udpDial(t, "", listen)
	active := udpDial(t, "", listen)
	roundTrip := func(c *net.UDPConn, msg string) {
		t.Helper()
		if _, err := udpRoundTrip(c, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	cleared := func(c *net.UDPConn) bool {
		data, _ := os.ReadFile(m.logPath)
		return strings.Contains(string(data), fmt.Sprintf("inactive connection {%s} cleared", c.LocalAddr()))
	}
	roundTrip(active, "active")
	roundTrip(idle, "idle")
	last := time.Now()
	keepalive := last
	var late *net.UDPConn
	for !cleared(idle) {
		if elapsed := time.Since(last); elapsed > 210*time.Second {
			t.Fatalf("空闲 %v 后会话仍未被清理（超时应为 180 s）", elapsed.Round(time.Second))
		}
		if late == nil && time.Since(keepalive) >= 30*time.Second {
			roundTrip(active, "keepalive")
			keepalive = time.Now()
			if keepalive.Sub(last) >= 60*time.Second {
				late = udpDial(t, "", listen)
				roundTrip(late, "late")
			}
		}
		time.Sleep(time.Second)
	}
	elapsed := time.Since(last)
	t.Logf("空闲会话在 %v 后被清理", elapsed.Round(time.Second))
	if elapsed < 170*time.Second {
		t.Errorf("空闲会话过早被清理：%v（超时应为 180 s）", elapsed.Round(time.Second))
	}
	time.Sleep(5 * time.Second)
	if cleared(active) {
		t.Error("保持活跃的会话也被清理了")
	}
	roundTrip(active, "after")
	roundTrip(idle, "after")
	roundTrip(late, "after")
	if peers := be.peerList(); len(peers) != 4 {
		t.Errorf("上游源地址 %v，期望 4 个：活跃客户端 1 个，空闲客户端清理前后各 1 个，后建的客户端 1 个", peers)
	}
}

// 只有上行流量的会话（后端从不回包，如 syslog、指标上报）全靠入向路径上的 lru.update 刷新空闲时间（U3 起它在按会话分组发送的
// 循环里；回程的 udp_cb 也刷新，所以往返流量测不出漏掉的入向刷新）。每 15 s 发一个包、持续 200 s，超过 conn_timeout_udp（180 s）：
// 会话不能被当作空闲清理，后端始终只看到一个源地址、收到全部的包
func TestUDPSessionOneWay(t *testing.T) {
	t.Parallel()
	slow(t)
	ua, err := net.ResolveUDPAddr("udp", loopback4(t))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp", ua) // 只收不回
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	var mu sync.Mutex
	peers := map[string]int{}
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := sink.ReadFromUDP(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err == nil {
				mu.Lock()
				peers[from.String()]++
				mu.Unlock()
			}
		}
	}()
	listen := loopback4(t)
	m := forward(t, "u", listen, sink.LocalAddr().String())
	c := udpDial(t, "", listen)
	sent := 0
	for start := time.Now(); time.Since(start) < 200*time.Second; sent++ {
		if _, err := fmt.Fprintf(c, "oneway-%d", sent); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Second)
	}
	m.fatalIfExited(t, "单向发送 200 s 后")
	if n := m.logLines("[udp]inactive connection", "cleared"); n != 0 {
		t.Errorf("日志里有 %d 行会话清理：只有上行流量的会话被当作空闲清理了（入向没有刷新 LRU）", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(peers) != 1 {
		t.Errorf("后端看到源地址 %v，期望只有一个会话", peers)
	}
	for p, n := range peers {
		if n != sent {
			t.Errorf("后端从 %s 收到 %d 个包，期望 %d", p, n, sent)
		}
	}
}

// C9：UDP 会话 socket 加进 epoll 失败时 udp_cb 收到 EV_ERROR，只释放这个会话；修复前 assert(0==1) 使整个进程中止。UDP 单规则
// 启动后 tinymapper 有 n 个 fd，k 个正常会话占 n..n+k-1，让 fd ≥ n+k 的 ADD 失败：新客户端的会话 socket 拿到 n+k，首包已由
// udp_accept_cb 发给后端，回包却没人读，客户端收不到；EV_ERROR 回调后会话被释放（inactive connection … cleared），fd 号空出。
// 客户端的下一个包重新建会话、再次失败：每次尝试各一行 new connection、warn 与 cleared，warn 中是会话的 fd，cleared 的下一行
// lru.size() 为 k，fd 数回到 n+k，进程不退出，k 个正常会话不受影响
func TestUDPEpollAddFail(t *testing.T) {
	t.Parallel()
	const k, attempts = 3, 4
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	wait := listenPoints("u", portOf(listen))
	args := []string{"-l", listen, "-r", be.addr, "-u", "--log-level", "5"}
	n := startupFDs(t, wait, args...)
	m := startMapperEpollAddFail(t, n+k, 0, wait, args...)
	healthy := make([]*net.UDPConn, k)
	for i := range healthy {
		healthy[i] = udpDial(t, "", listen)
		udpReplyFrom(t, healthy[i], fmt.Sprintf("healthy-%d", i))
	}
	if got := fdCount(t, m.pid()); got != n+k {
		t.Fatalf("%d 个正常会话之后 tinymapper 有 %d 个 fd，期望 %d", k, got, n+k)
	}

	bad := udpDial(t, "", listen)
	addr := fmt.Sprintf("{%s}", bad.LocalAddr())
	warn := fmt.Sprintf("[udp]connection %s closed bc of EV_ERROR (epoll_ctl failed),udp fd=%d", addr, n+k)
	buf := make([]byte, 100)
	for i := 1; i <= attempts; i++ {
		if _, err := fmt.Fprintf(bad, "lost-%d", i); err != nil {
			t.Fatal(err)
		}
		eventually(t, everrorWithin+logFlushWithin, 10*time.Millisecond, func() error {
			m.fatalIfExited(t, "第 %d 次尝试后", i)
			for _, s := range []string{"[udp]new connection from " + addr + ",udp fd=", warn, "[udp]inactive connection " + addr + " cleared"} {
				if got := m.logLines(s); got != i {
					return fmt.Errorf("日志中有 %d 行含 %q，期望 %d（每次尝试新建并释放一个会话）", got, s, i)
				}
			}
			if got := fdCount(t, m.pid()); got != n+k {
				return fmt.Errorf("tinymapper 有 %d 个 fd，期望 %d：失败的会话 fd 没有关闭", got, n+k)
			}
			return nil
		})
		// 会话已释放：后端的回包留在会话 socket 里，随 close 丢弃
		bad.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if nr, err := bad.Read(buf); err == nil {
			t.Errorf("第 %d 次尝试收到回包 %q：会话 socket 没有加进 epoll，回包不应被转发", i, buf[:nr])
		}
	}
	for i, c := range healthy {
		udpReplyFrom(t, c, fmt.Sprintf("still-alive-%d", i))
	}

	data, err := os.ReadFile(m.logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.Contains(line, "[udp]inactive connection ") {
			next := ""
			if i+1 < len(lines) {
				next = lines[i+1]
			}
			if !strings.HasSuffix(line, fmt.Sprintf("udp connections=%d", k)) || !strings.HasSuffix(next, fmt.Sprintf("[udp] lru.size()=%d", k)) {
				t.Errorf("%q 与下一行 %q：释放失败的会话后应剩 %d 个会话，lru.size() 相同", line, next, k)
			}
		}
	}
}

// C9：UDP 监听 socket 加进 epoll 失败（启动时的 ADD）时 udp_accept_cb 收到 EV_ERROR 后返回，clear_timer_cb 每 400 ms 重新 start
// 这个 watcher（与 C6 的 TCP 监听相同），下一轮 fd_reify 再试 ADD。只让 UDP 监听 fd 的 ADD 失败：进程不退出（修复前 assert 中止），
// 每个定时器周期一行 warn，2 s 内至少 2 行说明在重试（不重新 start 时只有启动后的 1 行），不超过 10 行、CPU 不超过 10% 说明没有
// 空转；同一规则的 TCP 照常转发，UDP 包没有回应。这里 ADD 一直失败；ADD 恢复成功后 UDP 转发恢复，由 build/c9/ 中的 strace 脚本验证
func TestUDPEpollAddFailListener(t *testing.T) {
	t.Parallel()
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	serveUDP(t, remote, "")
	listen := loopback4(t)
	wait := listenPoints("tu", portOf(listen))
	args := []string{"-l", listen, "-r", remote, "-t", "-u"}
	probe := startMapper(t, wait, args...)
	fd := listenFD(probe.pid(), "udp", portOf(listen))
	probe.stop(t, false)
	if fd < 0 {
		t.Fatal("探测时没有找到 UDP 监听 socket")
	}
	m := startMapperEpollAddFail(t, fd, fd+1, wait, args...)
	if got := listenFD(m.pid(), "udp", portOf(listen)); got != fd {
		t.Fatalf("注入故障后 UDP 监听 socket 的 fd 为 %d，探测时为 %d", got, fd)
	}
	warn := fmt.Sprintf("[udp]accept watcher of listen fd %d got EV_ERROR", fd)
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		m.fatalIfExited(t, "UDP 监听 fd 加进 epoll 失败后")
		if m.logLines("[WARN]", warn) == 0 {
			return errors.New("日志中没有 UDP 监听 watcher 的 EV_ERROR warn：故障注入没有生效")
		}
		return nil
	})
	start := time.Now()
	ticks0, warns0 := m.cpuTicks(t), m.logLines(warn)
	mustEcho(t, dial(t, listen), "tcp")
	u := udpDial(t, "", listen)
	u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := u.Write([]byte("udp")); err != nil {
		t.Fatal(err)
	}
	if nr, err := u.Read(make([]byte, 100)); err == nil {
		t.Errorf("UDP 监听 fd 不在 epoll 中，却收到 %d 字节回包", nr)
	}
	time.Sleep(2*time.Second - time.Since(start))
	ticks, warns := m.cpuTicks(t)-ticks0, m.logLines(warn)-warns0
	m.fatalIfExited(t, "UDP 监听 fd 的 ADD 失败 2 s 后")
	t.Logf("UDP 监听 fd %d 的 ADD 一直失败的 2 s：CPU %.2f s，%d 行 warn", fd, float64(ticks)/100, warns)
	// warn 由 400 ms 的定时器写出，两次读数各偏移不到一个周期，2 s 内约 5 行
	if warns < 2 {
		t.Errorf("2 s 内只有 %d 行 warn：clear_timer_cb 没有重新 start UDP 监听 watcher，ADD 不再重试", warns)
	}
	if warns > 10 {
		t.Errorf("2 s 内有 %d 行 warn：UDP 监听 watcher 的重试在空转", warns)
	}
	// 时钟滴答为 1/100 s：2 s 内超过 20 个即 CPU 占用 >10%
	if ticks > 20 {
		t.Errorf("UDP 监听 fd 的 ADD 失败期间空转：2 s 内消耗 CPU %.2f s", float64(ticks)/100)
	}
}

// udpTry 发送 msg 并返回回包，超时则重发，最多 attempts 次。整条测试套件并行时环回偶有丢包，
// 重发只是重走同一客户端：首包已建会话时命中既有会话、不新建，故不影响 total/会话数/后端源地址集等不变式。
func udpTry(c *net.UDPConn, msg []byte, per time.Duration, attempts int) ([]byte, error) {
	buf := make([]byte, 2048)
	var last error
	for i := 0; i < attempts; i++ {
		c.SetReadDeadline(time.Now().Add(per))
		if _, err := c.Write(msg); err != nil {
			return nil, err
		}
		n, err := c.Read(buf)
		if err == nil {
			return append([]byte(nil), buf[:n]...), nil
		}
		last = err
		if !isTimeout(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("重发 %d 次仍超时：%w", attempts, last)
}

// udpEcho 发送 msg，要求回包与 msg 完全一致（后端前缀为空），到达的是本客户端自己的 socket。
func udpEcho(t testing.TB, c *net.UDPConn, msg []byte) {
	t.Helper()
	got, err := udpTry(c, msg, 2*time.Second, 4)
	if err != nil {
		t.Fatalf("往返 %q 失败：%v", msg, err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("回包 %q 与请求 %q 不一致：会话串了或查找查错了", got, msg)
	}
}

// 大量会话：顺序建立（跨越多个扩容阈值）、交替轮转（每次查找都错过 last_hit）、每客户端连发突发（命中 last_hit）。
// 每个回包必须等于请求并落到正确的客户端 socket；后端恰好看到 N 个不同源地址；全部阶段后 sessions==N、total==N（无重复会话），
// 池不变式成立。会话表从 64 槽起按需翻倍：第 49/97/193/385/769 个会话触发扩容。
func TestUDPManySessions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name           string
		listen, client string
		backend        string
		n              int
	}{
		{"ipv4", "127.0.0.1", "127.0.0.1", "127.0.0.1", 1000},
		{"ipv6", "::1", "::1", "::1", 300},
		{"v4mapped", "::", "127.0.0.1", "127.0.0.1", 300},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := serveUDP(t, hostPort(c.backend, freePort(t)), "")
			lport := freePort(t)
			m := forward(t, "u", hostPort(c.listen, lport), be.addr)
			target := hostPort(c.client, lport)
			conns := make([]*net.UDPConn, c.n)
			for i := range conns {
				conns[i] = udpDial(t, "", target)
			}
			msgOf := func(i, seq int) []byte { return fmt.Appendf(nil, "c%05d-s%03d", i, seq) }

			// 阶段 1：顺序建立，每个客户端一次往返（跨越扩容阈值）
			for i, cn := range conns {
				udpEcho(t, cn, msgOf(i, 0))
			}
			// 阶段 2：交替轮转两轮，相邻两包来自不同客户端，每次查找都错过 last_hit
			for round := 1; round <= 2; round++ {
				for i, cn := range conns {
					udpEcho(t, cn, msgOf(i, round))
				}
			}
			// 阶段 3：每客户端连发 4 包，后 3 包命中 last_hit
			for i, cn := range conns {
				for seq := 10; seq < 14; seq++ {
					udpEcho(t, cn, msgOf(i, seq))
				}
			}

			if peers := be.peerList(); len(peers) != c.n {
				t.Errorf("后端看到 %d 个源地址，期望每客户端一个（%d）", len(peers), c.n)
			}
			if s := m.statsAfterSignal(t).udp[1]; s.sessions != c.n || int(s.total) != c.n {
				t.Errorf("统计 sessions=%d total=%d，期望 %d/%d（会话串了或重复建会话）", s.sessions, s.total, c.n, c.n)
			}
		})
	}
}

// 删除后幸存会话仍可查到：两个上游做等权轮询，上游 A 为字面量 IP，上游 B 为域名（经 /etc/hosts 解析）。
// 约 600 个会话按 A、B 交替建立（偶数号→A，奇数号→B）。最后建立的是一个 B 客户端，故 last_hit 指向一个即将被删除的会话。
// 切换域名 B 的地址后，DNS 刷新（30 s）触发 clear_remote_index 删掉全部 B 会话：
//   - 那个 last_hit B 客户端再发包必须得到回复（新会话），而不是命中已归还的旧会话（nolastclear 变异在此被杀）；
//   - 每个 A 客户端仍能经各自的旧会话到达 A：A 后端源地址集不变、A 会话不重建，sessions==numA+1、total==N+1
//     （删除用后移，表不被打乱；noshift/shiftgt 变异会让部分 A 会话查不到→重建→计数超出，在此被杀）。
func TestUDPSessionChurn(t *testing.T) {
	t.Parallel()
	inContainer(t)
	const n = 600
	const name = "tpm-u2churn.test"
	bport := freePort(t)
	aAddr := hostPort("127.0.0.2", bport)
	beA := serveUDP(t, aAddr, "A")                  // 上游 A：字面量 IP
	serveUDP(t, hostPort("127.0.0.3", bport), "B3") // 上游 B 初始地址
	serveUDP(t, hostPort("127.0.0.4", bport), "B4") // 上游 B 切换后的地址
	setLast := hostsEntry(t, "127.0.0.3", name)

	listen := loopback4(t)
	args := []string{"-l", listen, "--balance", "roundrobin: 1, 1", "-r", aAddr, "-r", fmt.Sprintf("%s:%d", name, bport), "-u"}
	m := startMapper(t, listenPoints("u", portOf(listen)), args...)

	// 顺序建立 n 个会话，确认轮询把偶数号发往 A、奇数号发往 B（初始地址 127.0.0.3）
	conns := make([]*net.UDPConn, n)
	numA := 0
	for i := range conns {
		conns[i] = udpDial(t, "", listen)
		got, err := udpTry(conns[i], fmt.Appendf(nil, "init-%d", i), 2*time.Second, 4)
		if err != nil {
			t.Fatalf("建立第 %d 个会话失败：%v", i, err)
		}
		want := "B3"
		if i%2 == 0 {
			want = "A"
			numA++
		}
		if !strings.HasPrefix(string(got), want) {
			t.Fatalf("第 %d 个会话回包 %q，期望上游 %q（轮询序列或路由异常）", i, got, want)
		}
	}
	numB := n - numA
	// 最后建立的是奇数号 B 客户端，last_hit 即指向它
	if conns[n-1] == nil || (n-1)%2 == 0 {
		t.Fatalf("用例前提：最后一个客户端应为 B 客户端")
	}
	lastHitB := conns[n-1]

	// 切换域名 B 的地址：127.0.0.3 → 127.0.0.4，等 DNS 刷新触发 clear_remote_index
	setLast('4')
	start := time.Now()
	eventually(t, 50*time.Second, 500*time.Millisecond, func() error {
		if m.logLines("changed from", fmt.Sprintf("udp=%d", numB)) != 0 {
			return nil
		}
		return fmt.Errorf("还没看到 B 域名地址切换、删除 %d 个 B 会话的日志", numB)
	})
	t.Logf("切换 /etc/hosts 后 %v 内删除了 %d 个 B 会话", time.Since(start).Round(time.Second), numB)

	// last_hit 曾指向的 B 客户端先发包：必须得到回复（新会话），而不是命中已归还的旧会话。
	// 删除后轮询状态回到周期起点，这个新会话按轮询路由到 A；若 last_hit 没清零会命中已关 fd 的旧会话→无回复/断言中止。
	got, err := udpTry(lastHitB, []byte("after-switch"), 2*time.Second, 4)
	if err != nil {
		t.Fatalf("切换后 last_hit B 客户端无回复：last_hit 可能仍指向已删除的会话：%v", err)
	}
	m.fatalIfExited(t, "切换后 last_hit B 客户端发包后")
	if p := string(got[:len(got)-len("after-switch")]); p == "B3" {
		t.Fatalf("切换后回包来自旧 B 地址（%q）：新会话不应连到已失效的地址", p)
	}

	// 每个 A 客户端再发包：必须命中各自的旧 A 会话、回包仍来自 A，不新建会话
	for i := 0; i < n; i += 2 {
		got, err := udpTry(conns[i], fmt.Appendf(nil, "a-again-%d", i), 2*time.Second, 4)
		if err != nil {
			t.Fatalf("切换后第 %d 个 A 客户端无回复：A 会话被删除缠绕打乱了：%v", i, err)
		}
		if !strings.HasPrefix(string(got), "A") {
			t.Fatalf("切换后第 %d 个 A 客户端回包 %q，期望仍来自 A：该 A 会话被删除打乱、重建并改了路由", i, got)
		}
	}
	m.fatalIfExited(t, "切换后重发全部 A 客户端后")

	// A 后端源地址集 = numA + 1（last_hit B 客户端重建的新会话按轮询也落到 A）；没有任何 A 客户端新建会话→无新源端口
	if peers := beA.peerList(); len(peers) != numA+1 {
		t.Errorf("A 后端看到 %d 个源地址，期望 %d（numA + 重建的 last_hit B 客户端）：A 会话被删除打乱后重建会多出源端口", len(peers), numA+1)
	}
	// 统计：当前会话 = numA + 1，累计 = N + 1。noshift/shiftgt 会让部分 A 会话查不到→重建，令两者超出
	if s := m.statsAfterSignal(t).udp[1]; s.sessions != numA+1 || int(s.total) != n+1 {
		t.Errorf("统计 sessions=%d total=%d，期望 %d/%d（删除打乱会话表会导致重建、计数超出）", s.sessions, s.total, numA+1, n+1)
	}
}

// max_conn_num：填满单规则到上限（20000 会话，用到最大的 32768 槽表），再来的新客户端被忽略（日志 but ignored,bc of
// max_conv_num reached），既有会话仍能转发，统计 sessions=20000。
//
// 临时端口：tinymapper 的 20000 个上游 socket 都在 connect 时从临时端口范围（net.ipv4.ip_local_port_range 32768–60999，
// 约 28k）自动绑定源端口。客户端也自动绑定时（即便分到别的 127.0.x.y 源 IP），实测 tinymapper 建到第 18738 个（客户端分 3 个
// 源 IP）或第 19584 个（分 80 个源 IP）上游 socket 时 connect 就返回 EAGAIN（inet_autobind 失败），填不满 20000；机理未查明。
// 所以客户端显式绑定固定源端口，完全不用临时端口：127.0.1.1 与 127.0.1.2 各 10000 个，端口 1024–11023。端口都低于 20000：
// freePort 从 20001 起分配给并行用例，其中通配地址（0.0.0.0:p、[::]:p）的绑定会与 127.0.1.x:p 冲突（EADDRINUSE）。
//
// 顺序建会话（非并发）：环回上单线程往返约 5000 次/秒，20000 个会话约几秒就建完，远在 180 s 空闲超时之前；并发建会话时首包
// 大量丢失、靠超时重发，速率反而骤降到约 100/秒，早建的会话会先于填满被 conn_timeout_udp 清掉，sessions 永远到不了 20000。
//
// 填满后再测批内拒绝（U1/U3）：暂停期间先排一批 64 个既有会话各一包，这一批的每个下标都对应一个活会话，恢复后收齐回包；再暂停，
// 排 64 个包，下标 1、20、40、63 来自 4 个新客户端，其余来自另外 60 个既有会话。新客户端在批内逐个被 max_conn_num 拒绝，只丢它们
// 自己的包：不能沿用同一下标上一批的会话发出去（后端收不到 reject- 开头的包），同批既有会话的包照常往返
func TestUDPMaxConn(t *testing.T) {
	t.Parallel()
	heavy(t)
	const maxConn = 20000
	const perIP, clientPortBase = 10000, 1024 // 每个源 IP 的客户端数与起始端口：1024..1024+perIP 低于 freePort 的 20001
	clientAddr := func(i int) *net.UDPAddr {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 1, byte(1+i/perIP)), Port: clientPortBase + i%perIP}
	}
	be := recordUDP(t, loopback4(t))
	listen := loopback4(t)
	m := forward(t, "u", listen, be.addr)
	ra, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		t.Fatal(err)
	}

	conns := make([]*net.UDPConn, maxConn)
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
	})
	start := time.Now()
	for i := range conns {
		c, err := net.DialUDP("udp", clientAddr(i), ra)
		if err != nil {
			t.Fatalf("第 %d 个客户端建 socket 失败：%v", i, err)
		}
		conns[i] = c
		msg := fmt.Appendf(nil, "fill-%05d", i)
		got, err := udpTry(c, msg, 2*time.Second, 4)
		if err != nil {
			t.Fatalf("第 %d 个会话失败：%v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("第 %d 个会话回包 %q 与请求不一致", i, got)
		}
	}
	t.Logf("顺序建立 %d 个 UDP 会话用时 %v", maxConn, time.Since(start).Round(time.Millisecond))

	// 第 20001 个客户端（127.0.1.1 上下一个未用的端口 11024，确保是新会话）：被 max_conn_num 忽略、不建会话、无回复
	extra, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 1, 1), Port: clientPortBase + perIP}, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { extra.Close() })
	if _, err := extra.Write([]byte("overflow")); err != nil {
		t.Fatal(err)
	}
	eventually(t, logFlushWithin+ioTimeout, 50*time.Millisecond, func() error {
		m.fatalIfExited(t, "填满 max_conn_num 后")
		if m.logLines("but ignored,bc of max_conv_num reached") == 0 {
			return fmt.Errorf("还没看到 max_conn_num 的忽略日志")
		}
		return nil
	})
	extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if nr, err := extra.Read(make([]byte, 64)); err == nil {
		t.Errorf("超限的新客户端收到 %d 字节回包：不应为它建会话", nr)
	}

	// 抽查若干既有会话仍能转发
	for _, i := range []int{0, 1, 9999, 15000, maxConn - 2, maxConn - 1} {
		msg := fmt.Appendf(nil, "alive-%05d", i)
		got, err := udpTry(conns[i], msg, 3*time.Second, 6)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("超限后第 %d 个既有会话异常：got=%q err=%v", i, got, err)
		}
	}

	var sends []udpSend
	for k := range 64 {
		sends = append(sends, udpSend{conns[k*300], fmt.Appendf(nil, "batch-a-%05d", k*300)})
	}
	m.pause(t)
	queueUDP(t, m, listen, sends)
	m.resume(t)
	for _, s := range sends {
		expectReplies(t, s.c, [][]byte{s.msg}, fmt.Sprintf("第一批的既有客户端 %s ", s.c.LocalAddr()))
	}
	sends = nil
	var rejected []*net.UDPConn
	for k := range 64 {
		if k == 1 || k == 20 || k == 40 || k == 63 {
			c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 1, 1), Port: clientPortBase + perIP + 1 + len(rejected)}, ra)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			rejected = append(rejected, c)
			sends = append(sends, udpSend{c, fmt.Appendf(nil, "reject-%d", k)})
		} else {
			sends = append(sends, udpSend{conns[k*300+1], fmt.Appendf(nil, "batch-b-%05d", k*300+1)})
		}
	}
	m.pause(t)
	queueUDP(t, m, listen, sends)
	m.resume(t)
	for _, s := range sends {
		if !bytes.HasPrefix(s.msg, []byte("reject-")) {
			expectReplies(t, s.c, [][]byte{s.msg}, fmt.Sprintf("第二批的既有客户端 %s ", s.c.LocalAddr()))
		}
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for _, c := range rejected {
		c.SetReadDeadline(deadline)
		if nr, err := c.Read(make([]byte, 64)); err == nil {
			t.Errorf("批内被拒绝的新客户端 %s 收到 %d 字节回包：不应为它建会话", c.LocalAddr(), nr)
		}
	}
	got, _, _ := be.bySource(t, 0)
	for src, pkts := range got {
		for _, p := range pkts {
			if bytes.HasPrefix(p, []byte("reject-")) {
				t.Errorf("后端从 %s 收到被拒绝客户端的包 %q：批内被拒绝的包交给了别的会话", src, p)
			}
		}
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if n := m.logLines("but ignored,bc of max_conv_num reached"); n != 1+len(rejected) {
			return fmt.Errorf("日志中有 %d 行因 max_conn_num 忽略新客户端，期望 %d", n, 1+len(rejected))
		}
		return nil
	})
	if s := m.statsAfterSignal(t).udp[1]; s.sessions != maxConn {
		t.Errorf("统计 sessions=%d，期望 %d", s.sessions, maxConn)
	}
}

// ---- U1/U3：监听 socket 批量收包（recvmmsg）与按会话分组批量发送（sendmmsg）----
//
// 下面的用例在 tinymapper 暂停（SIGSTOP）期间把包逐个排进监听 socket 的接收队列，恢复后第一次回调就读到整批：每次 recvmmsg 最多
// 64 个，每次回调最多 256 个，所以包在队列里的位置决定了它落在哪一批、和哪些包同批。转发语义与逐包收发相同（会话内保序、会话之间
// 不串、包内容不变），这些用例在 ed197d2（逐包 recvfrom + send）上同样通过。

// udpSend 是暂停期间要排队的一个包：从客户端 c 发出 msg
type udpSend struct {
	c   *net.UDPConn
	msg []byte
}

// queueUDP 在 tinymapper 暂停期间按顺序发出 sends，每发一个都等它进了监听 socket listen 的接收队列再发下一个，所以队列中的顺序就是
// sends 的顺序。sock_diag 报的 UDP rqueue 是队列中各包 truesize 之和，暂停期间没人读，每入队一个包就严格增大；环回上软中断通常在
// write 返回前就把包放进队列，负载高时可能推迟到 ksoftirqd。队列满时内核静默丢包（sk_drops 加一），这里直接失败：监听 socket 的
// rcvbuf 在 tests/run.sh 的容器里为 2×2 MiB（U6：tinymapper 有 CAP_NET_ADMIN，用 SO_RCVBUFFORCE 设，不受 rmem_max 截断）；没有
// 这项能力时为 2×min(2 MiB, rmem_max)，默认 rmem_max 下是 425984 字节，各用例排队的包都按这个较小的值控制。实测 60 字节左右的
// 小包 truesize 为 960 字节，65527 字节的 IPv6 包约 66 KiB
func queueUDP(t testing.TB, m *mapper, listen string, sends []udpSend) {
	t.Helper()
	queueListen(t, m, listen, len(sends), func(i int) int { return len(sends[i].msg) }, func(i int) error {
		_, err := sends[i].c.Write(sends[i].msg)
		return err
	})
}

// queueListen 是 queueUDP 的通用写法：暂停期间依次调 send(0..n-1) 发出一个包（size(i) 字节，只用于报错），每个都等它进了监听 socket
// listen 的接收队列再发下一个。U5 的 GSO 发送也走这里：开了 UDP_GRO 的监听 socket 整包收下一个合并包，没开的拆成多个数据报入队，
// 两种情况 rqueue 都严格增大
func queueListen(t testing.TB, m *mapper, listen string, n int, size func(i int) int, send func(i int) error) {
	t.Helper()
	remote := "0.0.0.0:0"
	if strings.HasPrefix(listen, "[") {
		remote = "[::]:0"
	}
	q := lookupSockBuf(t, m.pid(), syscall.IPPROTO_UDP, "UDP 监听 socket", listen, remote)
	drops0 := q.drops
	for i := range n {
		prev := q.rqueue
		if err := send(i); err != nil {
			t.Fatalf("暂停期间第 %d 个包（%d 字节）发送失败：%v", i, size(i), err)
		}
		eventually(t, ioTimeout, time.Millisecond, func() error {
			var err error
			if q, err = sockDiag(syscall.IPPROTO_UDP, listen, remote); err != nil {
				return err
			}
			if q.drops != drops0 {
				t.Fatalf("监听 socket 丢了 %d 个包（第 %d 个包 %d 字节；接收队列 %d 字节，rcvbuf %d）：暂停期间排队的包超出了接收缓冲",
					q.drops-drops0, i, size(i), q.rqueue, q.rcv)
			}
			if q.rqueue <= prev {
				return fmt.Errorf("第 %d 个包（%d 字节）还没进监听 socket 的接收队列（%d 字节）", i, size(i), q.rqueue)
			}
			return nil
		})
	}
	t.Logf("暂停期间 %d 个包已排进监听 socket：接收队列 %d 字节，rcvbuf %d", n, q.rqueue, q.rcv)
}

// resume 让 pause 停下的 tinymapper 继续运行
func (m *mapper) resume(t testing.TB) {
	t.Helper()
	if err := m.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatalf("发送 SIGCONT 失败：%v", err)
	}
}

// udpRecorder 是按到达顺序记录每个包（源地址与内容）的 UDP 后端：recordUDP 回显，回包与原包相同（无前缀）；quietUDP 不回显
type udpRecorder struct {
	addr string
	conn *net.UDPConn
	mu   sync.Mutex
	pkts []udpPacket
}

type udpPacket struct {
	from string
	data []byte
}

func recordUDP(t testing.TB, addr string) *udpRecorder { return newUDPRecorder(t, addr, true) }

// quietUDP 同 recordUDP，但不回显：回包由用例经 sendTo 在选定的时刻发往各会话 socket（U4 的用例在 tinymapper 暂停期间排队回包）
func quietUDP(t testing.TB, addr string) *udpRecorder { return newUDPRecorder(t, addr, false) }

func newUDPRecorder(t testing.TB, addr string, echo bool) *udpRecorder {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatalf("UDP 后端监听 %s 失败：%v", addr, err)
	}
	conn.SetReadBuffer(4 << 20)
	conn.SetWriteBuffer(4 << 20)
	r := &udpRecorder{addr: conn.LocalAddr().String(), conn: conn}
	go func() {
		buf := make([]byte, 70000)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				continue
			}
			r.mu.Lock()
			r.pkts = append(r.pkts, udpPacket{from.String(), append([]byte(nil), buf[:n]...)})
			r.mu.Unlock()
			if echo {
				conn.WriteToUDP(buf[:n], from)
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return r
}

func (r *udpRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pkts)
}

// bySource 等到后端共收到至少 n 个包，返回按源地址分组、保持到达顺序的内容，以及收到的总包数与总字节数
func (r *udpRecorder) bySource(t testing.TB, n int) (got map[string][][]byte, pkts, nbytes uint64) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.pkts) < n {
			return fmt.Errorf("后端收到 %d 个包，期望 %d", len(r.pkts), n)
		}
		return nil
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	got = map[string][][]byte{}
	for _, p := range r.pkts {
		got[p.from] = append(got[p.from], p.data)
		nbytes += uint64(len(p.data))
	}
	return got, uint64(len(r.pkts)), nbytes
}

// describePkts 概括一串包：包数，以及前几个包的长度与开头
func describePkts(pkts [][]byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d 个包：", len(pkts))
	for i, p := range pkts {
		if i == 6 {
			b.WriteString(" …")
			break
		}
		fmt.Fprintf(&b, " %d B %q", len(p), p[:min(len(p), 12)])
	}
	return b.String()
}

// expectBySource 要求后端按源地址分组的内容与 want 一一对应：每个客户端恰好对应一个源地址（一个会话），该源上的包与 want[i]
// 逐字节相同、顺序相同（包里不一定有客户端编号，如 0 字节的包，所以按整串匹配）。返回各客户端对应的源地址
func expectBySource(t testing.TB, got map[string][][]byte, want [][][]byte) []string {
	t.Helper()
	srcs := make([]string, len(want))
	used := map[string]bool{}
	ok := len(got) == len(want)
	if !ok {
		t.Errorf("后端看到 %d 个源地址，期望每个客户端一个（%d）", len(got), len(want))
	}
	for i, w := range want {
		for src, g := range got {
			if !used[src] && slices.EqualFunc(g, w, bytes.Equal) {
				used[src], srcs[i] = true, src
				break
			}
		}
		if srcs[i] == "" {
			ok = false
			t.Errorf("客户端 %d 的包（%s）没有原样、按序、完整地出现在任何一个源地址上", i, describePkts(w))
		}
	}
	if !ok {
		for src, g := range got {
			t.Logf("后端源地址 %s：%s", src, describePkts(g))
		}
	}
	return srcs
}

// expectReplies 从客户端 c 依次读回包，要求与 want 逐字节相同、顺序相同。以 -warm 结尾的是预热包重发后迟到的回包，跳过
func expectReplies(t testing.TB, c *net.UDPConn, want [][]byte, who string) {
	t.Helper()
	buf := make([]byte, 70000)
	for j, w := range want {
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		n, err := c.Read(buf)
		for err == nil && bytes.HasSuffix(buf[:n], []byte("-warm")) {
			n, err = c.Read(buf)
		}
		if err != nil {
			t.Fatalf("%s的第 %d 个回包（期望 %d 字节）：%v", who, j, len(w), err)
		}
		if !bytes.Equal(buf[:n], w) {
			t.Fatalf("%s的第 %d 个回包为 %d 字节 %q，期望 %d 字节 %q", who, j, n, buf[:min(n, 12)], len(w), w[:min(len(w), 12)])
		}
	}
}

// U1/U3：同一批里交错着多个会话的包。暂停期间 n 个客户端各排 k 个带编号的包，恢复后批量读出：后端每个客户端恰好一个源地址、包收齐
// 且保序，回包回到各自的客户端且保序。偶数号客户端暂停前做过一次往返（会话已存在），奇数号的会话在它批内的首包处新建，与既有会话的包
// 同批。roundrobin 每批依次轮过各客户端：64 个客户端时每批 64 个会话各一包（分组数达到批大小）；100 个客户端时 300 个包跨 5 批、
// 两次回调（256 包的预算），各批的会话顺序不同。random 按固定种子随机交错，各批的会话构成与首包顺序都不同：批与批之间残留的分组状态
// 会把包交给别的会话。dualstack 的 [::] 监听同批收到 IPv4（v4 映射）与 IPv6 客户端。预热包超时会重发（udpEcho），所以后端按
// 源地址比对前先去掉预热包，再要求偶数号客户端的预热包与批内的包来自同一个源地址（批内命中既有会话）。统计：sessions==total==n，
// 上行包数与字节数等于后端实收，没有丢包
func TestUDPBatchInterleave(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		listen  string   // 监听地址
		clients []string // 客户端目标地址，按客户端编号轮换
		backend string
		n, k    int
		random  bool
	}{
		{"3x40", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1", 3, 40, true},
		{"64x3", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1", 64, 3, false},
		{"100x3", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1", 100, 3, false},
		{"ipv6-5x20", "::1", []string{"::1"}, "::1", 5, 20, true},
		{"dualstack-6x12", "::", []string{"127.0.0.1", "::1"}, "127.0.0.1", 6, 12, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := recordUDP(t, hostPort(c.backend, freePort(t)))
			lport := freePort(t)
			listen := hostPort(c.listen, lport)
			m := forward(t, "u", listen, be.addr)
			msgOf := func(i, seq int) []byte {
				b := fmt.Appendf(nil, "c%03d-s%03d-", i, seq)
				for j := range (i*7 + seq*13) % 50 {
					b = append(b, byte('a'+(i+seq+j)%26))
				}
				return b
			}

			conns := make([]*net.UDPConn, c.n)
			for i := range conns {
				conns[i] = udpDial(t, "", hostPort(c.clients[i%len(c.clients)], lport))
				if i%2 == 0 {
					udpEcho(t, conns[i], fmt.Appendf(nil, "c%03d-warm", i))
				}
			}

			var order []int // 第 j 个排队的包来自客户端 order[j]；客户端 i 第 seq 次出现即它的第 seq 个包
			if c.random {
				rng := rand.New(rand.NewPCG(uint64(c.n), uint64(c.k)))
				left := make([]int, c.n)
				for i := range left {
					left[i] = c.k
				}
				for len(order) < c.n*c.k {
					if i := rng.IntN(c.n); left[i] > 0 {
						left[i]--
						order = append(order, i)
					}
				}
			} else {
				for range c.k {
					for i := range c.n {
						order = append(order, i)
					}
				}
			}
			sends := make([]udpSend, 0, len(order))
			batch := make([][][]byte, c.n) // 各客户端在批里发出的包
			for _, i := range order {
				msg := msgOf(i, len(batch[i]))
				sends = append(sends, udpSend{conns[i], msg})
				batch[i] = append(batch[i], msg)
			}
			total := be.count() + c.n*c.k // 预热包可能因重发多于 (n+1)/2 个
			m.pause(t)
			queueUDP(t, m, listen, sends)
			m.resume(t)

			got, pkts, nbytes := be.bySource(t, total)
			warmSrc := map[int]string{}
			for src, g := range got {
				g = slices.DeleteFunc(g, func(p []byte) bool {
					var i int
					if _, err := fmt.Sscanf(string(p), "c%d-warm", &i); err == nil && bytes.HasSuffix(p, []byte("-warm")) {
						warmSrc[i] = src
						return true
					}
					return false
				})
				if len(g) == 0 {
					delete(got, src)
				} else {
					got[src] = g
				}
			}
			srcs := expectBySource(t, got, batch)
			for i := 0; i < c.n; i += 2 {
				if srcs[i] != "" && warmSrc[i] != srcs[i] {
					t.Errorf("客户端 %d 的预热包来自源地址 %q，批内的包来自 %s：批内没有命中既有会话", i, warmSrc[i], srcs[i])
				}
			}
			for i, cn := range conns {
				expectReplies(t, cn, batch[i], fmt.Sprintf("客户端 %d ", i))
			}
			s := m.statsAfterSignal(t).udp[1]
			if s.sessions != c.n || int(s.total) != c.n {
				t.Errorf("统计 sessions=%d total=%d，期望 %d/%d（批内新建会话重复或串了）", s.sessions, s.total, c.n, c.n)
			}
			if int(pkts) < total || s.upPkts != pkts || s.upBytes != nbytes || s.upDrop != 0 {
				t.Errorf("统计 up_pkts=%d up_bytes=%d up_drop=%d，后端实收 %d 个包 %d 字节，期望 %d 个包、无丢包", s.upPkts, s.upBytes, s.upDrop, pkts, nbytes, total)
			}
			if s.downPkts != pkts || s.downBytes != nbytes || s.downDrop != 0 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d，期望与后端回显的 %d 个包 %d 字节相同", s.downPkts, s.downBytes, s.downDrop, pkts, nbytes)
			}
		})
	}
}

// U1/U3：同一批里混着各种包长。每个消息的接收缓冲是 2048 字节的槽加一块溢出区，合计 65536 字节：跨槽边界的 2047/2048/2049 字节、
// 远大于槽的 4096、9000 字节与 IPv4 的 65507、IPv6 的 65527 字节（各自的 UDP 载荷上限；IPv6 的在环回上分片）都必须原样转发，
// 0 字节的包也照转。两个客户端交错排队，A 按包长升序、B 按降序，同一批里有多个大包（各用自己的溢出区）；第二轮再暂停，两者顺序互换：
// 第一轮放过小包的槽这次收大包（发送时若改了 iov 长度，下次收包前必须恢复，否则大包被截断成 huge packet 丢掉）。后端逐字节核对每个
// 源地址上的内容与顺序，回包逐字节回到各自的客户端
func TestUDPBatchSizes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		host  string
		sizes []int
	}{
		{"127.0.0.1", []int{0, 1, 64, 2047, 2048, 2049, 4096, 9000, 65507}},
		{"::1", []int{0, 1, 64, 2047, 2048, 2049, 4096, 9000, 65527}},
	} {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			be := recordUDP(t, hostPort(c.host, freePort(t)))
			listen := hostPort(c.host, freePort(t))
			m := forward(t, "u", listen, be.addr)
			conns := []*net.UDPConn{udpDial(t, "", listen), udpDial(t, "", listen)}
			msgOf := func(client, round, size int) []byte {
				msg := make([]byte, size)
				for i := range msg {
					msg[i] = byte(size+client*7+round*13) ^ byte(i*31)
				}
				return msg
			}
			want := make([][][]byte, len(conns)) // 两轮累计
			for round := range 2 {
				var sends []udpSend
				cur := make([][][]byte, len(conns)) // 本轮
				for j := range c.sizes {
					for i, cn := range conns {
						size := c.sizes[j]
						if (i+round)%2 == 1 {
							size = c.sizes[len(c.sizes)-1-j]
						}
						msg := msgOf(i, round, size)
						sends = append(sends, udpSend{cn, msg})
						cur[i] = append(cur[i], msg)
						want[i] = append(want[i], msg)
					}
				}
				m.pause(t)
				queueUDP(t, m, listen, sends)
				m.resume(t)
				got, _, _ := be.bySource(t, len(conns)*len(c.sizes)*(round+1))
				expectBySource(t, got, want)
				for i, cn := range conns {
					expectReplies(t, cn, cur[i], fmt.Sprintf("第 %d 轮客户端 %d ", round+1, i))
				}
				if t.Failed() {
					t.FailNow()
				}
			}
		})
	}
}

// loggedUpDrops 汇总日志里上行发送失败的 warn 报告的丢包数：逐包发送时每行 "[udp]send returned -1,..." 丢 1 个，批量发送时每行
// "[udp]sendmmsg returned -1,<strerror>,dropped N packets" 丢 N 个；lines 为这两种 warn 的总行数
func loggedUpDrops(m *mapper) (drops, lines int) {
	data, _ := os.ReadFile(m.logPath)
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(line, "[udp]send returned -1,"):
			drops++
			lines++
		case strings.Contains(line, "[udp]sendmmsg returned -1,"):
			n := -1
			if i := strings.LastIndex(line, ",dropped "); i >= 0 {
				fmt.Sscanf(line[i:], ",dropped %d packets", &n)
			}
			drops += n
			lines++
		}
	}
	return drops, lines
}

// U3：批内发送出错。6to4（IPv6 监听、IPv4 上游）时 65527 字节（IPv6 的 UDP 载荷上限）的包转成 IPv4 发不出去：IPv4 的 UDP 载荷上限
// 是 65507，send/sendmmsg 返回 EMSGSIZE（先在测试自己的 IPv4 socket 上确认）。一个客户端暂停期间排 [大, a, b, 大, c, d, 大]：逐包发送
// 时每个大包各失败一次；批量发送时 sendmmsg 在第 0 个就失败（返回 -1），只丢它、从 a 继续，发出 a、b 后返回 2（错误被内核吞掉），
// 再从第二个大包起又是 -1……非 EAGAIN 的错误只丢出错的那一个，同组其余的包照发。后端按序收到 a、b、c、d，up_pkts=4、up_drop=3，
// 日志报告的丢包数之和也是 3；a、b、c、d 长度各不相同，部分发送后从错的下标累加字节数时 up_bytes 对不上。回包按序回到客户端
func TestUDPBatchSendError(t *testing.T) {
	t.Parallel()
	const big = 65527
	probe, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: freePort(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.Write(make([]byte, big))
	probe.Close()
	if !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("在 IPv4 UDP socket 上发 %d 字节返回 %v，期望 EMSGSIZE：本用例的前提不成立", big, err)
	}

	be := recordUDP(t, loopback4(t))
	listen := hostPort("::1", freePort(t))
	m := forward(t, "u", listen, be.addr)
	c := udpDial(t, "", listen)
	large := bytes.Repeat([]byte{'L'}, big)
	small := [][]byte{[]byte("a"), bytes.Repeat([]byte("b"), 10), bytes.Repeat([]byte("c"), 100), bytes.Repeat([]byte("d"), 1000)}
	var sends []udpSend
	for _, msg := range [][]byte{large, small[0], small[1], large, small[2], small[3], large} {
		sends = append(sends, udpSend{c, msg})
	}
	m.pause(t)
	queueUDP(t, m, listen, sends)
	m.resume(t)

	got, _, _ := be.bySource(t, len(small))
	expectBySource(t, got, [][][]byte{small})
	expectReplies(t, c, small, "客户端")
	s := m.statsAfterSignal(t).udp[1]
	if s.upPkts != 4 || s.upBytes != 1111 || s.upDrop != 3 {
		t.Errorf("统计 up_pkts=%d up_bytes=%d up_drop=%d，期望 4/1111/3（3 个大包各丢一次，其余照发）", s.upPkts, s.upBytes, s.upDrop)
	}
	if s.sessions != 1 || s.total != 1 {
		t.Errorf("统计 sessions=%d total=%d，期望 1/1", s.sessions, s.total)
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if drops, lines := loggedUpDrops(m); drops != 3 || lines != 3 {
			return fmt.Errorf("日志里有 %d 行上行发送失败的 warn，共报告丢 %d 个包，期望 3 行、3 个（每个大包一行）", lines, drops)
		}
		return nil
	})
}

// ---- U4：回程批量收发（会话 socket 的回包收进回程批，跨会话按规则对监听 socket 调 sendmmsg）----
//
// 下面的用例用不回显的后端（quietUDP）：客户端先各发一个 hello 建会话，后端从源地址得知每个会话 socket 的地址；tinymapper 暂停
// （SIGSTOP）期间后端把回包逐个排进各会话 socket 的接收队列（queueReplies），恢复后第一轮循环里各会话的回调一起收包，回程批跨会话
// 攒包、批满时或本轮阻塞之前发出。转发语义与逐包 recv + sendto 相同（会话内保序、回到各自的客户端、内容不变、从规则自己的监听地址
// 发出），这些用例在 835690e（逐包收发）上同样通过。

// helloSession 经 send 发出 msg（后端不回显），等后端收到后返回它的源地址，即 tinymapper 为这个客户端建的会话 socket 的地址。
// 环回偶有丢包，500 ms 没收到就重发（命中既有会话，不新建）
func helloSession(t testing.TB, be *udpRecorder, msg []byte, send func([]byte) error) string {
	t.Helper()
	for range 8 {
		if err := send(msg); err != nil {
			t.Fatalf("发送 %q 失败：%v", msg, err)
		}
		for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if src := be.sourceOf(msg); src != "" {
				return src
			}
		}
	}
	t.Fatalf("后端一直没收到 %q：会话没有建立", msg)
	return ""
}

// helloConn 是 helloSession 用于已 connect 的客户端 socket 的写法
func helloConn(t testing.TB, be *udpRecorder, c *net.UDPConn, msg []byte) string {
	t.Helper()
	return helloSession(t, be, msg, func(b []byte) error { _, err := c.Write(b); return err })
}

// sourceOf 返回后端收到的第一个内容为 msg 的包的源地址，没有则返回空串
func (r *udpRecorder) sourceOf(msg []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.pkts {
		if bytes.Equal(p.data, msg) {
			return p.from
		}
	}
	return ""
}

// sendTo 从后端 socket 向 to（会话 socket 的地址）发一个包
func (r *udpRecorder) sendTo(t testing.TB, to string, msg []byte) {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.conn.WriteToUDP(msg, ua); err != nil {
		t.Fatalf("后端向 %s 发 %d 字节失败：%v", to, len(msg), err)
	}
}

// udpReply 是暂停期间后端 be 要发往会话 socket session（后端看到的源地址）的一个回包
type udpReply struct {
	be      *udpRecorder
	session string
	msg     []byte
}

// queueReplies 在 tinymapper 暂停期间按顺序发出 replies，每发一个都等它进了 tinymapper 那个会话 socket 的接收队列再发下一个
// （sock_diag 按会话 socket 的本端、对端地址精确查找，UDP 的 rqueue 是队列中各包 truesize 之和，暂停期间没人读，每入队一个包就
// 严格增大），所以 epoll 里各会话 socket 变为就绪的先后就是它们第一个回包在 replies 里的先后。会话 socket 的 rcvbuf 为
// 2×min(1 MiB, rmem_max)，默认 425984 字节（U6：会话 socket 只在给了 --sock-buf 时才用 FORCE，D38 修订），
// 队列满时内核静默丢包（sk_drops 加一），这里直接失败
func queueReplies(t testing.TB, m *mapper, replies []udpReply) {
	t.Helper()
	queueSessions(t, m, len(replies), func(i int) (string, string, int) {
		return replies[i].session, replies[i].be.addr, len(replies[i].msg)
	}, func(i int) { replies[i].be.sendTo(t, replies[i].session, replies[i].msg) })
}

// queueSessions 是 queueReplies 的通用写法：第 i 个回包由 send(i) 从后端地址 from 发往会话 socket session（at(i) 给出两者与包长），
// 每个都等它进了那个会话 socket 的接收队列再发下一个。U5 的后端用 GSO 发回包也走这里（会话 socket 开了 UDP_GRO 时整包入队）
func queueSessions(t testing.TB, m *mapper, n int, at func(i int) (session, from string, size int), send func(i int)) {
	t.Helper()
	q := map[string]sockBuf{}
	for i := range n {
		session, from, size := at(i)
		prev, ok := q[session]
		if !ok {
			prev = lookupSockBuf(t, m.pid(), syscall.IPPROTO_UDP, "会话 socket", session, from)
		}
		send(i)
		eventually(t, ioTimeout, time.Millisecond, func() error {
			cur, err := sockDiag(syscall.IPPROTO_UDP, session, from)
			if err != nil {
				return err
			}
			if cur.drops != prev.drops {
				t.Fatalf("会话 socket %s 丢了 %d 个包（第 %d 个回包 %d 字节；接收队列 %d 字节，rcvbuf %d）：暂停期间排队的回包超出了接收缓冲",
					session, cur.drops-prev.drops, i, size, cur.rqueue, cur.rcv)
			}
			if cur.rqueue <= prev.rqueue {
				return fmt.Errorf("第 %d 个回包（%d 字节）还没进会话 socket %s 的接收队列（%d 字节）", i, size, session, cur.rqueue)
			}
			q[session] = cur
			return nil
		})
	}
	t.Logf("暂停期间 %d 个回包已排进 %d 个会话 socket", n, len(q))
}

// interleaveOrder 返回 n 个客户端各 k 个包的排队顺序：第 j 个包来自客户端 order[j]。random 时按固定种子随机交错，否则依次轮转
func interleaveOrder(n, k int, random bool) []int {
	var order []int
	if !random {
		for range k {
			for i := range n {
				order = append(order, i)
			}
		}
		return order
	}
	rng := rand.New(rand.NewPCG(uint64(n), uint64(k)))
	left := make([]int, n)
	for i := range left {
		left[i] = k
	}
	for len(order) < n*k {
		if i := rng.IntN(n); left[i] > 0 {
			left[i]--
			order = append(order, i)
		}
	}
	return order
}

// totalLen 返回各包长度之和
func totalLen(pkts ...[][]byte) uint64 {
	var n uint64
	for _, ps := range pkts {
		for _, p := range ps {
			n += uint64(len(p))
		}
	}
	return n
}

// U4：多个会话的回包在同一轮里攒成回程批。暂停期间后端给 n 个会话各排 k 个带编号、长度各异的回包（轮转或随机交错），恢复后每个客户端
// 按序、逐字节收到自己的回包；客户端 socket 已 connect 到监听地址，内核只收从监听地址发来的包，所以回包也必须从监听地址发出。
// 100x3 共 300 个回包，第一轮里约 21 个会话的回调就攒满 64 个，批满时当场发出，读到一半的会话剩下的回包留到下一轮：
// 跨批也要保序。3x40 时一个会话一次收包就占去大半个批。ipv6 与 dualstack（[::] 监听同批回给 v4 映射与 IPv6 客户端）核对
// 各包的目的地址与 msg_namelen。统计：down_pkts、down_bytes 精确，无丢包，sessions==total==n；之后不空转
func TestUDPReturnBatch(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		listen  string   // 监听地址
		clients []string // 客户端目标地址，按客户端编号轮换
		backend string
		n, k    int
		random  bool
	}{
		{"100x3", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1", 100, 3, false},
		{"3x40", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1", 3, 40, true},
		{"ipv6-10x8", "::1", []string{"::1"}, "::1", 10, 8, true},
		{"dualstack-8x10", "::", []string{"127.0.0.1", "::1"}, "127.0.0.1", 8, 10, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := quietUDP(t, hostPort(c.backend, freePort(t)))
			lport := freePort(t)
			m := forward(t, "u", hostPort(c.listen, lport), be.addr)
			conns := make([]*net.UDPConn, c.n)
			sessions := make([]string, c.n)
			for i := range conns {
				conns[i] = udpDial(t, "", hostPort(c.clients[i%len(c.clients)], lport))
				sessions[i] = helloConn(t, be, conns[i], fmt.Appendf(nil, "hello-%03d", i))
			}
			var replies []udpReply
			want := make([][][]byte, c.n)
			for _, i := range interleaveOrder(c.n, c.k, c.random) {
				seq := len(want[i])
				msg := fmt.Appendf(nil, "r%03d-s%03d-", i, seq)
				for j := range (i*7 + seq*13) % 50 {
					msg = append(msg, byte('A'+(i+seq+j)%26))
				}
				replies = append(replies, udpReply{be, sessions[i], msg})
				want[i] = append(want[i], msg)
			}
			m.pause(t)
			queueReplies(t, m, replies)
			m.resume(t)
			for i, cn := range conns {
				expectReplies(t, cn, want[i], fmt.Sprintf("客户端 %d ", i))
			}
			s := m.statsAfterSignal(t).udp[1]
			if s.sessions != c.n || int(s.total) != c.n {
				t.Errorf("统计 sessions=%d total=%d，期望 %d/%d", s.sessions, s.total, c.n, c.n)
			}
			if s.downPkts != uint64(c.n*c.k) || s.downBytes != totalLen(want...) || s.downDrop != 0 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d，期望 %d/%d/0", s.downPkts, s.downBytes, s.downDrop, c.n*c.k, totalLen(want...))
			}
			if s.upPkts != uint64(be.count()) || s.upDrop != 0 {
				t.Errorf("统计 up_pkts=%d up_drop=%d，期望 %d/0（后端收到的 hello 数）", s.upPkts, s.upDrop, be.count())
			}
			// 统计输出时已 fflush：收发都不该出错（如 recvmmsg 的 vlen 超出回程批剩余的空位时，越界的那一项让内核记下错误，下一次收包报
			// recv failed）
			if data, _ := os.ReadFile(m.logPath); bytes.Contains(data, []byte("[WARN]")) {
				var warns []string
				for _, l := range strings.Split(string(data), "\n") {
					if strings.Contains(l, "[WARN]") {
						warns = append(warns, l)
					}
				}
				t.Errorf("日志里有 %d 行 warn，期望没有，前几行：\n%s", len(warns), strings.Join(warns[:min(len(warns), 3)], "\n"))
			}
			m.expectIdleCPU(t, "回程批发出之后")
		})
	}
}

// recvTraces 返回日志里 --log-level 6 的逐包收包 trace 行：入向 "[udp]received data from udp_listen_fd from {…}"，
// 回程 "[udp]received data from udp fd N"
func recvTraces(m *mapper) []string {
	data, _ := os.ReadFile(m.logPath)
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "received data from udp") {
			out = append(out, line)
		}
	}
	return out
}

// U4：回程与入向在同一轮循环里，两个方向逐字节核对。回程批的设计可能与入向批共用 64 个槽和溢出区（D36）：那时入向的回调必须先发出
// 回程批再收包，否则回包被入向的包覆盖。libev 在同一优先级内按入队的逆序回调（ev_invoke_pending 从 pendings 末尾取），epoll 按
// fd 变为就绪的先后报告（就绪链表先进先出），所以 sessions-cb-first 先在监听 socket 排入向包、再在会话 socket 排回包：恢复后会话的
// 回调先收回包，监听的回调后收；listener-cb-first 反过来。从 trace 日志确认这一轮里第一个收包的是哪一方。包长跨 2 KiB 槽边界直到
// 65507，入向与回程内容不同；后端按源地址核对入向，客户端核对回程；两个方向的计数精确
func TestUDPReturnWithInbound(t *testing.T) {
	t.Parallel()
	sizes := []int{0, 1, 64, 2047, 2048, 2049, 9000, 65507}
	for _, c := range []struct {
		name          string
		listenerFirst bool // 先排入向包：监听 socket 先就绪，回调在会话之后
	}{
		{"sessions-cb-first", true},
		{"listener-cb-first", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			const n = 3
			be := quietUDP(t, loopback4(t))
			listen := loopback4(t)
			m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u", "--log-level", "6")
			conns := make([]*net.UDPConn, n)
			sessions := make([]string, n)
			for i := range conns {
				conns[i] = udpDial(t, "", listen)
				sessions[i] = helloConn(t, be, conns[i], fmt.Appendf(nil, "hello-%d", i))
			}
			msgOf := func(dir, client, size int) []byte {
				msg := make([]byte, size)
				for j := range msg {
					msg[j] = byte(size+client*7+dir*101) ^ byte(j*31)
				}
				return msg
			}
			var sends []udpSend
			var replies []udpReply
			up, down := make([][][]byte, n), make([][][]byte, n)
			for j := range sizes {
				for i := range n {
					u := msgOf(0, i, sizes[(j+i)%len(sizes)])
					sends = append(sends, udpSend{conns[i], u})
					up[i] = append(up[i], u)
					d := msgOf(1, i, sizes[(len(sizes)-1-j+i)%len(sizes)])
					replies = append(replies, udpReply{be, sessions[i], d})
					down[i] = append(down[i], d)
				}
			}
			hellos := be.count()
			// hello 的 trace 行都写进文件之后再暂停（日志最多晚一个 400 ms 的定时器周期写出），恢复后的第一行 trace 就是这一轮的
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
				queueUDP(t, m, listen, sends)
				queueReplies(t, m, replies)
			} else {
				queueReplies(t, m, replies)
				queueUDP(t, m, listen, sends)
			}
			m.resume(t)

			for i, cn := range conns {
				expectReplies(t, cn, down[i], fmt.Sprintf("客户端 %d ", i))
			}
			got, pkts, nbytes := be.bySource(t, hellos+len(sends))
			for src, g := range got {
				got[src] = slices.DeleteFunc(g, func(p []byte) bool { return bytes.HasPrefix(p, []byte("hello-")) })
			}
			srcs := expectBySource(t, got, up)
			for i := range n {
				if srcs[i] != "" && srcs[i] != sessions[i] {
					t.Errorf("客户端 %d 的入向包来自源地址 %s，hello 来自 %s：没有命中既有会话", i, srcs[i], sessions[i])
				}
			}
			s := m.statsAfterSignal(t).udp[1]
			if s.upPkts != pkts || s.upBytes != nbytes || s.upDrop != 0 {
				t.Errorf("统计 up_pkts=%d up_bytes=%d up_drop=%d，期望与后端实收的 %d 个包 %d 字节相同、无丢包", s.upPkts, s.upBytes, s.upDrop, pkts, nbytes)
			}
			if s.downPkts != uint64(len(replies)) || s.downBytes != totalLen(down...) || s.downDrop != 0 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d，期望 %d/%d/0", s.downPkts, s.downBytes, s.downDrop, len(replies), totalLen(down...))
			}

			// 用例前提：这一轮里先收包的一方
			var traces []string
			eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
				if traces = recvTraces(m); len(traces) < before+len(sends)+len(replies) {
					return fmt.Errorf("日志里恢复后有 %d 行收包 trace，期望 %d", len(traces)-before, len(sends)+len(replies))
				}
				return nil
			})
			first := traces[before]
			sessionFirst := strings.Contains(first, "received data from udp fd")
			t.Logf("恢复后第一行收包 trace：%s", first)
			if sessionFirst != c.listenerFirst {
				t.Errorf("恢复后第一行收包 trace 为 %q：用例前提不成立（期望先回调%s）", first, map[bool]string{true: "会话", false: "监听"}[c.listenerFirst])
			}
		})
	}
}

// U4：回程批里各种包长。回程的每个包也收进 2048 字节的槽加一块溢出区：跨槽边界的 2047/2048/2049 字节、4096、9000 字节与 IPv4 的
// 65507、IPv6 的 65527 字节（IPv6 的在环回上分片）都必须原样回到客户端，0 字节的包也照转。3 个会话交错排队，客户端 0 按包长升序、
// 1 按降序、2 从中间轮转，同一批里有多个大包；第二轮再暂停，各会话的顺序轮换：第一轮放过小包的槽这次收大包（发送时若改了 iov 长度，
// 下次收包前必须恢复，否则大包被截断成 huge packet 丢掉）。down_bytes 精确
func TestUDPReturnSizes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		host  string
		sizes []int
	}{
		{"127.0.0.1", []int{0, 1, 64, 2047, 2048, 2049, 4096, 9000, 65507}},
		{"::1", []int{0, 1, 64, 2047, 2048, 2049, 4096, 9000, 65527}},
	} {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			const n = 3
			be := quietUDP(t, hostPort(c.host, freePort(t)))
			listen := hostPort(c.host, freePort(t))
			m := forward(t, "u", listen, be.addr)
			conns := make([]*net.UDPConn, n)
			sessions := make([]string, n)
			for i := range conns {
				conns[i] = udpDial(t, "", listen)
				sessions[i] = helloConn(t, be, conns[i], fmt.Appendf(nil, "hello-%d", i))
			}
			sizeOf := func(client, j int) int {
				switch client {
				case 0:
					return c.sizes[j]
				case 1:
					return c.sizes[len(c.sizes)-1-j]
				}
				return c.sizes[(j+len(c.sizes)/2)%len(c.sizes)]
			}
			var all [][]byte
			for round := range 2 {
				var replies []udpReply
				cur := make([][][]byte, n)
				for j := range c.sizes {
					for i := range n {
						size := sizeOf((i+round)%n, j)
						msg := make([]byte, size)
						for b := range msg {
							msg[b] = byte(size+i*7+round*13) ^ byte(b*31)
						}
						replies = append(replies, udpReply{be, sessions[i], msg})
						cur[i] = append(cur[i], msg)
						all = append(all, msg)
					}
				}
				m.pause(t)
				queueReplies(t, m, replies)
				m.resume(t)
				for i, cn := range conns {
					expectReplies(t, cn, cur[i], fmt.Sprintf("第 %d 轮客户端 %d ", round+1, i))
				}
			}
			s := m.statsAfterSignal(t).udp[1]
			if s.downPkts != uint64(len(all)) || s.downBytes != totalLen(all) || s.downDrop != 0 {
				t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d，期望 %d/%d/0", s.downPkts, s.downBytes, s.downDrop, len(all), totalLen(all))
			}
		})
	}
}

// loggedDownDrops 汇总日志里回程发送失败的 warn 报告的丢包数：逐包发送时每行 "[udp]sento returned -1,..." 丢 1 个；回程批量发送
// （U4）时每行 "[udp]sendmmsg to clients returned -1,<strerror>,dropped N packets" 丢 N 个，batch 依次是这些行各自报告的 N
func loggedDownDrops(m *mapper) (drops, lines int, batch []int) {
	data, _ := os.ReadFile(m.logPath)
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(line, "[udp]sento returned -1,"):
			drops++
			lines++
		case strings.Contains(line, "[udp]sendmmsg to clients returned -1,"):
			n := -1
			if i := strings.LastIndex(line, ",dropped "); i >= 0 {
				fmt.Sscanf(line[i:], ",dropped %d packets", &n)
			}
			drops += n
			lines++
			batch = append(batch, n)
		}
	}
	return drops, lines, batch
}

// U4：回程批内发送出错。与 TestUDPBatchSendError 方向相反的 4to6（IPv4 监听、IPv6 上游）：后端回 65527 字节（IPv6 的 UDP 载荷上限）
// 的包，会话 socket 照收，经 IPv4 监听 socket 发给 IPv4 客户端时 EMSGSIZE（IPv4 的上限是 65507）。暂停期间排 [大, a, b, 大, c, d, 大]：
// 逐包 sendto 时每个大包各失败一次；批量发送时 sendmmsg 在第 0 个就返回 -1，只丢它、从 a 继续，发出 a、b 后返回 2（错误被内核吞掉），
// 再从第二个大包起又是 -1……非 EAGAIN 的错误只丢出错的那一个。客户端按序收到 a、b、c、d，down_pkts=4、down_bytes=1111、
// down_drop=3，日志报告的丢包数之和也是 3（每个大包一行）；a、b、c、d 长度各不相同，部分发送后从错的下标累加字节数时 down_bytes
// 对不上。发送失败之后不空转
func TestUDPReturnSendError(t *testing.T) {
	t.Parallel()
	const big = 65527
	be := quietUDP(t, hostPort("::1", freePort(t)))
	listen := loopback4(t)
	m := forward(t, "u", listen, be.addr)
	c := udpDial(t, "", listen)
	session := helloConn(t, be, c, []byte("hello"))
	large := bytes.Repeat([]byte{'L'}, big)
	small := [][]byte{[]byte("a"), bytes.Repeat([]byte("b"), 10), bytes.Repeat([]byte("c"), 100), bytes.Repeat([]byte("d"), 1000)}
	var replies []udpReply
	for _, msg := range [][]byte{large, small[0], small[1], large, small[2], small[3], large} {
		replies = append(replies, udpReply{be, session, msg})
	}
	m.pause(t)
	queueReplies(t, m, replies)
	m.resume(t)

	expectReplies(t, c, small, "客户端")
	// 逐包收发时最后一个大包在客户端收到 d 之后才处理
	var s udpStat
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if s = m.statsAfterSignal(t).udp[1]; s.downDrop < 3 {
			return fmt.Errorf("down_drop=%d，期望 3", s.downDrop)
		}
		return nil
	})
	if s.downPkts != 4 || s.downBytes != 1111 || s.downDrop != 3 {
		t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d，期望 4/1111/3（3 个大包各丢一次，其余照发）", s.downPkts, s.downBytes, s.downDrop)
	}
	if s.upPkts != uint64(be.count()) || s.upDrop != 0 {
		t.Errorf("统计 up_pkts=%d up_drop=%d，期望 %d/0", s.upPkts, s.upDrop, be.count())
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if drops, lines, _ := loggedDownDrops(m); drops != 3 || lines != 3 {
			return fmt.Errorf("日志里有 %d 行回程发送失败的 warn，共报告丢 %d 个包，期望 3 行、3 个（每个大包一行）", lines, drops)
		}
		return nil
	})
	m.expectIdleCPU(t, "回程发送 EMSGSIZE 之后")
}

// U4：两条以上 UDP 规则的回包在同一轮里进同一个回程批，按规则分组、各用自己规则的监听 socket 发出，计数记在各自的规则上。三条规则：
// 两条 IPv4（不同端口）、一条 IPv6，各 2 个客户端，暂停期间后端按规则交错排 15 轮回包（共 90 个，跨一次批满；批里各会话的回包连在
// 一起，会话按回调顺序、规则交替）。客户端 socket 不
// connect，用 ReadFromUDP 核对每个回包的源地址就是本规则的监听地址：组发错了监听 socket 时，IPv4 规则的回包源端口不对，IPv6 的回包
// 在 IPv4 socket 上发不出去。每条规则的 down_pkts、down_bytes 精确
func TestUDPReturnMultiRule(t *testing.T) {
	t.Parallel()
	type rule struct {
		listen string
		be     *udpRecorder
	}
	rules := []rule{
		{loopback4(t), quietUDP(t, loopback4(t))},
		{loopback4(t), quietUDP(t, loopback4(t))},
		{hostPort("::1", freePort(t)), quietUDP(t, hostPort("::1", freePort(t)))},
	}
	var cfg strings.Builder
	var wait []listenPoint
	for _, r := range rules {
		fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", r.listen, r.be.addr)
		wait = append(wait, listenPoints("u", portOf(r.listen))...)
	}
	m := startMapper(t, wait, "-c", writeConfig(t, cfg.String()))

	const perRule, k = 2, 15
	type client struct {
		rule    int
		c       *net.UDPConn
		session string
		want    [][]byte
	}
	var clients []*client
	for j := range perRule {
		for r, rl := range rules {
			to, err := net.ResolveUDPAddr("udp", rl.listen)
			if err != nil {
				t.Fatal(err)
			}
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: to.IP})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			cl := &client{rule: r, c: c}
			cl.session = helloSession(t, rl.be, fmt.Appendf(nil, "hello-r%d-c%d", r, j), func(b []byte) error {
				_, err := c.WriteToUDP(b, to)
				return err
			})
			clients = append(clients, cl)
		}
	}
	var replies []udpReply
	for seq := range k {
		for ci, cl := range clients {
			msg := fmt.Appendf(nil, "rule%d-c%d-s%02d-", cl.rule, ci, seq)
			for j := range (ci*11 + seq*7) % 40 {
				msg = append(msg, byte('a'+(ci+j)%26))
			}
			replies = append(replies, udpReply{rules[cl.rule].be, cl.session, msg})
			cl.want = append(cl.want, msg)
		}
	}
	m.pause(t)
	queueReplies(t, m, replies)
	m.resume(t)

	buf := make([]byte, 2048)
	for ci, cl := range clients {
		lp := netip.MustParseAddrPort(rules[cl.rule].listen)
		for j, w := range cl.want {
			cl.c.SetReadDeadline(time.Now().Add(ioTimeout))
			n, from, err := cl.c.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatalf("规则 %d 的客户端 %d 第 %d 个回包：%v", cl.rule+1, ci, j, err)
			}
			if from := netip.AddrPortFrom(from.Addr().Unmap(), from.Port()); from != lp {
				t.Errorf("规则 %d 的客户端 %d 第 %d 个回包来自 %s，期望来自本规则的监听地址 %s", cl.rule+1, ci, j, from, lp)
			}
			if !bytes.Equal(buf[:n], w) {
				t.Fatalf("规则 %d 的客户端 %d 第 %d 个回包为 %q，期望 %q", cl.rule+1, ci, j, buf[:n], w)
			}
		}
	}
	d := m.statsAfterSignal(t)
	for r, rl := range rules {
		var want [][]byte
		for _, cl := range clients {
			if cl.rule == r {
				want = append(want, cl.want...)
			}
		}
		s := d.udp[r+1]
		if s.sessions != perRule || int(s.total) != perRule {
			t.Errorf("规则 %d 统计 sessions=%d total=%d，期望 %d/%d", r+1, s.sessions, s.total, perRule, perRule)
		}
		if s.downPkts != uint64(len(want)) || s.downBytes != totalLen(want) || s.downDrop != 0 {
			t.Errorf("规则 %d 统计 down_pkts=%d down_bytes=%d down_drop=%d，期望 %d/%d/0", r+1, s.downPkts, s.downBytes, s.downDrop, len(want), totalLen(want))
		}
		if s.upPkts != uint64(rl.be.count()) {
			t.Errorf("规则 %d 统计 up_pkts=%d，期望 %d", r+1, s.upPkts, rl.be.count())
		}
	}
}

// U4：低负载时回包不等定时器。回程批在每轮循环阻塞之前（ev_prepare）发出：一问一答时回包所在的那一轮结束前就发出去了。只在批满或
// 400 ms 的定时器里发出时，每个回包平均多等约 200 ms；只在下一次入向收包之前发出时，回包要等客户端的下一个请求，一问一答就卡住。
// 200 次顺序往返，每次都应远低于 50 ms：全量并行时调度偶有延迟，允许至多 10 次超过 50 ms，1 s 没有回包就重发一次（环回偶有丢包）
func TestUDPReturnLatency(t *testing.T) {
	t.Parallel()
	const rounds, slowLimit, maxSlow = 200, 50 * time.Millisecond, 10
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	forward(t, "u", listen, be.addr)
	c := udpDial(t, "", listen)
	buf := make([]byte, 100)
	var lat []time.Duration
	slowN := 0
	for i := range rounds {
		msg := fmt.Appendf(nil, "rtt-%03d", i)
		start := time.Now()
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			if _, err = c.Write(msg); err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			var n int
			for n, err = c.Read(buf); err == nil && !bytes.Equal(buf[:n], msg); n, err = c.Read(buf) {
				// 上一次往返重发后迟到的回包
			}
			if err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("第 %d 次往返重发后 1 s 内仍没有回包：%v", i, err)
		}
		d := time.Since(start)
		lat = append(lat, d)
		if d > slowLimit {
			if slowN++; slowN > maxSlow {
				t.Fatalf("前 %d 次往返里已有 %d 次超过 %v（本次 %v）：回包在等定时器或下一个请求，没有在本轮循环结束前发出", i+1, slowN, slowLimit, d)
			}
		}
	}
	slices.Sort(lat)
	t.Logf("%d 次往返：中位数 %v，第 99 百分位 %v，最大 %v，超过 %v 的 %d 次", rounds, lat[rounds/2], lat[rounds*99/100], lat[rounds-1], slowLimit, slowN)
}

// 只有回程流量的会话（客户端发过一个请求后只收不发，如订阅推送）全靠回程的 lru.update 刷新空闲时间（U4 起每次回调刷新一次）：
// 后端每 15 s 向会话推一个包、持续 200 s，超过 conn_timeout_udp（180 s）：会话不能被当作空闲清理，客户端收到全部推送
func TestUDPSessionOneWayDown(t *testing.T) {
	t.Parallel()
	slow(t)
	be := quietUDP(t, loopback4(t))
	listen := loopback4(t)
	m := forward(t, "u", listen, be.addr)
	c := udpDial(t, "", listen)
	session := helloConn(t, be, c, []byte("subscribe"))
	sent := 0
	for start := time.Now(); time.Since(start) < 200*time.Second; sent++ {
		msg := fmt.Appendf(nil, "push-%d", sent)
		be.sendTo(t, session, msg)
		expectReplies(t, c, [][]byte{msg}, fmt.Sprintf("第 %d 次推送（会话建立后 %v）", sent, time.Since(start).Round(time.Second)))
		time.Sleep(15 * time.Second)
	}
	m.fatalIfExited(t, "单向推送 200 s 后")
	if n := m.logLines("[udp]inactive connection", "cleared"); n != 0 {
		t.Errorf("日志里有 %d 行会话清理：只有回程流量的会话被当作空闲清理了（回程没有刷新 LRU）", n)
	}
	if s := m.statsAfterSignal(t).udp[1]; s.total != 1 || s.downPkts != uint64(sent) {
		t.Errorf("统计 total=%d down_pkts=%d，期望 1/%d", s.total, s.downPkts, sent)
	}
}

// icmpPortUnreachable 用原始 socket 向本机发一个 ICMP 端口不可达（type 3 code 3），内层是 from → to 的 IPv4 UDP 包头，两者都是
// "127.x.x.x:port"。内核按内层四元组找到本端为 from、connect 到 to 的 UDP socket（__udp4_lib_err）：端口不可达是硬错误，
// connect 过的 socket 置 sk_err=ECONNREFUSED，此后第一次收包先返回这个错误，队列里的包留给下一次（__skb_recv_udp 先查 sock_error）。
// 收 ICMP 不受发送方向的限速影响。需要 CAP_NET_RAW（Docker 默认给 root），没有时跳过用例
func icmpPortUnreachable(t testing.TB, from, to string) {
	t.Helper()
	src, dst := netip.MustParseAddrPort(from), netip.MustParseAddrPort(to)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("建原始 ICMP socket 失败（没有 CAP_NET_RAW？）：%v", err)
	}
	defer syscall.Close(fd)
	csum := func(b []byte) uint16 {
		var s uint32
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		for s > 0xffff {
			s = s>>16 + s&0xffff
		}
		return ^uint16(s)
	}
	pkt := make([]byte, 8+20+8)
	pkt[0], pkt[1] = 3, 3 // ICMP_DEST_UNREACH、ICMP_PORT_UNREACH；pkt[4:8] 未用
	ip := pkt[8:28]
	ip[0], ip[8], ip[9] = 0x45, 64, syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[2:], 28)
	copy(ip[12:16], src.Addr().AsSlice())
	copy(ip[16:20], dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(ip[10:], csum(ip))
	udp := pkt[28:]
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], 8)
	binary.BigEndian.PutUint16(pkt[2:], csum(pkt))
	if err := syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: dst.Addr().As4()}); err != nil {
		t.Fatalf("发送 ICMP 端口不可达失败：%v", err)
	}
}

// U4：会话 socket 上同时有待取的 ICMP 错误与排队的回包（u4-review 的建议）。暂停期间后端向会话排 k 个回包，再伪造一个"后端端口不可达"
// 的 ICMP 让会话 socket 带上 ECONNREFUSED：恢复后 udp_cb 的 recvmmsg 先返回这个错误（一行 "[udp]recv failed ... Connection refused"，
// 不能把它当成没有数据或丢掉会话），排着的 k 个回包下一轮照收照发；之后后端再发 m 个，同一会话照常回到客户端。从 --log-level 6 的
// 日志确认错误先于这些回包的收包 trace。down_pkts 精确，之后不空转
func TestUDPReturnRecvError(t *testing.T) {
	t.Parallel()
	const k, more = 5, 3
	be := quietUDP(t, loopback4(t))
	listen := loopback4(t)
	m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u", "--log-level", "6")
	c := udpDial(t, "", listen)
	session := helloConn(t, be, c, []byte("hello"))
	var replies []udpReply
	var want [][]byte
	for i := range k {
		msg := fmt.Appendf(nil, "before-%d", i)
		replies = append(replies, udpReply{be, session, msg})
		want = append(want, msg)
	}
	m.pause(t)
	queueReplies(t, m, replies)
	icmpPortUnreachable(t, session, be.addr)
	m.resume(t)
	expectReplies(t, c, want, "客户端（ICMP 错误之前排队的回包）")
	var after [][]byte
	for i := range more {
		msg := fmt.Appendf(nil, "after-%d", i)
		be.sendTo(t, session, msg)
		expectReplies(t, c, [][]byte{msg}, "客户端（ICMP 错误之后）")
		after = append(after, msg)
	}
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		if n := m.logLines("[udp]recv failed", "Connection refused"); n != 1 {
			return fmt.Errorf("日志里有 %d 行会话 socket 的 recv 失败（ECONNREFUSED），期望 1：伪造的 ICMP 没有生效或错误被报了多次", n)
		}
		return nil
	})
	data, _ := os.ReadFile(m.logPath)
	lines := strings.Split(string(data), "\n")
	iErr := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "[udp]recv failed") })
	// 835690e 的逐包 recv 在判断错误之前就记 trace（len=-1），跳过它
	iData := slices.IndexFunc(lines, func(l string) bool {
		return strings.Contains(l, "received data from udp fd") && !strings.HasSuffix(l, "len=-1")
	})
	if iData >= 0 && iErr > iData {
		t.Errorf("日志里第一行回程收包 trace（第 %d 行）早于 recv 失败（第 %d 行）：用例前提不成立，期望错误先于排队的回包返回", iData, iErr)
	}
	s := m.statsAfterSignal(t).udp[1]
	if s.downPkts != k+more || s.downBytes != totalLen(want, after) || s.downDrop != 0 || s.sessions != 1 || s.total != 1 {
		t.Errorf("统计 down_pkts=%d down_bytes=%d down_drop=%d sessions=%d total=%d，期望 %d/%d/0/1/1",
			s.downPkts, s.downBytes, s.downDrop, s.sessions, s.total, k+more, totalLen(want, after))
	}
	m.expectIdleCPU(t, "会话 socket 的 ICMP 错误取走之后")
}

// U4：回程批的 ev_prepare watcher 每轮循环都执行，不能让循环空转（u4-review 的建议）：TCP+UDP 规则上只有 TCP 流量（回程批一直是空的）
// 之后，以及一次 UDP 往返之后，tinymapper 都应空闲
func TestUDPReturnIdle(t *testing.T) {
	t.Parallel()
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	serveUDP(t, remote, "")
	listen := loopback4(t)
	m := forward(t, "tu", listen, remote)
	mustEcho(t, dial(t, listen), "tcp")
	m.expectIdleCPU(t, "TCP+UDP 规则上只有 TCP 流量之后")
	udpReplyFrom(t, udpDial(t, "", listen), "udp")
	m.expectIdleCPU(t, "一次 UDP 往返之后")
}

// ---- U6：UDP socket 缓冲（D38–D40）----

// udpBufModes 是 U6 用例的两种权限：cap 直接启动 tinymapper（tests/run.sh 的容器里以 root 运行，有 CAP_NET_ADMIN），nocap 由
// startMapperNoNetAdmin 去掉这项能力后启动
var udpBufModes = []struct {
	name     string
	netAdmin bool
}{{"cap", true}, {"nocap", false}}

// startUDPBufMapper 按 netAdmin 启动 tinymapper，并核对它的 CapEff 里是否真有 CAP_NET_ADMIN
func startUDPBufMapper(t testing.TB, netAdmin bool, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	if !netAdmin {
		return startMapperNoNetAdmin(t, wait, args...)
	}
	needNetAdmin(t)
	m := startMapper(t, wait, args...)
	if !hasNetAdmin(t, m.pid()) {
		t.Fatalf("tinymapper（pid %d）没有 CAP_NET_ADMIN（CapEff=%#x）", m.pid(), capEff(t, m.pid()))
	}
	return m
}

// udpBufWant 返回请求 req 字节时 UDP socket 缓冲的期望值：force（tinymapper 有 CAP_NET_ADMIN 且对这个 socket 用 SO_*BUFFORCE）时不截断，
// 恰为 2×req；否则为
// 2×min(req, rmem_max/wmem_max)，与测试自己的 socket 上用 SO_RCVBUF/SO_SNDBUF 设出的值相同
func udpBufWant(t testing.TB, force bool, req int) sockBuf {
	t.Helper()
	if force {
		return sockBuf{rcv: uint32(2 * req), snd: uint32(2 * req)}
	}
	return setBuf(t, req)
}

// udpBufInfoLine 是监听 socket 的缓冲小于 2×请求值（req 字节）时第 rule 条规则的 info 行（D40），got 为实际的缓冲
func udpBufInfoLine(rule int, got sockBuf, req int) string {
	return fmt.Sprintf("rule %d [udp] listen socket buffers are rcv %d / snd %d bytes instead of %d: "+
		"capped by net.core.rmem_max/wmem_max, raise them to at least %d or run with CAP_NET_ADMIN", rule, got.rcv, got.snd, 2*req, req)
}

// udpBufForceFailed 是 SO_*BUFFORCE 第一次失败（EPERM）时的 debug 行，之后整个进程只用 SO_SNDBUF/SO_RCVBUF，不再记
const udpBufForceFailed = "SO_SNDBUFFORCE/SO_RCVBUFFORCE failed (1:Operation not permitted), UDP socket buffers are capped by net.core.rmem_max/wmem_max"

// U6（D38–D40）：UDP socket 的缓冲。tinymapper 先用 SO_SNDBUFFORCE/SO_RCVBUFFORCE（要 CAP_NET_ADMIN，不受 rmem_max/wmem_max 截断），
// 第一次失败后整个进程只用 SO_SNDBUF/SO_RCVBUF；监听 socket 按 --udp-listen-buf（默认 2048 KiB），会话 socket 按 --sock-buf（默认
// 1 MiB），会话 socket 只在给了 --sock-buf 时才用 FORCE（D38 修订）。cap 与 nocap 各跑一遍，经 sock_diag 查监听 socket 和 3 个
// 会话 socket：用了 FORCE 的（cap 下的监听 socket，cap 且给了 --sock-buf 时的会话 socket）恰为 2×请求值，其余为 2×min(请求值,
// rmem_max/wmem_max)（默认 rmem_max 为 212992，内核存 425984；cap/default 的会话 socket 因此与 nocap 相同）。请求值低于 rmem_max、介于 rmem_max 与其 2 倍之间（300 KiB：
// 截断后 425984 仍大于请求值，info 的条件少了内核的 2 倍时看不出截断）、远高于 rmem_max 的各有一组，--udp-listen-buf 的边界值
// 10、10240 也在这里（越界的值见 TestConfigInvalid）。日志（--log-level 5，log-level-4 一组除外）：
//   - 监听 socket 小于 2×请求值时恰有一行 info，带实际的 rcv/snd 与请求值；否则没有（cap，以及 nocap 下请求值不高于 rmem_max）；
//   - nocap 下 FORCE 失败的 debug 行恰有一行：失败在第一个 UDP socket（监听 socket）上，之后的会话 socket 不再试。缺了失败缓存时
//     给了 --sock-buf 的一组里每个会话 socket 都再试一次、再记一行（配置模式的三个监听 socket 同样），所以先建 3 个会话再数；
//     cap 下一行也没有；默认的 --log-level 4 下也没有（只有 info 行）
func TestUDPSockBuf(t *testing.T) {
	t.Parallel()
	t.Logf("测试进程 CapEff=%#x；SO_RCVBUF/SO_SNDBUF 设 2 MiB 得到 %v", capEff(t, os.Getpid()), setBuf(t, 2<<20))
	const sessions = 3
	for _, mode := range udpBufModes {
		for _, c := range []struct {
			name            string
			extra           []string
			listen, session int  // 监听 socket、会话 socket 请求的字节数
			level4          bool // 以 --log-level 4 运行：debug 行不该出现
			sockBuf         bool // 给了 --sock-buf：会话 socket 也用 FORCE
		}{
			{"default", nil, 2048 << 10, 1 << 20, false, false},
			{"log-level-4", []string{"--log-level", "4"}, 2048 << 10, 1 << 20, true, false},
			{"listen-3000", []string{"--udp-listen-buf", "3000"}, 3000 << 10, 1 << 20, false, false},
			{"listen-300", []string{"--udp-listen-buf", "300"}, 300 << 10, 1 << 20, false, false},
			{"listen-100", []string{"--udp-listen-buf", "100"}, 100 << 10, 1 << 20, false, false},
			{"listen-10", []string{"--udp-listen-buf", "10"}, 10 << 10, 1 << 20, false, false},
			{"listen-10240", []string{"--udp-listen-buf", "10240"}, 10240 << 10, 1 << 20, false, false},
			{"sock-buf-40", []string{"--sock-buf", "40"}, 2048 << 10, 40 << 10, false, true},
			{"sock-buf-3000", []string{"--sock-buf", "3000"}, 2048 << 10, 3000 << 10, false, true},
		} {
			t.Run(mode.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				be := serveUDP(t, loopback4(t), "")
				listen := loopback4(t)
				// 同一选项给了两次时后一个生效：log-level-4 一组的 --log-level 4 盖过这里的 5
				args := append([]string{"-l", listen, "-r", be.addr, "-u", "--log-level", "5"}, c.extra...)
				m := startUDPBufMapper(t, mode.netAdmin, listenPoints("u", portOf(listen)), args...)
				for range sessions {
					udpReplyFrom(t, udpDial(t, "", listen), "udp") // 首包创建会话 socket
				}
				peers := be.peerList()
				if len(peers) != sessions {
					t.Fatalf("后端看到的源地址为 %v，期望恰好 %d 个（tinymapper 的会话 socket）", peers, sessions)
				}
				// 统计行写完后 tinymapper fflush stdout：此前的日志（启动时的 info 行、debug 行）都已在文件里
				if s := m.statsAfterSignal(t).udp[1]; s.sessions != sessions {
					t.Fatalf("统计 sessions=%d，期望 %d", s.sessions, sessions)
				}

				for _, s := range []struct {
					name, local, remote string
					req                 int
					force               bool // 期望用 FORCE 设
				}{
					{"UDP 监听 socket", listen, "0.0.0.0:0", c.listen, mode.netAdmin},
					{"UDP 会话 socket 1", peers[0], be.addr, c.session, mode.netAdmin && c.sockBuf},
					{"UDP 会话 socket 2", peers[1], be.addr, c.session, mode.netAdmin && c.sockBuf},
					{"UDP 会话 socket 3", peers[2], be.addr, c.session, mode.netAdmin && c.sockBuf},
				} {
					got, want := lookupSockBuf(t, m.pid(), syscall.IPPROTO_UDP, s.name, s.local, s.remote), udpBufWant(t, s.force, s.req)
					t.Logf("%s：%v", s.name, got)
					if got.rcv != want.rcv || got.snd != want.snd {
						t.Errorf("%s rcvbuf=%d sndbuf=%d，期望 %d、%d（请求 %d 字节，CAP_NET_ADMIN=%v，FORCE=%v）", s.name, got.rcv, got.snd, want.rcv, want.snd, s.req, mode.netAdmin, s.force)
					}
				}

				lis := udpBufWant(t, mode.netAdmin, c.listen)
				wantInfo := 0
				if lis.rcv < uint32(2*c.listen) || lis.snd < uint32(2*c.listen) {
					wantInfo = 1
				} else if !mode.netAdmin && c.name == "default" {
					t.Logf("rmem_max/wmem_max 不低于 2 MiB：nocap 下默认请求也不截断，info 行出现的分支没有覆盖")
				}
				if n := m.logLines(udpBufInfoLine(1, lis, c.listen)); n != wantInfo {
					t.Errorf("日志中有 %d 行 %q，期望 %d 行", n, udpBufInfoLine(1, lis, c.listen), wantInfo)
				}
				if n := m.logLines("listen socket buffers are"); n != wantInfo {
					t.Errorf("日志中有 %d 行监听 socket 缓冲的 info，期望 %d 行", n, wantInfo)
				}
				wantDebug := 1
				if mode.netAdmin || c.level4 {
					wantDebug = 0
				}
				if n := m.logLines(udpBufForceFailed); n != wantDebug {
					t.Errorf("建了 %d 个会话之后日志中有 %d 行 %q，期望 %d 行", sessions, n, udpBufForceFailed, wantDebug)
				}
			})
		}
	}
}

// U6：配置文件模式下 --udp-listen-buf（D39，作用于整个进程）对每条 UDP 规则的监听 socket 生效。四条规则：TCP+UDP、仅 UDP、仅 TCP、
// IPv6 的 TCP+UDP，--udp-listen-buf 3000（高于默认的 rmem_max）。cap 下三个 UDP 监听 socket 都恰为 2×3000 KiB，没有 info 行；
// nocap 下为 2×min(3000 KiB, rmem_max/wmem_max)，UDP 规则 1、2、4 各有一行 info，仅 TCP 的规则 3 没有；FORCE 失败的 debug 行只有
// 一行（三个监听 socket，缺了失败缓存时有三行）
func TestUDPSockBufConfig(t *testing.T) {
	t.Parallel()
	const req = 3000 << 10
	for _, mode := range udpBufModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			remote := loopback4(t) // 只看监听 socket，不需要后端
			p1, p2, p3 := loopback4(t), loopback4(t), loopback4(t)
			p4 := hostPort("::1", freePort(t))
			cfg := writeConfig(t, fmt.Sprintf(`[[endpoints]]   # 规则 1：TCP + UDP
listen = %q
remote = %q
use_udp = true

[[endpoints]]   # 规则 2：仅 UDP
listen = %q
remote = %q
no_tcp = true
use_udp = true

[[endpoints]]   # 规则 3：仅 TCP
listen = %q
remote = %q

[[endpoints]]   # 规则 4：IPv6，TCP + UDP
listen = %q
remote = %q
use_udp = true
`, p1, remote, p2, remote, p3, remote, p4, remote))
			wait := slices.Concat(listenPoints("tu", portOf(p1)), listenPoints("u", portOf(p2)), listenPoints("t", portOf(p3)), listenPoints("tu", portOf(p4)))
			m := startUDPBufMapper(t, mode.netAdmin, wait, "-c", cfg, "--udp-listen-buf", "3000", "--log-level", "5")
			m.statsAfterSignal(t) // 统计行之后 fflush：启动时的日志都已在文件里

			want := udpBufWant(t, mode.netAdmin, req)
			wantInfo := 0
			if want.rcv < 2*req || want.snd < 2*req {
				wantInfo = 1
			}
			for _, r := range []struct {
				rule          int
				listen, other string
			}{{1, p1, "0.0.0.0:0"}, {2, p2, "0.0.0.0:0"}, {4, p4, "[::]:0"}} {
				name := fmt.Sprintf("规则 %d 的 UDP 监听 socket", r.rule)
				got := lookupSockBuf(t, m.pid(), syscall.IPPROTO_UDP, name, r.listen, r.other)
				t.Logf("%s：%v", name, got)
				if got.rcv != want.rcv || got.snd != want.snd {
					t.Errorf("%s rcvbuf=%d sndbuf=%d，期望 %d、%d", name, got.rcv, got.snd, want.rcv, want.snd)
				}
				if n := m.logLines(udpBufInfoLine(r.rule, want, req)); n != wantInfo {
					t.Errorf("日志中有 %d 行 %q，期望 %d 行", n, udpBufInfoLine(r.rule, want, req), wantInfo)
				}
			}
			if n := m.logLines("rule 3 [udp]"); n != 0 {
				t.Errorf("仅 TCP 的规则 3 有 %d 行 [udp] 日志，期望没有", n)
			}
			if n := m.logLines("listen socket buffers are"); n != 3*wantInfo {
				t.Errorf("日志中有 %d 行监听 socket 缓冲的 info，期望 %d 行（每条 UDP 规则 %d 行）", n, 3*wantInfo, wantInfo)
			}
			wantDebug := 1
			if mode.netAdmin {
				wantDebug = 0
			}
			if n := m.logLines(udpBufForceFailed); n != wantDebug {
				t.Errorf("三个 UDP 监听 socket 建好后日志中有 %d 行 %q，期望 %d 行", n, udpBufForceFailed, wantDebug)
			}
		})
	}
}
