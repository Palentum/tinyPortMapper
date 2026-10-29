package tests

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
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
func TestUDPMaxConn(t *testing.T) {
	t.Parallel()
	heavy(t)
	const maxConn = 20000
	const perIP, clientPortBase = 10000, 1024 // 每个源 IP 的客户端数与起始端口：1024..1024+perIP 低于 freePort 的 20001
	clientAddr := func(i int) *net.UDPAddr {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 1, byte(1+i/perIP)), Port: clientPortBase + i%perIP}
	}
	be := serveUDP(t, loopback4(t), "")
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
	if s := m.statsAfterSignal(t).udp[1]; s.sessions != maxConn {
		t.Errorf("统计 sessions=%d，期望 %d", s.sessions, maxConn)
	}
}
