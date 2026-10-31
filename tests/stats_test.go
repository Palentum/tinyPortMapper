// O1 运行时计数器（SIGUSR1 打印统计）的功能测试。
//
// O1（D25–D27）：收到 SIGUSR1 时 sigusr1_cb 为每条规则各打印一行 TCP、一行 UDP 统计（按启用的协议），再加一行进程级的池统计，
// 随后 fflush；不受 --log-level 过滤（--log-level 0 除外，什么都不写），用普通 [INFO] 前缀（mylog_unfiltered）。
// 热路径上只累加转发计数，当前连接数、半关闭对数、持有的块数在信号时沿 LRU 现数。
//
// 每次转储都复核池不变式（块池与 pipe 池各自 alloc==held+free+scratch；TCP/UDP 在用对象数==各规则连接数/会话数之和），
// 发布构建里也查（-assert 构建的 sigusr1_cb 自己也断言，破坏不变式会中止进程），所以每个用例都兼作泄漏检查。
//
// UDP 丢包用 seccomp 过滤器确定性注入：令指定 fd 区间的 sendto、sendmsg、sendmmsg 返回 EAGAIN（基线的上行与 udp_cb 的回程用
// send()/sendto()，arm64/x86_64 上都是 sendto 系统调用；U3 起上行直接调 sendmmsg 系统调用）。
// 这里用 init() 在重新执行的测试二进制里先装过滤器再 exec tinymapper，与 harness_test.go 的 epoll 故障注入同一套路。
package tests

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// ---- SIGUSR1 统计行的解析 ----

type tcpStat struct {
	conns, halfClosed         int
	total, upBytes, downBytes uint64
	// B1/B2（D49）：经 splice 从 pipe 写出的字节（up_bytes/down_bytes 的一部分），以及想 splice 但拿不到 pipe、改走 recv 的读次数
	upSplice, downSplice, spliceFallback uint64
}

// tcpStatLine 按 sigusr1_cb 的格式重新写出一行 tcp 统计（从 "stats rule" 起），解析后与原行逐字节比较：D49 只在行末加三项
func tcpStatLine(idx int, s tcpStat) string {
	return fmt.Sprintf("stats rule %d tcp: conns=%d total=%d half_closed=%d up_bytes=%d down_bytes=%d up_splice=%d down_splice=%d splice_fallback=%d",
		idx, s.conns, s.total, s.halfClosed, s.upBytes, s.downBytes, s.upSplice, s.downSplice, s.spliceFallback)
}

type udpStat struct {
	sessions                                                      int
	total, upPkts, upBytes, downPkts, downBytes, upDrop, downDrop uint64
	// U5（D42）：只有给了 --udp-gro 时行末才有这四项，gro 记录这一行是否带着它们
	gro                                            bool
	upGRO, downGRO, upGSOFallback, downGSOFallback uint64
}

// udpStatLine 按 sigusr1_cb 的格式重新写出一行 udp 统计（从 "stats rule" 起），解析后与原行逐字节比较
func udpStatLine(idx int, u udpStat) string {
	s := fmt.Sprintf("stats rule %d udp: sessions=%d total=%d up_pkts=%d up_bytes=%d down_pkts=%d down_bytes=%d up_drop=%d down_drop=%d",
		idx, u.sessions, u.total, u.upPkts, u.upBytes, u.downPkts, u.downBytes, u.upDrop, u.downDrop)
	if u.gro {
		s += fmt.Sprintf(" up_gro=%d down_gro=%d up_gso_fallback=%d down_gso_fallback=%d", u.upGRO, u.downGRO, u.upGSOFallback, u.downGSOFallback)
	}
	return s
}

type poolStat struct {
	alloc, held, free, scratch           int
	tcpSlabs, tcpFree, udpSlabs, udpFree int
	// B2（D49）：pipe 池，pipeHeld 是持有 pipe 的方向数（沿 LRU 现数）
	pipeAlloc, pipeHeld, pipeFree, pipeScratch int
	// B3（D58）：累计没能扩到 --pipe-size 的新 pipe 个数（含扩容失败之后、下一个定时器周期之前没试的）
	resizeFail uint64
}

// poolStatLine 按 sigusr1_cb 的格式重新写出 pool 行（从 "stats pool:" 起）：D49 只在行末加 pipes 四项，D58 再加 resize_fail
func poolStatLine(p poolStat) string {
	return fmt.Sprintf("stats pool: bufs alloc=%d held=%d free=%d scratch=%d tcp_pairs slabs=%d free=%d udp_pairs slabs=%d free=%d pipes alloc=%d held=%d free=%d scratch=%d resize_fail=%d",
		p.alloc, p.held, p.free, p.scratch, p.tcpSlabs, p.tcpFree, p.udpSlabs, p.udpFree, p.pipeAlloc, p.pipeHeld, p.pipeFree, p.pipeScratch, p.resizeFail)
}

type statsDump struct {
	tcp  map[int]tcpStat
	udp  map[int]udpStat
	pool poolStat
}

// parseStatsBlock 解析一组统计行（连续的 stats rule... 行加末尾一行 stats pool:）
func parseStatsBlock(block []string) (statsDump, error) {
	d := statsDump{tcp: map[int]tcpStat{}, udp: map[int]udpStat{}}
	poolSeen := false
	for _, line := range block {
		switch {
		case strings.Contains(line, "stats rule ") && strings.Contains(line, " tcp: "):
			s := line[strings.Index(line, "stats rule "):]
			var idx int
			var t tcpStat
			if _, err := fmt.Sscanf(s, "stats rule %d tcp: conns=%d total=%d half_closed=%d up_bytes=%d down_bytes=%d up_splice=%d down_splice=%d splice_fallback=%d",
				&idx, &t.conns, &t.total, &t.halfClosed, &t.upBytes, &t.downBytes, &t.upSplice, &t.downSplice, &t.spliceFallback); err != nil {
				return d, fmt.Errorf("解析 tcp 统计行失败：%q：%w", line, err)
			}
			if want := tcpStatLine(idx, t); s != want {
				return d, fmt.Errorf("tcp 统计行格式不符：%q，期望 %q", s, want)
			}
			d.tcp[idx] = t
		case strings.Contains(line, "stats rule ") && strings.Contains(line, " udp: "):
			s := line[strings.Index(line, "stats rule "):]
			var idx int
			var u udpStat
			if _, err := fmt.Sscanf(s, "stats rule %d udp: sessions=%d total=%d up_pkts=%d up_bytes=%d down_pkts=%d down_bytes=%d up_drop=%d down_drop=%d",
				&idx, &u.sessions, &u.total, &u.upPkts, &u.upBytes, &u.downPkts, &u.downBytes, &u.upDrop, &u.downDrop); err != nil {
				return d, fmt.Errorf("解析 udp 统计行失败：%q：%w", line, err)
			}
			if i := strings.Index(s, " up_gro="); i >= 0 {
				u.gro = true
				if _, err := fmt.Sscanf(s[i:], " up_gro=%d down_gro=%d up_gso_fallback=%d down_gso_fallback=%d",
					&u.upGRO, &u.downGRO, &u.upGSOFallback, &u.downGSOFallback); err != nil {
					return d, fmt.Errorf("解析 udp 统计行的 GRO 计数失败：%q：%w", line, err)
				}
			}
			// 不带 --udp-gro 时必须与 U5 之前的行逐字节相同，带时只在末尾多四项（D42）
			if want := udpStatLine(idx, u); s != want {
				return d, fmt.Errorf("udp 统计行格式不符：%q，期望 %q", s, want)
			}
			d.udp[idx] = u
		case strings.Contains(line, "stats pool: "):
			s := line[strings.Index(line, "stats pool: "):]
			p := &d.pool
			if _, err := fmt.Sscanf(s, "stats pool: bufs alloc=%d held=%d free=%d scratch=%d tcp_pairs slabs=%d free=%d udp_pairs slabs=%d free=%d pipes alloc=%d held=%d free=%d scratch=%d resize_fail=%d",
				&p.alloc, &p.held, &p.free, &p.scratch, &p.tcpSlabs, &p.tcpFree, &p.udpSlabs, &p.udpFree,
				&p.pipeAlloc, &p.pipeHeld, &p.pipeFree, &p.pipeScratch, &p.resizeFail); err != nil {
				return d, fmt.Errorf("解析 pool 统计行失败：%q：%w", line, err)
			}
			if want := poolStatLine(*p); s != want {
				return d, fmt.Errorf("pool 统计行格式不符：%q，期望 %q", s, want)
			}
			poolSeen = true
		}
	}
	if !poolSeen {
		return d, fmt.Errorf("统计块里没有 pool 行：%q", block)
	}
	return d, nil
}

const objPoolSlabObjs = 64 // main.cpp 的 obj_pool_slab_objs

// checkPoolInvariants 从解析出的数字复核池不变式（发布构建里也要查）：块池与 pipe 池各自 alloc==held+free+scratch，
// 两个对象池的在用对象数等于各规则连接数/会话数之和；另外 pipe 池空闲不超过上限、scratch 至多一个，每个方向至多持有块与 pipe 之一，
// splice 字节是同方向字节的一部分（D49）
func checkPoolInvariants(t testing.TB, d statsDump) {
	t.Helper()
	p := d.pool
	if p.alloc != p.held+p.free+p.scratch {
		t.Fatalf("池不变式 alloc==held+free+scratch 不成立：alloc=%d held=%d free=%d scratch=%d", p.alloc, p.held, p.free, p.scratch)
	}
	if p.pipeAlloc != p.pipeHeld+p.pipeFree+p.pipeScratch {
		t.Fatalf("pipe 池不变式 alloc==held+free+scratch 不成立：pipes alloc=%d held=%d free=%d scratch=%d",
			p.pipeAlloc, p.pipeHeld, p.pipeFree, p.pipeScratch)
	}
	if p.pipeFree > pipePoolMaxFree || p.pipeScratch > 1 || p.scratch > 1 {
		t.Fatalf("pipe 池空闲 %d（上限 %d）、scratch pipe %d、scratch 块 %d：超出上限", p.pipeFree, pipePoolMaxFree, p.pipeScratch, p.scratch)
	}
	tcpConns := 0
	for idx, s := range d.tcp {
		tcpConns += s.conns
		if s.upSplice > s.upBytes || s.downSplice > s.downBytes {
			t.Fatalf("规则 %d：splice 字节多于同方向字节：up_splice=%d up_bytes=%d down_splice=%d down_bytes=%d",
				idx, s.upSplice, s.upBytes, s.downSplice, s.downBytes)
		}
	}
	if p.held+p.pipeHeld > 2*tcpConns {
		t.Fatalf("持有块 %d 个、持有 pipe %d 个，多于 %d 条 TCP 连接的方向数：一个方向至多持有其一", p.held, p.pipeHeld, tcpConns)
	}
	if p.tcpSlabs*objPoolSlabObjs-p.tcpFree != tcpConns {
		t.Fatalf("TCP 对象池不变式不成立：slabs*64-free=%d，各规则 conns 之和=%d（slabs=%d free=%d）",
			p.tcpSlabs*objPoolSlabObjs-p.tcpFree, tcpConns, p.tcpSlabs, p.tcpFree)
	}
	udpSessions := 0
	for _, s := range d.udp {
		udpSessions += s.sessions
	}
	if p.udpSlabs*objPoolSlabObjs-p.udpFree != udpSessions {
		t.Fatalf("UDP 对象池不变式不成立：slabs*64-free=%d，各规则 sessions 之和=%d（slabs=%d free=%d）",
			p.udpSlabs*objPoolSlabObjs-p.udpFree, udpSessions, p.udpSlabs, p.udpFree)
	}
}

func (m *mapper) sendUSR1(t testing.TB) {
	t.Helper()
	if err := m.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatalf("发送 SIGUSR1 失败：%v", err)
	}
}

// statsAfterSignal 发送 SIGUSR1，等到日志里多出一组统计（pool 行数增加），解析最后一组并复核池不变式。
// 进程若在此前退出则清晰失败（-assert 构建里被破坏的不变式会在此中止进程）
func (m *mapper) statsAfterSignal(t testing.TB) statsDump {
	t.Helper()
	before := m.logLines("stats pool:")
	m.sendUSR1(t)
	var dump statsDump
	eventually(t, everrorWithin+logFlushWithin, 10*time.Millisecond, func() error {
		m.fatalIfExited(t, "发送 SIGUSR1 后")
		data, _ := os.ReadFile(m.logPath)
		lines := strings.Split(string(data), "\n")
		poolIdx, count := -1, 0
		for i, l := range lines {
			if strings.Contains(l, "stats pool:") {
				count++
				poolIdx = i
			}
		}
		if count <= before {
			return fmt.Errorf("还没有新的统计输出（pool 行 %d，发信号前 %d）", count, before)
		}
		start := poolIdx
		for start-1 >= 0 && strings.Contains(lines[start-1], "stats rule ") {
			start--
		}
		d, err := parseStatsBlock(lines[start : poolIdx+1])
		if err != nil {
			return err
		}
		dump = d
		return nil
	})
	checkPoolInvariants(t, dump)
	// D48：--disable-splice 时不创建 pipe，splice 计数全 0
	if slices.Contains(m.cmd.Args, "--disable-splice") {
		if dump.pool.pipeAlloc != 0 {
			t.Errorf("--disable-splice 下 pipes alloc=%d，期望 0", dump.pool.pipeAlloc)
		}
		for idx, s := range dump.tcp {
			if s.upSplice != 0 || s.downSplice != 0 || s.spliceFallback != 0 {
				t.Errorf("--disable-splice 下规则 %d 的 splice 计数非零：up_splice=%d down_splice=%d splice_fallback=%d",
					idx, s.upSplice, s.downSplice, s.spliceFallback)
			}
		}
	}
	// D58：有 CAP_SYS_RESOURCE 的 tinymapper（tests/run.sh 的容器里以 root 启动的都有）扩容 pipe 不受 fs.pipe-max-size 与 pipe 限额约束，
	// resize_fail 应为 0；故意让扩容失败的用例设 growFailOK
	if dump.pool.resizeFail != 0 && !m.growFailOK && capEff(t, m.pid())&(1<<capSysResource) != 0 {
		t.Errorf("resize_fail=%d：tinymapper 有 CAP_SYS_RESOURCE，扩容 pipe 不应失败", dump.pool.resizeFail)
	}
	// U5（D42）：udp 行带不带 GRO 四项只取决于 --udp-gro（以及它是否因第一个监听 socket 开不了 UDP_GRO 而整体关闭，groOff）
	want := slices.Contains(m.cmd.Args, "--udp-gro") && !m.groOff
	for idx, s := range dump.udp {
		if s.gro != want {
			t.Errorf("规则 %d 的 udp 统计行%s GRO 计数，期望%s（--udp-gro %v）", idx, map[bool]string{true: "带", false: "不带"}[s.gro],
				map[bool]string{true: "带", false: "不带"}[want], want)
		}
	}
	return dump
}

// TCP：已知传输量下的双向字节精确。上/下行不同以便发现方向搞反；传输量大于一个 64 KiB 块。
// 数据完整性协议里客户端额外发 28 B 头（计入上行），后端额外回 64 B 校验尾（计入下行）
func TestStatsTCPBytes(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)
	const up, down = 200 << 10, 500 << 10
	if err := transfer(listen, up, down, 4096, 1); err != nil {
		t.Fatal(err)
	}
	d := m.statsAfterSignal(t)
	s, ok := d.tcp[1]
	if !ok {
		t.Fatalf("统计里没有规则 1 的 tcp 行：%+v", d.tcp)
	}
	if s.total != 1 {
		t.Errorf("tcp total=%d，期望 1", s.total)
	}
	if want := uint64(up + streamHeaderLen); s.upBytes != want {
		t.Errorf("up_bytes=%d，期望 %d（客户端→上游，含 %d B 头）", s.upBytes, want, streamHeaderLen)
	}
	if want := uint64(down + 64); s.downBytes != want {
		t.Errorf("down_bytes=%d，期望 %d（上游→客户端，含 64 B 校验尾）", s.downBytes, want)
	}
	if _, ok := d.udp[1]; ok {
		t.Errorf("仅 TCP 规则却打印了 udp 行：%+v", d.udp)
	}
}

// TCP：部分连接关闭、部分保持空闲后的 conns 与 total。关闭连接不减 total
func TestStatsTCPConns(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)
	const total = 5
	conns := make([]*net.TCPConn, total)
	for i := range conns {
		conns[i] = dial(t, listen)
		mustEcho(t, conns[i], "x")
	}
	conns[0].Close()
	conns[1].Close()
	var d statsDump
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		d = m.statsAfterSignal(t)
		if d.tcp[1].conns != 3 {
			return fmt.Errorf("当前连接数 %d，期望 3", d.tcp[1].conns)
		}
		return nil
	})
	if d.tcp[1].total != total {
		t.Errorf("tcp total=%d，期望 %d（关闭连接不应减少 total）", d.tcp[1].total, total)
	}
}

// TCP：半关闭。half_closed 统计恰好一侧发过 EOF 的连接对（两侧都 EOF 后立即释放）
func TestStatsTCPHalfClose(t *testing.T) {
	t.Parallel()
	t.Run("client", func(t *testing.T) {
		t.Parallel()
		// 后端读到 EOF 后不关（handler 返回时 serveTCP 会关闭连接，所以要停在 done 上）：客户端半关闭后 local.eof，连接对保持。
		// done 在 serveTCP 之后注册，清理时先于它关闭
		done := make(chan struct{})
		be := serveTCP(t, loopback4(t), func(c net.Conn) {
			io.Copy(io.Discard, c)
			<-done
		})
		t.Cleanup(func() { close(done) })
		listen := loopback4(t)
		m := forward(t, "t", listen, be.addr)
		c := dial(t, listen)
		if _, err := c.Write([]byte("hi")); err != nil {
			t.Fatal(err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			d := m.statsAfterSignal(t)
			if d.tcp[1].halfClosed != 1 || d.tcp[1].conns != 1 {
				return fmt.Errorf("half_closed=%d conns=%d，期望 1/1", d.tcp[1].halfClosed, d.tcp[1].conns)
			}
			return nil
		})
		if !m.aliveAfter(100 * time.Millisecond) {
			t.Fatal("发送 SIGUSR1 后进程退出")
		}
		// 客户端一侧读到 EOF 后去掉了 READ，客户端一侧一直可读
		m.expectIdleCPU(t, "客户端半关闭后（S3：EOF 去 READ）")
	})
	t.Run("upstream", func(t *testing.T) {
		t.Parallel()
		// 后端立即关写方向再只读：上游侧 EOF（remote.eof），客户端不关，连接对保持
		be := serveTCP(t, loopback4(t), func(c net.Conn) {
			c.(*net.TCPConn).CloseWrite()
			io.Copy(io.Discard, c)
		})
		listen := loopback4(t)
		m := forward(t, "t", listen, be.addr)
		c := dial(t, listen)
		// 读到上游转发来的 EOF，确认 shutdown 已传到客户端（此时 local 仍未 EOF）
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		if n, err := c.Read(make([]byte, 16)); n != 0 || err == nil {
			t.Fatalf("期望读到上游的 EOF，却得到 n=%d err=%v", n, err)
		}
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			d := m.statsAfterSignal(t)
			if d.tcp[1].halfClosed != 1 || d.tcp[1].conns != 1 {
				return fmt.Errorf("half_closed=%d conns=%d，期望 1/1", d.tcp[1].halfClosed, d.tcp[1].conns)
			}
			return nil
		})
		if !m.aliveAfter(100 * time.Millisecond) {
			t.Fatal("发送 SIGUSR1 后进程退出")
		}
		// 上游的 FIN 常与建连完成同一次回调读到：那时 S1 的 stop/start 已把 fd 排进 fd_reify，S3 去掉的 READ 随之进 epoll，
		// 所以这里不一定能抓到 S3 漏 stop/start（客户端子用例与 TestTCPHalfCloseConnecting 总能抓到），但仍检查这一状态不空转
		m.expectIdleCPU(t, "上游半关闭后（S3：EOF 去 READ）")
	})
}

// TCP：背压下持有的块数与 pipe 数。m 条下行方向同时持有（> 64 的空闲上限），排空后归零，持有过程与排空计数都要对。
// --sock-buf 32 把两侧 socket 缓冲锁小，慢读端（8 KiB 接收缓冲、小 MSS）让 tinymapper 持有并反复部分发送（走 write 分支）。
//   - blocks（--disable-splice，拷贝路径）：每个方向持有一块 64 KiB 缓冲，排空后超过 64 的空闲块 free；
//   - pipes（splice，B2）：后端以 32 KiB 一块写，每个方向第一次读（recv）就 ≥ 16 KiB、能整段发出，之后都 splice，发不完时持有 pipe：
//     峰值恰好 m 个方向持有 pipe、0 个持有块；排空后 pipe 还池，超过空闲上限的 close（默认 256 KiB 的 pipe 为 16 个，B3 审查 M1；
//     alloc 比峰值少），down_splice 非零，pipe fd 恰为 2×alloc
func TestStatsHeldBlocks(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		pipes bool
		extra []string
	}{
		{"blocks", false, []string{"--disable-splice"}},
		{"pipes", true, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if c.pipes {
				needPipeQuotaExempt(t)
			}
			heavy(t)
			heldBackpressure(t, c.pipes, c.extra...)
		})
	}
}

func heldBackpressure(t *testing.T, pipes bool, extra ...string) {
	const m, S = 96, 512 << 10
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		var i int
		fmt.Sscan(strings.TrimSpace(line), &i)
		writeStream(c, S, 32<<10, streamSeed(uint64(i), true))
		io.Copy(io.Discard, r) // 等客户端关闭
	})
	listen := loopback4(t)
	mp := startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t", "--sock-buf", "32"}, extra...)...)

	reader := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
	conns := make([]*net.TCPConn, m)
	for i := range conns {
		nc, err := reader.Dial("tcp", listen)
		if err != nil {
			t.Fatalf("连接 %s 失败：%v", listen, err)
		}
		c := nc.(*net.TCPConn)
		t.Cleanup(func() { c.Close() })
		conns[i] = c
		fmt.Fprintf(c, "%d\n", i) // 发 key 触发后端写 S 字节；客户端此后不读，形成下行背压
	}
	// 峰值：m 个方向都持有一块（blocks）或一个 pipe（pipes）
	var peak statsDump
	eventually(t, 3*ioTimeout, 100*time.Millisecond, func() error {
		peak = mp.statsAfterSignal(t)
		if held, other := peak.pool.held, peak.pool.pipeHeld; pipes && (other != m || held != 0) || !pipes && held != m {
			return fmt.Errorf("持有块数 %d、持有 pipe 数 %d，期望 %d 个方向都持有%s", held, other, m, map[bool]string{false: "块", true: " pipe"}[pipes])
		}
		return nil
	})
	if pipes {
		mp.expectPipeFDs(t, peak, "峰值")
	}
	// 慢读排空并校验端到端一致
	results := make(chan error, m)
	for i, c := range conns {
		i, c := i, c
		go func() { results <- slowVerify(c, S, streamSeed(uint64(i), true)) }()
	}
	for range conns {
		if err := <-results; err != nil {
			t.Fatalf("排空校验失败：%v", err)
		}
	}
	// 排空后持有归零；超过 64 的空闲块与 pipe 已释放（alloc 相应减少），不变式仍成立
	var d statsDump
	eventually(t, 3*ioTimeout, 100*time.Millisecond, func() error {
		d = mp.statsAfterSignal(t)
		if d.pool.held != 0 || d.pool.pipeHeld != 0 {
			return fmt.Errorf("排空后持有块数 %d、持有 pipe 数 %d，期望都为 0", d.pool.held, d.pool.pipeHeld)
		}
		return nil
	})
	t.Logf("峰值 pool %+v；排空后 pool %+v", peak.pool, d.pool)
	if d.pool.free > tcpBufPoolMaxFree {
		t.Errorf("空闲块 %d 超过上限 %d", d.pool.free, tcpBufPoolMaxFree)
	}
	if d.tcp[1].total != m {
		t.Errorf("tcp total=%d，期望 %d", d.tcp[1].total, m)
	}
	if want := uint64(m) * S; d.tcp[1].downBytes != want {
		t.Errorf("down_bytes=%d，期望 %d（经 write 分支排空的字节也要计数）", d.tcp[1].downBytes, want)
	}
	if !pipes {
		return
	}
	if c := pipePoolCap(defaultPipeSize); d.pool.pipeFree > c || d.pool.pipeAlloc >= peak.pool.pipeAlloc {
		t.Errorf("排空后 pipes alloc=%d free=%d（峰值 alloc %d）：空闲超过 %d 个的 pipe 应当 close", d.pool.pipeAlloc, d.pool.pipeFree,
			peak.pool.pipeAlloc, c)
	}
	if d.tcp[1].downSplice == 0 {
		t.Error("down_splice=0：持有 pipe 的方向排空时写出的是 splice 字节")
	}
	mp.expectPipeFDs(t, d, "排空后")
}

const tcpBufPoolMaxFree = 64 // main.cpp 的 tcp_buf_pool_max_free

// UDP：会话/总数、两个方向精确的包数与字节数、两个方向确定性的丢包。
// 用 seccomp 令选定 fd 区间的发送返回 EAGAIN：up、upbatch 子用例打会话 socket（上行丢），down 子用例打监听 socket（下行丢），
// 另一方向保持精确
func TestStatsUDPDrops(t *testing.T) {
	t.Parallel()
	const K = 5
	t.Run("up", func(t *testing.T) {
		t.Parallel()
		be := serveUDP(t, loopback4(t), "")
		listen := loopback4(t)
		wait := listenPoints("u", portOf(listen))
		args := []string{"-l", listen, "-r", be.addr, "-u"}
		n := startupFDs(t, wait, args...)
		// 会话 socket 的 fd ≥ n，令其 sendto 一律 EAGAIN；监听 fd < n 不受影响
		m := startMapperSendtoFail(t, n, 0, wait, args...)
		c := udpDial(t, "", listen)
		for range K {
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
		}
		var d statsDump
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			d = m.statsAfterSignal(t)
			if d.udp[1].upDrop != K {
				return fmt.Errorf("up_drop=%d，期望 %d", d.udp[1].upDrop, K)
			}
			return nil
		})
		s := d.udp[1]
		if s.upPkts != 0 || s.upBytes != 0 {
			t.Errorf("up_pkts=%d up_bytes=%d，期望全 0（上行发送全部失败）", s.upPkts, s.upBytes)
		}
		if s.downPkts != 0 || s.downBytes != 0 || s.downDrop != 0 {
			t.Errorf("下行计数非零 %+v：上行从未送达，不应有回包", s)
		}
		if s.sessions != 1 || s.total != 1 {
			t.Errorf("sessions=%d total=%d，期望 1/1", s.sessions, s.total)
		}
	})
	// 批量：暂停期间两个客户端交错排队各 kb 个包，恢复后同一批里两个会话（批内新建）的发送都 EAGAIN：up_drop 恰为 2kb、up_pkts 为 0，
	// 日志报告的丢包数之和与 up_drop 相同。批量发送时（日志为 sendmmsg 的 warn）EAGAIN 说明会话 socket 的发送缓冲已满，一组只试一次、
	// 丢掉组里剩下的全部包，所以每个会话恰好一行 "dropped kb packets"；EAGAIN 后逐包重试，或只把相邻的包分成一组，都会多出若干行
	t.Run("upbatch", func(t *testing.T) {
		t.Parallel()
		const kb = 20
		be := serveUDP(t, loopback4(t), "")
		listen := loopback4(t)
		wait := listenPoints("u", portOf(listen))
		args := []string{"-l", listen, "-r", be.addr, "-u"}
		n := startupFDs(t, wait, args...)
		m := startMapperSendtoFail(t, n, 0, wait, args...)
		a, b := udpDial(t, "", listen), udpDial(t, "", listen)
		var sends []udpSend
		for range kb {
			sends = append(sends, udpSend{a, []byte("ping-a")}, udpSend{b, []byte("ping-b")})
		}
		m.pause(t)
		queueUDP(t, m, listen, sends)
		m.resume(t)
		var d statsDump
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			d = m.statsAfterSignal(t)
			if d.udp[1].upDrop != 2*kb {
				return fmt.Errorf("up_drop=%d，期望 %d", d.udp[1].upDrop, 2*kb)
			}
			return nil
		})
		s := d.udp[1]
		if s.upPkts != 0 || s.upBytes != 0 {
			t.Errorf("up_pkts=%d up_bytes=%d，期望全 0（上行发送全部失败）", s.upPkts, s.upBytes)
		}
		if s.downPkts != 0 || s.downBytes != 0 || s.downDrop != 0 {
			t.Errorf("下行计数非零 %+v：上行从未送达，不应有回包", s)
		}
		if s.sessions != 2 || s.total != 2 {
			t.Errorf("sessions=%d total=%d，期望 2/2", s.sessions, s.total)
		}
		eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
			if drops, lines := loggedUpDrops(m); drops != 2*kb {
				return fmt.Errorf("日志里 %d 行上行发送失败的 warn 共报告丢 %d 个包，期望 %d", lines, drops, 2*kb)
			}
			return nil
		})
		if lines := m.logLines("[udp]sendmmsg returned -1,"); lines != 0 {
			if whole := m.logLines("[udp]sendmmsg returned -1,", fmt.Sprintf(",dropped %d packets", kb)); lines != 2 || whole != 2 {
				t.Errorf("日志里有 %d 行 sendmmsg 失败的 warn，其中 %d 行丢 %d 个包；期望每个会话恰好一行、丢掉整组（2 行）", lines, whole, kb)
			}
		}
	})
	t.Run("down", func(t *testing.T) {
		t.Parallel()
		be := serveUDP(t, loopback4(t), "")
		listen := loopback4(t)
		wait := listenPoints("u", portOf(listen))
		args := []string{"-l", listen, "-r", be.addr, "-u"}
		probe := startMapper(t, wait, args...)
		fd := listenFD(probe.pid(), "udp", portOf(listen))
		probe.stop(t, false)
		if fd < 0 {
			t.Fatal("探测时没有找到 UDP 监听 socket")
		}
		// 只令监听 fd 的 sendto 失败：会话 socket 的上行照常，回包经监听 socket sendto 下行失败
		m := startMapperSendtoFail(t, fd, fd+1, wait, args...)
		c := udpDial(t, "", listen)
		for range K {
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
		}
		var d statsDump
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			d = m.statsAfterSignal(t)
			if d.udp[1].downDrop != K {
				return fmt.Errorf("down_drop=%d，期望 %d", d.udp[1].downDrop, K)
			}
			return nil
		})
		s := d.udp[1]
		if s.upPkts != K || s.upBytes != uint64(K*4) {
			t.Errorf("up_pkts=%d up_bytes=%d，期望 %d/%d（上行应全部成功）", s.upPkts, s.upBytes, K, K*4)
		}
		if s.downPkts != 0 || s.downBytes != 0 {
			t.Errorf("down_pkts=%d down_bytes=%d，期望全 0（回包 sendto 全部失败）", s.downPkts, s.downBytes)
		}
		if s.upDrop != 0 {
			t.Errorf("up_drop=%d，期望 0", s.upDrop)
		}
		if s.sessions != 1 || s.total != 1 {
			t.Errorf("sessions=%d total=%d，期望 1/1", s.sessions, s.total)
		}
	})
	// 回程批量（U4）：监听 fd 的发送一律 EAGAIN，暂停期间 3 个会话各排 k 个回包，恢复后同一轮里收进回程批。downbatch 共 30 个，
	// 本轮阻塞之前一次发出：EAGAIN 丢掉该规则这一组剩下的全部包，恰好一行 "dropped 30 packets"（EAGAIN 后逐包重试会多出若干行）；
	// downbatchfull 共 90 个，跨一次批满，每行报告的丢包数不超过批大小 64，至少两行。down_drop 精确、down_pkts 为 0，日志报告的
	// 丢包数之和与 down_drop 相同；逐包 sendto 时（835690e）每包一行 "[udp]sento returned -1"。之后不空转
	for _, c := range []struct {
		name string
		k    int
	}{{"downbatch", 10}, {"downbatchfull", 30}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			const n = 3
			be := quietUDP(t, loopback4(t))
			listen := loopback4(t)
			wait := listenPoints("u", portOf(listen))
			args := []string{"-l", listen, "-r", be.addr, "-u"}
			probe := startMapper(t, wait, args...)
			fd := listenFD(probe.pid(), "udp", portOf(listen))
			probe.stop(t, false)
			if fd < 0 {
				t.Fatal("探测时没有找到 UDP 监听 socket")
			}
			m := startMapperSendtoFail(t, fd, fd+1, wait, args...)
			sessions := make([]string, n)
			for i := range sessions {
				sessions[i] = helloConn(t, be, udpDial(t, "", listen), fmt.Appendf(nil, "hello-%d", i))
			}
			var replies []udpReply
			for _, i := range interleaveOrder(n, c.k, true) {
				replies = append(replies, udpReply{be, sessions[i], []byte("pong")})
			}
			total := len(replies)
			m.pause(t)
			queueReplies(t, m, replies)
			m.resume(t)
			var d statsDump
			eventually(t, ioTimeout, 50*time.Millisecond, func() error {
				d = m.statsAfterSignal(t)
				if d.udp[1].downDrop != uint64(total) {
					return fmt.Errorf("down_drop=%d，期望 %d", d.udp[1].downDrop, total)
				}
				return nil
			})
			s := d.udp[1]
			if s.downPkts != 0 || s.downBytes != 0 {
				t.Errorf("down_pkts=%d down_bytes=%d，期望全 0（回包发送全部失败）", s.downPkts, s.downBytes)
			}
			if s.upPkts != uint64(be.count()) || s.upDrop != 0 {
				t.Errorf("up_pkts=%d up_drop=%d，期望 %d/0（上行应全部成功）", s.upPkts, s.upDrop, be.count())
			}
			if s.sessions != n || s.total != n {
				t.Errorf("sessions=%d total=%d，期望 %d/%d", s.sessions, s.total, n, n)
			}
			var batch []int
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				var drops, lines int
				if drops, lines, batch = loggedDownDrops(m); drops != total {
					return fmt.Errorf("日志里 %d 行回程发送失败的 warn 共报告丢 %d 个包，期望 %d", lines, drops, total)
				}
				return nil
			})
			if len(batch) != 0 {
				t.Logf("回程批量发送失败的 warn 各行报告的丢包数：%v", batch)
				switch {
				case total <= 64 && (len(batch) != 1 || batch[0] != total):
					t.Errorf("回程 sendmmsg 失败的 warn 报告 %v，期望恰好一行丢掉整组 %d 个", batch, total)
				case total > 64 && (len(batch) < 2 || slices.Max(batch) > 64):
					t.Errorf("回程 sendmmsg 失败的 warn 报告 %v，期望至少两行、每行不超过批大小 64", batch)
				}
			}
			m.expectIdleCPU(t, "回程发送 EAGAIN 之后")
		})
	}
	// 回程批量（U4）、两条规则：只有规则 1 的监听 fd 发送 EAGAIN。两条规则各 2 个会话、各 8 个回包，暂停期间排好，恢复后在同一轮里收进
	// 回程批、一次发出：规则 1 的组整组丢掉（EAGAIN 只丢该规则这一组剩下的包），规则 2 的组照发、按序到达；down_drop 只记在规则 1 上，
	// 规则 2 的 down_pkts、down_bytes 精确。批里的顺序是会话回调的顺序（各会话一次收完自己的回包），回调按就绪的逆序执行，所以先排
	// 规则 2 的会话、后排规则 1 的：规则 1 的组排在批首、先发，它的 EAGAIN 不能连累后面规则 2 的组
	t.Run("downmultirule", func(t *testing.T) {
		t.Parallel()
		const perRule, k = 2, 8
		bes := []*udpRecorder{quietUDP(t, loopback4(t)), quietUDP(t, loopback4(t))}
		listens := []string{loopback4(t), loopback4(t)}
		var cfg strings.Builder
		var wait []listenPoint
		for r := range bes {
			fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n\n", listens[r], bes[r].addr)
			wait = append(wait, listenPoints("u", portOf(listens[r]))...)
		}
		path := writeConfig(t, cfg.String())
		probe := startMapper(t, wait, "-c", path)
		fd := listenFD(probe.pid(), "udp", portOf(listens[0]))
		probe.stop(t, false)
		if fd < 0 {
			t.Fatal("探测时没有找到规则 1 的 UDP 监听 socket")
		}
		m := startMapperSendtoFail(t, fd, fd+1, wait, "-c", path)
		type client struct {
			rule    int
			c       *net.UDPConn
			session string
			want    [][]byte
		}
		var clients []*client
		for j := range perRule {
			for r := len(bes) - 1; r >= 0; r-- {
				c := udpDial(t, "", listens[r])
				clients = append(clients, &client{r, c, helloConn(t, bes[r], c, fmt.Appendf(nil, "hello-r%d-c%d", r, j)), nil})
			}
		}
		var replies []udpReply
		for seq := range k {
			for ci, cl := range clients {
				msg := fmt.Appendf(nil, "rule%d-c%d-s%d-%s", cl.rule, ci, seq, strings.Repeat("x", ci*3+seq))
				replies = append(replies, udpReply{bes[cl.rule], cl.session, msg})
				cl.want = append(cl.want, msg)
			}
		}
		m.pause(t)
		queueReplies(t, m, replies)
		m.resume(t)
		var want2 [][]byte
		for ci, cl := range clients {
			if cl.rule == 1 {
				expectReplies(t, cl.c, cl.want, fmt.Sprintf("规则 2 的客户端 %d ", ci))
				want2 = append(want2, cl.want...)
			}
		}
		for ci, cl := range clients {
			if cl.rule == 0 {
				cl.c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if nr, err := cl.c.Read(make([]byte, 100)); err == nil {
					t.Errorf("规则 1 的客户端 %d 收到 %d 字节回包：规则 1 的监听 fd 发送一律失败", ci, nr)
				}
			}
		}
		const dropped = perRule * k
		var d statsDump
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			if d = m.statsAfterSignal(t); d.udp[1].downDrop != dropped {
				return fmt.Errorf("规则 1 down_drop=%d，期望 %d", d.udp[1].downDrop, dropped)
			}
			return nil
		})
		if s := d.udp[1]; s.downPkts != 0 || s.downBytes != 0 {
			t.Errorf("规则 1 down_pkts=%d down_bytes=%d，期望全 0", s.downPkts, s.downBytes)
		}
		if s := d.udp[2]; s.downPkts != uint64(len(want2)) || s.downBytes != totalLen(want2) || s.downDrop != 0 {
			t.Errorf("规则 2 down_pkts=%d down_bytes=%d down_drop=%d，期望 %d/%d/0（另一条规则的发送失败不影响本规则）",
				s.downPkts, s.downBytes, s.downDrop, len(want2), totalLen(want2))
		}
		eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
			drops, lines, batch := loggedDownDrops(m)
			if drops != dropped {
				return fmt.Errorf("日志里 %d 行回程发送失败的 warn 共报告丢 %d 个包，期望 %d", lines, drops, dropped)
			}
			if len(batch) != 0 && (len(batch) != 1 || batch[0] != dropped) {
				t.Errorf("回程 sendmmsg 失败的 warn 报告 %v，期望恰好一行丢掉规则 1 的整组 %d 个", batch, dropped)
			}
			return nil
		})
		m.expectIdleCPU(t, "一条规则的回程发送 EAGAIN 之后")
	})
}

// 日志级别：--log-level 1 仍打印三类统计行；--log-level 0 什么都不打印且进程存活
func TestStatsLogLevel(t *testing.T) {
	t.Parallel()
	t.Run("level1", func(t *testing.T) {
		t.Parallel()
		remote := loopback4(t)
		serveTCP(t, remote, echoHandler(""))
		serveUDP(t, remote, "")
		listen := loopback4(t)
		m := startMapper(t, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--log-level", "1")
		mustEcho(t, dial(t, listen), "x")
		udpReplyFrom(t, udpDial(t, "", listen), "u")
		d := m.statsAfterSignal(t) // --log-level 1 下统计仍输出（不受过滤）
		if _, ok := d.tcp[1]; !ok {
			t.Errorf("--log-level 1 下缺少 tcp 统计行：%+v", d.tcp)
		}
		if _, ok := d.udp[1]; !ok {
			t.Errorf("--log-level 1 下缺少 udp 统计行：%+v", d.udp)
		}
	})
	t.Run("level0", func(t *testing.T) {
		t.Parallel()
		be := serveTCP(t, loopback4(t), echoHandler(""))
		listen := loopback4(t)
		m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--log-level", "0")
		mustEcho(t, dial(t, listen), "x")
		m.sendUSR1(t)
		time.Sleep(logFlushWithin) // 给足处理与刷新时间
		if n := m.logLines("stats "); n != 0 {
			t.Errorf("--log-level 0 下仍输出了 %d 行统计", n)
		}
		if !m.aliveAfter(100 * time.Millisecond) {
			t.Fatal("发送 SIGUSR1 后进程退出（--log-level 0 下应继续运行）")
		}
	})
}

// 多规则 TOML：规则 1 仅 TCP、规则 2 仅 UDP、规则 3 TCP+UDP。计数归属正确；仅 TCP 规则无 udp 行、仅 UDP 规则无 tcp 行；一次信号恰好一行 pool
func TestStatsMultiRule(t *testing.T) {
	t.Parallel()
	be1 := serveTCP(t, loopback4(t), echoHandler("a\n"))
	be2 := serveUDP(t, loopback4(t), "b")
	remote3 := loopback4(t)
	serveTCP(t, remote3, echoHandler("c\n"))
	serveUDP(t, remote3, "c")
	p1, p2, p3 := loopback4(t), loopback4(t), loopback4(t)
	cfg := writeConfig(t, fmt.Sprintf(`[[endpoints]]       # 规则 1：仅 TCP（默认）
listen = %q
remote = %q

[[endpoints]]       # 规则 2：仅 UDP
listen = %q
remote = %q
no_tcp = true
use_udp = true

[[endpoints]]       # 规则 3：TCP + UDP
listen = %q
remote = %q
use_udp = true
`, p1, be1.addr, p2, be2.addr, p3, remote3))
	wait := append(append(listenPoints("t", portOf(p1)), listenPoints("u", portOf(p2))...), listenPoints("tu", portOf(p3))...)
	m := startMapper(t, wait, "-c", cfg)

	if got := readLine(t, dial(t, p1)); got != "a" {
		t.Fatalf("规则 1 TCP 连到 %q，期望 a", got)
	}
	if got := udpReplyFrom(t, udpDial(t, "", p2), "x"); got != "b" {
		t.Fatalf("规则 2 UDP 发往 %q，期望 b", got)
	}
	if got := readLine(t, dial(t, p3)); got != "c" {
		t.Fatalf("规则 3 TCP 连到 %q，期望 c", got)
	}
	if got := udpReplyFrom(t, udpDial(t, "", p3), "x"); got != "c" {
		t.Fatalf("规则 3 UDP 发往 %q，期望 c", got)
	}

	d := m.statsAfterSignal(t)
	if _, ok := d.tcp[1]; !ok {
		t.Errorf("规则 1 缺少 tcp 行")
	}
	if _, ok := d.udp[1]; ok {
		t.Errorf("规则 1 仅 TCP，却有 udp 行")
	}
	if _, ok := d.udp[2]; !ok {
		t.Errorf("规则 2 缺少 udp 行")
	}
	if _, ok := d.tcp[2]; ok {
		t.Errorf("规则 2 仅 UDP，却有 tcp 行")
	}
	if _, ok := d.tcp[3]; !ok {
		t.Errorf("规则 3 缺少 tcp 行")
	}
	if _, ok := d.udp[3]; !ok {
		t.Errorf("规则 3 缺少 udp 行")
	}
	if d.tcp[1].total != 1 {
		t.Errorf("规则 1 tcp total=%d，期望 1", d.tcp[1].total)
	}
	if d.udp[2].total != 1 {
		t.Errorf("规则 2 udp total=%d，期望 1", d.udp[2].total)
	}
	if d.tcp[3].total != 1 || d.udp[3].total != 1 {
		t.Errorf("规则 3 tcp/udp total=%d/%d，期望 1/1", d.tcp[3].total, d.udp[3].total)
	}
	if n := m.logLines("stats pool:"); n != 1 {
		t.Errorf("一次信号后有 %d 行 pool 统计，期望恰好 1 行", n)
	}
}

// UDP 会话释放后的对象计数：EV_ERROR 释放一个会话后，当前会话数回到 k，已创建会话数 total=k+1，释放的对象必须归还对象池。
// AGENTS.md 记有“永不归还的 UDP 会话对象测不出”，O1 的 UDP 对象池不变式（slabs*64-free==sessions）现在能捕获它
func TestStatsUDPSessionRelease(t *testing.T) {
	t.Parallel()
	const k = 2
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	wait := listenPoints("u", portOf(listen))
	args := []string{"-l", listen, "-r", be.addr, "-u"}
	n := startupFDs(t, wait, args...)
	// fd ≥ n+k 的新会话 socket 加 epoll 失败 → udp_cb 收到 EV_ERROR 释放该会话
	m := startMapperEpollAddFail(t, n+k, 0, wait, args...)
	healthy := make([]*net.UDPConn, k)
	for i := range healthy {
		healthy[i] = udpDial(t, "", listen)
		udpReplyFrom(t, healthy[i], fmt.Sprintf("h-%d", i))
	}
	bad := udpDial(t, "", listen)
	if _, err := bad.Write([]byte("bad")); err != nil {
		t.Fatal(err)
	}
	// 等待条件必须只在失败的会话建立并被释放之后成立：只看 sessions==k 时，bad 的包到达之前的转储也满足（实测发布构建出现过一次）。
	// total==k+1 说明 bad 的会话已建立，sessions==k 说明它已被释放
	eventually(t, everrorWithin+logFlushWithin, 20*time.Millisecond, func() error {
		d := m.statsAfterSignal(t)
		if s := d.udp[1]; s.total != k+1 || s.sessions != k {
			return fmt.Errorf("udp total=%d sessions=%d，期望 %d/%d（失败的会话应先建立、再被 EV_ERROR 释放）", s.total, s.sessions, k+1, k)
		}
		return nil
	})
	// 释放后对象必须归还：slabs*64-free==sessions，由 statsAfterSignal 里的 checkPoolInvariants 保证（o1udpleak 在此被捕获）
}

// 域名 remote 会启动 DNS 线程，进程有两个线程。glibc 构建里 libev 用 signalfd，只在调用 ev_signal_start 的线程里屏蔽 SIGUSR1；
// DNS 线程在信号 watcher 启动之后创建、继承屏蔽字，发给进程的 SIGUSR1 才不会落到它头上走默认动作（终止进程）。
// 连发几次，每次都要有一组统计，进程不退出，转发照常
func TestStatsDomainRemote(t *testing.T) {
	t.Parallel()
	bport := freePort(t)
	// localhost 按 AF_UNSPEC 解析，取第一个结果，可能是 127.0.0.1 也可能是 ::1：两个都监听
	serveTCP(t, hostPort("127.0.0.1", bport), echoHandler(""))
	serveTCP(t, hostPort("::1", bport), echoHandler(""))
	listen := loopback4(t)
	m := forward(t, "t", listen, fmt.Sprintf("localhost:%d", bport))
	// event_loop 先 listen，再启动 DNS 线程：监听就绪时线程可能还没创建
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", m.pid()))
		if err != nil {
			return err
		}
		if len(tasks) < 2 {
			return fmt.Errorf("tinymapper 只有 %d 个线程：域名 remote 应启动 DNS 线程，本用例没有测到多线程", len(tasks))
		}
		return nil
	})
	mustEcho(t, dial(t, listen), "x")
	for range 5 {
		if s := m.statsAfterSignal(t).tcp[1]; s.total != 1 {
			t.Fatalf("tcp total=%d，期望 1", s.total)
		}
	}
	mustEcho(t, dial(t, listen), "y")
}

// ---- seccomp sendto 故障注入（确定性 UDP 丢包）----
//
// init() 在重新执行的测试二进制里运行：TPM_SENDTO_FAIL="lo hi" 存在时，装 seccomp 过滤器后 exec tinymapper，
// 使 fd 在 [lo, hi) 内的 sendto、sendmsg、sendmmsg 返回 EAGAIN，其他系统调用不受影响。基线的上行与 udp_cb 的回程用
// send()/sendto()，arm64/x86_64 上都是 sendto 系统调用；U3 的上行用 syscall(SYS_sendmmsg) 直接调 sendmmsg 系统调用，64 位 musl 上
// 也是（musl 的 sendmmsg 包装函数会逐个调 sendmsg，内核与 musl 的 msghdr 字段类型不同）。sendmsg 也拦下，是防将来改回 libc 的
// sendmmsg 时 musl 构建绕过过滤器：那时第一个 sendmsg 就失败，包装函数返回 -1，与真正的 sendmmsg 相同。过滤器按 args[0]（fd）比较。
// no_new_privs 与过滤器只作用于调用线程并由 execve 保留，对静态链接的 tinymapper 同样有效。
// 与 harness_test.go 的 TPM_EPOLL_ADD_FAIL 互不干扰（各认各的环境变量）

const sendtoFailEnv = "TPM_SENDTO_FAIL"

func init() {
	if spec := os.Getenv(sendtoFailEnv); spec != "" {
		execSendtoFail(spec)
	}
}

// sendmmsg 的系统调用号：syscall 包的 amd64 表里没有 SYS_SENDMMSG
var sendmmsgNR = map[string]uint32{"amd64": 307, "arm64": 269}

// sendtoFailFilter 返回 BPF 程序：arch 相符、nr 为 sendto/sendmsg/sendmmsg、lo ≤ args[0] < hi 时返回 SECCOMP_RET_ERRNO|errno
// （默认 EAGAIN；U5 的用例另用 ECONNREFUSED、EPERM 这类不是 GSO 本身的错误），否则放行。
// 只支持小端架构（取 u64 fd 的低 32 位）
func sendtoFailFilter(arch, lo, hi uint32, errno syscall.Errno) []syscall.SockFilter {
	const (
		ld   = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS
		jeq  = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		jge  = syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K
		ret  = syscall.BPF_RET | syscall.BPF_K
		nr   = 0      // struct seccomp_data：int nr; u32 arch; u64 ip; u64 args[6]
		arg0 = 16 + 0 // args[0]：fd
	)
	stmt := func(code uint16, k uint32) syscall.SockFilter { return syscall.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) syscall.SockFilter {
		return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	// 跳转偏移相对下一条指令；索引 10 为放行
	return []syscall.SockFilter{
		stmt(ld, 4),           // 0：arch
		jump(jeq, arch, 0, 8), // 1：不匹配 → 放行
		stmt(ld, nr),          // 2：nr
		jump(jeq, uint32(syscall.SYS_SENDTO), 2, 0),  // 3：sendto → 6
		jump(jeq, uint32(syscall.SYS_SENDMSG), 1, 0), // 4：sendmsg → 6
		jump(jeq, sendmmsgNR[runtime.GOARCH], 0, 4),  // 5：都不是 → 放行
		stmt(ld, arg0),                      // 6：fd
		jump(jge, lo, 0, 2),                 // 7：fd<lo → 放行
		jump(jge, hi, 1, 0),                 // 8：fd≥hi → 放行
		stmt(ret, 0x00050000|uint32(errno)), // 9：SECCOMP_RET_ERRNO|errno
		stmt(ret, 0x7fff0000),               // 10：SECCOMP_RET_ALLOW
	}
}

// execSendtoFail 在重新执行的测试二进制里运行：os.Args[1:] 是 tinymapper 的 argv。成功时不返回
func execSendtoFail(spec string) {
	const (
		prSetSeccomp      = 22
		prSetNoNewPrivs   = 38
		seccompModeFilter = 2
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "sendto 故障注入启动失败："+format+"\n", a...)
		os.Exit(127)
	}
	var lo, hi uint32
	errno := uint32(syscall.EAGAIN) // 可选的第三项
	if n, _ := fmt.Sscan(spec, &lo, &hi, &errno); n < 2 || len(os.Args) < 2 {
		fail("%s=%q 或参数 %q 无效", sendtoFailEnv, spec, os.Args)
	}
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		fail("不支持 %s", runtime.GOARCH)
	}
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		fail("prctl(PR_SET_NO_NEW_PRIVS)：%v", e)
	}
	filter := sendtoFailFilter(arch, lo, hi, syscall.Errno(errno))
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); e != 0 {
		fail("prctl(PR_SET_SECCOMP)：%v", e)
	}
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	fail("exec %s：%v", os.Args[1], err)
}

// startMapperSendtoFail 同 startMapper，但 tinymapper 里 fd 在 [lo, hi) 内的 sendto、sendmsg、sendmmsg 都返回 EAGAIN；hi 为 0 表示不设上限
func startMapperSendtoFail(t testing.TB, lo, hi int, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	return startMapperSendFail(t, lo, hi, syscall.EAGAIN, wait, args...)
}

// startMapperSendFail 同 startMapperSendtoFail，但返回的是 errno
func startMapperSendFail(t testing.TB, lo, hi int, errno syscall.Errno, wait []listenPoint, args ...string) *mapper {
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
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d %d %d", sendtoFailEnv, lo, hi, int(errno)))
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}
