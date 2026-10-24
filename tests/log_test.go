package tests

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// T6：log0 只在 stdout 是终端时逐行 fflush。stdout 是文件或管道时日志攒在 stdio 缓冲里（glibc 按文件的 st_blksize 分配，
// 容器里为 4096 B；musl 固定为 BUFSIZ 1024 B），缓冲写满时写出，其余由 clear_timer_cb（每 timer_interval 400 ms 一次，
// 事件循环开始时先触发一次）末尾的 fflush 写出；myexit 在 _exit 前也 fflush。
const (
	// 突发阶段的连接数：每个连接 3 行，约 285 B
	burstConns = 100
	// 一行日志从记下到出现在文件里的时限：至多等一个定时器周期（400 ms），其余留给全量并行运行时的调度延迟
	logFlushWithin = 2 * time.Second
)

// cycleConn 经 listen 建一个连接，回显一次后关闭写方向并等到 EOF：回显后端读到转发的 FIN 后也关闭写方向，两侧都 EOF，
// tinymapper 释放连接对（先关闭 fd 再记最后一行，同一次回调内记完）。info 级下这个连接记 connLogs 中的 3 行
func cycleConn(listen string) error {
	c, err := net.DialTimeout("tcp", listen, ioTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := echo(c, []byte("x")); err != nil {
		return err
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	return closedWithin(c, ioTimeout)
}

var connLogs = []string{"[tcp]new_connection", "closed bc of EOF", "[tcp]closed connection"}

// connLogCounts 返回日志中 connLogs 各自的行数
func connLogCounts(m *mapper) []int {
	got := make([]int, len(connLogs))
	for i, s := range connLogs {
		got[i] = m.logLines(s)
	}
	return got
}

// waitConnLogs 等待日志中 connLogs 各有 n 行：tinymapper 不退出，记下的日志也要在 logFlushWithin 内写进文件
func waitConnLogs(t testing.TB, m *mapper, n int) {
	t.Helper()
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		if got := connLogCounts(m); got[0] != n || got[1] != n || got[2] != n {
			return fmt.Errorf("日志中 new_connection、closed bc of EOF、closed connection 分别有 %v 行，期望各 %d 行：已记下的日志"+
				"没有及时写进文件（stdout 不是终端时应由 clear_timer_cb 每 400 ms 刷新一次，是终端时逐行刷新）", got, n)
		}
		return nil
	})
}

func logSize(t testing.TB, m *mapper) int {
	t.Helper()
	fi, err := os.Stat(m.logPath)
	if err != nil {
		t.Fatal(err)
	}
	return int(fi.Size())
}

// logBurst 先建一个连接并等它的日志可见（此前的启动日志也已写出，stdio 缓冲为空），再以 8 路并发突发建立 burstConns 个连接，
// 等全部日志可见。返回突发期间 tinymapper 的 write 类系统调用次数、日志文件增加的字节数，以及两次读数之间的时长。
// 内核在 write 把数据写完之后才累加 syscw，测试看到一行时它的那次 write 可能还没计入；tinymapper 只有主线程写日志，
// 任一时刻至多差 1 次：基线读数可能少计热身连接的最后一次 write（增量多 1），末尾读数可能少计突发的最后一次（增量少 1）
func logBurst(t testing.TB, m *mapper, listen string) (writes, bytes int, elapsed time.Duration) {
	t.Helper()
	if err := cycleConn(listen); err != nil {
		t.Fatal(err)
	}
	waitConnLogs(t, m, 1)
	w0, b0, start := m.syscw(t), logSize(t, m), time.Now()
	errs := make([]error, burstConns)
	parallelFor(burstConns, 8, func(i int) { errs[i] = cycleConn(listen) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("突发阶段第 %d 个连接：%v", i+1, err)
		}
	}
	waitConnLogs(t, m, 1+burstConns)
	return m.syscw(t) - w0, logSize(t, m) - b0, time.Since(start)
}

// T6：stdout 是文件时日志不逐行写出。
//   - 系统调用数：突发期间 syscw 的增量应不超过 ⌈B/1024⌉+⌊D/400ms⌋+3（B 为突发写出的字节数，D 为 logBurst 两次读数之间的
//     时长）。缓冲写满才写一次，每次至少写出 1024 B：glibc 写满 4096 B 的缓冲才写；musl 在缓冲放不下新的一行时把缓冲连同
//     这一行一起 writev，超过 1024 B。定时器每次触发至多再写一次（缓冲为空时不写），D 内至多 ⌊D/400ms⌋+1 次，libev 补一次
//     迟到的触发再加 1；基线读数少计的一次再加 1（见 logBurst）。逐行刷新时每行至少一次 write，增量 ≥ 3·burstConns−1（299），
//     约为上界的 10 倍
//   - 可见性：进程不退出，每批日志都要在 logFlushWithin 内全部写进文件。最后再建一个连接：此前的日志已全部可见即缓冲为空，
//     这 3 行（约 285 B）小于任一 libc 的缓冲，只能由定时器写出，去掉 clear_timer_cb 里的 fflush 后必然看不到
func TestLogBufferedFile(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)
	writes, bytes, elapsed := logBurst(t, m, listen)
	lines := 3 * burstConns
	bound := (bytes+1023)/1024 + int(elapsed/(400*time.Millisecond)) + 3
	t.Logf("突发 %d 个连接：%d 行 %d B，用时 %v，write 类系统调用 %d 次（上界 %d）", burstConns, lines, bytes,
		elapsed.Round(time.Millisecond), writes, bound)
	if 2*bound > lines {
		t.Fatalf("突发用时 %v 过长：上界 %d 超过行数 %d 的一半，区分不了逐行刷新", elapsed.Round(time.Millisecond), bound, lines)
	}
	if writes > bound {
		t.Errorf("stdout 是文件，突发期间 write 类系统调用 %d 次，超过上界 %d（%d 行）：log0 仍在逐行刷新", writes, bound, lines)
	}
	if err := cycleConn(listen); err != nil {
		t.Fatal(err)
	}
	waitConnLogs(t, m, 2+burstConns)
}

// startMapperTTY 同 startMapper，但 stdout、stderr 接到伪终端的从设备上：打开主设备 /dev/ptmx，解锁（TIOCSPTLCK）后按
// TIOCGPTN 返回的编号打开 /dev/pts/N。一个 goroutine 持续读出主设备并追加到 m.logPath，tinymapper 不会因伪终端缓冲写满
// 而阻塞；终端默认的 ONLCR 把行尾变成 \r\n，不影响按子串数行
func startMapperTTY(t testing.TB, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("打不开 /dev/ptmx（%v）：环境中没有伪终端", err)
	}
	t.Cleanup(func() { ptmx.Close() })
	rc, err := ptmx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var unlock int32
	var n uint32
	var errno syscall.Errno
	err = rc.Control(func(fd uintptr) {
		if _, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno == 0 {
			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
		}
	})
	if err == nil && errno != 0 {
		err = errno
	}
	if err != nil {
		t.Fatalf("解锁伪终端或读取编号失败：%v", err)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("打开伪终端从设备失败：%v", err)
	}
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		pts.Close()
		t.Fatal(err)
	}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			f.Write(buf[:n])
			if err != nil {
				return // 从设备全部关闭后读到 EIO
			}
		}
	}()
	// 清理按注册的逆序执行：先停止 tinymapper（runMapper 注册），再关闭本进程持有的从设备，主设备随即读到 EIO
	t.Cleanup(func() {
		select {
		case <-copied:
		case <-time.After(ioTimeout):
		}
		ptmx.Close()
		<-copied
		f.Close()
	})
	t.Cleanup(func() { pts.Close() })
	cmd := exec.Command(mapperBin, append([]string{"--disable-color"}, args...)...)
	cmd.Stdout, cmd.Stderr = pts, pts
	return runMapper(t, cmd, logPath, wait)
}

// T6：stdout 是终端时日志仍逐行写出（交互运行时即时可见）：突发期间 syscw 的增量应不小于日志行数减 1（末尾读数可能少计
// 最后一次 write，见 logBurst）。stdio 对终端本就是行缓冲（glibc 分配缓冲时、musl 第一次写出时检查是否终端），以 \n 结尾的行即使没有 log0 里的 fflush 也逐行
// 写出，所以本用例防的是终端输出整体退化为攒批（如对 stdout 全局 setvbuf 全缓冲），分辨不出 log0 的 isatty 判断本身
func TestLogTTYLineFlush(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := startMapperTTY(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")
	writes, bytes, elapsed := logBurst(t, m, listen)
	lines := 3 * burstConns
	t.Logf("突发 %d 个连接：%d 行 %d B（含 ONLCR 加的 \\r），用时 %v，write 类系统调用 %d 次", burstConns, lines, bytes,
		elapsed.Round(time.Millisecond), writes)
	if writes < lines-1 {
		t.Errorf("stdout 是终端，突发期间 write 类系统调用只有 %d 次，少于 %d 行减 1：日志没有逐行写出", writes, lines)
	}
}

// T7：客户端地址只在记日志时由 address_t::to_str 格式化（tcp_pair_t 存 address_t，UDP 每包的 trace 行不再预先格式化），
// IPv4 与端口手写。clientAddrRe 取出日志里打印客户端地址的位置：new_connection from {X}、connection {X}（EOF、half-closed、
// closed connection、上游建连失败、空闲清理）、new connection from {X}（TCP 立即建连失败、UDP 新会话）与 UDP 每包的
// udp_listen_fd from {X}；上游地址前是 remote {R}，不匹配
var clientAddrRe = regexp.MustCompile(`(?:connection(?: from)?|udp_listen_fd from) \{([^}]*)\}`)

// clientAddrs 按日志顺序返回含 marker 的行里打印的客户端地址，marker 为空时返回全部
func clientAddrs(log, marker string) []string {
	var addrs []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, marker) {
			for _, sm := range clientAddrRe.FindAllStringSubmatch(line, -1) {
				addrs = append(addrs, sm[1])
			}
		}
	}
	return addrs
}

// waitClientAddrs 等待日志中含 want 各 marker 的行依次打印 want[marker] 中的客户端地址（个数与顺序都一致），
// 且日志中任何一处客户端地址都出现在 want 里。地址与 Go 的 LocalAddr().String() 同为 a.b.c.d:port、[v6]:port
func waitClientAddrs(t testing.TB, m *mapper, want map[string][]string) {
	t.Helper()
	known := map[string]bool{}
	for _, addrs := range want {
		for _, a := range addrs {
			known[a] = true
		}
	}
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		if m.exited() {
			return fmt.Errorf("tinymapper 已退出：%v", m.exitErr)
		}
		data, _ := os.ReadFile(m.logPath)
		for _, marker := range slices.Sorted(maps.Keys(want)) {
			if got := clientAddrs(string(data), marker); !slices.Equal(got, want[marker]) {
				return fmt.Errorf("含 %q 的行打印的客户端地址依次为 %q，期望 %q", marker, got, want[marker])
			}
		}
		for _, a := range clientAddrs(string(data), "") {
			if !known[a] {
				return fmt.Errorf("日志中出现了不属于任何客户端的地址 {%s}", a)
			}
		}
		return nil
	})
}

// T7：TCP 连接各行日志里的客户端地址。debug 级下每个连接依次记 new_connection、half-closed（客户端先关闭写方向）、
// closed bc of EOF（后端读到转发的 FIN 后也关闭）、closed connection 各一行；先后两个连接各自的源端口不同。
// 双栈监听 [::] 上的 IPv4 客户端以 v4 映射地址出现，按 IPv6 格式化为 [::ffff:127.0.0.1]:port
func TestLogClientAddrTCP(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, listen, client string
		mapped               bool
	}{
		{"ipv4", "127.0.0.1", "127.0.0.1", false},
		{"ipv6", "::1", "::1", false},
		{"dualstack_v4client", "::", "127.0.0.1", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), echoHandler(""))
			lport := freePort(t)
			m := startMapper(t, listenPoints("t", lport), "-l", hostPort(c.listen, lport), "-r", be.addr, "-t", "--log-level", "5")
			var addrs []string
			for range 2 {
				conn := dial(t, hostPort(c.client, lport))
				addr := conn.LocalAddr().String()
				if c.mapped {
					addr = hostPort("::ffff:"+c.client, portOf(addr))
				}
				addrs = append(addrs, addr)
				mustEcho(t, conn, "x")
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				expectClosed(t, conn, ioTimeout)
			}
			waitClientAddrs(t, m, map[string][]string{"[tcp]new_connection": addrs, "half-closed by": addrs,
				"closed bc of EOF": addrs, "[tcp]closed connection": addrs})
			// T9：closed connection 的下一行（debug）打印释放后的 lru.size()，应与 tcp connections 相同：
			// LRU 自己维护的计数漏减时偏大，清理逻辑看不出来（清理条数按连接对链表的长度截断）
			eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
				data, _ := os.ReadFile(m.logPath)
				lines := strings.Split(string(data), "\n")
				for i, line := range lines {
					if _, n, ok := strings.Cut(line, "[tcp]closed connection"); ok {
						_, n, _ = strings.Cut(n, "tcp connections=")
						next := ""
						if i+1 < len(lines) {
							next = lines[i+1]
						}
						if !strings.HasSuffix(next, "[tcp] lru.size()="+n) {
							return fmt.Errorf("%q 的下一行是 %q，期望以 [tcp] lru.size()=%s 结尾", line, next, n)
						}
					}
				}
				return nil
			})
		})
	}
}

// T7：上游建连失败的 warn 行里的客户端地址。上游拒绝（异步失败）：new_connection、connect to remote {R} failed,connection {X}、
// closed connection 各一行；上游无路由（connect 立即失败，不建连接对）：只有 new connection from {X},but connect to remote {R} 一行
func TestLogClientAddrTCPConnectFailed(t *testing.T) {
	t.Parallel()
	const unreachable = "192.0.2.1:9"
	refused := loopback4(t)
	for _, c := range []struct {
		name, remote string
		markers      []string // 各恰有一行，打印该客户端的地址
	}{
		{"refused", refused, []string{"[tcp]new_connection", "connect to remote {" + refused + "} failed,connection", "[tcp]closed connection"}},
		{"unreachable", unreachable, []string{"but connect to remote {" + unreachable + "} failed"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if c.remote == unreachable {
				if _, err := net.DialTimeout("tcp", c.remote, 2*time.Second); !errors.Is(err, syscall.ENETUNREACH) {
					t.Skipf("当前网络中 %s 并非无路由（%v），在 --network none 容器中运行", c.remote, err)
				}
			}
			listen := loopback4(t)
			m := forward(t, "t", listen, c.remote)
			conn := dial(t, listen)
			expectClosed(t, conn, ioTimeout)
			want := map[string][]string{}
			for _, marker := range c.markers {
				want[marker] = []string{conn.LocalAddr().String()}
			}
			waitClientAddrs(t, m, want)
		})
	}
}

// T7：UDP 每个包都经过 udp_accept_cb，trace 级（--log-level 6）每包记一行 received data from udp_listen_fd from {X}。
// 两个客户端 socket 交替各发 3 个包，每个包收到回包后才发下一个，日志顺序即发送顺序：每行必须是该包发送方的地址，
// 而不是上一个包或已有会话的地址；new connection from 每个客户端一行
func TestLogClientAddrUDP(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			be := serveUDP(t, hostPort(host, freePort(t)), "")
			listen := hostPort(host, freePort(t))
			m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u", "--log-level", "6")
			clients := []*net.UDPConn{udpDial(t, "", listen), udpDial(t, "", listen)}
			var sent []string
			for i := range 6 {
				c := clients[i%2]
				if _, err := udpRoundTrip(c, []byte("x")); err != nil {
					t.Fatal(err)
				}
				sent = append(sent, c.LocalAddr().String())
			}
			waitClientAddrs(t, m, map[string][]string{"udp_listen_fd from": sent, "[udp]new connection from": sent[:2]})
		})
	}
}
