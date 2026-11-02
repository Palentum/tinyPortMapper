// M2 + M3 + M4 + M6（docs/tasks/p4.md 的 D61–D64、S1–S12）：多 worker 的功能测试。
//
// D62 起 tinymapper 总是一个主线程（默认 loop：信号、400 ms 定时器上的 DNS 调度与 fflush、DNS 结果与统计回传的 ev_async）加 N 个 worker
// 线程（各自 ev_loop_new(EVBACKEND_EPOLL) 的 loop，做全部转发），N 由 --threads N|auto 给（S1）。每条规则在每个 worker 上各有一个
// SO_REUSEPORT 的 TCP/UDP 监听（S2），内核按四元组散列把连接与数据报分给各 worker；主线程只经消息访问 worker 的状态（S3–S6）。
// 这里的用例都显式给 --threads，不受 TPM_THREADS 影响（mapperArgv 见到 --threads 就不再加）
package tests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// threadsFatal 是 --threads 的值不是 1–64 也不是 auto 时的 fatal 行
const threadsFatal = "threads value must be between 1 and 64, or auto"

// taskIDs 返回进程 pid 的全部线程号（/proc/<pid>/task，升序；主线程的线程号等于 pid）
func taskIDs(t testing.TB, pid int) []int {
	t.Helper()
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatal(err)
	}
	var tids []int
	for _, e := range ents {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			t.Fatalf("/proc/%d/task 里有 %q", pid, e.Name())
		}
		tids = append(tids, tid)
	}
	slices.Sort(tids)
	return tids
}

// waitTasks 等到 tinymapper 恰有 n 个线程，返回线程号。worker 线程在全部监听就绪之后才建（S2），DNS 线程更晚，所以要等
func waitTasks(t testing.TB, m *mapper, n int) []int {
	t.Helper()
	var tids []int
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		m.fatalIfExited(t, "等线程时")
		if tids = taskIDs(t, m.pid()); len(tids) != n {
			return fmt.Errorf("tinymapper 有 %d 个线程，期望 %d", len(tids), n)
		}
		return nil
	})
	return tids
}

// sigBlk 返回线程 tid 的信号屏蔽字（/proc/<pid>/task/<tid>/status 的 SigBlk，第 k−1 位是信号 k）
func sigBlk(t testing.TB, pid, tid int) uint64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", pid, tid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "SigBlk:"); ok {
			b, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("线程 %d 的 SigBlk 无法解析：%q", tid, line)
			}
			return b
		}
	}
	t.Fatalf("/proc/%d/task/%d/status 里没有 SigBlk", pid, tid)
	return 0
}

func sigBit(s syscall.Signal) uint64 { return 1 << (uint(s) - 1) }

// fdLinks 返回进程 pid 的 fd 中链接为 want 的个数
func fdLinks(t testing.TB, pid int, want string) int {
	t.Helper()
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if link, _ := os.Readlink(dir + "/" + e.Name()); link == want {
			n++
		}
	}
	return n
}

// portListeners 返回端口 port 上 proto 的监听 socket 个数（不分进程：别的实例的 socket 加入 reuseport 组时也数得到）
func portListeners(proto string, port int) int {
	ipproto, states := syscall.IPPROTO_TCP, uint32(1)<<10 // TCP_LISTEN
	if proto == "udp" {
		ipproto, states = syscall.IPPROTO_UDP, uint32(1)<<7 // TCP_CLOSE
	}
	n := 0
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		sockDiagDump(family, ipproto, states, func(p, _ uint16, _ uint32) {
			if int(p) == port {
				n++
			}
		})
	}
	return n
}

// expectListeners 要求 tinymapper 在 port 上恰有 n 个 proto 监听 socket
func expectListeners(t testing.TB, m *mapper, proto string, port, n int) {
	t.Helper()
	if fds := listenFDs(m.pid(), proto, port); len(fds) != n {
		t.Errorf("端口 %d 上有 %d 个 %s 监听 socket（fd %v），期望 %d", port, len(fds), proto, fds, n)
	}
}

// busyWorkers 返回 tcp（proto 为 "tcp"）或 udp 已建数大于 0 的 worker 个数
func busyWorkers(d statsDump, proto string) int {
	n := 0
	for _, w := range d.workers {
		if proto == "tcp" && w.tcpTotal > 0 || proto == "udp" && w.udpTotal > 0 {
			n++
		}
	}
	return n
}

// logLineRe 匹配一行日志开头的前缀（--disable-color）：每行恰有一个，多个线程同时写时一行被别的线程的行截断、拼接都会破坏它
var logLineRe = regexp.MustCompile(`\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]\[(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\]`)

// expectWholeLogLines 要求日志的每一行以前缀开头、只有一个前缀（S9：worker 线程与主线程都写日志，一行一次 fwrite）
func expectWholeLogLines(t testing.TB, m *mapper) {
	t.Helper()
	data, err := os.ReadFile(m.logPath)
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if loc := logLineRe.FindAllStringIndex(line, -1); len(loc) != 1 || loc[0][0] != 0 {
			if bad++; bad <= 5 {
				t.Errorf("日志行不完整或被拼接：%q", line)
			}
		}
	}
	if bad > 5 {
		t.Errorf("……共 %d 行", bad)
	}
}

// S1：--threads N|auto，N 为 1–64，auto 取 sched_getaffinity 的 CPU 数、上限 8；只在命令行（TOML 的 [network] threads 是未知键）。
// 合法值：启动时恰有一行 info "worker threads: N"，进程有 N+1 个线程（主线程 + N 个 worker），每条规则每个协议 N 个监听，TCP、UDP 都能转发；
// 非法值（0、65、负数、非数字、空串）与缺值以 fatal 退出。默认（不给 --threads）为 1，TPM_THREADS 设了时那一项跳过
func TestWorkerThreadsOption(t *testing.T) {
	t.Parallel()
	t.Run("help", func(t *testing.T) {
		t.Parallel()
		out, err := exec.Command(mapperBin, "-h").Output()
		if err != nil {
			t.Fatalf("-h 退出状态异常：%v", err)
		}
		if !strings.Contains(string(out), "--threads") {
			t.Errorf("帮助文本里没有 --threads：\n%s", out)
		}
	})
	infoRe := regexp.MustCompile(`\[INFO\]worker threads: (\d+)$`)
	accept := func(t *testing.T, n int, args ...string) {
		t.Helper()
		affinityTooMany(t, n)
		remote := loopback4(t)
		serveTCP(t, remote, echoHandler(""))
		serveUDP(t, remote, "")
		listen := loopback4(t)
		m := startMapper(t, listenPoints("tu", portOf(listen)), append([]string{"-l", listen, "-r", remote, "-t", "-u"}, args...)...)
		if m.threads() != n {
			t.Fatalf("harness 算出的 worker 数 %d，期望 %d", m.threads(), n)
		}
		waitTasks(t, m, n+1)
		eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
			data, _ := os.ReadFile(m.logPath)
			var got []string
			for _, line := range strings.Split(string(data), "\n") {
				if s := infoRe.FindStringSubmatch(line); s != nil {
					got = append(got, s[1])
				}
			}
			if len(got) != 1 || got[0] != strconv.Itoa(n) {
				return fmt.Errorf("worker 数的 info 行：%q，期望恰好一行 %d", got, n)
			}
			return nil
		})
		expectListeners(t, m, "tcp", portOf(listen), n)
		expectListeners(t, m, "udp", portOf(listen), n)
		mustEcho(t, dial(t, listen), "tcp")
		if got := udpReplyFrom(t, udpDial(t, "", listen), "udp"); got != "" {
			t.Errorf("UDP 回包前缀 %q", got)
		}
	}
	for _, c := range []struct {
		value string
		n     int
	}{{"1", 1}, {"2", 2}, {"64", 64}, {"auto", autoThreads()}} {
		t.Run(c.value, func(t *testing.T) {
			t.Parallel()
			accept(t, c.n, "--threads", c.value)
		})
	}
	t.Run("default", func(t *testing.T) {
		t.Parallel()
		if os.Getenv("TPM_THREADS") != "" {
			t.Skip("TPM_THREADS 设了，所有启动都带 --threads")
		}
		accept(t, 1)
	})
	for _, c := range []struct{ name, value string }{
		{"0", "0"}, {"65", "65"}, {"negative", "-1"}, {"junk", "abc"}, {"empty", ""},
	} {
		t.Run("reject-"+c.name, func(t *testing.T) {
			t.Parallel()
			out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "--threads", c.value)
			if !strings.Contains(out, threadsFatal) {
				t.Errorf("--threads %q 的输出里没有 %q：\n%s", c.value, threadsFatal, out)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		if out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "--threads"); !strings.Contains(out, "requires an argument") {
			t.Errorf("--threads 没给值的报错不符：\n%s", out)
		}
	})
	t.Run("toml-key", func(t *testing.T) {
		t.Parallel()
		cfg := writeConfig(t, fmt.Sprintf("[network]\nthreads = 2\n\n[[endpoints]]\nlisten = %q\nremote = %q\n", loopback4(t), loopback4(t)))
		if out := runExpectFail(t, 5*time.Second, "-c", cfg, "--threads", "2"); !strings.Contains(out, "unknown key in [network]") {
			t.Errorf("[network] threads 的报错不符：\n%s", out)
		}
	})
}

// D62、S2：N 个 worker 时进程恰有 N+1 个线程、N+1 个 epoll 实例（默认 loop 加每个 worker 一个 ev_loop_new(EVBACKEND_EPOLL)），转发之后
// 不多出线程；worker 线程屏蔽信号（发给进程的 SIGTERM/SIGUSR1 只能由主线程处理，worker 写向已 RST 的对端时的 SIGPIPE 留在该线程上
// 不递送）：标准信号 1–31 里除 SIGKILL、SIGSTOP（不能屏蔽）与 abort() 和同步故障用的 SIGABRT、SIGSEGV、SIGBUS、SIGFPE、SIGILL、SIGTRAP
// （审查 L-3：musl 1.1.20 以前 abort() 不解除屏蔽）之外全部屏蔽，这 6 个不屏蔽；主线程什么都不屏蔽（测试进程启动它时屏蔽字为空）。
// SIGUSR1 连发几次，每次都有一组统计、进程不退出。有域名 remote 时另有 DNS 线程，共 N+2 个，DNS 线程与 worker 线程的屏蔽字相同
// （审查 L-2：在屏蔽信号的窗口里创建）
func TestWorkerThreads(t *testing.T) {
	t.Parallel()
	var all, faults uint64
	for _, s := range []syscall.Signal{syscall.SIGABRT, syscall.SIGSEGV, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGILL, syscall.SIGTRAP} {
		faults |= sigBit(s)
	}
	for s := syscall.Signal(1); s <= 31; s++ {
		if s != syscall.SIGKILL && s != syscall.SIGSTOP && faults&sigBit(s) == 0 {
			all |= sigBit(s)
		}
	}
	// expectWorkerMask 核对主线程以外的线程 tid 的屏蔽字
	expectWorkerMask := func(t *testing.T, pid, tid int) {
		t.Helper()
		blk := sigBlk(t, pid, tid)
		if blk&all != all {
			t.Errorf("线程 %d 的 SigBlk=%#x，没有屏蔽 %#x：worker 线程应屏蔽全部信号（同步故障信号除外）", tid, blk, all&^blk)
		}
		if blk&faults != 0 {
			t.Errorf("线程 %d 的 SigBlk=%#x 屏蔽了同步故障信号 %#x（审查 L-3）", tid, blk, blk&faults)
		}
	}
	for _, n := range []int{1, 2, 4} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			remote := loopback4(t)
			serveTCP(t, remote, echoHandler(""))
			serveUDP(t, remote, "")
			listen := loopback4(t)
			m := startMapper(t, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--threads", strconv.Itoa(n))
			waitTasks(t, m, n+1)
			for i := range 8 {
				mustEcho(t, dial(t, listen), fmt.Sprintf("tcp-%d", i))
				udpReplyFrom(t, udpDial(t, "", listen), fmt.Sprintf("udp-%d", i))
			}
			for range 3 {
				m.statsAfterSignal(t)
			}
			tids := taskIDs(t, m.pid())
			if len(tids) != n+1 {
				t.Errorf("转发之后有 %d 个线程，期望仍为 %d", len(tids), n+1)
			}
			if got := fdLinks(t, m.pid(), "anon_inode:[eventpoll]"); got != n+1 {
				t.Errorf("有 %d 个 epoll 实例，期望 %d（主线程的默认 loop 加每个 worker 一个）", got, n+1)
			}
			for _, tid := range tids {
				blk := sigBlk(t, m.pid(), tid)
				if tid == m.pid() {
					if blk != 0 {
						t.Errorf("主线程（%d）的 SigBlk=%#x，期望什么都不屏蔽：信号由主线程的默认 loop 处理（创建线程之后恢复原屏蔽字）", tid, blk)
					}
					continue
				}
				expectWorkerMask(t, m.pid(), tid)
			}
		})
	}
	t.Run("domain", func(t *testing.T) {
		t.Parallel()
		const n = 2
		bport := freePort(t)
		serveTCP(t, hostPort("127.0.0.1", bport), echoHandler(""))
		serveTCP(t, hostPort("::1", bport), echoHandler(""))
		listen := loopback4(t)
		m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", fmt.Sprintf("localhost:%d", bport), "-t", "--threads", strconv.Itoa(n))
		tids := waitTasks(t, m, n+2)
		mustEcho(t, dial(t, listen), "x")
		for _, tid := range tids {
			if tid != m.pid() {
				expectWorkerMask(t, m.pid(), tid)
			} else if blk := sigBlk(t, m.pid(), tid); blk != 0 {
				t.Errorf("主线程的 SigBlk=%#x，期望什么都不屏蔽", blk)
			}
		}
		for range 3 {
			m.statsAfterSignal(t)
		}
		mustEcho(t, dial(t, listen), "y")
	})
}

// S2：每条规则在每个 worker 各有一个监听（TCP、UDP 分别），N=2、4。三条规则：IPv4 的 TCP+UDP、IPv6 仅 UDP、双栈 [::] 仅 TCP。
// 进程的 socket 恰为这些监听（TCP 启动探测用的 socket 已关闭），每条规则都能转发（双栈规则另经 IPv4 连一次）
func TestWorkerListeners(t *testing.T) {
	t.Parallel()
	for _, n := range []int{2, 4} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			remote := loopback4(t)
			serveTCP(t, remote, echoHandler(""))
			serveUDP(t, remote, "")
			p1, p2, p3 := loopback4(t), hostPort("::1", freePort(t)), freePort(t)
			cfg := writeConfig(t, fmt.Sprintf(`[[endpoints]]   # 规则 1：TCP + UDP
listen = %q
remote = %q
use_udp = true

[[endpoints]]   # 规则 2：IPv6 仅 UDP
listen = %q
remote = %q
no_tcp = true
use_udp = true

[[endpoints]]   # 规则 3：双栈仅 TCP
listen = "[::]:%d"
remote = %q
`, p1, remote, p2, remote, p3, remote))
			wait := slices.Concat(listenPoints("tu", portOf(p1)), listenPoints("u", portOf(p2)), listenPoints("t", p3))
			m := startMapper(t, wait, "-c", cfg, "--threads", strconv.Itoa(n))
			expectListeners(t, m, "tcp", portOf(p1), n)
			expectListeners(t, m, "udp", portOf(p1), n)
			expectListeners(t, m, "tcp", portOf(p2), 0)
			expectListeners(t, m, "udp", portOf(p2), n)
			expectListeners(t, m, "tcp", p3, n)
			expectListeners(t, m, "udp", p3, 0)
			if got := len(socketInodes(m.pid())); got != 4*n {
				t.Errorf("tinymapper 有 %d 个 socket，期望恰为 %d 个监听（启动探测的 socket 应已关闭）", got, 4*n)
			}
			mustEcho(t, dial(t, p1), "rule1")
			udpReplyFrom(t, udpDial(t, "", p1), "rule1")
			udpReplyFrom(t, udpDial(t, "", p2), "rule2")
			mustEcho(t, dial(t, hostPort("::1", p3)), "rule3-v6")
			mustEcho(t, dial(t, hostPort("127.0.0.1", p3)), "rule3-v4")
		})
	}
}

// S2：N=2、4 时 TCP 的完整性。64 条连接同时双向传输（各 0–2 MiB、写块 1 B–64 KiB，按种子随机，SHA-256 校验），再并发 1000 条短连接各回显
// 一次；统计精确（total、两个方向的字节含 28 B 头与 64 B 校验尾），worker 行之和等于规则行（statsAfterSignal），每个 worker 都分到了连接
// （64 条连接散列到 4 个 worker 时某个 worker 一条都没有的概率约 4×(3/4)^64 ≈ 4e-8）。info 级日志里每条连接一行 new_connection，
// 所有行都完整（S9：多个线程写日志，一行一次 fwrite）
func TestWorkerTCPIntegrity(t *testing.T) {
	t.Parallel()
	for _, n := range []int{2, 4} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			affinityOverlap(t, n) // 每个 worker 都分到了连接
			const conns, short = 64, 1000
			be := serveTCP(t, loopback4(t), streamHandler)
			listen := loopback4(t)
			m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--threads", strconv.Itoa(n))
			rng := rand.New(rand.NewPCG(uint64(n), 61))
			up, down, chunk := make([]int64, conns), make([]int64, conns), make([]int, conns)
			var wantUp, wantDown uint64
			for i := range conns {
				up[i], down[i], chunk[i] = rng.Int64N(2<<20), rng.Int64N(2<<20), 1+rng.IntN(64<<10)
				wantUp += uint64(up[i] + streamHeaderLen)
				wantDown += uint64(down[i] + 64)
			}
			errs := make([]error, conns)
			parallelFor(conns, conns, func(i int) { errs[i] = transfer(listen, up[i], down[i], chunk[i], uint64(i)) })
			for i, err := range errs {
				if err != nil {
					t.Fatalf("第 %d 条连接（上行 %d、下行 %d、写块 %d）：%v", i, up[i], down[i], chunk[i], err)
				}
			}
			d := m.waitTCPConns(t, 1, 0)
			if s := d.tcp[1]; s.total != conns || s.upBytes != wantUp || s.downBytes != wantDown {
				t.Errorf("total=%d up_bytes=%d down_bytes=%d，期望 %d/%d/%d", s.total, s.upBytes, s.downBytes, conns, wantUp, wantDown)
			}
			if k := busyWorkers(d, "tcp"); k != n {
				t.Errorf("只有 %d 个 worker 分到了连接（worker 行 %+v），期望 %d 个", k, d.workers, n)
			}
			echoBE := serveTCP(t, loopback4(t), echoHandler(""))
			listen2 := loopback4(t)
			m2 := startMapper(t, listenPoints("t", portOf(listen2)), "-l", listen2, "-r", echoBE.addr, "-t", "--threads", strconv.Itoa(n))
			serrs := make([]error, short)
			parallelFor(short, 100, func(i int) {
				c, err := net.DialTimeout("tcp", listen2, ioTimeout)
				if err != nil {
					serrs[i] = err
					return
				}
				defer c.Close()
				serrs[i] = echo(c, fmt.Appendf(nil, "short-%d", i))
			})
			for i, err := range serrs {
				if err != nil {
					t.Fatalf("第 %d 条短连接：%v", i, err)
				}
			}
			d2 := m2.waitTCPConns(t, 1, 0)
			if s := d2.tcp[1]; s.total != short {
				t.Errorf("短连接 total=%d，期望 %d", s.total, short)
			}
			if k := busyWorkers(d2, "tcp"); k != n {
				t.Errorf("短连接只有 %d 个 worker 分到（worker 行 %+v），期望 %d 个", k, d2.workers, n)
			}
			if got := m2.logLines("[tcp]new_connection"); got != short {
				t.Errorf("日志里有 %d 行 new_connection，期望 %d", got, short)
			}
			expectWholeLogLines(t, m)
			expectWholeLogLines(t, m2)
		})
	}
}

// S2：N=2、4 时 UDP 的完整性与会话亲和。64 个客户端同时各发 8 轮、每轮连发 4 个带编号的包（1–1400 B，每个客户端最后一个 9000 B，
// 跨过 2 KiB 槽），每轮收齐 4 个回包、逐字节与发出的相同且保序。后端按源地址分组：每个客户端恰好一个源地址（一个会话：同一客户端的包
// 总由同一个 worker 收到），该源上的包与客户端发出的逐字节相同、顺序相同；统计 sessions==total==64，两个方向包数、字节数精确，没有丢包；
// 每个 worker 都建了会话。后端的一个 socket 收全部 64 个会话的包：SetReadBuffer 受 rmem_max 截断（约 416 KiB），多个 worker 同时转发时
// 一轮突发（实测）就溢出、丢在后端的接收队列里（tinymapper 的 up_pkts 比后端收到的多，sk_drops 非零），所以用 SO_RCVBUFFORCE 设 16 MiB
func TestWorkerUDPIntegrity(t *testing.T) {
	t.Parallel()
	needNetAdmin(t)
	for _, n := range []int{2, 4} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			const clients, rounds, burst = 64, 8, 4
			be := recordUDP(t, loopback4(t))
			rc, err := be.conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var serr error
			rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 16<<20)
			})
			if serr != nil {
				t.Fatalf("后端 SO_RCVBUFFORCE：%v", serr)
			}
			listen := loopback4(t)
			m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u", "--threads", strconv.Itoa(n))
			msg := func(i, k int) []byte {
				size := 1 + (i*131+k*977)%1400
				if k == rounds*burst-1 {
					size = 9000
				}
				b := fmt.Appendf(nil, "c%03d-%04d-", i, k)
				for len(b) < size {
					b = append(b, byte('a'+(i+k+len(b))%26))
				}
				return b[:size]
			}
			want := make([][][]byte, clients)
			var wantBytes uint64
			for i := range clients {
				for k := range rounds * burst {
					want[i] = append(want[i], msg(i, k))
					wantBytes += uint64(len(want[i][k]))
				}
			}
			cs := make([]*net.UDPConn, clients)
			for i := range cs {
				cs[i] = udpDial(t, "", listen)
			}
			errs := make([]error, clients)
			parallelFor(clients, clients, func(i int) {
				buf := make([]byte, 70000)
				for r := range rounds {
					for b := range burst {
						if _, err := cs[i].Write(want[i][r*burst+b]); err != nil {
							errs[i] = err
							return
						}
					}
					for b := range burst {
						cs[i].SetReadDeadline(time.Now().Add(ioTimeout))
						nr, err := cs[i].Read(buf)
						if err != nil {
							errs[i] = fmt.Errorf("第 %d 轮第 %d 个回包：%w", r, b, err)
							return
						}
						if w := want[i][r*burst+b]; !bytes.Equal(buf[:nr], w) {
							errs[i] = fmt.Errorf("第 %d 轮第 %d 个回包 %d B %q，期望 %d B %q", r, b, nr, buf[:min(nr, 12)], len(w), w[:min(len(w), 12)])
							return
						}
					}
				}
			})
			if i := slices.IndexFunc(errs, func(err error) bool { return err != nil }); i >= 0 {
				d := m.statsAfterSignal(t)
				q, _ := sockDiag(syscall.IPPROTO_UDP, be.addr, "0.0.0.0:0")
				t.Fatalf("客户端 %d：%v（后端收到 %d 个包、socket 丢 %d 个；统计 %+v，worker 行 %+v）", i, errs[i], be.count(), q.drops, d.udp[1], d.workers)
			}
			got, pkts, nbytes := be.bySource(t, clients*rounds*burst)
			expectBySource(t, got, want)
			if pkts != clients*rounds*burst || nbytes != wantBytes {
				t.Errorf("后端收到 %d 个包、%d 字节，期望 %d、%d", pkts, nbytes, clients*rounds*burst, wantBytes)
			}
			d := m.statsAfterSignal(t)
			s := d.udp[1]
			if s.sessions != clients || s.total != clients || s.upPkts != pkts || s.downPkts != pkts || s.upBytes != wantBytes ||
				s.downBytes != wantBytes || s.upDrop != 0 || s.downDrop != 0 {
				t.Errorf("udp 统计 %+v，期望 sessions=total=%d、两个方向各 %d 包 %d 字节、没有丢包", s, clients, pkts, wantBytes)
			}
			if k := busyWorkers(d, "udp"); k != n {
				t.Errorf("只有 %d 个 worker 建了会话（worker 行 %+v），期望 %d 个", k, d.workers, n)
			}
		})
	}
}

// S7（M4）：max_conn_num（每条规则 20000）按所有 worker 合计。N=2，规则为 roundrobin 9:1 的两个 remote：可用的回显后端与没有监听的
// 地址（上游拒绝：连接对随即释放，有的在 connect 当场失败、有的建好连接对后由 tcp_cb 释放，两条路径都要把名额还回去）。
//  1. 并发建连到 19800 条可用连接（同时在途的不超过 128 条，合计到不了上限）、再逐条建到恰好 20000 条：每次被拒（上游拒绝）后等统计里
//     的连接数回到可用连接数，名额已还；全程没有一行 max_conn_num 的拒绝——上游拒绝的连接对若不还名额，约 2200 次拒绝会让计数提前到
//     20000，可用连接建不满；
//  2. 再连 3 条：都被立即关闭、各一行 max_conn_num 的 warn，后端没有多出连接；两个 worker 都持有连接（上限确实跨 worker）；
//  3. 关掉 32 条可用连接，统计回到 19968 之后再逐条建，恰好 32 条成功之后的下一条被拒：关闭之后计数恰好减回 32（少减建不满，多减会多建）
func TestWorkerTCPMaxConn(t *testing.T) {
	t.Parallel()
	heavy(t)
	const maxConn, reopen = 20000, 32
	const rejectLine = "[tcp]new connection from {"
	const rejectWhy = "but ignored,bc of max_conn_num reached"
	be := serveTCP(t, loopback4(t), echoHandler(""))
	refused := loopback4(t) // 没有监听
	listen := loopback4(t)
	m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-r", refused, "--balance", "roundrobin: 9, 1",
		"-t", "--threads", "2")
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		closeAll(conns)
	})
	// try 建一条连接并回显 1 字节：成功返回连接；tinymapper 关掉了它（上游拒绝或超限）返回 nil；超时等其他错误返回 error
	try := func() (net.Conn, error) {
		c, err := net.DialTimeout("tcp", listen, 10*time.Second)
		if err != nil {
			return nil, err
		}
		c.SetDeadline(time.Now().Add(ioTimeout))
		b := []byte{'x'}
		if _, err = c.Write(b); err == nil {
			_, err = io.ReadFull(c, b)
		}
		if err == nil {
			c.SetDeadline(time.Time{})
			return c, nil
		}
		c.Close()
		if isTimeout(err) {
			return nil, fmt.Errorf("回显超时：%w", err)
		}
		return nil, nil
	}
	rejects := func() int { return m.logLines(rejectLine, rejectWhy) }
	var refusedN atomic.Int64
	var fatal atomic.Pointer[error]
	parallelFor(128, 128, func(int) {
		for {
			mu.Lock()
			have := len(conns)
			mu.Unlock()
			if have >= maxConn-200 || fatal.Load() != nil {
				return
			}
			c, err := try()
			switch {
			case err != nil:
				fatal.Store(&err)
				return
			case c == nil:
				refusedN.Add(1)
			default:
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}
		}
	})
	if e := fatal.Load(); e != nil {
		t.Fatalf("并发建连：%v", *e)
	}
	mu.Lock()
	have := len(conns)
	mu.Unlock()
	d0 := m.statsAfterSignal(t)
	t.Logf("并发阶段：%d 条可用连接、上游拒绝 %d 次；统计 %+v，worker 行 %+v", have, refusedN.Load(), d0.tcp[1], d0.workers)
	// fill 逐条建连直到有 target 条可用连接；每次被关闭后等统计回到可用连接数（被拒的连接对已释放、名额已还），max_conn_num 的拒绝
	// 须仍为 rejected 行
	fill := func(target, rejected int) {
		t.Helper()
		for {
			mu.Lock()
			have := len(conns)
			mu.Unlock()
			if have >= target {
				return
			}
			c, err := try()
			if err != nil {
				t.Fatal(err)
			}
			if c != nil {
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
				continue
			}
			refusedN.Add(1)
			m.waitTCPConns(t, 1, have)
			if k := rejects(); k != rejected {
				t.Fatalf("只有 %d 条可用连接（另有 %d 次上游拒绝）时有 %d 行 max_conn_num 拒绝，期望 %d：释放的连接对没有把名额还回去",
					have, refusedN.Load(), k, rejected)
			}
		}
	}
	fill(maxConn, 0)
	d := m.waitTCPConns(t, 1, maxConn)
	t.Logf("%d 条可用连接，上游拒绝 %d 次；worker 行 %+v", maxConn, refusedN.Load(), d.workers)
	if k := rejects(); k != 0 {
		t.Fatalf("建满之前有 %d 行 max_conn_num 拒绝", k)
	}
	if got := be.accepted.Load(); got != maxConn {
		t.Errorf("后端收到 %d 个连接，期望 %d", got, maxConn)
	}
	for _, w := range d.workers {
		if w.tcpConns == 0 {
			t.Errorf("有 worker 一条连接都没有（worker 行 %+v）：上限没有跨 worker 测到", d.workers)
		}
	}
	for i := range 3 {
		c, err := try()
		if err != nil {
			t.Fatal(err)
		}
		if c != nil {
			c.Close()
			t.Fatalf("达到上限后第 %d 条新连接仍被转发", i+1)
		}
	}
	eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
		if k := rejects(); k != 3 {
			return fmt.Errorf("日志里有 %d 行 max_conn_num 拒绝，期望 3", k)
		}
		return nil
	})
	if got := be.accepted.Load(); got != maxConn {
		t.Errorf("超限后后端收到 %d 个连接，期望仍为 %d", got, maxConn)
	}
	mu.Lock()
	rand.Shuffle(len(conns), func(i, j int) { conns[i], conns[j] = conns[j], conns[i] })
	closeAll(conns[:reopen])
	conns = conns[reopen:]
	mu.Unlock()
	m.waitTCPConns(t, 1, maxConn-reopen)
	fill(maxConn, 3)
	if c, err := try(); err != nil || c != nil {
		if c != nil {
			c.Close()
		}
		t.Fatalf("关掉 %d 条、再建满 %d 条之后，下一条新连接没有被拒（err=%v）：关闭之后名额多还了", reopen, reopen, err)
	}
	eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
		if k := rejects(); k != 4 {
			return fmt.Errorf("日志里有 %d 行 max_conn_num 拒绝，期望 4", k)
		}
		return nil
	})
	if got := be.accepted.Load(); got != maxConn+reopen {
		t.Errorf("后端收到 %d 个连接，期望 %d", got, maxConn+reopen)
	}
}

// S7（M4）+ S5（M3）：UDP 的 max_conn_num 按所有 worker 合计，释放会话时名额还回去。N=2，remote 为 /etc/hosts 里的域名
// （TPM_IN_CONTAINER）。客户端绑固定的源地址与端口（127.0.2.1、127.0.2.2 各 10000 个，端口 1024 起，原因见 TestUDPMaxConn），
// 顺序建满 20000 个会话，第 20001 个客户端被忽略（一行 max_conv_num 的日志、没有回包），两个 worker 都有会话；旧后端不再回包，
// 20000 个客户端各发一包，再改 /etc/hosts 让地址变化，每个 worker 各关掉自己的会话（remote_sweep：两行 changed from，或刷新早于 10 s 时
// 30 s 后的 old address check 行，closed udp= 之和 20000），会话数归零；20000 个客户端再各发一包：都由新地址的后端回应
// （会话重建，名额全部还回来了才建得满），第 20001 个仍被忽略
func TestWorkerUDPMaxConn(t *testing.T) {
	t.Parallel()
	inContainer(t)
	heavy(t)
	const maxConn = 20000
	const perIP, clientPortBase = 10000, 1024
	const name = "tpm-worker-udpmax.test"
	const ignored = "but ignored,bc of max_conv_num reached"
	clientAddr := func(i int) *net.UDPAddr {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 2, byte(1+i/perIP)), Port: clientPortBase + i%perIP}
	}
	bport := freePort(t)
	be2 := serveUDP(t, hostPort("127.0.0.2", bport), "2")
	serveUDP(t, hostPort("127.0.0.3", bport), "3")
	setLast := hostsEntry(t, "127.0.0.2", name)
	listen := loopback4(t)
	m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", fmt.Sprintf("%s:%d", name, bport), "-u", "--threads", "2")
	ra, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UDPConn, maxConn+1)
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
	})
	for i := range conns {
		if conns[i], err = net.DialUDP("udp", clientAddr(i), ra); err != nil {
			t.Fatalf("第 %d 个客户端建 socket 失败：%v", i, err)
		}
	}
	// fillAll 让前 maxConn 个客户端各往返一次，回包前缀须为 id
	fillAll := func(id string) {
		t.Helper()
		start := time.Now()
		for i := range maxConn {
			msg := fmt.Appendf(nil, "fill-%05d", i)
			got, err := udpTry(conns[i], msg, 2*time.Second, 4)
			if err != nil {
				t.Fatalf("第 %d 个会话失败：%v", i, err)
			}
			if !bytes.Equal(got, append([]byte(id), msg...)) {
				t.Fatalf("第 %d 个会话回包 %q，期望来自后端 %s", i, got, id)
			}
		}
		t.Logf("顺序建立 %d 个 UDP 会话用时 %v", maxConn, time.Since(start).Round(time.Millisecond))
	}
	// expectIgnored 让第 20001 个客户端发一包：没有回包，日志里 max_conv_num 的忽略行共 n 行
	expectIgnored := func(n int) {
		t.Helper()
		extra := conns[maxConn]
		if _, err := extra.Write([]byte("overflow")); err != nil {
			t.Fatal(err)
		}
		eventually(t, logFlushWithin+ioTimeout, 50*time.Millisecond, func() error {
			m.fatalIfExited(t, "填满 max_conn_num 后")
			if k := m.logLines(ignored); k != n {
				return fmt.Errorf("日志里有 %d 行 max_conv_num 的忽略，期望 %d", k, n)
			}
			return nil
		})
		extra.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if nr, err := extra.Read(make([]byte, 64)); err == nil {
			t.Errorf("超限的新客户端收到 %d 字节回包：不应为它建会话", nr)
		}
	}
	fillAll("2")
	expectIgnored(1)
	d := m.statsAfterSignal(t)
	if s := d.udp[1]; s.sessions != maxConn {
		t.Fatalf("sessions=%d，期望 %d", s.sessions, maxConn)
	}
	for _, w := range d.workers {
		if w.udpSessions == 0 {
			t.Errorf("有 worker 一个会话都没有（worker 行 %+v）：上限没有跨 worker 测到", d.workers)
		}
	}
	// 旧后端不再回包，每个会话各发一包（unans）：up_pkts 恰好多 maxConn 个才算每个会话都发出去了，环回丢包时整轮重发
	be2.mute.Store(true)
	for up := d.udp[1].upPkts; ; {
		for i := range maxConn {
			if _, err := conns[i].Write([]byte("silent")); err != nil {
				t.Fatal(err)
			}
		}
		var got uint64
		eventually(t, ioTimeout, 50*time.Millisecond, func() error {
			if got = m.statsAfterSignal(t).udp[1].upPkts; got < up+maxConn {
				return fmt.Errorf("up_pkts 只多了 %d 个，期望 %d", got-up, maxConn)
			}
			return nil
		})
		if got == up+maxConn {
			break
		}
		t.Logf("up_pkts 多了 %d 个（期望 %d），重发一轮", got-up, maxConn)
		up = got
	}
	setLast('3')
	changed := regexp.MustCompile(`changed from 127\.0\.0\.2:\d+ to 127\.0\.0\.3:\d+, closed unresponsive tcp=(\d+) udp=(\d+), kept`)
	closed := regexp.MustCompile(`(?:changed from 127\.0\.0\.2:\d+ to 127\.0\.0\.3:\d+,|old address check:) closed unresponsive tcp=(\d+) udp=(\d+),`)
	eventually(t, 80*time.Second, 200*time.Millisecond, func() error {
		if lines := changedLines(m, changed); len(lines) != 2 {
			return fmt.Errorf("日志里有 %d 行地址变化，期望 2 行（每个 worker 一行）", len(lines))
		}
		lines := changedLines(m, closed)
		sum := 0
		for _, l := range lines {
			sum += l[1]
		}
		if sum != maxConn {
			return fmt.Errorf("关掉的会话合计 %d（%v），期望 %d", sum, lines, maxConn)
		}
		return nil
	})
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if s := m.statsAfterSignal(t).udp[1]; s.sessions != 0 {
			return fmt.Errorf("地址变化后 sessions=%d，期望 0", s.sessions)
		}
		return nil
	})
	fillAll("3")
	expectIgnored(2)
	if s := m.statsAfterSignal(t).udp[1]; s.sessions != maxConn || s.total != 2*maxConn {
		t.Errorf("重建后 sessions=%d total=%d，期望 %d/%d", s.sessions, s.total, maxConn, 2*maxConn)
	}
}

// changedLines 返回日志里匹配 re 的地址变化行的 (tcp, udp) 计数
func changedLines(m *mapper, re *regexp.Regexp) [][2]int {
	data, _ := os.ReadFile(m.logPath)
	var out [][2]int
	for _, line := range strings.Split(string(data), "\n") {
		if s := re.FindStringSubmatch(line); s != nil {
			a, _ := strconv.Atoi(s[1])
			b, _ := strconv.Atoi(s[2])
			out = append(out, [2]int{a, b})
		}
	}
	return out
}

// S5（M3）：域名 remote 的地址变化广播给每个 worker。N=2，TCP+UDP 规则，16 条 TCP 连接与 16 个 UDP 会话（两个 worker 都有）。改
// /etc/hosts 后恰有 2 行 changed from（每个 worker 一行），旧后端正常，各行 closed 为 0、kept 的 tcp=、udp= 与地址变化前那个 worker 的
// tcp_conns、udp_sessions 一一对应（worker 只查自己的，remote_sweep）；旧的 TCP 连接与旧 UDP 客户端都仍连旧后端；
// 之后 32 条新连接都连到新地址，两个 worker 都建了新连接
func TestWorkerDNSBroadcast(t *testing.T) {
	t.Parallel()
	inContainer(t)
	const n, k = 2, 16
	const name = "tpm-worker-dns.test"
	bport := freePort(t)
	for _, id := range []string{"2", "3"} {
		serveTCP(t, hostPort("127.0.0."+id, bport), echoHandler(id+"\n"))
		serveUDP(t, hostPort("127.0.0."+id, bport), id)
	}
	setLast := hostsEntry(t, "127.0.0.2", name)
	listen := loopback4(t)
	m := startMapper(t, listenPoints("tu", portOf(listen)), "-l", listen, "-r", fmt.Sprintf("%s:%d", name, bport), "-t", "-u",
		"--threads", strconv.Itoa(n))
	old := make([]*net.TCPConn, k)
	for i := range old {
		old[i] = dial(t, listen)
		if got := readLine(t, old[i]); got != "2" {
			t.Fatalf("启动时应解析到 127.0.0.2，第 %d 条连接连到后端 %q", i, got)
		}
	}
	us := make([]*net.UDPConn, k)
	for i := range us {
		us[i] = udpDial(t, "", listen)
		if got := udpReplyFrom(t, us[i], "before"); got != "2" {
			t.Fatalf("启动时 UDP 应发往 127.0.0.2，第 %d 个客户端 %q", i, got)
		}
	}
	before := m.statsAfterSignal(t)
	var want [][2]int
	for _, w := range before.workers {
		if w.tcpConns == 0 || w.udpSessions == 0 {
			t.Fatalf("worker 行 %+v：%d 条连接、%d 个会话没有分到每个 worker，用例测不到广播", before.workers, k, k)
		}
		want = append(want, [2]int{w.tcpConns, w.udpSessions})
	}
	setLast('3')
	changed := regexp.MustCompile(`rule 1 remote 0 domain ` + regexp.QuoteMeta(name) + `:\d+ changed from 127\.0\.0\.2:\d+ to 127\.0\.0\.3:\d+, closed unresponsive tcp=0 udp=0, kept tcp=(\d+) udp=(\d+)$`)
	var lines [][2]int
	eventually(t, 50*time.Second, 200*time.Millisecond, func() error {
		if lines = changedLines(m, changed); len(lines) < n {
			return fmt.Errorf("日志里有 %d 行地址变化，期望 %d 行（每个 worker 一行）", len(lines), n)
		}
		return nil
	})
	for i, c := range old {
		mustEcho(t, c, fmt.Sprintf("old-%d", i))
	}
	time.Sleep(time.Second) // 再等两个定时器周期：同一次变化不能广播两次
	if lines = changedLines(m, changed); len(lines) != n {
		t.Errorf("日志里有 %d 行地址变化 %v，期望恰好 %d 行", len(lines), lines, n)
	}
	sortPairs := func(p [][2]int) {
		slices.SortFunc(p, func(a, b [2]int) int { return a[0]*100000 + a[1] - b[0]*100000 - b[1] })
	}
	sortPairs(lines)
	sortPairs(want)
	if !slices.Equal(lines, want) {
		t.Errorf("地址变化行留下的 (tcp, udp) 为 %v，期望与变化前各 worker 的 (tcp_conns, udp_sessions) %v 一致", lines, want)
	}
	for i, c := range us {
		if got := udpReplyFrom(t, c, "after"); got != "2" {
			t.Fatalf("地址变化后旧 UDP 客户端 %d 发往后端 %q，期望仍为旧后端 2", i, got)
		}
	}
	mid := m.statsAfterSignal(t)
	for i := range 2 * k {
		c := dial(t, listen)
		if got := readLine(t, c); got != "3" {
			t.Fatalf("地址变化后第 %d 条新连接连到后端 %q", i, got)
		}
		mustEcho(t, c, "new")
	}
	after := m.statsAfterSignal(t)
	for w := range after.workers {
		if after.workers[w].tcpTotal == mid.workers[w].tcpTotal {
			t.Errorf("worker %d 在地址变化后没有建新连接（之前 %+v，之后 %+v）", w, mid.workers, after.workers)
		}
	}
	if s := after.udp[1]; s.sessions != k || s.total != k {
		t.Errorf("统计 udp sessions=%d total=%d，期望 %d/%d（旧会话都留下）", s.sessions, s.total, k, k)
	}
}

// S6（D63）：N=2、4 的 SIGUSR1。规则 1 仅 TCP、规则 2 仅 UDP；规则 1 先有 16 条双向传输完并关闭的连接（字节已知）、再有 4 条保持的空闲
// 连接，规则 2 有 10 个会话各往返 3 包。一组统计恰为：worker 0..N-1 各一行，规则 1 的 tcp 行，规则 2 的 udp 行，pool 行，连续、依此顺序；
// 求和的规则行精确，至少两个 worker 有 TCP 与 UDP（worker 行之和等于规则行，statsAfterSignal 核对）。之后边转发（info 级下 worker 线程
// 每条连接都写日志）边连发 30 次 SIGUSR1：一轮没收齐时再来的合并为下一轮，所以组数在 1 与 31 之间；每组都完整、连续（v2 起整组锁 stdout，
// worker 的日志行不能插进组里），各组的不变式都成立
func TestWorkerStats(t *testing.T) {
	t.Parallel()
	for _, n := range []int{2, 4} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			workerStats(t, n)
		})
	}
}

func workerStats(t *testing.T, n int) {
	affinityOverlap(t, n) // 连接分到至少两个 worker
	be := serveTCP(t, loopback4(t), streamHandler)
	ube := serveUDP(t, loopback4(t), "")
	p1, p2 := loopback4(t), loopback4(t)
	cfg := writeConfig(t, fmt.Sprintf(`[[endpoints]]
listen = %q
remote = %q

[[endpoints]]
listen = %q
remote = %q
no_tcp = true
use_udp = true
`, p1, be.addr, p2, ube.addr))
	m := startMapper(t, slices.Concat(listenPoints("t", portOf(p1)), listenPoints("u", portOf(p2))), "-c", cfg, "--threads", strconv.Itoa(n))
	var wantUp, wantDown uint64
	errs := make([]error, 16)
	parallelFor(16, 16, func(i int) {
		up, down := int64(1000*(i+1)), int64(70000*(i+1))
		errs[i] = transfer(p1, up, down, 4096, uint64(i))
	})
	for i := range 16 {
		if errs[i] != nil {
			t.Fatalf("第 %d 条连接：%v", i, errs[i])
		}
		wantUp += uint64(1000*(i+1) + streamHeaderLen)
		wantDown += uint64(70000*(i+1) + 64)
	}
	idle := make([]net.Conn, 4)
	for i := range idle {
		idle[i] = dial(t, p1) // streamHandler 等 28 B 头，连接保持
	}
	var upPkts, upBytes uint64
	for i := range 10 {
		c := udpDial(t, "", p2)
		for j := range 3 {
			msg := strings.Repeat("u", 100*i+j+1)
			udpReplyFrom(t, c, msg)
			upPkts++
			upBytes += uint64(len(msg))
		}
	}
	var d statsDump
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if d = m.statsAfterSignal(t); d.tcp[1].conns != len(idle) {
			return fmt.Errorf("规则 1 当前 %d 条连接，期望 %d", d.tcp[1].conns, len(idle))
		}
		return nil
	})
	if s := d.tcp[1]; s.total != 20 || s.upBytes != wantUp || s.downBytes != wantDown {
		t.Errorf("规则 1 tcp total=%d up_bytes=%d down_bytes=%d，期望 20/%d/%d", s.total, s.upBytes, s.downBytes, wantUp, wantDown)
	}
	if s := d.udp[2]; s.sessions != 10 || s.total != 10 || s.upPkts != upPkts || s.downPkts != upPkts || s.upBytes != upBytes || s.downBytes != upBytes {
		t.Errorf("规则 2 udp %+v，期望 sessions=total=10、两个方向各 %d 包 %d 字节", s, upPkts, upBytes)
	}
	if _, ok := d.udp[1]; ok || len(d.tcp) != 1 || len(d.udp) != 1 {
		t.Errorf("规则行 tcp %v udp %v：规则 1 只有 tcp 行、规则 2 只有 udp 行", d.tcp, d.udp)
	}
	if busyWorkers(d, "tcp") < 2 || busyWorkers(d, "udp") < 2 {
		t.Errorf("worker 行 %+v：20 条连接、10 个会话应分到至少两个 worker", d.workers)
	}
	// 边转发边连发 SIGUSR1
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				transfer(p1, 64<<10, 64<<10, 4096, uint64(100+i*1000+j))
			}
		})
	}
	before := m.logLines("stats pool:")
	for range 30 {
		m.sendUSR1(t)
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	m.statsAfterSignal(t)
	data, _ := os.ReadFile(m.logPath)
	lines := strings.Split(string(data), "\n")
	kind := func(l string) string {
		switch {
		case strings.Contains(l, "stats worker "):
			return "w"
		case strings.Contains(l, "stats rule 1 tcp: "):
			return "t"
		case strings.Contains(l, "stats rule 2 udp: "):
			return "u"
		case strings.Contains(l, "stats pool: "):
			return "p"
		case strings.Contains(l, "stats "):
			return "?"
		}
		return ""
	}
	var seq strings.Builder
	var groups []statsDump
	start := -1
	for i, l := range lines {
		k := kind(l)
		seq.WriteString(map[bool]string{true: k, false: "."}[k != ""])
		if k == "" {
			if start >= 0 {
				t.Errorf("第 %d 行起的一组统计没有以 pool 行结尾", start+1)
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
		if k == "p" {
			g, err := parseStatsBlock(lines[start : i+1])
			if err != nil {
				t.Errorf("第 %d–%d 行的一组统计：%v", start+1, i+1, err)
			} else if layout, want := seq.String()[start:i+1], strings.Repeat("w", n)+"tup"; layout != want {
				t.Errorf("第 %d–%d 行的一组统计排成 %q，期望 %q（worker 0..%d、规则 1 tcp、规则 2 udp、pool）", start+1, i+1, layout, want, n-1)
			} else {
				checkPoolInvariants(t, g)
				groups = append(groups, g)
			}
			start = -1
		}
	}
	got := len(groups) - before
	t.Logf("连发 30 次 SIGUSR1 之后多出 %d 组统计（含最后一次的 1 组）", got)
	if got < 2 || got > 31 {
		t.Errorf("连发 30 次 SIGUSR1、再发 1 次之后多出 %d 组统计，期望 2–31 组", got)
	}
}

// S6 的合并与审查 L-5：N=2，经 seccomp 通知让一个 worker 线程停在一次 sendto 里（notifier.setHold），这时连发 5 次 SIGUSR1：这一轮收不齐，
// 1 s 内没有输出；发出 5 s 后恰好一行 warn "stats: worker(s) K did not answer SIGUSR1 within 5 s, still waiting"（K 为停住的 worker 号，
// 按线程名 worker<K> 对照）；放开之后恰好多出 2 组统计（停住的那一轮，加上合并了其余 4 次的下一轮），再等 1 s 也不再多，两组都完整
func TestWorkerStatsMerge(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--threads", "2")
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	var holding atomic.Int64
	pid := m.pid()
	nf.setHold(func(c notifyCall) <-chan struct{} {
		if (c.nr == syscall.SYS_SENDTO || c.nr == syscall.SYS_SENDMSG) && c.pid != pid && holding.CompareAndSwap(0, int64(c.pid)) {
			return release
		}
		return nil
	})
	c := dial(t, listen)
	if _, err := c.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	eventually(t, ioTimeout, 5*time.Millisecond, func() error {
		if holding.Load() == 0 {
			return errors.New("worker 还没有发送")
		}
		return nil
	})
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/comm", pid, holding.Load()))
	stuck, _ := strings.CutPrefix(strings.TrimSpace(string(comm)), "worker")
	t.Logf("停住的线程 %d（%s）", holding.Load(), strings.TrimSpace(string(comm)))
	before := m.logLines("stats pool:")
	start := time.Now()
	for range 5 {
		m.sendUSR1(t)
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(time.Second - time.Since(start))
	if k := m.logLines("stats pool:"); k != before {
		t.Fatalf("一个 worker 停住时有 %d 组统计输出：一轮没收齐不应输出", k-before)
	}
	late := "did not answer SIGUSR1 within 5 s, still waiting"
	eventually(t, 5*time.Second+3*logFlushWithin, 50*time.Millisecond, func() error {
		if k := m.logLines("[WARN]", "stats: worker(s) "+stuck+" "+late); k != 1 {
			return fmt.Errorf("没收齐的 warn（worker %s）有 %d 行，期望 1 行；含 %q 的共 %d 行", stuck, k, late, m.logLines(late))
		}
		return nil
	})
	if took := time.Since(start); took < 5*time.Second {
		t.Errorf("发出 SIGUSR1 之后 %v 就记了没收齐的 warn，期望 5 s 之后", took)
	}
	free()
	mustEchoRead(t, c, "held")
	eventually(t, ioTimeout, 20*time.Millisecond, func() error {
		if k := m.logLines("stats pool:") - before; k != 2 {
			return fmt.Errorf("放开之后有 %d 组统计，期望 2 组（停住的一轮 + 合并的一轮）", k)
		}
		return nil
	})
	time.Sleep(time.Second)
	if k := m.logLines("stats pool:") - before; k != 2 {
		t.Errorf("放开 1 s 之后共 %d 组统计，期望仍为 2 组：其余 4 次 SIGUSR1 应合并成一轮", k)
	}
	if k := m.logLines(late); k != 1 {
		t.Errorf("没收齐的 warn 共 %d 行，期望 1 行", k)
	}
	m.statsAfterSignal(t) // 之后照常：一次信号一组，格式与不变式由 statsAfterSignal 核对
}

// mustEchoRead 读回 c 上已经写出的 msg（回显）
func mustEchoRead(t testing.TB, c net.Conn, msg string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("回显 %q（%v），期望 %q", got, err, msg)
	}
}

// S8（M6）：SIGTERM、SIGINT 在 N=1、2、4 时边转发边退出：8 条并发的 TCP 双向传输与 4 个 UDP 客户端持续收发，发信号后 1.5 s 内以状态 0
// 退出，"got sigterm, exit"（或 sigint）恰好一行、已写进文件，没有 worker 超时的 warn。
// stuck：N=2 时让一个 worker 线程停在一次发送里（seccomp 通知收下这次 sendto 后不回应，见 notifier.setHold），SIGTERM 之后主线程合计
// 等 1 s，记一行 "1 of 2 workers did not stop within 1 s, exiting anyway"，仍以状态 0 退出（用时 0.9–2.5 s）
func TestWorkerSignalExit(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 4} {
		for _, sig := range []struct {
			name string
			sig  syscall.Signal
			line string
		}{{"sigterm", syscall.SIGTERM, "got sigterm, exit"}, {"sigint", syscall.SIGINT, "got sigint, exit"}} {
			t.Run(fmt.Sprintf("%s-%d", sig.name, n), func(t *testing.T) {
				t.Parallel()
				remote := loopback4(t)
				serveTCP(t, remote, streamHandler)
				serveUDP(t, remote, "")
				listen := loopback4(t)
				m := startMapper(t, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--threads", strconv.Itoa(n))
				stop := make(chan struct{})
				var wg sync.WaitGroup
				var moved atomic.Int64
				for i := range 8 {
					wg.Go(func() {
						for j := 0; ; j++ {
							select {
							case <-stop:
								return
							default:
							}
							if transfer(listen, 1<<20, 1<<20, 16<<10, uint64(i*1000+j)) == nil {
								moved.Add(1)
							}
						}
					})
				}
				for range 4 {
					wg.Go(func() {
						c, err := net.Dial("udp", listen)
						if err != nil {
							return
						}
						defer c.Close()
						buf := make([]byte, 2048)
						for {
							select {
							case <-stop:
								return
							default:
							}
							c.Write([]byte("load"))
							c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
							c.Read(buf)
						}
					})
				}
				defer func() { close(stop); wg.Wait() }()
				eventually(t, 10*time.Second, 10*time.Millisecond, func() error {
					if moved.Load() < 8 {
						return fmt.Errorf("只完成了 %d 次传输", moved.Load())
					}
					return nil
				})
				start := time.Now()
				m.cmd.Process.Signal(sig.sig)
				select {
				case <-m.done:
				case <-time.After(1500 * time.Millisecond):
					t.Fatalf("%v 之后 1.5 s 内没有退出", sig.sig)
				}
				t.Logf("%v 之后 %v 退出（%d 次传输完成）", sig.sig, time.Since(start).Round(time.Millisecond), moved.Load())
				m.stop(t, true)
				if m.exitErr != nil {
					t.Errorf("%v 之后退出状态 %v，期望 0", sig.sig, m.exitErr)
				}
				if k := m.logLines(sig.line); k != 1 {
					t.Errorf("日志里有 %d 行 %q，期望 1 行", k, sig.line)
				}
				if k := m.logLines("did not stop within"); k != 0 {
					t.Errorf("日志里有 %d 行 worker 退出超时的 warn", k)
				}
			})
		}
	}
	t.Run("stuck", func(t *testing.T) {
		t.Parallel()
		be := serveTCP(t, loopback4(t), echoHandler(""))
		listen := loopback4(t)
		m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--threads", "2")
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		var holding atomic.Int64
		pid := m.pid()
		nf.setHold(func(c notifyCall) <-chan struct{} {
			if (c.nr == syscall.SYS_SENDTO || c.nr == syscall.SYS_SENDMSG) && c.pid != pid && holding.CompareAndSwap(0, int64(c.pid)) {
				return release
			}
			return nil
		})
		c := dial(t, listen)
		if _, err := c.Write([]byte("stuck")); err != nil {
			t.Fatal(err)
		}
		eventually(t, ioTimeout, 5*time.Millisecond, func() error {
			if holding.Load() == 0 {
				return errors.New("worker 还没有发送")
			}
			return nil
		})
		start := time.Now()
		m.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-m.done:
		case <-time.After(3 * time.Second):
			t.Fatal("一个 worker 停在系统调用里时 SIGTERM 之后 3 s 内没有退出")
		}
		took := time.Since(start)
		t.Logf("worker 线程 %d 停在 sendto 里，SIGTERM 之后 %v 退出", holding.Load(), took.Round(time.Millisecond))
		m.stop(t, true)
		if m.exitErr != nil {
			t.Errorf("退出状态 %v，期望 0", m.exitErr)
		}
		if took < 900*time.Millisecond || took > 2500*time.Millisecond {
			t.Errorf("SIGTERM 之后 %v 退出，期望约 1 s（主线程合计等 1 s）", took)
		}
		if k := m.logLines("[WARN]", "1 of 2 workers did not stop within 1 s, exiting anyway"); k != 1 {
			t.Errorf("worker 退出超时的 warn 有 %d 行，期望 1 行：\n%s", k, m.logTail(10))
		}
		if k := m.logLines("got sigterm, exit"); k != 1 {
			t.Errorf("日志里有 %d 行 got sigterm, exit，期望 1 行", k)
		}
	})
}

// S2：启动时的端口冲突。TCP 先用一个不带 SO_REUSEPORT 的 socket 试 bind：
//   - tcp-instance-A-B：已有一个 A 个 worker 的实例时，再起一个 B 个 worker 的实例在同一 TCP 端口上以 bind 失败（EADDRINUSE）退出，没有
//     加入前一个的 reuseport 组（端口上的监听仍恰为 A 个），前一个照常转发；
//   - tcp-overlap-*：同一配置里 [::]:p 与 0.0.0.0:p 两条 TCP 规则（任一先后，1 个与 2 个 worker）在第 2 条规则上 bind 失败；
//   - udp-instance、udp-overlap：UDP 的探测只带 SO_REUSEADDR（审查 L-1），SO_REUSEADDR 本来就允许重复绑定（与 M2 之前相同）：第二个
//     实例、同一配置里重叠的两条 UDP 规则都照常启动；udp-busy：端口被不带 SO_REUSEADDR 的 socket 占着时以 bind 失败退出；
//   - tcp/udp-reuseport-holder：端口被只带 SO_REUSEPORT 的 socket 占着时以 bind 失败退出、没有加入它的组；udp-reuseaddr-holder：只带
//     SO_REUSEADDR 时照常启动
func TestWorkerListenConflict(t *testing.T) {
	t.Parallel()
	const bindFailed = "[tcp] socket bind failed on "
	inUse := fmt.Sprintf(", %d:", int(syscall.EADDRINUSE))
	for _, c := range [][2]int{{2, 1}, {1, 2}, {2, 2}} {
		t.Run(fmt.Sprintf("tcp-instance-%d-%d", c[0], c[1]), func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), echoHandler(""))
			listen := loopback4(t)
			a := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--threads", strconv.Itoa(c[0]))
			out := runExpectFail(t, 5*time.Second, "-l", listen, "-r", be.addr, "-t", "--threads", strconv.Itoa(c[1]))
			if !strings.Contains(out, "rule 1 "+bindFailed+listen) || !strings.Contains(out, inUse) {
				t.Errorf("第二个实例的输出里没有 %q 与 %q：\n%s", "rule 1 "+bindFailed+listen, inUse, out)
			}
			expectListeners(t, a, "tcp", portOf(listen), c[0])
			if got := portListeners("tcp", portOf(listen)); got != c[0] {
				t.Errorf("端口上有 %d 个 TCP 监听，期望仍为第一个实例的 %d 个", got, c[0])
			}
			for i := range 8 {
				mustEcho(t, dial(t, listen), fmt.Sprintf("a-%d", i))
			}
		})
	}
	for _, c := range []struct {
		name   string
		first  string
		second string
		n      int
	}{
		{"tcp-overlap-v6-v4-1", "[::]", "0.0.0.0", 1},
		{"tcp-overlap-v6-v4-2", "[::]", "0.0.0.0", 2},
		{"tcp-overlap-v4-v6-2", "0.0.0.0", "[::]", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			remote := loopback4(t)
			p := freePort(t)
			cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = \"%s:%d\"\nremote = %q\n\n[[endpoints]]\nlisten = \"%s:%d\"\nremote = %q\n",
				c.first, p, remote, c.second, p, remote))
			out := runExpectFail(t, 5*time.Second, "-c", cfg, "--threads", strconv.Itoa(c.n))
			if want := fmt.Sprintf("rule 2 %s%s:%d", bindFailed, c.second, p); !strings.Contains(out, want) || !strings.Contains(out, inUse) {
				t.Errorf("输出里没有 %q 与 %q：\n%s", want, inUse, out)
			}
		})
	}
	t.Run("udp-instance", func(t *testing.T) {
		t.Parallel()
		be := serveUDP(t, loopback4(t), "")
		listen := loopback4(t)
		wait := listenPoints("u", portOf(listen))
		a := startMapper(t, wait, "-l", listen, "-r", be.addr, "-u", "--threads", "2")
		b := startMapper(t, wait, "-l", listen, "-r", be.addr, "-u", "--threads", "2")
		expectListeners(t, a, "udp", portOf(listen), 2)
		expectListeners(t, b, "udp", portOf(listen), 2)
		if !a.aliveAfter(200*time.Millisecond) || b.exited() {
			t.Fatal("同一 UDP 端口上的两个实例应当都在运行")
		}
	})
	// sockOpts 返回在 bind 之前设 SOL_SOCKET 选项 opts（值为 1）的 ListenConfig
	sockOpts := func(opts ...int) net.ListenConfig {
		return net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				for _, o := range opts {
					if serr == nil {
						serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, o, 1)
					}
				}
			}); err != nil {
				return err
			}
			return serr
		}}
	}
	const soReusePort = 15 // SO_REUSEPORT（syscall 包里没有这个常量）
	// 审查 L-1：同 uid 的别的 socket 只带 SO_REUSEPORT 占着端口时，不探测的话 tinymapper 的 reuseport socket 会静默加入它的组；探测 socket
	// 只带 SO_REUSEADDR，bind 失败、以 fatal 退出。TCP 与 UDP 相同
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto+"-reuseport-holder", func(t *testing.T) {
			t.Parallel()
			listen := loopback4(t)
			lc := sockOpts(soReusePort)
			if proto == "tcp" {
				ln, err := lc.Listen(context.Background(), "tcp", listen)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
			} else {
				pc, err := lc.ListenPacket(context.Background(), "udp", listen)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { pc.Close() })
			}
			flag := map[string]string{"tcp": "-t", "udp": "-u"}[proto]
			out := runExpectFail(t, 5*time.Second, "-l", listen, "-r", loopback4(t), flag, "--threads", "2")
			if want := fmt.Sprintf("rule 1 [%s] socket bind failed on %s", proto, listen); !strings.Contains(out, want) || !strings.Contains(out, inUse) {
				t.Errorf("输出里没有 %q 与 %q：\n%s", want, inUse, out)
			}
			if got := portListeners(proto, portOf(listen)); got != 1 {
				t.Errorf("端口上有 %d 个 %s 监听，期望只有占着它的那 1 个（tinymapper 的 socket 没有加入它的 reuseport 组）", got, proto)
			}
		})
	}
	// L-1：占着 UDP 端口的 socket 只带 SO_REUSEADDR 时照常启动（与 M2 之前相同：两边都带 SO_REUSEADDR）
	t.Run("udp-reuseaddr-holder", func(t *testing.T) {
		t.Parallel()
		listen := loopback4(t)
		lc := sockOpts(syscall.SO_REUSEADDR)
		pc, err := lc.ListenPacket(context.Background(), "udp", listen)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		m := startMapper(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", loopback4(t), "-u", "--threads", "2")
		expectListeners(t, m, "udp", portOf(listen), 2)
		if got := portListeners("udp", portOf(listen)); got != 3 {
			t.Errorf("端口上有 %d 个 UDP socket，期望 3（占着的 1 个与 tinymapper 的 2 个）", got)
		}
	})
	// 审查 L-1：UDP 也先用只带 SO_REUSEADDR 的 socket 试 bind；端口被不带 SO_REUSEADDR 的 socket 占着时（M2 之前同样）以 bind 失败退出
	t.Run("udp-busy", func(t *testing.T) {
		t.Parallel()
		busy, err := net.ListenPacket("udp", loopback4(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { busy.Close() })
		listen := busy.LocalAddr().String()
		out := runExpectFail(t, 5*time.Second, "-l", listen, "-r", loopback4(t), "-u", "--threads", "2")
		if want := "rule 1 [udp] socket bind failed on " + listen; !strings.Contains(out, want) || !strings.Contains(out, inUse) {
			t.Errorf("输出里没有 %q 与 %q：\n%s", want, inUse, out)
		}
	})
	t.Run("udp-overlap", func(t *testing.T) {
		t.Parallel()
		be := serveUDP(t, loopback4(t), "")
		p := freePort(t)
		cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = \"[::]:%d\"\nremote = %q\nno_tcp = true\nuse_udp = true\n\n"+
			"[[endpoints]]\nlisten = \"0.0.0.0:%d\"\nremote = %q\nno_tcp = true\nuse_udp = true\n", p, be.addr, p, be.addr))
		m := startMapper(t, listenPoints("u", p), "-c", cfg, "--threads", "2")
		expectListeners(t, m, "udp", p, 4)
		udpReplyFrom(t, udpDial(t, "", hostPort("127.0.0.1", p)), "v4")
		udpReplyFrom(t, udpDial(t, "", hostPort("::1", p)), "v6")
	})
}

// D64、S10：空闲 pipe 进程合计仍 ≤ 1024 页，按 worker 数均分、每个 worker 至少 1 个：每个 worker 的上限为 max(1, pipePoolCap(size)/N)。
// 做法同 TestSplicePoolCap：conns 条慢读连接（后端各写 512 KiB）都持有下行 pipe 之后慢读排空、逐条校验；排空后空闲 pipe 合计不超过
// N×每 worker 上限（照每个 worker 1024 页算时 2-default 留到 32 个），空闲加 scratch 不少于各 worker min(持有数, 上限) 之和，pipe fd 恰为
// 2×alloc。8-1024 一项每个 worker 按页算是 0 个，至少留 1 个
func TestWorkerPipePoolCap(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	for _, c := range []struct {
		name  string
		n     int
		args  []string
		size  int
		conns int
	}{
		{"2-default", 2, nil, defaultPipeSize, 40},
		{"4-1024", 4, []string{"--pipe-size", "1024"}, 1 << 20, 24},
		{"8-1024", 8, []string{"--pipe-size", "1024"}, 1 << 20, 24},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			affinityTooMany(t, c.n)
			const S = 512 << 10
			perWorker := max(1, pipePoolCap(c.size)/c.n)
			be := serveTCP(t, loopback4(t), sizedStreamHandler(S))
			listen := loopback4(t)
			m := startMapper(t, listenPoints("t", portOf(listen)),
				append([]string{"-l", listen, "-r", be.addr, "-t", "--threads", strconv.Itoa(c.n)}, c.args...)...)
			reader := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
			conns := make([]*net.TCPConn, c.conns)
			for i := range conns {
				nc, err := reader.Dial("tcp", listen)
				if err != nil {
					t.Fatalf("连接 %s 失败：%v", listen, err)
				}
				conns[i] = nc.(*net.TCPConn)
				t.Cleanup(func() { nc.Close() })
				fmt.Fprintf(conns[i], "%d\n", i)
			}
			var peak statsDump
			eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
				if peak = m.statsAfterSignal(t); peak.pool.pipeHeld != c.conns {
					return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望 %d 个方向都持有 pipe", peak.pool.pipeHeld, peak.pool.held, c.conns)
				}
				return nil
			})
			lower, over := 0, false
			for _, w := range peak.workers {
				lower += min(w.tcpConns, perWorker)
				over = over || w.tcpConns > perWorker
			}
			if !over {
				t.Fatalf("没有哪个 worker 持有超过 %d 个 pipe（worker 行 %+v）：测不到上限", perWorker, peak.workers)
			}
			results := make(chan error, c.conns)
			for i, cn := range conns {
				go func() { results <- slowVerify(cn, S, streamSeed(uint64(i), true)) }()
			}
			for range conns {
				if err := <-results; err != nil {
					t.Fatalf("排空校验失败：%v", err)
				}
			}
			var d statsDump
			eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
				if d = m.statsAfterSignal(t); d.pool.pipeHeld != 0 || d.pool.held != 0 {
					return fmt.Errorf("排空后仍有 %d 个方向持有 pipe、%d 个持有块", d.pool.pipeHeld, d.pool.held)
				}
				return nil
			})
			t.Logf("每 worker 上限 %d：峰值 pool %+v、worker 行 %+v；排空后 %+v", perWorker, peak.pool, peak.workers, d.pool)
			if p := d.pool; p.pipeFree > c.n*perWorker || p.pipeFree+p.pipeScratch < lower {
				t.Errorf("排空后 pipes free=%d scratch=%d，期望 free ≤ %d（%d 个 worker 各 %d）、free+scratch ≥ %d", p.pipeFree, p.pipeScratch,
					c.n*perWorker, c.n, perWorker, lower)
			}
			m.expectPipeFDs(t, d, "排空后")
		})
	}
}
