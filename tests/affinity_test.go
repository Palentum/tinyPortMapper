// M5（docs/tasks/p4.md 的 D70–D73、A1–A11）：--cpu-affinity 的功能测试。
//
// --cpu-affinity 时 worker k 绑到启动时 sched_getaffinity 掩码里的第 k 个 CPU（升序，A2/A3），主线程与 DNS 线程不绑（A8）；N>1 时每条启用 TCP
// 的规则的 TCP reuseport 组挂一个 cBPF（A4/A5）：softirq 所在 CPU 是 worker k 的 CPU 就选组里第 k 个 socket（worker k 的监听），否则返回
// 0xffffffff，内核回退到原来的四元组哈希。UDP 组不挂（D73、A11）：UDP 流照旧按四元组哈希，收包 CPU 变了也不换 worker。loopback 上收方的
// 协议处理（softirq）在发送线程的 CPU 上（build/m5/probe.c 核实），所以用例把发送线程绑到某个 CPU（onCPU）就能确定性地决定新连接落到哪个
// worker、核对 UDP 流不随 CPU 走，再按 SIGUSR1 的 stats worker 行数出每个 worker 新建的连接与会话；tinymapper 的 CPU 掩码由 startMapperOnCPUs 给定（从绑了核的线程 fork，同 taskset -c）。这里的用例都显式给 --threads，并显式
// 给 --cpu-affinity（故意不给的在 TPM_AFFINITY=1 时跳过），不受 TPM_THREADS、TPM_AFFINITY 影响；绑核与按 CPU 分流的用例在可用 CPU 不够时跳过
package tests

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// getcpuNR：getcpu 的系统调用号（syscall 包的 amd64 表里没有 SYS_GETCPU）
var getcpuNR = map[string]uintptr{"amd64": 309, "arm64": 168}

const soReuseport = 15 // SO_REUSEPORT（syscall 包的 amd64 表里没有这个常量）

// needCPUs 要求 tinymapper 至少有 n 个可用 CPU（mapperCPUs），返回它们；不够时跳过
func needCPUs(t testing.TB, n int) []int {
	t.Helper()
	if _, ok := getcpuNR[runtime.GOARCH]; !ok {
		t.Skipf("getcpu 的系统调用号只登记了 amd64、arm64，当前为 %s", runtime.GOARCH)
	}
	cpus := mapperCPUs()
	if len(cpus) < n {
		t.Skipf("只有 %d 个可用 CPU（%v），本用例需要至少 %d 个", len(cpus), cpus, n)
	}
	return cpus
}

// cpuPick 从 cpus（至少 3 个）里选给 tinymapper 的两个 CPU 与一个不在其中的 CPU：4 个以上时为 cpus[1]、cpus[3]（不相邻，也不从第一个起：
// worker k 用的是掩码里第 k 个 CPU，不是 CPU 号 k；按指导原文 SKF_AD_CPU % N 分流时 cpus[1] 上的流会落到 socket 1，D70），只有 3 个时
// 为 cpus[1]、cpus[2]；掩码外的取 cpus[0]
func cpuPick(cpus []int) (mask []int, outside int) {
	if len(cpus) >= 4 {
		return []int{cpus[1], cpus[3]}, cpus[0]
	}
	return []int{cpus[1], cpus[2]}, cpus[0]
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ",")
}

// onCPU 在一个只许运行在 cpu 上的线程里执行 f，返回它的错误：goroutine 锁定线程（不解锁：goroutine 结束时 Go 连同线程一起退出，绑过核的
// 线程不回到线程池）后 sched_setaffinity 到 cpu，内核在调用返回之前就把线程迁过去（getcpu 核对）。f 里的 connect、send 都从这个线程发出，
// loopback 上收方的 softirq 也在 cpu 上，cBPF 读到的 SKF_AD_CPU 就是 cpu。f 不在测试 goroutine 上，不能调 t.Fatal
func onCPU(cpu int, f func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := schedSetaffinity(0, []int{cpu}); err != nil {
			errc <- fmt.Errorf("sched_setaffinity 到 CPU %d：%w", cpu, err)
			return
		}
		var got uint32
		if _, _, e := syscall.RawSyscall(getcpuNR[runtime.GOARCH], uintptr(unsafe.Pointer(&got)), 0, 0); e != 0 || int(got) != cpu {
			errc <- fmt.Errorf("绑到 CPU %d 之后线程在 CPU %d 上（getcpu：%v）", cpu, got, e)
			return
		}
		errc <- f()
	}()
	return <-errc
}

// startMapperOnCPUs 同 startMapper，tinymapper 以 CPU 掩码 cpus 启动（同 taskset -c）
func startMapperOnCPUs(t testing.TB, cpus []int, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(mapperBin, mapperArgv(args...)...)
	cmd.Stdout, cmd.Stderr = f, f
	return runMapperOn(t, cmd, cpus, logPath, wait)
}

// cpuList 解析 Cpus_allowed_list 的格式（如 "0-2,4"）
func cpuList(s string) ([]int, error) {
	var cpus []int
	for part := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("CPU 列表 %q：%w", s, err)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("CPU 列表 %q：%w", s, err)
			}
		}
		for c := a; c <= b; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}

// threadCPUs 返回线程 tid 的 Cpus_allowed_list（/proc/<pid>/task/<tid>/status）与线程名
func threadCPUs(pid, tid int) (cpus []int, comm string, err error) {
	c, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/comm", pid, tid))
	if err != nil {
		return nil, "", err
	}
	comm = strings.TrimSpace(string(c))
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", pid, tid))
	if err != nil {
		return nil, comm, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			cpus, err = cpuList(v)
			return cpus, comm, err
		}
	}
	return nil, comm, fmt.Errorf("/proc/%d/task/%d/status 里没有 Cpus_allowed_list", pid, tid)
}

// expectPinned 等到 tinymapper 恰有 threads 个线程，其中 worker 线程恰为 worker0..worker<n-1>（n = len(workerCPUs)，按线程名认），worker k
// 的 Cpus_allowed_list 恰为 workerCPUs[k]，主线程与其余线程（DNS 线程）恰为 full。worker 线程在全部监听就绪之后才建，先改名、再在 ev_run 之前
// 绑核，所以要等
func expectPinned(t testing.TB, m *mapper, threads int, workerCPUs [][]int, full []int) {
	t.Helper()
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		m.fatalIfExited(t, "等绑核时")
		tids := taskIDs(t, m.pid())
		if len(tids) != threads {
			return fmt.Errorf("tinymapper 有 %d 个线程，期望 %d", len(tids), threads)
		}
		seen := map[int]bool{}
		for _, tid := range tids {
			got, comm, err := threadCPUs(m.pid(), tid)
			if err != nil {
				return err
			}
			want, role := full, "主线程"
			if tid != m.pid() {
				role = "DNS 线程"
				if s, ok := strings.CutPrefix(comm, "worker"); ok {
					k, err := strconv.Atoi(s)
					if err != nil || k >= len(workerCPUs) || seen[k] {
						return fmt.Errorf("线程 %d 名为 %q：期望 worker0..worker%d 各一个", tid, comm, len(workerCPUs)-1)
					}
					seen[k] = true
					want, role = workerCPUs[k], comm
				}
			}
			if !slices.Equal(got, want) {
				return fmt.Errorf("线程 %d（%s，%s）的 Cpus_allowed_list 为 %v，期望 %v", tid, comm, role, got, want)
			}
		}
		if len(seen) != len(workerCPUs) {
			return fmt.Errorf("只认出 %d 个 worker 线程（%v），期望 %d 个", len(seen), seen, len(workerCPUs))
		}
		return nil
	})
}

// pinnedEach 返回 cpus 里每个 CPU 单独一个的掩码：worker k 绑到 cpus[k] 时 expectPinned 的期望
func pinnedEach(cpus []int) [][]int {
	var w [][]int
	for _, c := range cpus {
		w = append(w, []int{c})
	}
	return w
}

// unpinned 返回 n 个 full：worker 都没有绑核时 expectPinned 的期望
func unpinned(n int, full []int) [][]int {
	var w [][]int
	for range n {
		w = append(w, full)
	}
	return w
}

var affinityInfoRe = regexp.MustCompile(`\[INFO\]cpu affinity: workers on cpus ([0-9,]+)$`)

// expectAffinityInfo 等到日志里恰有一行 "cpu affinity: workers on cpus c0,c1,..."（A2，按 worker 次序），CPU 恰为 cpus
func expectAffinityInfo(t testing.TB, m *mapper, cpus []int) {
	t.Helper()
	eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
		data, _ := os.ReadFile(m.logPath)
		var got []string
		for _, line := range strings.Split(string(data), "\n") {
			if s := affinityInfoRe.FindStringSubmatch(line); s != nil {
				got = append(got, s[1])
			}
		}
		if len(got) != 1 || got[0] != joinInts(cpus) || m.logLines("cpu affinity:") != 1 {
			return fmt.Errorf("cpu affinity 的 info 行：%q（含 \"cpu affinity:\" 的共 %d 行），期望恰好一行 %s", got, m.logLines("cpu affinity:"), joinInts(cpus))
		}
		return nil
	})
}

// workerTotals 返回 SIGUSR1 统计里每个 worker 的已建 TCP 连接数（proto 为 "tcp"）或已建 UDP 会话数
func workerTotals(t testing.TB, m *mapper, proto string) []uint64 {
	t.Helper()
	d := m.statsAfterSignal(t)
	tot := make([]uint64, len(d.workers))
	for k, w := range d.workers {
		tot[k] = w.tcpTotal
		if proto == "udp" {
			tot[k] = w.udpTotal
		}
	}
	return tot
}

// sub 返回 after - before（逐个 worker）
func sub(after, before []uint64) []uint64 {
	d := make([]uint64, len(after))
	for k := range after {
		d[k] = after[k] - before[k]
	}
	return d
}

// spread 从绑在 cpu 上的线程向 listen 新建 n 条 TCP 连接（proto 为 "tcp"，各回显一次后关闭）或 n 个 UDP 流（各一来一回），返回每个 worker
// 因此多出的已建连接数或会话数（前后两次 SIGUSR1 的 stats worker 行相减）
func spread(t testing.TB, m *mapper, proto string, cpu int, listen string, n int) []uint64 {
	t.Helper()
	before := workerTotals(t, m, proto)
	var udp []*net.UDPConn
	if proto == "udp" {
		for range n {
			udp = append(udp, udpDial(t, "", listen)) // UDP 的 connect 不发包：建 socket 不必在绑核的线程上
		}
	}
	var conns []net.Conn
	err := onCPU(cpu, func() error {
		for i := range n {
			msg := fmt.Appendf(nil, "%s-cpu%d-%d", proto, cpu, i)
			if proto == "udp" {
				got, err := udpRoundTrip(udp[i], msg)
				if err != nil {
					return fmt.Errorf("第 %d 个流：%w", i, err)
				}
				if !bytes.Equal(got, msg) {
					return fmt.Errorf("第 %d 个流的回包 %q，期望 %q", i, got, msg)
				}
				continue
			}
			c, err := net.DialTimeout("tcp", listen, ioTimeout)
			if err != nil {
				return fmt.Errorf("第 %d 条连接：%w", i, err)
			}
			conns = append(conns, c)
			if err := echo(c, msg); err != nil {
				return fmt.Errorf("第 %d 条连接：%w", i, err)
			}
		}
		return nil
	})
	for _, c := range conns {
		c.Close()
	}
	if err != nil {
		t.Fatalf("从 CPU %d 发出：%v", cpu, err)
	}
	d := sub(workerTotals(t, m, proto), before)
	t.Logf("CPU %d 上新建的 %d 个 %s 流：各 worker %v", cpu, n, proto, d)
	return d
}

// expectAllOn 要求 d 里只有 worker k 是 n，其余为 0
func expectAllOn(t testing.TB, what string, d []uint64, k int, n uint64) {
	t.Helper()
	want := make([]uint64, len(d))
	want[k] = n
	if !slices.Equal(d, want) {
		t.Errorf("%s：各 worker 新建 %v，期望全在 worker %d 上（%v）", what, d, k, want)
	}
}

// expectHashed 要求 d 的和为 n，且每个 worker 都分到了（按四元组哈希，64 个流全落在 2 个 worker 之一的概率约 1e-19）
func expectHashed(t testing.TB, what string, d []uint64, n uint64) {
	t.Helper()
	var sum uint64
	for _, v := range d {
		sum += v
	}
	if sum != n || slices.Contains(d, 0) {
		t.Errorf("%s：各 worker 新建 %v，期望共 %d 个、每个 worker 都有（按哈希分配）", what, d, n)
	}
}

// A1、A2：--cpu-affinity 只在命令行、没有参数；帮助文本里有它；TOML 的 [network] cpu_affinity 是未知键。可用 CPU 少于 worker 数时以 fatal
// 退出（默认掩码下 N = CPU 数 + 1，taskset 两个 CPU 时 --threads 3）；info 行按 worker 次序列出 CPU：taskset 给的掩码不从第一个起、不相邻
// 时就是那两个 CPU
func TestAffinityOption(t *testing.T) {
	t.Parallel()
	t.Run("help", func(t *testing.T) {
		t.Parallel()
		out, err := exec.Command(mapperBin, "-h").Output()
		if err != nil {
			t.Fatalf("-h 退出状态异常：%v", err)
		}
		if !strings.Contains(string(out), "--cpu-affinity") {
			t.Errorf("帮助文本里没有 --cpu-affinity：\n%s", out)
		}
	})
	t.Run("toml-key", func(t *testing.T) {
		t.Parallel()
		cfg := writeConfig(t, fmt.Sprintf("[network]\ncpu_affinity = true\n\n[[endpoints]]\nlisten = %q\nremote = %q\n", loopback4(t), loopback4(t)))
		if out := runExpectFail(t, 5*time.Second, "-c", cfg, "--threads", "2", "--cpu-affinity"); !strings.Contains(out, "unknown key in [network]") {
			t.Errorf("[network] cpu_affinity 的报错不符：\n%s", out)
		}
	})
	t.Run("too-many", func(t *testing.T) {
		t.Parallel()
		cpus := mapperCPUs()
		n := len(cpus) + 1
		if n > 64 {
			t.Skipf("%d 个可用 CPU：--threads 最多 64", len(cpus))
		}
		out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "--threads", strconv.Itoa(n), "--cpu-affinity")
		if want := fmt.Sprintf("--cpu-affinity: %d worker threads but only %d usable cpus", n, len(cpus)); !strings.Contains(out, "[FATAL]") || !strings.Contains(out, want) {
			t.Errorf("输出里没有 fatal %q：\n%s", want, out)
		}
	})
	t.Run("too-many-taskset", func(t *testing.T) {
		t.Parallel()
		cpus := needCPUs(t, 2)
		mask := cpus[len(cpus)-2:]
		out := runExpectFailOn(t, mask, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "-u", "--threads", "3", "--cpu-affinity")
		if want := "--cpu-affinity: 3 worker threads but only 2 usable cpus"; !strings.Contains(out, "[FATAL]") || !strings.Contains(out, want) {
			t.Errorf("taskset %v 下的输出里没有 fatal %q：\n%s", mask, want, out)
		}
	})
	t.Run("taskset-list", func(t *testing.T) {
		t.Parallel()
		mask, _ := cpuPick(needCPUs(t, 3))
		remote := loopback4(t)
		serveTCP(t, remote, echoHandler(""))
		listen := loopback4(t)
		m := startMapperOnCPUs(t, mask, listenPoints("t", portOf(listen)), "-l", listen, "-r", remote, "-t", "--threads", "2", "--cpu-affinity")
		expectAffinityInfo(t, m, mask)
		mustEcho(t, dial(t, listen), "x")
	})
}

// A2、A3、A6、A8：--threads 1、2 与 CPU 数个 worker 时 worker k 的线程恰绑在启动掩码的第 k 个 CPU 上，主线程不绑（Cpus_allowed_list 仍是整个
// 启动掩码），info 行恰好一行；threads=1 只绑核（没有 reuseport 组）；taskset 给的掩码下按掩码里的次序；有域名 remote 时 DNS 线程也不绑。
// 每种都照常转发 TCP 与 UDP
func TestAffinityPinning(t *testing.T) {
	t.Parallel()
	cpus := mapperCPUs()
	ns := []int{1}
	if len(cpus) >= 2 {
		ns = append(ns, 2)
	}
	if len(cpus) > 2 {
		ns = append(ns, min(len(cpus), 64))
	}
	for _, n := range ns {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			remote := loopback4(t)
			serveTCP(t, remote, echoHandler(""))
			serveUDP(t, remote, "")
			listen := loopback4(t)
			m := startMapper(t, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--threads", strconv.Itoa(n), "--cpu-affinity")
			expectAffinityInfo(t, m, cpus[:n])
			expectPinned(t, m, n+1, pinnedEach(cpus[:n]), cpus)
			mustEcho(t, dial(t, listen), "tcp")
			if got := udpReplyFrom(t, udpDial(t, "", listen), "udp"); got != "" {
				t.Errorf("UDP 回包前缀 %q", got)
			}
		})
	}
	t.Run("taskset", func(t *testing.T) {
		t.Parallel()
		mask, _ := cpuPick(needCPUs(t, 3))
		remote := loopback4(t)
		serveTCP(t, remote, echoHandler(""))
		listen := loopback4(t)
		m := startMapperOnCPUs(t, mask, listenPoints("t", portOf(listen)), "-l", listen, "-r", remote, "-t", "--threads", "2", "--cpu-affinity")
		expectPinned(t, m, 3, pinnedEach(mask), mask)
		mustEcho(t, dial(t, listen), "x")
	})
	t.Run("domain", func(t *testing.T) {
		t.Parallel()
		cpus := needCPUs(t, 2)
		bport := freePort(t)
		serveTCP(t, hostPort("127.0.0.1", bport), echoHandler(""))
		serveTCP(t, hostPort("::1", bport), echoHandler(""))
		listen := loopback4(t)
		m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", fmt.Sprintf("localhost:%d", bport), "-t", "--threads", "2", "--cpu-affinity")
		expectPinned(t, m, 4, pinnedEach(cpus[:2]), cpus)
		mustEcho(t, dial(t, listen), "x")
	})
}

// A4、A5（D70）：2 个 worker，tinymapper 在两个 CPU 的掩码上（cpuPick），规则只有 TCP。发送线程绑在 worker k 的 CPU 上时 64 条新 TCP 连接全由 worker k 接受；
// 绑在掩码外的 CPU 上时按四元组哈希分给两个 worker。foreign-member：启动之后同 uid 的外来 socket 以 SO_REUSEPORT 监听同一地址、加入组成为
// 第 3 个成员时，非 worker CPU 上的新连接仍按哈希分给整组（3 个都分到；cBPF 若返回 N 就会全给外来 socket），worker CPU 上的照旧全给对应的 worker
func TestAffinitySteerTCP(t *testing.T) {
	t.Parallel()
	mask, outside := cpuPick(needCPUs(t, 3))
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	listen := loopback4(t)
	m := startMapperOnCPUs(t, mask, listenPoints("t", portOf(listen)), "-l", listen, "-r", remote, "-t", "--threads", "2", "--cpu-affinity")
	expectAffinityInfo(t, m, mask)
	for k, c := range mask {
		expectAllOn(t, fmt.Sprintf("CPU %d（worker %d）上的 64 条连接", c, k), spread(t, m, "tcp", c, listen, 64), k, 64)
	}
	expectHashed(t, fmt.Sprintf("掩码外 CPU %d 上的 64 条连接", outside), spread(t, m, "tcp", outside, listen, 64), 64)

	t.Run("foreign-member", func(t *testing.T) {
		lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
			var serr error
			if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReuseport, 1) }); err != nil {
				return err
			}
			return serr
		}}
		foreign := serveTCPConfig(t, lc, listen, echoHandler(""))
		if got := portListeners("tcp", portOf(listen)); got != 3 {
			t.Fatalf("端口上有 %d 个 TCP 监听，期望 3（tinymapper 的 2 个与外来的 1 个）", got)
		}
		// count 从 cpu 上建 64 条连接（不发数据），等到都被接受，返回各 worker 与外来 socket 各接受了多少
		count := func(cpu int) ([]uint64, uint64) {
			t.Helper()
			before, f0 := workerTotals(t, m, "tcp"), foreign.accepted.Load()
			var conns []net.Conn
			err := onCPU(cpu, func() error {
				for i := range 64 {
					c, err := net.DialTimeout("tcp", listen, ioTimeout)
					if err != nil {
						return fmt.Errorf("第 %d 条连接：%w", i, err)
					}
					conns = append(conns, c)
				}
				return nil
			})
			defer func() {
				for _, c := range conns {
					c.Close()
				}
			}()
			if err != nil {
				t.Fatalf("从 CPU %d 发出：%v", cpu, err)
			}
			var d []uint64
			var f uint64
			eventually(t, ioTimeout, 50*time.Millisecond, func() error {
				d, f = sub(workerTotals(t, m, "tcp"), before), uint64(foreign.accepted.Load()-f0)
				if d[0]+d[1]+f != 64 {
					return fmt.Errorf("各 worker 接受 %v、外来 socket 接受 %d，合计不到 64", d, f)
				}
				return nil
			})
			t.Logf("CPU %d 上的 64 条连接：各 worker %v，外来 socket %d", cpu, d, f)
			return d, f
		}
		if d, f := count(mask[0]); f != 0 {
			t.Errorf("worker 0 的 CPU %d 上的连接有 %d 条给了外来 socket（各 worker %v）", mask[0], f, d)
		} else {
			expectAllOn(t, fmt.Sprintf("组里有外来 socket 时 CPU %d 上的 64 条连接", mask[0]), d, 0, 64)
		}
		// 3 个成员按哈希分，某一个一条都没有的概率约 3×(2/3)^64 ≈ 2e-11
		if d, f := count(outside); f == 0 || f == 64 || slices.Contains(d, 0) {
			t.Errorf("掩码外 CPU %d 上的 64 条连接：各 worker %v、外来 socket %d，期望 3 个成员都分到（cBPF 对非 worker CPU 返回越界值，回退哈希）",
				outside, d, f)
		}
	})
}

// D73、A11：UDP 不按 CPU 分流。2 个 worker，tinymapper 在 cpuPick 的掩码上，一条 TCP+UDP 规则：发送线程绑在 worker 0 的 CPU 上时新 TCP 连接
// 全给 worker 0（同一条规则的 TCP 组照样挂了 cBPF），64 个新 UDP 流（每个流一个新客户端 socket，一来一回）却按四元组哈希分给两个 worker；
// 绑在 worker 1 的 CPU 与掩码外的 CPU 上的 64 个流同样按哈希分。no-hop：同一个流在 worker 0 的 CPU、worker 1 的 CPU、掩码外的 CPU 之间
// 轮流各发 4 包（共 3 轮），自始至终只有一个会话、后端只看到一个源地址，回包照常（按 CPU 分流时它会在两个 worker 上各建一个会话、上游看到
// 交替的源端口，审查中-2）
func TestAffinityUDPHash(t *testing.T) {
	t.Parallel()
	mask, outside := cpuPick(needCPUs(t, 3))
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	be := serveUDP(t, remote, "")
	listen := loopback4(t)
	m := startMapperOnCPUs(t, mask, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--threads", "2", "--cpu-affinity")
	expectAffinityInfo(t, m, mask)
	expectAllOn(t, fmt.Sprintf("CPU %d（worker 0）上的 64 条连接", mask[0]), spread(t, m, "tcp", mask[0], listen, 64), 0, 64)
	for _, c := range []int{mask[0], mask[1], outside} {
		expectHashed(t, fmt.Sprintf("CPU %d 上的 64 个 UDP 流", c), spread(t, m, "udp", c, listen, 64), 64)
	}

	t.Run("no-hop", func(t *testing.T) {
		c := udpDial(t, "", listen)
		before, peers := workerTotals(t, m, "udp"), len(be.peerList())
		for r := range 3 {
			for _, cpu := range []int{mask[0], mask[1], outside} {
				if err := onCPU(cpu, func() error {
					for i := range 4 {
						msg := fmt.Appendf(nil, "hop-%d-cpu%d-%d", r, cpu, i)
						got, err := udpRoundTrip(c, msg)
						if err != nil {
							return fmt.Errorf("第 %d 包：%w", i, err)
						}
						if !bytes.Equal(got, msg) {
							return fmt.Errorf("第 %d 包的回包 %q，期望 %q", i, got, msg)
						}
					}
					return nil
				}); err != nil {
					t.Fatalf("第 %d 轮从 CPU %d 发出：%v", r, cpu, err)
				}
			}
		}
		d, p := sub(workerTotals(t, m, "udp"), before), len(be.peerList())-peers
		if d[0]+d[1] != 1 || p != 1 {
			t.Errorf("同一个流轮流在 CPU %d、%d、%d 上发：各 worker 新建会话 %v、后端多看到 %d 个源地址，期望共 1 个会话、1 个源地址（UDP 不分流，D73）",
				mask[0], mask[1], outside, d, p)
		}
	})
}

// D70（默认关）：不给 --cpu-affinity 时 2 个 worker 都不绑核（Cpus_allowed_list 是整个启动掩码）、没有 cpu affinity 的 info 行，发送线程绑在
// 启动掩码第一个 CPU 上的 64 条 TCP 连接与 64 个 UDP 流照常按哈希分给两个 worker（没有挂 cBPF）
func TestAffinityDefaultOff(t *testing.T) {
	t.Parallel()
	if os.Getenv("TPM_AFFINITY") == "1" {
		t.Skip("TPM_AFFINITY=1：所有启动都带 --cpu-affinity")
	}
	mask, _ := cpuPick(needCPUs(t, 3))
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	serveUDP(t, remote, "")
	listen := loopback4(t)
	m := startMapperOnCPUs(t, mask, listenPoints("tu", portOf(listen)), "-l", listen, "-r", remote, "-t", "-u", "--threads", "2")
	expectPinned(t, m, 3, unpinned(2, mask), mask)
	expectHashed(t, fmt.Sprintf("CPU %d 上的 64 条连接", mask[0]), spread(t, m, "tcp", mask[0], listen, 64), 64)
	expectHashed(t, fmt.Sprintf("CPU %d 上的 64 个流", mask[0]), spread(t, m, "udp", mask[0], listen, 64), 64)
	// spread 等到了 SIGUSR1 的统计（写完即 fflush），启动时的日志行都已在文件里
	if k := m.logLines("cpu affinity"); k != 0 {
		t.Errorf("没给 --cpu-affinity，日志里却有 %d 行 cpu affinity", k)
	}
}

// attachCall 是一次被通知的 setsockopt(SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF)：发起的线程、fd 与传入的程序
type attachCall struct {
	tid, fd int
	prog    []syscall.SockFilter
	err     error // 读程序失败
}

// affinityCalls 在 notifier 的 decide 里记下 M5 相关的调用：每次 SO_ATTACH_REUSEPORT_CBPF 与每次 sched_setaffinity 的发起线程；
// fail 中的系统调用以对应的 errno 失败（setsockopt 只通知 SO_ATTACH_REUSEPORT_CBPF，见 notifyFilter）
type affinityCalls struct {
	fail   map[uint32]syscall.Errno
	mu     sync.Mutex
	attach []attachCall
	pins   []int
}

func (a *affinityCalls) decide(c notifyCall) syscall.Errno {
	switch {
	case c.nr == syscall.SYS_SETSOCKOPT && uint32(c.args[1]) == syscall.SOL_SOCKET && uint32(c.args[2]) == soAttachReuseportCBPF:
		prog, err := readCBPF(c)
		a.mu.Lock()
		a.attach = append(a.attach, attachCall{c.pid, c.fd(0), prog, err})
		a.mu.Unlock()
	case c.nr == syscall.SYS_SCHED_SETAFFINITY:
		a.mu.Lock()
		a.pins = append(a.pins, c.pid)
		a.mu.Unlock()
	}
	return a.fail[c.nr]
}

func (a *affinityCalls) snapshot() ([]attachCall, []int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.attach), slices.Clone(a.pins)
}

// readTargetMem 读进程 pid 地址 addr 处的 n 字节（同 readTargetString 经 /proc/<pid>/mem）
func readTargetMem(pid int, addr uint64, n int) ([]byte, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, int64(addr)); err != nil {
		return nil, err
	}
	return b, nil
}

// readCBPF 读被通知的 setsockopt(SO_ATTACH_REUSEPORT_CBPF) 传入的程序：optval 是 struct sock_fprog { u16 len; struct sock_filter *filter; }
// （64 位上 filter 在偏移 8），每条 struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; } 8 字节
func readCBPF(c notifyCall) ([]syscall.SockFilter, error) {
	if c.args[4] < 16 {
		return nil, fmt.Errorf("optlen 为 %d，小于 struct sock_fprog", c.args[4])
	}
	hdr, err := readTargetMem(c.pid, c.args[3], 16)
	if err != nil {
		return nil, err
	}
	ne := binary.NativeEndian
	n := int(ne.Uint16(hdr))
	ins, err := readTargetMem(c.pid, ne.Uint64(hdr[8:]), 8*n)
	if err != nil {
		return nil, err
	}
	prog := make([]syscall.SockFilter, n)
	for i := range prog {
		o := ins[8*i:]
		prog[i] = syscall.SockFilter{Code: ne.Uint16(o), Jt: o[2], Jf: o[3], K: ne.Uint32(o[4:])}
	}
	return prog, nil
}

// cpuSteerProg 是 A4 的程序：ld [SKF_AD_OFF+SKF_AD_CPU]；每个 worker k 一对 jeq #cpus[k], 0, 1 与 ret #k；最后 ret #0xffffffff，共 2N+2 条
func cpuSteerProg(cpus []int) []syscall.SockFilter {
	const skfAdCPU = 0xfffff000 + 36 // SKF_AD_OFF（-0x1000）+ SKF_AD_CPU
	prog := []syscall.SockFilter{{Code: syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS, K: skfAdCPU}}
	for k, c := range cpus {
		prog = append(prog,
			syscall.SockFilter{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jf: 1, K: uint32(c)},
			syscall.SockFilter{Code: syscall.BPF_RET | syscall.BPF_K, K: uint32(k)})
	}
	return append(prog, syscall.SockFilter{Code: syscall.BPF_RET | syscall.BPF_K, K: 0xffffffff})
}

// affinityRules 写一个三条规则的配置（后端是 TCP、UDP 回显）：规则 1、2 各 TCP+UDP，规则 3 仅 UDP；返回配置路径、三个监听地址与要等的监听
func affinityRules(t testing.TB) (cfg string, ls [3]string, wait []listenPoint) {
	t.Helper()
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	serveUDP(t, remote, "")
	ls = [3]string{loopback4(t), loopback4(t), loopback4(t)}
	cfg = writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\nuse_udp = true\n\n[[endpoints]]\nlisten = %q\nremote = %q\nuse_udp = true\n\n"+
		"[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n", ls[0], remote, ls[1], remote, ls[2], remote))
	return cfg, ls, slices.Concat(listenPoints("tu", portOf(ls[0])), listenPoints("tu", portOf(ls[1])), listenPoints("u", portOf(ls[2])))
}

// expectForwarding 要求 affinityRules 的规则 1、2 都能转发 TCP 与 UDP，规则 3 能转发 UDP
func expectForwarding(t testing.TB, ls [3]string) {
	t.Helper()
	for i, l := range ls {
		if i < 2 {
			mustEcho(t, dial(t, l), "tcp-"+l)
		}
		if got := udpReplyFrom(t, udpDial(t, "", l), "udp-"+l); got != "" {
			t.Errorf("%s 的 UDP 回包前缀 %q", l, got)
		}
	}
}

// expectWorkerPins 要求 pins 恰为 n 个不同的 worker 线程（按线程名 worker<k> 认，不是主线程）
func expectWorkerPins(t testing.TB, m *mapper, pins []int, n int) {
	t.Helper()
	seen := map[string]bool{}
	for _, tid := range pins {
		_, comm, err := threadCPUs(m.pid(), tid)
		if err != nil || tid == m.pid() || !strings.HasPrefix(comm, "worker") || seen[comm] {
			t.Errorf("sched_setaffinity 来自线程 %d（%q，%v），期望 %d 个 worker 线程各一次（主线程不绑核）", tid, comm, err, n)
		}
		seen[comm] = true
	}
	if len(pins) != n {
		t.Errorf("sched_setaffinity 共 %d 次，期望 %d 次（每个 worker 一次）", len(pins), n)
	}
}

// seccomp 通知（notifier）看 tinymapper 的 setsockopt(SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF) 与 sched_*affinity，并注入失败。三条规则（affinityRules：
// 两条 TCP+UDP、一条仅 UDP）：
//   - program-N（N=2 与 CPU 数）：启动时恰有 2 次挂载，都在主线程上、依次在规则 1、规则 2 的 TCP 组上（fd 是该组的监听之一），UDP 组一次都
//     不挂（D73、A11）；程序恰为 A4 的 2N+2 条（worker k ↔ 启动掩码第 k 个 CPU）；sched_setaffinity 恰为 N 次、来自 N 个 worker 线程；
//     没有 warn；照常转发；
//   - threads1（A6）：--threads 1 不挂（没有 reuseport 组），只绑 1 次；
//   - off（D72）：不给 --cpu-affinity 时既不挂也不绑（TPM_AFFINITY=1 时跳过）；
//   - attach-fail（A5、A10、A11）：挂载以 EINVAL 失败：规则 1 的 [tcp] 一行 warn、规则 2 的记 debug，没有 [udp] 的挂载失败行，照常转发，
//     worker 照样绑核，worker 0 的 CPU 上发出的 64 条连接按哈希分给两个 worker；
//   - pin-fail（A3、A10）：sched_setaffinity 以 EINVAL 失败：每个 worker 一行 warn（worker 号、CPU、running unpinned），worker 线程保持整个
//     启动掩码，照常转发；cBPF 照样挂上，worker 1 的 CPU 上的 64 条连接仍全给 worker 1；
//   - getaffinity-fail（A2、A10）：sched_getaffinity 以 EINVAL 失败：fatal 退出
func TestAffinityNotify(t *testing.T) {
	t.Parallel()
	cpus := mapperCPUs()
	start := func(t *testing.T, a *affinityCalls, wait []listenPoint, args ...string) *mapper {
		t.Helper()
		m, _ := startMapperNotifyWith(t, func(n *notifier) { n.setDecide(a.decide) }, wait, args...)
		return m
	}
	ns := []int{2}
	if len(cpus) > 2 {
		ns = append(ns, min(len(cpus), 64))
	}
	for _, n := range ns {
		t.Run(fmt.Sprintf("program-%d", n), func(t *testing.T) {
			t.Parallel()
			needCPUs(t, n)
			cfg, ls, wait := affinityRules(t)
			a := &affinityCalls{}
			m := start(t, a, wait, "-c", cfg, "--threads", strconv.Itoa(n), "--cpu-affinity")
			expectPinned(t, m, n+1, pinnedEach(cpus[:n]), cpus)
			attach, pins := a.snapshot()
			want := cpuSteerProg(cpus[:n])
			groups := []struct {
				proto, listen string
			}{{"tcp", ls[0]}, {"tcp", ls[1]}}
			if len(attach) != len(groups) {
				t.Fatalf("SO_ATTACH_REUSEPORT_CBPF 共 %d 次，期望 %d 次（每条启用 TCP 的规则一次，UDP 组不挂）：%+v", len(attach), len(groups), attach)
			}
			for i, g := range groups {
				c := attach[i]
				fds := listenFDs(m.pid(), g.proto, portOf(g.listen))
				switch {
				case c.tid != m.pid():
					t.Errorf("第 %d 次挂载（%s %s）来自线程 %d，期望主线程 %d", i+1, g.proto, g.listen, c.tid, m.pid())
				case !slices.Contains(fds, c.fd):
					t.Errorf("第 %d 次挂载在 fd %d 上，期望 %s %s 的监听之一 %v", i+1, c.fd, g.proto, g.listen, fds)
				case c.err != nil:
					t.Errorf("第 %d 次挂载的程序读不出：%v", i+1, c.err)
				case !slices.Equal(c.prog, want):
					t.Errorf("第 %d 次挂载（%s %s）的程序 %+v，期望 %+v", i+1, g.proto, g.listen, c.prog, want)
				}
			}
			expectWorkerPins(t, m, pins, n)
			expectForwarding(t, ls)
			m.statsAfterSignal(t) // 统计写完即 fflush：启动时的日志行都已在文件里
			if k := m.logLines("[WARN]"); k != 0 {
				t.Errorf("日志里有 %d 行 warn：\n%s", k, m.logTail(20))
			}
		})
	}
	t.Run("threads1", func(t *testing.T) {
		t.Parallel()
		cfg, ls, wait := affinityRules(t)
		a := &affinityCalls{}
		m := start(t, a, wait, "-c", cfg, "--threads", "1", "--cpu-affinity")
		expectPinned(t, m, 2, pinnedEach(cpus[:1]), cpus)
		expectForwarding(t, ls)
		attach, pins := a.snapshot()
		if len(attach) != 0 {
			t.Errorf("--threads 1 时 SO_ATTACH_REUSEPORT_CBPF 有 %d 次，期望 0 次（没有 reuseport 组，A6）", len(attach))
		}
		expectWorkerPins(t, m, pins, 1)
	})
	t.Run("off", func(t *testing.T) {
		t.Parallel()
		if os.Getenv("TPM_AFFINITY") == "1" {
			t.Skip("TPM_AFFINITY=1：所有启动都带 --cpu-affinity")
		}
		needCPUs(t, 2)
		cfg, ls, wait := affinityRules(t)
		a := &affinityCalls{}
		m := start(t, a, wait, "-c", cfg, "--threads", "2")
		expectPinned(t, m, 3, unpinned(2, cpus), cpus)
		expectForwarding(t, ls)
		if attach, pins := a.snapshot(); len(attach) != 0 || len(pins) != 0 {
			t.Errorf("没给 --cpu-affinity：SO_ATTACH_REUSEPORT_CBPF %d 次、sched_setaffinity %d 次，期望都是 0", len(attach), len(pins))
		}
	})
	t.Run("attach-fail", func(t *testing.T) {
		t.Parallel()
		needCPUs(t, 2)
		cfg, ls, wait := affinityRules(t)
		a := &affinityCalls{fail: map[uint32]syscall.Errno{syscall.SYS_SETSOCKOPT: syscall.EINVAL}}
		m := start(t, a, wait, "-c", cfg, "--threads", "2", "--cpu-affinity", "--log-level", "5")
		expectPinned(t, m, 3, pinnedEach(cpus[:2]), cpus)
		expectForwarding(t, ls)
		failed := fmt.Sprintf("setsockopt SO_ATTACH_REUSEPORT_CBPF failed (%d:", int(syscall.EINVAL))
		const hint = "steering by cpu needs Linux 4.6 or later, new connections are spread by hash"
		eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
			for _, l := range []struct{ level, rule string }{{"[WARN]", "rule 1 [tcp] "}, {"[DEBUG]", "rule 2 [tcp] "}} {
				if k := m.logLines(l.level, l.rule+failed, hint); k != 1 {
					return fmt.Errorf("%s %s%s…%s 有 %d 行，期望 1 行", l.level, l.rule, failed, hint, k)
				}
			}
			if k, w := m.logLines(failed), m.logLines("[WARN]", failed); k != 2 || w != 1 {
				return fmt.Errorf("挂载失败的日志共 %d 行（warn %d 行），期望 2 行（第一次 warn、之后 debug；UDP 组不挂，没有 [udp] 行）", k, w)
			}
			return nil
		})
		expectHashed(t, fmt.Sprintf("挂载失败时 worker 0 的 CPU %d 上的 64 条连接", cpus[0]), spread(t, m, "tcp", cpus[0], ls[0], 64), 64)
	})
	t.Run("pin-fail", func(t *testing.T) {
		t.Parallel()
		needCPUs(t, 2)
		cfg, ls, wait := affinityRules(t)
		a := &affinityCalls{fail: map[uint32]syscall.Errno{syscall.SYS_SCHED_SETAFFINITY: syscall.EINVAL}}
		m := start(t, a, wait, "-c", cfg, "--threads", "2", "--cpu-affinity")
		expectPinned(t, m, 3, unpinned(2, cpus), cpus)
		expectAffinityInfo(t, m, cpus[:2])
		expectForwarding(t, ls)
		eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
			for k := range 2 {
				line := fmt.Sprintf("worker %d: sched_setaffinity to cpu %d failed, %d:", k, cpus[k], int(syscall.EINVAL))
				if n := m.logLines("[WARN]", line, ", running unpinned"); n != 1 {
					return fmt.Errorf("warn %q…running unpinned 有 %d 行，期望 1 行", line, n)
				}
			}
			if n := m.logLines("sched_setaffinity"); n != 2 {
				return fmt.Errorf("含 sched_setaffinity 的日志有 %d 行，期望 2 行", n)
			}
			return nil
		})
		_, pins := a.snapshot()
		expectWorkerPins(t, m, pins, 2)
		expectAllOn(t, fmt.Sprintf("绑核失败时 worker 1 的 CPU %d 上的 64 条连接", cpus[1]), spread(t, m, "tcp", cpus[1], ls[0], 64), 1, 64)
	})
	t.Run("getaffinity-fail", func(t *testing.T) {
		t.Parallel()
		a := &affinityCalls{fail: map[uint32]syscall.Errno{syscall.SYS_SCHED_GETAFFINITY: syscall.EINVAL}}
		m := start(t, a, nil, "-l", loopback4(t), "-r", loopback4(t), "-t", "--threads", "2", "--cpu-affinity")
		select {
		case <-m.done:
		case <-time.After(5 * time.Second):
			t.Fatal("sched_getaffinity 失败后 5 s 内没有退出")
		}
		m.stop(t, true)
		if m.exitErr == nil {
			t.Error("sched_getaffinity 失败后以状态 0 退出，期望非零")
		}
		if line := fmt.Sprintf("--cpu-affinity: sched_getaffinity failed, %d:", int(syscall.EINVAL)); m.logLines("[FATAL]", line) != 1 {
			t.Errorf("日志里没有恰好一行 fatal %q：\n%s", line, m.logTail(10))
		}
	})
}
