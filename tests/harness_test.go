// tinymapper 功能测试的公共设施：进程管理、端口分配、就绪检测、预期失败（XFAIL）与用例分级。
//
// 环境变量：
//
//	TINYMAPPER_BIN    被测 tinymapper 可执行文件（必填）
//	TPM_SLOW=1        运行耗时超过约 60 s 的用例（TCP/UDP 空闲超时、TCP 上游建连超时）
//	TPM_IN_CONTAINER=1 允许修改 /etc/hosts 的用例运行，并要求测试进程有 CAP_NET_ADMIN（needNetAdmin）（只应由 tests/run.sh 在容器中设置）
//	TPM_VARIANT       被测构建的 libc（glibc 或 musl），用于只在某一变体上预期失败的已知缺陷
package tests

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var (
	mapperBin string
	nextPort  atomic.Int32
	// 重负载用例（大流量、数千连接）互斥执行，避免在 6 vCPU 的 VM 上相互挤占
	heavySem = make(chan struct{}, 1)
)

func TestMain(m *testing.M) {
	if spec := os.Getenv(epollAddFailEnv); spec != "" {
		execEpollAddFail(spec)
	}
	if os.Getenv(noNetAdminEnv) != "" {
		execNoNetAdmin()
	}
	mapperBin = os.Getenv("TINYMAPPER_BIN")
	if mapperBin == "" || runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "需要在 Linux 上运行并设置 TINYMAPPER_BIN；在开发机上请用 tests/run.sh")
		os.Exit(2)
	}
	nextPort.Store(20000)
	os.Exit(m.Run())
}

func slow(t testing.TB) {
	t.Helper()
	if os.Getenv("TPM_SLOW") != "1" {
		t.Skip("慢速用例，设置 TPM_SLOW=1 运行")
	}
}

func inContainer(t testing.TB) {
	t.Helper()
	if os.Getenv("TPM_IN_CONTAINER") != "1" {
		t.Skip("会修改 /etc/hosts，只在容器中运行（TPM_IN_CONTAINER=1）")
	}
}

// heavy 须在 t.Parallel() 之后调用，用例结束时自动释放
func heavy(t testing.TB) {
	heavySem <- struct{}{}
	t.Cleanup(func() { <-heavySem })
}

var ephemeralRange = sync.OnceValues(func() (int, int) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		var lo, hi int
		if _, err := fmt.Sscan(string(data), &lo, &hi); err == nil {
			return lo, hi
		}
	}
	return 32768, 60999
})

// freePort 返回本进程内不重复、当前 TCP/UDP 均空闲的端口。
// 避开内核临时端口范围，防止与出站连接的源端口冲突。
func freePort(t testing.TB) int {
	t.Helper()
	lo, hi := ephemeralRange()
	for {
		p := int(nextPort.Add(1))
		if p > 65535 {
			t.Fatal("可用端口已分配完")
		}
		if p >= lo && p <= hi {
			continue
		}
		if portFree(p) {
			return p
		}
	}
}

// portFree 试绑定 TCP 与 UDP 端口 p。全程持有 ForkLock 读锁：否则并发启动的子进程会在
// fork 与 exec 之间继承探测 socket，使端口在 Close 之后仍被占用片刻（实测导致 EADDRINUSE）。
func portFree(p int) bool {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
	if err != nil {
		return false
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
	if err != nil {
		return false
	}
	pc.Close()
	return true
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// listenPoint 是等待 tinymapper 就绪时要检查的监听：proto 为 "tcp" 或 "udp"
type listenPoint struct {
	proto string
	port  int
}

type mapper struct {
	cmd     *exec.Cmd
	logPath string
	done    chan struct{}
	exitErr error
	stopped sync.Once
	groOff  bool // U5：--udp-gro 因第一个监听 socket 开不了 UDP_GRO 而整体关闭，统计行不带 GRO 计数（statsAfterSignal 据此核对）
}

// startMapper 启动 tinymapper，等待 wait 中的监听全部就绪；测试结束时自动停止。
func startMapper(t testing.TB, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	return startMapperLimit(t, 0, wait, args...)
}

// startMapperLimit 同 startMapper；nofile>0 时以 `ulimit -n nofile` 启动。
func startMapperLimit(t testing.TB, nofile int, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	argv := append([]string{"--disable-color"}, args...)
	cmd := exec.Command(mapperBin, argv...)
	if nofile > 0 {
		script := fmt.Sprintf(`ulimit -n %d && exec "$0" "$@"`, nofile)
		cmd = exec.Command("sh", append([]string{"-c", script, mapperBin}, argv...)...)
	}
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}

// runMapper 启动已设好输出的 cmd（其输出最终落到 logPath），等待 wait 中的监听全部就绪；测试结束时自动停止。
func runMapper(t testing.TB, cmd *exec.Cmd, logPath string, wait []listenPoint) *mapper {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 tinymapper 失败：%v", err)
	}
	m := &mapper{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() { m.exitErr = cmd.Wait(); close(m.done) }()
	t.Cleanup(func() { m.stop(t, false) })
	m.waitListen(t, wait)
	return m
}

// C9 故障注入：startMapperEpollAddFail 以环境变量 epollAddFailEnv="lo hi" 重新执行测试二进制自身，TestMain 见到它就不跑测试，
// 改由 execEpollAddFail 在当前线程上装 seccomp 过滤器后 exec tinymapper：fd 在 [lo, hi) 内的 epoll_ctl(EPOLL_CTL_ADD)
// 返回 ENOSPC，其他系统调用不受影响。真实的 ENOSPC（达到 fs.epoll.max_user_watches）也是 ep_insert 在插入前返回，没有副作用，
// 与过滤器直接返回错误一致；libev 的 epoll_modify 对 ENOENT/EEXIST/EPERM 以外的 errno 调 fd_kill（停掉该 fd 的 watcher 并
// 喂 EV_ERROR）。T13 起新 fd 一律直接 ADD（libev fd_reify 本地补丁），不再先 MOD 得到 ENOENT。过滤器让区间内的每个 ADD 都返回
// ENOSPC，包括内核本会返回 EEXIST 的已登记 fd：将来若有代码对区间内仍已登记的 fd 重新 ev_io_set，这里会出现 EV_ERROR，生产环境
// 则是 EEXIST 加 MOD（目前没有这样的调用点）。prctl 设的 no_new_privs 与 seccomp 过滤器都只作用于
// 调用线程、并由 execve 保留，所以锁定线程后在同一线程上 exec；不需要特权，对静态链接的 tinymapper 同样有效。
// 测试二进制的 fd 都带 O_CLOEXEC，exec 后 tinymapper 的 fd 布局与直接启动相同（0–2 之外从 3 起依次分配）
const epollAddFailEnv = "TPM_EPOLL_ADD_FAIL"

// seccomp_data.arch 的取值（AUDIT_ARCH_*）；其他架构上故障注入用例跳过
var auditArch = map[string]uint32{"amd64": 0xc000003e, "arm64": 0xc00000b7}

// epollAddFailFilter 返回 BPF 程序：arch 相符、nr 为 epoll_ctl、args[1] 为 EPOLL_CTL_ADD、lo ≤ args[2] < hi 时返回
// SECCOMP_RET_ERRNO|ENOSPC，否则 SECCOMP_RET_ALLOW。参数按 32 位比较，取 u64 的低半部分（只支持小端架构）
func epollAddFailFilter(arch, lo, hi uint32) []syscall.SockFilter {
	const (
		ld   = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS
		jeq  = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		jge  = syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K
		ret  = syscall.BPF_RET | syscall.BPF_K
		nr   = 0      // struct seccomp_data：int nr; u32 arch; u64 instruction_pointer; u64 args[6]
		arg1 = 16 + 8 // args[1]：op
		arg2 = 16 + 16
		add  = 1 // EPOLL_CTL_ADD
	)
	stmt := func(code uint16, k uint32) syscall.SockFilter { return syscall.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) syscall.SockFilter {
		return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	// 跳转偏移相对下一条指令；第 10 条为放行
	return []syscall.SockFilter{
		stmt(ld, 4),
		jump(jeq, arch, 0, 8),
		stmt(ld, nr),
		jump(jeq, uint32(syscall.SYS_EPOLL_CTL), 0, 6),
		stmt(ld, arg1),
		jump(jeq, add, 0, 4),
		stmt(ld, arg2),
		jump(jge, lo, 0, 2),
		jump(jge, hi, 1, 0),
		stmt(ret, 0x00050000|uint32(syscall.ENOSPC)), // SECCOMP_RET_ERRNO
		stmt(ret, 0x7fff0000),                        // SECCOMP_RET_ALLOW
	}
}

// execEpollAddFail 在重新执行的测试二进制里运行：os.Args[1:] 是 tinymapper 的 argv。成功时不返回
func execEpollAddFail(spec string) {
	const (
		prSetSeccomp      = 22
		prSetNoNewPrivs   = 38
		seccompModeFilter = 2
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "故障注入启动失败："+format+"\n", a...)
		os.Exit(127)
	}
	var lo, hi uint32
	if _, err := fmt.Sscan(spec, &lo, &hi); err != nil || len(os.Args) < 2 {
		fail("%s=%q 或参数 %q 无效", epollAddFailEnv, spec, os.Args)
	}
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		fail("不支持 %s", runtime.GOARCH)
	}
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		fail("prctl(PR_SET_NO_NEW_PRIVS)：%v", e)
	}
	filter := epollAddFailFilter(arch, lo, hi)
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); e != 0 {
		fail("prctl(PR_SET_SECCOMP)：%v", e)
	}
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	fail("exec %s：%v", os.Args[1], err)
}

// startMapperEpollAddFail 同 startMapper，但 tinymapper 里 fd 在 [lo, hi) 内的 epoll_ctl(EPOLL_CTL_ADD) 都返回 ENOSPC；
// hi 为 0 表示不设上限
func startMapperEpollAddFail(t testing.TB, lo, hi int, wait []listenPoint, args ...string) *mapper {
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
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d %d", epollAddFailEnv, lo, hi))
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}

// U6：tinymapper 有 CAP_NET_ADMIN 时用 SO_SNDBUFFORCE/SO_RCVBUFFORCE 设 UDP socket 缓冲。tests/run.sh 给容器加了这项能力，以 root
// 运行的测试进程直接启动的 tinymapper 也有。startMapperNoNetAdmin 以环境变量 noNetAdminEnv 重新执行测试二进制自身，TestMain 见到它
// 就不跑测试，改由 execNoNetAdmin 在当前线程上把 CAP_NET_ADMIN 从 bounding 集与 inheritable 集里去掉后 exec tinymapper：root 执行
// 没有文件能力的程序时，新的 permitted、effective 集为 inheritable ∪ bounding，所以 tinymapper 仍以 root 运行、只少这一项能力（与
// 默认能力集的 Docker 容器里以 root 运行相同）。不改用 uid 65534（SysProcAttr.Credential）：uid 不同时读 /proc/<pid>/fd 的链接要过
// ptrace_may_access，Docker 默认能力集里没有 CAP_SYS_PTRACE，listening、lookupSockBuf 都认不出 tinymapper 的 socket；同为 root 时
// 测试进程的 permitted 集是 tinymapper 的超集（cap_ptrace_access_check），照常可读。bounding 集与 capset 都只作用于调用线程，所以
// 锁定线程后在同一线程上 exec
const noNetAdminEnv = "TPM_NO_NET_ADMIN"

const capNetAdmin = 12 // CAP_NET_ADMIN 在能力位图中的位号

// execNoNetAdmin 在重新执行的测试二进制里运行：os.Args[1:] 是 tinymapper 的 argv。成功时不返回
func execNoNetAdmin() {
	const (
		prCapbsetDrop = 24         // PR_CAPBSET_DROP
		capVersion3   = 0x20080522 // _LINUX_CAPABILITY_VERSION_3
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "去掉 CAP_NET_ADMIN 启动失败："+format+"\n", a...)
		os.Exit(127)
	}
	if len(os.Args) < 2 {
		fail("参数 %q 无效", os.Args)
	}
	runtime.LockOSThread()
	// 非 root 没有 CAP_SETPCAP，返回 EPERM；非 root 执行没有文件能力的程序本来就得不到能力，由 startMapperNoNetAdmin 核对 CapEff
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prCapbsetDrop, capNetAdmin, 0); e != 0 && os.Getuid() == 0 {
		fail("prctl(PR_CAPBSET_DROP)：%v", e)
	}
	hdr := struct {
		version uint32
		pid     int32
	}{capVersion3, 0}
	var data [2]struct{ effective, permitted, inheritable uint32 } // data[0] 为能力 0–31
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		fail("capget：%v", e)
	}
	data[0].inheritable &^= 1 << capNetAdmin // ambient 集随之去掉这一位（内核保证 ambient ⊆ permitted ∩ inheritable）
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		fail("capset：%v", e)
	}
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	fail("exec %s：%v", os.Args[1], err)
}

// startMapperNoNetAdmin 同 startMapper，但 tinymapper 没有 CAP_NET_ADMIN；wait 中的监听就绪时已 exec 成 tinymapper，随即核对它的 CapEff
func startMapperNoNetAdmin(t testing.TB, wait []listenPoint, args ...string) *mapper {
	t.Helper()
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
	cmd.Env = append(os.Environ(), noNetAdminEnv+"=1")
	cmd.Stdout, cmd.Stderr = f, f
	m := runMapper(t, cmd, logPath, wait)
	if hasNetAdmin(t, m.pid()) {
		t.Fatalf("tinymapper（pid %d）仍有 CAP_NET_ADMIN（CapEff=%#x）", m.pid(), capEff(t, m.pid()))
	}
	return m
}

// capEff 返回进程 pid 的有效能力集（/proc/<pid>/status 的 CapEff，十六进制位图；任何进程都可读，不经 ptrace 检查）
func capEff(t testing.TB, pid int) uint64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			c, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("/proc/%d/status 的 CapEff 无法解析：%q", pid, line)
			}
			return c
		}
	}
	t.Fatalf("/proc/%d/status 中没有 CapEff", pid)
	return 0
}

func hasNetAdmin(t testing.TB, pid int) bool {
	t.Helper()
	return capEff(t, pid)&(1<<capNetAdmin) != 0
}

// needNetAdmin 用于要求 tinymapper 有 CAP_NET_ADMIN 的用例：测试进程没有这项能力时，容器中（TPM_IN_CONTAINER=1）判为失败
// （tests/run.sh 应以 --cap-add NET_ADMIN 启动容器），否则跳过
func needNetAdmin(t testing.TB) {
	t.Helper()
	if hasNetAdmin(t, os.Getpid()) {
		return
	}
	if os.Getenv("TPM_IN_CONTAINER") == "1" {
		t.Fatalf("测试进程没有 CAP_NET_ADMIN（CapEff=%#x）：tests/run.sh 应以 --cap-add NET_ADMIN 启动容器", capEff(t, os.Getpid()))
	}
	t.Skip("测试进程没有 CAP_NET_ADMIN（在容器中以 root 运行时由 tests/run.sh 的 --cap-add NET_ADMIN 提供），跳过")
}

// startupFDs 不注入故障启动一次 tinymapper，返回它就绪后打开的 fd 数 n，并要求这些 fd 恰好是 0..n-1：
// 新 fd 总取最小的空闲号，之后的连接依次拿到 n、n+1……
func startupFDs(t testing.TB, wait []listenPoint, args ...string) int {
	t.Helper()
	probe := startMapper(t, wait, args...)
	defer probe.stop(t, false)
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", probe.pid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if fd, _ := strconv.Atoi(e.Name()); fd >= len(ents) {
			t.Fatalf("tinymapper 启动后的 fd 不连续：共 %d 个，却有 fd %d", len(ents), fd)
		}
	}
	return len(ents)
}

// forward 用命令行启动单规则 tinymapper：proto 含 't' 启用 TCP、含 'u' 启用 UDP
func forward(t testing.TB, proto, listen string, remotes ...string) *mapper {
	t.Helper()
	args := []string{"-l", listen}
	for _, r := range remotes {
		args = append(args, "-r", r)
	}
	return startMapper(t, listenPoints(proto, portOf(listen)), append(args, protoFlags(proto)...)...)
}

func protoFlags(proto string) []string {
	var flags []string
	if strings.Contains(proto, "t") {
		flags = append(flags, "-t")
	}
	if strings.Contains(proto, "u") {
		flags = append(flags, "-u")
	}
	return flags
}

func listenPoints(proto string, port int) []listenPoint {
	var lps []listenPoint
	if strings.Contains(proto, "t") {
		lps = append(lps, listenPoint{"tcp", port})
	}
	if strings.Contains(proto, "u") {
		lps = append(lps, listenPoint{"udp", port})
	}
	return lps
}

func (m *mapper) pid() int { return m.cmd.Process.Pid }

func (m *mapper) exited() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// fatalIfExited 在 tinymapper 已退出时让用例失败，stop 随后附上日志末尾（assert、ASan 报告等都写在这里）
func (m *mapper) fatalIfExited(t testing.TB, format string, a ...any) {
	t.Helper()
	if m.exited() {
		t.Errorf(format+" tinymapper 退出：%v", append(a, m.exitErr)...)
		m.stop(t, true)
		t.FailNow()
	}
}

// aliveAfter 等待 d 后返回进程是否仍在运行
func (m *mapper) aliveAfter(d time.Duration) bool {
	select {
	case <-m.done:
		return false
	case <-time.After(d):
		return true
	}
}

// stop 结束进程；expectExited=false 时，若进程在此之前已自行退出则判为失败。
func (m *mapper) stop(t testing.TB, expectExited bool) {
	m.stopped.Do(func() {
		if m.exited() {
			if !expectExited {
				t.Errorf("tinymapper 在测试期间意外退出：%v", m.exitErr)
			}
		} else {
			m.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-m.done:
			case <-time.After(3 * time.Second):
				m.cmd.Process.Kill()
				<-m.done
			}
		}
		if t.Failed() {
			t.Logf("tinymapper 日志末尾（%s）：\n%s", m.logPath, m.logTail(40))
		}
	})
}

func (m *mapper) logTail(n int) string {
	data, _ := os.ReadFile(m.logPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// logLines 返回日志中同时包含全部 substrs 的行数
func (m *mapper) logLines(substrs ...string) int {
	data, _ := os.ReadFile(m.logPath)
	n := 0
next:
	for _, line := range strings.Split(string(data), "\n") {
		for _, s := range substrs {
			if !strings.Contains(line, s) {
				continue next
			}
		}
		n++
	}
	return n
}

func (m *mapper) waitListen(t testing.TB, wait []listenPoint) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := true
		for _, lp := range wait {
			if !listening(m.pid(), lp.proto, lp.port) {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		select {
		case <-m.done:
			t.Fatalf("tinymapper 启动后立即退出：%v\n%s", m.exitErr, m.logTail(20))
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待 tinymapper 监听 %v 就绪超时\n%s", wait, m.logTail(20))
		}
	}
}

// socketInodes 返回进程打开的全部 socket inode
func socketInodes(pid int) map[string]bool {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, _ := os.ReadDir(dir)
	set := make(map[string]bool, len(ents))
	for _, e := range ents {
		link, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") {
			set[link[len("socket:["):len(link)-1]] = true
		}
	}
	return set
}

// sockBuf 是一个 socket 的 inode、缓冲上限 sk_rcvbuf / sk_sndbuf（即 getsockopt SO_RCVBUF / SO_SNDBUF 的返回值），
// 以及 inet_diag_msg 的 idiag_rqueue / idiag_wqueue：TCP 监听 socket 上为 accept 队列的当前长度 sk_ack_backlog 与上限
// sk_max_ack_backlog（tcp_diag_get_info），UDP socket 上 rqueue 为接收队列中各包 truesize 之和；drops 为 sk_drops
// （UDP 接收队列满时丢弃的包数）
type sockBuf struct{ inode, rcv, snd, rqueue, wqueue, drops uint32 }

func (b sockBuf) String() string {
	return fmt.Sprintf("rcvbuf=%d sndbuf=%d（inode %d）", b.rcv, b.snd, b.inode)
}

// sockDiag 用 NETLINK_SOCK_DIAG 按地址查找一个 IPv4 或 IPv6 TCP/UDP socket，返回其 inode、idiag_rqueue / idiag_wqueue 与
// INET_DIAG_SKMEMINFO 中的 SK_MEMINFO_RCVBUF / SK_MEMINFO_SNDBUF / SK_MEMINFO_DROPS。请求不带 NLM_F_DUMP，内核只按四元组查一次哈希表
// （inet_diag_find_one_icsk、udp_dump_one），不遍历全部 socket，不受并行用例里数万个 socket 的影响。local、remote 是该
// socket 的本端与对端地址，监听 socket 的 remote 为 0.0.0.0:0（IPv6 为 [::]:0）
func sockDiag(proto int, local, remote string) (sockBuf, error) {
	const (
		netlinkSockDiag   = 4  // NETLINK_SOCK_DIAG
		sockDiagByFamily  = 20 // SOCK_DIAG_BY_FAMILY
		inetDiagSkmeminfo = 7  // INET_DIAG_SKMEMINFO：u32 数组，下标 1 为 RCVBUF，3 为 SNDBUF，8 为 DROPS
		inetDiagMsgLen    = 72 // struct inet_diag_msg，idiag_rqueue、idiag_wqueue、idiag_inode 在偏移 56、60、68
	)
	src, err := netip.ParseAddrPort(local)
	if err != nil {
		return sockBuf{}, err
	}
	dst, err := netip.ParseAddrPort(remote)
	if err != nil {
		return sockBuf{}, err
	}
	family := syscall.AF_INET
	switch {
	case src.Addr().Is4() && dst.Addr().Is4():
	case src.Addr().Is6() && dst.Addr().Is6():
		family = syscall.AF_INET6
	default:
		return sockBuf{}, fmt.Errorf("本端与对端的地址族不同：%s → %s", local, remote)
	}
	if proto == syscall.IPPROTO_UDP {
		src, dst = dst, src // udp_dump_one 按收包方向查找，idiag_src 填对端（内核注释：src and dst are swapped for historical reasons）
	}
	ne := binary.NativeEndian
	req := make([]byte, syscall.NLMSG_HDRLEN+56) // nlmsghdr + struct inet_diag_req_v2
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], sockDiagByFamily)
	ne.PutUint16(req[6:], syscall.NLM_F_REQUEST)
	r := req[syscall.NLMSG_HDRLEN:]
	r[0], r[1], r[2] = byte(family), byte(proto), 1<<(inetDiagSkmeminfo-1)
	ne.PutUint32(r[4:], ^uint32(0)) // idiag_states：全部状态
	binary.BigEndian.PutUint16(r[8:], src.Port())
	binary.BigEndian.PutUint16(r[10:], dst.Port())
	copy(r[12:], src.Addr().AsSlice()) // idiag_src[4]、idiag_dst[4]：IPv4 只占第一个字
	copy(r[28:], dst.Addr().AsSlice())
	ne.PutUint64(r[48:], ^uint64(0)) // idiag_cookie 为 INET_DIAG_NOCOOKIE：不核对 cookie

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return sockBuf{}, err
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(int64(ioTimeout))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return sockBuf{}, err
	}
	buf := make([]byte, 1<<16)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return sockBuf{}, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return sockBuf{}, err
	}
	for _, m := range msgs {
		switch {
		case m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4:
			return sockBuf{}, syscall.Errno(-int32(ne.Uint32(m.Data)))
		case m.Header.Type == sockDiagByFamily && len(m.Data) >= inetDiagMsgLen:
			inode := ne.Uint32(m.Data[68:])
			for a := m.Data[inetDiagMsgLen:]; len(a) >= 4; {
				l, typ := int(ne.Uint16(a)), ne.Uint16(a[2:])
				if l < 4 || l > len(a) {
					break
				}
				if typ == inetDiagSkmeminfo && l >= 4+16 {
					b := sockBuf{inode: inode, rcv: ne.Uint32(a[8:]), snd: ne.Uint32(a[16:]),
						rqueue: ne.Uint32(m.Data[56:]), wqueue: ne.Uint32(m.Data[60:])}
					if l >= 4+36 {
						b.drops = ne.Uint32(a[36:])
					}
					return b, nil
				}
				a = a[min((l+3)&^3, len(a)):]
			}
			return sockBuf{}, errors.New("应答中没有 INET_DIAG_SKMEMINFO")
		}
	}
	return sockBuf{}, errors.New("应答中没有 socket 信息")
}

// lookupSockBuf 用 sockDiag 查找 name 所指的 socket，并要求它是进程 owner 打开的
func lookupSockBuf(t testing.TB, owner, proto int, name, local, remote string) sockBuf {
	t.Helper()
	b, err := sockDiag(proto, local, remote)
	if err != nil {
		t.Fatalf("sock_diag 查找%s（%s → %s）失败：%v", name, local, remote, err)
	}
	if !socketInodes(owner)[strconv.FormatUint(uint64(b.inode), 10)] {
		t.Fatalf("查到的%s（%s → %s，inode %d）不是进程 %d 的 socket", name, local, remote, b.inode, owner)
	}
	return b
}

// sockDiagDump 用 NETLINK_SOCK_DIAG 的 dump 请求列出 family（AF_INET 或 AF_INET6）中协议为 proto、状态在 states 位图里的 socket，
// 对每个 socket 调 f(本端端口, 对端端口, inode)。请求不带端口过滤，由调用方筛选（udp_dump 按主机字节序比较端口，与 TCP 不一致）。
// 只请求 LISTEN 状态时 inet_diag_dump_icsk 只遍历监听哈希表、不碰已建立连接的 ehash；其他状态在内核里逐个比较状态，只回符合的
// socket，不像 /proc/net/tcp 那样把每个连接都格式化成文本；UDP 只遍历 UDP 哈希表
func sockDiagDump(family, proto int, states uint32, f func(sport, dport uint16, inode uint32)) error {
	const (
		netlinkSockDiag  = 4  // NETLINK_SOCK_DIAG
		sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY
		inetDiagMsgLen   = 72 // struct inet_diag_msg：idiag_sport、idiag_dport 在偏移 4、6（网络字节序），idiag_inode 在偏移 68
	)
	ne := binary.NativeEndian
	req := make([]byte, syscall.NLMSG_HDRLEN+56) // nlmsghdr + struct inet_diag_req_v2
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], sockDiagByFamily)
	ne.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	r := req[syscall.NLMSG_HDRLEN:]
	r[0], r[1] = byte(family), byte(proto)
	ne.PutUint32(r[4:], states)

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(int64(ioTimeout))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch {
			case m.Header.Type == syscall.NLMSG_DONE:
				return nil
			case m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4:
				return syscall.Errno(-int32(ne.Uint32(m.Data)))
			case m.Header.Type == sockDiagByFamily && len(m.Data) >= inetDiagMsgLen:
				f(binary.BigEndian.Uint16(m.Data[4:]), binary.BigEndian.Uint16(m.Data[6:]), ne.Uint32(m.Data[68:]))
			}
		}
	}
}

// listening 判断进程 pid 是否已在 port 上监听 proto（IPv4 或 IPv6）。
func listening(pid int, proto string, port int) bool { return listenFD(pid, proto, port) >= 0 }

// listenFD 返回进程 pid 在 port 上监听 proto 的 socket 的 fd 号，没有则返回 -1：TCP 为 LISTEN 状态，UDP 为未连接的 socket
// （TCP_CLOSE，即 /proc/net/udp 的 st=07），IPv4、IPv6 都算。原来每次整表读 /proc/net/{tcp,tcp6}：与 TestTCPMaxConn 并行时
// 两张表各有约 8 万行，读一遍要数秒，waitListen 的 10 s 里只试得了几次，就绪超时（两份套件并行时 27 次全量里 10 次）。
// 改用 sockDiagDump 只列监听 socket，耗时与系统里已建立的连接数无关
func listenFD(pid int, proto string, port int) int {
	ipproto, states := syscall.IPPROTO_TCP, uint32(1)<<10 // TCP_LISTEN
	if proto == "udp" {
		ipproto, states = syscall.IPPROTO_UDP, uint32(1)<<7 // TCP_CLOSE
	}
	inodes := map[string]bool{}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		sockDiagDump(family, ipproto, states, func(p, _ uint16, inode uint32) {
			if int(p) == port {
				inodes[strconv.FormatUint(uint64(inode), 10)] = true
			}
		})
	}
	if len(inodes) == 0 {
		return -1
	}
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		link, _ := os.Readlink(filepath.Join(dir, e.Name()))
		if inode, ok := strings.CutPrefix(link, "socket:["); ok && inodes[strings.TrimSuffix(inode, "]")] {
			fd, _ := strconv.Atoi(e.Name())
			return fd
		}
	}
	return -1
}

// portHolders 列出 /proc/net/{tcp,tcp6,udp,udp6} 中本地端口为 port 的 socket 及持有它的进程，用于诊断 EADDRINUSE：
// freePort 按代码不会重复分配，但全量运行中出现过一次两个用例同时 bind 失败，原因未查明
func portHolders(port int) string {
	owners := map[string][]string{}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		for ino := range socketInodes(pid) {
			owners[ino] = append(owners[ino], fmt.Sprintf("%d(%s)", pid, strings.TrimSpace(string(comm))))
		}
	}
	var out []string
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, _ := os.ReadFile("/proc/net/" + name)
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 10 && strings.HasSuffix(f[1], fmt.Sprintf(":%04X", port)) {
				out = append(out, fmt.Sprintf("%s %s->%s st=%s inode=%s %v", name, f[1], f[2], f[3], f[9], owners[f[9]]))
			}
		}
	}
	if len(out) == 0 {
		return "无"
	}
	return strings.Join(out, "；")
}

func fdCount(t testing.TB, pid int) int {
	t.Helper()
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// cpuTicks 返回进程累计的 utime+stime（单位：时钟滴答，Linux 上为 1/100 s）
func (m *mapper) cpuTicks(t testing.TB) int64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", m.pid()))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:]) // f[0] 是第 3 个字段 state
	utime, _ := strconv.ParseInt(f[11], 10, 64)
	stime, _ := strconv.ParseInt(f[12], 10, 64)
	return utime + stime
}

// expectIdleCPU 的采样窗口与上限：时钟滴答为 1/100 s，1 s 内超过 10 个即 CPU 占用 >10%。状态静止时正确实现接近 0，
// 负载下全量运行实测最多 0.01 s；空转的变异在 4 份全量套件并行时实测 0.24–1.00 s（空转只分到 CPU 的一部分）
const (
	idleCPUWindow   = time.Second
	idleCPUMaxTicks = 10
)

// expectIdleCPU 在 tinymapper 无事可做的状态下采样它 idleCPUWindow 内消耗的 CPU 时间，超过上限即失败。量的是进程自己的
// utime+stime：并行负载只会拉长墙钟，不会把空闲进程的 CPU 时间推高。用于 tcp_cb 去掉某个事件位之后的状态：去位时漏掉
// ev_io_stop/ev_io_start，w->events 已去位，epoll 里的掩码却还留着这一位，fd 一直就绪，libev 的 fd_event 把事件过滤掉，
// 功能上看不出来，唯一的后果是事件循环空转（build/t13/tests-report.md §4）。state 说明当前状态与对应的切换点
func (m *mapper) expectIdleCPU(t testing.TB, state string) {
	t.Helper()
	m.fatalIfExited(t, "%s：", state)
	ticks0 := m.cpuTicks(t)
	time.Sleep(idleCPUWindow)
	ticks := m.cpuTicks(t) - ticks0
	t.Logf("%s：%v 内 tinymapper 消耗 CPU %.2f s", state, idleCPUWindow, float64(ticks)/100)
	if ticks > idleCPUMaxTicks {
		t.Errorf("%s：tinymapper 空转，%v 内消耗 CPU %.2f s（上限 %.2f s）：去掉的事件位没有经 ev_io_stop/ev_io_start 更新到 epoll",
			state, idleCPUWindow, float64(ticks)/100, float64(idleCPUMaxTicks)/100)
	}
}

// syscw 返回进程累计的 write 类系统调用次数（/proc/<pid>/io 的 syscw：write、writev、pwrite 等，不含 send、sendto）
func (m *mapper) syscw(t testing.TB) int {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", m.pid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "syscw:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatalf("/proc/%d/io 的 syscw 无法解析：%q", m.pid(), line)
			}
			return n
		}
	}
	t.Fatalf("/proc/%d/io 中没有 syscw：\n%s", m.pid(), data)
	return 0
}

// pause 向 tinymapper 发送 SIGSTOP 并等到它停下（kill 返回时目标进程未必已停下），测试结束时自动 SIGCONT
func (m *mapper) pause(t testing.TB) {
	t.Helper()
	m.cmd.Process.Signal(syscall.SIGSTOP)
	t.Cleanup(func() { m.cmd.Process.Signal(syscall.SIGCONT) })
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", m.pid()))
		if err != nil {
			return err
		}
		s := string(data)
		if st := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])[0]; st != "T" {
			return fmt.Errorf("tinymapper 状态为 %s，SIGSTOP 尚未生效", st)
		}
		return nil
	})
}

// runExpectFail 运行 tinymapper 并期望它以非零状态退出，返回其输出
func runExpectFail(t testing.TB, timeout time.Duration, args ...string) string {
	t.Helper()
	cmd := exec.Command(mapperBin, append([]string{"--disable-color"}, args...)...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("tinymapper 以状态 0 退出，期望拒绝该配置：\n%s", out.String())
		}
	case <-time.After(timeout):
		cmd.Process.Kill()
		<-done
		t.Fatalf("tinymapper 在 %v 内未退出，期望拒绝该配置：\n%s", timeout, out.String())
	}
	return out.String()
}

// eventually 每隔 interval 重试 f，直到成功或超过 within
func eventually(t testing.TB, within, interval time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%v 内未达成：%v", within, err)
		}
		time.Sleep(interval)
	}
}

// xfailT 在已知缺陷用例中代替 testing.T：记录失败而不让外层测试失败
type xfailT struct {
	testing.TB
	mu      sync.Mutex
	failed  bool
	skipped bool
	msgs    []string
}

func (r *xfailT) record(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.msgs = append(r.msgs, strings.TrimSpace(s))
}

func (r *xfailT) Fail()                          { r.record("") }
func (r *xfailT) FailNow()                       { r.record(""); runtime.Goexit() }
func (r *xfailT) Error(args ...any)              { r.record(fmt.Sprintln(args...)) }
func (r *xfailT) Errorf(format string, a ...any) { r.record(fmt.Sprintf(format, a...)) }
func (r *xfailT) Fatal(args ...any)              { r.Error(args...); runtime.Goexit() }
func (r *xfailT) Fatalf(format string, a ...any) { r.Errorf(format, a...); runtime.Goexit() }
func (r *xfailT) Skip(args ...any)               { r.Helper(); r.Log(args...); r.SkipNow() }
func (r *xfailT) Skipf(format string, a ...any)  { r.Helper(); r.Logf(format, a...); r.SkipNow() }
func (r *xfailT) SkipNow()                       { r.mu.Lock(); r.skipped = true; r.mu.Unlock(); runtime.Goexit() }
func (r *xfailT) Skipped() bool                  { r.mu.Lock(); defer r.mu.Unlock(); return r.skipped }
func (r *xfailT) Failed() bool                   { r.mu.Lock(); defer r.mu.Unlock(); return r.failed }

// xfail 运行已知缺陷 id 的用例体，body 断言的是正确行为：
// body 失败时本测试通过并记录 "XFAIL id"；body 意外通过时本测试失败，提醒删除标记。
func xfail(t *testing.T, id string, body func(t testing.TB)) {
	t.Helper()
	r := &xfailT{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		body(r)
	}()
	<-done
	switch {
	case r.Skipped():
		t.SkipNow()
	case r.Failed():
		var msgs []string
		for _, s := range r.msgs {
			if s != "" {
				msgs = append(msgs, s)
			}
		}
		t.Logf("XFAIL %s：%s", id, strings.Join(msgs, "；"))
	default:
		t.Errorf("XPASS %s：已知缺陷 %s 的用例意外通过；若已修复，请删除该用例的 xfail 标记", id, id)
	}
}
