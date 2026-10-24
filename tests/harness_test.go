// tinymapper 功能测试的公共设施：进程管理、端口分配、就绪检测、预期失败（XFAIL）与用例分级。
//
// 环境变量：
//
//	TINYMAPPER_BIN    被测 tinymapper 可执行文件（必填）
//	TPM_SLOW=1        运行耗时超过约 60 s 的用例（TCP/UDP 空闲超时、TCP 上游建连超时）
//	TPM_IN_CONTAINER=1 允许修改 /etc/hosts 的用例运行（只应由 tests/run.sh 在容器中设置）
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
)

var (
	mapperBin string
	nextPort  atomic.Int32
	// 重负载用例（大流量、数千连接）互斥执行，避免在 6 vCPU 的 VM 上相互挤占
	heavySem = make(chan struct{}, 1)
)

func TestMain(m *testing.M) {
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
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 tinymapper 失败：%v", err)
	}
	m := &mapper{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() { m.exitErr = cmd.Wait(); close(m.done) }()
	t.Cleanup(func() { m.stop(t, false) })
	m.waitListen(t, wait)
	return m
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
// sk_max_ack_backlog（tcp_diag_get_info）
type sockBuf struct{ inode, rcv, snd, rqueue, wqueue uint32 }

func (b sockBuf) String() string {
	return fmt.Sprintf("rcvbuf=%d sndbuf=%d（inode %d）", b.rcv, b.snd, b.inode)
}

// sockDiag 用 NETLINK_SOCK_DIAG 按地址查找一个 IPv4 TCP/UDP socket，返回其 inode、idiag_rqueue / idiag_wqueue 与
// INET_DIAG_SKMEMINFO 中的 SK_MEMINFO_RCVBUF / SK_MEMINFO_SNDBUF。请求不带 NLM_F_DUMP，内核只按四元组查一次哈希表
// （inet_diag_find_one_icsk、udp_dump_one），不遍历全部 socket，不受并行用例里数万个 socket 的影响。local、remote 是该
// socket 的本端与对端地址，监听 socket 的 remote 为 0.0.0.0:0
func sockDiag(proto int, local, remote string) (sockBuf, error) {
	const (
		netlinkSockDiag   = 4  // NETLINK_SOCK_DIAG
		sockDiagByFamily  = 20 // SOCK_DIAG_BY_FAMILY
		inetDiagSkmeminfo = 7  // INET_DIAG_SKMEMINFO：u32 数组，下标 1 为 RCVBUF，3 为 SNDBUF
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
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		return sockBuf{}, fmt.Errorf("只支持 IPv4 地址：%s → %s", local, remote)
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
	r[0], r[1], r[2] = syscall.AF_INET, byte(proto), 1<<(inetDiagSkmeminfo-1)
	ne.PutUint32(r[4:], ^uint32(0)) // idiag_states：全部状态
	binary.BigEndian.PutUint16(r[8:], src.Port())
	binary.BigEndian.PutUint16(r[10:], dst.Port())
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(r[12:], s4[:])
	copy(r[28:], d4[:])
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
					return sockBuf{inode: inode, rcv: ne.Uint32(a[8:]), snd: ne.Uint32(a[16:]),
						rqueue: ne.Uint32(m.Data[56:]), wqueue: ne.Uint32(m.Data[60:])}, nil
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

// listening 读取 /proc/net/{tcp,tcp6,udp,udp6}，判断进程 pid 是否已在 port 上监听 proto。
func listening(pid int, proto string, port int) bool {
	inodes := socketInodes(pid)
	state := "0A" // TCP_LISTEN
	if proto == "udp" {
		state = "07" // 未连接的 UDP socket
	}
	for _, name := range []string{proto, proto + "6"} {
		data, err := os.ReadFile("/proc/net/" + name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != state || !inodes[f[9]] {
				continue
			}
			local := f[1]
			p, err := strconv.ParseUint(local[strings.LastIndexByte(local, ':')+1:], 16, 16)
			if err == nil && int(p) == port {
				return true
			}
		}
	}
	return false
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
