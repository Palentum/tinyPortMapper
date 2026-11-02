// 通配 UDP 监听回包源地址（D87–D91）的测试设施：在 lo 上加删 IPv6 地址、读出回包源地址的客户端、回退日志行的核对，以及两种故障注入：
// seccomp 过滤器让 setsockopt(IP_PKTINFO / IPV6_RECVPKTINFO) 返回 ENOPROTOOPT；seccomp 用户态通知让 tinymapper 的 sendto、sendmsg、
// sendmmsg 交给测试决定照常执行还是失败（notify_test.go 的过滤器不通知 sendmmsg，而 UDP 两个方向都用它发）。
package tests

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	// pktinfoFallbackPhrase 是回包带着记下的本地地址发送失败、去掉源地址重发时那行日志（D90）里固定的部分：每条规则第一次写 info，之后 debug
	pktinfoFallbackPhrase = "letting the kernel choose the source address"
	// pktinfoSetFailPhrase 是监听 socket 开不了 IP_PKTINFO / IPV6_RECVPKTINFO 时每条规则一行 warn 里固定的部分（该规则照旧由内核选源）
	pktinfoSetFailPhrase = "replies go out from the address the kernel chooses"
)

// ---- lo 上的 IPv6 地址 ----

const siocDIFAddr = 0x8936 // SIOCDIFADDR

// lo6Seq 给每次 newLoAddrs6 分配不重复的前缀（用例并行）：第 k 次的地址为 fd00:7470:k::1、::2……
var lo6Seq atomic.Int32

// setLoAddr6 用 AF_INET6 socket 上的 SIOCSIFADDR / SIOCDIFADDR（struct in6_ifreq）在 lo 上加或删 a/128
func setLoAddr6(add bool, a netip.Addr) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	s, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	var r [24]byte // struct in6_ifreq：ifr6_addr[16]、u32 ifr6_prefixlen、int ifr6_ifindex
	a16 := a.As16()
	copy(r[:16], a16[:])
	binary.NativeEndian.PutUint32(r[16:], 128)
	binary.NativeEndian.PutUint32(r[20:], uint32(lo.Index))
	req := uintptr(siocSIFAddr)
	if !add {
		req = siocDIFAddr
	}
	return ioctl(s, req, unsafe.Pointer(&r[0]))
}

// waitLoAddr6 等到 a 可用：lo 不做 DAD，但去掉 tentative、装上本机路由要等 addrconf 的工作队列，之前 bind 报 EADDRNOTAVAIL、发往它的包
// 没有路由。绑定 a 的 UDP socket 发给自己、收得到就算可用
func waitLoAddr6(t testing.TB, a netip.Addr) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		c, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, 0)))
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.WriteToUDPAddrPort([]byte("probe"), c.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			return err
		}
		_, _, err = c.ReadFromUDPAddrPort(make([]byte, 16))
		return err
	})
}

// newLoAddrs6 在 lo 上加 n 个本用例专用的 /128 地址，等到都可用后返回；用例结束时删掉。加删地址要 CAP_NET_ADMIN（needNetAdmin）
func newLoAddrs6(t testing.TB, n int) []netip.Addr {
	t.Helper()
	needNetAdmin(t)
	k := lo6Seq.Add(1)
	addrs := make([]netip.Addr, n)
	for i := range addrs {
		addrs[i] = netip.AddrFrom16([16]byte{0xfd, 0x00, 0x74, 0x70, byte(k >> 8), byte(k), 15: byte(i + 1)})
		if err := setLoAddr6(true, addrs[i]); err != nil {
			t.Fatalf("在 lo 上加 %s/128 失败：%v", addrs[i], err)
		}
		t.Cleanup(func() { setLoAddr6(false, addrs[i]) }) // 用例里已经删掉的再删报 EADDRNOTAVAIL，忽略
		waitLoAddr6(t, addrs[i])
	}
	return addrs
}

// lo6Sub 在 lo 上加 n 个 IPv6 地址（n 为 0 时不加），返回把字符串里的 "$1"……"$n" 换成这些地址的函数
func lo6Sub(t testing.TB, n int) func(string) string {
	t.Helper()
	if n == 0 {
		return func(s string) string { return s }
	}
	var pairs []string
	for i, a := range newLoAddrs6(t, n) {
		pairs = append(pairs, fmt.Sprintf("$%d", i+1), a.String())
	}
	return strings.NewReplacer(pairs...).Replace
}

// ---- 看得到回包源地址的客户端 ----

// unmapped 把 v4 映射地址换成 IPv4（双栈 socket 收发 IPv4 包时地址是 ::ffff:a.b.c.d）
func unmapped(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// srcClient 返回绑定 local（端口由内核选）、没有 connect 的 UDP socket：发往 tinymapper 的哪个本机地址由每次发送决定，读回包时看得到源地址
func srcClient(t testing.TB, local string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(local)})
	if err != nil {
		t.Fatalf("客户端绑定 %s 失败：%v", local, err)
	}
	c.SetReadBuffer(1 << 20)
	t.Cleanup(func() { c.Close() })
	return c
}

// sendTo 返回从 c 向 to 发一个包的函数（helloSession 的 send 参数）
func sendTo(c *net.UDPConn, to netip.AddrPort) func([]byte) error {
	return func(b []byte) error { _, err := c.WriteToUDPAddrPort(b, to); return err }
}

// readReply 从 c 读一个回包，返回内容与源地址（v4 映射转成 IPv4）
func readReply(t testing.TB, c *net.UDPConn, who string) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 70000)
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("%s读回包：%v", who, err)
	}
	return buf[:n], unmapped(from)
}

// expectFrom 从 c 依次读回包，要求与 want 逐字节相同、顺序相同，且都来自 from（v4 映射地址按 IPv4 比较）
func expectFrom(t testing.TB, c *net.UDPConn, want [][]byte, from netip.AddrPort, who string) {
	t.Helper()
	for j, w := range want {
		got, src := readReply(t, c, fmt.Sprintf("%s第 %d 个（期望 %q，来自 %s）：", who, j, w[:min(len(w), 16)], from))
		if !bytes.Equal(got, w) {
			t.Fatalf("%s的第 %d 个回包为 %q，期望 %q", who, j, got[:min(len(got), 16)], w[:min(len(w), 16)])
		}
		if src != unmapped(from) {
			t.Errorf("%s的第 %d 个回包 %q 来自 %s，期望来自 %s", who, j, w[:min(len(w), 16)], src, from)
		}
	}
}

// expectGROFrom 同 groClient.expect（消息内容、段长、顺序都要相同），但回包必须来自 from
func expectGROFrom(t testing.TB, c *net.UDPConn, want []groMsg, from netip.AddrPort, who string) {
	t.Helper()
	buf := make([]byte, 70000)
	for j, w := range want {
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		n, gso, src, err := readGRO(c, buf)
		if err != nil {
			t.Fatalf("%s的第 %d 个消息（期望 %v）：%v", who, j, w, err)
		}
		if got := (groMsg{buf[:n], gso}); !msgsEqual([]groMsg{got}, []groMsg{w}) {
			t.Fatalf("%s的第 %d 个消息为 [%v]，期望 [%v]", who, j, got, w)
		}
		if src = unmapped(src); src != unmapped(from) {
			t.Errorf("%s的第 %d 个消息来自 %s，期望来自 %s", who, j, src, from)
		}
	}
}

// echoVia 经 c 发 msg 并等后端（recordUDP）的回显，返回回显的源地址（v4 映射转成 IPv4）。to 有效时 c 没有 connect、发往 to；否则 c 已
// connect，内核只收从 connect 的地址发来的包，收到回显就说明回包的源地址就是客户端发往的地址。内容不同的包是之前重发引来的迟到回包，
// 跳过；环回偶有丢包，1 s 没有回显就重发，共 4 次（命中既有会话，不新建）
func echoVia(c *net.UDPConn, to netip.AddrPort, msg []byte) (netip.AddrPort, error) {
	buf := make([]byte, 70000)
	for range 4 {
		var err error
		if to.IsValid() {
			_, err = c.WriteToUDPAddrPort(msg, to)
		} else {
			_, err = c.Write(msg)
		}
		if err != nil {
			return netip.AddrPort{}, err
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if isTimeout(err) {
				break
			}
			if err != nil {
				return netip.AddrPort{}, err
			}
			if bytes.Equal(buf[:n], msg) {
				return unmapped(from), nil
			}
		}
	}
	return netip.AddrPort{}, fmt.Errorf("%q 发了 4 次，每次 1 s 内都没有回显", msg)
}

// sessionOf 等到后端 be 收到内容为 msg 的包，返回它的源地址（tinymapper 为这个客户端建的会话 socket 的地址）
func sessionOf(t testing.TB, be *udpRecorder, msg []byte) string {
	t.Helper()
	var src string
	eventually(t, ioTimeout, 2*time.Millisecond, func() error {
		if src = be.sourceOf(msg); src == "" {
			return fmt.Errorf("后端还没收到 %q", msg)
		}
		return nil
	})
	return src
}

// setBroadcast 在 c 上开 SO_BROADCAST（发往广播地址要它，否则 EACCES）
func setBroadcast(t testing.TB, c *net.UDPConn) {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1) }); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatalf("SO_BROADCAST：%v", serr)
	}
}

// ---- 日志 ----

// phraseLines 返回日志里含 phrase 的行（统计输出时已 fflush，调用前先 statsAfterSignal）
func phraseLines(m *mapper, phrase string) []string {
	data, _ := os.ReadFile(m.logPath)
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.Contains(l, phrase) {
			out = append(out, l)
		}
	}
	return out
}

// expectFallbackLog 要求日志里 D90 的回退行恰好有 info 行是 [INFO]（每条规则第一次），其余都是 [DEBUG]（--log-level 5 才看得到），
// 返回回退行的总数。调用前先 statsAfterSignal
func expectFallbackLog(t testing.TB, m *mapper, info int) int {
	t.Helper()
	var lines []string
	infos := func() int {
		n := 0
		for _, l := range lines {
			if strings.Contains(l, "[INFO]") {
				n++
			}
		}
		return n
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if lines = phraseLines(m, pktinfoFallbackPhrase); infos() < info {
			return fmt.Errorf("日志里有 %d 行 info 级的源地址回退行（%q），期望 %d", infos(), pktinfoFallbackPhrase, info)
		}
		return nil
	})
	if n := infos(); n != info {
		t.Errorf("日志里有 %d 行 info 级的源地址回退行，期望 %d（每条规则只有第一次写 info，之后 debug）：\n%s", n, info, strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if !strings.Contains(l, "[INFO]") && !strings.Contains(l, "[DEBUG]") {
			t.Errorf("源地址回退行的级别不是 info 或 debug：%q", l)
		}
	}
	return len(lines)
}

// ---- seccomp setsockopt(IP_PKTINFO / IPV6_RECVPKTINFO) 故障注入 ----
//
// TPM_PKTINFO_FAIL="lo hi" 存在时，init() 在重新执行的测试二进制里装 seccomp 过滤器后 exec tinymapper：fd 在 [lo, hi) 内的
// setsockopt(fd, SOL_IP, IP_PKTINFO, ...) 与 setsockopt(fd, SOL_IPV6, IPV6_RECVPKTINFO, ...) 返回 ENOPROTOOPT，其他系统调用不受影响。
// 与 TPM_GRO_FAIL 同一套路，各认各的环境变量
const pktinfoFailEnv = "TPM_PKTINFO_FAIL"

func init() {
	if spec := os.Getenv(pktinfoFailEnv); spec != "" {
		execPktinfoFail(spec)
	}
}

// pktinfoFailFilter 返回 BPF 程序：arch 相符、nr 为 setsockopt、(level, optname) 为 (SOL_IP, IP_PKTINFO) 或 (SOL_IPV6, IPV6_RECVPKTINFO)、
// lo ≤ args[0] < hi 时返回 SECCOMP_RET_ERRNO|ENOPROTOOPT，否则放行。只支持小端架构（参数取 u64 的低 32 位）
func pktinfoFailFilter(arch, lo, hi uint32) []syscall.SockFilter {
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
	// 跳转偏移相对下一条指令；索引 15 为放行
	return []syscall.SockFilter{
		stmt(ld, 4),            // 0：arch
		jump(jeq, arch, 0, 13), // 1
		stmt(ld, nr),           // 2
		jump(jeq, uint32(syscall.SYS_SETSOCKOPT), 0, 11), // 3
		stmt(ld, arg1),                                    // 4：level
		jump(jeq, syscall.SOL_IP, 0, 2),                   // 5：不是 SOL_IP → 8
		stmt(ld, arg2),                                    // 6：optname
		jump(jeq, syscall.IP_PKTINFO, 3, 7),               // 7：IP_PKTINFO → 11，否则放行
		jump(jeq, syscall.SOL_IPV6, 0, 6),                 // 8：A 仍是 level；不是 SOL_IPV6 → 放行
		stmt(ld, arg2),                                    // 9：optname
		jump(jeq, syscall.IPV6_RECVPKTINFO, 0, 4),         // 10：不是 → 放行
		stmt(ld, arg0),                                    // 11：fd
		jump(jge, lo, 0, 2),                               // 12：fd<lo → 放行
		jump(jge, hi, 1, 0),                               // 13：fd≥hi → 放行
		stmt(ret, 0x00050000|uint32(syscall.ENOPROTOOPT)), // 14：SECCOMP_RET_ERRNO|ENOPROTOOPT
		stmt(ret, 0x7fff0000),                             // 15：SECCOMP_RET_ALLOW
	}
}

// execPktinfoFail 在重新执行的测试二进制里运行：os.Args[1:] 是 tinymapper 的 argv。成功时不返回
func execPktinfoFail(spec string) {
	const (
		prSetSeccomp      = 22
		prSetNoNewPrivs   = 38
		seccompModeFilter = 2
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "PKTINFO 故障注入启动失败："+format+"\n", a...)
		os.Exit(127)
	}
	var lo, hi uint32
	if _, err := fmt.Sscan(spec, &lo, &hi); err != nil || len(os.Args) < 2 {
		fail("%s=%q 或参数 %q 无效", pktinfoFailEnv, spec, os.Args)
	}
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		fail("不支持 %s", runtime.GOARCH)
	}
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		fail("prctl(PR_SET_NO_NEW_PRIVS)：%v", e)
	}
	filter := pktinfoFailFilter(arch, lo, hi)
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); e != 0 {
		fail("prctl(PR_SET_SECCOMP)：%v", e)
	}
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	fail("exec %s：%v", os.Args[1], err)
}

// startMapperPktinfoFail 同 startMapper，但 tinymapper 里 fd 在 [lo, hi) 内的 setsockopt(SOL_IP, IP_PKTINFO) 与
// setsockopt(SOL_IPV6, IPV6_RECVPKTINFO) 返回 ENOPROTOOPT；hi 为 0 表示不设上限
func startMapperPktinfoFail(t testing.TB, lo, hi int, wait []listenPoint, args ...string) *mapper {
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
	cmd := exec.Command(self, append([]string{mapperBin}, mapperArgv(args...)...)...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d %d", pktinfoFailEnv, lo, hi))
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}

// ---- seccomp 用户态通知：只通知发送调用 ----
//
// 同 notify_test.go 的 startMapperNotify（共用 notifier 与它的 loop），但过滤器只通知 sendto、sendmsg、sendmmsg：那边的过滤器不通知
// sendmmsg，而 UDP 入向（U3）与回程（U4）都直接调 sendmmsg 系统调用。用例经 setDecide 让某次发送以选定的 errno 失败（D90：带 PKTINFO 的
// 回包只失败一次）。环境变量 sendNotifyEnv 与 notifyEnv 各认各的
const sendNotifyEnv = "TPM_SEND_NOTIFY"

func init() {
	if os.Getenv(sendNotifyEnv) != "" {
		execSendNotify()
	}
}

// isSendNR 判断被通知的调用是不是 sendto、sendmsg、sendmmsg
func isSendNR(nr uint32) bool {
	return nr == uint32(syscall.SYS_SENDTO) || nr == uint32(syscall.SYS_SENDMSG) || nr == sendmmsgNR[runtime.GOARCH]
}

// sendNotifyFilter 返回 BPF 程序：arch 相符、nr 为 sendto/sendmsg/sendmmsg、fd（args[0] 低 32 位）不是 3 时通知，否则放行。
// fd 3 放行的原因同 notifyFilter：execSendNotify 装好过滤器之后经 fd 3 交出监听 fd
func sendNotifyFilter(arch uint32) []syscall.SockFilter {
	const (
		ld   = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS
		jeq  = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		ret  = syscall.BPF_RET | syscall.BPF_K
		nr   = 0
		arg0 = 16 + 0
	)
	stmt := func(code uint16, k uint32) syscall.SockFilter { return syscall.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) syscall.SockFilter {
		return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	// 跳转偏移相对下一条指令；索引 9 为放行
	return []syscall.SockFilter{
		stmt(ld, 4),           // 0：arch
		jump(jeq, arch, 0, 7), // 1：不匹配 → 放行
		stmt(ld, nr),          // 2：nr
		jump(jeq, uint32(syscall.SYS_SENDTO), 2, 0),  // 3：sendto → 6
		jump(jeq, uint32(syscall.SYS_SENDMSG), 1, 0), // 4：sendmsg → 6
		jump(jeq, sendmmsgNR[runtime.GOARCH], 0, 3),  // 5：都不是 → 放行
		stmt(ld, arg0),                 // 6：fd
		jump(jeq, 3, 1, 0),             // 7：fd 3 → 放行
		stmt(ret, seccompRetUserNotif), // 8
		stmt(ret, seccompRetAllow),     // 9
	}
}

// execSendNotify 同 execNotify，过滤器换成 sendNotifyFilter。成功时不返回
func execSendNotify() {
	const (
		prSetNoNewPrivs      = 38
		seccompSetModeFilter = 1
		notifyParentSocketFD = 3
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "seccomp 发送通知启动失败："+format+"\n", a...)
		os.Exit(127)
	}
	if len(os.Args) < 2 {
		fail("参数 %q 无效", os.Args)
	}
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		fail("不支持 %s", runtime.GOARCH)
	}
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		fail("prctl(PR_SET_NO_NEW_PRIVS)：%v", e)
	}
	filter := sendNotifyFilter(arch)
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	lfd, _, e := syscall.RawSyscall(seccompNR[runtime.GOARCH], seccompSetModeFilter, seccompFlagNewListener|seccompFlagWaitKillableRecv,
		uintptr(unsafe.Pointer(&prog)))
	if e == syscall.EINVAL { // 5.19 以前没有这个标志
		lfd, _, e = syscall.RawSyscall(seccompNR[runtime.GOARCH], seccompSetModeFilter, seccompFlagNewListener, uintptr(unsafe.Pointer(&prog)))
	}
	if e != 0 {
		fail("seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER)：%v", e)
	}
	if err := syscall.Sendmsg(notifyParentSocketFD, []byte{0}, syscall.UnixRights(int(lfd)), nil, 0); err != nil {
		fail("把监听 fd 交给测试进程：%v", err)
	}
	syscall.Close(notifyParentSocketFD)
	syscall.Close(int(lfd))
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	fail("exec %s：%v", os.Args[1], err)
}

// startMapperSendNotify 同 startMapperNotify，但经 notifier 的只有 tinymapper 的 sendto、sendmsg、sendmmsg（初值全部照常执行）
func startMapperSendNotify(t testing.TB, wait []listenPoint, args ...string) (*mapper, *notifier) {
	t.Helper()
	if _, ok := seccompNR[runtime.GOARCH]; !ok {
		t.Skipf("seccomp 通知只支持 amd64、arm64，当前为 %s", runtime.GOARCH)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	child := os.NewFile(uintptr(pair[1]), "notify-child")
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(self, append([]string{mapperBin}, mapperArgv(args...)...)...)
	cmd.Env = append(os.Environ(), sendNotifyEnv+"=1")
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdout, cmd.Stderr = f, f
	err = startCmd(cmd, nil)
	child.Close()
	if err != nil {
		syscall.Close(pair[0])
		t.Fatalf("启动 tinymapper 失败：%v", err)
	}
	m := &mapper{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() { m.exitErr = cmd.Wait(); close(m.done) }()
	t.Cleanup(func() { m.stop(t, false) })
	tv := syscall.NsecToTimeval(int64(ioTimeout))
	syscall.SetsockoptTimeval(pair[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	buf, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	var oobn int
	for {
		_, oobn, _, _, err = syscall.Recvmsg(pair[0], buf, oob, syscall.MSG_CMSG_CLOEXEC)
		if err != syscall.EINTR {
			break
		}
	}
	syscall.Close(pair[0])
	if err != nil {
		t.Fatalf("没有收到 seccomp 监听 fd：%v\n%s", err, m.logTail(10))
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("解析 SCM_RIGHTS 失败：%v（%d 条）", err, len(msgs))
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("解析 SCM_RIGHTS 失败：%v（%v）", err, fds)
	}
	n := &notifier{fd: fds[0], gone: make(chan struct{})}
	go n.loop()
	m.waitListen(t, wait)
	return m, n
}
