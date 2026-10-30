// seccomp 用户态通知（SECCOMP_RET_USER_NOTIF 5.0 起，SECCOMP_USER_NOTIF_FLAG_CONTINUE 5.5 起）：tinymapper 的每次 sendto、sendmsg、splice
// 都先停在内核里，交给测试进程里的 notifier 决定照常执行（CONTINUE）还是直接返回某个 errno。与 TPM_SENDTO_FAIL 这类无状态的过滤器不同，
// 它能在运行中途开始、停止注入，并按 fd、按 splice 的方向（读进 pipe 还是从 pipe 写出）区分，用于 D50（写分支 EAGAIN 继续等可写）与
// 审查 L1（splice 不可用时整个进程改走拷贝）；epoll 等待也经过它，测试能按事件循环的轮次给调用分组（D53）。
//
// 做法同 TPM_EPOLL_ADD_FAIL：startMapperNotify 以环境变量 notifyEnv 重新执行测试二进制自身，init() 见到它就不跑测试，改由 execNotify 在当前线程上
// 设 no_new_privs、以 SECCOMP_FILTER_FLAG_NEW_LISTENER 装过滤器得到监听 fd，经 fd 3（与测试进程相连的 unix socket，ExtraFiles）用 SCM_RIGHTS
// 交给测试进程，关掉 fd 3 后 exec tinymapper：过滤器只作用于调用线程并由 execve 保留，监听 fd 带 O_CLOEXEC 不会留给 tinymapper，tinymapper 的
// fd 布局与直接启动相同。交监听 fd 的那次 sendmsg 也会被过滤，所以过滤器对 fd 3 上的 sendto、sendmsg 放行（tinymapper 不会在 fd 3 上发送：
// 那是它的 epoll/eventfd/监听 socket 之一）。notifier 的协程用 epoll 等监听 fd：有通知时 EPOLLIN，tinymapper 退出、过滤器不再有使用者时 EPOLLHUP。
// 被通知的系统调用在 notifier 回应之前一直阻塞，所以 decide 必须很快返回
package tests

import (
	"encoding/binary"
	"fmt"
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

const notifyEnv = "TPM_SECCOMP_NOTIFY"

func init() {
	if os.Getenv(notifyEnv) != "" {
		execNotify()
	}
}

// seccomp 的系统调用号：syscall 包的 amd64 表里没有 SYS_SECCOMP
var seccompNR = map[string]uintptr{"amd64": 317, "arm64": 277}

const (
	seccompRetUserNotif    = 0x7fc00000
	seccompRetAllow        = 0x7fff0000
	seccompNotifRecv       = 0xc0502100 // SECCOMP_IOCTL_NOTIF_RECV = _IOWR('!', 0, struct seccomp_notif)（80 字节）
	seccompNotifSend       = 0xc0182101 // SECCOMP_IOCTL_NOTIF_SEND = _IOWR('!', 1, struct seccomp_notif_resp)（24 字节）
	seccompNotifContinue   = 1          // SECCOMP_USER_NOTIF_FLAG_CONTINUE
	seccompFlagNewListener = 1 << 3     // SECCOMP_FILTER_FLAG_NEW_LISTENER
)

// epollWaitNR：事件循环的 epoll 等待（arm64 上 libev 的 epoll_wait 经 libc 走 epoll_pwait），测试据此把调用按事件循环的轮次分组
// （D53：一次回调里 splice 的轮数）
var epollWaitNR = map[string][]uint32{
	"arm64": {uint32(syscall.SYS_EPOLL_PWAIT), 441},      // 441：epoll_pwait2
	"amd64": {232, uint32(syscall.SYS_EPOLL_PWAIT), 441}, // 232：epoll_wait
}

// notifyAlways 返回每次都通知的系统调用：splice、getsockopt（D54 的用例假造 SO_SNDBUF）与 epoll 等待
func notifyAlways() []uint32 {
	return append([]uint32{uint32(syscall.SYS_SPLICE), uint32(syscall.SYS_GETSOCKOPT)}, epollWaitNR[runtime.GOARCH]...)
}

// isEpollWait 判断被通知的调用是不是事件循环的 epoll 等待
func isEpollWait(nr uint32) bool {
	for _, n := range epollWaitNR[runtime.GOARCH] {
		if nr == n {
			return true
		}
	}
	return false
}

// notifyFilter 返回 BPF 程序：arch 相符时 notifyAlways() 里的调用一律通知；sendto、sendmsg 的 fd（args[0] 低 32 位）不是 3 时通知；其余放行
func notifyFilter(arch uint32) []syscall.SockFilter {
	const (
		ld   = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS
		jeq  = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		ret  = syscall.BPF_RET | syscall.BPF_K
		nr   = 0      // struct seccomp_data：int nr; u32 arch; u64 ip; u64 args[6]
		arg0 = 16 + 0 // args[0]
	)
	always := notifyAlways()
	// 布局：0 arch，1 比较 arch，2 nr，3.. 每个 always 一条，然后 sendto、sendmsg、取 fd、比较 fd、通知、放行
	notif := uint8(3 + len(always) + 4)
	allow := notif + 1
	prog := []syscall.SockFilter{
		{Code: ld, K: 4},
		{Code: jeq, K: arch, Jf: allow - 2},
		{Code: ld, K: nr},
	}
	for _, n := range always {
		pc := uint8(len(prog))
		prog = append(prog, syscall.SockFilter{Code: jeq, K: n, Jt: notif - pc - 1})
	}
	pc := uint8(len(prog))
	prog = append(prog,
		syscall.SockFilter{Code: jeq, K: uint32(syscall.SYS_SENDTO), Jt: 1},               // sendto → 取 fd
		syscall.SockFilter{Code: jeq, K: uint32(syscall.SYS_SENDMSG), Jf: allow - pc - 2}, // 都不是 → 放行
		syscall.SockFilter{Code: ld, K: arg0},
		syscall.SockFilter{Code: jeq, K: 3, Jt: 1}, // fd 3 → 放行
		syscall.SockFilter{Code: ret, K: seccompRetUserNotif},
		syscall.SockFilter{Code: ret, K: seccompRetAllow},
	)
	return prog
}

// execNotify 在重新执行的测试二进制里运行：os.Args[1:] 是 tinymapper 的 argv，fd 3 是交监听 fd 用的 unix socket。成功时不返回
func execNotify() {
	const (
		prSetNoNewPrivs      = 38
		seccompSetModeFilter = 1
		notifyParentSocketFD = 3
	)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "seccomp 通知启动失败："+format+"\n", a...)
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
	filter := notifyFilter(arch)
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	lfd, _, e := syscall.RawSyscall(seccompNR[runtime.GOARCH], seccompSetModeFilter, seccompFlagNewListener, uintptr(unsafe.Pointer(&prog)))
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

// notifyCall 是一次被通知的系统调用；pid 是调用线程在测试进程的 pid 命名空间里的号
type notifyCall struct {
	pid  int
	nr   uint32
	args [6]uint64
}

func (c notifyCall) fd(i int) int { return int(int32(c.args[i])) }

// notifier 回应 tinymapper 的被通知调用：先问 emulate，它返回 ok 时这次调用不执行、直接以 val 返回（输出参数由 emulate 经
// writeTargetMem 写好）；否则 decide 返回 0 表示照常执行，返回 errno 则以它失败
type notifier struct {
	fd      int
	emulate atomic.Pointer[func(notifyCall) (int64, bool)]
	decide  atomic.Pointer[func(notifyCall) syscall.Errno]
	calls   atomic.Int64 // 收到的通知数
}

func (n *notifier) setDecide(f func(notifyCall) syscall.Errno) { n.decide.Store(&f) }

func (n *notifier) setEmulate(f func(notifyCall) (int64, bool)) { n.emulate.Store(&f) }

// writeTargetMem 把 b 写进进程 pid 地址 addr 处（/proc/<pid>/mem：要求对它有 PTRACE_MODE_ATTACH 权限，tinymapper 是测试进程的子进程、
// 同为 root，Yama ptrace_scope=1 也允许）
func writeTargetMem(pid int, addr uint64, b []byte) error {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt(b, int64(addr))
	return err
}

func (n *notifier) loop() {
	defer syscall.Close(n.fd)
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return
	}
	defer syscall.Close(ep)
	if err := syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, n.fd, &syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(n.fd)}); err != nil {
		return
	}
	events := make([]syscall.EpollEvent, 1)
	ne := binary.NativeEndian
	for {
		k, err := syscall.EpollWait(ep, events, 1000)
		if err == syscall.EINTR || k == 0 {
			continue
		}
		if err != nil || events[0].Events&(syscall.EPOLLHUP|syscall.EPOLLERR) != 0 {
			return // tinymapper 已退出
		}
		var req [80]byte // struct seccomp_notif：u64 id; u32 pid; u32 flags; struct seccomp_data（nr、arch、ip、args[6]）；RECV 要求清零
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(n.fd), seccompNotifRecv, uintptr(unsafe.Pointer(&req[0]))); e != 0 {
			if e == syscall.EINTR || e == syscall.ENOENT {
				continue
			}
			return
		}
		n.calls.Add(1)
		c := notifyCall{pid: int(ne.Uint32(req[8:])), nr: ne.Uint32(req[16:])}
		for i := range c.args {
			c.args[i] = ne.Uint64(req[32+8*i:])
		}
		var resp [24]byte // struct seccomp_notif_resp：u64 id; s64 val; s32 error; u32 flags
		copy(resp[0:8], req[0:8])
		var errno syscall.Errno
		emulated := false
		if f := n.emulate.Load(); f != nil {
			var val int64
			if val, emulated = (*f)(c); emulated {
				ne.PutUint64(resp[8:], uint64(val))
			}
		}
		if !emulated {
			if f := n.decide.Load(); f != nil {
				errno = (*f)(c)
			}
			if errno == 0 {
				ne.PutUint32(resp[20:], seccompNotifContinue)
			} else {
				ne.PutUint32(resp[16:], uint32(-int32(errno)))
			}
		}
		// 调用方已被杀时 ENOENT，忽略；EINTR 必须重发，否则这次调用一直停在内核里
		for {
			if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(n.fd), seccompNotifSend, uintptr(unsafe.Pointer(&resp[0]))); e != syscall.EINTR {
				break
			}
		}
	}
}

// startMapperNotify 同 startMapper，但 tinymapper 的 sendto、sendmsg、splice、getsockopt 与 epoll 等待都经 notifier（初值全部照常执行）
func startMapperNotify(t testing.TB, wait []listenPoint, args ...string) (*mapper, *notifier) {
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
	cmd := exec.Command(self, append([]string{mapperBin, "--disable-color"}, args...)...)
	cmd.Env = append(os.Environ(), notifyEnv+"=1")
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdout, cmd.Stderr = f, f
	err = cmd.Start()
	child.Close()
	if err != nil {
		syscall.Close(pair[0])
		t.Fatalf("启动 tinymapper 失败：%v", err)
	}
	m := &mapper{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() { m.exitErr = cmd.Wait(); close(m.done) }()
	t.Cleanup(func() { m.stop(t, false) })
	// 收监听 fd（SO_RCVTIMEO 防止子进程启动失败时一直等）
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
	n := &notifier{fd: fds[0]}
	go n.loop()
	m.waitListen(t, wait)
	return m, n
}

// isSocketFD 判断进程 pid 的 fd 是不是 socket（notifier 用来区分 splice 读进 pipe 与从 pipe 写出：读进时 args[0] 是 socket）
func isSocketFD(pid, fd int) bool {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	return err == nil && strings.HasPrefix(link, "socket:[")
}

// fdOfSocket 返回进程 pid 里指向 socket inode 的 fd 号（sock_diag 查到的 inode → /proc/<pid>/fd），找不到返回 -1
func fdOfSocket(pid int, inode uint32) int {
	want := fmt.Sprintf("socket:[%d]", inode)
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if link, _ := os.Readlink(filepath.Join(dir, e.Name())); link == want {
			var fd int
			fmt.Sscan(e.Name(), &fd)
			return fd
		}
	}
	return -1
}

// waitCount 等到 c 至少为 n
func waitCount(t testing.TB, c *atomic.Int64, n int64, within time.Duration, what string) {
	t.Helper()
	eventually(t, within, 5*time.Millisecond, func() error {
		if v := c.Load(); v < n {
			return fmt.Errorf("%s只有 %d 次，期望至少 %d 次", what, v, n)
		}
		return nil
	})
}
