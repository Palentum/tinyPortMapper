package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func writeConfig(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapper.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// udpRefused 判断 addr 上没有 UDP 监听（回 ICMP 端口不可达，loopback 不受 ICMP 限速影响）
func udpRefused(t testing.TB, addr string) bool {
	t.Helper()
	c := udpDial(t, "", addr)
	c.Write([]byte("probe"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 64))
	return errors.Is(err, syscall.ECONNREFUSED)
}

func tcpRefused(addr string) bool {
	_, err := net.DialTimeout("tcp", addr, 2*time.Second)
	return errors.Is(err, syscall.ECONNREFUSED)
}

// rrSequence 经 listen 顺序建立 n 个 TCP 连接，返回各自连到的后端序号
func rrSequence(t testing.TB, listen string, n int) []int {
	got := make([]int, n)
	for i := range got {
		c := dial(t, listen)
		fmt.Sscan(readLine(t, c), &got[i])
		c.Close()
	}
	return got
}

// sigtermExits 断言 tinymapper 收到 SIGTERM 后 2 s 内以状态 0 退出，且日志里有退出行。T6 起 stdout 是文件时日志攒在 stdio
// 缓冲里由 400 ms 的定时器刷新，防的是 myexit 的 _exit 丢掉缓冲中的行。conns>0 时 remote 须是 TCP 回显后端：先建一个连接并等
// 它的日志可见（缓冲为空），再依次建 conns 个连接后立即发送 SIGTERM，这些连接的日志多半还在缓冲中，退出后也必须全部在文件里。
// conns 个连接约 285·conns B，连同退出行要小于 musl 的 1024 B 缓冲，全程写不满：写满时缓冲连同新的一行一起写出，若恰好是
// 退出行写满，缓冲为空，去掉 myexit 的 fflush 也看不出来
func sigtermExits(t testing.TB, remote string, conns int) {
	t.Helper()
	listen := loopback4(t)
	m := forward(t, "tu", listen, remote)
	if conns > 0 {
		if err := cycleConn(listen); err != nil {
			t.Fatal(err)
		}
		waitConnLogs(t, m, 1)
		for range conns {
			if err := cycleConn(listen); err != nil {
				t.Fatal(err)
			}
		}
		// 客户端读到 EOF 时 tinymapper 正在释放连接对的回调里，SIGTERM 要等这次回调记完日志、回到事件循环后才处理
		t.Logf("发送 SIGTERM 前已写进文件的连接日志：%v（期望最终各 %d 行）", connLogCounts(m), 1+conns)
	}
	m.cmd.Process.Signal(syscall.SIGTERM)
	if m.aliveAfter(2 * time.Second) {
		t.Fatal("SIGTERM 后 2 s 内未退出")
	}
	m.stop(t, true)
	if m.exitErr != nil {
		t.Fatalf("SIGTERM 后退出状态异常：%v", m.exitErr)
	}
	if conns > 0 {
		if got := connLogCounts(m); got[0] != 1+conns || got[1] != 1+conns || got[2] != 1+conns {
			t.Errorf("退出后日志中 new_connection、closed bc of EOF、closed connection 分别有 %v 行，期望各 %d 行：缓冲中的日志没有在退出前写出",
				got, 1+conns)
		}
	}
	if m.logLines("got sigterm, exit") != 1 {
		t.Fatalf("日志中没有 \"got sigterm, exit\"：\n%s", m.logTail(5))
	}
	if data, _ := os.ReadFile(m.logPath); !strings.Contains(string(data), "got sigterm, exit\n") {
		t.Fatalf("\"got sigterm, exit\" 没有以换行结尾：\n%q", m.logTail(3))
	}
}

func TestSigtermExit(t *testing.T) {
	t.Parallel()
	sigtermExits(t, serveTCP(t, loopback4(t), echoHandler("")).addr, 2)
}

// 域名 remote 会启动 DNS 线程。C8：修复前 glibc 构建在 exit() 析构 dns_cv 时阻塞（DNS 线程仍在 wait），musl 不受影响
func TestSigtermExitDomain(t *testing.T) {
	t.Parallel()
	sigtermExits(t, fmt.Sprintf("localhost:%d", freePort(t)), 0)
}

// D105：启动时同步解析域名 remote 期间（getaddrinfo 在等一个只收不回的 DNS 服务器），SIGTERM、SIGINT 按默认处置立即终止进程，
// 不再等解析超时、监听与 worker 都起来之后才退出；SIGUSR1 仍由 libev 接住（它的默认处置也是终止进程），进程照旧等解析。
// 要改写容器的 /etc/resolv.conf、占用 127.0.0.1:53，所以不并行：并行的用例解析 /etc/hosts 之外的名字时会被它卡住
func TestStartupSignal(t *testing.T) {
	inContainer(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	queries := make(chan struct{}, 64)
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			select {
			case queries <- struct{}{}:
			default:
			}
		}
	}()
	old, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	// 原地改写：容器的 /etc/resolv.conf 是 Docker bind mount 进来的文件
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.1\noptions timeout:30 attempts:1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.WriteFile("/etc/resolv.conf", old, 0644) })
	for _, c := range []struct {
		name string
		sig  syscall.Signal
	}{{"sigterm", syscall.SIGTERM}, {"sigint", syscall.SIGINT}, {"sigusr1", syscall.SIGUSR1}} {
		t.Run(c.name, func(t *testing.T) {
			for len(queries) > 0 {
				<-queries
			}
			m := startMapper(t, nil, "-l", loopback4(t), "-r", fmt.Sprintf("blackhole.test:%d", freePort(t)), "-t")
			select {
			case <-queries:
			case <-time.After(5 * time.Second):
				t.Fatalf("5 s 内 DNS 服务器没有收到查询：\n%s", m.logTail(10))
			}
			sig := c.sig
			if sig == syscall.SIGUSR1 {
				m.cmd.Process.Signal(sig)
				if !m.aliveAfter(500 * time.Millisecond) {
					t.Fatalf("解析期间收到 SIGUSR1 后退出：%v", m.exitErr)
				}
				sig = syscall.SIGTERM
			}
			start := time.Now()
			m.cmd.Process.Signal(sig)
			if m.aliveAfter(time.Second) {
				t.Fatalf("解析期间收到 %v 后 1 s 内没有退出", sig)
			}
			t.Logf("%v 之后 %v 退出", sig, time.Since(start).Round(time.Millisecond))
			m.stop(t, true)
			var ee *exec.ExitError
			if !errors.As(m.exitErr, &ee) {
				t.Fatalf("退出状态 %v，期望被 %v 终止", m.exitErr, sig)
			}
			if ws := ee.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != sig {
				t.Fatalf("退出状态 %v，期望被 %v 终止", m.exitErr, sig)
			}
		})
	}
}

// C8：myexit 用 _exit，不经过 exit 刷新 stdio。stdout 是管道时全缓冲，约 1.6 KB 的帮助文本要靠 myexit 里的 fflush 写出
func TestHelpOutput(t *testing.T) {
	t.Parallel()
	out, err := exec.Command(mapperBin, "-h").Output()
	if err != nil {
		t.Fatalf("-h 退出状态异常：%v", err)
	}
	if !strings.Contains(string(out), "-h,--help") {
		t.Fatalf("帮助文本不完整（%d B）：\n%s", len(out), out)
	}
}

// C1：libev 只编入 epoll（修复前 musl 构建回落到 poll），信号通知用 eventfd 而不是 pipe
func TestEventBackend(t *testing.T) {
	t.Parallel()
	m := forward(t, "tu", loopback4(t), loopback4(t))
	dir := fmt.Sprintf("/proc/%d/fd", m.pid())
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var links []string // 跳过继承的 0-2
	for _, e := range ents {
		if fd, _ := strconv.Atoi(e.Name()); fd < 3 {
			continue
		}
		if link, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
			links = append(links, link)
		}
	}
	if !slices.Contains(links, "anon_inode:[eventpoll]") {
		t.Errorf("没有 epoll 实例，fd：%v", links)
	}
	if slices.ContainsFunc(links, func(l string) bool { return strings.HasPrefix(l, "pipe:[") }) {
		t.Errorf("libev 用 pipe 而不是 eventfd 通知，fd：%v", links)
	}
	eventually(t, 2*time.Second, 50*time.Millisecond, func() error {
		data, _ := os.ReadFile(m.logPath)
		if !strings.Contains(string(data), "event backend: epoll") {
			return errors.New("日志中没有 \"event backend: epoll\"")
		}
		return nil
	})
}

// socketRoles 扫描 /proc/net/{tcp,tcp6,udp,udp6}，按 tinymapper 的监听端口 listen 与后端端口 remote
// 给 socket 归类，返回 inode → 类别。调用方只查 tinymapper 持有的 inode，其他进程的行不影响结果
func socketRoles(listen, remote int) map[string]string {
	port := func(addr string) int {
		p, _ := strconv.ParseUint(addr[strings.LastIndexByte(addr, ':')+1:], 16, 16)
		return int(p)
	}
	roles := map[string]string{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, _ := os.ReadFile("/proc/net/" + name)
		tcp := strings.HasPrefix(name, "tcp")
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			lp, rp, st := port(f[1]), port(f[2]), f[3]
			switch {
			case tcp && st == "0A" && lp == listen:
				roles[f[9]] = "TCP 监听"
			case tcp && st == "01" && lp == listen:
				roles[f[9]] = "TCP 客户端"
			case tcp && st == "01" && rp == remote:
				roles[f[9]] = "TCP 上游"
			case !tcp && st == "07" && lp == listen:
				roles[f[9]] = "UDP 监听"
			case !tcp && st == "01" && rp == remote:
				roles[f[9]] = "UDP 会话"
			}
		}
	}
	return roles
}

// T2：tinymapper 创建的 socket 都应带 O_NONBLOCK 与 O_CLOEXEC（socket()/accept4 传 SOCK_NONBLOCK|SOCK_CLOEXEC），
// 修复前用 fcntl 设非阻塞、没有 close-on-exec。fdinfo 的 flags 在 close_on_exec 置位时含 O_CLOEXEC（fs/proc/fd.c）。
// 五类 socket 按 /proc/net 中的端口认出并要求每类至少一个，防止一个都没查到也通过
func TestFdFlags(t *testing.T) {
	t.Parallel()
	// -r 同时用于 TCP 与 UDP，两个回显后端共用一个端口
	remote := loopback4(t)
	serveTCP(t, remote, echoHandler(""))
	serveUDP(t, remote, "")
	listen := loopback4(t)
	m := forward(t, "tu", listen, remote)
	mustEcho(t, dial(t, listen), "tcp") // 回显成功说明上游已连上
	udpReplyFrom(t, udpDial(t, "", listen), "udp")

	type sock struct {
		fd, inode, role string
		flags           uint64
	}
	var socks []sock
	var others []string
	dir := fmt.Sprintf("/proc/%d/fd", m.pid())
	scans := 0
	// /proc/net/tcp 不是一致快照，并行负载下可能漏行（见 synSentTo）：重扫直到每个 socket 都能归类
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		socks, others = nil, nil
		scans++
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		roles := socketRoles(portOf(listen), portOf(remote))
		unknown := 0
		for _, e := range ents {
			link, _ := os.Readlink(filepath.Join(dir, e.Name()))
			inode, ok := strings.CutPrefix(link, "socket:[")
			if !ok {
				others = append(others, e.Name()+"→"+link)
				continue
			}
			s := sock{fd: e.Name(), inode: strings.TrimSuffix(inode, "]"), role: "未归类"}
			if r, ok := roles[s.inode]; ok {
				s.role = r
			} else {
				unknown++
			}
			info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", m.pid(), e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(info), "\n") {
				if v, ok := strings.CutPrefix(line, "flags:"); ok {
					s.flags, _ = strconv.ParseUint(strings.TrimSpace(v), 8, 32)
				}
			}
			socks = append(socks, s)
		}
		if unknown == 0 || time.Now().After(deadline) {
			break
		}
	}
	t.Logf("扫描 /proc/net %d 次；非 socket fd：%v", scans, others)

	count := map[string]int{}
	for _, s := range socks {
		count[s.role]++
		var missing []string
		if s.flags&syscall.O_NONBLOCK == 0 {
			missing = append(missing, "O_NONBLOCK")
		}
		if s.flags&syscall.O_CLOEXEC == 0 {
			missing = append(missing, "O_CLOEXEC")
		}
		if len(missing) > 0 {
			t.Errorf("%s socket（fd %s，inode %s）flags=0%o，缺少 %s", s.role, s.fd, s.inode, s.flags, strings.Join(missing, "、"))
		} else {
			t.Logf("%s socket（fd %s，inode %s）flags=0%o", s.role, s.fd, s.inode, s.flags)
		}
	}
	for _, k := range []string{"TCP 监听", "TCP 客户端", "TCP 上游", "UDP 监听", "UDP 会话"} {
		if count[k] == 0 {
			t.Errorf("没有找到 %s socket，这一类未被检查", k)
		}
	}
	if n := count["未归类"]; n > 0 {
		t.Errorf("%d 个 socket 在 /proc/net 中找不到对应行或无法归类", n)
	}
}

// 命令行与 TOML 配置的等价性
func TestConfigEquivalence(t *testing.T) {
	t.Parallel()
	t.Run("tcp_udp", func(t *testing.T) {
		t.Parallel()
		remote := balancedBackends(t, 1)[0]
		cli, toml := loopback4(t), loopback4(t)
		forward(t, "tu", cli, remote)
		cfg := writeConfig(t, fmt.Sprintf("[network]\nuse_udp = true\n\n[[endpoints]]\nlisten = %q\nremote = %q\n", toml, remote))
		startMapper(t, listenPoints("tu", portOf(toml)), "-c", cfg)
		for _, listen := range []string{cli, toml} {
			if got := readLine(t, dial(t, listen)); got != "0" {
				t.Fatalf("%s：TCP 连到 %q", listen, got)
			}
			if got := udpReplyFrom(t, udpDial(t, "", listen), "x"); got != "0" {
				t.Fatalf("%s：UDP 发往 %q", listen, got)
			}
		}
	})
	t.Run("default_tcp_only", func(t *testing.T) {
		t.Parallel()
		remote := balancedBackends(t, 1)[0]
		cli, toml := loopback4(t), loopback4(t)
		mc := forward(t, "t", cli, remote)
		cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\n", toml, remote))
		mt := startMapper(t, listenPoints("t", portOf(toml)), "-c", cfg)
		for listen, m := range map[string]*mapper{cli: mc, toml: mt} {
			if got := readLine(t, dial(t, listen)); got != "0" {
				t.Fatalf("%s：TCP 连到 %q", listen, got)
			}
			if !udpRefused(t, listen) || listening(m.pid(), "udp", portOf(listen)) {
				t.Fatalf("%s：未启用 UDP 时不应监听 UDP", listen)
			}
		}
	})
	t.Run("roundrobin", func(t *testing.T) {
		t.Parallel()
		weights := []int{2, 1, 1}
		remotes := balancedBackends(t, len(weights))
		cli, toml := loopback4(t), loopback4(t)
		balance := weightsSpec("roundrobin", weights)
		startMapper(t, listenPoints("t", portOf(cli)), balanceArgs(cli, remotes, balance, "t")...)
		cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\nextra_remotes = [%q, %q]\nbalance = %q\n",
			toml, remotes[0], remotes[1], remotes[2], balance))
		startMapper(t, listenPoints("t", portOf(toml)), "-c", cfg)
		want := swrr(weights, 8)
		for _, listen := range []string{cli, toml} {
			if got := rrSequence(t, listen, len(want)); !slices.Equal(got, want) {
				t.Fatalf("%s：选择序列 %v，期望 %v", listen, got, want)
			}
		}
	})
}

// 多规则：[network] 默认值、仅 TCP / 仅 UDP 规则、TCP 与 UDP 规则共用同一监听地址、IPv6 规则
func TestConfigMultiRule(t *testing.T) {
	t.Parallel()
	b := make([]string, 4)
	for i := range b {
		b[i] = loopback4(t)
		id := fmt.Sprint("r", i+1)
		serveTCP(t, b[i], echoHandler(id+"\n"))
		serveUDP(t, b[i], id)
	}
	p1, p2 := loopback4(t), loopback4(t)
	p3 := hostPort("::1", freePort(t))
	cfg := writeConfig(t, fmt.Sprintf(`# 多规则配置
[network]
use_udp = true

[[endpoints]]   # 规则 1：继承 [network]，TCP + UDP
listen = %q
remote = %q

[[endpoints]]
listen = %q
remote = %q
no_tcp = true   # 规则 2：仅 UDP

[[endpoints]]
listen = %q    # 规则 3：仅 TCP，与规则 2 共用监听地址
remote = %q
use_udp = false

[[endpoints]]
  listen   =   %q
  remote = %q
`, p1, b[0], p2, b[1], p2, b[2], p3, b[3]))
	startMapper(t, append(append(listenPoints("tu", portOf(p1)), listenPoints("tu", portOf(p2))...), listenPoints("tu", portOf(p3))...), "-c", cfg)
	for _, c := range []struct{ listen, tcp, udp string }{
		{p1, "r1", "r1"},
		{p2, "r3", "r2"},
		{p3, "r4", "r4"},
	} {
		if got := readLine(t, dial(t, c.listen)); got != c.tcp {
			t.Errorf("%s：TCP 连到 %s，期望 %s", c.listen, got, c.tcp)
		}
		if got := udpReplyFrom(t, udpDial(t, "", c.listen), "x"); got != c.udp {
			t.Errorf("%s：UDP 发往 %s，期望 %s", c.listen, got, c.udp)
		}
	}
}

// 仅 UDP 规则不监听 TCP
func TestConfigUDPOnly(t *testing.T) {
	t.Parallel()
	remote := balancedBackends(t, 1)[0]
	listen := loopback4(t)
	cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\nno_tcp = true\nuse_udp = true\n", listen, remote))
	m := startMapper(t, listenPoints("u", portOf(listen)), "-c", cfg)
	if got := udpReplyFrom(t, udpDial(t, "", listen), "x"); got != "0" {
		t.Fatalf("UDP 发往 %q", got)
	}
	if !tcpRefused(listen) || listening(m.pid(), "tcp", portOf(listen)) {
		t.Fatal("no_tcp = true 时不应监听 TCP")
	}
}

// udpListenBufFatal 是 --udp-listen-buf 的值越界或不是数字时的 fatal 行
const udpListenBufFatal = "udp-listen-buf value must be between 10 and 10240 (kbyte)"

// sockBufFatal 是 --sock-buf 的值越界或不是数字时的完整 fatal 行（以前写的范围是 1..10240，实际下限 10，行尾还多一个空格）
const sockBufFatal = "sock-buf value must be between 10 and 10240 (kbyte)\n"

// 非法配置：进程以非零状态退出并给出原因
func TestConfigInvalid(t *testing.T) {
	t.Parallel()
	l := loopback4(t)
	r1, r2 := loopback4(t), loopback4(t)
	busy, err := net.Listen("tcp", loopback4(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { busy.Close() })
	ep := func(extra string) string {
		return fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\n%s", l, r1, extra)
	}
	dir := t.TempDir()
	// 以前被宽松接受的监听地址与 cli_positional_echo 各用一个空闲端口：旧版本会真的监听在上面并一直运行，而不是撞上别的用例的端口
	lp := func() int { return portOf(loopback4(t)) }
	junkListen, colonListen, v6JunkListen, plusListen, wrapListen := fmt.Sprintf("127.0.0.1:%dabc", lp()), fmt.Sprintf("127.0.0.1:%d:90", lp()),
		fmt.Sprintf("[::1]:%djunk", lp()), fmt.Sprintf("127.0.0.1:+%d", lp()), fmt.Sprintf("127.0.0.1:%d", 1<<32+lp())
	echoListen := loopback4(t)

	cases := []struct {
		name string
		args []string // 含 "CFG" 时替换为 toml 写出的文件路径
		toml string
		want string
	}{
		{"cli_missing_r", []string{"-l", l, "-t"}, "", "-r not found"},
		{"cli_missing_l", []string{"-r", r1, "-t"}, "", "-l not found"},
		{"cli_no_proto", []string{"-l", l, "-r", r1}, "", "you must specify -t or -u"},
		{"cli_c_with_l", []string{"-c", "CFG", "-l", l}, ep(""), "cannot be combined"},
		{"cli_c_with_t", []string{"-c", "CFG", "-t"}, ep(""), "cannot be combined"},
		{"cli_duplicate_c", []string{"-c", "CFG", "-c", "CFG"}, ep(""), "duplicate -c"},
		// D101：重复的 -l 与多余的位置参数以前被静默忽略（后一个 -l 覆盖前一个；"-r a b" 只用 a，"-c a b" 只读 a，"--" 之后的都不看）
		{"cli_duplicate_l", []string{"-l", l, "-l", loopback4(t), "-r", r1, "-t"}, "", "duplicate -l option"},
		{"cli_extra_remote", []string{"-l", l, "-r", r1, r2, "-t"}, "", "unexpected argument '" + r2 + "'"},
		{"cli_c_extra", []string{"-c", "CFG", "extra"}, ep(""), "unexpected argument 'extra'"},
		{"cli_after_dashdash", []string{"-l", l, "-r", r1, "-t", "--", "-u"}, "", "unexpected argument '-u'"},
		// 空参数（systemd 的 ${VAR} 未设置时恰好展开成一个）也是多余参数，加了引号才看得出来
		{"cli_empty_positional", []string{"-c", "CFG", ""}, ep(""), "unexpected argument ''"},
		// GNU getopt、musl 把位置参数挪到最后再报；预扫描在 argv 的副本上跑，argc= 回显仍是命令行原序（D93）
		{"cli_positional_first", []string{"foo", "-l", l, "-r", r1, "-t"}, "", "unexpected argument 'foo'"},
		{"cli_positional_echo", []string{"foo", "-l", echoListen, "-r", r1, "-t"}, "", fmt.Sprintf("foo -l %s -r %s -t \n", echoListen, r1)},
		{"cli_multi_r_no_balance", []string{"-l", l, "-r", r1, "-r", r2, "-t"}, "", "balance is required"},
		{"cli_weight_count", []string{"-l", l, "-r", r1, "-r", r2, "-t", "--balance", "roundrobin: 1"}, "", "weight count must equal remote count"},
		{"cli_weight_zero", []string{"-l", l, "-r", r1, "-r", r2, "-t", "--balance", "roundrobin: 0, 1"}, "", "between 1 and 255"},
		{"cli_weight_256", []string{"-l", l, "-r", r1, "-r", r2, "-t", "--balance", "iphash: 256, 1"}, "", "between 1 and 255"},
		{"cli_unknown_strategy", []string{"-l", l, "-r", r1, "-r", r2, "-t", "--balance", "random: 1, 1"}, "", "unknown balance strategy"},
		{"cli_balance_no_colon", []string{"-l", l, "-r", r1, "-r", r2, "-t", "--balance", "roundrobin"}, "", "missing ':'"},
		{"cli_off_multi", []string{"-l", l, "-r", r1, "-r", r2, "-t", "--balance", "off:"}, "", "off balance allows only one remote"},
		{"cli_duplicate_balance", []string{"-l", l, "-r", r1, "-t", "--balance", "off:", "--balance", "off:"}, "", "duplicate --balance"},
		{"cli_bad_ipv4_remote", []string{"-l", l, "-r", "1.2.3:80", "-t"}, "", "invalid IPv4 address"},
		{"cli_unbracketed_ipv6_remote", []string{"-l", l, "-r", "::1:80", "-t"}, "", "IPv6 address must be enclosed"},
		{"cli_bad_port_remote", []string{"-l", l, "-r", "127.0.0.1:70000", "-t"}, "", "-r remote: port must be between 1 and 65535"},
		// D103：端口 0 监听时每个 socket 各绑一个随机端口，远端时每个连接都失败
		{"cli_remote_port_0", []string{"-l", l, "-r", "127.0.0.1:0", "-t"}, "", "-r remote: port must be between 1 and 65535"},
		// D102：-l 与配置文件的 listen 同一个严格的解析（以前 sscanf("%[^:]:%u") 不管端口后面的内容、接受符号、按 32 位回绕），
		// 用语同 -r；出错是 fatal，--log-level 1 时也看得到原因（以前是 log_error，静默以 255 退出）
		{"cli_listen_no_port", []string{"-l", "127.0.0.1", "-r", r1, "-t"}, "", "-l 127.0.0.1: missing ':'"},
		{"cli_listen_no_port_level1", []string{"--log-level", "1", "-l", "127.0.0.1", "-r", r1, "-t"}, "", "-l 127.0.0.1: missing ':'"},
		{"cli_listen_hostname", []string{"-l", "localhost:80", "-r", r1, "-t"}, "", "-l localhost:80: invalid IPv4 address"},
		{"cli_listen_port_junk", []string{"-l", junkListen, "-r", r1, "-t"}, "", "-l " + junkListen + ": invalid port"},
		{"cli_listen_two_colons", []string{"-l", colonListen, "-r", r1, "-t"}, "", "-l " + colonListen + ": IPv6 address must be enclosed in []"},
		{"cli_listen_ipv6_port_junk", []string{"-l", v6JunkListen, "-r", r1, "-t"}, "", "-l " + v6JunkListen + ": invalid port"},
		{"cli_listen_port_plus", []string{"-l", plusListen, "-r", r1, "-t"}, "", "-l " + plusListen + ": invalid port"},
		{"cli_listen_port_wrap", []string{"-l", wrapListen, "-r", r1, "-t"}, "", "-l " + wrapListen + ": port must be between 1 and 65535"},
		{"cli_listen_port_0", []string{"-l", "127.0.0.1:0", "-r", r1, "-t"}, "", "-l 127.0.0.1:0: port must be between 1 and 65535"},
		{"cli_listen_empty", []string{"-l", "", "-r", r1, "-t"}, "", "-l : empty address"},
		{"cli_listen_v6_no_close", []string{"-l", "[::1:80", "-r", r1, "-t"}, "", "-l [::1:80: missing ']'"},
		{"cli_listen_v6_no_colon", []string{"-l", "[::1]80", "-r", r1, "-t"}, "", "-l [::1]80: missing ':'"},
		{"cli_listen_v6_empty_host", []string{"-l", "[]:80", "-r", r1, "-t"}, "", "-l []:80: empty host"},
		{"cli_listen_v6_bad", []string{"-l", "[1.2.3.4]:80", "-r", r1, "-t"}, "", "-l [1.2.3.4]:80: invalid IPv6 address"},
		{"cli_listen_empty_port", []string{"-l", "127.0.0.1:", "-r", r1, "-t"}, "", "-l 127.0.0.1:: empty port"},
		{"cli_listen_not_local", []string{"-l", "192.0.2.1:80", "-r", r1, "-t"}, "", "bind failed"},
		{"cli_listen_busy", []string{"-l", busy.Addr().String(), "-r", r1, "-t"}, "", "bind failed"},
		{"cli_sock_buf", []string{"-l", l, "-r", r1, "-t", "--sock-buf", "5"}, "", sockBufFatal},
		// D100：数值选项只认十进制数字，以前 sscanf("%d") 不管后面的内容、接受符号、按 32 位回绕（4294968320 = 2^32+1024）
		{"cli_sock_buf_suffix", []string{"-l", l, "-r", r1, "-t", "--sock-buf", "1024x"}, "", sockBufFatal},
		{"cli_sock_buf_wrap", []string{"-l", l, "-r", r1, "-t", "--sock-buf", "4294968320"}, "", sockBufFatal},
		{"cli_udp_listen_buf_plus", []string{"-l", l, "-r", r1, "-u", "--udp-listen-buf", "+100"}, "", udpListenBufFatal},
		{"cli_pipe_size_suffix", []string{"-l", l, "-r", r1, "-t", "--pipe-size", "256k"}, "", pipeSizeFatal},
		{"cli_threads_list", []string{"-l", l, "-r", r1, "-t", "--threads", "4,8"}, "", threadsFatal},
		{"cli_threads_wrap", []string{"-l", l, "-r", r1, "-t", "--threads", "4294967297"}, "", threadsFatal},
		{"cli_log_level_suffix", []string{"-l", l, "-r", r1, "-t", "--log-level", "3abc"}, "", "invalid log_level"},
		{"cli_log_level_wrap", []string{"-l", l, "-r", r1, "-t", "--log-level", "4294967300"}, "", "invalid log_level"},
		// U6：--udp-listen-buf 只接受 10–10240（KiB）；边界值 10、10240 的生效见 TestUDPSockBuf
		{"cli_udp_listen_buf_9", []string{"-l", l, "-r", r1, "-u", "--udp-listen-buf", "9"}, "", udpListenBufFatal},
		{"cli_udp_listen_buf_10241", []string{"-l", l, "-r", r1, "-u", "--udp-listen-buf", "10241"}, "", udpListenBufFatal},
		{"cli_udp_listen_buf_abc", []string{"-l", l, "-r", r1, "-u", "--udp-listen-buf", "abc"}, "", udpListenBufFatal},
		{"cli_udp_listen_buf_empty", []string{"-l", l, "-r", r1, "-u", "--udp-listen-buf", ""}, "", udpListenBufFatal},
		// 没给值：getopt_long 把下一个参数 -u 当作值；在最后一个参数时由 getopt_long 报错（glibc、musl 的措辞都含这一句）
		{"cli_udp_listen_buf_no_value", []string{"-l", l, "-r", r1, "--udp-listen-buf", "-u"}, "", udpListenBufFatal},
		{"cli_udp_listen_buf_missing", []string{"-l", l, "-r", r1, "-u", "--udp-listen-buf"}, "", "requires an argument"},
		{"toml_udp_listen_buf_9", []string{"-c", "CFG", "--udp-listen-buf", "9"}, ep("use_udp = true\n"), udpListenBufFatal},
		{"cli_log_level", []string{"--log-level", "9", "-l", l, "-r", r1, "-t"}, "", "invalid log_level"},
		// D93：--log-level 的预扫描与正式解析是同一套 getopt_long，--log-level=N、缩写也校验；非数字、空串、负数（以前不报错就退出）都拒绝
		{"cli_log_level_eq", []string{"--log-level=9", "-l", l, "-r", r1, "-t"}, "", "invalid log_level"},
		{"cli_log_level_abbrev", []string{"--log-l", "9", "-l", l, "-r", r1, "-t"}, "", "invalid log_level"},
		{"cli_log_level_abc", []string{"-l", l, "-r", r1, "-t", "--log-level", "abc"}, "", "invalid log_level"},
		{"cli_log_level_empty", []string{"-l", l, "-r", r1, "-t", "--log-level="}, "", "invalid log_level"},
		{"cli_log_level_negative", []string{"-l", l, "-r", r1, "-t", "--log-level", "-1"}, "", "invalid log_level"},
		// 没给值：getopt_long 把下一个参数 -t 当作值，预扫描也一样
		{"cli_log_level_no_value", []string{"-l", l, "-r", r1, "--log-level", "-t"}, "", "invalid log_level"},
		{"cli_config_missing", []string{"-c", filepath.Join(dir, "missing.toml")}, "", "cannot be accessed"},
		{"cli_config_dir", []string{"-c", dir}, "", "must be a regular file"},
		{"toml_empty", []string{"-c", "CFG"}, "# 只有注释\n", "at least one [[endpoints]]"},
		{"toml_missing_listen", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nremote = %q\n", r1), "listen: missing required endpoint key"},
		{"toml_missing_remote", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = %q\n", l), "remote: missing required endpoint key"},
		{"toml_unknown_key", []string{"-c", "CFG"}, ep("weight = 1\n"), "unknown key in [[endpoints]]"},
		{"toml_unknown_network_key", []string{"-c", "CFG"}, "[network]\nzero_copy = true\n" + ep(""), "unknown key in [network]"},
		{"toml_duplicate_key", []string{"-c", "CFG"}, ep(fmt.Sprintf("listen = %q\n", l)), "duplicate key in [[endpoints]]"},
		{"toml_duplicate_network", []string{"-c", "CFG"}, "[network]\n[network]\n" + ep(""), "duplicate [network] section"},
		{"toml_unknown_section", []string{"-c", "CFG"}, "[log]\n" + ep(""), "unknown or unsupported section"},
		{"toml_key_outside_section", []string{"-c", "CFG"}, "no_tcp = false\n" + ep(""), "key appears outside"},
		{"toml_missing_equal", []string{"-c", "CFG"}, ep("no_tcp\n"), "missing '=' after key"},
		{"toml_bad_bool", []string{"-c", "CFG"}, ep("use_udp = yes\n"), "expected boolean literal"},
		{"toml_unquoted_string", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = %s\nremote = %q\n", l, r1), "expected double quoted string"},
		{"toml_unterminated_string", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"%s\nremote = %q\n", l, r1), "unterminated double quoted string"},
		{"toml_listen_hostname", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"localhost:%d\"\nremote = %q\n", portOf(l), r1), "listen: invalid IPv4 address"},
		{"toml_listen_unbracketed_ipv6", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"::1:%d\"\nremote = %q\n", portOf(l), r1), "listen: IPv6 address must be enclosed in []"},
		{"toml_listen_bad_port", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"127.0.0.1:70000\"\nremote = %q\n", r1), "listen: port must be between 1 and 65535"},
		{"toml_listen_port_0", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"127.0.0.1:0\"\nremote = %q\n", r1), "listen: port must be between 1 and 65535"},
		{"toml_listen_empty", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"\"\nremote = %q\n", r1), "listen: empty address"},
		{"toml_listen_v6_no_colon", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"[::1]%d\"\nremote = %q\n", portOf(l), r1), "listen: missing ':'"},
		// 字符串里的 NUL：值按 c_str() 解析，NUL 之后的内容以前被静默丢掉（listen 曾由 validate_address_literal 按整个 string 拒绝）
		{"toml_listen_nul", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"%s\x00junk\"\nremote = %q\n", l, r1), "listen: NUL byte inside string"},
		{"toml_extra_nul", []string{"-c", "CFG"}, ep(fmt.Sprintf("extra_remotes = [\"%s\x00junk\"]\nbalance = \"roundrobin: 1, 1\"\n", r2)), "extra_remotes: NUL byte inside string"},
		{"toml_remote_port_0", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = \"127.0.0.1:0\"\n", l), "remote: port must be between 1 and 65535"},
		{"toml_no_protocol", []string{"-c", "CFG"}, ep("no_tcp = true\n"), "both tcp and udp are disabled"},
		{"toml_network_no_protocol", []string{"-c", "CFG"}, "[network]\nno_tcp = true\n" + ep(""), "both tcp and udp are disabled"},
		{"toml_extra_not_array", []string{"-c", "CFG"}, ep(fmt.Sprintf("extra_remotes = %q\nbalance = \"roundrobin: 1, 1\"\n", r2)), "expected inline string array"},
		{"toml_extra_trailing_comma", []string{"-c", "CFG"}, ep(fmt.Sprintf("extra_remotes = [%q, ]\nbalance = \"roundrobin: 1, 1\"\n", r2)), "trailing comma or empty array item"},
		{"toml_extra_no_balance", []string{"-c", "CFG"}, ep(fmt.Sprintf("extra_remotes = [%q]\n", r2)), "balance is required"},
		{"toml_weight_count", []string{"-c", "CFG"}, ep(fmt.Sprintf("extra_remotes = [%q]\nbalance = \"iphash: 1, 2, 3\"\n", r2)), "weight count must equal remote count"},
		{"toml_bad_remote", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = \"300.1.1.1:80\"\n", l), "invalid IPv4 address"},
		{"toml_tcp_listen_conflict", []string{"-c", "CFG"}, ep("") + ep(""), "conflicts with rule 1"},
		{"toml_udp_listen_conflict", []string{"-c", "CFG"}, ep("no_tcp = true\nuse_udp = true\n") + ep("no_tcp = true\nuse_udp = true\n"), "[udp] listen address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			args := slices.Clone(c.args)
			if c.toml != "" {
				cfg := writeConfig(t, c.toml)
				for i, a := range args {
					if a == "CFG" {
						args[i] = cfg
					}
				}
			}
			out := runExpectFail(t, 5*time.Second, args...)
			if !strings.Contains(out, c.want) {
				t.Fatalf("输出中没有 %q：\n%s", c.want, out)
			}
		})
	}
}

// 选项本身有错（getopt_long 返回 '?'：缺值、未知选项）：getopt_long 已把具体原因写到 stderr（tinymapper 把它并到了 stdout），随后是一行
// fatal "invalid command line option, see -h"，以换行结尾。以前这一行是 "unknown option <3f>"（'?' 的十六进制）且没有换行。
// 两种 libc 的措辞不同（glibc "option '--threads' requires an argument"、"unrecognized option '--bogus'"；musl "option requires an
// argument: threads"、"unrecognized option: bogus"），都有同一行里的原因与选项名。harness 总带 --disable-color，myexit 不再补颜色复位行
func TestConfigOptionError(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, arg, reason string }{
		{"missing-value", "--threads", "requires an argument"},
		{"unknown", "--bogus", "unrecognized option"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", c.arg)
			opt := strings.TrimPrefix(c.arg, "--")
			if !slices.ContainsFunc(strings.Split(out, "\n"), func(l string) bool { return strings.Contains(l, c.reason) && strings.Contains(l, opt) }) {
				t.Errorf("输出中没有同时含 %q 与 %q 的一行（getopt_long 的原因）：\n%s", c.reason, opt, out)
			}
			if !strings.HasSuffix(out, "[FATAL]invalid command line option, see -h\n") || strings.Contains(out, "<3f>") {
				t.Errorf("输出应以 fatal 行 \"invalid command line option, see -h\" 加换行结束、不含 \"<3f>\"：%q", out)
			}
		})
	}
}

// ptyPair 返回一对伪终端（打开方式同 startMapperTTY）：主设备，与关掉输出处理 OPOST 的从设备（否则 ONLCR 把 \n 写成 \r\n）。
// Fd() 把两端都切成阻塞模式
func ptyPair(t testing.TB) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("打不开 /dev/ptmx（%v）：环境中没有伪终端", err)
	}
	t.Cleanup(func() { master.Close() })
	var unlock int32
	var n uint32
	if err := ioctl(int(master.Fd()), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		t.Fatalf("解锁伪终端失败：%v", err)
	}
	if err := ioctl(int(master.Fd()), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		t.Fatalf("读取伪终端编号失败：%v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("打开伪终端从设备失败：%v", err)
	}
	t.Cleanup(func() { slave.Close() })
	var tio syscall.Termios
	if err := ioctl(int(slave.Fd()), syscall.TCGETS, unsafe.Pointer(&tio)); err != nil {
		t.Fatalf("TCGETS：%v", err)
	}
	tio.Oflag &^= syscall.OPOST
	if err := ioctl(int(slave.Fd()), syscall.TCSETS, unsafe.Pointer(&tio)); err != nil {
		t.Fatalf("TCSETS：%v", err)
	}
	return master, slave
}

// D104：配置文件读到一半出错时以 fatal 退出，不按已读到的部分启动。经 seccomp 通知把 tinymapper 打开配置文件的 open/openat 换成伪终端的主设备：
// 从设备写入文件的前一段（一个完整的 [[endpoints]]）后关闭，主设备先读出缓冲的这一段，读完再读就是 EIO（startMapperTTY 收尾也靠这一点），
// 相当于磁盘在第一块之后读出错，文件里的第二个 [[endpoints]] 永远读不到。以前 libstdc++ 的 underflow 抛出的 ios_failure 被 getline 接住、
// 只置 badbit，循环像读到文件尾一样结束，只按第一条规则启动
func TestConfigReadError(t *testing.T) {
	t.Parallel()
	l1, l2, remote := loopback4(t), loopback4(t), loopback4(t)
	first := fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\n", l1, remote)
	cfg := writeConfig(t, first+fmt.Sprintf("\n[[endpoints]]\nlisten = %q\nremote = %q\n", l2, remote))
	master, slave := ptyPair(t)
	if _, err := slave.WriteString(first); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	masterFD := int(master.Fd())
	var opens atomic.Int64
	m, _ := startMapperNotifyWith(t, func(n *notifier) {
		n.setAddFD(func(call notifyCall) int {
			if path, ok := openPath(call); ok && path == cfg {
				opens.Add(1)
				return masterFD
			}
			return -1
		})
	}, nil, "-c", cfg)
	deadline := time.Now().Add(10 * time.Second)
	for !m.exited() {
		if listening(m.pid(), "tcp", portOf(l1)) {
			t.Fatalf("读配置文件出错后仍按读到的部分启动：监听了第一条规则的 %s（第二条的 %s：%v），配置文件经 notifier 打开 %d 次",
				l1, l2, listening(m.pid(), "tcp", portOf(l2)), opens.Load())
		}
		if time.Now().After(deadline) {
			t.Fatalf("tinymapper 在 10 s 内既没有退出也没有监听 %s", l1)
		}
		time.Sleep(20 * time.Millisecond)
	}
	m.stop(t, true)
	var ee *exec.ExitError
	if !errors.As(m.exitErr, &ee) {
		t.Errorf("tinymapper 退出：%v，期望非零状态", m.exitErr)
	}
	if n := opens.Load(); n != 1 {
		t.Errorf("配置文件经 notifier 换成伪终端 %d 次，期望 1 次", n)
	}
	if want := fmt.Sprintf("%s:%d: path: failed to read config file", cfg, strings.Count(first, "\n")+1); m.logLines("[FATAL]", want) != 1 {
		t.Errorf("日志里没有一行 fatal %q：\n%s", want, m.logTail(20))
	}
}

// D107：remote 指回本进程同协议的监听且成环（规则自身，或跨规则）时以 fatal 退出；确定会落到监听上才算：remote 等于具体监听地址
// （0.0.0.0、[::] 按回环算），或 TCP 通配监听（[::] 也收 IPv4）同端口且 remote 是回环、本机网卡地址。A→B→后端的链照常转发；
// UDP 通配监听同端口只 warn：带 SO_REUSEADDR 绑在具体地址上的 UDP socket 会接走发往它的包（如 systemd-resolved 的 127.0.0.53:53）
func TestForwardLoop(t *testing.T) {
	t.Parallel()
	p := strconv.Itoa(freePort(t))
	a, b := loopback4(t), loopback4(t)
	ext := loopback4(t)
	ep := func(listen, remote, extra string) string {
		return fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\n%s", listen, remote, extra)
	}
	for _, c := range []struct {
		name string
		args []string // 含 "CFG" 时替换为 toml 写出的文件路径
		toml string
		want string
	}{
		{"tcp_exact", []string{"-l", "127.0.0.1:" + p, "-r", "127.0.0.1:" + p, "-t"}, "", "remote 127.0.0.1:" + p + " reaches the listen address 127.0.0.1:" + p + " of rule 1: forwarding loop"},
		{"tcp_unspecified", []string{"-l", "127.0.0.1:" + p, "-r", "0.0.0.0:" + p, "-t"}, "", "of rule 1: forwarding loop"},
		{"tcp_wildcard_loopback", []string{"-l", "0.0.0.0:" + p, "-r", "127.0.0.2:" + p, "-t"}, "", "of rule 1: forwarding loop"},
		{"tcp_dualstack_v4", []string{"-l", "[::]:" + p, "-r", "127.0.0.1:" + p, "-t"}, "", "of rule 1: forwarding loop"},
		// localhost 解析成 127.0.0.1 还是 ::1 取决于 libc 的排序，[::] 两个都收
		{"tcp_domain", []string{"-l", "[::]:" + p, "-r", "localhost:" + p, "-t"}, "", "remote localhost:" + p + " ("},
		{"tcp_balance", []string{"-l", "127.0.0.1:" + p, "-r", ext, "-r", "127.0.0.1:" + p, "-t", "--balance", "roundrobin: 1, 1"}, "", "of rule 1: forwarding loop"},
		{"udp_exact", []string{"-l", "127.0.0.1:" + p, "-r", "127.0.0.1:" + p, "-u"}, "", "rule 1 [udp] remote 127.0.0.1:" + p + " reaches"},
		{"toml_cycle", []string{"-c", "CFG"}, ep(a, b, "") + ep(b, a, ""), "rule 1 [tcp] remote " + b + " reaches the listen address " + b + " of rule 2, which forwards back to rule 1: forwarding loop"},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := slices.Clone(c.args)
			if c.toml != "" {
				cfg := writeConfig(t, c.toml)
				for i, a := range args {
					if a == "CFG" {
						args[i] = cfg
					}
				}
			}
			out := runExpectFail(t, 5*time.Second, args...)
			if !strings.Contains(out, c.want) || !strings.Contains(out, "[FATAL]") {
				t.Fatalf("输出中没有 fatal %q：\n%s", c.want, out)
			}
		})
	}
	t.Run("tcp_local_iface", func(t *testing.T) {
		loAlias4(t, [4]byte{192, 0, 2, 77})
		out := runExpectFail(t, 5*time.Second, "-l", "0.0.0.0:"+p, "-r", "192.0.2.77:"+p, "-t")
		if !strings.Contains(out, "remote 192.0.2.77:"+p+" reaches the listen address 0.0.0.0:"+p+" of rule 1: forwarding loop") {
			t.Fatalf("输出中没有 forwarding loop：\n%s", out)
		}
	})
	t.Run("chain", func(t *testing.T) {
		be := serveTCP(t, loopback4(t), echoHandler(""))
		startMapper(t, append(listenPoints("t", portOf(a)), listenPoints("t", portOf(b))...), "-c", writeConfig(t, ep(a, b, "")+ep(b, be.addr, "")))
		if err := cycleConn(a); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("udp_wildcard_holder", func(t *testing.T) {
		lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
			var err error
			rc.Control(func(fd uintptr) { err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1) })
			return err
		}}
		up := freePort(t)
		holder, err := lc.ListenPacket(context.Background(), "udp", hostPort("127.0.0.2", up))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { holder.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := holder.ReadFrom(buf)
				if err != nil {
					return
				}
				holder.WriteTo(buf[:n], from)
			}
		}()
		m := startMapper(t, listenPoints("u", up), "-l", hostPort("0.0.0.0", up), "-r", hostPort("127.0.0.2", up), "-u")
		udpEcho(t, udpDial(t, "", hostPort("127.0.0.1", up)), []byte("holder"))
		if n := udpSockets(m.pid()); n > m.threads()+1 {
			t.Errorf("tinymapper 有 %d 个 UDP socket，期望监听 %d 个加 1 个会话：包回到了自己的监听", n, m.threads())
		}
		eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
			if m.logLines("[WARN]", "rule 1 [udp] remote 127.0.0.2:"+strconv.Itoa(up), "forwarding loop unless another socket") != 1 {
				return errors.New("日志里没有 UDP 通配监听的 warn")
			}
			return nil
		})
	})
}
