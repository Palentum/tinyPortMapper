package tests

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// etcHostsMu 保护 hostsEntry 的"取文件末尾 + 追加"：TestDomainRefresh 与 TestUDPSessionChurn 并行，同时追加会写到同一偏移
var etcHostsMu sync.Mutex

// 各种地址族组合下 TCP 与 UDP 都能转发
func TestAddressFamilies(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name           string
		listen, client string
		backends       []string
		remote         string
	}{
		{"ipv4", "127.0.0.1", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1"},
		{"ipv6", "::1", "::1", []string{"::1"}, "::1"},
		{"4to6", "127.0.0.1", "127.0.0.1", []string{"::1"}, "::1"},
		{"6to4", "::1", "::1", []string{"127.0.0.1"}, "127.0.0.1"},
		{"v4mapped_remote", "::1", "::1", []string{"127.0.0.1"}, "::ffff:127.0.0.1"},
		{"dualstack_listen_v4client", "::", "127.0.0.1", []string{"127.0.0.1"}, "127.0.0.1"},
		{"wildcard_v4", "0.0.0.0", "127.0.0.1", []string{"::1"}, "::1"},
		// localhost 可能解析为 127.0.0.1 或 ::1，两者都放后端
		{"hostname_remote", "127.0.0.1", "127.0.0.1", []string{"127.0.0.1", "::1"}, "localhost"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			bport := freePort(t)
			for _, h := range c.backends {
				serveTCP(t, hostPort(h, bport), echoHandler(c.name+"\n"))
				serveUDP(t, hostPort(h, bport), c.name+":")
			}
			lport := freePort(t)
			remote := hostPort(c.remote, bport)
			if c.remote == "localhost" {
				remote = fmt.Sprintf("localhost:%d", bport)
			}
			forward(t, "tu", hostPort(c.listen, lport), remote)
			target := hostPort(c.client, lport)

			tc := dial(t, target)
			if got := readLine(t, tc); got != c.name {
				t.Fatalf("TCP banner = %q", got)
			}
			mustEcho(t, tc, "tcp-payload")
			if got := udpReplyFrom(t, udpDial(t, "", target), "udp-payload"); got != c.name+":" {
				t.Fatalf("UDP 回包前缀 = %q", got)
			}
		})
	}
}

// D121：net.ipv6.bindv6only=1 时新建的 AF_INET6 socket 默认 IPV6_V6ONLY=1，bind 到 v4 映射地址返回 EINVAL、connect 到它返回 ENETUNREACH
// （修复前 v4 映射地址的监听启动即退出，发往 v4 映射 remote 的 TCP 连接与 UDP 会话都建不成，D99 的可达性探测把它判为不可达）。
// tinymapper 给 v4 映射地址的 socket 在 bind/connect 之前清掉 IPV6_V6ONLY；[::] 监听照旧跟随 sysctl，只收 IPv6。
// 这个 sysctl 是 netns 级的，测试容器里 /proc/sys 只读、也没有 CAP_SYS_ADMIN，改不了：tests/run.sh 每个变体另起一个
// --sysctl net.ipv6.bindv6only=1 的容器只跑本用例，主套件里（bindv6only=0）跳过。bindv6only=0 下的 v4 映射地址由
// TestAddressFamilies/v4mapped_remote 与 TestUDPPktinfoSource/v4mapped-any 覆盖
func TestBindV6Only(t *testing.T) {
	if b, _ := os.ReadFile("/proc/sys/net/ipv6/bindv6only"); strings.TrimSpace(string(b)) != "1" {
		t.Skip("需要 net.ipv6.bindv6only=1，由 tests/run.sh 另起容器运行")
	}
	t.Parallel()
	for _, c := range []struct {
		name, listen, remote string
		client, target       string   // UDP 客户端从 client 发往 target，回包须来自 target；TCP 客户端连 target
		hosts                []string // 非空时 remote 是 /etc/hosts 里有这些地址的域名
	}{
		// 上游 TCP、UDP socket connect 到 v4 映射地址
		{"mapped_remote", "::1", "::ffff:127.0.0.1", "::1", "::1", nil},
		// 监听 bind 到 v4 映射地址（listen_probe 与 TCP、UDP 监听 socket）
		{"mapped_listen", "::ffff:127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil},
		// [::ffff:0.0.0.0]：UDP 回包照旧以客户端发往的地址为源（IP_PKTINFO，D87），发往非首选的 127.0.0.2
		{"mapped_any_listen", "::ffff:0.0.0.0", "::ffff:127.0.0.1", "127.0.0.1", "127.0.0.2", nil},
		// 域名：libc 排序时的探测同样失败，不可达的 2001:db8::1 排在前面；D99 的探测须把 v4 映射地址判为可达并选它
		{"hostname_remote", "::1", "", "::1", "::1", []string{"2001:db8::1", "::ffff:127.0.0.1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			bport := freePort(t)
			serveTCP(t, hostPort("127.0.0.1", bport), echoHandler(c.name+"\n"))
			recordUDP(t, hostPort("127.0.0.1", bport))
			remote := hostPort(c.remote, bport)
			if c.hosts != nil {
				inContainer(t)
				name := fmt.Sprintf("bindv6only-%d.test", bport)
				for _, ip := range c.hosts {
					hostsEntry(t, ip, name)
				}
				remote = fmt.Sprintf("%s:%d", name, bport)
			}
			lport := freePort(t)
			m := forward(t, "tu", hostPort(c.listen, lport), remote)
			tc := dial(t, hostPort(c.target, lport))
			if got := readLine(t, tc); got != c.name {
				t.Fatalf("TCP banner = %q", got)
			}
			mustEcho(t, tc, "tcp-payload")
			target := netip.AddrPortFrom(netip.MustParseAddr(c.target), uint16(lport))
			if from, err := echoVia(srcClient(t, c.client), target, []byte("udp-payload")); err != nil {
				t.Errorf("UDP 客户端（%s → %s）收不到回显：%v", c.client, target, err)
			} else if from != target {
				t.Errorf("UDP 回包来自 %s，期望来自客户端发往的 %s", from, target)
			}
			if c.hosts != nil {
				if want := "is not routable from this host, using " + hostPort("::ffff:127.0.0.1", bport); m.logLines(want) != 1 {
					t.Errorf("日志里没有一行 %q", want)
				}
			}
			expectNoWarn(t, m)
		})
	}
	// [::] 监听照旧跟随 sysctl：IPv4 客户端被拒（不强制双栈：同端口另有 0.0.0.0 规则的配置靠它）
	t.Run("any_listen_v6only", func(t *testing.T) {
		t.Parallel()
		bport := freePort(t)
		serveTCP(t, hostPort("127.0.0.1", bport), echoHandler("any\n"))
		lport := freePort(t)
		forward(t, "t", hostPort("::", lport), hostPort("127.0.0.1", bport))
		if got := readLine(t, dial(t, hostPort("::1", lport))); got != "any" {
			t.Fatalf("IPv6 客户端的 TCP banner = %q", got)
		}
		c, err := net.DialTimeout("tcp", hostPort("127.0.0.1", lport), ioTimeout)
		if err == nil {
			c.Close()
			t.Fatal("IPv4 客户端连上了 [::] 监听，期望 bindv6only=1 时被拒")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("IPv4 客户端连 [::] 监听：%v，期望 ECONNREFUSED", err)
		}
	})
}

// D120：静态 glibc 构建解析域名只用 libc.a 内置的 files、dns，不按 /etc/nsswitch.conf 的 hosts 行 dlopen 宿主机的 libnss_*.so：
// 它们会带进宿主机的 libc.so.6 与 ld.so，按宿主机 glibc 版本与模块不同，启动时或 DNS 刷新线程里崩溃。hosts 行改成 compat files dns：镜像里有 libnss_compat.so.2
// 但它没有 hosts 函数，修复前它与 libc.so.6 被映射进 tinymapper，名字再由 files 查到。改写 /etc/nsswitch.conf，不并行
func TestStaticGlibcNSSBuiltin(t *testing.T) {
	inContainer(t)
	if os.Getenv("TPM_VARIANT") != "glibc" {
		t.Skip("musl 自己读 /etc/hosts、发 DNS，不经 NSS")
	}
	f, err := elf.Open(mapperBin)
	if err != nil {
		t.Fatal(err)
	}
	dynamic := slices.ContainsFunc(f.Progs, func(p *elf.Prog) bool { return p.Type == elf.PT_INTERP })
	f.Close()
	if dynamic {
		t.Skip("动态链接的构建照常按 nsswitch.conf 解析")
	}
	old, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		t.Fatal(err)
	}
	conf := regexp.MustCompile(`(?m)^hosts:.*$`).ReplaceAll(old, []byte("hosts: compat files dns"))
	if bytes.Equal(conf, old) {
		t.Fatalf("/etc/nsswitch.conf 里没有 hosts: 行：\n%s", old)
	}
	if m, _ := filepath.Glob("/usr/lib/*/libnss_compat.so.2"); len(m) == 0 {
		t.Fatal("镜像里没有 libnss_compat.so.2，修复前的构建也映射不到它，用例区分不了")
	}
	if err := os.WriteFile("/etc/nsswitch.conf", conf, 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.WriteFile("/etc/nsswitch.conf", old, 0644) })

	bport := freePort(t)
	serveTCP(t, hostPort("127.0.0.1", bport), echoHandler("nss\n"))
	name := fmt.Sprintf("nss-%d.test", bport)
	hostsEntry(t, "127.0.0.1", name)
	lport := freePort(t)
	m := forward(t, "t", hostPort("127.0.0.1", lport), fmt.Sprintf("%s:%d", name, bport))
	if got := readLine(t, dial(t, hostPort("127.0.0.1", lport))); got != "nss" {
		t.Fatalf("TCP banner = %q", got)
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", m.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, so := range []string{"libnss_", "libc.so.6", "ld-linux"} {
		if strings.Contains(string(maps), so) {
			t.Errorf("tinymapper 映射了 %s：静态 glibc 构建按 nsswitch.conf 载入了宿主机的 NSS 模块", so)
		}
	}
}

// hostsEntry 在容器的 /etc/hosts 末尾追加 "ip name"，返回原地改写该 IP 最后一个字符的函数。
// 只做单次 pwrite，避免并发解析的其他进程读到截断的文件。测试结束时在该行行首写 '#' 注释掉它，不截断文件：
// 并行用例后来追加的行还在后面
func hostsEntry(t testing.TB, ip, name string) func(last byte) {
	t.Helper()
	f, err := os.OpenFile("/etc/hosts", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	line := ip + " " + name + "\n"
	var orig int64
	func() {
		etcHostsMu.Lock()
		defer etcHostsMu.Unlock()
		if orig, err = f.Seek(0, 2); err != nil {
			t.Fatal(err)
		}
		last := make([]byte, 1)
		if orig > 0 {
			f.ReadAt(last, orig-1)
			if last[0] != '\n' {
				line = "\n" + line
			}
		}
		if _, err := f.WriteAt([]byte(line), orig); err != nil {
			t.Fatal(err)
		}
	}()
	t.Cleanup(func() { f.WriteAt([]byte{'#'}, orig+int64(len(line)-len(name)-len(ip)-2)) })
	offset := orig + int64(len(line)-len(name)-3) // ip 最后一个字符的位置
	return func(b byte) {
		if _, err := f.WriteAt([]byte{b}, offset); err != nil {
			t.Fatal(err)
		}
	}
}

// hostsBlock 在容器的 /etc/hosts 末尾追加一段 "ip name" 行（各 ip 等长），返回原地改写整段的函数：新的 ip 列表须条数相同、各 ip 与原来等长，
// 单次 pwrite 写回，文件长度不变。测试结束时在每行行首写 '#'
func hostsBlock(t testing.TB, name string, ips []string) func(ips []string) {
	t.Helper()
	ipLen := len(ips[0])
	render := func(ips []string) []byte {
		var b strings.Builder
		for _, ip := range ips {
			if len(ip) != ipLen {
				t.Fatalf("hostsBlock：%q 有 %d 字节，应为 %d 字节，行首偏移会错位", ip, len(ip), ipLen)
			}
			b.WriteString(ip + " " + name + "\n")
		}
		return []byte(b.String())
	}
	f, err := os.OpenFile("/etc/hosts", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	block := render(ips)
	var off int64
	func() {
		etcHostsMu.Lock()
		defer etcHostsMu.Unlock()
		if off, err = f.Seek(0, 2); err != nil {
			t.Fatal(err)
		}
		last := make([]byte, 1)
		if off > 0 {
			f.ReadAt(last, off-1)
			if last[0] != '\n' {
				if _, err := f.WriteAt([]byte{'\n'}, off); err != nil {
					t.Fatal(err)
				}
				off++
			}
		}
		if _, err := f.WriteAt(block, off); err != nil {
			t.Fatal(err)
		}
	}()
	lineLen := int64(len(block) / len(ips))
	t.Cleanup(func() {
		for i := range ips {
			f.WriteAt([]byte{'#'}, off+int64(i)*lineLen)
		}
	})
	return func(ips []string) {
		b := render(ips)
		if len(b) != len(block) {
			t.Fatalf("hostsBlock：新的 ip 列表有 %d 字节，原来 %d 字节", len(b), len(block))
		}
		if _, err := f.WriteAt(b, off); err != nil {
			t.Fatal(err)
		}
	}
}

// 域名 remote 每 30 s 重新解析：地址变化后新连接改连新地址；连在旧地址上的 TCP 连接和 UDP 会话还可用就留着（审查 #9，remote_sweep）。
// 旧后端一直正常：变化时它们都留下（变化行 kept tcp=1 udp=1），之后照常收发、经过下一次定时检查（变化后 dns_refresh_interval）也不关
func TestDomainRefresh(t *testing.T) {
	t.Parallel()
	inContainer(t)
	const name = "tpm-refresh.test"
	bport := freePort(t)
	for _, id := range []string{"2", "3"} {
		serveTCP(t, hostPort("127.0.0."+id, bport), echoHandler(id+"\n"))
		serveUDP(t, hostPort("127.0.0."+id, bport), id)
	}
	setLast := hostsEntry(t, "127.0.0.2", name)
	listen := loopback4(t)
	m := forward(t, "tu", listen, fmt.Sprintf("%s:%d", name, bport))
	start := time.Now()

	old := dial(t, listen)
	if got := readLine(t, old); got != "2" {
		t.Fatalf("启动时应解析到 127.0.0.2，实际连到后端 %q", got)
	}
	udp := udpDial(t, "", listen)
	if got := udpReplyFrom(t, udp, "before"); got != "2" {
		t.Fatalf("启动时 UDP 应发往 127.0.0.2，实际 %q", got)
	}

	setLast('3')
	eventually(t, 50*time.Second, 500*time.Millisecond, func() error {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		b := make([]byte, 2)
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		if string(b) != "3\n" {
			return fmt.Errorf("新连接仍连到后端 %q", b[:1])
		}
		return nil
	})
	t.Logf("修改 /etc/hosts 后 %v 内切换到新地址", time.Since(start).Round(time.Second))
	// 每个 worker 一行；旧连接与旧会话可能在不同的 worker 上，合计各为 1
	changed := regexp.MustCompile(`domain ` + regexp.QuoteMeta(name) + `:\d+ changed from 127\.0\.0\.2:\d+ to 127\.0\.0\.3:\d+, closed unresponsive tcp=0 udp=0, kept tcp=(\d+) udp=(\d+)$`)
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		lines := changedLines(m, changed)
		var sum [2]int
		for _, l := range lines {
			sum[0] += l[0]
			sum[1] += l[1]
		}
		if len(lines) != m.threads() || sum != [2]int{1, 1} {
			return fmt.Errorf("地址变化行 %v，期望 %d 行、kept 合计 tcp=1 udp=1", lines, m.threads())
		}
		return nil
	})
	changedAt := time.Now()
	// 旧连接与旧会话留在旧后端，此时 tinymapper 持有 UDP 监听 socket（M2：每个 worker 一个）和旧会话的 socket
	if want := m.threads() + 1; udpSockets(m.pid()) != want {
		t.Errorf("地址变化后 tinymapper 持有 %d 个 UDP socket，期望 %d（%d 个监听 socket 与旧会话）", udpSockets(m.pid()), want, m.threads())
	}
	// 跨过变化后 dns_refresh_interval 的那次定时检查（30 s，worker_tick 每 400 ms）一直收发：旧后端正常，旧连接与旧会话都不关
	for i := 0; time.Since(changedAt) < 32*time.Second; i++ {
		mustEcho(t, old, fmt.Sprintf("old-%d", i))
		if got := udpReplyFrom(t, udp, fmt.Sprintf("old-%d", i)); got != "2" {
			t.Fatalf("地址变化后 %v 旧 UDP 会话发往后端 %q，期望仍为旧后端 2", time.Since(changedAt).Round(time.Second), got)
		}
		time.Sleep(time.Second)
	}
	m.fatalIfExited(t, "地址变化后的定时检查")
	if n := m.logLines("old address check"); n != 0 {
		t.Errorf("旧后端正常，定时检查却关掉了连接（%d 行 old address check）", n)
	}
	for i := 0; i < 2; i++ {
		c := dial(t, listen)
		if got := readLine(t, c); got != "3" {
			t.Fatalf("地址变化后新连接连到后端 %q", got)
		}
		mustEcho(t, c, "new")
	}
	if got := udpReplyFrom(t, udpDial(t, "", listen), "new"); got != "3" {
		t.Fatalf("地址变化后新的 UDP 客户端发往后端 %q", got)
	}
	if s := m.statsAfterSignal(t).udp[1]; s.sessions != 2 || s.total != 2 {
		t.Errorf("统计 udp sessions=%d total=%d，期望 2/2（旧会话留下，新客户端一个新会话）", s.sessions, s.total)
	}
}

// loAlias4Mu 串行化 loAlias4 的加地址：SIOCSIFADDR 先按类别装成 /24，两个并行用例同一 /24 的地址这时会成为对方的从地址，
// 随后改掩码删掉主地址时连同从地址一起删掉（promote_secondaries 默认关）
var loAlias4Mu sync.Mutex

// loAlias4 在 lo 上加 IPv4 地址 a/32（标签 lo:<最后一字节>），返回删掉它的函数，用例结束时也删。SIOCSIFADDR 之后 SIOCSIFNETMASK 改成 /32
// （192.0.2.0/24 是 TEST-NET-1，别的用例不用）；IPv4 没有 SIOCDIFADDR，删除用不带 IFF_UP 的 SIOCSIFFLAGS：devinet_ioctl 对带冒号的标签
// 据此删掉这个地址（inet_del_ifa）。删除后绑定这个地址返回 EADDRNOTAVAIL；加删要 CAP_NET_ADMIN（needNetAdmin）
func loAlias4(t testing.TB, a [4]byte) func() {
	t.Helper()
	needNetAdmin(t)
	label := fmt.Sprintf("lo:%d", a[3])
	do := func(req uintptr, sin []byte) error {
		s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(s)
		var r [40]byte // struct ifreq：ifr_name[16]，联合体从偏移 16 起
		copy(r[:15], label)
		if sin != nil {
			binary.NativeEndian.PutUint16(r[16:], syscall.AF_INET) // struct sockaddr_in，sin_addr 在偏移 20；SIOCSIFFLAGS 时 ifr_flags 为 0
			copy(r[20:24], sin)
		}
		return ioctl(s, req, unsafe.Pointer(&r[0]))
	}
	func() {
		loAlias4Mu.Lock()
		defer loAlias4Mu.Unlock()
		if err := do(siocSIFAddr, a[:]); err != nil {
			t.Fatalf("SIOCSIFADDR %s %v 失败：%v", label, a, err)
		}
		if err := do(siocSIFNetmsk, []byte{255, 255, 255, 255}); err != nil {
			t.Fatalf("SIOCSIFNETMASK %s 失败：%v", label, err)
		}
	}()
	var once sync.Once
	del := func() {
		once.Do(func() {
			if err := do(siocSIFFlags, nil); err != nil {
				t.Errorf("删除 %s 失败：%v", label, err)
			}
		})
	}
	t.Cleanup(del)
	return del
}

// 审查 #9：域名地址变化后，连在旧地址上的连接对与会话不可用时才关（remote_sweep）。旧后端在 lo 的别名地址上，删掉这个地址模拟后端消失：
// tinymapper 的上游 TCP socket 的源地址也是它，删掉后待发数据发不出去、走零窗口探测定时器（tcpi_probes 每次加一，约 1.5 s 到 3）；
// UDP 客户端的包等不到回包。客户端一直发：TCP 每 100 ms 写 100 字节，UDP 每 500 ms 一包。两种情况下客户端的 TCP 连接都被关闭，
// UDP 客户端的下一个包建新会话到新地址；被释放的连接对与会话关掉 socket、归还对象池：
//   - atchange：改 /etc/hosts 后马上删地址，DNS 变化时就关掉（变化行 closed unresponsive tcp=1 udp=1，UDP 的包已等了 10 s 以上）；
//   - periodic：DNS 变化时旧后端正常（kept tcp=1 udp=1），之后才删地址，由变化后 dns_refresh_interval 的定时检查关掉（old address check 行）
func TestDomainRefreshUnresponsive(t *testing.T) {
	t.Parallel()
	inContainer(t)
	for i, mode := range []string{"atchange", "periodic"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			domainUnresponsive(t, mode, byte(1+4*i))
		})
	}
}

// domainUnresponsive：旧后端 192.0.2.<last>，新后端 192.0.2.<last+1>（hostsEntry 只改地址的最后一个字符，last 为 1–8）
func domainUnresponsive(t *testing.T, mode string, last byte) {
	name := "tpm-unresp-" + mode + ".test"
	oldIP, newIP := net.IPv4(192, 0, 2, last), net.IPv4(192, 0, 2, last+1)
	delOld := loAlias4(t, [4]byte(oldIP.To4()))
	loAlias4(t, [4]byte(newIP.To4()))
	bport := freePort(t)
	serveTCP(t, hostPort(oldIP.String(), bport), echoHandler("old\n"))
	serveUDP(t, hostPort(oldIP.String(), bport), "old")
	serveTCP(t, hostPort(newIP.String(), bport), echoHandler("new\n"))
	serveUDP(t, hostPort(newIP.String(), bport), "new")
	setLast := hostsEntry(t, oldIP.String(), name)
	listen := loopback4(t)
	m := forward(t, "tu", listen, fmt.Sprintf("%s:%d", name, bport))

	c := dial(t, listen)
	if got := readLine(t, c); got != "old" {
		t.Fatalf("启动时应连到旧后端 %s，实际 %q", oldIP, got)
	}
	u := udpDial(t, "", listen)
	if got := udpReplyFrom(t, u, "before"); got != "old" {
		t.Fatalf("启动时 UDP 应发往旧后端 %s，实际 %q", oldIP, got)
	}
	start := time.Now()
	setLast('0' + last + 1)
	sum := func(re *regexp.Regexp) (n int, s [2]int) {
		for _, l := range changedLines(m, re) {
			n++
			s[0] += l[0]
			s[1] += l[1]
		}
		return
	}
	prefix := `domain ` + regexp.QuoteMeta(name) + `:\d+ `
	changed := regexp.MustCompile(prefix + `changed from ` + regexp.QuoteMeta(oldIP.String()) + `:\d+ to ` + regexp.QuoteMeta(newIP.String()) +
		`:\d+, closed unresponsive tcp=(\d+) udp=(\d+), kept tcp=\d+ udp=\d+$`)
	kept := regexp.MustCompile(prefix + `changed from \S+ to \S+, closed unresponsive tcp=0 udp=0, kept tcp=(\d+) udp=(\d+)$`)
	periodic := regexp.MustCompile(prefix + `old address check: closed unresponsive tcp=(\d+) udp=(\d+), kept tcp=0 udp=0$`)
	if mode == "periodic" {
		eventually(t, 50*time.Second, 200*time.Millisecond, func() error {
			if n, s := sum(kept); n != m.threads() || s != [2]int{1, 1} {
				return fmt.Errorf("还没看到 %d 行留下旧连接与旧会话的地址变化（kept 合计 %v）", m.threads(), s)
			}
			return nil
		})
		t.Logf("修改 /etc/hosts 后 %v 看到地址变化，旧连接与旧会话都留下", time.Since(start).Round(time.Millisecond))
		mustEcho(t, c, "still")
		if got := udpReplyFrom(t, u, "still"); got != "old" {
			t.Fatalf("地址变化后旧 UDP 会话发往 %q，期望仍为旧后端", got)
		}
	}
	delOld()
	deleted := time.Now()
	if l, err := net.Listen("tcp4", hostPort(oldIP.String(), 0)); err == nil {
		l.Close()
		t.Fatalf("SIOCSIFFLAGS 没有删掉 %s：还能绑定", oldIP)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := c.Write(make([]byte, 100)); err != nil {
				return
			}
		}
	}()
	tcpClosed := make(chan time.Duration, 1)
	go func() {
		c.SetReadDeadline(time.Now().Add(80 * time.Second))
		n, err := c.Read(make([]byte, 4096))
		if n > 0 || isTimeout(err) {
			tcpClosed <- -1
			return
		}
		tcpClosed <- time.Since(deleted)
	}()
	var udpNew time.Duration
	eventually(t, 80*time.Second, 0, func() error {
		got, err := udpTry(u, []byte("ping"), 500*time.Millisecond, 1)
		if err != nil {
			return err
		}
		if p := strings.TrimSuffix(string(got), "ping"); p != "new" {
			return fmt.Errorf("UDP 回包来自 %q", p)
		}
		udpNew = time.Since(deleted)
		return nil
	})
	var tcpAfter time.Duration
	select {
	case tcpAfter = <-tcpClosed:
	case <-time.After(ioTimeout):
		t.Fatal("UDP 已换到新地址，TCP 连接还没关")
	}
	if tcpAfter < 0 {
		t.Fatal("旧 TCP 连接收到数据或 80 s 内没有关闭")
	}
	re := changed
	if mode == "periodic" {
		re = periodic
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if _, s := sum(re); s != [2]int{1, 1} {
			return fmt.Errorf("关掉旧连接与旧会话的日志行合计 %v，期望 tcp=1 udp=1", s)
		}
		return nil
	})
	t.Logf("%s：修改 /etc/hosts 后 %v、删地址后 %v 关掉 TCP 连接，删地址后 %v UDP 换到新地址",
		mode, (tcpAfter + deleted.Sub(start)).Round(time.Millisecond), tcpAfter.Round(time.Millisecond), udpNew.Round(time.Millisecond))

	// T10：释放的旧会话要关掉 socket，此时 tinymapper 只持有 UDP 监听 socket（每个 worker 一个）和新会话的 socket
	want := m.threads() + 1
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if got := udpSockets(m.pid()); got != want {
			return fmt.Errorf("旧会话释放后 tinymapper 持有 %d 个 UDP socket，期望 %d：被释放的旧会话没有关闭 socket", got, want)
		}
		return nil
	})
	// 被释放的连接对与会话的 fd 号随后被新 socket 复用：再建两条 TCP 连接各往返一次，旧会话的 watcher 若没有 stop，
	// 新 socket 上的事件也会回调到已释放的会话（ASan 报 heap-use-after-free，release 构建里数据被它取走）
	for i := 0; i < 2; i++ {
		nc := dial(t, listen)
		if got := readLine(t, nc); got != "new" {
			t.Fatalf("地址变化后新连接连到后端 %q", got)
		}
		mustEcho(t, nc, "reuse")
	}
	// O1：释放的旧会话与连接对都要归还对象池（statsAfterSignal 复核池不变式）；同一客户端新建一个会话
	if s := m.statsAfterSignal(t).udp[1]; s.sessions != 1 || s.total != 2 {
		t.Errorf("统计 udp sessions=%d total=%d，期望 1/2", s.sessions, s.total)
	}
}

// 审查 Medium #8（D92）：解析结果超过 16 条时，当前地址被 RRset 轮转排到前 16 条之外、但仍在结果里，不算地址变化；
// 真的从结果里消失才切换。四条规则在同一轮刷新：rot 把当前地址轮转到下标 17，gone 删掉当前地址，mark 是单条记录的标记域名。
// rot 被两条后端端口不同的规则引用，合并为一次查询（D108），第二条的当前地址要换成第一条的端口再在结果里找。
// 三个域名的查询同时入队、分在不同的 DNS 线程上（D108），结果到达的先后不定：等 gone 与 mark 的 changed from 都到齐，rot 没有日志可等，
// 再等 2 s（三个都是 /etc/hosts 里的名字，毫秒级返回）
func TestDomainRefreshLargeRRset(t *testing.T) {
	t.Parallel()
	inContainer(t)
	const rot, gone, mark = "tpm-rrset-rot.test", "tpm-rrset-gone.test", "tpm-rrset-mark.test"
	ips := func(c, n int) []string {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, fmt.Sprintf("127.0.%d.%d", c, 10+i))
		}
		return s
	}
	rotIPs, goneIPs := ips(9, 20), ips(10, 21) // goneIPs[20] 是删除后顶替的地址
	bport, bport2 := freePort(t), freePort(t)
	for _, ip := range append(slices.Clone(rotIPs), goneIPs...) {
		serveTCP(t, hostPort(ip, bport), echoHandler(ip+"\n"))
	}
	for _, ip := range rotIPs {
		serveTCP(t, hostPort(ip, bport2), echoHandler(ip+"\n"))
	}
	setRot := hostsBlock(t, rot, rotIPs)
	setGone := hostsBlock(t, gone, goneIPs[:20])
	setMark := hostsEntry(t, "127.0.11.2", mark)
	lRot, lRot2, lGone, lMark := loopback4(t), loopback4(t), loopback4(t), loopback4(t)
	var cfg strings.Builder
	var wait []listenPoint
	for _, e := range []struct {
		listen, host string
		port         int
	}{{lRot, rot, bport}, {lRot2, rot, bport2}, {lGone, gone, bport}, {lMark, mark, bport}} {
		fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = \"%s:%d\"\n\n", e.listen, e.host, e.port)
		wait = append(wait, listenPoints("t", portOf(e.listen))...)
	}
	m := startMapper(t, wait, "-c", writeConfig(t, cfg.String()))
	start := time.Now()

	oldRot, oldGone := dial(t, lRot), dial(t, lGone)
	if got := readLine(t, oldRot); got != rotIPs[0] {
		t.Fatalf("启动时 %s 应解析到 %s，实际连到后端 %q", rot, rotIPs[0], got)
	}
	if got := readLine(t, oldGone); got != goneIPs[0] {
		t.Fatalf("启动时 %s 应解析到 %s，实际连到后端 %q", gone, goneIPs[0], got)
	}

	setRot(append(slices.Clone(rotIPs[3:]), rotIPs[:3]...))
	setGone(append([]string{goneIPs[20]}, goneIPs[1:20]...))
	setMark('3')
	workers := m.threads()
	eventually(t, 50*time.Second, 500*time.Millisecond, func() error {
		for _, name := range []string{gone, mark} {
			if got := m.logLines("domain "+name+":", "changed from"); got < workers {
				return fmt.Errorf("%s 的 changed from 有 %d 行，应有 %d 行", name, got, workers)
			}
		}
		return nil
	})
	t.Logf("修改 /etc/hosts 后 %v 内完成一轮刷新", time.Since(start).Round(time.Second))
	time.Sleep(2 * time.Second)

	// rot 这一轮解析失败时只记一行 warn、保留当前地址，下面的断言会空过
	if got := m.logLines("domain "+rot+":", "resolve failed"); got != 0 {
		t.Fatalf("%s 解析失败（%d 行）：\n%s", rot, got, m.logTail(10))
	}
	if got := m.logLines("domain "+rot+":", "changed from"); got != 0 {
		t.Fatalf("%s 的当前地址轮转到下标 17（仍在解析结果里），却被当作地址变化（%d 行）：\n%s", rot, got, m.logTail(10))
	}
	mustEcho(t, oldRot, "still")
	for _, l := range []string{lRot, lRot2} {
		if got := readLine(t, dial(t, l)); got != rotIPs[0] {
			t.Fatalf("%s 经 %s 的新连接应仍连到 %s，实际 %q", rot, l, rotIPs[0], got)
		}
	}

	if got := m.logLines("domain "+gone+":", "changed from "+goneIPs[0]+":", "to "+goneIPs[20]+":"); got != workers {
		t.Fatalf("%s 的当前地址被删除后应有 %d 行 changed from，实际 %d 行：\n%s", gone, workers, got, m.logTail(10))
	}
	// D94：旧后端仍在服务，连往它的旧连接留着（每个 worker 一行，kept 合计 tcp=1）。后端消失时关闭由 TestDomainRefreshUnresponsive 覆盖：
	// 127/8 的地址删不掉，停掉后端会发 FIN，连接对在 tcp_cb 里就关了
	goneChanged := regexp.MustCompile(`domain ` + regexp.QuoteMeta(gone) + `:\d+ changed from \S+ to \S+, closed unresponsive tcp=0 udp=0, kept tcp=(\d+) udp=(\d+)$`)
	lines := changedLines(m, goneChanged)
	var kept [2]int
	for _, l := range lines {
		kept[0] += l[0]
		kept[1] += l[1]
	}
	if len(lines) != workers || kept != [2]int{1, 0} {
		t.Fatalf("%s 的地址变化行 %v，期望 %d 行、kept 合计 tcp=1 udp=0：\n%s", gone, lines, workers, m.logTail(10))
	}
	mustEcho(t, oldGone, "still")
	if got := readLine(t, dial(t, lGone)); got != goneIPs[20] {
		t.Fatalf("%s 的新连接应连到 %s，实际 %q", gone, goneIPs[20], got)
	}
}

// fakeDNS 是 127.0.0.1:53 上的进程内假 DNS（UDP，手拼报文，TTL 0）：a 里的名字答一条 A 记录、AAAA 答 NODATA，drop 里的名字不回，
// tc 里的名字答 TC=1 的空应答（解析器改走 TCP），其他名字 NXDOMAIN；aq 按名字记收到的 A 查询数
type fakeDNS struct {
	mu   sync.Mutex
	a    map[string]net.IP
	drop map[string]bool
	tc   map[string]bool
	aq   map[string]int
}

// startFakeDNS 启动 fakeDNS，把容器的 /etc/resolv.conf 原地改成只用它、每次查询最多等 30 s（timeout:30 attempts:1，glibc 与 musl
// 都是不回时等满 30 s 返回失败），用例结束时改回。改写 /etc/resolv.conf、占用 127.0.0.1:53 的用例不能并行：
// 并行的用例解析 /etc/hosts 之外的名字时会被它卡住
func startFakeDNS(t testing.TB) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	d := &fakeDNS{a: map[string]net.IP{}, drop: map[string]bool{}, tc: map[string]bool{}, aq: map[string]int{}}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := d.reply(buf[:n]); r != nil {
				pc.WriteTo(r, src)
			}
		}
	}()
	useLocalResolver(t)
	return d
}

func (d *fakeDNS) reply(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return nil
		}
		l := int(q[i])
		i++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || i+l > len(q) {
			return nil
		}
		labels = append(labels, strings.ToLower(string(q[i:i+l])))
		i += l
	}
	if i+4 > len(q) {
		return nil
	}
	name, qtype, qend := strings.Join(labels, "."), binary.BigEndian.Uint16(q[i:]), i+4
	d.mu.Lock()
	ip, ok := d.a[name]
	drop, tc := d.drop[name], d.tc[name]
	if qtype == 1 {
		d.aq[name]++
	}
	d.mu.Unlock()
	if drop {
		return nil
	}
	r := make([]byte, 12, 512)
	copy(r, q[:2])
	r[2] = 0x80 | q[2]&0x79 | 0x04 // QR，沿用 opcode 与 RD，AA
	r[3] = 0x80                    // RA
	if !ok {
		r[3] |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(r[4:], 1)
	r = append(r, q[12:qend]...)
	if tc {
		r[2] |= 0x02
		return r
	}
	if ok && qtype == 1 {
		binary.BigEndian.PutUint16(r[6:], 1)
		r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4) // 指回问题里的名字，A，IN，TTL 0
		r = append(r, ip.To4()...)
	}
	return r
}

// 审查 Low（D108）：一个域名的查询很慢时，别的域名照常每 30 s 刷新。四条规则：slow.hol.test 被规则 1、2 引用，mover.hol.test 被规则 3、4
// 引用（各规则端口不同）；启动时都正常应答，之后 slow 不再回（每次查询等满 30 s），mover 的 A 记录从 127.0.3.1 换到 127.0.3.2。
// 修复前所有请求在一个 DNS 线程里按（规则，remote）依次各查一次，mover 要排在 slow 的两次超时之后，约 90 s 才换地址；
// 修复后同一域名合并为一次查询、不同域名在不同线程上查，mover 在第一轮刷新（约 30 s，slow 的查询还没返回）就换，这一轮只收到一个 A 查询，
// 两条规则的新连接都连到 127.0.3.2。改写 /etc/resolv.conf，不并行（startFakeDNS）
func TestDomainRefreshSlowHost(t *testing.T) {
	inContainer(t)
	const slowName, mover = "slow.hol.test", "mover.hol.test"
	d := startFakeDNS(t)
	d.mu.Lock()
	d.a[slowName] = net.IPv4(127, 0, 3, 9)
	d.a[mover] = net.IPv4(127, 0, 3, 1)
	d.mu.Unlock()
	var listens [4]string
	var ports [4]int
	var cfg strings.Builder
	var wait []listenPoint
	for i := range listens {
		name := slowName
		listens[i], ports[i] = loopback4(t), freePort(t)
		if i >= 2 {
			name = mover
			for _, id := range []string{"1", "2"} {
				serveTCP(t, hostPort("127.0.3."+id, ports[i]), echoHandler(id+"\n"))
			}
		}
		fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = \"%s:%d\"\n\n", listens[i], name, ports[i])
		wait = append(wait, listenPoints("t", portOf(listens[i]))...)
	}
	m := startMapper(t, wait, "-c", writeConfig(t, cfg.String()))
	for i := 2; i < 4; i++ {
		if got := readLine(t, dial(t, listens[i])); got != "1" {
			t.Fatalf("启动时规则 %d 应连到 127.0.3.1，实际连到后端 %q", i+1, got)
		}
	}
	d.mu.Lock()
	d.drop[slowName] = true
	d.a[mover] = net.IPv4(127, 0, 3, 2)
	d.aq[slowName], d.aq[mover] = 0, 0
	d.mu.Unlock()
	start := time.Now()

	workers := m.threads()
	changed := func(i int) string {
		return fmt.Sprintf("rule %d remote 1 domain %s:%d changed from 127.0.3.1:%d to 127.0.3.2:%d,", i+1, mover, ports[i], ports[i], ports[i])
	}
	eventually(t, 45*time.Second, 200*time.Millisecond, func() error {
		for i := 2; i < 4; i++ {
			if got := m.logLines(changed(i)); got < workers {
				return fmt.Errorf("规则 %d 的 changed from 有 %d 行，应有 %d 行（每个 worker 一行）", i+1, got, workers)
			}
		}
		return nil
	})
	t.Logf("改应答后 %v 两条规则都换到新地址", time.Since(start).Round(time.Second))
	time.Sleep(time.Second) // 再等两个定时器周期：这一轮不能再查 mover，也不能广播两次
	d.mu.Lock()
	aSlow, aMover := d.aq[slowName], d.aq[mover]
	d.mu.Unlock()
	if aMover != 1 {
		t.Errorf("这一轮 %s 收到 %d 个 A 查询，期望 1 个（规则 3、4 合并为一次查询）", mover, aMover)
	}
	if aSlow == 0 || m.logLines("domain "+slowName+":", "resolve failed") != 0 {
		t.Fatalf("%s 在这一轮应已查询、还没超时（A 查询 %d 个），用例没有测到慢查询：\n%s", slowName, aSlow, m.logTail(10))
	}
	for i := 2; i < 4; i++ {
		if got := m.logLines(changed(i)); got != workers {
			t.Errorf("规则 %d 的 changed from 有 %d 行，期望恰好 %d 行", i+1, got, workers)
		}
		if got := readLine(t, dial(t, listens[i])); got != "2" {
			t.Fatalf("地址变化后规则 %d 的新连接连到后端 %q，期望 127.0.3.2", i+1, got)
		}
	}
}

// D109：一个域名的查询在途超过 2 个刷新周期时记一行 warn（每次卡住只记一行），结果到达时记一行 info。启动后 UDP 应答改为
// TC=1，glibc 改走 TCP，假 DNS 接受连接但不回：glibc 的 TCP 读没有超时，查询一直不返回。看到 warn 后关掉 TCP 监听与连接，查询失败返回。
// musl 的 TCP 回退也算在 timeout 里，每次查询最多 30 s，卡不到 2 个刷新周期，只在 glibc 上测。约 95 s。改写 /etc/resolv.conf，不并行
func TestDomainRefreshStuckWarn(t *testing.T) {
	slow(t)
	inContainer(t)
	if os.Getenv("TPM_VARIANT") != "glibc" {
		t.Skip("musl 每次查询最多等 timeout（含 TCP 回退），查询卡不住")
	}
	const name = "stuck.hol.test"
	ln, err := net.Listen("tcp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	release := func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	}
	t.Cleanup(release)
	d := startFakeDNS(t)
	d.mu.Lock()
	d.a[name] = net.IPv4(127, 0, 3, 9)
	d.mu.Unlock()
	m := forward(t, "t", loopback4(t), fmt.Sprintf("%s:%d", name, freePort(t)))
	d.mu.Lock()
	d.tc[name] = true
	d.mu.Unlock()
	start := time.Now()

	warn := regexp.MustCompile(`domain ` + regexp.QuoteMeta(name) + `: no lookup result for (\d+) s, keeping current address$`)
	warnLines := func() []string {
		data, _ := os.ReadFile(m.logPath)
		var s []string
		for _, line := range strings.Split(string(data), "\n") {
			if w := warn.FindStringSubmatch(line); w != nil {
				s = append(s, w[1])
			}
		}
		return s
	}
	eventually(t, 100*time.Second, 200*time.Millisecond, func() error {
		if len(warnLines()) == 0 {
			return fmt.Errorf("没有 no lookup result 行：\n%s", m.logTail(5))
		}
		return nil
	})
	t.Logf("改应答后 %v 记 warn", time.Since(start).Round(time.Second))
	time.Sleep(time.Second) // 再等两个定时器周期：同一次卡住只记一行
	if w := warnLines(); len(w) != 1 || (w[0] != "60" && w[0] != "61") {
		t.Errorf("warn 行等待秒数 %v，期望恰好一行、60 s", w)
	}
	mu.Lock()
	n := len(held)
	mu.Unlock()
	if n == 0 || m.logLines("domain "+name+":", "resolve failed") != 0 {
		t.Fatalf("查询应卡在 TCP 上（%d 条连接）、还没返回：\n%s", n, m.logTail(10))
	}
	release()
	eventually(t, 10*time.Second, 100*time.Millisecond, func() error {
		if m.logLines("domain "+name+": lookup returned after 6") != 1 || m.logLines("domain "+name+":", "resolve failed") != 1 {
			return fmt.Errorf("关掉 TCP 连接后应各有一行 lookup returned after 6x s 与 resolve failed：\n%s", m.logTail(5))
		}
		return nil
	})
}

// udpSockets 返回进程 pid 持有的 UDP socket 个数（sock_diag 列出的 IPv4、IPv6 UDP socket 中 inode 属于该进程的；原来读 /proc/net/udp，
// 与上万个 UDP socket 的用例并行时又慢又会漏行）
func udpSockets(pid int) int {
	inodes := socketInodes(pid)
	n := 0
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		sockDiagDump(family, syscall.IPPROTO_UDP, ^uint32(0), func(_, _ uint16, inode uint32) {
			if inodes[strconv.FormatUint(uint64(inode), 10)] {
				n++
			}
		})
	}
	return n
}

// swrr 复刻 select_remote_index 的平滑加权轮询，返回前 n 次的选择
func swrr(weights []int, n int) []int {
	cur := make([]int, len(weights))
	total := 0
	for _, w := range weights {
		total += w
	}
	out := make([]int, n)
	for k := range out {
		best := -1
		for i, w := range weights {
			cur[i] += w
			if best < 0 || cur[i] > cur[best] {
				best = i
			}
		}
		cur[best] -= total
		out[k] = best
	}
	return out
}

// sdbm 与 common.cpp 中的实现一致
func sdbm(b []byte) uint32 {
	var h uint32
	for _, c := range b {
		h = uint32(c) + (h << 6) + (h << 16) - h
	}
	return h
}

// iphashIndex 复刻 iphash：对客户端 in_addr/in6_addr 原始字节做 sdbm，按权重分桶
func iphashIndex(ip net.IP, weights []int) int {
	total := 0
	for _, w := range weights {
		total += w
	}
	bucket := int(sdbm(ip) % uint32(total))
	for i, w := range weights {
		if bucket < w {
			return i
		}
		bucket -= w
	}
	panic("unreachable")
}

// balancedBackends 启动 n 个后端（TCP banner 与 UDP 前缀均为其序号），返回 -r 参数
func balancedBackends(t testing.TB, n int) []string {
	var remotes []string
	for i := range n {
		addr := loopback4(t)
		serveTCP(t, addr, echoHandler(fmt.Sprint(i)+"\n"))
		serveUDP(t, addr, fmt.Sprint(i))
		remotes = append(remotes, addr)
	}
	return remotes
}

func weightsSpec(strategy string, weights []int) string {
	var s []string
	for _, w := range weights {
		s = append(s, fmt.Sprint(w))
	}
	return strategy + ": " + strings.Join(s, ", ")
}

func balanceArgs(listen string, remotes []string, balance string, proto string) []string {
	args := []string{"-l", listen, "--balance", balance}
	for _, r := range remotes {
		args = append(args, "-r", r)
	}
	return append(args, protoFlags(proto)...)
}

// 平滑加权轮询的选择序列与 nginx 算法完全一致（因此比例精确）
func TestBalanceRoundRobin(t *testing.T) {
	t.Parallel()
	for _, weights := range [][]int{{2, 1, 1}, {3, 1, 2}, {1, 1}} {
		t.Run(fmt.Sprint(weights), func(t *testing.T) {
			t.Parallel()
			listen := loopback4(t)
			remotes := balancedBackends(t, len(weights))
			startMapper(t, listenPoints("t", portOf(listen)), balanceArgs(listen, remotes, weightsSpec("roundrobin", weights), "t")...)
			want := swrr(weights, 12*len(weights))
			got := make([]int, len(want))
			for i := range got {
				c := dial(t, listen)
				fmt.Sscan(readLine(t, c), &got[i])
				c.Close()
			}
			if !slices.Equal(got, want) {
				t.Fatalf("选择序列 = %v，期望 %v", got, want)
			}
		})
	}
}

// TCP 与 UDP 共享同一规则的轮询状态：交替建立 TCP 连接和 UDP 会话时按同一序列推进
func TestBalanceRoundRobinSharedTCPUDP(t *testing.T) {
	t.Parallel()
	weights := []int{2, 1, 1}
	listen := loopback4(t)
	remotes := balancedBackends(t, len(weights))
	startMapper(t, listenPoints("tu", portOf(listen)), balanceArgs(listen, remotes, weightsSpec("roundrobin", weights), "tu")...)
	want := swrr(weights, 16)
	got := make([]int, len(want))
	for i := range got {
		var id string
		if i%2 == 0 {
			c := dial(t, listen)
			id = readLine(t, c)
			c.Close()
		} else {
			id = udpReplyFrom(t, udpDial(t, "", listen), "x")
		}
		fmt.Sscan(id, &got[i])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("TCP/UDP 交替时的选择序列 = %v，期望 %v", got, want)
	}
}

// D85：多个 worker 共用规则的一个选择序列（原子计数取一个周期的平滑加权轮询表），第 k 次选择与 threads=1 时的第 k 次相同，与连接、会话
// 散列到哪个 worker 无关。自带 --threads 4（默认的 threads=1 套件也跑到），TCP 与 UDP 同一个监听地址：先顺序建 8 个 UDP 会话（每个一个
// 新 socket，源端口各不相同），再顺序建 8 条 TCP 连接、一直开到最后，16 次选择恰好是 swrr([1, 1], 16)。之后从统计核对 UDP 会话确实分到
// 了至少 2 个 worker（8 个会话都落在 4 个 worker 中同一个的概率 4×(1/4)^8 ≈ 6e-5），否则序列对了也说明不了跨 worker。修复前每个 worker
// 一份从 current_weight=0 起的轮询状态，几个长连接多半都落到 remote 0（审查 Medium #5）。UDP 组不挂 cBPF（D73），TPM_AFFINITY=1 时也按
// 哈希分；TCP 可能按 CPU 分流，不影响序列
func TestBalanceRoundRobinWorkers(t *testing.T) {
	t.Parallel()
	const n = 4
	affinityTooMany(t, n)
	weights := []int{1, 1}
	listen := loopback4(t)
	remotes := balancedBackends(t, len(weights))
	m := startMapper(t, listenPoints("tu", portOf(listen)),
		append(balanceArgs(listen, remotes, weightsSpec("roundrobin", weights), "tu"), "--threads", strconv.Itoa(n))...)
	want := swrr(weights, 16)
	got := make([]int, len(want))
	for i := range got {
		var id string
		if i < len(got)/2 {
			id = udpReplyFrom(t, udpDial(t, "", listen), "x")
		} else {
			id = readLine(t, dial(t, listen)) // dial 的连接到用例结束才关
		}
		fmt.Sscan(id, &got[i])
	}
	d := m.statsAfterSignal(t)
	t.Logf("选择序列 %v；worker 行 %+v", got, d.workers)
	if !slices.Equal(got, want) {
		t.Errorf("%d 个 worker 时的选择序列（前 8 个 UDP、后 8 个 TCP）= %v，期望 %v", n, got, want)
	}
	if k := busyWorkers(d, "udp"); k < 2 {
		t.Errorf("8 个 UDP 会话只分到了 %d 个 worker（worker 行 %+v），期望至少 2 个", k, d.workers)
	}
}

// iphash：同一客户端 IP 总落在 sdbm(地址字节) 按权重分桶的那个后端；TCP 与 UDP 一致
func TestBalanceIPHash(t *testing.T) {
	t.Parallel()
	weights := []int{1, 2, 3}
	for _, c := range []struct {
		name   string
		listen string
		mapped bool // 双栈监听时 IPv4 客户端以 ::ffff:a.b.c.d 出现，按 16 字节计算
	}{
		{"ipv4_listen", "127.0.0.1", false},
		{"dualstack_listen", "::", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			listen := hostPort(c.listen, freePort(t))
			target := hostPort("127.0.0.1", portOf(listen))
			remotes := balancedBackends(t, len(weights))
			startMapper(t, listenPoints("tu", portOf(listen)), balanceArgs(listen, remotes, weightsSpec("iphash", weights), "tu")...)
			buckets := map[int]bool{}
			for x := 1; x <= 24; x++ {
				ip := net.IPv4(127, 0, 0, byte(x))
				key := ip.To4()
				if c.mapped {
					key = ip.To16()
				}
				want := iphashIndex(key, weights)
				buckets[want] = true
				for round := range 2 { // 同一 IP 的不同源端口结果相同
					tc := dialFrom(t, ip.String(), target)
					if got := readLine(t, tc); got != fmt.Sprint(want) {
						t.Fatalf("客户端 %s 第 %d 次 TCP 连到后端 %s，期望 %d", ip, round+1, got, want)
					}
					tc.Close()
				}
				if got := udpReplyFrom(t, udpDial(t, ip.String(), target), "x"); got != fmt.Sprint(want) {
					t.Fatalf("客户端 %s 的 UDP 发往后端 %s，期望 %d", ip, got, want)
				}
			}
			if len(buckets) != len(weights) {
				t.Fatalf("测试数据只覆盖了 %d 个后端", len(buckets))
			}
			if c.mapped {
				want := iphashIndex(net.IPv6loopback, weights)
				tc := dial(t, hostPort("::1", portOf(listen)))
				if got := readLine(t, tc); got != fmt.Sprint(want) {
					t.Fatalf("客户端 ::1 连到后端 %s，期望 %d", got, want)
				}
			}
		})
	}
}

// D98：拦截型 DNS（AdGuard Home default、Pi-hole NULL）与 hosts 黑名单把被拦截的域名解析为未指定地址。
// connect/sendto 到 0.0.0.0、::、::ffff:0.0.0.0 会落到本机回环的同号端口，所以这些地址要跳过；全是未指定地址时与 NXDOMAIN 一样算解析失败，
// 启动时退出
func TestDomainUnspecifiedStartup(t *testing.T) {
	t.Parallel()
	inContainer(t)
	for i, ip := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		name := fmt.Sprintf("tpm-unspec-%d.test", i)
		hostsEntry(t, ip, name)
		out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", fmt.Sprintf("%s:%d", name, freePort(t)), "-t", "-u")
		if !strings.Contains(out, "-r remote: only unspecified addresses") {
			t.Errorf("%s 解析为 %s：输出中没有 only unspecified addresses：\n%s", name, ip, out)
		}
	}
}

// D98：应答里同时有未指定地址与真实地址时只用真实地址。回环 127.0.0.1 上的同号端口放一个后端，连到它说明用了 0.0.0.0
func TestDomainUnspecifiedMixed(t *testing.T) {
	t.Parallel()
	inContainer(t)
	const name = "tpm-unspec-mixed.test"
	bport := freePort(t)
	for _, b := range [][2]string{{"127.0.0.1", "lo"}, {"127.0.0.2", "2"}} {
		serveTCP(t, hostPort(b[0], bport), echoHandler(b[1]+"\n"))
		serveUDP(t, hostPort(b[0], bport), b[1])
	}
	hostsEntry(t, "0.0.0.0", name)
	hostsEntry(t, "127.0.0.2", name)
	listen := loopback4(t)
	forward(t, "tu", listen, fmt.Sprintf("%s:%d", name, bport))
	if got := readLine(t, dial(t, listen)); got != "2" {
		t.Fatalf("应答里有 0.0.0.0 与 127.0.0.2，TCP 应连到 127.0.0.2，实际连到后端 %q", got)
	}
	if got := udpReplyFrom(t, udpDial(t, "", listen), "mixed"); got != "2" {
		t.Fatalf("应答里有 0.0.0.0 与 127.0.0.2，UDP 应发往 127.0.0.2，实际 %q", got)
	}
}

// D98：运行中域名被拦截（解析结果变成 0.0.0.0）时按解析失败处理：只记 resolve failed、保留当前地址，新连接与新会话仍去原来的后端，
// 旧连接不受影响。不能变成 changed from ... to 0.0.0.0（新连接会落到 127.0.0.1 的同号端口）
func TestDomainUnspecifiedRefresh(t *testing.T) {
	t.Parallel()
	inContainer(t)
	const name = "tpm-unspec-refresh.test"
	bport := freePort(t)
	for _, b := range [][2]string{{"127.0.0.1", "lo"}, {"127.0.0.2", "2"}} {
		serveTCP(t, hostPort(b[0], bport), echoHandler(b[1]+"\n"))
		serveUDP(t, hostPort(b[0], bport), b[1])
	}
	setIPs := hostsBlock(t, name, []string{"127.0.0.2"})
	listen := loopback4(t)
	m := forward(t, "tu", listen, fmt.Sprintf("%s:%d", name, bport))
	old := dial(t, listen)
	if got := readLine(t, old); got != "2" {
		t.Fatalf("启动时应解析到 127.0.0.2，实际连到后端 %q", got)
	}

	setIPs([]string{"0.0.0.0  "}) // 与 127.0.0.2 等长，行首偏移不变
	start := time.Now()
	eventually(t, 50*time.Second, 500*time.Millisecond, func() error {
		if n := m.logLines("domain "+name+":", "changed from"); n > 0 {
			return nil
		}
		if n := m.logLines("domain "+name+":", "resolve failed: only unspecified addresses", "keeping current address"); n == 0 {
			return fmt.Errorf("没有 resolve failed 行")
		}
		return nil
	})
	t.Logf("修改 /etc/hosts 后 %v 看到刷新结果", time.Since(start).Round(time.Second))
	if n := m.logLines("domain "+name+":", "changed from"); n != 0 {
		t.Fatalf("域名解析为 0.0.0.0 后被当作地址变化（%d 行）：\n%s", n, m.logTail(10))
	}
	mustEcho(t, old, "still")
	if got := readLine(t, dial(t, listen)); got != "2" {
		t.Fatalf("域名被拦截后新 TCP 连接应仍连到 127.0.0.2，实际连到后端 %q", got)
	}
	if got := udpReplyFrom(t, udpDial(t, "", listen), "after"); got != "2" {
		t.Fatalf("域名被拦截后新 UDP 会话应仍发往 127.0.0.2，实际 %q", got)
	}
}

// D99：当前地址后来在本机没有路由了（IPv6 上联掉线、v6 路由消失），DNS 仍返回它时也要换成可达的地址；以前只要还在解析结果里就一直用它。
// 域名同时有 127.0.0.2 与 lo 上的 2001:db8:99::1/128：两个都可达时 glibc、musl 都把 IPv6 排前（::/0 的 precedence 高于 IPv4），tinymapper 选 v6。
// 不用 newLoAddrs6 的 fd00::/8：musl 给 ULA 的 precedence 是 3，低于 IPv4，启动时就选 v4。删掉 v6 地址（本机路由随之消失）后，
// 下一次刷新（30 s）要换到 127.0.0.2
func TestDomainUnroutableCurrent(t *testing.T) {
	t.Parallel()
	inContainer(t)
	needNetAdmin(t)
	const name = "tpm-unroutable.test"
	v6 := netip.MustParseAddr("2001:db8:99::1")
	if err := setLoAddr6(true, v6); err != nil {
		t.Fatalf("在 lo 上加 %s/128 失败：%v", v6, err)
	}
	t.Cleanup(func() { setLoAddr6(false, v6) }) // 用例里已经删掉，再删报 EADDRNOTAVAIL，忽略
	waitLoAddr6(t, v6)
	bport := freePort(t)
	for _, b := range [][2]string{{v6.String(), "6"}, {"127.0.0.2", "4"}} {
		serveTCP(t, hostPort(b[0], bport), echoHandler(b[1]+"\n"))
		serveUDP(t, hostPort(b[0], bport), b[1])
	}
	hostsEntry(t, "127.0.0.2", name)
	hostsEntry(t, v6.String(), name)
	listen := loopback4(t)
	m := forward(t, "tu", listen, fmt.Sprintf("%s:%d", name, bport))
	if got := readLine(t, dial(t, listen)); got != "6" {
		t.Fatalf("两个地址都可达时应选 %s，实际连到后端 %q", v6, got)
	}

	if err := setLoAddr6(false, v6); err != nil {
		t.Fatalf("删除 %s 失败：%v", v6, err)
	}
	start := time.Now()
	eventually(t, 50*time.Second, 500*time.Millisecond, func() error {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		b := make([]byte, 2)
		if _, err := io.ReadFull(c, b); err != nil {
			return fmt.Errorf("%s 没有路由后新连接仍连不上：%v", v6, err)
		}
		if string(b) != "4\n" {
			return fmt.Errorf("新连接连到后端 %q", b[:1])
		}
		return nil
	})
	t.Logf("删除 %s 后 %v 内切换到 127.0.0.2", v6, time.Since(start).Round(time.Second))
	// 写到文件的日志每 400 ms 刷新一次
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if got, want := m.logLines("domain "+name+":", "changed from ["+v6.String()+"]:", "to 127.0.0.2:"), m.threads(); got != want {
			return fmt.Errorf("changed from [%s] to 127.0.0.2 有 %d 行，期望 %d 行", v6, got, want)
		}
		return nil
	})
	if got := udpReplyFrom(t, udpDial(t, "", listen), "after"); got != "4" {
		t.Fatalf("切换后新的 UDP 会话应发往 127.0.0.2，实际 %q", got)
	}
}
