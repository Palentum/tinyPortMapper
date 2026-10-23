package tests

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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

// sigtermExits 断言 tinymapper 收到 SIGTERM 后 2 s 内以状态 0 退出
func sigtermExits(t testing.TB, remote string) {
	t.Helper()
	m := forward(t, "tu", loopback4(t), remote)
	m.cmd.Process.Signal(syscall.SIGTERM)
	if m.aliveAfter(2 * time.Second) {
		t.Fatal("SIGTERM 后 2 s 内未退出")
	}
	m.stop(t, true)
	if m.exitErr != nil {
		t.Fatalf("SIGTERM 后退出状态异常：%v", m.exitErr)
	}
}

func TestSigtermExit(t *testing.T) {
	t.Parallel()
	sigtermExits(t, loopback4(t))
}

// 域名 remote 会启动 DNS 线程。已知缺陷 C8：glibc 构建在 exit() 析构 dns_cv 时阻塞，musl 不受影响
func TestSigtermExitDomain(t *testing.T) {
	t.Parallel()
	body := func(t testing.TB) { sigtermExits(t, fmt.Sprintf("localhost:%d", freePort(t))) }
	if os.Getenv("TPM_VARIANT") == "glibc" {
		xfail(t, "C8", body)
	} else {
		body(t)
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
		{"cli_bad_port_remote", []string{"-l", l, "-r", "127.0.0.1:70000", "-t"}, "", "invalid port"},
		{"cli_listen_no_port", []string{"-l", "127.0.0.1", "-r", r1, "-t"}, "", "failed to parse"},
		{"cli_listen_hostname", []string{"-l", "localhost:80", "-r", r1, "-t"}, "", "is not an ipv4 address"},
		{"cli_listen_not_local", []string{"-l", "192.0.2.1:80", "-r", r1, "-t"}, "", "bind failed"},
		{"cli_listen_busy", []string{"-l", busy.Addr().String(), "-r", r1, "-t"}, "", "bind failed"},
		{"cli_sock_buf", []string{"-l", l, "-r", r1, "-t", "--sock-buf", "5"}, "", "sock-buf value"},
		{"cli_log_level", []string{"--log-level", "9", "-l", l, "-r", r1, "-t"}, "", "invalid log_level"},
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
		{"toml_listen_hostname", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"localhost:%d\"\nremote = %q\n", portOf(l), r1), "invalid ipv4 address literal"},
		{"toml_listen_unbracketed_ipv6", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"::1:%d\"\nremote = %q\n", portOf(l), r1), "must be surrounded with []"},
		{"toml_listen_bad_port", []string{"-c", "CFG"}, fmt.Sprintf("[[endpoints]]\nlisten = \"127.0.0.1:70000\"\nremote = %q\n", r1), "port must be between 0 and 65535"},
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
