package tests

import (
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

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

// hostsEntry 在容器的 /etc/hosts 末尾追加 "ip name"，返回原地改写该 IP 最后一个字符的函数。
// 只做单次 pwrite，避免并发解析的其他进程读到截断的文件；测试结束时截回原长度。
func hostsEntry(t testing.TB, ip, name string) func(last byte) {
	t.Helper()
	f, err := os.OpenFile("/etc/hosts", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := f.Seek(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := ip + " " + name + "\n"
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
	t.Cleanup(func() {
		f.Truncate(orig)
		f.Close()
	})
	offset := orig + int64(len(line)-len(name)-3) // ip 最后一个字符的位置
	return func(b byte) {
		if _, err := f.WriteAt([]byte{b}, offset); err != nil {
			t.Fatal(err)
		}
	}
}

// 域名 remote 每 30 s 重新解析：地址变化后新连接改连新地址，连往旧地址的 TCP 连接和 UDP 会话被关闭
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
	forward(t, "tu", listen, fmt.Sprintf("%s:%d", name, bport))
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
	expectClosed(t, old, ioTimeout)
	if got := udpReplyFrom(t, udp, "after"); got != "3" {
		t.Fatalf("地址变化后旧 UDP 客户端仍发往后端 %q", got)
	}
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
