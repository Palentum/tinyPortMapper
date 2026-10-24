package tests

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// 各种包长（含大于 MTU 的包）原样往返
func TestUDPSizes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		host  string
		sizes []int
	}{
		{"127.0.0.1", []int{1, 64, 1472, 9000, 65507}},
		{"::1", []int{1, 64, 1452, 9000, 65527}},
	} {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			be := serveUDP(t, hostPort(c.host, freePort(t)), "")
			listen := hostPort(c.host, freePort(t))
			forward(t, "u", listen, be.addr)
			conn := udpDial(t, "", listen)
			for _, size := range c.sizes {
				msg := bytes.Repeat([]byte{byte(size)}, size)
				for i := range msg {
					msg[i] ^= byte(i * 31)
				}
				got, err := udpRoundTrip(conn, msg)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, msg) {
					t.Fatalf("%d 字节包回包不一致（收到 %d 字节）", size, len(got))
				}
			}
		})
	}
}

// 多客户端并发收发：每个客户端只收到自己的回包，上游为每个客户端建立独立会话
func TestUDPSessionIsolation(t *testing.T) {
	t.Parallel()
	const clients, packets = 16, 50
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	forward(t, "u", listen, be.addr)
	conns := make([]*net.UDPConn, clients)
	for i := range conns {
		conns[i] = udpDial(t, "", listen)
	}
	errs := make([]error, clients)
	parallelFor(clients, clients, func(i int) {
		for j := range packets {
			msg := fmt.Appendf(nil, "client-%02d-seq-%03d", i, j)
			got, err := udpRoundTrip(conns[i], msg)
			if err == nil && !bytes.Equal(got, msg) {
				err = fmt.Errorf("收到 %q，期望 %q", got, msg)
			}
			if err != nil {
				errs[i] = fmt.Errorf("客户端 %d 第 %d 个包：%w", i, j, err)
				return
			}
		}
	})
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if peers := be.peerList(); len(peers) != clients {
		t.Errorf("上游看到 %d 个源地址，期望每个客户端一个（%d）：%v", len(peers), clients, peers)
	}
}

// 空闲超过 conn_timeout_udp（180 s）的会话被清理，期间保持活跃的会话不受影响；
// 被清理的客户端再发包时，tinymapper 为它新建会话，上游看到新的源地址。
// 清理每轮最多关 1 条、约 1.2 s 一轮：活跃会话若也超时了（LRU 没把它挪到队首，或挪动时没刷新时间戳），
// 可能比空闲会话晚一轮才被清理，所以空闲会话被清理后再等 5 s 才检查活跃会话
func TestUDPSessionTimeout(t *testing.T) {
	t.Parallel()
	slow(t)
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	m := forward(t, "u", listen, be.addr)
	idle := udpDial(t, "", listen)
	active := udpDial(t, "", listen)
	roundTrip := func(c *net.UDPConn, msg string) {
		t.Helper()
		if _, err := udpRoundTrip(c, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	cleared := func(c *net.UDPConn) bool {
		data, _ := os.ReadFile(m.logPath)
		return strings.Contains(string(data), fmt.Sprintf("inactive connection {%s} cleared", c.LocalAddr()))
	}
	roundTrip(active, "active")
	roundTrip(idle, "idle")
	last := time.Now()
	keepalive := last
	for !cleared(idle) {
		if elapsed := time.Since(last); elapsed > 210*time.Second {
			t.Fatalf("空闲 %v 后会话仍未被清理（超时应为 180 s）", elapsed.Round(time.Second))
		}
		if time.Since(keepalive) >= 30*time.Second {
			roundTrip(active, "keepalive")
			keepalive = time.Now()
		}
		time.Sleep(time.Second)
	}
	elapsed := time.Since(last)
	t.Logf("空闲会话在 %v 后被清理", elapsed.Round(time.Second))
	if elapsed < 170*time.Second {
		t.Errorf("空闲会话过早被清理：%v（超时应为 180 s）", elapsed.Round(time.Second))
	}
	time.Sleep(5 * time.Second)
	if cleared(active) {
		t.Error("保持活跃的会话也被清理了")
	}
	roundTrip(active, "after")
	roundTrip(idle, "after")
	if peers := be.peerList(); len(peers) != 3 {
		t.Errorf("上游源地址 %v，期望 3 个：活跃客户端 1 个，空闲客户端清理前后各 1 个", peers)
	}
}
