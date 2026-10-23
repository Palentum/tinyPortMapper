package tests

import (
	"bytes"
	"fmt"
	"net"
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

// udpSessionAfterIdle 让同一客户端空闲 idle 后再发包，返回上游看到的源地址序列
func udpSessionAfterIdle(t testing.TB, idle time.Duration) []string {
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	forward(t, "u", listen, be.addr)
	c := udpDial(t, "", listen)
	for _, msg := range []string{"first", "second"} {
		if _, err := udpRoundTrip(c, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	if peers := be.peerList(); len(peers) != 1 {
		t.Fatalf("同一客户端连续发包应复用同一会话，上游看到 %v", peers)
	}
	time.Sleep(idle)
	if _, err := udpRoundTrip(c, []byte("after-idle")); err != nil {
		t.Fatal(err)
	}
	return be.peerList()
}

// UDP 会话空闲超过 conn_timeout_udp（180 s）后应被清理（已知缺陷 C4：实际使用了 TCP 的 360 s）
func TestUDPSessionTimeout(t *testing.T) {
	t.Parallel()
	slow(t)
	xfail(t, "C4", func(t testing.TB) {
		if peers := udpSessionAfterIdle(t, 200*time.Second); len(peers) != 2 {
			t.Fatalf("空闲 200 s 后仍复用旧会话（上游源地址 %v），UDP 超时应为 180 s", peers)
		}
	})
}

// 无论超时取 180 s 还是 360 s，空闲 380 s 后会话都应已被清理
func TestUDPSessionExpiry(t *testing.T) {
	t.Parallel()
	slow(t)
	if peers := udpSessionAfterIdle(t, 380*time.Second); len(peers) != 2 {
		t.Fatalf("空闲 380 s 后会话仍未被清理（上游源地址 %v）", peers)
	}
}
