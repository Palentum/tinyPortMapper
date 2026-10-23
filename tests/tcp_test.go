package tests

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func loopback4(t testing.TB) string { return hostPort("127.0.0.1", freePort(t)) }

// TCP 数据完整性：不同数据量与写块大小的双向并发传输
func TestTCPIntegrity(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	cases := []struct {
		up, down int64
		chunk    int
	}{
		{1, 1, 1},
		{100, 100, 1},
		{4097, 4097, 7},
		{16384, 16384, 16384},
		{16385, 16385, 1000},
		{0, 1 << 20, 4096},
		{1 << 20, 1, 4096},
		{1 << 20, 1 << 20, 4096},
		{8 << 20, 8 << 20, 65536},
		{64 << 20, 64 << 20, 1 << 20},
		{1 << 30, 1 << 30, 256 << 10},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("up%d_down%d_chunk%d", c.up, c.down, c.chunk), func(t *testing.T) {
			t.Parallel()
			if max(c.up, c.down) >= 64<<20 {
				heavy(t)
			}
			start := time.Now()
			if err := transfer(listen, c.up, c.down, c.chunk, uint64(i)); err != nil {
				t.Fatal(err)
			}
			if c.up >= 64<<20 {
				t.Logf("双向各 %d MiB 用时 %v", c.up>>20, time.Since(start).Round(time.Millisecond))
			}
		})
	}
}

// concurrentTransfers 先建立 n 个连接，全部建立后再同时双向传输并校验
func concurrentTransfers(t *testing.T, n int) {
	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)

	conns := make([]net.Conn, n)
	errs := make([]error, n)
	t.Cleanup(func() { closeAll(conns) })
	parallelFor(n, 200, func(i int) {
		conns[i], errs[i] = net.DialTimeout("tcp", listen, 10*time.Second)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 个连接建立失败：%v", i+1, err)
		}
	}
	parallelFor(n, n, func(i int) {
		size := int64(1 + (i*7919)%(64<<10))
		errs[i] = transferOn(conns[i], size, size, 4096, uint64(i))
	})
	failed := 0
	for i, err := range errs {
		if err != nil {
			if failed++; failed <= 5 {
				t.Errorf("连接 %d：%v", i, err)
			}
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d 个连接校验失败", failed, n)
	}
}

func TestTCPConcurrent100(t *testing.T) {
	t.Parallel()
	concurrentTransfers(t, 100)
}

func TestTCPConcurrent5000(t *testing.T) {
	t.Parallel()
	heavy(t)
	concurrentTransfers(t, 5000)
}

func closeAll(conns []net.Conn) {
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
}

// parallelFor 以最多 workers 个 goroutine 执行 f(0..n-1)
func parallelFor(n, workers int, f func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			f(i)
		})
	}
	wg.Wait()
}

// 半关闭：客户端关闭写方向后仍应收完后端的响应
func TestTCPHalfClose(t *testing.T) {
	t.Parallel()
	resp := bytes.Repeat([]byte("response-"), 32<<10)
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		req, err := io.ReadAll(c) // 读到客户端的 FIN 才响应
		if err != nil {
			return
		}
		c.Write(append(req, resp...))
	})
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	c := dial(t, listen)
	req := []byte("request-body")
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	got, err := io.ReadAll(c)
	if want := append(req, resp...); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("关闭写方向后收到 %d/%d 字节响应（%v），期望随后读到 EOF", len(got), len(want), err)
	}
}

// 上游先半关闭：客户端应收到 banner 与 EOF 且仍能向上游发送请求，两端都 EOF 后连接对被释放
func TestTCPHalfCloseUpstream(t *testing.T) {
	t.Parallel()
	banner := bytes.Repeat([]byte("server-done\n"), 512)
	got := make(chan []byte, 1)
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		if _, err := c.Write(banner); err != nil {
			return
		}
		c.(*net.TCPConn).CloseWrite()
		req, _ := io.ReadAll(c)
		got <- req
	})
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)
	fds := fdCount(t, m.pid()) // 尚无连接时的基线
	c := dial(t, listen)
	c.SetDeadline(time.Now().Add(ioTimeout))
	resp, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(resp, banner) {
		t.Fatalf("上游关闭写方向后客户端收到 %d/%d 字节 banner（%v），期望随后读到 EOF", len(resp), len(banner), err)
	}
	req := bytes.Repeat([]byte("request-"), 100<<10/8)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("上游半关闭后发送请求失败：%v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if !bytes.Equal(r, req) {
			t.Fatalf("上游收到 %d/%d 字节请求", len(r), len(req))
		}
	case <-time.After(ioTimeout):
		t.Fatal("上游未收到请求与 FIN")
	}
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if n := fdCount(t, m.pid()); n != fds {
			return fmt.Errorf("tinymapper 打开 %d 个 fd，无连接时为 %d：连接对未释放", n, fds)
		}
		return nil
	})
}

// 半关闭排空：客户端关闭写方向时反方向仍有大量积压，积压应完整送达，FIN 随后到达上游
func TestTCPHalfCloseDrain(t *testing.T) {
	t.Parallel()
	// 32 MiB 远超环回上的在途容量（客户端接收缓冲 + tinymapper 两侧 socket 缓冲 + 后端发送缓冲），
	// 一侧 EOF 即整对关闭时必然丢失积压
	const size, chunk = 32 << 20, 64 << 10
	seed := streamSeed(1, true)
	got := make(chan []byte, 1)
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		if _, err := writeStream(c, size, chunk, seed); err != nil {
			return
		}
		req, _ := io.ReadAll(c)
		got <- req
	})
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	c := dial(t, listen)
	req := []byte("drain-request")
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // 不读取，让下行各级缓冲区积满
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(transferTimeout(size)))
	h, err := readStream(c, size)
	if err != nil {
		t.Fatalf("关闭写方向后下行数据不完整：%v", err)
	}
	if n, err := io.Copy(io.Discard, c); n != 0 || err != nil {
		t.Fatalf("下行 %d 字节之后期望 EOF，却又收到 %d 字节（%v）", size, n, err)
	}
	want, _ := writeStream(io.Discard, size, chunk, seed)
	if !bytes.Equal(h.Sum(nil), want) {
		t.Fatal("下行数据 SHA-256 不一致")
	}
	select {
	case r := <-got:
		if !bytes.Equal(r, req) {
			t.Fatalf("上游收到 %q，期望 %q", r, req)
		}
	case <-time.After(ioTimeout):
		t.Fatal("上游未收到请求与 FIN")
	}
}

// listenFull 在 127.0.0.1 上以 backlog=1 监听，并用 2 个不 accept 的占位连接占满 accept 队列：
// Linux 在 sk_ack_backlog > backlog 时判满，此后到达的 SYN 被直接丢弃，由对端约 1 s 后重传。
// 不用 backlog=0：其首个连接会因 SYN 队列判满而依赖 tcp_syncookies。
// 返回的 release 取走并关闭占位连接，使之后重传的 SYN 能建立连接。
func listenFull(t testing.TB) (ln net.Listener, release func()) {
	t.Helper()
	port := freePort(t)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "listen-full")
	defer file.Close()
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	if ln, err = net.FileListener(file); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	const fillers = 2
	for range fillers {
		dial(t, ln.Addr().String())
	}
	// LISTEN 状态的 socket 在 /proc/net/tcp 中的 rx_queue 即当前 accept 队列长度
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		data, err := os.ReadFile("/proc/net/tcp")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 5 || f[3] != "0A" || !strings.HasSuffix(f[1], fmt.Sprintf(":%04X", port)) {
				continue
			}
			_, rx, _ := strings.Cut(f[4], ":")
			if n, _ := strconv.ParseUint(rx, 16, 32); n < fillers {
				return fmt.Errorf("accept 队列长度为 %d，期望 %d", n, fillers)
			}
			return nil
		}
		return fmt.Errorf("/proc/net/tcp 中没有端口 %d 的监听", port)
	})
	return ln, func() {
		for range fillers {
			c, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
	}
}

// 上游连接建立前客户端即关闭写方向：FIN 应推迟到上游连接建立后再转发，而不是中止连接
func TestTCPHalfCloseConnecting(t *testing.T) {
	t.Parallel()
	ln, release := listenFull(t)
	listen := loopback4(t)
	forward(t, "t", listen, ln.Addr().String())
	c := dial(t, listen)
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	time.Sleep(300 * time.Millisecond) // 转发的 SYN 已被丢弃，release 后由约 1 s 时的重传建立连接
	release()
	const resp = "late-response"
	go func() {
		be, err := ln.Accept()
		if err != nil {
			return
		}
		defer be.Close()
		be.SetDeadline(time.Now().Add(ioTimeout))
		// 读到延迟转发的 FIN（0 字节即 EOF）才响应
		if req, err := io.ReadAll(be); err == nil && len(req) == 0 {
			io.WriteString(be, resp)
		}
	}()
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	got, err := io.ReadAll(c)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil || string(got) != resp {
		t.Fatalf("客户端在 %v 后收到 %q（%v），期望 %q：上游应在连接建立后收到 FIN 并响应", elapsed, got, err, resp)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("响应在 %v 后即到达：上游连接未被推迟，用例未覆盖连接建立前收到 FIN 的路径", elapsed)
	}
}

// 同上，但上游连上后立即持续推流、直到读到 EOF 才停：推迟的 FIN 不能因上游每轮都可读而一直发不出去。
// 建连期间暂停 tinymapper，恢复时上游已同时可读可写，模拟转发器繁忙时的事件顺序
func TestTCPHalfCloseConnectingStream(t *testing.T) {
	t.Parallel()
	ln, release := listenFull(t)
	listen := loopback4(t)
	m := forward(t, "t", listen, ln.Addr().String())
	c := dial(t, listen)
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // tinymapper 已读到 EOF，shutdown 推迟到上游连接建立
	m.cmd.Process.Signal(syscall.SIGSTOP)
	t.Cleanup(func() { m.cmd.Process.Signal(syscall.SIGCONT) })
	release()
	accepted := make(chan struct{})
	var written atomic.Int64
	eofAt := make(chan int64, 1) // 上游读到 EOF 时已写出的字节数
	go func() {
		be, err := ln.Accept()
		if err != nil {
			return
		}
		defer be.Close()
		close(accepted)
		be.SetDeadline(time.Now().Add(3 * ioTimeout))
		eof := make(chan struct{})
		go func() { io.Copy(io.Discard, be); eofAt <- written.Load(); close(eof) }()
		buf := make([]byte, 64<<10)
		for {
			select {
			case <-eof:
				return
			default:
			}
			n, err := be.Write(buf)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-accepted:
	case <-time.After(ioTimeout):
		t.Fatal("上游未收到转发的连接")
	}
	time.Sleep(200 * time.Millisecond) // 上游数据积压在 tinymapper 的上游接收缓冲中
	before := written.Load()
	m.cmd.Process.Signal(syscall.SIGCONT)
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	if n, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("客户端读了 %d 字节仍未读到 EOF（%v）：推迟的 FIN 没有转发给上游", n, err)
	}
	// 实测：FIN 先于读处理时恢复后上游没有再写出数据（0 字节）；只走读分支时要等客户端偶然背压，多写 1.9–4.6 MiB
	select {
	case w := <-eofAt:
		if extra := w - before; extra > 1<<20 {
			t.Fatalf("恢复后上游又写出 %d 字节才收到 FIN：推迟的 shutdown 被持续可读的上游拖延", extra)
		}
	case <-time.After(ioTimeout):
		t.Fatal("上游未读到 EOF")
	}
}

// 上游发 RST：客户端连接应被及时关闭
func TestTCPUpstreamReset(t *testing.T) {
	t.Parallel()
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		c.Read(make([]byte, 16))
		c.(*net.TCPConn).SetLinger(0) // close 时发送 RST
	})
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	c := dial(t, listen)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c, ioTimeout)
}

// 客户端发 RST：上游连接应被及时关闭
func TestTCPClientReset(t *testing.T) {
	t.Parallel()
	closed := make(chan struct{})
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		io.Copy(c, c)
		close(closed)
	})
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	c := dial(t, listen)
	mustEcho(t, c, "ping")
	c.SetLinger(0)
	c.Close()
	select {
	case <-closed:
	case <-time.After(ioTimeout):
		t.Fatal("客户端 RST 后上游连接未被关闭")
	}
}

// 上游端口未监听（连接被拒绝）：客户端连接应被及时关闭，tinymapper 继续运行
func TestTCPUpstreamRefused(t *testing.T) {
	t.Parallel()
	listen := loopback4(t)
	m := forward(t, "t", listen, loopback4(t))
	for range 3 {
		expectClosed(t, dial(t, listen), ioTimeout)
	}
	if !m.aliveAfter(200 * time.Millisecond) {
		t.Fatal("上游拒绝连接后 tinymapper 退出")
	}
}

// 上游不可达（无路由）：客户端连接应被及时关闭，tinymapper 继续运行
func TestTCPUpstreamUnreachable(t *testing.T) {
	t.Parallel()
	for _, remote := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		t.Run(remote, func(t *testing.T) {
			t.Parallel()
			_, err := net.DialTimeout("tcp", remote, 2*time.Second)
			if !errors.Is(err, syscall.ENETUNREACH) {
				t.Skipf("当前网络中 %s 并非无路由（%v），在 --network none 容器中运行", remote, err)
			}
			listen := loopback4(t)
			m := forward(t, "t", listen, remote)
			for range 3 {
				expectClosed(t, dial(t, listen), ioTimeout)
			}
			if !m.aliveAfter(200 * time.Millisecond) {
				t.Fatal("上游不可达后 tinymapper 退出")
			}
		})
	}
}

// 上游先发言（SSH 式 banner）：客户端不发送任何数据也能收到 banner
func TestTCPServerSpeaksFirst(t *testing.T) {
	t.Parallel()
	const banner = "SSH-2.0-tinymapper-test"
	be := serveTCP(t, loopback4(t), echoHandler(banner+"\r\n"))
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	c := dial(t, listen)
	if got := readLine(t, c); got != banner+"\r" {
		t.Fatalf("banner = %q，期望 %q", got, banner)
	}
	mustEcho(t, c, "client-hello")
}

// 达到 max_conn_num（20000）后新连接被立即关闭，已有连接不受影响，释放后可再建立
func TestTCPMaxConn(t *testing.T) {
	t.Parallel()
	heavy(t)
	const maxConn = 20000
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)

	conns := make([]net.Conn, maxConn)
	errs := make([]error, maxConn)
	t.Cleanup(func() { closeAll(conns) })
	// 每个连接做一次回显，确保 tinymapper 已逐个接受并连上上游
	parallelFor(maxConn, 128, func(i int) {
		c, err := net.DialTimeout("tcp", listen, 10*time.Second)
		if err == nil {
			conns[i] = c
			err = echo(c, []byte{byte(i)})
		}
		errs[i] = err
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 个连接失败：%v", i+1, err)
		}
	}

	extra := dial(t, listen)
	expectClosed(t, extra, ioTimeout)
	if n := be.accepted.Load(); n != maxConn {
		t.Errorf("上游收到 %d 个连接，期望 %d（超限连接不应转发）", n, maxConn)
	}
	for _, i := range []int{0, 1, 4999, 10000, 15000, maxConn - 2, maxConn - 1} {
		if err := echo(conns[i], []byte("still-alive")); err != nil {
			t.Fatalf("超限后第 %d 个已有连接异常：%v", i+1, err)
		}
	}
	conns[0].Close()
	eventually(t, ioTimeout, 100*time.Millisecond, func() error {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			return err
		}
		defer c.Close()
		return echo(c, []byte("new"))
	})
}

// startMapperFreeFDs 启动 tinymapper，并限制 nofile 使其就绪后恰好剩 free 个可用 fd
func startMapperFreeFDs(t testing.TB, free int, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	probe := startMapperLimit(t, 4096, wait, args...)
	used := fdCount(t, probe.pid())
	probe.stop(t, false)
	m := startMapperLimit(t, used+free, wait, args...)
	if got := fdCount(t, m.pid()); got != used {
		t.Fatalf("启动后 fd 数为 %d，探测时为 %d", got, used)
	}
	return m
}

// 上游 socket() 因 EMFILE 失败时只丢弃该连接：进程不退出，已有连接不受影响，释放 fd 后恢复
func TestTCPNofileUpstreamSocket(t *testing.T) {
	t.Parallel()
	const k = 4
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	// 剩余 2k+1 个 fd：k 个连接之后，下一个连接能 accept 但无法创建上游 socket
	m := startMapperFreeFDs(t, 2*k+1, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")
	var conns []*net.TCPConn
	for range k {
		c := dial(t, listen)
		mustEcho(t, c, "x")
		conns = append(conns, c)
	}
	expectClosed(t, dial(t, listen), ioTimeout)
	if !m.aliveAfter(500 * time.Millisecond) {
		m.stop(t, true)
		t.Fatalf("创建上游 socket 失败（EMFILE）时 tinymapper 退出：%v", m.exitErr)
	}
	for _, c := range conns[1:] {
		mustEcho(t, c, "y")
	}
	conns[0].Close()
	eventually(t, 10*time.Second, 200*time.Millisecond, func() error {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			return err
		}
		defer c.Close()
		return echo(c, []byte("z"))
	})
}

// accept 遇到 EMFILE 时暂停接受：不空转、不刷日志，backlog 中的连接在 fd 释放后照常转发
func TestTCPNofileAccept(t *testing.T) {
	t.Parallel()
	const k = 4
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	// 剩余 2k 个 fd：k 个连接之后 accept 返回 EMFILE
	m := startMapperFreeFDs(t, 2*k, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")
	acceptFailures := func() int {
		data, _ := os.ReadFile(m.logPath)
		return strings.Count(string(data), "accept failed")
	}
	var conns []*net.TCPConn
	for range k {
		c := dial(t, listen)
		mustEcho(t, c, "x")
		conns = append(conns, c)
	}
	pending := dial(t, listen) // 停在 backlog 中，accept 失败
	time.Sleep(200 * time.Millisecond)
	ticks0, failures0 := m.cpuTicks(t), acceptFailures()
	if failures0 == 0 {
		t.Fatal("pending 连接没有触发 accept 失败：fd 余量计算有误，用例没有测到 EMFILE")
	}
	time.Sleep(2 * time.Second)
	ticks, failures := m.cpuTicks(t)-ticks0, acceptFailures()-failures0
	if m.exited() {
		m.stop(t, true)
		t.Fatalf("accept 遇到 EMFILE 后 tinymapper 退出：%v", m.exitErr)
	}
	t.Logf("accept 返回 EMFILE 期间的 2 s：CPU %.2f s，%d 行 accept failed", float64(ticks)/100, failures)
	// 时钟滴答为 1/100 s：2 s 内超过 40 个即 CPU 占用 >20%，空闲时应接近 0
	if ticks > 40 {
		t.Errorf("accept 遇到 EMFILE 时空转：2 s 内消耗 CPU %.2f s", float64(ticks)/100)
	}
	// 每暂停一次记一行 warn，400 ms 的定时器恢复后再试
	if failures > 20 {
		t.Errorf("accept 遇到 EMFILE 时刷日志：2 s 内 %d 行 accept failed", failures)
	}
	// 释放一个连接后，backlog 中的连接被接受并转发
	conns[0].Close()
	mustEcho(t, pending, "p")
	conns[1].Close()
	eventually(t, 10*time.Second, 200*time.Millisecond, func() error {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			return err
		}
		defer c.Close()
		return echo(c, []byte("z"))
	})
}

// 空闲超过 conn_timeout_tcp（360 s）的连接被清理，期间保持活跃的连接不受影响
func TestTCPIdleTimeout(t *testing.T) {
	t.Parallel()
	slow(t)
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	forward(t, "t", listen, be.addr)
	idle := dial(t, listen)
	active := dial(t, listen)
	mustEcho(t, idle, "idle")
	mustEcho(t, active, "active")
	last := time.Now()
	for {
		err := closedWithin(idle, 30*time.Second)
		if err == nil {
			break
		}
		if elapsed := time.Since(last); elapsed > 420*time.Second {
			t.Fatalf("空闲 %v 后连接仍未被清理", elapsed.Round(time.Second))
		}
		mustEcho(t, active, "keepalive")
	}
	elapsed := time.Since(last)
	t.Logf("空闲连接在 %v 后被清理", elapsed.Round(time.Second))
	if elapsed < 350*time.Second {
		t.Errorf("空闲连接过早被清理：%v（超时应为 360 s）", elapsed.Round(time.Second))
	}
	mustEcho(t, active, "after")
}
