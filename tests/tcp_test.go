package tests

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
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
	fds := nonPipeFDs(t, m.pid()) // 尚无连接时的基线；100 KiB 的请求会走 splice，scratch pipe 之后合法地留着
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
		if n := nonPipeFDs(t, m.pid()); n != fds {
			return fmt.Errorf("tinymapper 打开 %d 个非 pipe fd，无连接时为 %d：连接对未释放", n, fds)
		}
		return nil
	})
	m.expectPipeFDs(t, m.statsAfterSignal(t), "连接对释放之后")
}

// 半关闭排空：客户端关闭写方向时反方向仍有大量积压，积压应完整送达，FIN 随后到达上游
func TestTCPHalfCloseDrain(t *testing.T) {
	t.Parallel()
	// 32 MiB 远超环回上的在途容量（客户端接收缓冲 + tinymapper 两侧 socket 缓冲 + 后端发送缓冲），
	// 一侧 EOF 即整对关闭时必然丢失积压
	const size, chunk = 32 << 20, 64 << 10
	seed := streamSeed(1, true)
	got := make(chan []byte, 1)
	hold := make(chan struct{}) // 上游读完请求后先不关闭，连接对保持到排空后的 CPU 采样之后
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		if _, err := writeStream(c, size, chunk, seed); err != nil {
			return
		}
		req, _ := io.ReadAll(c)
		got <- req
		<-hold
	})
	releaseHold := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(releaseHold) // 在 serveTCP 之后注册，清理时先于它执行
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)
	c := dial(t, listen)
	req := []byte("drain-request")
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // 不读取，让下行各级缓冲区积满
	// 下行背压：tinymapper 持有发不完的块、停读上游一侧，上游一侧的接收队列一直非空
	m.expectIdleCPU(t, "下行背压中（S5：停本侧 READ）")
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(transferTimeout(size)))
	h, err := readStream(c, size)
	if err != nil {
		t.Fatalf("关闭写方向后下行数据不完整：%v", err)
	}
	// 下行已排空、上游还没关闭：客户端一侧的 watcher 去掉了 WRITE，客户端一侧一直可写
	m.expectIdleCPU(t, "下行排空后（S6：去 WRITE）")
	releaseHold()
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
	// 同 net.Listen（portFree 用它探测）设 SO_REUSEADDR：否则该端口上还有 TIME_WAIT 连接（如同一网络命名空间里上一个测试进程
	// 用过这个端口）时 portFree 认为空闲，这里的 bind 却返回 EADDRINUSE
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind 127.0.0.1:%d 失败：%v；该端口上的 socket：%s", port, err, portHolders(port))
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatalf("listen 127.0.0.1:%d 失败：%v；该端口上的 socket：%s", port, err, portHolders(port))
	}
	if ln, err = net.FileListener(file); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	const fillers = 2
	for range fillers {
		dial(t, ln.Addr().String())
	}
	// LISTEN 状态的 socket 的 idiag_rqueue 即当前 accept 队列长度。用 sock_diag 精确查询，不整表读 /proc/net/tcp
	//（与 TestTCPMaxConn 并行时读一遍要数秒）。端口由本进程独占，不再核对 inode（测试进程的 fd 表可能有数万项）
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		q, err := sockDiag(syscall.IPPROTO_TCP, ln.Addr().String(), "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("sock_diag 查找监听 socket %s：%w", ln.Addr(), err)
		}
		if q.rqueue < fillers {
			return fmt.Errorf("accept 队列长度为 %d，期望 %d", q.rqueue, fillers)
		}
		return nil
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

// synSentTo 返回处于 SYN_SENT、目的端口为 port 的 IPv4 socket 数（按 inode 去重）。建连失败（收到 RST）的 socket 已从哈希表摘除，
// 不再列出。用 sockDiagDump 只列 SYN_SENT 状态的 socket：原来整表读 /proc/net/tcp，与 TestTCPMaxConn 并行时读一遍要数秒，
// TestTCPConnectingRefusedData 的 15 s 里只试得了一两次而超时。/proc/net/tcp 也不是一致快照：每次 read(2) 最多一页，下一次按
// （桶号，桶内偏移）续读（tcp_seek_last_pos），两次 read 之间同一桶里的插入或删除会让一行重复出现或被跳过（TestTCPMaxConn 并行时
// 实测同一 socket 被列出 4 次），所以调用方扫两次；dump 只回几个 socket，一次就能取完，两次扫描对它无害
func synSentTo(t testing.TB, port int) int {
	t.Helper()
	inodes := map[uint32]bool{}
	err := sockDiagDump(syscall.AF_INET, syscall.IPPROTO_TCP, 1<<2, func(_, dport uint16, inode uint32) { // TCP_SYN_SENT
		if int(dport) == port {
			inodes[inode] = true
		}
	})
	if err != nil {
		t.Fatalf("sock_diag 列出 SYN_SENT socket 失败：%v", err)
	}
	return len(inodes)
}

// 上游连接建立前客户端即关闭写方向：FIN 应推迟到上游连接建立后再转发，而不是中止连接
func TestTCPHalfCloseConnecting(t *testing.T) {
	t.Parallel()
	ln, release := listenFull(t)
	listen := loopback4(t)
	m := forward(t, "t", listen, ln.Addr().String())
	c := dial(t, listen)
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	time.Sleep(300 * time.Millisecond) // 转发的 SYN 已被丢弃，release 后由约 1 s 时的重传建立连接
	release()
	const resp = "late-response"
	finSeen, respond := make(chan struct{}), make(chan struct{})
	go func() {
		be, err := ln.Accept()
		if err != nil {
			return
		}
		defer be.Close()
		be.SetDeadline(time.Now().Add(ioTimeout))
		// 读到延迟转发的 FIN（0 字节即 EOF）才响应
		if req, err := io.ReadAll(be); err == nil && len(req) == 0 {
			close(finSeen)
			<-respond
			io.WriteString(be, resp)
		}
	}()
	func() {
		defer close(respond)
		select {
		case <-finSeen:
			// 推迟的 shutdown 已发出，上游一侧的 watcher 去掉了 WRITE；上游先不响应，连接对静止
			m.expectIdleCPU(t, "推迟的 shutdown 发出后（S2：去 WRITE）")
		case <-time.After(ioTimeout): // 下面读响应时报告
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

// streamUntil 以 64 KiB 为块向 c 持续写，每写完一块就非阻塞地读一次 c，done 返回真时停止，返回此时已写出的字节数。
// 写和检查在同一个协程里交替：请求或 FIN 进入接收队列后，下一块写完时的检查就能看到，结果不受 Go 调度延迟影响。
// 原来由另一个协程读，全量并行运行时它排队等 P 的那段时间里，写协程能把整条管道重新灌满（实测多写 3–4.6 MiB）
func streamUntil(c *net.TCPConn, written *atomic.Int64, done func(data []byte, eof bool) bool) (int64, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	wbuf, rbuf := make([]byte, 64<<10), make([]byte, 64<<10)
	for {
		n, err := c.Write(wbuf)
		written.Add(int64(n))
		if err != nil {
			return written.Load(), err
		}
		var rn int
		var rerr error
		if err := rc.Read(func(fd uintptr) bool { rn, rerr = syscall.Read(int(fd), rbuf); return true }); err != nil {
			return written.Load(), err
		}
		if rerr != nil && rerr != syscall.EAGAIN {
			return written.Load(), rerr
		}
		if rerr == nil && done(rbuf[:rn], rn == 0) {
			return written.Load(), nil
		}
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
		if w, err := streamUntil(be.(*net.TCPConn), &written, func(_ []byte, eof bool) bool { return eof }); err == nil {
			eofAt <- w
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
	// 实测：FIN 先于读处理时恰好多写 64 KiB（暂停时没写完的那一块）；只走读分支（c3pre）时要等客户端偶然背压，
	// 多写 0.56–3.5 MiB，所以门槛取 256 KiB
	select {
	case w := <-eofAt:
		extra := w - before
		t.Logf("恢复后上游又写出 %d 字节才收到 FIN", extra)
		if extra > 256<<10 {
			t.Fatalf("恢复后上游又写出 %d 字节才收到 FIN：推迟的 shutdown 被持续可读的上游拖延", extra)
		}
	case <-time.After(ioTimeout):
		t.Fatal("上游未读到 EOF")
	}
}

// 上游建连期间客户端发来超过 tinymapper 单个缓冲（T11 起 64 KiB）的请求：数据应留在缓冲中，连上后完整转发。
// 取 256 KiB 使请求明确跨多个 64 KiB 缓冲：tinymapper 建连期间读满一块就停读、把这块交给该方向（D17），连上后发出、
// 排空再读下一块，整个请求要经过多块缓冲才转发完
func TestTCPConnectingData(t *testing.T) {
	t.Parallel()
	ln, release := listenFull(t)
	listen := loopback4(t)
	forward(t, "t", listen, ln.Addr().String())
	const size = 256 << 10
	var req bytes.Buffer
	sum, _ := writeStream(&req, size, size, streamSeed(1, false))
	c := dial(t, listen)
	c.SetDeadline(time.Now().Add(ioTimeout))
	werr := make(chan error, 1)
	go func() { _, err := c.Write(req.Bytes()); werr <- err }() // tinymapper 读满一个缓冲即停读，其余留在 socket 缓冲中
	start := time.Now()
	time.Sleep(300 * time.Millisecond) // 转发的 SYN 已被丢弃，release 后由约 1 s 时的重传建立连接
	release()
	go func() {
		be, err := ln.Accept()
		if err != nil {
			return
		}
		defer be.Close()
		be.SetDeadline(time.Now().Add(ioTimeout))
		if h, err := readStream(be, size); err == nil {
			be.Write(h.Sum(nil))
		}
	}()
	got := make([]byte, len(sum))
	_, err := io.ReadFull(c, got)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		t.Fatalf("客户端在 %v 后未收到上游对 %d 字节请求的校验和（%v）：建连期间收到的请求没有完整转发", elapsed, size, err)
	}
	if err := <-werr; err != nil {
		t.Fatalf("发送请求失败：%v", err)
	}
	if !bytes.Equal(got, sum) {
		t.Fatal("上游收到的请求 SHA-256 不一致")
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("响应在 %v 后即到达：上游连接未被推迟，用例未覆盖建连期间收到数据的路径", elapsed)
	}
}

// 同上，但上游连上后立即持续推流、直到收到请求才停：建连期间缓冲的请求不能因上游每轮都可读而一直发不出去。
// 建连期间暂停 tinymapper，恢复时上游已同时可读可写，模拟转发器繁忙时的事件顺序
func TestTCPConnectingDataStream(t *testing.T) {
	t.Parallel()
	ln, release := listenFull(t)
	listen := loopback4(t)
	m := forward(t, "t", listen, ln.Addr().String())
	c := dial(t, listen)
	req := []byte("request-while-connecting")
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // tinymapper 已读入请求，等上游连接建立后再发
	m.cmd.Process.Signal(syscall.SIGSTOP)
	t.Cleanup(func() { m.cmd.Process.Signal(syscall.SIGCONT) })
	release()
	accepted := make(chan struct{})
	var written atomic.Int64
	reqAt := make(chan int64, 1) // 上游收到完整请求时已写出的字节数
	go func() {
		be, err := ln.Accept()
		if err != nil {
			return
		}
		defer be.Close()
		close(accepted)
		be.SetDeadline(time.Now().Add(3 * ioTimeout))
		var got []byte
		w, err := streamUntil(be.(*net.TCPConn), &written, func(data []byte, eof bool) bool {
			got = append(got, data...)
			return eof || len(got) >= len(req)
		})
		if err == nil && bytes.Equal(got, req) {
			reqAt <- w
		}
	}()
	select {
	case <-accepted:
	case <-time.After(ioTimeout):
		t.Fatal("上游未收到转发的连接")
	}
	time.Sleep(200 * time.Millisecond) // 上游数据积压在 tinymapper 的上游接收缓冲中
	before := written.Load()
	go io.Copy(io.Discard, c) // 客户端持续读，不制造背压
	m.cmd.Process.Signal(syscall.SIGCONT)
	// 实测：先发缓冲的请求时恰好多写 64 KiB（暂停时没写完的那一块）；只走读分支（c7pre）时要等某次发往客户端的
	// send 偶然只发出一部分，多写 0.19–3.8 MiB（约一成 ≤ 256 KiB 而漏过）。门槛取 256 KiB，不再降低：
	// 请求在暂停前还没读到时，正确实现也可能多写一两块
	select {
	case w := <-reqAt:
		extra := w - before
		t.Logf("恢复后上游又写出 %d 字节才收到请求", extra)
		if extra > 256<<10 {
			t.Fatalf("恢复后上游又写出 %d 字节才收到请求：建连期间缓冲的请求被持续可读的上游拖延", extra)
		}
	case <-time.After(ioTimeout):
		t.Fatal("上游未收到建连期间发出的请求")
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

// expectConnectFailed 等待日志中出现至少 n 行 warn 级、含上游地址 remote 与 errno 的建连失败记录（日志格式为 "<errno>:<strerror>"）。
// 只比对 errno 数值：glibc 与 musl 的 strerror 文本不同，如 ETIMEDOUT 为 Connection timed out / Operation timed out。
// 调用时 tinymapper 已记下这些行（先记 warn 再关闭客户端）；T6 起 stdout 是文件时要等 400 ms 的定时器才写进文件，
// 窗口在原来的 1 s 上加一个刷新周期再取整，保留原有的调度余量
func expectConnectFailed(t testing.TB, m *mapper, n int, remote string, errno syscall.Errno) {
	t.Helper()
	code := fmt.Sprintf("%d:", int(errno))
	eventually(t, 2*time.Second, 20*time.Millisecond, func() error {
		if got := m.logLines("[WARN]", "{"+remote+"}", code); got < n {
			return fmt.Errorf("日志中有 %d 行 [WARN] 级、含 %s 的上游 {%s} 建连失败记录，期望至少 %d 行：建连失败的真实原因（%v）应以 warn 级记录", got, code, remote, n, errno)
		}
		return nil
	})
}

// 上游端口未监听（连接被拒绝）：客户端连接应被及时关闭并以 warn 记录拒绝原因，tinymapper 继续运行
func TestTCPUpstreamRefused(t *testing.T) {
	t.Parallel()
	listen, remote := loopback4(t), loopback4(t)
	m := forward(t, "t", listen, remote)
	for range 3 {
		expectClosed(t, dial(t, listen), ioTimeout)
	}
	if !m.aliveAfter(200 * time.Millisecond) {
		t.Fatal("上游拒绝连接后 tinymapper 退出")
	}
	expectConnectFailed(t, m, 3, remote, syscall.ECONNREFUSED)
	// O1：异步建连失败前连接对已建立，计入 total，失败后释放
	if s := m.statsAfterSignal(t).tcp[1]; s.total != 3 || s.conns != 0 {
		t.Errorf("统计 total=%d conns=%d，期望 3/0", s.total, s.conns)
	}
}

// 上游不可达（无路由）：客户端连接应被及时关闭并以 warn 记录原因，tinymapper 继续运行
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
			expectConnectFailed(t, m, 3, remote, syscall.ENETUNREACH)
			// O1：connect 立即失败时不建连接对，不计入 total；连接对象在 socket()/connect() 之前就从池里取出（F2），失败后放回池里，
			// 所以可能已分配过 slab，但不能有对象还在用
			if d := m.statsAfterSignal(t); d.tcp[1].total != 0 || d.pool.tcpSlabs*objPoolSlabObjs-d.pool.tcpFree != 0 {
				t.Errorf("统计 total=%d tcp_pairs slabs=%d free=%d，期望 total=0、在用对象 0 个", d.tcp[1].total, d.pool.tcpSlabs, d.pool.tcpFree)
			}
		})
	}
}

// 上游建连期间客户端关闭写方向，随后上游拒绝连接：应以 warn 记录拒绝原因并关闭客户端，
// 而不是在失败的 socket 上执行推迟的 shutdown、只记下 ENOTCONN
func TestTCPConnectingRefusedHalfClose(t *testing.T) {
	t.Parallel()
	ln, _ := listenFull(t)
	upstream := ln.Addr().String()
	listen := loopback4(t)
	m := forward(t, "t", listen, upstream)
	c := dial(t, listen)
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // tinymapper 已读到 EOF，转发的 SYN 已被丢弃
	ln.Close()                         // 约 1 s 时重传的 SYN 收到 RST
	expectClosed(t, c, ioTimeout)
	expectConnectFailed(t, m, 1, upstream, syscall.ECONNREFUSED)
}

// 上游建连失败后、tinymapper 察觉之前客户端发来数据：不能把数据 send 给失败的上游（吞掉 SO_ERROR，
// 随后 recv 返回 0 被误当作上游 EOF，最终 EPIPE），应以 warn 记录拒绝原因并关闭客户端。
// 暂停 tinymapper 期间上游先收到 RST、客户端后发来数据，恢复后 epoll 依次报告两者，libev 后进先出，先回调客户端
func TestTCPConnectingRefusedData(t *testing.T) {
	t.Parallel()
	ln, _ := listenFull(t)
	upstream := ln.Addr().String()
	listen := loopback4(t)
	m := forward(t, "t", listen, upstream)
	c := dial(t, listen)
	time.Sleep(300 * time.Millisecond) // tinymapper 已接受连接并回到 epoll_wait，转发的 SYN 已被丢弃
	if n := max(synSentTo(t, portOf(upstream)), synSentTo(t, portOf(upstream))); n != 1 {
		t.Fatalf("到上游的 SYN_SENT socket 有 %d 个，期望 1：用例没有测到上游建连中的路径", n)
	}
	m.cmd.Process.Signal(syscall.SIGSTOP)
	t.Cleanup(func() { m.cmd.Process.Signal(syscall.SIGCONT) })
	ln.Close() // 约 1 s 时重传的 SYN 收到 RST
	// tinymapper 已暂停，多等不影响事件顺序；放宽到 3 倍是为了全量并行运行时 VM 繁忙的情形
	eventually(t, 3*ioTimeout, 10*time.Millisecond, func() error {
		if n := max(synSentTo(t, portOf(upstream)), synSentTo(t, portOf(upstream))); n != 0 {
			return fmt.Errorf("到上游的 SYN_SENT socket 仍有 %d 个：重传的 SYN 没有收到 RST", n)
		}
		return nil
	})
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // 环回上数据随 write 送达，tinymapper 一侧的客户端 socket 晚于上游就绪
	m.cmd.Process.Signal(syscall.SIGCONT)
	expectClosed(t, c, ioTimeout)
	expectConnectFailed(t, m, 1, upstream, syscall.ECONNREFUSED)
	if n := m.logLines("Broken pipe"); n > 0 {
		t.Fatalf("日志中有 %d 行 Broken pipe：客户端数据被发给了建连失败的上游", n)
	}
}

// 上游的 SYN 一直被丢弃：内核按 tcp_syn_retries（加 tcp_syn_linear_timeouts）重传后约 130 s 放弃，
// 客户端连接随之关闭并以 warn 记录超时（tinymapper 没有用户态的建连超时）
func TestTCPConnectTimeout(t *testing.T) {
	t.Parallel()
	slow(t)
	ln, _ := listenFull(t)
	upstream := ln.Addr().String()
	listen := loopback4(t)
	m := forward(t, "t", listen, upstream)
	start := time.Now()
	c := dial(t, listen)
	if err := closedWithin(c, 180*time.Second); err != nil {
		t.Fatalf("上游 SYN 一直被丢弃：%v", err)
	}
	elapsed := time.Since(start)
	t.Logf("客户端连接在 %v 后被关闭", elapsed.Round(time.Second))
	if elapsed < 100*time.Second {
		t.Fatalf("客户端连接在 %v 后即被关闭，期望在内核放弃建连（约 130 s）之后", elapsed.Round(time.Second))
	}
	expectConnectFailed(t, m, 1, upstream, syscall.ETIMEDOUT)
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

const nagleGap = 5 * time.Millisecond

// writeGapWrite 先写 first，停顿 nagleGap 后再写 seg
func writeGapWrite(c net.Conn, first, seg []byte) error {
	if _, err := c.Write(first); err != nil {
		return err
	}
	time.Sleep(nagleGap)
	_, err := c.Write(seg)
	return err
}

// quickAckOff 对 c 设 TCP_QUICKACK=0，让它进入 pingpong（延迟确认）模式，与 tcp_pingpong_thresh 无关。新连接收到第一段数据后
// 处于 quickack 模式、每段立即确认，所以要在连接上还没有数据时设。监听 socket 上设返回 ENOPROTOOPT（6.8 实测），accept 得到的
// 连接无从继承，只能逐个设
func quickAckOff(c *net.TCPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 0)
	}); err != nil {
		return err
	}
	return serr
}

const (
	nagleConns         = 5 // nagleRounds 依次建立的连接数
	nagleRoundsPerConn = 8
)

// nagleRounds 在 nagleConns 条新连接上各测 nagleRoundsPerConn 轮"写-停顿-写"的往返用时，返回 [连接][轮]。toUpstream 为真时由客户端
// 先写 first 字节（0 即 8 字节）、停顿后再写 8 字节，上游收齐后回 1 字节；否则客户端发 1 字节，上游分两次各写回 8 字节。tinymapper 的
// 发送侧开着 Nagle 时，第二段要等前面没确认的小段被确认才发出；对端处于 pingpong 模式时延迟确认，这一轮要多等一个延迟 ACK（≥ 40 ms）。
// 收两段的一方（toUpstream 时为后端，否则为客户端）在连接上还没有数据时 quickAckOff：否则它在第 0 轮还处于 quickack 模式，第一段立即
// 被确认，第二段即使被 Nagle 扣住也只多等一个环回 RTT。上游方向的第 0 轮含连接上第二次往上游的 send，T15 起上游的 TCP_NODELAY 推迟到
// 这次 send 之前才设（第一次 send 超过 nodelay_first_max 字节时在它之前），只有这次没设时，停顿只出现在第 0 轮
func nagleRounds(t testing.TB, toUpstream bool, first int, extra ...string) [][]time.Duration {
	t.Helper()
	seg := []byte("01234567")
	firstSeg := seg
	if first > 0 {
		firstSeg = bytes.Repeat([]byte{'f'}, first)
	}
	ready := make(chan error, 1) // 上游方向：后端设好 TCP_QUICKACK=0，客户端才开始写
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		req := make([]byte, 1)
		if toUpstream {
			ready <- quickAckOff(c.(*net.TCPConn))
			req = make([]byte, len(firstSeg)+len(seg))
		}
		for {
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			var err error
			if toUpstream {
				_, err = c.Write(req[:1])
			} else {
				err = writeGapWrite(c, seg, seg)
			}
			if err != nil {
				return
			}
		}
	})
	listen := loopback4(t)
	startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, extra...)...)
	resp := make([]byte, 2*len(seg))
	if toUpstream {
		resp = resp[:1]
	}
	all := make([][]time.Duration, nagleConns)
	for k := range all {
		c := dial(t, listen)
		c.SetDeadline(time.Now().Add(4 * ioTimeout))
		var err error
		if toUpstream {
			select {
			case err = <-ready:
			case <-time.After(ioTimeout):
				err = errors.New("后端没有 accept")
			}
		} else {
			err = quickAckOff(c)
		}
		if err != nil {
			t.Fatalf("连接 %d：设 TCP_QUICKACK=0：%v", k, err)
		}
		rounds := make([]time.Duration, nagleRoundsPerConn)
		for i := range rounds {
			t0 := time.Now()
			if toUpstream {
				err = writeGapWrite(c, firstSeg, seg)
			} else {
				_, err = c.Write(seg[:1])
			}
			if err == nil {
				_, err = io.ReadFull(c, resp)
			}
			if err != nil {
				t.Fatalf("连接 %d 第 %d 轮：%v", k, i, err)
			}
			rounds[i] = time.Since(t0).Round(10 * time.Microsecond)
		}
		all[k] = rounds
		c.Close()
	}
	t.Logf("各连接各轮用时：%v", all)
	return all
}

// nagleConnecting 测上游第一次 send 走写分支时，第二次 send 的用时，返回 3 条连接中的最小值。后端的 accept 队列先被占满（listenFull），
// 转发的 SYN 被丢弃、约 1 s 后重传才建连；客户端先写的 8 字节被 tinymapper 读进缓冲（停读客户端一侧），连上后由写分支发出（第一次
// send），客户端再写的 8 字节由读分支发出（第二次 send）。放行建连之前暂停 tinymapper：握手由内核完成，后端 accept 后 quickAckOff，
// 再恢复 tinymapper 并开始计时，到后端收齐 16 字节为止。第二段在暂停期间就已写出：tinymapper 恢复后先由写分支发第一段、重新开始读
// 客户端一侧，下一轮才读到它，顺序是确定的；第二段被 Nagle 扣住时要等后端对第一段的延迟 ACK，整段停顿都在计时之内
func nagleConnecting(t testing.TB, extra ...string) time.Duration {
	t.Helper()
	seg := []byte("01234567")
	ds := make([]time.Duration, 3)
	for k := range ds {
		ln, release := listenFull(t)
		listen := loopback4(t)
		m := startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", ln.Addr().String(), "-t"}, extra...)...)
		c := dial(t, listen)
		c.SetDeadline(time.Now().Add(4 * ioTimeout))
		if _, err := c.Write(seg); err != nil {
			t.Fatal(err)
		}
		eventually(t, ioTimeout, 5*time.Millisecond, func() error {
			b, err := sockDiag(syscall.IPPROTO_TCP, listen, c.LocalAddr().String())
			if err != nil {
				return fmt.Errorf("sock_diag 查找 tinymapper 的客户端一侧 socket：%w", err)
			}
			if b.rqueue != 0 {
				return fmt.Errorf("tinymapper 还没读走第一段：客户端一侧接收队列有 %d 字节", b.rqueue)
			}
			return nil
		})
		m.pause(t)
		if _, err := c.Write(seg); err != nil {
			t.Fatal(err)
		}
		release()
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(4 * ioTimeout))
		be, err := ln.Accept()
		if err != nil {
			t.Fatalf("连接 %d：后端 accept：%v", k, err)
		}
		t.Cleanup(func() { be.Close() })
		if err := quickAckOff(be.(*net.TCPConn)); err != nil {
			t.Fatalf("连接 %d：设 TCP_QUICKACK=0：%v", k, err)
		}
		be.SetDeadline(time.Now().Add(4 * ioTimeout))
		t0 := time.Now()
		m.cmd.Process.Signal(syscall.SIGCONT)
		if _, err := io.ReadFull(be, make([]byte, 2*len(seg))); err != nil {
			t.Fatalf("连接 %d：后端读两段：%v", k, err)
		}
		ds[k] = time.Since(t0).Round(10 * time.Microsecond)
	}
	t.Logf("各连接 tinymapper 恢复运行到后端收齐两段的用时：%v", ds)
	return slices.Min(ds)
}

// TCP_NODELAY（T1、T15）：两侧默认关闭 Nagle，小段数据不等对端的延迟 ACK；--disable-tcp-nodelay 时恢复 Nagle。T15 起上游一侧的
// TCP_NODELAY 推迟到连接上第二次往上游 send 之前才设，所以除了全部轮次的中位数，还看各连接第 0 轮用时的最小值：偶发的调度延迟只拉长
// 个别连接，第二次 send 没设 TCP_NODELAY 则每条连接的第 0 轮都停顿。first1000 的第一段超过 nodelay_first_max，走第一次 send 之前就设的
// 分支；环回 MSS 远大于 1000 字节，它是一个不满 MSS 的段，后端照样延迟确认，第二次 send 没设时第二段被扣住。这个分支本身（第一次 send
// 也推迟）测不出来：Linux 的 Nagle（Minshall 变体）只在前面还有没确认的小段时扣小段，第一次 send 之前没有这样的段，分成几段都整个发出
// （后端 TCP_MAXSEG 536 时实测同样）。connecting 让第一次 send 走写分支（nagleConnecting）。
// disabled 子用例断言停顿确实出现，用来证明本用例能区分两种行为，同时检验回滚开关。第 0 轮与 connecting 的停顿只靠 quickAckOff；中位数的
// 停顿还要求对端每轮都回到 pingpong 模式，即 tcp_pingpong_thresh 为 1：v5.19 起的主线与 5.10.y/5.15.y 默认如此，v5.1–v5.18 与 5.4.y
// 为 3，此时只跳过中位数的检查。延迟 ACK 是 TCP_DELACK_MIN（40 ms），按 HZ 取整后最短约 30 ms
func TestTCPNoDelay(t *testing.T) {
	t.Parallel()
	disabled := []string{"--disable-tcp-nodelay"}
	for _, c := range []struct {
		name       string
		toUpstream bool
		first      int  // 上游方向第一段的字节数，0 即 8
		connecting bool // 第一段在上游建连期间到达（nagleConnecting）
		extra      []string
	}{
		{"upstream", true, 0, false, nil},
		{"upstream/first1000", true, 1000, false, nil},
		{"upstream/connecting", true, 0, true, nil},
		{"client", false, 0, false, nil},
		{"disabled/upstream", true, 0, false, disabled},
		{"disabled/upstream/first1000", true, 1000, false, disabled},
		{"disabled/upstream/connecting", true, 0, true, disabled},
		{"disabled/client", false, 0, false, disabled},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			const fast, slow = nagleGap + 15*time.Millisecond, 25 * time.Millisecond
			if c.connecting {
				d := nagleConnecting(t, c.extra...)
				if c.extra == nil && d >= fast-nagleGap {
					t.Errorf("第二次 send 最快 %v 才到达后端，期望 < %v：第一次 send 走写分支时，第二次 send 之前没有设 TCP_NODELAY", d, fast-nagleGap)
				}
				if c.extra != nil && d < slow {
					t.Errorf("第二次 send 最快 %v 就到达后端，期望 ≥ %v：关闭 TCP_NODELAY 后应等到后端对第一段的延迟 ACK", d, slow)
				}
				return
			}
			var firsts, rounds []time.Duration
			for _, r := range nagleRounds(t, c.toUpstream, c.first, c.extra...) {
				firsts = append(firsts, r[0])
				rounds = append(rounds, r...)
			}
			first := slices.Min(firsts)
			slices.Sort(rounds)
			med := rounds[len(rounds)/2]
			if c.extra == nil {
				if first >= fast {
					t.Errorf("各连接第 0 轮用时的最小值 %v，期望 < %v：每条连接的第 0 轮都被 Nagle 扣住（上游方向即第二次 send 之前没有设 TCP_NODELAY）", first, fast)
				}
				if med >= fast {
					t.Errorf("每轮用时中位数 %v，期望 < %v：小段数据被 Nagle 扣住，等到了对端的延迟 ACK", med, fast)
				}
				return
			}
			if first < slow {
				t.Errorf("各连接第 0 轮用时的最小值 %v，期望 ≥ %v：关闭 TCP_NODELAY 后第 0 轮应出现 Nagle 与延迟 ACK 叠加的停顿", first, slow)
			}
			if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_pingpong_thresh"); err == nil && strings.TrimSpace(string(b)) != "1" {
				t.Logf("tcp_pingpong_thresh=%s，对端不会每轮回到延迟确认，跳过中位数的检查", strings.TrimSpace(string(b)))
			} else if med < slow {
				t.Errorf("每轮用时中位数 %v，期望 ≥ %v：关闭 TCP_NODELAY 后应出现 Nagle 与延迟 ACK 叠加的停顿", med, slow)
			}
		})
	}
}

// setBuf 返回 setsockopt(SO_RCVBUF/SO_SNDBUF, v) 后内核保存的值，即 2×min(v, rmem_max/wmem_max)。
// 容器的网络命名空间里没有 /proc/sys/net/core/{r,w}mem_max（只在初始命名空间注册），所以在测试自己的 socket 上设一次再读回
func setBuf(t testing.TB, v int) sockBuf {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var got [2]int
	for i, opt := range []int{syscall.SO_RCVBUF, syscall.SO_SNDBUF} {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, opt, v); err != nil {
			t.Fatal(err)
		}
		if got[i], err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, opt); err != nil {
			t.Fatal(err)
		}
	}
	return sockBuf{rcv: uint32(got[0]), snd: uint32(got[1])}
}

// tcpBufDefault 返回 /proc/sys/net/ipv4/<name>（tcp_rmem 或 tcp_wmem：最小值、初始值、最大值）中的初始值
func tcpBufDefault(t testing.TB, name string) int {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/net/ipv4/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var lo, def int
	if _, err := fmt.Sscan(string(data), &lo, &def); err != nil {
		t.Fatalf("/proc/sys/net/ipv4/%s 内容异常：%q", name, data)
	}
	return def
}

// T4：TCP socket 默认不设 SO_RCVBUF/SO_SNDBUF，交给内核自动调优；修复前监听 socket 设 2 MiB、客户端与上游 socket 各设
// 1 MiB（--sock-buf 的默认值），内核截到 rmem_max/wmem_max 后翻倍（默认 212992 → 425984）并加上锁位，自动调优随之关闭。
// 锁位不导出到用户态，只能经 sock_diag 按值判断。客户端 socket（accept 得到）与上游 socket 分别在建连后、传数据前检查：
//   - 发送缓冲：没锁 SNDBUF 的 socket 建连时由 tcp_sndbuf_expand 按 2×初始拥塞窗口×每段内存扩大，结果确定（loopback 上为 2626560）。
//     用测试自己持有、从未设过缓冲的同类 socket 对照：客户端 socket（被动打开）对照后端 accept 的连接，上游 socket（主动打开）对照测试拨出的连接
//   - 接收缓冲：建连时不变，为 tcp_rmem[1]（4.20 起；之前的 tcp_fixup_rcvbuf 建连时会扩大接收缓冲，a337531b942b 删除）。
//     这个值看不出是否加锁（--sock-buf 64 设出的 131072 恰好相等），但传输后的增长也不能当判据：loopback 上 advmss 约 64 KiB，
//     tcp_rcv_space_adjust 起始的 space 就是整个初始窗口（65535），tinymapper 每次最多读 64 KiB（T11），一个 RTT 估计内读走的数据
//     只在一个窗口上下，增长与否取决于计时抖动（实测约 1/10 的连接回显 64 MiB 后仍为 131072）
//   - --sock-buf N：两侧都是 2×min(N KiB, rmem_max/wmem_max)；双向各传 16 MiB 后不变。N 高于 rmem_max 时同样截断：tests/run.sh 的
//     容器里 tinymapper 有 CAP_NET_ADMIN，但 SO_*BUFFORCE 只用于 UDP socket（U6，D38）
//
// 监听 socket 也要检查：accept 得到的 socket 复制监听 socket 的缓冲与锁位，SYN-ACK 的窗口、wscale 也按监听 socket 的缓冲计算，
// 所以 --sock-buf 应设在监听 socket 上，而不是每次 accept 后再设（只看客户端 socket 分不出这两种做法）；没给 --sock-buf 时
// 监听 socket 不能设，否则客户端 socket 继承到锁住的缓冲。
//
// UDP socket 的缓冲见 TestUDPSockBuf（U6）
func TestTCPSockBuf(t *testing.T) {
	t.Parallel()
	rmemDefault, wmemDefault := tcpBufDefault(t, "tcp_rmem"), tcpBufDefault(t, "tcp_wmem")
	t.Logf("tcp_rmem[1]=%d tcp_wmem[1]=%d；设 1 MiB 得到 %v", rmemDefault, wmemDefault, setBuf(t, 1<<20))
	for _, mode := range []struct {
		name  string
		extra []string
		kib   int // --sock-buf 的值，0 表示未给出
	}{
		{"default", nil, 0},
		{"sock-buf", []string{"--sock-buf", "40"}, 40},
		{"sock-buf-3000", []string{"--sock-buf", "3000"}, 3000},
	} {
		t.Run("tcp/"+mode.name, func(t *testing.T) {
			t.Parallel()
			accepted := make(chan net.Conn, 1)
			be := serveTCP(t, loopback4(t), func(c net.Conn) {
				accepted <- c
				streamHandler(c)
			})
			listen := loopback4(t)
			m := startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, mode.extra...)...)
			cl := dial(t, listen)
			// 后端 accept 返回时，tinymapper 的上游 socket 已处理完 SYN-ACK（建连时的缓冲调整在回 ACK 之前）
			var up net.Conn
			select {
			case up = <-accepted:
			case <-time.After(ioTimeout):
				t.Fatal("后端没有收到上游连接")
			}
			tcp := syscall.IPPROTO_TCP
			socks := []struct{ name, local, remote, ref, refLocal, refRemote string }{
				{"客户端 socket", listen, cl.LocalAddr().String(), "后端 accept 的连接", up.LocalAddr().String(), up.RemoteAddr().String()},
				{"上游 socket", up.RemoteAddr().String(), up.LocalAddr().String(), "测试拨出的连接", cl.LocalAddr().String(), cl.RemoteAddr().String()},
			}
			var want sockBuf // --sock-buf 时监听 socket 与两侧的期望值
			if mode.kib != 0 {
				want = setBuf(t, mode.kib<<10)
			}
			// 监听 socket 不经过建连时的 tcp_init_buffer_space，没设过时为 tcp_rmem[1]、tcp_wmem[1]
			lisWant := sockBuf{rcv: uint32(rmemDefault), snd: uint32(wmemDefault)}
			if mode.kib != 0 {
				lisWant = want
			}
			lis := lookupSockBuf(t, m.pid(), tcp, "监听 socket", listen, "0.0.0.0:0")
			t.Logf("监听 socket：%v", lis)
			if lis.rcv != lisWant.rcv || lis.snd != lisWant.snd {
				t.Errorf("监听 socket rcvbuf=%d sndbuf=%d，期望 %d、%d", lis.rcv, lis.snd, lisWant.rcv, lisWant.snd)
			}
			for _, s := range socks {
				got := lookupSockBuf(t, m.pid(), tcp, s.name, s.local, s.remote)
				ref := lookupSockBuf(t, os.Getpid(), tcp, s.ref, s.refLocal, s.refRemote)
				t.Logf("建连后 %s：%v；对照（%s）：%v", s.name, got, s.ref, ref)
				if mode.kib != 0 {
					if got.rcv != want.rcv || got.snd != want.snd {
						t.Errorf("建连后 %s rcvbuf=%d sndbuf=%d，期望 %d、%d（2×min(%d KiB, rmem_max/wmem_max)）",
							s.name, got.rcv, got.snd, want.rcv, want.snd, mode.kib)
					}
					continue
				}
				if got.rcv != uint32(rmemDefault) {
					t.Errorf("建连后 %s rcvbuf=%d，期望 tcp_rmem[1]=%d：设过 SO_RCVBUF", s.name, got.rcv, rmemDefault)
				}
				if got.snd != ref.snd {
					t.Errorf("建连后 %s sndbuf=%d，期望与%s相同（%d）：设过 SO_SNDBUF，建连时没有按拥塞窗口扩大发送缓冲",
						s.name, got.snd, s.ref, ref.snd)
				}
			}
			if mode.kib == 0 {
				return
			}
			if err := transferOn(cl, 16<<20, 16<<20, 256<<10, 0); err != nil {
				t.Fatalf("双向各传 16 MiB 失败：%v", err)
			}
			for _, s := range socks {
				got := lookupSockBuf(t, m.pid(), tcp, s.name, s.local, s.remote)
				t.Logf("双向各传 16 MiB 后 %s：%v", s.name, got)
				if got.rcv != want.rcv || got.snd != want.snd {
					t.Errorf("双向各传 16 MiB 后 %s rcvbuf=%d sndbuf=%d，期望仍为 %d、%d", s.name, got.rcv, got.snd, want.rcv, want.snd)
				}
			}
		})
	}
}

// 达到 max_conn_num（20000）后新连接被立即关闭，已有连接不受影响，释放后可再建立
func TestTCPMaxConn(t *testing.T) {
	t.Parallel()
	heavy(t)
	const maxConn = 20000
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)

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
	// O1：因 max_conn_num 被拒的客户端不计入 total
	if s := m.statsAfterSignal(t).tcp[1]; s.total != maxConn || s.conns != maxConn {
		t.Errorf("统计 total=%d conns=%d，期望 %d/%d", s.total, s.conns, maxConn, maxConn)
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
	// O1：上游 socket() 失败的客户端在建连接对之前就被丢弃，不计入 total
	if s := m.statsAfterSignal(t).tcp[1]; s.total != k || s.conns != k {
		t.Errorf("统计 total=%d conns=%d，期望 %d/%d", s.total, s.conns, k, k)
	}
	// warn 行的参数里 get_str() 先于 get_sock_error() 求值（T7 起两种构建都如此）：address_t::to_str 不能改动 errno
	eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
		if got := m.logLines("[WARN]", "create new_remote_fd failed,24:"); got != 1 {
			return fmt.Errorf("日志中有 %d 行 [WARN] 级、含 create new_remote_fd failed,24: 的记录，期望 1 行：创建上游 socket 失败的原因应记为 EMFILE（24）", got)
		}
		return nil
	})
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
	// T6 起 stdout 是文件时日志由 400 ms 的定时器写出，等第一行 accept failed 出现后再开始计时
	eventually(t, ioTimeout, 20*time.Millisecond, func() error {
		if acceptFailures() == 0 {
			return errors.New("pending 连接没有触发 accept 失败：fd 余量计算有误，用例没有测到 EMFILE")
		}
		return nil
	})
	ticks0, failures0 := m.cpuTicks(t), acceptFailures()
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
	// 每暂停一次记一行 warn，400 ms 的定时器恢复后再试。这些行也由该定时器写出，比记下时晚一个周期，两次读数各偏移
	// 不到 400 ms，2 s 内看到的仍约 5 行（至多 ⌊2.4 s/400 ms⌋+1=7 行）；空转时每轮都记，缓冲很快写满，远超 20 行
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

// EV_ERROR 在 fd_reify 里登记，要等本轮 epoll_wait 返回才回调：没有别的事件时最晚等一个 400 ms 的定时器周期，其余留给全量并行运行时的调度延迟
const everrorWithin = 2 * time.Second

// C9：新连接对的 fd 加进 epoll 失败（epoll_ctl ADD 返回 ENOSPC，如达到 fs.epoll.max_user_watches）时，libev 的 fd_kill 停掉该
// watcher 并以 EV_ERROR 回调 tcp_cb，只释放这一对；修复前 assert(0==1) 使整个进程中止。启动后 tinymapper 有 n 个 fd，k 个正常
// 连接对占 n..n+2k-1，之后的新连接对拿到 a=n+2k（客户端，accept 先于创建上游 socket）与 a+1（上游），释放后两个号空出，下一对又拿到它们。
//   - both：fd ≥ a 的 ADD 都失败。同一次 fd_reify 里先后 fd_kill 两个 fd，libev 后进先出地先回调上游一侧，erase_closed 对客户端
//     一侧的 ev_io_stop 清掉它还没回调的 EV_ERROR，所以每对恰好一行 warn；漏掉这一步则在已释放的连接对上再回调一次
//   - upstream：只有上游（fd ≥ a+1）失败，客户端一侧正常加进 epoll
//   - client：只有客户端一侧（fd a）失败，上游照常连上
//
// 偶数次尝试的客户端建连后立即发数据，奇数次不发：upstream 下数据已到时客户端一侧的 EV_READ 与上游的 EV_ERROR 同轮回调（前者后登记、
// 先回调，数据留在缓冲里，客户端随后读到 EOF；客户端一侧也失败时数据没人读，close 发 RST）。每次失败的尝试：客户端在 everrorWithin
// 内被关闭，warn 恰好多一行、fd 是失败一侧的 fd，fd 数回到 a，进程不退出（修复前在这里 assert 中止）。both、upstream 再做一次突发：
// 暂停 tinymapper 时排进 burst 个已发数据的客户端，恢复后同一轮 accept、下一轮全部失败（upstream 下第一对的客户端一侧正常，它的
// EV_READ 必与上游的 EV_ERROR 同轮），同样每对一行 warn。之后 k 个正常连接对仍能回显，每行 closed connection 的连接数与下一行
// lru.size() 相同；最后关闭一个正常连接对，新连接复用它低于失败区间的 fd 号，正常转发
func TestTCPEpollAddFail(t *testing.T) {
	t.Parallel()
	const k, attempts, burst = 3, 4, 3
	for _, c := range []struct {
		name   string
		lo, hi int // 失败区间 [a+lo, a+hi)；hi 为 0 表示不设上限
		burst  bool
	}{
		{"both", 0, 0, true},
		{"upstream", 1, 0, true},
		{"client", 0, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), echoHandler(""))
			listen := loopback4(t)
			wait := listenPoints("t", portOf(listen))
			// closed connection 的下一行是 lru.size()（debug 级）
			args := []string{"-l", listen, "-r", be.addr, "-t", "--log-level", "5"}
			n := startupFDs(t, wait, args...)
			a := n + 2*k
			lo, hi := a+c.lo, 0
			if c.hi != 0 {
				hi = a + c.hi
			}
			m := startMapperEpollAddFail(t, lo, hi, wait, args...)
			if got := fdCount(t, m.pid()); got != n {
				t.Fatalf("注入故障后启动时有 %d 个 fd，探测时为 %d", got, n)
			}
			healthy := make([]*net.TCPConn, k)
			for i := range healthy {
				healthy[i] = dial(t, listen)
				mustEcho(t, healthy[i], fmt.Sprintf("healthy-%d", i))
			}
			if got := fdCount(t, m.pid()); got != a {
				t.Fatalf("%d 个正常连接对之后 tinymapper 有 %d 个 fd，期望 %d", k, got, a)
			}

			const warn = "closed bc of EV_ERROR (epoll_ctl failed),fd="
			failed := map[string]bool{} // 失败连接对的客户端地址（日志中的 {ip:port}）
			// expectFailed 等 conns 都被关闭，且 warn 行、closed connection 行累计 len(failed) 行，fd 数回到 a
			expectFailed := func(what string, conns ...*net.TCPConn) {
				t.Helper()
				for i, cc := range conns {
					failed["{"+cc.LocalAddr().String()+"}"] = true
					if err := closedWithin(cc, everrorWithin); err != nil {
						t.Fatalf("%s第 %d 个客户端：%v（EV_ERROR 没有释放连接对）", what, i+1, err)
					}
				}
				eventually(t, logFlushWithin, 10*time.Millisecond, func() error {
					m.fatalIfExited(t, "%s后", what)
					if got := m.logLines("[WARN]", "[tcp]connection {", warn); got != len(failed) {
						return fmt.Errorf("日志中有 %d 行 EV_ERROR 的 warn，期望 %d（每个失败的连接对一行）", got, len(failed))
					}
					if got := m.logLines("[tcp]closed connection"); got != len(failed) {
						return fmt.Errorf("日志中有 %d 行 closed connection，期望 %d", got, len(failed))
					}
					if got := fdCount(t, m.pid()); got != a {
						return fmt.Errorf("tinymapper 有 %d 个 fd，期望 %d：失败的连接对有 fd 没有关闭", got, a)
					}
					return nil
				})
			}
			// 偶数次尝试建连后立即发数据，奇数次不发
			for i := range attempts {
				cc := dial(t, listen)
				if i%2 == 0 {
					if _, err := fmt.Fprintf(cc, "lost-%d\n", i); err != nil {
						t.Fatal(err)
					}
				}
				expectFailed(fmt.Sprintf("第 %d 次尝试", i+1), cc)
			}
			if c.burst {
				m.pause(t)
				conns := make([]*net.TCPConn, burst)
				for i := range conns {
					conns[i] = dial(t, listen)
					if _, err := fmt.Fprintf(conns[i], "burst-%d\n", i); err != nil {
						t.Fatal(err)
					}
				}
				m.cmd.Process.Signal(syscall.SIGCONT)
				expectFailed("突发中", conns...)
			}
			for i, hc := range healthy {
				if err := echo(hc, []byte("still-alive")); err != nil {
					t.Fatalf("第 %d 个正常连接对：%v", i+1, err)
				}
			}

			data, err := os.ReadFile(m.logPath)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(data), "\n")
			pairFDs := map[string][2]int{} // 客户端地址 → new_connection 行的 fd1、fd2
			warned := map[string]int{}
			for i, line := range lines {
				if _, rest, ok := strings.Cut(line, "[tcp]new_connection from "); ok {
					var fd [2]int
					for j, key := range []string{",fd1=", ",fd2="} {
						_, v, _ := strings.Cut(rest, key)
						v, _, _ = strings.Cut(v, ",")
						fd[j], _ = strconv.Atoi(v)
					}
					addr, _, _ := strings.Cut(rest, ",")
					pairFDs[addr] = fd
				}
				if _, rest, ok := strings.Cut(line, "[tcp]connection "); ok && strings.Contains(rest, warn) {
					addr, _, _ := strings.Cut(rest, " ")
					_, v, _ := strings.Cut(rest, warn)
					fd, _ := strconv.Atoi(strings.TrimSpace(v))
					warned[addr]++
					pf, ok := pairFDs[addr]
					switch {
					case !failed[addr]:
						t.Errorf("正常连接对 %s 收到 EV_ERROR：%q", addr, line)
					case !ok:
						t.Errorf("%q 之前没有 %s 的 new_connection 行", line, addr)
					case fd != pf[0] && fd != pf[1]:
						t.Errorf("%q 的 fd 不是该连接对的 fd（fd1=%d，fd2=%d）", line, pf[0], pf[1])
					case fd < lo || hi != 0 && fd >= hi:
						t.Errorf("%q 的 fd 不在失败区间 [%d, %d) 内：报错的是正常加进 epoll 的一侧", line, lo, hi)
					}
				}
				// 突发中的连接对逐个释放，剩余连接数从 k+burst-1 降到 k
				if _, rest, ok := strings.Cut(line, "[tcp]closed connection"); ok {
					_, v, _ := strings.Cut(rest, "tcp connections=")
					next := ""
					if i+1 < len(lines) {
						next = lines[i+1]
					}
					if left, _ := strconv.Atoi(v); left < k || left >= k+burst || !strings.HasSuffix(next, "[tcp] lru.size()="+v) {
						t.Errorf("%q 与下一行 %q：释放失败的连接对后应剩 %d–%d 个连接，lru.size() 相同", line, next, k, k+burst-1)
					}
				}
			}
			for addr := range failed {
				if warned[addr] != 1 {
					t.Errorf("失败的连接对 %s 有 %d 行 EV_ERROR 的 warn，期望 1", addr, warned[addr])
				}
			}

			// 恢复：正常连接对释放后空出低于失败区间的 fd 号，新连接拿到它们
			healthy[0].Close()
			eventually(t, ioTimeout, 10*time.Millisecond, func() error {
				if got := fdCount(t, m.pid()); got != a-2 {
					return fmt.Errorf("关闭一个正常连接对后 tinymapper 有 %d 个 fd，期望 %d", got, a-2)
				}
				return nil
			})
			mustEcho(t, dial(t, listen), "recovered")
		})
	}
}

// tcpState 用 TCP_INFO 读出 c 在本端的 TCP 状态（tcpi_state，取值同 /proc/net/tcp 的 st 列，如 5 为 FIN_WAIT2）
func tcpState(c *net.TCPConn) (uint8, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var info syscall.TCPInfo
	var errno syscall.Errno
	err = rc.Control(func(fd uintptr) {
		n := uint32(unsafe.Sizeof(info))
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&n)), 0)
	})
	if err == nil && errno != 0 {
		err = errno
	}
	return info.State, err
}

// acceptRuns 按日志顺序把 new_connection 行分段：段内只夹着 tcp_accept_one 自己打的 connect returned 调试行，
// 即同一次 tcp_accept_cb 回调接受的连接。返回各段长度，以及结束第一段的那一行
func acceptRuns(log string) (runs []int, firstEnd string) {
	in := false
	for _, line := range strings.Split(log, "\n") {
		switch {
		case strings.Contains(line, "[tcp]new_connection"):
			if !in {
				runs = append(runs, 0)
				in = true
			}
			runs[len(runs)-1]++
		case strings.Contains(line, "[tcp]connect returned"):
		case in:
			if len(runs) == 1 {
				firstEnd = line
			}
			in = false
		}
	}
	return runs, firstEnd
}

// T3：一次 accept 回调连续接受到 backlog 取空（EAGAIN，不记日志），但最多 batch 个。暂停 tinymapper，让 n 个已半关闭
// （FIN 已到）的连接排在 accept 队列里，恢复后第一次回调应恰好接受 batch 个。下一轮事件循环把这 batch 个客户端 socket 加进 epoll，
// 它们已可读（EOF），排在仍然就绪的监听 socket 之后（水平触发的监听 socket 上一轮报告后被放回就绪链表尾部，新加入的就绪 fd
// 排在它后面；libev 一次最多取 64 个事件，监听 socket 总在其中），libev 后进先出地回调，所以它们的 half-closed 日志
// 先于第 batch+1 个 new_connection。第一段长 1：每次回调只 accept 一个（1ba64a2）；长 n：一直 accept 到 EAGAIN
func TestTCPAcceptBatch(t *testing.T) {
	t.Parallel()
	// 每轮上限，与 main.cpp 的 max_accept_per_round 保持一致（4–64 均适用）
	const batch = 8
	// 大于两轮的上限，且不是 batch 的整数倍：最后一次回调接受余下 1 个后必然遇到 EAGAIN；远小于 listen backlog（截到 somaxconn，默认 4096）
	const n = 2*batch + 1
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	// half-closed 与 connect returned 是 debug 级日志；只开 info 级时两次回调的 new_connection 会连成一段
	m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--log-level", "5")
	m.pause(t)
	conns := make([]*net.TCPConn, n)
	for i := range conns {
		conns[i] = dial(t, listen)
		if err := conns[i].CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	// 客户端进入 FIN_WAIT2，即 accept 队列里对应的子 socket 已处理 FIN 并确认（CLOSE_WAIT），恢复后每个被 accept 的
	// 客户端 socket 一加入 epoll 就可读。不读 /proc/net/tcp：与 TestTCPMaxConn 并行时它有 8 万行，建连期间读一遍实测 7.8 s
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		for i, c := range conns {
			st, err := tcpState(c)
			if err != nil {
				return err
			}
			if st != 5 { // TCP_FIN_WAIT2
				return fmt.Errorf("第 %d 个客户端的 TCP 状态为 %d，期望 5（FIN_WAIT2）：tinymapper 一侧的子 socket 尚未确认 FIN", i+1, st)
			}
		}
		return nil
	})
	if got := m.logLines("[tcp]new_connection"); got != 0 {
		t.Fatalf("恢复前日志中已有 %d 行 new_connection：tinymapper 没有在建连前暂停", got)
	}
	m.cmd.Process.Signal(syscall.SIGCONT)
	// 上游读到转发的 FIN 后关闭写方向，两侧都 EOF 后连接对被释放，客户端读到 EOF
	deadline := time.Now().Add(3 * ioTimeout)
	for i, c := range conns {
		c.SetReadDeadline(deadline)
		if b, err := io.ReadAll(c); err != nil || len(b) != 0 {
			t.Fatalf("第 %d 个连接读到 %d 字节（%v），期望 EOF：backlog 中的连接没有全部被接受并转发", i+1, len(b), err)
		}
	}
	eventually(t, ioTimeout, 20*time.Millisecond, func() error {
		if got := m.logLines("[tcp]closed connection"); got != n {
			return fmt.Errorf("日志中有 %d 行 closed connection，期望 %d：连接对没有全部释放", got, n)
		}
		return nil
	})
	if got := m.logLines("[tcp]new_connection"); got != n {
		t.Errorf("日志中有 %d 行 new_connection，期望 %d", got, n)
	}
	// 最后一次回调取空 backlog，以 EAGAIN 结束
	if got := m.logLines("accept failed"); got != 0 {
		t.Errorf("日志中有 %d 行 accept failed，期望 0：backlog 取空时的 EAGAIN 是一轮的正常结束，不应记日志", got)
	}
	data, err := os.ReadFile(m.logPath)
	if err != nil {
		t.Fatal(err)
	}
	runs, end := acceptRuns(string(data))
	shown := fmt.Sprint(runs)
	if len(runs) > 8 {
		shown = fmt.Sprintf("%v…（共 %d 次）", runs[:8], len(runs))
	}
	t.Logf("各次 accept 回调接受的连接数：%s；结束第一段的日志：%s", shown, strings.TrimSpace(end))
	first := 0
	if len(runs) > 0 {
		first = runs[0]
	}
	if first != batch {
		t.Errorf("恢复后第一次 accept 回调连续接受了 %d 个连接，期望 %d（max_accept_per_round）：1 表示每次回调只 accept 一个；"+
			"%d（全部）表示一次取空 backlog，没有每轮上限或上限不小于 %d；其他值表示每轮上限与本用例的 batch 不一致", first, batch, n, n)
	}
}

// T10：watcher->data 直接指向连接对象，释放顺序固定为“两侧 ev_io_stop → close → 释放对象”。libev 的 ev_io_stop 先
// clear_pending：本轮 epoll_wait 已登记、还没回调的事件换成空 watcher，所以同一对的另一个 watcher 不会再回调到已释放的
// 对象上，fd 号随后被本轮后面 accept 的连接复用也安全。本用例让这两件事在恢复后的第一轮里发生：
//   - 建 nOld 个连接对，各往返一次（两侧 watcher 都只等读），然后暂停 tinymapper；
//   - 先排进 nNew 个新连接（各已写入一行独有的数据），等 accept 队列达到 nNew，监听 socket 先进入 epoll 就绪链表；
//   - 再让每个旧连接对的两个 fd 都可读：偶数对上游先写数据、客户端再发 RST；奇数对客户端先写数据、上游再发 RST。
//     恢复前用 sock_diag 确认 RST 与数据都已投递到 tinymapper 的 socket。
//     libev 按 epoll 返回的顺序登记、后进先出地回调，所以每对后变为可读的一侧（收到 RST 的那侧）先回调，recv 得到
//     ECONNRESET 后 erase_closed 释放连接对，这时另一侧的事件还在 pending 里。漏掉哪一侧的 ev_io_stop，偶数对或奇数对
//     就会在已释放的对象上回调：release 构建通常对已关闭的 fd 收发得到 EBADF 或堆损坏中止，ASan 构建报 heap-use-after-free；
//   - 2×nOld+1 个就绪 fd 不超过 libev 一次 epoll_wait 取的 64 个事件，监听 socket 排在最前、最后回调，本轮 accept 的连接
//     （每轮最多 max_accept_per_round=8 个）拿到的就是刚释放的最小 fd 号。nNew 多于两轮的上限，即使回调顺序不同，
//     后面几轮 accept 的连接也一定复用旧连接对的 fd 号。复用的 fd 号上，libev 缓存的事件掩码还是旧连接的（READ），新
//     watcher 必须经 ev_io_init（EV__IOFDSET）才会被重新加进 epoll，否则新连接收不到数据（T10 审查 F3）
//
// 恢复后：每个新连接收发自己的数据（不串线）并正常半关闭；旧连接对的另一端都被关闭；全部释放后 fd 数回到建连前（没有漏关）；
// 日志里没有 EBADF（对已关闭的 fd 收发），每行 closed connection 的连接数与下一行的 lru.size() 相同，tinymapper 没有退出
func TestTCPFdReuseBurst(t *testing.T) {
	t.Parallel()
	const nOld = 24
	const nNew = 2*8 + 1
	type reg struct {
		id int
		c  net.Conn
	}
	regs := make(chan reg, nOld)
	// 旧连接对的上游一侧读到 EOF/RST：偶数对说明 tinymapper 关闭了上游 socket，奇数对是本用例自己发的 RST
	oldDone := make(chan int, nOld)
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if id, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "old-"); ok {
			i, _ := strconv.Atoi(id)
			if _, err := io.WriteString(c, "ack "+line); err != nil {
				return
			}
			regs <- reg{i, c}
			io.Copy(io.Discard, r)
			oldDone <- i
			return
		}
		// 新连接：先回显首行，之后照常回显，读到 EOF 后关闭写方向
		if _, err := io.WriteString(c, line); err != nil {
			return
		}
		io.Copy(c, r)
		c.(*net.TCPConn).CloseWrite()
	})
	listen := loopback4(t)
	// new_connection 带 fd1/fd2（info 级），closed connection 的下一行是 lru.size()（debug 级）
	m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--log-level", "5")
	fds0 := fdCount(t, m.pid())

	clients := make([]*net.TCPConn, nOld)
	backs := make([]net.Conn, nOld)
	for i := range clients {
		clients[i] = dial(t, listen)
		if _, err := fmt.Fprintf(clients[i], "old-%d\n", i); err != nil {
			t.Fatal(err)
		}
		if got, want := readLine(t, clients[i]), fmt.Sprintf("ack old-%d", i); got != want {
			t.Fatalf("第 %d 个旧连接读到 %q，期望 %q", i+1, got, want)
		}
	}
	for range nOld {
		select {
		case r := <-regs:
			backs[r.id] = r.c
		case <-time.After(ioTimeout):
			t.Fatal("后端没有收到全部旧连接")
		}
	}

	// 每对旧连接在 tinymapper 一侧的两个 socket（[0] 客户端侧、[1] 上游侧）的本端、对端地址与 inode，用于确认 RST 与数据已投递
	type tmSock struct {
		local, remote string
		inode         uint32
	}
	tcp := syscall.IPPROTO_TCP
	tmSocks := make([][2]tmSock, nOld)
	for i := range clients {
		for k, a := range [2][2]string{{listen, clients[i].LocalAddr().String()}, {backs[i].RemoteAddr().String(), be.addr}} {
			tmSocks[i][k] = tmSock{a[0], a[1], lookupSockBuf(t, m.pid(), tcp, "旧连接对的 socket", a[0], a[1]).inode}
		}
	}

	m.pause(t)
	news := make([]*net.TCPConn, nNew)
	payloads := make([]string, nNew)
	for j := range news {
		news[j] = dial(t, listen)
		payloads[j] = fmt.Sprintf("new-%d-%016x\n", j, rand.Uint64())
		if _, err := io.WriteString(news[j], payloads[j]); err != nil {
			t.Fatal(err)
		}
	}
	// 新连接全部排进 accept 队列后再让旧连接对可读：监听 socket 一定排在 epoll 就绪链表里旧连接对的 fd 之前，
	// 不依赖“dial 返回 = 子 socket 已入队”（客户端发出最后的 ACK 即返回，服务端可能稍后才处理）
	eventually(t, ioTimeout, 5*time.Millisecond, func() error {
		if q := lookupSockBuf(t, m.pid(), tcp, "监听 socket", listen, "0.0.0.0:0"); q.rqueue != nNew {
			return fmt.Errorf("监听 socket 的 accept 队列长度为 %d，期望 %d", q.rqueue, nNew)
		}
		return nil
	})
	for i, c := range clients {
		if i%2 == 0 {
			if _, err := fmt.Fprintf(backs[i], "data-%d\n", i); err != nil {
				t.Fatal(err)
			}
			c.SetLinger(0) // close 时发送 RST
			c.Close()
		} else {
			if _, err := fmt.Fprintf(c, "data-%d\n", i); err != nil {
				t.Fatal(err)
			}
			backs[i].(*net.TCPConn).SetLinger(0)
			backs[i].Close()
		}
	}
	// SIGCONT 之前等 RST 与数据都投递到 tinymapper 的 socket：收到 RST 的一侧已从哈希表摘除（查不到，或按四元组查到的已是
	// 别的 socket，如客户端侧摘除后查到监听 socket），另一侧接收队列非空。不等时负载下约 2% 的运行在恢复时 epoll 里只有监听
	// socket 就绪，连续几轮 accept 都排在旧连接对释放之前，测不到 fd 复用（build/t13/tests-report.md §3.4）
	var delivered string // 投递状态，覆盖自检失败时打印
	eventually(t, ioTimeout, 5*time.Millisecond, func() error {
		gone, queued := 0, 0
		for i, s := range tmSocks {
			rst, data := s[0], s[1] // 偶数对客户端发 RST、上游发数据；奇数对相反
			if i%2 == 1 {
				rst, data = data, rst
			}
			if b, err := sockDiag(tcp, rst.local, rst.remote); err != nil || b.inode != rst.inode {
				gone++
			}
			if b, err := sockDiag(tcp, data.local, data.remote); err == nil && b.inode == data.inode && b.rqueue > 0 {
				queued++
			}
		}
		lis := lookupSockBuf(t, m.pid(), tcp, "监听 socket", listen, "0.0.0.0:0")
		delivered = fmt.Sprintf("SIGCONT 前 %d/%d 个旧连接对收到 RST 的一侧已摘除，%d/%d 个另一侧接收队列非空，accept 队列 %d",
			gone, nOld, queued, nOld, lis.rqueue)
		if gone != nOld || queued != nOld {
			return errors.New(delivered)
		}
		return nil
	})
	m.cmd.Process.Signal(syscall.SIGCONT)

	for j, c := range news {
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		got := make([]byte, len(payloads[j]))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != payloads[j] {
			t.Fatalf("第 %d 个新连接读回 %q（%v），期望 %q：新连接没有被转发，或串到了别的连接", j+1, got, err, payloads[j])
		}
		if err := echo(c, []byte(fmt.Sprintf("again-%d-%016x", j, rand.Uint64()))); err != nil {
			t.Fatalf("第 %d 个新连接第二次往返：%v", j+1, err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		if b, err := io.ReadAll(c); err != nil || len(b) != 0 {
			t.Fatalf("第 %d 个新连接半关闭后读到 %d 字节（%v），期望 EOF", j+1, len(b), err)
		}
	}
	for i := 1; i < nOld; i += 2 {
		if err := closedWithin(clients[i], ioTimeout); err != nil {
			t.Errorf("第 %d 个旧连接（上游发 RST）的客户端一侧：%v", i+1, err)
		}
	}
	done := map[int]bool{}
	timeout := time.After(ioTimeout)
	for len(done) < nOld {
		select {
		case i := <-oldDone:
			done[i] = true
		case <-timeout:
			var missing []int
			for i := 0; i < nOld; i += 2 {
				if !done[i] {
					missing = append(missing, i+1)
				}
			}
			t.Fatalf("客户端发 RST 的旧连接中，第 %v 个的上游一侧 %v 内没有被关闭", missing, ioTimeout)
		}
	}
	eventually(t, logFlushWithin, 20*time.Millisecond, func() error {
		if got := m.logLines("[tcp]closed connection"); got != nOld+nNew {
			return fmt.Errorf("日志中有 %d 行 closed connection，期望 %d：连接对没有全部释放", got, nOld+nNew)
		}
		if got := m.logLines("[tcp] lru.size()="); got != nOld+nNew {
			return fmt.Errorf("日志中有 %d 行 lru.size()，期望 %d", got, nOld+nNew)
		}
		if got := fdCount(t, m.pid()); got != fds0 {
			return fmt.Errorf("全部连接释放后 tinymapper 有 %d 个 fd，建连前为 %d：有 fd 没有关闭", got, fds0)
		}
		return nil
	})
	if m.exited() {
		t.Fatalf("tinymapper 已退出：%v", m.exitErr)
	}
	if got := m.logLines("bc of 9:"); got != 0 {
		t.Errorf("日志中有 %d 行因 EBADF（9）关闭连接：回调到了已释放的连接对，对已关闭的 fd 收发", got)
	}

	data, err := os.ReadFile(m.logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	var conns [][2]int // 各 new_connection 行的 fd1、fd2，按日志顺序：前 nOld 行是旧连接对
	firstNew, closedBefore := -1, 0
	for i, line := range lines {
		if _, rest, ok := strings.Cut(line, "[tcp]new_connection"); ok {
			var fd [2]int
			for k, key := range []string{",fd1=", ",fd2="} {
				_, v, _ := strings.Cut(rest, key)
				v, _, _ = strings.Cut(v, ",")
				fd[k], _ = strconv.Atoi(v)
			}
			conns = append(conns, fd)
			if len(conns) == nOld+1 {
				firstNew = i
			}
		}
		if _, n, ok := strings.Cut(line, "[tcp]closed connection"); ok {
			if firstNew < 0 {
				closedBefore++
			}
			_, n, _ = strings.Cut(n, "tcp connections=")
			next := ""
			if i+1 < len(lines) {
				next = lines[i+1]
			}
			if !strings.HasSuffix(next, "[tcp] lru.size()="+n) {
				t.Errorf("%q 的下一行是 %q，期望以 [tcp] lru.size()=%s 结尾", line, next, n)
			}
		}
	}
	if len(conns) != nOld+nNew {
		t.Fatalf("日志中有 %d 行 new_connection，期望 %d", len(conns), nOld+nNew)
	}
	oldFDs := map[int]bool{}
	for _, fd := range conns[:nOld] {
		oldFDs[fd[0]], oldFDs[fd[1]] = true, true
	}
	reused := 0
	for _, fd := range conns[nOld:] {
		if oldFDs[fd[0]] || oldFDs[fd[1]] {
			reused++
		}
	}
	t.Logf("新连接对中 %d/%d 个复用了旧连接对的 fd 号；第一个新连接对之前已释放 %d 个旧连接对（%d 表示本轮先释放再 accept）",
		reused, nNew, closedBefore, nOld)
	if reused == 0 {
		t.Errorf("没有一个新连接对复用旧连接对的 fd 号（旧 %v，新 %v；第一个新连接对之前已释放 %d 个旧连接对；%s）：用例没有覆盖 fd 复用",
			conns[:nOld], conns[nOld:], closedBefore, delivered)
	}
}

// T5：TCP 监听 socket 以 listen_backlog（65535）调用 listen，内核截到本网络命名空间的 net.core.somaxconn（5.4 起默认 4096）；
// 修复前固定为 512。accept 队列在 sk_ack_backlog > sk_max_ack_backlog 时判满，容量为 backlog+1，判满后到达的 SYN 被
// tcp_conn_request 丢弃（LISTENOVERFLOWS），客户端约 1 s、3 s 后重传，所以 tinymapper 来不及 accept 时，超出容量的突发建连
// 要等队列腾出空间才能连上。
//   - 监听 socket 的 sk_max_ack_backlog（LISTEN 状态下 sock_diag 的 idiag_wqueue）应为 min(65535, somaxconn)
//   - 暂停 tinymapper：内核照常完成握手，把子 socket 排进 accept 队列。逐个建立 n 个连接（远大于旧容量 513、远小于 4097），
//     应全部连上且 accept 队列长度（idiag_rqueue）达到 n；修复前第 514 个连接的 SYN 与重传全被丢弃，ioTimeout 内连不上。
//     不并发建连：并发时队列将满之际收下的 SYN，最后的 ACK 可能因队列已满被丢弃，客户端却已连上，连上的个数不再等于容量
//   - 恢复后每个连接都被接受并转发：各回显一次，new_connection 恰好 n 行
func TestTCPListenBacklog(t *testing.T) {
	t.Parallel()
	const n = 2048
	data, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		t.Fatal(err)
	}
	somaxconn, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("/proc/sys/net/core/somaxconn 内容异常：%q", data)
	}
	backlog := min(65535, somaxconn) // main.cpp 的 listen_backlog（65535）截到 somaxconn
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := forward(t, "t", listen, be.addr)
	tcp := syscall.IPPROTO_TCP
	lis := lookupSockBuf(t, m.pid(), tcp, "监听 socket", listen, "0.0.0.0:0")
	t.Logf("somaxconn=%d；监听 socket 的 accept 队列上限 %d", somaxconn, lis.wqueue)
	if lis.wqueue != uint32(backlog) {
		t.Errorf("监听 socket 的 sk_max_ack_backlog 为 %d，期望 min(65535, somaxconn)=%d：listen backlog 不是 65535（512 为修复前的固定值）",
			lis.wqueue, backlog)
	}
	if backlog+1 < n {
		t.Skipf("somaxconn=%d：accept 队列容量 %d 容不下 %d 个连接，跳过突发建连", somaxconn, backlog+1, n)
	}

	m.pause(t)
	conns := make([]net.Conn, 0, n)
	t.Cleanup(func() { closeAll(conns) })
	start := time.Now()
	for len(conns) < n {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			q := lookupSockBuf(t, m.pid(), tcp, "监听 socket", listen, "0.0.0.0:0")
			t.Fatalf("暂停期间只连上 %d 个，第 %d 个连接失败（%v），此时 accept 队列长度 %d、上限 %d。若是超时，即 SYN 与重传因队列已满"+
				"被丢弃：容量为 backlog+1，连上 %d 个对应 listen backlog %d，期望 %d", len(conns), len(conns)+1, err, q.rqueue, q.wqueue,
				len(conns), len(conns)-1, backlog)
		}
		conns = append(conns, c)
	}
	elapsed := time.Since(start)
	// 客户端发出最后的 ACK 后 connect 即返回，服务端可能稍后才处理这个 ACK
	var q sockBuf
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		if q = lookupSockBuf(t, m.pid(), tcp, "监听 socket", listen, "0.0.0.0:0"); q.rqueue != n {
			return fmt.Errorf("监听 socket 的 accept 队列长度为 %d，期望 %d：已连上的客户端没有全部作为子 socket 排在队列中", q.rqueue, n)
		}
		return nil
	})
	t.Logf("暂停期间逐个建立 %d 个连接用时 %v，accept 队列长度 %d", n, elapsed.Round(time.Millisecond), q.rqueue)

	m.cmd.Process.Signal(syscall.SIGCONT)
	errs := make([]error, n)
	parallelFor(n, 64, func(i int) { errs[i] = echo(conns[i], []byte(strconv.Itoa(i))) })
	failed := 0
	for i, err := range errs {
		if err != nil {
			if failed++; failed <= 5 {
				t.Errorf("恢复后第 %d 个连接回显失败：%v", i+1, err)
			}
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d 个连接回显失败：accept 队列中的连接没有全部被接受并转发", failed, n)
	}
	// T6 起 stdout 是文件时最后不满一个 stdio 缓冲的日志要等 400 ms 的定时器写出
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if got := m.logLines("[tcp]new_connection"); got != n {
			return fmt.Errorf("日志中有 %d 行 new_connection，期望 %d", got, n)
		}
		return nil
	})
}

// 空闲超过 conn_timeout_tcp（360 s）的连接被清理，期间保持活跃的连接不受影响。
// 清理每轮最多关 1 条、约 1.2 s 一轮：活跃连接若也超时了（LRU 没把它挪到队首，或挪动时没刷新时间戳），
// 会比空闲连接晚一轮才被清理，所以空闲连接被清理后再等 5 s 才检查活跃连接。
// 约 90 s 保活后再建一条之后不收发的连接 late：LRU 若把新连接挂在表尾，它会挡住空闲连接，直到它自己也超时（约 450 s）。
// 建 late 之后不再保活（活跃连接检查时空闲约 280 s，仍未超时）：否则活跃连接挪到 late 前面，
// 挪动时不刷新时间戳的错误实现里活跃连接的过期会被 late 挡住
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
	var late *net.TCPConn
	for {
		err := closedWithin(idle, 30*time.Second)
		if err == nil {
			break
		}
		if elapsed := time.Since(last); elapsed > 420*time.Second {
			t.Fatalf("空闲 %v 后连接仍未被清理", elapsed.Round(time.Second))
		}
		if late == nil {
			mustEcho(t, active, "keepalive")
			if time.Since(last) >= 75*time.Second {
				late = dial(t, listen)
				mustEcho(t, late, "late")
			}
		}
	}
	elapsed := time.Since(last)
	t.Logf("空闲连接在 %v 后被清理", elapsed.Round(time.Second))
	if elapsed < 350*time.Second {
		t.Errorf("空闲连接过早被清理：%v（超时应为 360 s）", elapsed.Round(time.Second))
	}
	time.Sleep(5 * time.Second)
	mustEcho(t, active, "after")
	mustEcho(t, late, "after")
}
