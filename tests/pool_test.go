// T11 连接对象瘦身与池化的功能测试：每连接用户态内存上限、背压下缓冲交接（池空/超出空闲上限两条路径）、释放路径不漏缓冲。
//
// T11 把 tcp_info_t 内联的两块 16 KiB 缓冲换成一个指针 buf：所有 recv 读进一块全局 64 KiB scratch，发完就留着给下一次；
// 没发完（含上游建连中）才把整块交给该方向（my_info.buf，不拷贝），下一次 recv 前再从 tcp_buf_pool 取一块。缓冲池最多留
// tcp_buf_pool_max_free=64 块空闲，超出就 free；池空就 malloc。连接对（tcp_pair_t/udp_pair_t）来自 obj_pool_t 的 slab。
package tests

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// vmRSS 读 /proc/<pid>/status 的 VmRSS，单位 KB
func vmRSS(t testing.TB, pid int) int {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			kb, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(v), " kB"))
			if err != nil {
				t.Fatalf("/proc/%d/status 的 VmRSS 无法解析：%q", pid, line)
			}
			return kb
		}
	}
	t.Fatalf("/proc/%d/status 中没有 VmRSS", pid)
	return 0
}

// startMapperStableRSS 同 startMapper，但让 ASan 构建的 RSS 只随 tinymapper 自己的分配变化，release 构建忽略 ASAN_OPTIONS：
//   - quarantine_size_mb=0：默认 256 MB 的隔离区让 free 掉的块暂不再分配，下一次 malloc 拿新内存，RSS 随每次 free 增长
//     （缓冲池超出 64 块上限时就会 free）；池里空闲的对象和块仍由 pool_poison 标为不可访问；
//   - detect_stack_use_after_return=0：不建 fake stack。它是一块约 11 MiB 的映射，栈帧分配位置逐次前移，页面被陆续碰到，
//     实测每个连接让 RSS 涨约 2.6 KB（直到整块碰完），与 tinymapper 的分配无关
func startMapperStableRSS(t testing.TB, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(mapperBin, append([]string{"--disable-color"}, args...)...)
	cmd.Env = append(os.Environ(), "ASAN_OPTIONS=quarantine_size_mb=0:thread_local_quarantine_size_kb=0:detect_stack_use_after_return=0")
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}

// T11：每个空闲连接的用户态内存（P1 门槛 ≤ 2 KB/连接）。8947a52 的 tcp_info_t 内联 data[16384+200]，每个连接对两块，
// 连同 std::list 节点约 33 KB；T11 之后连接对约 240 B（slab 每 64 个一块），收发只用全局一块 64 KiB scratch。
// 先建 warm 条连接各做一次 1 字节回显并保持：一次性开销（第一次 recv 分配的 scratch、第一块 slab 正好用满、libev 的初始数组）
// 都落在基线里；再先后建两批、各 n 条同样的空闲连接，每批前后各读一次，取增量较小的一批除以 n 作为每连接增量，断言 < 2 KiB。
// 取较小的一批：真正按连接计的开销两批都有，一次性的台阶（如 ASan 运行库内部的分配，实测在别的用例里出现过一次 +1.4 MB）只会落在
// 其中一批。1 字节回显在新连接上总能一次发完（发送缓冲为空），不会把块交给方向，所以测量期间缓冲池不会多出块（池最多 64 块
// ≈ 4 MiB，只可能来自本进程自己的流量，而本用例只有这些小回显）；内核 socket 缓冲不计入 VmRSS。
// 实测（每连接）：工作区 glibc/musl 约 0.3 KB，ASan 约 0.5 KB（经 startMapperStableRSS 关掉 fake stack 与隔离区，只多出红区与影子内存）；
// 8947a52 为 8.5 KB（glibc）/ 12.5 KB（musl）而失败：1 字节回显只碰到内联缓冲的头几页，基准里 32 KiB 往返把两块都写满才是 33 KB
func TestTCPConnPerConnMem(t *testing.T) {
	t.Parallel()
	heavy(t)
	const warm, n = 64, 1000
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := startMapperStableRSS(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")

	conns := make([]net.Conn, warm+2*n)
	t.Cleanup(func() { closeAll(conns) })
	// open 建立 conns[from:to]，每条做一次 1 字节回显（两个方向都经过 tcp_cb，上游已连上），之后保持空闲
	open := func(from, to int) {
		errs := make([]error, to-from)
		parallelFor(to-from, 128, func(k int) {
			c, err := net.DialTimeout("tcp", listen, 10*time.Second)
			if err == nil {
				conns[from+k] = c
				err = echo(c, []byte{byte(k)})
			}
			errs[k] = err
		})
		for k, err := range errs {
			if err != nil {
				t.Fatalf("第 %d 个连接：%v", from+k+1, err)
			}
		}
		m.fatalIfExited(t, "持有 %d 条空闲连接时", to)
		time.Sleep(300 * time.Millisecond) // 连接全部静止后再读 VmRSS
	}
	open(0, warm)
	rss := []int{vmRSS(t, m.pid())}
	for b := range 2 {
		open(warm+b*n, warm+(b+1)*n)
		rss = append(rss, vmRSS(t, m.pid()))
	}

	perConn := float64(min(rss[1]-rss[0], rss[2]-rss[1])) * 1024 / n
	const bound = 2 << 10
	t.Logf("预热 %d 条后、每再持有 %d 条空闲连接后的 VmRSS（KB）：%v；较小一批每连接 %.0f B（门槛 %d B）", warm, n, rss, perConn, bound)
	if perConn >= float64(bound) {
		t.Fatalf("每个空闲连接的用户态内存约 %.0f B，≥ 门槛 %d B：连接对没有瘦身（8947a52 在本用例中为 8.5–12.5 KB/连接）", perConn, bound)
	}
}

// 背压用例里读端 socket 的参数，在 connect/listen 之前设好（accept 得到的连接继承监听 socket 的）：
//   - readerRcv：接收缓冲小，tinymapper 发往读端的 socket 发送缓冲只能按读端的速度腾出空间，EPOLLOUT 时腾出的空间常常装不下
//     还持有的数据，write 分支的 send 一再只发出一部分；
//   - readerMSS：loopback 的 MSS 约 64 KiB，接收端按它估出的 rcv_mss 大于整个接收缓冲时，为避免糊涂窗口会一直通告零窗口，
//     传输只能靠持续探测定时器推进（实测每条流约 40 KiB/s）；MSS 压小后读端腾出一点空间就能通告窗口。
//
// 实测（glibc 诊断构建 build/t11/mk-diag.sh 在各路径打日志，TestTCPBufferPoolStorm 3 轮）：readerRcv 为 8 KiB 时 write 分支部分发送
// 471 次、交接 2459 次、池空 malloc 205 次、超上限 free 141 次；16 KiB 时 344 次部分发送；32 KiB 时只剩 9 次；读端不设这些参数
// （接收缓冲 128 KiB）时为 0 次，write 分支的部分发送整条路径都没有走到
const readerRcv, readerMSS = 8 << 10, 1460

// readerPace：读端每读这么多字节小睡 1 ms，保证读端始终比 tinymapper 慢
const readerPace = 32 << 10

func slowReaderSocket(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, readerMSS); serr == nil {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, readerRcv)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// slowVerify 从 r 分小块读 size 字节，每读 readerPace 字节小睡 1 ms，用 SHA-256 与 seed 推出的期望流比对
func slowVerify(r io.Reader, size int64, seed [32]byte) error {
	h := sha256.New()
	buf := make([]byte, 8<<10)
	var got int64
	for got < size {
		n, err := r.Read(buf[:min(int64(len(buf)), size-got)])
		if n > 0 {
			h.Write(buf[:n])
			got += int64(n)
			if got/readerPace != (got-int64(n))/readerPace {
				time.Sleep(time.Millisecond)
			}
		}
		if err != nil {
			return fmt.Errorf("读到 %d/%d 字节：%w", got, size, err)
		}
	}
	if exp, _ := writeStream(io.Discard, size, 64<<10, seed); !bytes.Equal(h.Sum(nil), exp) {
		return errors.New("SHA-256 不一致")
	}
	return nil
}

// tmHolds 用 sock_diag 判断 tinymapper 是否正持有某方向的缓冲，返回 nil 表示持有：源一侧 socket 接收队列非空（tinymapper 已停读），
// 目的一侧 socket 发送队列非空（发不出去）。tinymapper 不持有缓冲时源一侧一直在读（水平触发），接收队列很快被读空
func tmHolds(pid int, srcLocal, srcRemote, dstLocal, dstRemote string) error {
	inodes := socketInodes(pid)
	var q [2]sockBuf
	for i, a := range [2][2]string{{srcLocal, srcRemote}, {dstLocal, dstRemote}} {
		b, err := sockDiag(syscall.IPPROTO_TCP, a[0], a[1])
		if err != nil {
			return fmt.Errorf("sock_diag 查找 %s → %s：%w", a[0], a[1], err)
		}
		if !inodes[strconv.FormatUint(uint64(b.inode), 10)] {
			return fmt.Errorf("%s → %s（inode %d）不是 tinymapper 的 socket", a[0], a[1], b.inode)
		}
		q[i] = b
	}
	if q[0].rqueue == 0 || q[1].wqueue == 0 {
		return fmt.Errorf("源一侧 %s 接收队列 %d、目的一侧 %s 发送队列 %d", srcRemote, q[0].rqueue, dstRemote, q[1].wqueue)
	}
	return nil
}

// T11：缓冲池在背压下的交接。每轮同时建 nDown+nUp 条连接，两个方向各半：
//   - down：后端向客户端写 S 字节，客户端先不读：tinymapper 读满一块发不完，交给上游侧（remote.buf）并停读上游；
//   - up：客户端向后端写 S 字节，后端先不读：tinymapper 把块交给客户端侧（local.buf）并停读客户端。
//
// 放行前用 sock_diag 确认 96 条连接都在持有缓冲（> tcp_buf_pool_max_free=64）：持有数涨到 96 期间池一直是空的，每次交接后的下一次
// recv 都要 malloc（池空路径）。放行后读端（readerRcv/readerMSS/readerPace，见上）慢读排空：read 分支一再只发出一部分而交接，
// write 分支在 EPOLLOUT 后也一再只发出一部分、继续持有（这条路径只有本用例能稳定走到：发送缓冲自动调优时，EPOLLOUT 腾出的空间远大于
// 一块，write 分支总能一次发完），块陆续归还（池里超过 64 块的被 free，超上限路径）；每条流都用 SHA-256 校验端到端一致。
//   - sock-buf：--sock-buf 32 把 tinymapper 两侧 socket 缓冲锁在约 64 KiB（池块仍是 64 KiB，与 socket 缓冲无关）；
//   - default：不带 --sock-buf（默认部署路径）。tinymapper 发往读端的 socket 发送缓冲由 tcp_sndbuf_expand 按“2×拥塞窗口×每段内存”
//     扩大，读端 MSS 为 1460 时只有约 87 KB（MSS 64 KiB 时为 2.6 MB）；读端的接收窗口限住发送，拥塞窗口不再增长，发送缓冲也就不再扩大。
//     源一侧接收缓冲自动调优、recv 一次读满 64 KiB 的块，持有的剩余数据常常多于 EPOLLOUT 时腾出的空间。
//
// 这两项测的是块池，所以带 --disable-splice：splice 开着时大流量方向持有的是 pipe（B2）。
//   - splice：同 default 但 splice 开着：两个方向反复持有 pipe、write 分支一再只 splice 出一部分、pipe 还池或 close，SHA-256 照样校验；
//     fd 比的是非 pipe fd（scratch pipe 与空闲 pipe 合法地留着），VmRSS 这一项对它只是附带。
//
// 共 rounds 轮，比较第 2 轮与最后一轮结束时的 VmRSS：排空的块若只置 0 不还池，每次交接都泄漏一块；正常实现持平
func TestTCPBufferPoolStorm(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		extra []string
	}{
		{"sock-buf", []string{"--sock-buf", "32", "--disable-splice"}},
		{"default", []string{"--disable-splice"}},
		{"splice", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			poolStorm(t, c.extra...)
		})
	}
}

func poolStorm(t *testing.T, extra ...string) {
	const nDown, nUp = 48, 48
	const m = nDown + nUp
	const S = 512 << 10
	const rounds = 3

	results := make(chan error, m) // 每轮 m 个校验结果：down 由客户端、up 由后端校验
	goCh := make(chan struct{}, m) // 每轮放行 m 个读端：nDown 个 down 客户端与 nUp 个 up 后端
	var tmUpLocal sync.Map         // 标记行 → 后端看到的对端地址，即该连接的 tinymapper 上游 socket 的本端地址

	// 后端对 up 方向是读端（对 down 方向只读一行标记，读端参数无影响）
	be := serveTCPConfig(t, net.ListenConfig{Control: slowReaderSocket}, loopback4(t), func(c net.Conn) {
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\n")
		tmUpLocal.Store(line, c.RemoteAddr().String())
		kind, num, _ := strings.Cut(line, "-")
		i, _ := strconv.Atoi(num)
		if kind == "down" {
			writeStream(c, S, 32<<10, streamSeed(uint64(i), true))
		} else {
			<-goCh
			results <- slowVerify(r, S, streamSeed(uint64(i), false))
		}
		io.Copy(io.Discard, r) // 等客户端关闭
	})
	listen := loopback4(t)
	mp := startMapperStableRSS(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, extra...)...)
	base := nonPipeFDs(t, mp.pid())

	var rss []int
	for round := range rounds {
		t0 := time.Now()
		tmUpLocal.Clear() // 标记行每轮相同：上一轮的地址对应的 socket 已关闭（可能还在 TIME_WAIT），不能被这一轮读到
		type conn struct {
			c    *net.TCPConn
			key  string
			down bool
		}
		conns := make([]conn, 0, m)
		reader := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket} // down 方向客户端是读端
		for i := range nDown {
			nc, err := reader.Dial("tcp", listen)
			if err != nil {
				t.Fatalf("连接 %s 失败：%v", listen, err)
			}
			c := nc.(*net.TCPConn)
			t.Cleanup(func() { c.Close() })
			key := fmt.Sprintf("down-%d", i)
			conns = append(conns, conn{c, key, true})
			go func() {
				fmt.Fprintf(c, "%s\n", key)
				<-goCh
				results <- slowVerify(c, S, streamSeed(uint64(i), true))
			}()
		}
		for i := range nUp {
			c := dial(t, listen)
			key := fmt.Sprintf("up-%d", i)
			conns = append(conns, conn{c, key, false})
			go func() {
				fmt.Fprintf(c, "%s\n", key)
				writeStream(c, S, 32<<10, streamSeed(uint64(i), false))
			}()
		}
		// 放行前：每条连接都在持有一块缓冲
		eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
			mp.fatalIfExited(t, "第 %d 轮建立背压时", round+1)
			held, why := 0, error(nil)
			for _, cc := range conns {
				v, ok := tmUpLocal.Load(cc.key)
				if !ok {
					return fmt.Errorf("后端还没收到 %s", cc.key)
				}
				cli := [2]string{listen, cc.c.LocalAddr().String()} // tinymapper 客户端侧 socket：本端、对端
				up := [2]string{v.(string), be.addr}                // tinymapper 上游 socket
				src, dst := up, cli
				if !cc.down {
					src, dst = cli, up
				}
				if err := tmHolds(mp.pid(), src[0], src[1], dst[0], dst[1]); err == nil {
					held++
				} else if why == nil {
					why = fmt.Errorf("%s：%w", cc.key, err)
				}
			}
			if held != m {
				return fmt.Errorf("第 %d 轮只有 %d/%d 个方向在持有缓冲（如 %v）", round+1, held, m, why)
			}
			return nil
		})
		t1 := time.Now()
		for range m {
			goCh <- struct{}{}
		}
		for j := range m {
			select {
			case err := <-results:
				if err != nil {
					t.Fatalf("第 %d 轮：%v", round+1, err)
				}
			case <-time.After(3 * ioTimeout):
				t.Fatalf("第 %d 轮：%d/%d 条流在超时内没有完成校验", round+1, j, m)
			}
		}
		t2 := time.Now()
		for _, cc := range conns {
			cc.c.Close()
		}
		eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
			if got := nonPipeFDs(t, mp.pid()); got != base {
				return fmt.Errorf("第 %d 轮结束后 tinymapper 有 %d 个非 pipe fd，建连前为 %d：连接对未全部释放", round+1, got, base)
			}
			return nil
		})
		t.Logf("第 %d 轮：建连并确认 %d 个方向都持有缓冲 %v，慢读排空并校验 %v，释放 %v", round+1, m,
			t1.Sub(t0).Round(time.Millisecond), t2.Sub(t1).Round(time.Millisecond), time.Since(t2).Round(time.Millisecond))
		time.Sleep(300 * time.Millisecond)
		rss = append(rss, vmRSS(t, mp.pid()))
	}

	// 非 pipe fd 回到基线之外，留着的 pipe（scratch 与池里空闲的）必须恰为统计的 2×pipes alloc（--disable-splice 时为 0）
	mp.expectPipeFDs(t, mp.statsAfterSignal(t), "最后一轮释放之后")
	growth := rss[rounds-1] - rss[1]
	t.Logf("各轮结束时 VmRSS（KB）：%v；第 2 轮至最后一轮增长 %d KB", rss, growth)
	const leakThreshold = 12 << 10 // KB；排空不还池时每轮泄漏数十 MiB（96 条流各排空约 S/64KiB 块）
	if growth >= leakThreshold {
		t.Fatalf("第 2 轮至最后一轮 VmRSS 增长 %d KB（≥ %d KB）：排空的缓冲没有归还缓冲池", growth, leakThreshold)
	}
}

// fillUntilStalled 向 c 不停地写，直到某次写 stall 内没有写完为止：对端整条链路已满。tinymapper 持有上游侧缓冲时停读上游，
// 它的接收窗口随即关上，后端的写就停住；不持有时它一直在读（水平触发），写不会停住这么久
func fillUntilStalled(c net.Conn, stall time.Duration) error {
	defer c.SetWriteDeadline(time.Time{})
	buf := make([]byte, 64<<10)
	for {
		c.SetWriteDeadline(time.Now().Add(stall))
		if _, err := c.Write(buf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return err
		}
	}
}

// T11：释放路径不漏缓冲。每轮建 m 条连接，客户端一直不读，后端写到停住（tinymapper 已持有上游侧缓冲 remote.buf 并停读上游），
// 再由客户端发 RST：tinymapper 读到 ECONNRESET，erase_closed 释放连接对，释放前要把持有的块还给缓冲池；漏掉则每轮泄漏 m 块。
// 比较各轮结束时的 VmRSS（只比增长：glibc/musl 都保留 free 的内存）：正常实现下一轮从池里取回这些块（m ≤ 64，全部留在空闲链表），
// RSS 持平；漏还则每轮多 m 块（实测每轮 +200 KB～+2 MB，视块被碰到的页数）。
//   - default：tinymapper 不带 --sock-buf，两侧缓冲交给内核自动调优（默认部署路径）。客户端侧发送缓冲建连时在 loopback 上就有
//     约 2.6 MB，要先灌满它才会持有，固定的写入量不可靠，所以由后端写到停住来确认持有；连接数少一些，限住每轮几十 MB 的内核内存；
//   - sock-buf：--sock-buf 32 把两侧缓冲锁在约 64 KiB，几百 KiB 就持有，连接数多一些。
//
// 两项都带 --disable-splice：splice 开着时持有的是 pipe，释放时直接 close，见 TestSpliceReset。
// 只做上游→客户端方向（remote.buf）；变异把 local.buf、remote.buf 两行一并删除，捕到 remote.buf 泄漏即可判定。排空路径（write
// 分支归还）由 TestTCPBufferPoolStorm 覆盖。UDP 会话对象（udp_pair_t，D18）的池化复用由 TestDomainRefresh（释放旧会话后新会话
// 后进先出地复用同一对象与 fd 号）与 TestUDPEpollAddFail（反复取出、归还）覆盖；“UDP erase 不归还对象”这种纯泄漏每个会话只有
// 约 130 B，且只有 180 s 空闲超时、域名刷新与 EV_ERROR 三条释放路径，快速套件测不出，是已知缺口
func TestTCPBufferReleaseNoLeak(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		m     int
		extra []string
	}{
		{"default", 8, []string{"--disable-splice"}},
		{"sock-buf", 40, []string{"--sock-buf", "32", "--disable-splice"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			releaseNoLeak(t, c.m, c.extra...)
		})
	}
}

func releaseNoLeak(t *testing.T, m int, extra ...string) {
	const rounds = 6
	stalled := make(chan struct{}, m)
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		c.(*net.TCPConn).SetWriteBuffer(64 << 10) // 后端自己的发送缓冲（测试一侧，不是 tinymapper 的配置）：少占内核内存
		if fillUntilStalled(c, 500*time.Millisecond) == nil {
			stalled <- struct{}{}
		}
		io.Copy(io.Discard, c)
	})
	listen := loopback4(t)
	mp := startMapperStableRSS(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, extra...)...)
	base := fdCount(t, mp.pid())

	var rss []int
	for round := range rounds {
		conns := make([]*net.TCPConn, m)
		for i := range conns {
			conns[i] = dial(t, listen)
		}
		for i := range m {
			select {
			case <-stalled:
			case <-time.After(3 * ioTimeout):
				t.Fatalf("第 %d 轮：只有 %d/%d 条连接的后端写到停住：tinymapper 没有持有缓冲、停读上游", round+1, i, m)
			}
		}
		mp.fatalIfExited(t, "第 %d 轮持有缓冲时", round+1)
		for _, c := range conns {
			c.SetLinger(0) // close 时发 RST
			c.Close()
		}
		eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
			if got := fdCount(t, mp.pid()); got != base {
				return fmt.Errorf("第 %d 轮 RST 后 tinymapper 有 %d 个 fd，建连前为 %d：连接对未全部释放", round+1, got, base)
			}
			return nil
		})
		time.Sleep(300 * time.Millisecond)
		rss = append(rss, vmRSS(t, mp.pid()))
	}

	// 漏还时每一轮都多出 m 块，所以看第 2 轮之后每轮增长的最小值：正常实现各轮基本持平，只有偶发的一次性台阶（ASan 运行库内部分配，
	// 实测一次 +1.4 MB 后再不增长）和池里块的页面被陆续碰到（--sock-buf 下一次 recv 只填块的一部分，块按后进先出轮换，每轮几十 KB），
	// 总有一轮几乎不涨。门槛取 m×8 KiB：变异 t11noreturnbuf 每轮最少 +200 KB（default，m=8，门槛 64 KB）、+680 KB（sock-buf，
	// m=40，门槛 320 KB）
	minGrowth := rss[2] - rss[1]
	for r := 2; r < rounds; r++ {
		minGrowth = min(minGrowth, rss[r]-rss[r-1])
	}
	leakThreshold := m * 8
	t.Logf("各轮结束时 VmRSS（KB）：%v；第 2 轮之后每轮增长最少 %d KB（门槛 %d KB）", rss, minGrowth, leakThreshold)
	if minGrowth >= leakThreshold {
		t.Fatalf("第 2 轮之后每轮 VmRSS 都至少增长 %d KB（门槛 %d KB）：erase_closed 释放连接对时没有归还持有的缓冲", minGrowth, leakThreshold)
	}
}
