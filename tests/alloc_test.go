// T11 审查 F2 的功能测试：三条分配失败路径（TCP 连接对象 slab、UDP 连接对象 slab、TCP 64 KiB 缓冲块）malloc 失败后
// 只拒这一个客户端/会话/连接，不再 log_fatal + myexit(1) 退出进程（main.cpp v2）。
//
// 故障注入用 RLIMIT_DATA（用户决策）：启动时给 tinymapper 设 GLIBC_TUNABLES=glibc.malloc.top_pad=0（见下），预热到恰好的 slab
// 边界后把 RLIMIT_DATA 软限降到当前 VmData（只降软限、保留硬限，便于无 CAP_SYS_RESOURCE 还原），再触发目标 malloc 失败，随后还原。
//
// 确定性与规避范围外中止的要点（经 f2-review 的 prlimit 探针与 build/f2-tests/explore.bin 实测确认）：
//   - GLIBC_TUNABLES=glibc.malloc.top_pad=0：glibc 默认 brk 会多留 M_TOP_PAD(128 KiB) 余量，使降限后下一次 slab/块分配仍能从余量里
//     成功，失败点不确定；置 0 后 brk 不留余量，降到 VmData 即可让下一次分配确定失败。musl 的 mallocng 无需此项、本就在边界确定失败
//     （GLIBC_TUNABLES 对 musl 无副作用）。
//   - 预热到恰好的 slab 边界（objPoolSlabObjs 的整数倍、顺序建立使数量确定）：预热建满的对象占满整数个 slab，空闲数为 0，紧接着的
//     第 N+1 个连接/会话在 obj_pool_t::get() 里必须新开一个 slab（大块 malloc），降限下必失败。若没对齐到边界、留有空闲对象，
//     UDP 会话复用空闲对象且会话表又无需扩容时（U2 之后一个新 UDP 会话不再分配任何小块：adress_to_info 节点已去掉），
//     根本没有可失败的分配。因此 UDP 预热点选在既踩满对象 slab、又正好触发会话表扩容的位置（见 udpSlabWarm）。
//   - get() 的 slab malloc 发生在 ev_io_start 之前：失败即返回，不会触碰 libev 的 anfds 数组（fd 号超长度时翻倍再分配，失败会
//     「(libev) cannot allocate」abort）。预热阶段（未降限）建连已把 anfds 撑到高于后续会用到的 fd 号，被拒的探测连接又不 ev_io_start，
//     所以降限期间 anfds 不增长。
//   - 只降软限：Docker 无 CAP_SYS_RESOURCE，降了硬限就无法再抬回，故用 prlimit 只改 Cur、保留 Max。
//
// 探索/调参工具与原始数据在 build/f2-tests/（gitignored）。
package tests

import (
	"fmt"
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
	"unsafe"
)

// ---- RLIMIT_DATA 故障注入公共设施（本文件私有，名字与 harness_test.go 不冲突）----

const rlimitData = 2 // RLIMIT_DATA

// prlimitData 对进程 pid 的 RLIMIT_DATA 做 prlimit64：newv 非空则设置，oldv 非空则取回旧值
func prlimitData(pid int, newv, oldv *syscall.Rlimit) error {
	var np, op uintptr
	if newv != nil {
		np = uintptr(unsafe.Pointer(newv))
	}
	if oldv != nil {
		op = uintptr(unsafe.Pointer(oldv))
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRLIMIT64, uintptr(pid), rlimitData, np, op, 0, 0); e != 0 {
		return e
	}
	return nil
}

// procVmDataKB 读 /proc/<pid>/status 的 VmData（数据段大小，KB）
func procVmDataKB(t testing.TB, pid int) int {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "VmData:"); ok {
			kb, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), " kB")))
			if err != nil {
				t.Fatalf("/proc/%d/status 的 VmData 无法解析：%q", pid, line)
			}
			return kb
		}
	}
	t.Fatalf("/proc/%d/status 中没有 VmData", pid)
	return 0
}

// lowerDataLimit 把 pid 的 RLIMIT_DATA 软限降到（当前 VmData + deltaKB）KB，保留硬限；返回一次性还原函数（defer 调用保证
// 即便断言失败也会还原，否则进程继续在降限下运行会连带影响别的分配）
func lowerDataLimit(t testing.TB, pid, deltaKB int) func() {
	t.Helper()
	var old syscall.Rlimit
	if err := prlimitData(pid, nil, &old); err != nil {
		t.Fatalf("读取 RLIMIT_DATA 失败：%v", err)
	}
	cur := uint64(procVmDataKB(t, pid)+deltaKB) * 1024
	if err := prlimitData(pid, &syscall.Rlimit{Cur: cur, Max: old.Max}, nil); err != nil {
		t.Fatalf("降低 RLIMIT_DATA 失败：%v", err)
	}
	var once sync.Once
	return func() { once.Do(func() { prlimitData(pid, &old, nil) }) }
}

// startMapperTopPad0 同 startMapper，但给 tinymapper 设 GLIBC_TUNABLES=glibc.malloc.top_pad=0，让 glibc 的 brk 不留余量，
// 使降限后的首次 slab/块分配确定失败（musl 忽略该环境变量）
func startMapperTopPad0(t testing.TB, wait []listenPoint, args ...string) *mapper {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(mapperBin, append([]string{"--disable-color"}, args...)...)
	cmd.Env = append(os.Environ(), "GLIBC_TUNABLES=glibc.malloc.top_pad=0")
	cmd.Stdout, cmd.Stderr = f, f
	return runMapper(t, cmd, logPath, wait)
}

// assertAlive 断言进程仍存活，且日志里没有范围外中止（libev「cannot allocate」abort 或 std::bad_alloc/terminate）
func assertAlive(t testing.TB, m *mapper) {
	t.Helper()
	m.fatalIfExited(t, "分配失败后进程不应退出：")
	if m.logLines("cannot allocate") > 0 {
		t.Fatalf("出现 libev「cannot allocate」abort（范围外 anfds 增长失败）：\n%s", m.logTail(20))
	}
	if m.logLines("bad_alloc")+m.logLines("terminate called") > 0 {
		t.Fatalf("出现 std::bad_alloc/terminate（范围外分配失败）：\n%s", m.logTail(20))
	}
}

// 三条路径在 v2 构建里的日志关键子串；修复前（HEAD 899770c）打印的是带 myexit 的 [FATAL] 行，据此可区分 F2 与控制组
const (
	tcpObjWarn = "[tcp]new connection from"              // 与 objFailTag 同在一行（warn）
	udpObjWarn = "[udp]new connection from"              // 与 objFailTag 同在一行（v2 为 info）
	objFailTag = "but malloc for connection objects failed"
	tcpBufWarn = "closed bc of malloc for a"             // tcp_cb：... closed bc of malloc for a 65536-byte buffer failed（warn）
)

const objSlabWarm = 7 * objPoolSlabObjs // TCP 预热到 7 个 slab 整数倍（448），第 448+1 条触发新 slab 分配失败（f2-review 验证）
// UDP 预热到 3 个 slab 整数倍（192）：此时对象池 3 个 slab 恰好占满、空闲为 0，且第 193 个会话正好触发 U2 会话表从 256 扩容到 512 槽
// （LP64 下 512×16B=8 KiB 的 calloc，发生在 udp_accept_cb 里选上游/建 socket 之前的 reserve_one）。所以第 193 个会话既要扩容表、
// 又要新开第 4 个对象 slab。reserve_one 先分配，但降限后它的 8 KiB 不一定失败（可能由之前释放的块满足），这时失败的是随后的
// slab malloc；两条路径打印同一行 info，无论哪个先失败，这个会话都被拒、进程存活（本用例不区分是哪一个）。
// 第 193 个会话在四个变体上都确定被拒（各 5/5）。
const udpSlabWarm = 3 * objPoolSlabObjs

// TestAllocTCPObjPool：TCP 连接对象 slab 的 malloc 失败——tcp_accept_one 里 tcp_pair_pool.get() 返回 0 时（v2：在
// select_remote_index/socket/connect 之前），打印 warn 行、只 close 客户端 fd、返回 1 继续 accept 循环，不退出进程、上游看不到这次连接。
func TestAllocTCPObjPool(t *testing.T) {
	t.Parallel()
	heavy(t)
	be := serveTCP(t, loopback4(t), echoHandler(""))
	listen := loopback4(t)
	m := startMapperTopPad0(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")
	baseFd := fdCount(t, m.pid())

	// 预热：顺序建满 objSlabWarm 条回显连接（可靠地建满整数个 slab；并发建连会冲垮 accept backlog、只建成很少几条），分配 scratch、
	// 把 anfds 撑到高于后续会用到的 fd 号；再对全部连接同时收发一轮制造事件突发，撑大 libev 的 pendings / epoll_events 数组；
	// 然后全部关闭：对象回到池里（空闲数=slabs*64）、fd 释放，但 libev 数组不缩小。
	warm := make([]net.Conn, objSlabWarm)
	for i := range warm {
		warm[i] = dial(t, listen)
		mustEcho(t, warm[i], "w")
	}
	parallelFor(objSlabWarm, objSlabWarm, func(i int) { echo(warm[i], []byte("b")) }) // 事件突发，忽略个别错误
	m.fatalIfExited(t, "预热 TCP 连接时")
	closeAll(warm)
	eventually(t, 2*ioTimeout, 50*time.Millisecond, func() error {
		if got := fdCount(t, m.pid()); got > baseFd {
			return fmt.Errorf("预热连接关闭后 fd=%d 未回到基线 %d", got, baseFd)
		}
		return nil
	})
	beforeReject := be.accepted.Load()

	restore := lowerDataLimit(t, m.pid(), 0)
	defer restore()

	// 重新建连：前 slabs*64 条复用池里的空闲对象（不新分配堆、fd 爬回预热峰值但仍在已撑大的 anfds 内），紧接着的那条需要新开
	// slab→malloc 失败→拒绝。回显失败即说明该条被拒（tcp_accept_one 只 close 客户端 fd）。
	var held []net.Conn
	t.Cleanup(func() { closeAll(held) })
	rejected := false
	for i := 0; i < objSlabWarm+200; i++ {
		c, err := net.DialTimeout("tcp", listen, ioTimeout)
		if err != nil {
			t.Fatalf("重新建连第 %d 条 connect 失败：%v", i+1, err)
		}
		if echo(c, []byte("w")) != nil {
			c.Close() // 被拒：客户端被关闭（RST/EOF）
			rejected = true
			break
		}
		held = append(held, c)
		if i%64 == 0 {
			assertAlive(t, m)
		}
	}
	if !rejected {
		t.Fatalf("重新建连 %d 条都没被拒：对象 slab 没有分配失败\n%s", objSlabWarm+200, m.logTail(20))
	}
	// 等拒绝日志刷出：log_warn 在 stdout 非 tty 时被缓冲，每 timer_interval(400ms) 由 clear_timer_cb flush
	eventually(t, logFlushWithin+ioTimeout, 50*time.Millisecond, func() error {
		assertAlive(t, m)
		if m.logLines(tcpObjWarn, objFailTag) == 0 {
			return fmt.Errorf("还没看到 TCP 对象 slab 的拒绝日志")
		}
		return nil
	})

	// v2：被拒连接在 get() 失败后不再 select_remote_index/connect，后端不应为它多出一次 accept
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if got := be.accepted.Load(); got != beforeReject+int64(len(held)) {
			return fmt.Errorf("后端 accept 增量=%d，期望=%d（被拒连接不应建上游）", got-beforeReject, len(held))
		}
		return nil
	})

	// 既有流在耗尽期间仍能回显（数据路径复用全局 scratch，不分配对象/缓冲）
	mustEcho(t, held[0], "stillpre")

	// 被拒连接不漏 fd：当前 fd 数记作基准，再多拒几条，fd 不应增长
	fdHeld := fdCount(t, m.pid())
	for i := 0; i < 8; i++ {
		c, e := net.DialTimeout("tcp", listen, ioTimeout)
		if e == nil {
			echo(c, []byte("w")) // 预期失败
			c.Close()
		}
	}
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if got := fdCount(t, m.pid()); got > fdHeld {
			return fmt.Errorf("再拒若干连接后 fd=%d > %d：tcp_accept_one 没有 close 客户端 fd", got, fdHeld)
		}
		return nil
	})

	// 还原后新连接可用
	restore()
	nc := dial(t, listen)
	mustEcho(t, nc, "after")
	nc.Close()

	checkPoolInvariants(t, m.statsAfterSignal(t))
}

// TestAllocUDPObjPool：UDP 新会话的 malloc 失败路径。udp_accept_cb 里有两处：U2 会话表扩容 reserve_one() 的 calloc（返回 -1，
// 在选上游、建 socket 之前，没有要关的 fd），以及之后 udp_pair_pool.get() 的 slab malloc（返回 0，close 刚建的会话 fd）。两处都打印
// 同一行 info、丢弃该包，不退出进程。预热到 192（见 udpSlabWarm）让第 193 个会话同时需要扩容表（256→512 槽）与新开对象 slab，
// 降限后哪个分配先失败，会话就由哪条路径拒绝；用例只检查日志行、无回包、无 fd 泄漏与恢复，不区分两条路径。
// 预热对齐边界很关键，否则复用空闲对象且无需扩容的会话不分配任何东西（U2 去掉了每会话的 map 节点），没有可失败的分配。
func TestAllocUDPObjPool(t *testing.T) {
	t.Parallel()
	heavy(t)
	be := serveUDP(t, loopback4(t), "")
	listen := loopback4(t)
	m := startMapperTopPad0(t, listenPoints("u", portOf(listen)), "-l", listen, "-r", be.addr, "-u")

	// 预热：顺序建满 udpSlabWarm 个 UDP 会话（撑大 anfds、占满整数个 slab→空闲数 0）；保持这些会话
	ra, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		t.Fatal(err)
	}
	warm := make([]*net.UDPConn, udpSlabWarm)
	t.Cleanup(func() {
		for _, c := range warm {
			if c != nil {
				c.Close()
			}
		}
	})
	for i := range warm {
		c, err := net.DialUDP("udp", nil, ra)
		if err != nil {
			t.Fatalf("预热建 UDP 会话失败：%v", err)
		}
		if _, err := c.Write([]byte{1}); err != nil {
			t.Fatalf("预热 UDP 写失败：%v", err)
		}
		// 读回显确认该会话已建、tinymapper 处理完再建下一个（保证顺序、数量确定）；回包偶发丢失时会话其实已建，短超时即可，不拖慢
		c.SetReadDeadline(time.Now().Add(time.Second))
		c.Read(make([]byte, 16))
		warm[i] = c
	}
	m.fatalIfExited(t, "预热 UDP 会话时")

	restore := lowerDataLimit(t, m.pid(), 0)
	defer restore()

	// 探测：新源端口的会话，udp_pair_pool.get() 需新开 slab→malloc 失败→丢包、无回包
	fdBefore := fdCount(t, m.pid())
	rej := udpDial(t, "", listen)
	rej.SetDeadline(time.Now().Add(ioTimeout))
	if _, err := rej.Write([]byte("nope")); err != nil {
		t.Fatalf("探测 UDP 写失败：%v", err)
	}
	if nn, _ := rej.Read(make([]byte, 16)); nn > 0 {
		t.Fatalf("池耗尽时新发送方不应收到回包，却收到 %d 字节", nn)
	}
	rej.Close()
	// 等拒绝日志刷出（info 行同样被缓冲，每 timer_interval(400ms) flush）
	eventually(t, logFlushWithin+ioTimeout, 50*time.Millisecond, func() error {
		assertAlive(t, m)
		if m.logLines(udpObjWarn, objFailTag) == 0 {
			return fmt.Errorf("还没看到 UDP 对象 slab 的拒绝日志")
		}
		return nil
	})

	// 既有会话在耗尽期间仍能转发（数据路径 udp_cb 不分配）
	warm[0].SetDeadline(time.Now().Add(ioTimeout))
	if _, err := warm[0].Write([]byte("live")); err != nil {
		t.Fatalf("既有 UDP 会话写失败：%v", err)
	}
	pb := make([]byte, 16)
	if n, err := warm[0].Read(pb); err != nil || string(pb[:n]) != "live" {
		t.Fatalf("既有 UDP 会话耗尽期间转发异常：got=%q err=%v", pb[:n], err)
	}

	// 被拒会话不漏 fd：再驱动若干被拒会话，fd 数不应增长（udp_accept_cb 对分配失败只 close 新会话 fd）
	for i := 0; i < 16; i++ {
		c := udpDial(t, "", listen)
		c.SetWriteDeadline(time.Now().Add(ioTimeout))
		c.Write([]byte{9})
		c.Close()
	}
	eventually(t, ioTimeout, 50*time.Millisecond, func() error {
		if got := fdCount(t, m.pid()); got > fdBefore {
			return fmt.Errorf("被拒会话后 fd=%d > 之前 %d", got, fdBefore)
		}
		return nil
	})

	// 还原后新会话可用
	restore()
	nc := udpDial(t, "", listen)
	got, err := udpRoundTrip(nc, []byte("after"))
	if err != nil || string(got) != "after" {
		t.Fatalf("还原后新 UDP 会话回显异常：got=%q err=%v", got, err)
	}
	nc.Close()

	checkPoolInvariants(t, m.statsAfterSignal(t))
}

// smallRcvbufDialer 返回一个 TCP 拨号器，连接的接收缓冲设得很小：配合“只连不读”，让 tinymapper 发往该连接时很快发不出去、
// 交出 scratch 并持有该缓冲块，从而逼出下一次 recv 的缓冲块 malloc
func smallRcvbufDialer() net.Dialer {
	return net.Dialer{Timeout: ioTimeout, Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2<<10)
		}); err != nil {
			return err
		}
		return serr
	}}
}

// readFull 读满 buf（net.Conn 的 Read 可能分多次返回）
func readFull(c net.Conn, buf []byte) error {
	got := 0
	for got < len(buf) {
		c.SetReadDeadline(time.Now().Add(ioTimeout))
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			return err
		}
	}
	return nil
}

// TestAllocTCPBuffer：TCP 64 KiB 缓冲块的 malloc 失败——tcp_cb 读分支里 tcp_scratch==0 且 tcp_buf_pool.get() 返回 0 时，
// 打印 warn 行并 erase_closed 这一个连接对，不退出进程。两条规则：规则 1 回显（既有完整性流），规则 2 洪泛（制造下行背压、
// 逼出缓冲块 malloc）。缓冲池是进程级共享的。
func TestAllocTCPBuffer(t *testing.T) {
	t.Parallel()
	heavy(t)
	echoBE := serveTCP(t, loopback4(t), echoHandler(""))
	// 洪泛后端：一连上就持续猛写，客户端只连不读→tinymapper 读满 scratch 发不完→交出缓冲块
	floodLn, err := net.Listen("tcp", loopback4(t))
	if err != nil {
		t.Fatalf("洪泛后端监听失败：%v", err)
	}
	t.Cleanup(func() { floodLn.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			c, err := floodLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					c.SetWriteDeadline(time.Now().Add(2 * time.Second))
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	l1, l2 := loopback4(t), loopback4(t)
	cfg := writeConfig(t, fmt.Sprintf(`[[endpoints]]
listen = %q
remote = %q

[[endpoints]]
listen = %q
remote = %q
`, l1, echoBE.addr, l2, floodLn.Addr().String()))
	wait := append(listenPoints("t", portOf(l1)), listenPoints("t", portOf(l2))...)
	// 只测块：splice 开着时洪泛方向发不完的数据多半在 pipe 里（B2），不一定走到块的 malloc，pipe fd 也会让下面的 fd 基线对不上
	m := startMapperTopPad0(t, wait, "-c", cfg, "--disable-splice")
	baseFd := fdCount(t, m.pid())

	// 规则 1 上建一条既有回显流（顺便分配 scratch），保持空闲
	preA := dial(t, l1)
	mustEcho(t, preA, "x")

	restore := lowerDataLimit(t, m.pid(), 0)
	defer restore()

	// 规则 2 上逐条建“下行背压”连接（小 rcvbuf、只连不读），每条持有一块缓冲；直到某条 recv 的缓冲 malloc 失败
	var flood []net.Conn
	t.Cleanup(func() { closeAll(flood) })
	dialer := smallRcvbufDialer()
	deadline := time.Now().Add(20 * time.Second)
	for len(flood) < 200 {
		c, err := dialer.Dial("tcp", l2)
		if err != nil {
			t.Fatalf("洪泛连接建立失败：%v", err)
		}
		flood = append(flood, c)
		time.Sleep(30 * time.Millisecond)
		assertAlive(t, m)
		if m.logLines(tcpBufWarn) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%v 内未出现缓冲块 malloc 失败日志（已建 %d 条背压连接）\n%s", 20*time.Second, len(flood), m.logTail(20))
		}
	}
	assertAlive(t, m)
	if m.logLines(tcpBufWarn) == 0 {
		t.Fatalf("没有出现 TCP 缓冲块 malloc 失败的拒绝日志（%q）\n%s", tcpBufWarn, m.logTail(20))
	}

	// 还原
	restore()

	// 既有回显流仍可用（还原后 recv 能取到缓冲块）
	mustEcho(t, preA, "afterpre")
	// 新回显流转发正确（较大往返，跨多个缓冲块）
	preA.Close()
	nb := dial(t, l1)
	payload := strings.Repeat("Z", 200<<10)
	nb.SetDeadline(time.Now().Add(ioTimeout))
	if _, err := nb.Write([]byte(payload)); err != nil {
		t.Fatalf("还原后新流写失败：%v", err)
	}
	got := make([]byte, len(payload))
	if err := readFull(nb, got); err != nil {
		t.Fatalf("还原后新流读回显失败：%v", err)
	}
	if string(got) != payload {
		t.Fatal("还原后新流回显内容不一致")
	}
	nb.Close()

	// 关闭全部背压连接后，缓冲块归还、连接对释放，fd 回到基线（无泄漏）
	closeAll(flood)
	flood = nil
	eventually(t, 2*ioTimeout, 50*time.Millisecond, func() error {
		if got := fdCount(t, m.pid()); got > baseFd {
			return fmt.Errorf("背压连接全部关闭后 fd=%d > 基线 %d", got, baseFd)
		}
		return nil
	})

	checkPoolInvariants(t, m.statsAfterSignal(t))
}
