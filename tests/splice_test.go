// B1 + B2（D46–D49）大流量方向检测与 splice 混合模式的功能测试。
//
// 规格（docs/tasks/p3.md）：每个方向（src→dst）的状态放在读的一侧。本方向上一次读（recv 或 splice 进 pipe）≥ splice_read_min（16 KiB）
// 时这次用 splice(src→pipe) 再 splice(pipe→dst)，否则 recv/send；逐次判断、不粘滞（D46）。splice 读进每个 loop 一个的 scratch pipe，
// 整段写出就留着给下一次；没写完才把 pipe 连同数据交给该方向、停读源端、在目的端挂 EV_WRITE，写分支排空后还回 pipe 池（空闲最多 64 个，
// 多出的 close）；释放连接对时持有的 pipe 里一定有数据，直接 close，不复用（D47）。取不到 pipe（pipe2 失败，或新 pipe 小于 64 KiB）时
// 这次走 recv、splice_fallback 加 1，到下一个 400 ms 定时器周期之前不再创建，失败原因进程内第一次记 info、之后记 debug。splice 进 pipe
// 返回 EAGAIN（队首是紧急数据）时这次改走 recv。上游建连中只 recv。--disable-splice（D48）：不创建 pipe，全走拷贝。
// 计数（D49）：tcp 行末尾 up_splice/down_splice/splice_fallback，pool 行末尾 pipes alloc/held/free/scratch。
// B3（D55–D58）的 pipe 大小、每回调预算与扩容失败见 TestSpliceRounds 与文件末尾一节。
//
// 观察手段：SIGUSR1 统计（statsAfterSignal 每次都复核 pipe 池不变式）、/proc/<pid>/fd 里的 pipe:[…] 链接（每个 pipe 两个 fd，
// tinymapper 静止时恰为 2×alloc）、sock_diag 看 tinymapper 两侧 socket 的队列与状态、端到端 SHA-256。
package tests

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

const (
	spliceReadMin   = 16 << 10 // main.cpp 的 splice_read_min（D46）
	pipePoolMaxFree = 64       // main.cpp 的 tcp_pipe_pool_max_free（D47）：pipe 不大于 16 页时的空闲上限，更大的见 pipePoolCap
	// 创建 pipe 失败（pipe2 出错，或新 pipe 小于 64 KiB）的日志行都含这一段：进程内第一次 info，之后 debug
	pipeFailLog  = "forwarding by copy instead of splice until the next timer tick"
	tcpCloseWait = 8 // TCP_CLOSE_WAIT：已收到对端的 FIN
)

// spliceModes：默认（splice 开）与 --disable-splice
var spliceModes = []struct {
	name string
	args []string
}{{"splice", nil}, {"nosplice", []string{"--disable-splice"}}}

// ---- fd 与统计的辅助 ----

// pipeFDList 返回进程 pid 打开的 pipe fd 号（/proc/<pid>/fd 的链接为 pipe:[inode]）
func pipeFDList(pid int) ([]int, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, e := range ents {
		if link, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil && strings.HasPrefix(link, "pipe:[") {
			fd, _ := strconv.Atoi(e.Name())
			fds = append(fds, fd)
		}
	}
	return fds, nil
}

func pipeFDs(t testing.TB, pid int) int {
	t.Helper()
	fds, err := pipeFDList(pid)
	if err != nil {
		t.Fatal(err)
	}
	return len(fds)
}

// nonPipeFDs 返回进程 pid 打开的 fd 里不是 pipe 的个数。连接对全部释放后它应回到建连前的基线；scratch pipe 与池里空闲的 pipe 合法地留着，
// 由 expectPipeFDs 对照统计核对
func nonPipeFDs(t testing.TB, pid int) int {
	t.Helper()
	return fdCount(t, pid) - pipeFDs(t, pid)
}

// expectPipeFDs 在 tinymapper 静止时核对 pipe fd 恰为统计里的 2×pipes alloc：漏 close 的 pipe、计错的 alloc 都对不上
func (m *mapper) expectPipeFDs(t testing.TB, d statsDump, state string) {
	t.Helper()
	if got := pipeFDs(t, m.pid()); got != 2*d.pool.pipeAlloc {
		t.Errorf("%s：tinymapper 打开 %d 个 pipe fd，统计为 pipes alloc=%d（应有 %d 个 fd）", state, got, d.pool.pipeAlloc, 2*d.pool.pipeAlloc)
	}
}

// expectPipeFlags 要求 tinymapper 的每个 pipe fd 都带 O_NONBLOCK|O_CLOEXEC（规格：pipe2(O_NONBLOCK|O_CLOEXEC)），返回检查的个数
func expectPipeFlags(t testing.TB, pid int) int {
	t.Helper()
	fds, err := pipeFDList(pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
		if err != nil {
			t.Fatal(err)
		}
		var flags uint64
		for _, line := range strings.Split(string(info), "\n") {
			if v, ok := strings.CutPrefix(line, "flags:"); ok {
				flags, _ = strconv.ParseUint(strings.TrimSpace(v), 8, 32)
			}
		}
		if flags&syscall.O_NONBLOCK == 0 || flags&syscall.O_CLOEXEC == 0 {
			t.Errorf("pipe fd %d 的 flags=0%o，缺少 O_NONBLOCK 或 O_CLOEXEC", fd, flags)
		}
	}
	return len(fds)
}

// tcpDelta 返回两次统计之间 tcp 行累计计数的增量（conns、halfClosed 取 cur 的当前值）
func tcpDelta(cur, prev tcpStat) tcpStat {
	return tcpStat{conns: cur.conns, halfClosed: cur.halfClosed, total: cur.total - prev.total,
		upBytes: cur.upBytes - prev.upBytes, downBytes: cur.downBytes - prev.downBytes,
		upSplice: cur.upSplice - prev.upSplice, downSplice: cur.downSplice - prev.downSplice,
		spliceFallback: cur.spliceFallback - prev.spliceFallback}
}

func pct(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) * 100 / float64(whole)
}

// waitTCPConns 等到规则 rule 的当前 TCP 连接数为 n，返回那一次的统计
func (m *mapper) waitTCPConns(t testing.TB, rule, n int) statsDump {
	t.Helper()
	var d statsDump
	eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
		d = m.statsAfterSignal(t)
		if c := d.tcp[rule].conns; c != n {
			return fmt.Errorf("规则 %d 当前 %d 条 TCP 连接，期望 %d", rule, c, n)
		}
		return nil
	})
	return d
}

// ---- 两端都由用例驱动的连接 ----

// spliceRig 是一个 tinymapper 加一个把每条连接交给用例的后端：用例同时握着客户端与后端两端，自己决定每个方向何时写、何时读
type spliceRig struct {
	m        *mapper
	listen   string // 规则 1 的监听地址（→ 后端）
	be       *tcpServer
	accepted chan net.Conn
}

// newSpliceRig 起后端并用 start(listen, remote) 启动 tinymapper，start 须让规则 1 从 listen 转发到 remote
func newSpliceRig(t testing.TB, start func(listen, remote string) *mapper) *spliceRig {
	t.Helper()
	return newSpliceRigConfig(t, net.ListenConfig{}, start)
}

// newSpliceRigConfig 同 newSpliceRig，后端的监听 socket 由 lc 创建（如设 TCP_MAXSEG，accept 得到的连接继承）
func newSpliceRigConfig(t testing.TB, lc net.ListenConfig, start func(listen, remote string) *mapper) *spliceRig {
	t.Helper()
	r := &spliceRig{accepted: make(chan net.Conn, 64)}
	done := make(chan struct{})
	r.be = serveTCPConfig(t, lc, loopback4(t), func(c net.Conn) {
		r.accepted <- c
		<-done
	})
	t.Cleanup(func() { close(done) }) // 在 serveTCP 之后注册，清理时先于它执行
	r.listen = loopback4(t)
	r.m = start(r.listen, r.be.addr)
	return r
}

// splicePair 是经 tinymapper 的一条连接：cli 为客户端，srv 为后端 accept 到的一端；tmCli、tmUp 为 tinymapper 客户端一侧、上游一侧
// socket 的本端与对端地址（sock_diag 用）
type splicePair struct {
	cli, srv    *net.TCPConn
	tmCli, tmUp [2]string
}

// pair 建一条经 tinymapper 的连接，返回两端（须顺序调用：后端按到达顺序交出连接）
func (r *spliceRig) pair(t testing.TB) *splicePair {
	t.Helper()
	cli := dial(t, r.listen)
	select {
	case c := <-r.accepted:
		srv := c.(*net.TCPConn)
		return &splicePair{cli: cli, srv: srv,
			tmCli: [2]string{r.listen, cli.LocalAddr().String()}, tmUp: [2]string{srv.RemoteAddr().String(), r.be.addr}}
	case <-time.After(ioTimeout):
		t.Fatalf("后端在 %v 内没有收到经 tinymapper 的连接", ioTimeout)
	}
	return nil
}

// upHeld、downHeld 用 sock_diag 判断 tinymapper 是否持有上行（客户端→上游）/下行方向的数据（见 tmHolds），返回 nil 表示持有
func (p *splicePair) upHeld(pid int) func() error {
	return func() error { return tmHolds(pid, p.tmCli[0], p.tmCli[1], p.tmUp[0], p.tmUp[1]) }
}

func (p *splicePair) downHeld(pid int) func() error {
	return func() error { return tmHolds(pid, p.tmUp[0], p.tmUp[1], p.tmCli[0], p.tmCli[1]) }
}

// 让方向稳定持有数据的用例（半关闭、RST、空闲超时）给 tinymapper 加 --sock-buf holdSockBuf：两侧 socket 缓冲锁在 2×200 KiB（低于
// rmem_max/wmem_max 的 2 倍，TCP 不用 FORCE 选项），不随自动调优变大。持有开始之后目的端还能腾出的空间只剩读端（测试一侧，不读）接收窗口的
// 余量，不超过它的 128 KiB 接收缓冲（tcp_rmem[1]，不读就不调优）
var holdSockBuf = []string{"--sock-buf", "200"}

// holdReserve：确认持有之后 tinymapper 源一侧接收队列里至少留这么多数据，大于目的端还能腾出的空间（见 holdSockBuf）：这个方向即便排空，
// 读源端也还有数据，随即再次持有，不会因无数据可读而结束持有；又远小于源一侧的接收窗口（锁定的 400 KiB 缓冲），写出的数据都能被确认，
// 随后的 FIN 也能排进接收队列
const holdReserve = 192 << 10

// fill 让 p 的一个方向（up 为客户端→上游）持有数据：以 32 KiB 一块写 gen 的数据（同时写进 h），每块之后先用 sock_diag 粗筛（tmHolds：
// 源一侧接收队列与目的一侧发送队列都非空；CPU 紧张时 tinymapper 只是读得慢也会成立），再用统计确认持有 pipe 或块的方向总数到了 want；
// 确认之后接着写，直到源一侧接收队列至少有 holdReserve 字节且写出的全部被确认。读端一直不读。写端的发送缓冲锁在 2×128 KiB：tinymapper
// 一时读得慢时写端最多领先这么多，持有之后这些数据连同 holdReserve 仍装得进源一侧的接收窗口（半关闭用例要等它们全部被确认再发 FIN）。
// 返回写出的字节数
func (r *spliceRig) fill(t testing.TB, p *splicePair, up bool, gen *rand.ChaCha8, h io.Writer, want int) int64 {
	t.Helper()
	src, tmSrc, held := p.srv, p.tmUp, p.downHeld(r.m.pid())
	if up {
		src, tmSrc, held = p.cli, p.tmCli, p.upHeld(r.m.pid())
	}
	if err := src.SetWriteBuffer(128 << 10); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32<<10)
	var n int64
	write := func() {
		t.Helper()
		gen.Read(buf)
		h.Write(buf)
		src.SetWriteDeadline(time.Now().Add(ioTimeout))
		defer src.SetWriteDeadline(time.Time{})
		if _, err := src.Write(buf); err != nil {
			t.Fatalf("写到 %d 字节时：%v", n, err)
		}
		n += int64(len(buf))
	}
	for {
		if n > 256<<20 {
			t.Fatalf("写了 %d 字节 tinymapper 仍未持有这个方向的数据：%v", n, held())
		}
		write()
		if held() == nil {
			if d := r.m.statsAfterSignal(t); d.pool.pipeHeld+d.pool.held >= want {
				break
			}
		}
	}
	for {
		q, err := sockDiag(syscall.IPPROTO_TCP, tmSrc[0], tmSrc[1])
		if err != nil {
			t.Fatal(err)
		}
		if q.rqueue >= holdReserve {
			break
		}
		write()
		waitAcked(t, src)
	}
	return n
}

// waitAcked 等到测试一侧连接 c 写出的数据全部被对端确认（sock_diag 的 idiag_wqueue 为 write_seq-snd_una）：数据都已进了 tinymapper
// 那一侧 socket 的接收队列，随后的 FIN 不会卡在没发出的数据后面
func waitAcked(t testing.TB, c *net.TCPConn) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		b, err := sockDiag(syscall.IPPROTO_TCP, c.LocalAddr().String(), c.RemoteAddr().String())
		if err != nil {
			return err
		}
		if b.wqueue != 0 {
			return fmt.Errorf("%s → %s 还有 %d 字节没被确认", c.LocalAddr(), c.RemoteAddr(), b.wqueue)
		}
		return nil
	})
}

// waitTMState 等到 tinymapper 的 socket（addr 为本端、对端）进入 TCP 状态 state
func waitTMState(t testing.TB, addr [2]string, state uint8, what string) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		b, err := sockDiag(syscall.IPPROTO_TCP, addr[0], addr[1])
		if err != nil {
			return err
		}
		if b.state != state {
			return fmt.Errorf("%s（%s → %s）状态 %d，期望 %d", what, addr[0], addr[1], b.state, state)
		}
		return nil
	})
}

// readThenEOF 从 c 读 n 字节、SHA-256 须为 want，随后必须读到 EOF：FIN 之前的数据全部送达，FIN 不早于也不晚于数据
func readThenEOF(c net.Conn, n int64, want []byte) error {
	c.SetReadDeadline(time.Now().Add(transferTimeout(n)))
	defer c.SetReadDeadline(time.Time{})
	h, err := readStream(c, n)
	if err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return errors.New("SHA-256 不一致")
	}
	extra, err := io.Copy(io.Discard, c)
	if err != nil {
		return fmt.Errorf("%d 字节之后期望 EOF：%w", n, err)
	}
	if extra != 0 {
		return fmt.Errorf("%d 字节之后期望 EOF，却又收到 %d 字节", n, extra)
	}
	return nil
}

// echoConcurrent 在另一个协程里写 msg，同时读回同样长度并比对：回显大于各级缓冲之和时不会因先写后读而互相等死
func echoConcurrent(c net.Conn, msg []byte) error {
	c.SetDeadline(time.Now().Add(transferTimeout(int64(len(msg)))))
	defer c.SetDeadline(time.Time{})
	werr := make(chan error, 1)
	go func() {
		_, err := c.Write(msg)
		werr <- err
	}()
	got := make([]byte, len(msg))
	if n, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("读回显（%d/%d 字节）：%w", n, len(msg), err)
	}
	if err := <-werr; err != nil {
		return fmt.Errorf("写入：%w", err)
	}
	if !bytes.Equal(got, msg) {
		return errors.New("回显内容不一致")
	}
	return nil
}

// ---- 用例 ----

// 双向完整性与计数。每种模式一个 tinymapper，依次跑几种传输，每次前后各取一次统计：
//   - 两个方向的字节精确（含 28 B 头与 64 B 校验尾），splice 字节是其中一部分（checkPoolInvariants），splice_fallback 为 0；
//   - splice：大块写入（≥ 256 KiB）的方向必须有 splice 字节；只有头或校验尾、或逐字节写的方向每次读都 < 16 KiB，splice 字节必须为 0
//     （计数记反方向、新连接对继承上一个对象的 splice_next 都会失败）；
//   - nosplice：splice 计数全 0、pipes alloc 为 0（statsAfterSignal 也查），传输期间每 2 ms 采样 /proc/<pid>/fd，从未出现 pipe。
//
// concurrent：32 条连接同时双向各数 MiB、写块大小各不相同，scratch pipe 在连接之间轮转、背压时交接，串话或残留数据都让 SHA-256 失败。
// 结束时 pipe fd 恰为 2×alloc，且都带 O_NONBLOCK|O_CLOEXEC
func TestSpliceIntegrity(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, mode := range spliceModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			off := len(mode.args) > 0
			be := serveTCP(t, loopback4(t), streamHandler)
			listen := loopback4(t)
			m := startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, mode.args...)...)

			var maxPipes atomic.Int64
			stop, sampled := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(sampled)
				for {
					if fds, err := pipeFDList(m.pid()); err == nil && int64(len(fds)) > maxPipes.Load() {
						maxPipes.Store(int64(len(fds)))
					}
					select {
					case <-stop:
						return
					case <-time.After(2 * time.Millisecond):
					}
				}
			}()
			stopSampling := sync.OnceFunc(func() { close(stop); <-sampled })
			t.Cleanup(stopSampling)

			// wantUp/wantDown：1 该方向必须有 splice 字节，0 必须没有，-1 不限
			cases := []struct {
				name             string
				up, down         int64
				chunk            int
				wantUp, wantDown int
			}{
				{"bidir", 64 << 20, 64 << 20, 256 << 10, 1, 1},
				{"bidir-4k", 16 << 20, 16 << 20, 4096, -1, -1},
				{"up", 32 << 20, 0, 1 << 20, 1, 0},
				{"down", 0, 32 << 20, 1 << 20, 0, 1},
				{"tiny", 100, 100, 1, 0, 0},
			}
			prev := m.statsAfterSignal(t).tcp[1]
			for i, c := range cases {
				if err := transfer(listen, c.up, c.down, c.chunk, uint64(i)); err != nil {
					t.Fatalf("%s：%v", c.name, err)
				}
				cur := m.statsAfterSignal(t).tcp[1]
				dl := tcpDelta(cur, prev)
				prev = cur
				t.Logf("%s：上行 %d B，splice %d（%.1f%%）；下行 %d B，splice %d（%.1f%%）；fallback %d", c.name,
					dl.upBytes, dl.upSplice, pct(dl.upSplice, dl.upBytes), dl.downBytes, dl.downSplice, pct(dl.downSplice, dl.downBytes), dl.spliceFallback)
				if want := uint64(c.up + streamHeaderLen); dl.upBytes != want {
					t.Errorf("%s：up_bytes 增加 %d，期望 %d", c.name, dl.upBytes, want)
				}
				if want := uint64(c.down + 64); dl.downBytes != want {
					t.Errorf("%s：down_bytes 增加 %d，期望 %d", c.name, dl.downBytes, want)
				}
				if dl.spliceFallback != 0 {
					t.Errorf("%s：splice_fallback 增加 %d：pipe 应当拿得到（同一 uid 的 pipe 总量到了 fs.pipe-user-pages-soft？）\n%s",
						c.name, dl.spliceFallback, m.logTail(5))
				}
				if off {
					continue
				}
				for _, d := range []struct {
					dir  string
					want int
					got  uint64
				}{{"上行", c.wantUp, dl.upSplice}, {"下行", c.wantDown, dl.downSplice}} {
					switch {
					case d.want == 1 && d.got == 0:
						t.Errorf("%s：%s以 %d B 一块大量写入，却没有一个字节经 splice 转发", c.name, d.dir, c.chunk)
					case d.want == 0 && d.got != 0:
						t.Errorf("%s：%s每次读都小于 %d B，却有 %d 字节经 splice 转发（D46；或计数记到了另一个方向）", c.name, d.dir, spliceReadMin, d.got)
					}
				}
			}

			t.Run("concurrent", func(t *testing.T) {
				const n = 32
				chunks := []int{1000, 4096, 16 << 10, 64 << 10, 1 << 20}
				conns := make([]net.Conn, n)
				errs := make([]error, n)
				t.Cleanup(func() { closeAll(conns) })
				parallelFor(n, n, func(i int) { conns[i], errs[i] = net.DialTimeout("tcp", listen, ioTimeout) })
				for i, err := range errs {
					if err != nil {
						t.Fatalf("第 %d 个连接：%v", i+1, err)
					}
				}
				var wantUp, wantDown uint64
				for i := range n {
					wantUp += uint64(2<<20 + i*7919 + streamHeaderLen)
					wantDown += uint64(6<<20 - i*7919 + 64)
				}
				parallelFor(n, n, func(i int) {
					errs[i] = transferOn(conns[i], int64(2<<20+i*7919), int64(6<<20-i*7919), chunks[i%len(chunks)], uint64(100+i))
				})
				for i, err := range errs {
					if err != nil {
						t.Errorf("连接 %d（写块 %d B）：%v", i, chunks[i%len(chunks)], err)
					}
				}
				cur := m.statsAfterSignal(t).tcp[1]
				dl := tcpDelta(cur, prev)
				prev = cur
				t.Logf("并发 %d 条：上行 %d B，splice %.1f%%；下行 %d B，splice %.1f%%", n, dl.upBytes, pct(dl.upSplice, dl.upBytes),
					dl.downBytes, pct(dl.downSplice, dl.downBytes))
				if dl.upBytes != wantUp || dl.downBytes != wantDown {
					t.Errorf("up_bytes 增加 %d、down_bytes 增加 %d，期望 %d/%d", dl.upBytes, dl.downBytes, wantUp, wantDown)
				}
				if !off && (dl.upSplice == 0 || dl.downSplice == 0) {
					t.Errorf("并发大流量：up_splice 增加 %d、down_splice 增加 %d，期望都大于 0", dl.upSplice, dl.downSplice)
				}
			})

			stopSampling()
			d := m.waitTCPConns(t, 1, 0)
			if d.pool.pipeHeld != 0 {
				t.Errorf("连接全部释放后仍有 %d 个方向持有 pipe", d.pool.pipeHeld)
			}
			m.expectPipeFDs(t, d, "连接全部释放后")
			t.Logf("传输期间最多 %d 个 pipe fd；结束时 pool %+v", maxPipes.Load(), d.pool)
			if off {
				if maxPipes.Load() != 0 {
					t.Errorf("--disable-splice 下传输期间出现过 %d 个 pipe fd", maxPipes.Load())
				}
				return
			}
			if maxPipes.Load() == 0 {
				t.Error("splice 模式下传输期间从未出现 pipe fd")
			}
			if n := expectPipeFlags(t, m.pid()); n == 0 {
				t.Error("结束时没有空闲或 scratch pipe 可查 flags")
			}
		})
	}
}

// 小报文（D46）：每次读 < 16 KiB 的方向永远走 recv，不 splice、不创建 pipe。
//   - 64B：16 条长连接各 300 次 64 B 往返；
//   - 16383B：每次往返恰好比门槛小 1 字节；
//   - 16384B：恰好等于门槛，第一次读之后每次都 splice（门槛是 ≥）：splice 字节非零，且不超过 (往返次数−1)×16384（每条连接的第一次读
//     必须走 recv：splice_next 初值为 0）。
//
// 往返时间的中位数必须远小于 200 ms：splice 写出若带 SPLICE_F_MORE（内核映射为 MSG_MORE，把最后不满一段的数据塞住），一来一回、没有在途数据
// 时尾段要等约 200 ms 的零窗口探测定时器才发出（实测 16384B 子项从 0.04 s 变成 20 s），规格要求不带
func TestSpliceSmallMessages(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, c := range []struct {
		name                string
		conns, rounds, size int
		splice              bool
	}{
		{"64B", 16, 300, 64, false},
		{"16383B", 1, 50, spliceReadMin - 1, false},
		{"16384B", 1, 50, spliceReadMin, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), echoHandler(""))
			listen := loopback4(t)
			m := forward(t, "t", listen, be.addr)
			errs := make([]error, c.conns)
			rtts := make([][]time.Duration, c.conns)
			var wg sync.WaitGroup
			for i := range c.conns {
				conn := dial(t, listen)
				wg.Add(1)
				go func() {
					defer wg.Done()
					rng := rand.New(rand.NewPCG(uint64(i), 7))
					msg := make([]byte, c.size)
					for r := range c.rounds {
						for k := range msg {
							msg[k] = byte(rng.Uint32())
						}
						start := time.Now()
						if err := echo(conn, msg); err != nil {
							errs[i] = fmt.Errorf("连接 %d 第 %d 次往返：%w", i, r+1, err)
							return
						}
						rtts[i] = append(rtts[i], time.Since(start))
					}
				}()
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			all := slices.Concat(rtts...)
			slices.Sort(all)
			if med := all[len(all)/2]; med > 100*time.Millisecond {
				t.Errorf("往返时间中位数 %v（最大 %v）：尾段在等定时器（splice 写出带了 SPLICE_F_MORE？）", med, all[len(all)-1])
			} else {
				t.Logf("往返时间中位数 %v，最大 %v", med, all[len(all)-1])
			}
			d := m.statsAfterSignal(t)
			s := d.tcp[1]
			t.Logf("%d 条 × %d 次 %d B 往返：%+v；pool %+v", c.conns, c.rounds, c.size, s, d.pool)
			if total := uint64(c.conns * c.rounds * c.size); s.upBytes != total || s.downBytes != total {
				t.Errorf("up_bytes=%d down_bytes=%d，期望各 %d", s.upBytes, s.downBytes, total)
			}
			if !c.splice {
				if s.upSplice != 0 || s.downSplice != 0 || s.spliceFallback != 0 || d.pool.pipeAlloc != 0 {
					t.Errorf("每次读 %d B（< %d B）不应 splice、不应创建 pipe（D46）：up_splice=%d down_splice=%d splice_fallback=%d pipes alloc=%d",
						c.size, spliceReadMin, s.upSplice, s.downSplice, s.spliceFallback, d.pool.pipeAlloc)
				}
				if n := pipeFDs(t, m.pid()); n != 0 {
					t.Errorf("小报文转发后 tinymapper 有 %d 个 pipe fd", n)
				}
				return
			}
			bound := uint64((c.rounds - 1) * c.size * c.conns)
			if s.upSplice == 0 || s.downSplice == 0 {
				t.Errorf("每次读恰为 %d B（= splice_read_min），之后应当 splice（门槛是 ≥）：up_splice=%d down_splice=%d",
					c.size, s.upSplice, s.downSplice)
			}
			if s.upSplice > bound || s.downSplice > bound {
				t.Errorf("up_splice=%d down_splice=%d 超过 %d：每条连接每个方向的第一次读必须走 recv", s.upSplice, s.downSplice, bound)
			}
		})
	}
}

// 同一条连接上大块与小报文交替（D46：逐次判断、不粘滞）。
//   - steps：回显后端，每轮 1 MiB 大块、64 B、64 B，每步都等回显完、取一次统计：两方向字节精确；第一次 64 B 前一次读可能 ≥ 16 KiB，
//     至多这 64 B 经 splice；第二次 64 B 前一次读只有 64 B，必须走 recv（splice 字节不增加）；大块步骤合计两方向都有 splice 字节；
//   - stream：不等回显，客户端交替写 64–512 KiB 与 1–200 B 的报文共 32 MiB，读端每读 1 MiB 停 20 ms，两个方向都反复持有 pipe、
//     排空、在大小报文之间切换；回显的 SHA-256 与写出的一致、顺序不乱，过程中每读 4 MiB 取一次统计（持有 pipe 时也复核不变式）
func TestSpliceModeFlip(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	t.Run("steps", func(t *testing.T) {
		t.Parallel()
		be := serveTCP(t, loopback4(t), echoHandler(""))
		listen := loopback4(t)
		m := forward(t, "t", listen, be.addr)
		c := dial(t, listen)
		rng := rand.NewChaCha8(streamSeed(3, false))
		prev := m.statsAfterSignal(t).tcp[1]
		step := func(name string, size int) tcpStat {
			t.Helper()
			msg := make([]byte, size)
			rng.Read(msg)
			if err := echoConcurrent(c, msg); err != nil {
				t.Fatalf("%s：%v", name, err)
			}
			cur := m.statsAfterSignal(t).tcp[1]
			dl := tcpDelta(cur, prev)
			prev = cur
			if dl.upBytes != uint64(size) || dl.downBytes != uint64(size) {
				t.Errorf("%s：up_bytes 增加 %d、down_bytes 增加 %d，期望各 %d", name, dl.upBytes, dl.downBytes, size)
			}
			return dl
		}
		var big [2]uint64
		for r := range 6 {
			dl := step(fmt.Sprintf("第 %d 轮 1 MiB", r+1), 1<<20)
			big[0], big[1] = big[0]+dl.upSplice, big[1]+dl.downSplice
			if dl = step(fmt.Sprintf("第 %d 轮第一次 64 B", r+1), 64); dl.upSplice > 64 || dl.downSplice > 64 {
				t.Errorf("第 %d 轮第一次 64 B：splice 字节增加 %d/%d，至多是这 64 B", r+1, dl.upSplice, dl.downSplice)
			}
			if dl = step(fmt.Sprintf("第 %d 轮第二次 64 B", r+1), 64); dl.upSplice != 0 || dl.downSplice != 0 {
				t.Errorf("第 %d 轮第二次 64 B：splice 字节增加 %d/%d，期望 0：上一次读只有 64 B，这次应当 recv（D46 不粘滞）",
					r+1, dl.upSplice, dl.downSplice)
			}
		}
		t.Logf("大块步骤合计 splice：上行 %d、下行 %d 字节（共 %d）", big[0], big[1], 6<<20)
		if big[0] == 0 || big[1] == 0 {
			t.Errorf("6 次 1 MiB 回显：上行 splice %d、下行 splice %d 字节，期望都大于 0", big[0], big[1])
		}
	})
	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		be := serveTCP(t, loopback4(t), echoHandler(""))
		listen := loopback4(t)
		m := forward(t, "t", listen, be.addr)
		c := dial(t, listen)
		c.SetDeadline(time.Now().Add(60 * time.Second))
		const total = 32 << 20
		wsum := make(chan []byte, 1)
		go func() {
			rng := rand.New(rand.NewPCG(5, 6))
			gen := rand.NewChaCha8(streamSeed(5, false))
			h := sha256.New()
			buf := make([]byte, 512<<10)
			var n int64
			for k := 0; n < total; k++ {
				size := 1 + rng.IntN(200)
				if k%2 == 0 {
					size = 64<<10 + rng.IntN(448<<10)
				}
				b := buf[:min(int64(size), total-n)]
				gen.Read(b)
				h.Write(b)
				if _, err := c.Write(b); err != nil {
					wsum <- nil
					return
				}
				n += int64(len(b))
				if k%7 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
			c.CloseWrite()
			wsum <- h.Sum(nil)
		}()
		h := sha256.New()
		buf := make([]byte, 32<<10)
		var got int64
		maxHeld := 0
		for {
			n, err := c.Read(buf)
			h.Write(buf[:n])
			if (got+int64(n))>>20 != got>>20 {
				time.Sleep(20 * time.Millisecond)
				if (got+int64(n))>>22 != got>>22 {
					maxHeld = max(maxHeld, m.statsAfterSignal(t).pool.pipeHeld)
				}
			}
			got += int64(n)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("回显读到 %d 字节：%v", got, err)
			}
		}
		sum := <-wsum
		if sum == nil {
			t.Fatal("写入失败")
		}
		if got != total || !bytes.Equal(h.Sum(nil), sum) {
			t.Fatalf("回显 %d 字节（期望 %d），SHA-256 一致：%v", got, total, bytes.Equal(h.Sum(nil), sum))
		}
		// 两侧都 EOF，连接对释放
		d := m.waitTCPConns(t, 1, 0)
		s := d.tcp[1]
		t.Logf("交替流：%+v；过程中采样到最多 %d 个方向持有 pipe", s, maxHeld)
		if s.upBytes != total || s.downBytes != total {
			t.Errorf("up_bytes=%d down_bytes=%d，期望各 %d", s.upBytes, s.downBytes, total)
		}
		if s.upSplice == 0 || s.downSplice == 0 {
			t.Errorf("交替流：up_splice=%d down_splice=%d，期望都大于 0", s.upSplice, s.downSplice)
		}
		m.expectPipeFDs(t, d, "交替流结束后")
	})
}

// 背压：100 个下行方向同时持有 pipe（超过空闲上限：默认 256 KiB 的 pipe 为 16 个，见 pipePoolCap），排空后归还、多出的 close。
// 读端用 slowReaderSocket（8 KiB 接收缓冲、MSS 1460，tinymapper 发往它的 socket 发送缓冲约 87 KB）：第一次读（recv，≤ 64 KiB）能整段
// 发出，大流量随后的读都是 splice，发不完时把 pipe 交给该方向。核对：
//   - 峰值：100 个方向都持有 pipe、没有持有块的；pipe fd 恰为 2×alloc；不空转（停读上游后 epoll 里不能还留着 READ）；
//   - 慢读排空并逐条校验 SHA-256，之后持有归零、空闲不超过上限、空闲加 scratch 不少于上限（归还过 100 个，池是满的）、alloc 比峰值少
//     （多出的已 close）、down_bytes 精确且有 splice；不空转；
//   - 关闭全部连接后非 pipe fd 回到基线，pipe fd 恰为 2×alloc
func TestSpliceBackpressure(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	heavy(t)
	const m, S = 100, 512 << 10
	be := serveTCP(t, loopback4(t), func(c net.Conn) {
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		var i int
		fmt.Sscan(strings.TrimSpace(line), &i)
		writeStream(c, S, 64<<10, streamSeed(uint64(i), true))
		io.Copy(io.Discard, r)
	})
	listen := loopback4(t)
	mp := forward(t, "t", listen, be.addr)
	base := fdCount(t, mp.pid())

	reader := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
	conns := make([]*net.TCPConn, m)
	for i := range conns {
		nc, err := reader.Dial("tcp", listen)
		if err != nil {
			t.Fatalf("连接 %s 失败：%v", listen, err)
		}
		c := nc.(*net.TCPConn)
		t.Cleanup(func() { c.Close() })
		conns[i] = c
		fmt.Fprintf(c, "%d\n", i) // 后端随即写 S 字节；客户端先不读
	}
	var peak statsDump
	eventually(t, 3*ioTimeout, 100*time.Millisecond, func() error {
		peak = mp.statsAfterSignal(t)
		if got := peak.pool.pipeHeld + peak.pool.held; got != m {
			return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望共 %d 个", peak.pool.pipeHeld, peak.pool.held, m)
		}
		return nil
	})
	t.Logf("峰值 pool %+v", peak.pool)
	if peak.pool.pipeHeld != m {
		t.Fatalf("只有 %d/%d 个方向持有 pipe（其余 %d 个持有块）：大流量方向发不完时应当持有 pipe", peak.pool.pipeHeld, m, peak.pool.held)
	}
	mp.expectPipeFDs(t, peak, "背压中")
	mp.expectIdleCPU(t, "背压中（方向持有 pipe、停读上游）")

	results := make(chan error, m)
	for i, c := range conns {
		go func() { results <- slowVerify(c, S, streamSeed(uint64(i), true)) }()
	}
	for range conns {
		if err := <-results; err != nil {
			t.Fatalf("排空校验失败：%v", err)
		}
	}
	var d statsDump
	eventually(t, 3*ioTimeout, 100*time.Millisecond, func() error {
		d = mp.statsAfterSignal(t)
		if d.pool.pipeHeld != 0 || d.pool.held != 0 {
			return fmt.Errorf("排空后仍有 %d 个方向持有 pipe、%d 个持有块", d.pool.pipeHeld, d.pool.held)
		}
		return nil
	})
	t.Logf("排空后 pool %+v；tcp %+v", d.pool, d.tcp[1])
	if c := pipePoolCap(defaultPipeSize); d.pool.pipeFree > c || d.pool.pipeFree+d.pool.pipeScratch < c || d.pool.pipeAlloc >= peak.pool.pipeAlloc {
		t.Errorf("排空后 pipes alloc=%d free=%d scratch=%d（峰值 alloc %d）：空闲应恰好留满 %d 个（加 scratch 不少于它），多出的 close",
			d.pool.pipeAlloc, d.pool.pipeFree, d.pool.pipeScratch, peak.pool.pipeAlloc, c)
	}
	if want := uint64(m) * S; d.tcp[1].downBytes != want {
		t.Errorf("down_bytes=%d，期望 %d（写分支排空的字节也要计数）", d.tcp[1].downBytes, want)
	}
	if d.tcp[1].downSplice == 0 {
		t.Error("down_splice=0：持有 pipe 的方向排空时写出的是 splice 字节")
	}
	mp.expectPipeFDs(t, d, "排空后")
	mp.expectIdleCPU(t, "排空后（去掉 WRITE、恢复读上游）")

	for _, c := range conns {
		c.Close()
	}
	d = mp.waitTCPConns(t, 1, 0)
	if got := nonPipeFDs(t, mp.pid()); got != base {
		t.Errorf("连接全部关闭后 tinymapper 有 %d 个非 pipe fd，建连前为 %d", got, base)
	}
	mp.expectPipeFDs(t, d, "连接全部关闭后")
}

// 半关闭（splice 模式，--sock-buf 200 见 holdSockBuf）。每个子用例都用 fill 让一个方向稳定持有 pipe（统计里恰好 1 个方向持有 pipe、0 个持有块），再在精确的状态下
// 送 FIN，最后核对：数据按 SHA-256 全部送达且 EOF 紧随其后、连接对释放、pipe 不泄漏、持有时不空转。
//   - client-fin：上行持有，客户端的数据全部被确认后发 FIN，等到 tinymapper 客户端一侧 socket 进入 CLOSE_WAIT（FIN 已在内核里，排在没读的
//     数据之后），half_closed 必须仍为 0（持有数据时不读，EOF 只能在排空后读到）；后端随后读到全部数据再读到 EOF；
//   - upstream-fin：同上，方向相反；
//   - client-fin-other：下行持有时客户端发 FIN（另一方向空闲，tinymapper 立即读到 EOF 并 shutdown 上游）：后端读到请求与 EOF，
//     half_closed=1，下行仍持有；后端再关写方向，客户端排空后读到全部数据与 EOF，两侧都 EOF，连接对释放；
//   - upstream-fin-other：同上，方向相反
func TestSpliceHalfClose(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for i, c := range []struct {
		name  string
		up    bool // 持有的是上行（客户端→上游）
		other bool // FIN 来自另一方向
	}{
		{"client-fin", true, false},
		{"upstream-fin", false, false},
		{"client-fin-other", false, true},
		{"upstream-fin-other", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rig := newSpliceRig(t, func(listen, remote string) *mapper {
				return startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", remote, "-t"}, holdSockBuf...)...)
			})
			m := rig.m
			p := rig.pair(t)
			// src 写、dst 读的是持有的方向；src 一侧另有一个 tinymapper socket（tmSrc），另一方向的发送端是 dst
			src, dst, tmSrc := p.cli, p.srv, p.tmCli
			if !c.up {
				src, dst, tmSrc = p.srv, p.cli, p.tmUp
			}
			gen, h := rand.NewChaCha8(streamSeed(uint64(i), c.up)), sha256.New()
			n := rig.fill(t, p, c.up, gen, h, 1)
			sum := h.Sum(nil)
			var d statsDump
			eventually(t, ioTimeout, 20*time.Millisecond, func() error {
				if d = m.statsAfterSignal(t); d.pool.pipeHeld != 1 || d.pool.held != 0 {
					return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望恰好 1 个方向持有 pipe（%+v）", d.pool.pipeHeld, d.pool.held, d.tcp[1])
				}
				return nil
			})
			t.Logf("写了 %d 字节后持有：pool %+v", n, d.pool)
			if !c.other {
				// FIN 跟在数据后面进入 tinymapper 源一侧 socket 的接收队列
				waitAcked(t, src)
				if err := src.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				waitTMState(t, tmSrc, tcpCloseWait, "tinymapper 源一侧 socket")
				d = m.statsAfterSignal(t)
				if s := d.tcp[1]; s.halfClosed != 0 || s.conns != 1 || d.pool.pipeHeld != 1 {
					t.Fatalf("FIN 排在持有的数据之后：half_closed=%d conns=%d 持有 pipe %d，期望 0/1/1（排空之前不读 EOF）",
						s.halfClosed, s.conns, d.pool.pipeHeld)
				}
				m.expectIdleCPU(t, "持有 pipe、FIN 已在源一侧接收队列")
				if err := readThenEOF(dst, n, sum); err != nil {
					t.Fatalf("排空：%v", err)
				}
				// 另一方向照常，之后两侧都 EOF
				if _, err := dst.Write([]byte("bye")); err != nil {
					t.Fatal(err)
				}
				dst.CloseWrite()
				src.SetReadDeadline(time.Now().Add(ioTimeout))
				if got, err := io.ReadAll(src); err != nil || string(got) != "bye" {
					t.Fatalf("另一方向收到 %q（%v），期望 \"bye\" 与 EOF", got, err)
				}
			} else {
				// 另一方向：dst 发一个请求再 FIN，tinymapper 立即读到 EOF、shutdown src 一侧；src 读到请求与 EOF
				if _, err := dst.Write([]byte("req")); err != nil {
					t.Fatal(err)
				}
				if err := dst.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				src.SetReadDeadline(time.Now().Add(ioTimeout))
				if got, err := io.ReadAll(src); err != nil || string(got) != "req" {
					t.Fatalf("另一方向收到 %q（%v），期望 \"req\" 与 EOF：持有 pipe 的方向不应挡住另一方向的 EOF", got, err)
				}
				d = m.statsAfterSignal(t)
				if s := d.tcp[1]; s.halfClosed != 1 || s.conns != 1 || d.pool.pipeHeld != 1 {
					t.Fatalf("另一方向 EOF 之后：half_closed=%d conns=%d 持有 pipe %d，期望 1/1/1", s.halfClosed, s.conns, d.pool.pipeHeld)
				}
				m.expectIdleCPU(t, "持有 pipe、另一方向已 EOF")
				if err := src.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := readThenEOF(dst, n, sum); err != nil {
					t.Fatalf("排空：%v", err)
				}
			}
			d = m.waitTCPConns(t, 1, 0)
			if s := d.tcp[1]; s.upSplice+s.downSplice == 0 {
				t.Errorf("持有的方向没有 splice 字节：%+v", s)
			}
			m.expectPipeFDs(t, d, "连接对释放后")
		})
	}
}

// spliceReuse 在 listen（后端为 streamHandler）上同时跑 16 条慢读下载（每条 512 KiB）与 4 条双向 8 MiB 传输：方向反复持有、排空、
// 从池里取 pipe，池里若混进了有残留数据的 pipe（释放连接对时没有 close 而是还池），残留数据会写进别的连接，SHA-256 失败
func spliceReuse(t testing.TB, listen string) {
	t.Helper()
	const slow, fast = 16, 4
	errs := make(chan error, slow+fast)
	for i := range slow {
		go func() { errs <- slowDownload(listen, 512<<10, uint64(100+i)) }()
	}
	for i := range fast {
		go func() { errs <- transfer(listen, 8<<20, 8<<20, 64<<10, uint64(200+i)) }()
	}
	for range slow + fast {
		if err := <-errs; err != nil {
			t.Errorf("复用 pipe 池的传输：%v", err)
		}
	}
}

// slowDownload 按 streamHandler 的协议只下载 size 字节，用 slowReaderSocket 的连接慢读（slowVerify）并核对后端的校验尾
func slowDownload(listen string, size int64, seed uint64) error {
	d := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
	c, err := d.Dial("tcp", listen)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(transferTimeout(size)))
	var hdr [streamHeaderLen]byte
	binary.BigEndian.PutUint64(hdr[8:], uint64(size))
	binary.BigEndian.PutUint32(hdr[16:], 64<<10)
	binary.BigEndian.PutUint64(hdr[20:], seed)
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	if err := slowVerify(c, size, streamSeed(seed, true)); err != nil {
		return fmt.Errorf("慢读下载：%w", err)
	}
	var trailer [64]byte
	if _, err := io.ReadFull(c, trailer[:]); err != nil {
		return fmt.Errorf("读取校验尾：%w", err)
	}
	empty := sha256.Sum256(nil)
	want, _ := writeStream(io.Discard, size, 64<<10, streamSeed(seed, true))
	if !bytes.Equal(trailer[:32], empty[:]) || !bytes.Equal(trailer[32:], want) {
		return errors.New("校验尾与期望不一致")
	}
	return nil
}

// RST 释放持有 pipe 的连接对（D47：持有的 pipe 里一定有数据，直接 close，不还池）。规则 1（--sock-buf 200，见 holdSockBuf）的 8 条连接
// 各让方向稳定持有数据（fill），再由一端发 RST：
//   - client：下行持有（后端写、客户端不读），客户端 RST，tinymapper 读客户端一侧时读到 ECONNRESET；
//   - upstream：上行持有（客户端写、后端不读），后端 RST，读上游一侧时读到 ECONNRESET；
//   - both-client、both-upstream：两个方向都持有（16 个 pipe），发 RST 的一侧 socket 读、写都停着（读被本侧方向的持有停掉，写在等 EV_WRITE），
//     RST 只能经 EPOLLERR/EPOLLHUP（T14 映射为它等的 WRITE）到写分支：splice(pipe→socket) 返回 ECONNRESET（再写是 EPIPE 并触发 SIGPIPE，
//     进程不能退出），释放连接对时两个方向的 pipe 都要 close。
//
// 之后持有归零、pipe fd 恰为 2×alloc（漏 close 的 pipe 让 alloc 与 held+free+scratch 对不上，或 fd 多于 2×alloc）、非 pipe fd 回到基线；
// 再在规则 2（streamHandler 后端，pipe 池是进程级的）上跑 spliceReuse：还了池的残留数据会串进新连接
func TestSpliceReset(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, name := range []string{"client", "upstream", "both-client", "both-upstream"} {
		side, both := strings.TrimPrefix(name, "both-"), strings.HasPrefix(name, "both-")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			streamBE := serveTCP(t, loopback4(t), streamHandler)
			listen2 := loopback4(t)
			rig := newSpliceRig(t, func(listen, remote string) *mapper {
				cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\n\n[[endpoints]]\nlisten = %q\nremote = %q\n",
					listen, remote, listen2, streamBE.addr))
				return startMapper(t, append(listenPoints("t", portOf(listen)), listenPoints("t", portOf(listen2))...), append([]string{"-c", cfg}, holdSockBuf...)...)
			})
			m := rig.m
			base := fdCount(t, m.pid())
			const k = 8
			pairs := make([]*splicePair, k)
			gen := rand.NewChaCha8(streamSeed(9, side == "client"))
			held := 0
			for i := range pairs {
				p := rig.pair(t)
				pairs[i] = p
				if side == "client" || both {
					held++
					rig.fill(t, p, false, gen, io.Discard, held)
				}
				if side == "upstream" || both {
					held++
					rig.fill(t, p, true, gen, io.Discard, held)
				}
			}
			want := held
			var d statsDump
			eventually(t, ioTimeout, 20*time.Millisecond, func() error {
				if d = m.statsAfterSignal(t); d.pool.pipeHeld+d.pool.held != want || d.pool.pipeHeld == 0 {
					return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望共 %d 个且有 pipe（%+v）", d.pool.pipeHeld, d.pool.held, want, d.tcp[1])
				}
				return nil
			})
			t.Logf("RST 之前 pool %+v", d.pool)
			for _, p := range pairs {
				c := p.cli
				if side == "upstream" {
					c = p.srv
				}
				c.SetLinger(0) // close 时发 RST
				c.Close()
			}
			d = m.waitTCPConns(t, 1, 0)
			t.Logf("RST 之后 pool %+v", d.pool)
			// 单方向持有时 RST 由读分支读到（recv/splice 进 pipe 返回 ECONNRESET），两个方向都持有时只能由写分支的 splice 发现
			reason := "recv_len=-1,connection"
			if both {
				reason = "send_len=-1,connection"
			}
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				if n := m.logLines(reason, "closed bc of"); n != k {
					return fmt.Errorf("日志里有 %d 行 %q 的关闭，期望 %d 行", n, reason, k)
				}
				return nil
			})
			if d.pool.pipeHeld != 0 {
				t.Errorf("连接对全部释放后仍有 %d 个方向持有 pipe", d.pool.pipeHeld)
			}
			m.expectPipeFDs(t, d, "RST 释放连接对之后")
			if got := nonPipeFDs(t, m.pid()); got != base {
				t.Errorf("RST 释放连接对之后 tinymapper 有 %d 个非 pipe fd，建连前为 %d", got, base)
			}
			spliceReuse(t, listen2)
			d = m.waitTCPConns(t, 2, 0)
			if d.tcp[2].upSplice == 0 || d.tcp[2].downSplice == 0 {
				t.Errorf("复用阶段没有 splice：%+v", d.tcp[2])
			}
			m.expectPipeFDs(t, d, "复用之后")
		})
	}
}

// RST 到达时这一侧正在 splice（上一次读 ≥ 16 KiB、没有持有）：下一次 splice(src→pipe) 返回 ECONNRESET，按 recv 出错的路径关闭连接对
// （不能当作 EAGAIN 空等，也不能当作 EOF 只半关闭）。先送 4 MiB 进入 splice，排空后再送恰好 32 KiB（一个 skb，一次读完，读完 splice_next
// 必为 1），对端收齐后发 RST：tinymapper 读这一侧时走 splice。之后：另一端被关闭、连接对释放（日志一行 recv_len=-1 的关闭）、pipe fd 恰为
// 2×alloc、非 pipe fd 回到建连前
func TestSpliceResetStreaming(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, side := range []string{"client", "upstream"} {
		t.Run(side, func(t *testing.T) {
			t.Parallel()
			rig := newSpliceRig(t, func(listen, remote string) *mapper { return forward(t, "t", listen, remote) })
			m := rig.m
			base := fdCount(t, m.pid())
			p := rig.pair(t)
			src, dst := p.cli, p.srv
			if side == "upstream" {
				src, dst = p.srv, p.cli
			}
			var got atomic.Int64
			drained := make(chan error, 1)
			go func() {
				buf := make([]byte, 256<<10)
				for {
					n, err := dst.Read(buf)
					got.Add(int64(n))
					if err != nil {
						drained <- err
						return
					}
				}
			}()
			waitGot := func(n int64) {
				t.Helper()
				eventually(t, ioTimeout, 5*time.Millisecond, func() error {
					if g := got.Load(); g != n {
						return fmt.Errorf("对端收到 %d 字节，期望 %d", g, n)
					}
					return nil
				})
			}
			gen := rand.NewChaCha8(streamSeed(15, side == "client"))
			bulk := make([]byte, 4<<20)
			gen.Read(bulk)
			if _, err := src.Write(bulk); err != nil {
				t.Fatal(err)
			}
			waitGot(int64(len(bulk)))
			if s := m.statsAfterSignal(t).tcp[1]; s.upSplice+s.downSplice == 0 {
				t.Fatalf("4 MiB 之后还没有 splice 字节：%+v", s)
			}
			last := make([]byte, 32<<10)
			gen.Read(last)
			if _, err := src.Write(last); err != nil {
				t.Fatal(err)
			}
			waitGot(int64(len(bulk) + len(last)))
			src.SetLinger(0)
			src.Close()
			select {
			case err := <-drained:
				t.Logf("对端读到：%v", err)
			case <-time.After(ioTimeout):
				m.expectIdleCPU(t, "RST 之后另一端迟迟没有关闭时")
				t.Fatalf("%v 内另一端没有被关闭：splice 读到 ECONNRESET 应关闭连接对", ioTimeout)
			}
			d := m.waitTCPConns(t, 1, 0)
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				if n := m.logLines("recv_len=-1,connection", "closed bc of"); n != 1 {
					return fmt.Errorf("日志里有 %d 行读出错的关闭，期望 1 行", n)
				}
				return nil
			})
			m.expectPipeFDs(t, d, "RST 释放连接对之后")
			if got := nonPipeFDs(t, m.pid()); got != base {
				t.Errorf("RST 释放连接对之后 tinymapper 有 %d 个非 pipe fd，建连前为 %d", got, base)
			}
		})
	}
}

// 空闲超时释放持有 pipe 的连接对（TPM_SLOW，--sock-buf 200 见 holdSockBuf）：clear_inactive 走的是 erase()，不是 RST、出错时的 erase_closed()，
// pipe 的 close 两处各有一份。
// 一条连接两个方向都持有 pipe（两端都不读），之后没有任何事件、LRU 时间戳不再刷新，约 360 s 后被清理：持有归零，
// pipe fd 恰为 2×alloc，非 pipe fd 回到建连前
func TestSpliceIdleTimeoutHeld(t *testing.T) {
	t.Parallel()
	slow(t)
	needPipeQuotaExempt(t)
	rig := newSpliceRig(t, func(listen, remote string) *mapper {
		return startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", remote, "-t"}, holdSockBuf...)...)
	})
	m := rig.m
	base := fdCount(t, m.pid())
	p := rig.pair(t)
	gen := rand.NewChaCha8(streamSeed(13, true))
	rig.fill(t, p, false, gen, io.Discard, 1)
	rig.fill(t, p, true, gen, io.Discard, 2)
	eventually(t, ioTimeout, 20*time.Millisecond, func() error {
		if d := m.statsAfterSignal(t); d.pool.pipeHeld != 2 || d.pool.held != 0 {
			return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望 2 个方向都持有 pipe", d.pool.pipeHeld, d.pool.held)
		}
		return nil
	})
	start := time.Now()
	var d statsDump
	eventually(t, 420*time.Second, 5*time.Second, func() error {
		if d = m.statsAfterSignal(t); d.tcp[1].conns != 0 {
			return fmt.Errorf("空闲 %v 后仍有 %d 条连接", time.Since(start).Round(time.Second), d.tcp[1].conns)
		}
		return nil
	})
	elapsed := time.Since(start)
	t.Logf("持有 pipe 的连接对空闲 %v 后被清理：pool %+v", elapsed.Round(time.Second), d.pool)
	if elapsed < 340*time.Second {
		t.Errorf("持有 pipe 的连接对过早被清理：%v（超时应为 360 s）", elapsed.Round(time.Second))
	}
	if d.pool.pipeHeld != 0 {
		t.Errorf("清理后仍有 %d 个方向持有 pipe", d.pool.pipeHeld)
	}
	m.expectPipeFDs(t, d, "空闲超时清理之后")
	if got := nonPipeFDs(t, m.pid()); got != base {
		t.Errorf("空闲超时清理之后 tinymapper 有 %d 个非 pipe fd，建连前为 %d", got, base)
	}
}

// splice 读到 EOF（返回 0）走现有的 EOF 路径：只 shutdown 另一侧的写方向，反方向照常（半关闭），不能当作出错关掉连接对。
// 先送 1 MiB 进入 splice，排空后暂停 tinymapper，送恰好 32 KiB 再 FIN，等它们都进了 tinymapper 源一侧 socket（接收队列 32 KiB 加 FIN、
// CLOSE_WAIT）再恢复：第一次读 32 KiB（之后 splice_next 必为 1），第二次读是 splice、返回 0。核对：目的端收齐 32 KiB 后读到 EOF，
// half_closed=1，反方向还能送 "bye" 并收到 EOF，连接对随后释放
func TestSpliceEOF(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, dir := range []string{"up", "down"} {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()
			rig := newSpliceRig(t, func(listen, remote string) *mapper { return forward(t, "t", listen, remote) })
			m := rig.m
			p := rig.pair(t)
			src, dst, tmSrc := p.cli, p.srv, p.tmCli
			if dir == "down" {
				src, dst, tmSrc = p.srv, p.cli, p.tmUp
			}
			gen := rand.NewChaCha8(streamSeed(17, dir == "down"))
			bulk := make([]byte, 1<<20)
			gen.Read(bulk)
			go src.Write(bulk)
			dst.SetReadDeadline(time.Now().Add(ioTimeout))
			if _, err := io.ReadFull(dst, make([]byte, len(bulk))); err != nil {
				t.Fatal(err)
			}
			if s := m.statsAfterSignal(t).tcp[1]; s.upSplice+s.downSplice == 0 {
				t.Fatalf("1 MiB 之后还没有 splice 字节：%+v", s)
			}
			last := make([]byte, 32<<10)
			gen.Read(last)
			m.pause(t)
			if _, err := src.Write(last); err != nil {
				t.Fatal(err)
			}
			if err := src.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			waitTMState(t, tmSrc, tcpCloseWait, "tinymapper 源一侧 socket")
			// idiag_rqueue 是 rcv_nxt−copied_seq，FIN 占一个序号
			eventually(t, ioTimeout, 10*time.Millisecond, func() error {
				if q, err := sockDiag(syscall.IPPROTO_TCP, tmSrc[0], tmSrc[1]); err != nil || int(q.rqueue) != len(last)+1 {
					return fmt.Errorf("tinymapper 源一侧接收队列 %d（%v），期望 %d 字节加 FIN", q.rqueue, err, len(last))
				}
				return nil
			})
			m.resume(t)
			sum := sha256.Sum256(last)
			if err := readThenEOF(dst, int64(len(last)), sum[:]); err != nil {
				t.Fatalf("splice 读到 EOF：%v", err)
			}
			if s := m.statsAfterSignal(t).tcp[1]; s.halfClosed != 1 || s.conns != 1 {
				t.Fatalf("EOF 之后 half_closed=%d conns=%d，期望 1/1（只半关闭）", s.halfClosed, s.conns)
			}
			if _, err := dst.Write([]byte("bye")); err != nil {
				t.Fatal(err)
			}
			dst.CloseWrite()
			src.SetReadDeadline(time.Now().Add(ioTimeout))
			if got, err := io.ReadAll(src); err != nil || string(got) != "bye" {
				t.Fatalf("反方向收到 %q（%v），期望 \"bye\" 与 EOF", got, err)
			}
			d := m.waitTCPConns(t, 1, 0)
			m.expectPipeFDs(t, d, "两侧 EOF 之后")
		})
	}
}

// sendOOB 在 c 上以 MSG_OOB 发 1 字节紧急数据
func sendOOB(c *net.TCPConn, b byte) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Write(func(fd uintptr) bool {
		serr = syscall.Sendto(int(fd), []byte{b}, syscall.MSG_OOB, nil)
		return serr != syscall.EAGAIN
	}); err != nil {
		return err
	}
	return serr
}

// 大流量中途的 TCP 紧急数据（对端 MSG_OOB）。队首是紧急字节时非阻塞 splice 返回 EAGAIN，而 epoll 仍报可读（后面还有数据）：照搬 EAGAIN
// 会让这条连接每轮空转、后面的数据永远不转发；当作错误则会关掉连接。规格：这一次改走 recv，它跳过紧急字节（没有 SO_OOBINLINE），
// 与拷贝路径一致。两个方向 × 两种模式，过程相同、结果必须相同：
//  1. 1 MiB 大块（splice 模式下这个方向随后进入 splice，用例核对 splice 字节）；
//  2. 暂停 tinymapper，排好 A（20 KiB）、紧急字节、B（20 KiB），等它们都进了 tinymapper 源一侧 socket 的接收队列再恢复：读 A 停在紧急标记处，
//     A ≥ 16 KiB，下一次读在标记处 splice（EAGAIN）；目的端收到的必须恰为 A+B，转发停住时先采样 CPU 说明是否空转；之后不空转；
//  3. 再 1 MiB 照常；目的端没有多余字节
func TestSpliceUrgent(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, mode := range spliceModes {
		for _, dir := range []string{"up", "down"} {
			t.Run(mode.name+"-"+dir, func(t *testing.T) {
				t.Parallel()
				rig := newSpliceRig(t, func(listen, remote string) *mapper {
					return startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", remote, "-t"}, mode.args...)...)
				})
				m := rig.m
				p := rig.pair(t)
				src, dst, tmSrc := p.cli, p.srv, p.tmCli
				if dir == "down" {
					src, dst, tmSrc = p.srv, p.cli, p.tmUp
				}
				gen := rand.NewChaCha8(streamSeed(11, dir == "down"))
				chunk := func(n int) []byte {
					b := make([]byte, n)
					gen.Read(b)
					return b
				}
				expect := func(want []byte, what string) {
					t.Helper()
					werr := make(chan error, 1)
					go func() {
						src.SetWriteDeadline(time.Now().Add(ioTimeout))
						_, err := src.Write(want)
						werr <- err
					}()
					dst.SetReadDeadline(time.Now().Add(ioTimeout))
					got := make([]byte, len(want))
					n, err := io.ReadFull(dst, got)
					if err != nil {
						m.expectIdleCPU(t, what+"转发停住时")
						t.Fatalf("%s：只收到 %d/%d 字节：%v", what, n, len(want), err)
					}
					if err := <-werr; err != nil {
						t.Fatalf("%s：写入：%v", what, err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("%s：内容不一致", what)
					}
				}
				spliced := func(s tcpStat) uint64 {
					if dir == "down" {
						return s.downSplice
					}
					return s.upSplice
				}
				expect(chunk(1<<20), "紧急数据之前的 1 MiB")
				before := m.statsAfterSignal(t).tcp[1]
				if len(mode.args) == 0 && spliced(before) == 0 {
					t.Fatalf("1 MiB 之后这个方向还没有 splice 字节：用例没有进入 splice 模式（%+v）", before)
				}

				a, b := chunk(20<<10), chunk(20<<10)
				m.pause(t)
				src.SetWriteDeadline(time.Now().Add(ioTimeout))
				if _, err := src.Write(a); err != nil {
					t.Fatal(err)
				}
				if err := sendOOB(src, 'U'); err != nil {
					t.Fatalf("发送紧急数据：%v", err)
				}
				if _, err := src.Write(b); err != nil {
					t.Fatal(err)
				}
				queued := len(a) + 1 + len(b)
				eventually(t, ioTimeout, 10*time.Millisecond, func() error {
					q, err := sockDiag(syscall.IPPROTO_TCP, tmSrc[0], tmSrc[1])
					if err != nil {
						return err
					}
					if int(q.rqueue) != queued {
						return fmt.Errorf("tinymapper 源一侧接收队列 %d 字节，期望 %d", q.rqueue, queued)
					}
					return nil
				})
				m.resume(t)
				dst.SetReadDeadline(time.Now().Add(ioTimeout))
				got := make([]byte, len(a)+len(b))
				if n, err := io.ReadFull(dst, got); err != nil {
					m.expectIdleCPU(t, "紧急字节处转发停住时")
					t.Fatalf("紧急字节前后只收到 %d/%d 字节：%v（splice 在紧急标记处返回 EAGAIN 后应改走 recv）", n, len(got), err)
				}
				if !bytes.Equal(got, append(a, b...)) {
					t.Fatal("紧急字节前后的数据不一致：期望恰为 A+B（紧急字节被跳过，与拷贝路径相同）")
				}
				m.expectIdleCPU(t, "紧急字节之后")
				expect(chunk(1<<20), "紧急数据之后的 1 MiB")
				dst.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if n, err := dst.Read(make([]byte, 16)); n != 0 || !isTimeout(err) {
					t.Errorf("之后又收到 %d 字节（%v）：紧急字节不应作为普通数据转发", n, err)
				}
				after := m.statsAfterSignal(t).tcp[1]
				t.Logf("%s：紧急数据前 %+v；之后 %+v", dir, before, after)
			})
		}
	}
}

// ---- pipe 创建失败的回退 ----

const rlimitNofile = 7 // RLIMIT_NOFILE

// prlimit 对进程 pid 的资源 resource 做 prlimit64：newv 非空则设置，oldv 非空则取回旧值
func prlimit(pid, resource int, newv, oldv *syscall.Rlimit) error {
	if _, _, e := syscall.Syscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(resource),
		uintptr(unsafe.Pointer(newv)), uintptr(unsafe.Pointer(oldv)), 0, 0); e != 0 {
		return e
	}
	return nil
}

// lowerNofile 把 pid 的 RLIMIT_NOFILE 软限降到它当前最小的空闲 fd 号（只降软限、保留硬限，同 alloc_test.go 的 RLIMIT_DATA）：此后任何
// 新 fd 都分配不到，pipe2 返回 EMFILE，已打开的 fd 照常。返回一次性还原函数
func lowerNofile(t testing.TB, pid int) func() {
	t.Helper()
	var old syscall.Rlimit
	if err := prlimit(pid, rlimitNofile, nil, &old); err != nil {
		t.Fatalf("读取 RLIMIT_NOFILE 失败：%v", err)
	}
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	open := map[int]bool{}
	for _, e := range ents {
		fd, _ := strconv.Atoi(e.Name())
		open[fd] = true
	}
	low := 0
	for open[low] {
		low++
	}
	if err := prlimit(pid, rlimitNofile, &syscall.Rlimit{Cur: uint64(low), Max: old.Max}, nil); err != nil {
		t.Fatalf("降低 RLIMIT_NOFILE 失败：%v", err)
	}
	t.Logf("RLIMIT_NOFILE 软限 %d → %d（fd 0..%d 都已打开）", old.Cur, low, low-1)
	var once sync.Once
	return func() { once.Do(func() { prlimit(pid, rlimitNofile, &old, nil) }) }
}

// pipe2 失败（EMFILE）时回退拷贝。先建好 3 条连接（降限之后 accept 也会失败），把 tinymapper 的 RLIMIT_NOFILE 软限降到没有空闲 fd，
// 依次在这 3 条连接上双向各传 4 MiB，两次之间停 500 ms（跨过 400 ms 的定时器周期）：
//   - 数据完整；splice_fallback > 0、splice 字节为 0、pipes alloc 为 0、没有 pipe fd；
//   - 失败原因进程内只有第一次记 info（恰好 1 行），之后记 debug（--log-level 5，后两次传输各跨过一个周期，至少 2 行）；
//   - 失败后到下一个周期之前不再创建：尝试次数（info+debug 行）不超过经过的周期数 + 2，而回退的读远多于此（≥ 10 倍）；
//
// 还原软限后（下一个周期起）新连接重新 splice；info 行仍只有 1 行；关闭全部连接后 pipe fd 恰为 2×alloc
func TestSpliceFallbackEMFILE(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	m := startMapper(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--log-level", "5")
	const k = 3
	conns := make([]net.Conn, k)
	t.Cleanup(func() { closeAll(conns) })
	for i := range conns {
		conns[i] = dial(t, listen)
	}
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		if n := be.accepted.Load(); n != k {
			return fmt.Errorf("后端接受了 %d 条连接，期望 %d", n, k)
		}
		return nil
	})
	restore := lowerNofile(t, m.pid())
	defer restore()
	start := time.Now()
	for i, c := range conns {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		if err := transferOn(c, 4<<20, 4<<20, 256<<10, uint64(i)); err != nil {
			t.Fatalf("第 %d 次传输（pipe2 返回 EMFILE）：%v", i+1, err)
		}
	}
	elapsed := time.Since(start)
	d := m.statsAfterSignal(t)
	s := d.tcp[1]
	t.Logf("降限期间（%v）：%+v；pool %+v", elapsed.Round(time.Millisecond), s, d.pool)
	if s.spliceFallback == 0 || s.upSplice != 0 || s.downSplice != 0 || d.pool.pipeAlloc != 0 {
		t.Errorf("pipe2 一律 EMFILE：期望 splice_fallback > 0、splice 字节为 0、pipes alloc 为 0，实际 %+v，pipes alloc=%d", s, d.pool.pipeAlloc)
	}
	if n := pipeFDs(t, m.pid()); n != 0 {
		t.Errorf("降限期间 tinymapper 有 %d 个 pipe fd", n)
	}
	var info, debug int
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		info, debug = m.logLines("[INFO]", "pipe2 failed", pipeFailLog), m.logLines("[DEBUG]", "pipe2 failed", pipeFailLog)
		if info+debug < k {
			return fmt.Errorf("pipe2 失败的日志 info %d 行、debug %d 行，期望共至少 %d 行", info, debug, k)
		}
		return nil
	})
	tries := info + debug
	t.Logf("pipe2 失败日志：info %d 行，debug %d 行；回退的读 %d 次", info, debug, s.spliceFallback)
	if info != 1 {
		t.Errorf("pipe2 失败的 info 行有 %d 行，期望进程内恰好 1 行（之后记 debug）", info)
	}
	if debug < k-1 {
		t.Errorf("pipe2 失败的 debug 行只有 %d 行：后 %d 次传输各跨过了定时器周期，应各再试一次", debug, k-1)
	}
	if limit := int(elapsed/(400*time.Millisecond)) + 2; tries > limit {
		t.Errorf("%v 内试了 %d 次创建 pipe（上限约 %d 次）：失败后到下一个定时器周期之前不应再试", elapsed.Round(time.Millisecond), tries, limit)
	}
	if s.spliceFallback < uint64(10*tries) {
		t.Errorf("回退的读只有 %d 次、创建尝试 %d 次：用例没有测到“每个周期最多试一次”", s.spliceFallback, tries)
	}
	restore()
	eventually(t, 5*time.Second, 100*time.Millisecond, func() error {
		if err := transfer(listen, 4<<20, 4<<20, 256<<10, 9); err != nil {
			t.Fatalf("还原软限之后：%v", err)
		}
		if s := m.statsAfterSignal(t).tcp[1]; s.upSplice == 0 || s.downSplice == 0 {
			return fmt.Errorf("还原 RLIMIT_NOFILE 后仍未 splice：%+v", s)
		}
		return nil
	})
	if n := m.logLines("[INFO]", pipeFailLog); n != 1 {
		t.Errorf("创建 pipe 失败的 info 行共 %d 行，期望 1 行", n)
	}
	closeAll(conns)
	d = m.waitTCPConns(t, 1, 0)
	m.expectPipeFDs(t, d, "还原并关闭全部连接后")
}

// ---- fs.pipe-user-pages-soft：以专用的非 root uid 运行 tinymapper ----
//
// 一个用户的 pipe 总页数达到 fs.pipe-user-pages-soft（默认 16384 页，即 1024 个默认 16 页的 pipe）之后，它新建的 pipe 只有 2 页（5.14 起；
// 4 KiB 页时 8 KiB），也不能扩容。只约束同时没有 CAP_SYS_RESOURCE 与 CAP_SYS_ADMIN 的进程：容器里的 root 两者都没有，所以也受限，
// 但 uid 0 被 Docker VM 里所有 root 进程共用（其他测试容器、lead 的基准），不能拿它占满。这里让一个随机的非 root uid 的占位进程
// （重新执行的测试二进制，pipeHogEnv）持有足够多的 pipe，再以同一 uid 启动 tinymapper：它的每个新 pipe 都只有 2 页，规格要求关掉、回退拷贝。
// 测试进程读不了其他 uid 的 /proc/<pid>/fd（没有 CAP_SYS_PTRACE，见 startMapperNoNetAdmin），这里只看统计与日志
const pipeHogEnv = "TPM_PIPE_HOG"

func init() {
	if os.Getenv(pipeHogEnv) != "" {
		runPipeHog()
	}
}

const fGetpipeSz = 1032 // F_GETPIPE_SZ

func pipeSize(fd int) (int, error) {
	r, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), fGetpipeSz, 0)
	if e != 0 {
		return 0, e
	}
	return int(r), nil
}

// runPipeHog 在重新执行的测试二进制里运行：不断创建 pipe 并持有，直到新 pipe 的容量小于 64 KiB（本用户已达软限），在 stdout 写一行
// "ready <pipe 数> <最后一个的容量>"，然后阻塞到 stdin 关闭。不返回
func runPipeHog() {
	for n := 1; n <= 1<<16; n++ {
		var p [2]int
		if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
			fmt.Printf("error pipe2 #%d: %v\n", n, err)
			os.Exit(1)
		}
		size, err := pipeSize(p[1])
		if err != nil {
			fmt.Printf("error F_GETPIPE_SZ: %v\n", err)
			os.Exit(1)
		}
		if size < 65536 {
			fmt.Printf("ready %d %d\n", n, size)
			io.Copy(io.Discard, os.Stdin)
			os.Exit(0)
		}
	}
	fmt.Println("error: 65536 个 pipe 之后新 pipe 仍不小于 64 KiB")
	os.Exit(1)
}

func readSysctlInt(t testing.TB, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("读不到 %s：%v", path, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("%s 的内容无法解析：%q", path, data)
	}
	return v
}

// tcpListening 用 sock_diag 判断 port 上有没有 TCP 监听（IPv4 或 IPv6），不核对属于哪个进程（freePort 分配的端口在本进程内不重复）
func tcpListening(port int) bool {
	found := false
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		sockDiagDump(family, syscall.IPPROTO_TCP, 1<<10, func(p, _ uint16, _ uint32) {
			if int(p) == port {
				found = true
			}
		})
	}
	return found
}

// startMapperAsUID 以 uid（同号 gid）启动 tinymapper：setuid 到非 0 时能力全部清空，受该 uid 的 pipe 限额约束。就绪只看 port 上有没有
// TCP 监听（读不了它的 /proc/<pid>/fd，不能用 listening、fdCount、pipeFDs、expectPipeFDs），随后核对它确实以该 uid 运行
func startMapperAsUID(t testing.TB, uid uint32, port int, args ...string) *mapper {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "tinymapper.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(mapperBin, append([]string{"--disable-color"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("以 uid %d 启动 tinymapper 失败：%v", uid, err)
	}
	m := &mapper{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() { m.exitErr = cmd.Wait(); close(m.done) }()
	t.Cleanup(func() { m.stop(t, false) })
	eventually(t, 10*time.Second, 20*time.Millisecond, func() error {
		m.fatalIfExited(t, "等待监听就绪时")
		if !tcpListening(port) {
			return fmt.Errorf("端口 %d 上还没有 TCP 监听", port)
		}
		return nil
	})
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", m.pid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) < 2 || f[1] != strconv.Itoa(int(uid)) {
				t.Fatalf("tinymapper 的 Uid 行为 %q，期望有效 uid %d", line, uid)
			}
		}
	}
	return m
}

// 新 pipe 小于 64 KiB（本用户的 pipe 总页数已达 fs.pipe-user-pages-soft）时回退拷贝：占位进程以随机的非 root uid 持有约 1025 个 pipe，
// tinymapper 以同一 uid 运行。双向各 8 MiB：数据完整、splice_fallback > 0、splice 字节为 0、pipes alloc 为 0（容量检查漏掉时 tinymapper
// 会用 8 KiB 的 pipe splice）；info 行恰好 1 行并报出新 pipe 的容量。占位进程退出后（下一个定时器周期起）重新 splice，info 行仍是 1 行
func TestSpliceFallbackPipeQuota(t *testing.T) {
	t.Parallel()
	if os.Getuid() != 0 {
		t.Skip("以另一个 uid 启动进程需要 root")
	}
	soft := readSysctlInt(t, "/proc/sys/fs/pipe-user-pages-soft")
	hard := readSysctlInt(t, "/proc/sys/fs/pipe-user-pages-hard")
	if soft == 0 {
		t.Skip("fs.pipe-user-pages-soft 为 0（不限）")
	}
	if hard != 0 && hard <= soft+64 {
		t.Skipf("fs.pipe-user-pages-hard=%d 不比软限 %d 大出足够余量：到软限附近就会拒绝创建", hard, soft)
	}
	uid := uint32(42000 + rand.IntN(20000))
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hog := exec.Command(self)
	hog.Env = append(os.Environ(), pipeHogEnv+"=1")
	hog.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	stdin, err := hog.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := hog.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := hog.Start(); err != nil {
		t.Fatalf("以 uid %d 启动占位进程失败：%v", uid, err)
	}
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()
	var line string
	select {
	case line = <-lines:
	case <-time.After(30 * time.Second):
		hog.Process.Kill()
		hog.Wait()
		t.Fatal("占位进程 30 s 内没有报告就绪")
	}
	hogDone := make(chan error, 1)
	go func() {
		io.Copy(io.Discard, stdout)
		hogDone <- hog.Wait()
	}()
	release := sync.OnceFunc(func() {
		stdin.Close()
		select {
		case <-hogDone:
		case <-time.After(5 * time.Second):
			hog.Process.Kill()
			<-hogDone
		}
	})
	t.Cleanup(release)
	var held, size int
	if _, err := fmt.Sscanf(line, "ready %d %d", &held, &size); err != nil {
		t.Fatalf("占位进程：%q", line)
	}
	t.Logf("uid %d 的占位进程持有 %d 个 pipe，最后一个只有 %d B（fs.pipe-user-pages-soft=%d 页，页大小 %d B）", uid, held, size, soft, os.Getpagesize())

	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	m := startMapperAsUID(t, uid, portOf(listen), "-l", listen, "-r", be.addr, "-t", "--log-level", "5")
	if err := transfer(listen, 8<<20, 8<<20, 256<<10, 1); err != nil {
		t.Fatalf("pipe 只有 %d B 时：%v", size, err)
	}
	d := m.statsAfterSignal(t)
	s := d.tcp[1]
	t.Logf("占位期间：%+v；pool %+v", s, d.pool)
	if s.spliceFallback == 0 || s.upSplice != 0 || s.downSplice != 0 || d.pool.pipeAlloc != 0 {
		t.Errorf("新 pipe 只有 %d B（< 64 KiB）：期望 splice_fallback > 0、splice 字节为 0、pipes alloc 为 0，实际 %+v，pipes alloc=%d",
			size, s, d.pool.pipeAlloc)
	}
	want := fmt.Sprintf("only %d bytes", size)
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if n := m.logLines("[INFO]", want, pipeFailLog); n != 1 {
			return fmt.Errorf("含 %q 的 info 行有 %d 行，期望 1 行", want, n)
		}
		return nil
	})
	release()
	eventually(t, 5*time.Second, 100*time.Millisecond, func() error {
		if err := transfer(listen, 4<<20, 4<<20, 256<<10, 2); err != nil {
			t.Fatalf("占位进程退出之后：%v", err)
		}
		if s := m.statsAfterSignal(t).tcp[1]; s.upSplice == 0 || s.downSplice == 0 {
			return fmt.Errorf("占位进程退出后仍未 splice：%+v", s)
		}
		return nil
	})
	if n := m.logLines("[INFO]", pipeFailLog); n != 1 {
		t.Errorf("创建 pipe 失败的 info 行共 %d 行，期望 1 行", n)
	}
}

// --disable-splice（D48）：帮助文本里有；不带参数；只有命令行，没有 TOML 键；与 -c 一起用时对所有规则生效（双向 8 MiB 后 splice 计数为 0、
// 没有 pipe fd，statsAfterSignal 也核对）
func TestSpliceOptions(t *testing.T) {
	t.Parallel()
	t.Run("help", func(t *testing.T) {
		t.Parallel()
		out, err := exec.Command(mapperBin, "-h").Output()
		if err != nil {
			t.Fatalf("-h 退出状态异常：%v", err)
		}
		if !strings.Contains(string(out), "--disable-splice") {
			t.Errorf("帮助文本里没有 --disable-splice：\n%s", out)
		}
	})
	t.Run("argument", func(t *testing.T) {
		t.Parallel()
		out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "--disable-splice=1")
		if !strings.Contains(out, "disable-splice") {
			t.Errorf("--disable-splice=1 的报错没有提到这个选项：\n%s", out)
		}
	})
	t.Run("toml-key", func(t *testing.T) {
		t.Parallel()
		cfg := writeConfig(t, fmt.Sprintf("[network]\ndisable_splice = true\n\n[[endpoints]]\nlisten = %q\nremote = %q\n", loopback4(t), loopback4(t)))
		if out := runExpectFail(t, 5*time.Second, "-c", cfg); !strings.Contains(out, "unknown key in [network]") {
			t.Errorf("[network] disable_splice 的报错不符：\n%s", out)
		}
	})
	t.Run("config", func(t *testing.T) {
		t.Parallel()
		bes := []*tcpServer{serveTCP(t, loopback4(t), streamHandler), serveTCP(t, loopback4(t), streamHandler)}
		listens := []string{loopback4(t), loopback4(t)}
		var cfg strings.Builder
		var wait []listenPoint
		for r := range bes {
			fmt.Fprintf(&cfg, "[[endpoints]]\nlisten = %q\nremote = %q\n\n", listens[r], bes[r].addr)
			wait = append(wait, listenPoints("t", portOf(listens[r]))...)
		}
		m := startMapper(t, wait, "-c", writeConfig(t, cfg.String()), "--disable-splice")
		for r := range bes {
			if err := transfer(listens[r], 8<<20, 8<<20, 256<<10, uint64(r)); err != nil {
				t.Fatalf("规则 %d：%v", r+1, err)
			}
		}
		d := m.statsAfterSignal(t)
		for r := range bes {
			if s := d.tcp[r+1]; s.upSplice != 0 || s.downSplice != 0 || s.spliceFallback != 0 || s.upBytes != 8<<20+streamHeaderLen {
				t.Errorf("规则 %d：%+v，期望 splice 计数全 0、up_bytes=%d", r+1, s, 8<<20+streamHeaderLen)
			}
		}
		if d.pool.pipeAlloc != 0 || pipeFDs(t, m.pid()) != 0 {
			t.Errorf("--disable-splice 下 pipes alloc=%d、pipe fd %d 个，期望都为 0", d.pool.pipeAlloc, pipeFDs(t, m.pid()))
		}
	})
}

// ---- 修订 2：D50（写分支 EAGAIN）、D52（fd 预算）、审查 L1（splice 不可用）----

// D50：写分支（持有块时 send、持有 pipe 时从 pipe splice 写出）返回 EAGAIN 时继续等可写，不关闭连接对。主机越过 tcp_mem[2] 时 EPOLLOUT
// 之后发送仍可能 EAGAIN（EPOLLOUT 只看本 socket 的剩余空间）；这里用 seccomp 通知（startMapperNotify）确定性注入：下行方向稳定持有数据
// （fill）后开始让发往 tinymapper 客户端一侧 socket 的 sendto/sendmsg 与 splice（fd_out 为它）返回 EAGAIN，客户端随即开始读，写分支
// 每轮都碰到 EAGAIN（注入期间空转是设计如此，不查 CPU）；注入至少 50 次后停止，连接对必须还在、没有 send_len=-1 的关闭，客户端收齐 SHA-256
// 一致的数据，后端关写方向后紧接着读到 EOF；第 4 版起第一次 EAGAIN 记一行 info（报出 fd），之后的记 debug。
//   - block（--disable-splice）：持有块，注入落在 send 上；
//   - pipe：持有 pipe，注入落在 splice(pipe→socket) 上，down_splice 非零
func TestSpliceWriteEAGAIN(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, c := range []struct {
		name  string
		pipe  bool
		extra []string
	}{
		{"block", false, []string{"--disable-splice"}},
		{"pipe", true, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var nf *notifier
			rig := newSpliceRig(t, func(listen, remote string) *mapper {
				m, n := startMapperNotify(t, listenPoints("t", portOf(listen)),
					append(append([]string{"-l", listen, "-r", remote, "-t"}, holdSockBuf...), c.extra...)...)
				nf = n
				return m
			})
			m := rig.m
			p := rig.pair(t)
			b, err := sockDiag(syscall.IPPROTO_TCP, p.tmCli[0], p.tmCli[1])
			if err != nil {
				t.Fatal(err)
			}
			target := fdOfSocket(m.pid(), b.inode)
			if target < 0 {
				t.Fatalf("找不到 tinymapper 客户端一侧 socket（inode %d）的 fd", b.inode)
			}
			var failing atomic.Bool
			var injected, viaSplice, viaSend atomic.Int64
			nf.setDecide(func(call notifyCall) syscall.Errno {
				if !failing.Load() {
					return 0
				}
				switch {
				case call.nr == syscall.SYS_SPLICE && call.fd(2) == target:
					viaSplice.Add(1)
				case (call.nr == syscall.SYS_SENDTO || call.nr == syscall.SYS_SENDMSG) && call.fd(0) == target:
					viaSend.Add(1)
				default:
					return 0
				}
				injected.Add(1)
				return syscall.EAGAIN
			})
			gen, h := rand.NewChaCha8(streamSeed(19, c.pipe)), sha256.New()
			n := rig.fill(t, p, false, gen, h, 1)
			sum := h.Sum(nil)
			eventually(t, ioTimeout, 20*time.Millisecond, func() error {
				d := m.statsAfterSignal(t)
				if c.pipe && (d.pool.pipeHeld != 1 || d.pool.held != 0) || !c.pipe && d.pool.held != 1 {
					return fmt.Errorf("持有 pipe %d 个、块 %d 个，期望下行持有%s", d.pool.pipeHeld, d.pool.held, map[bool]string{false: "块", true: " pipe"}[c.pipe])
				}
				return nil
			})
			failing.Store(true)
			got := make(chan error, 1)
			go func() { got <- readThenEOF(p.cli, n, sum) }()
			waitCount(t, &injected, 50, ioTimeout, "注入的 EAGAIN ")
			if d := m.statsAfterSignal(t); d.tcp[1].conns != 1 {
				t.Fatalf("注入 EAGAIN 期间连接对被释放：%+v", d.tcp[1])
			}
			failing.Store(false)
			t.Logf("注入 EAGAIN %d 次（splice 写出 %d 次，send %d 次）", injected.Load(), viaSplice.Load(), viaSend.Load())
			if c.pipe && viaSplice.Load() == 0 || !c.pipe && viaSend.Load() == 0 {
				t.Errorf("注入没有落在期望的写法上：splice %d 次、send %d 次", viaSplice.Load(), viaSend.Load())
			}
			p.srv.CloseWrite()
			select {
			case err := <-got:
				if err != nil {
					t.Fatalf("注入结束后下行：%v", err)
				}
			case <-time.After(transferTimeout(n)):
				t.Fatal("注入结束后下行没有排空")
			}
			d := m.statsAfterSignal(t) // 统计之后 fflush，之前的日志行都已写出
			if s := d.tcp[1]; s.downBytes != uint64(n) || c.pipe && s.downSplice == 0 {
				t.Errorf("down_bytes=%d down_splice=%d，期望 %d 字节%s", s.downBytes, s.downSplice, n, map[bool]string{false: "", true: "且有 splice 字节"}[c.pipe])
			}
			if k := m.logLines("send_len=-1"); k != 0 {
				t.Errorf("日志里有 %d 行 send_len=-1：写分支把 EAGAIN 当成了错误（D50）", k)
			}
			// 第 4 版：写分支的 EAGAIN 进程内第一次记 info（之后 debug，默认级别不写），报出 fd
			line := fmt.Sprintf("[tcp]send to fd=%d returned EAGAIN although writable", target)
			if k, all := m.logLines("[INFO]", line), m.logLines("returned EAGAIN although writable"); k != 1 || all != 1 {
				t.Errorf("%q 的 info 行有 %d 行（含这句的共 %d 行），期望恰好 1 行", line, k, all)
			}
		})
	}
}

// 审查 L1：splice 本身不可用（seccomp 白名单里没有它返回 ENOSYS，或 EPERM、EINVAL、EOPNOTSUPP）时只记一行 warn "[tcp]splice failed (...)"，
// 整个进程从此改走拷贝，失败的那次读改用 recv（什么都没读到，数据不丢）。
//   - ENOSYS、EPERM：每次 splice 都失败；两次双向 8 MiB：数据完整，splice 计数为 0，没有读写出错的关闭，warn 恰好 1 行，splice 只被调用过 1 次；
//   - dynamic：先照常 splice；再让读进 pipe 的 splice（args[0] 是 socket）返回 ENOSYS：恰好失败 1 次、1 行 warn；之后即使 splice 又能用，
//     也不再有读进 pipe 的 splice，splice 计数不再增长（进程级、不可逆）
func TestSpliceUnavailable(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	const warn = "[tcp]splice failed ("
	noErrorCloses := func(t *testing.T, m *mapper) {
		t.Helper()
		if k := m.logLines("recv_len=-1") + m.logLines("send_len=-1"); k != 0 {
			t.Errorf("日志里有 %d 行读写出错的关闭", k)
		}
	}
	for _, errno := range []syscall.Errno{syscall.ENOSYS, syscall.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), streamHandler)
			listen := loopback4(t)
			m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")
			var calls atomic.Int64
			nf.setDecide(func(call notifyCall) syscall.Errno {
				if call.nr == syscall.SYS_SPLICE {
					calls.Add(1)
					return errno
				}
				return 0
			})
			for i := range 2 {
				if err := transfer(listen, 8<<20, 8<<20, 256<<10, uint64(i)); err != nil {
					t.Fatalf("第 %d 次传输：%v", i+1, err)
				}
			}
			d := m.statsAfterSignal(t)
			s := d.tcp[1]
			t.Logf("splice 被调用 %d 次；%+v；pool %+v", calls.Load(), s, d.pool)
			if want := uint64(2 * (8<<20 + streamHeaderLen)); s.upBytes != want || s.upSplice != 0 || s.downSplice != 0 {
				t.Errorf("up_bytes=%d（期望 %d）up_splice=%d down_splice=%d：splice 不可用时全部走拷贝", s.upBytes, want, s.upSplice, s.downSplice)
			}
			if k := m.logLines("[WARN]", warn); k != 1 {
				t.Errorf("%q 的 warn 有 %d 行，期望恰好 1 行", warn, k)
			}
			if calls.Load() != 1 {
				t.Errorf("splice 被调用 %d 次，期望 1 次：第一次失败后应当整个进程改走拷贝", calls.Load())
			}
			noErrorCloses(t, m)
		})
	}
	t.Run("dynamic", func(t *testing.T) {
		t.Parallel()
		be := serveTCP(t, loopback4(t), streamHandler)
		listen := loopback4(t)
		m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t")
		pid := m.pid()
		var failing atomic.Bool
		var spliceIn, failed atomic.Int64
		nf.setDecide(func(call notifyCall) syscall.Errno {
			if call.nr != syscall.SYS_SPLICE || !isSocketFD(pid, call.fd(0)) {
				return 0
			}
			spliceIn.Add(1)
			if failing.Load() {
				failed.Add(1)
				return syscall.ENOSYS
			}
			return 0
		})
		if err := transfer(listen, 8<<20, 8<<20, 256<<10, 1); err != nil {
			t.Fatal(err)
		}
		s1 := m.statsAfterSignal(t).tcp[1]
		if s1.upSplice == 0 || s1.downSplice == 0 {
			t.Fatalf("splice 可用时没有 splice 字节：%+v", s1)
		}
		failing.Store(true)
		if err := transfer(listen, 8<<20, 8<<20, 256<<10, 2); err != nil {
			t.Fatalf("splice 失败之后：%v", err)
		}
		failing.Store(false)
		in2 := spliceIn.Load()
		if err := transfer(listen, 8<<20, 8<<20, 256<<10, 3); err != nil {
			t.Fatalf("splice 恢复可用之后：%v", err)
		}
		s3 := m.statsAfterSignal(t).tcp[1]
		t.Logf("第 1 次后 %+v；第 3 次后 %+v；读进 pipe 的 splice 共 %d 次，失败 %d 次", s1, s3, spliceIn.Load(), failed.Load())
		if failed.Load() != 1 {
			t.Errorf("读进 pipe 的 splice 失败了 %d 次，期望恰好 1 次", failed.Load())
		}
		if spliceIn.Load() != in2 || s3.upSplice != s1.upSplice || s3.downSplice != s1.downSplice {
			t.Errorf("splice 失败之后又有读进 pipe 的 splice（%d → %d 次）或 splice 字节增长（%d/%d → %d/%d）：应当整个进程改走拷贝",
				in2, spliceIn.Load(), s1.upSplice, s1.downSplice, s3.upSplice, s3.downSplice)
		}
		if k := m.logLines("[WARN]", warn); k != 1 {
			t.Errorf("%q 的 warn 有 %d 行，期望恰好 1 行", warn, k)
		}
		noErrorCloses(t, m)
	})
}

// fillFDHoles 向 listen（后端 be，空闲连接只连不发）建空闲连接，直到 tinymapper 在最高的已打开 fd 以下没有空闲 fd（每条连接占最小的两个
// 空闲 fd：accept 一个、上游 socket 一个），返回这时最高的 fd
func fillFDHoles(t testing.TB, pid int, listen string, be *tcpServer) int {
	t.Helper()
	for {
		ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			t.Fatal(err)
		}
		top := 0
		for _, e := range ents {
			fd, _ := strconv.Atoi(e.Name())
			top = max(top, fd)
		}
		if len(ents) == top+1 {
			return top
		}
		want := be.accepted.Load() + 1
		dial(t, listen)
		eventually(t, ioTimeout, 10*time.Millisecond, func() error {
			if n := be.accepted.Load(); n != want {
				return fmt.Errorf("后端接受了 %d 条连接，期望 %d", n, want)
			}
			return nil
		})
	}
}

// setNofile 把 pid 的 RLIMIT_NOFILE 软限设为 cur（保留硬限），返回一次性还原函数
func setNofile(t testing.TB, pid int, cur uint64) func() {
	t.Helper()
	var old syscall.Rlimit
	if err := prlimit(pid, rlimitNofile, nil, &old); err != nil {
		t.Fatalf("读取 RLIMIT_NOFILE 失败：%v", err)
	}
	if err := prlimit(pid, rlimitNofile, &syscall.Rlimit{Cur: cur, Max: old.Max}, nil); err != nil {
		t.Fatalf("设置 RLIMIT_NOFILE 失败：%v", err)
	}
	var once sync.Once
	return func() { once.Do(func() { prlimit(pid, rlimitNofile, &old, nil) }) }
}

// lowestFreeFDs 返回进程 pid 最小的两个空闲 fd 号（pipe2 拿到的就是它们）
func lowestFreeFDs(t testing.TB, pid int) (int, int) {
	t.Helper()
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	open := map[int]bool{}
	for _, e := range ents {
		fd, _ := strconv.Atoi(e.Name())
		open[fd] = true
	}
	var free []int
	for fd := 0; len(free) < 2; fd++ {
		if !open[fd] {
			free = append(free, fd)
		}
	}
	return free[0], free[1]
}

// D52(c)：新 pipe 的 fd 落在 RLIMIT_NOFILE 软限的最后 1/4（max(fd) ≥ 软限/4*3，每次创建时重读软限）就关掉、当作创建失败（回退拷贝、
// 到下一个周期之前不再创建，第一次记 info）。pipe2 拿到的是最小的两个空闲 fd f1<f2，用空闲连接把 f2 调到合适的余数，再用 prlimit 设软限：
//   - reject：f2 恰好等于门槛（软限 = f2/3*4）：回退，info 行里的 fd 与软限都精确，splice 字节为 0、pipes alloc 为 0；
//   - accept：f2 比门槛小 1（软限 = (f2+1)/3*4）：第一个 pipe 照常建成，有 splice 字节，日志里没有说 fd f2 的那一行。
//
// 两项的数据都按 SHA-256 完整；比较写成 > 或门槛减 1 时其中一项失败
func TestSpliceFdQuarter(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, c := range []struct {
		name   string
		reject bool
	}{{"reject", true}, {"accept", false}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), streamHandler)
			listen := loopback4(t)
			m := forward(t, "t", listen, be.addr)
			conns := []net.Conn{dial(t, listen)}
			want := 2 // f2 % 3：accept 时 f2+1 是门槛
			if c.reject {
				want = 0
			}
			var f1, f2 int
			for {
				eventually(t, ioTimeout, 10*time.Millisecond, func() error {
					if n := be.accepted.Load(); n != int64(len(conns)) {
						return fmt.Errorf("后端接受了 %d 条连接，期望 %d", n, len(conns))
					}
					return nil
				})
				if f1, f2 = lowestFreeFDs(t, m.pid()); f2%3 == want {
					break
				}
				conns = append(conns, dial(t, listen))
			}
			soft := uint64(f2 / 3 * 4) // (soft/4)*3 == f2
			if !c.reject {
				soft = uint64((f2 + 1) / 3 * 4) // (soft/4)*3 == f2+1
			}
			t.Logf("空闲 fd %d、%d，RLIMIT_NOFILE 软限 %d（门槛 %d）", f1, f2, soft, soft/4*3)
			restore := setNofile(t, m.pid(), soft)
			defer restore()
			if err := transferOn(conns[0], 4<<20, 4<<20, 256<<10, 1); err != nil {
				t.Fatal(err)
			}
			restore()
			d := m.statsAfterSignal(t)
			s := d.tcp[1]
			t.Logf("%+v；pool %+v", s, d.pool)
			line := fmt.Sprintf("[tcp]pipe fd %d is in the last quarter of RLIMIT_NOFILE (%d)", f2, soft)
			if !c.reject {
				if s.upSplice == 0 || s.downSplice == 0 || m.logLines(fmt.Sprintf("[tcp]pipe fd %d is in the last quarter", f2)) != 0 {
					t.Errorf("pipe 的 fd %d 低于门槛 %d，应当照常 splice：%+v", f2, soft/4*3, s)
				}
				return
			}
			if s.spliceFallback == 0 || s.upSplice != 0 || s.downSplice != 0 || d.pool.pipeAlloc != 0 {
				t.Errorf("pipe 的 fd %d 达到门槛 %d：期望回退拷贝（splice_fallback>0、splice 字节与 pipes alloc 为 0），实际 %+v，pipes alloc=%d",
					f2, soft/4*3, s, d.pool.pipeAlloc)
			}
			if k := m.logLines("[INFO]", line, pipeFailLog); k != 1 {
				t.Errorf("%q 的 info 行有 %d 行，期望 1 行\n%s", line, k, m.logTail(10))
			}
			if n := pipeFDs(t, m.pid()); n != 0 {
				t.Errorf("回退之后 tinymapper 有 %d 个 pipe fd", n)
			}
		})
	}
}

// D52(b)（第 4 版）：accept4、上游 socket() 或 UDP 会话 socket() 返回 EMFILE/ENFILE 时关掉池里空闲的 pipe 与 scratch pipe（tcp_pipe_trim），
// 记一行 debug "[tcp]out of file descriptors, closed N idle pipes"，关掉了就接着 accept / 再试一次 socket()，这个客户端照常转发；
// 方向持有的 pipe 里有数据，不动。两条规则：规则 1 的一条连接下行稳定持有 pipe；规则 2（TCP 为 streamHandler，UDP 为回显）上 4 条慢读下载
// 让池里留下空闲 pipe。用空闲连接填满最高 fd 以下的空洞（fillFDHoles），再把软限降到最高 fd + 1（一个空闲 fd 也没有；socket 项为 + 2，
// 只剩一个），然后：
//   - accept：新 TCP 客户端：accept4 失败（一行 accept failed 的 warn），关掉空闲 pipe 后同一轮接着 accept 成功；
//   - socket：新 TCP 客户端：accept4 拿到最后一个 fd，上游 socket() 失败，关掉空闲 pipe 后再试成功（没有 create new_remote_fd failed）；
//   - udp：新 UDP 客户端：会话 socket() 失败，关掉空闲 pipe 后再试成功，收到回包。
//
// 核对：debug 行里的 N 恰为之前的空闲数 + scratch 数且只有一行；统计里空闲与 scratch 归零、持有的那个还在，pipe fd 恰为 2×alloc；不还原软限，
// 这个客户端的传输完整；还原后持有的方向排空，数据完整、EOF 紧随
func TestSpliceTrimOnEMFILE(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	for _, where := range []string{"accept", "socket", "udp"} {
		t.Run(where, func(t *testing.T) {
			t.Parallel()
			streamBE := serveTCP(t, loopback4(t), streamHandler)
			serveUDP(t, streamBE.addr, "")
			listen2 := loopback4(t)
			rig := newSpliceRig(t, func(listen, remote string) *mapper {
				cfg := writeConfig(t, fmt.Sprintf("[[endpoints]]\nlisten = %q\nremote = %q\n\n[[endpoints]]\nlisten = %q\nremote = %q\nuse_udp = true\n",
					listen, remote, listen2, streamBE.addr))
				return startMapper(t, append(listenPoints("t", portOf(listen)), listenPoints("tu", portOf(listen2))...),
					append([]string{"-c", cfg, "--log-level", "5"}, holdSockBuf...)...)
			})
			m := rig.m
			p := rig.pair(t)
			gen, h := rand.NewChaCha8(streamSeed(21, where == "accept")), sha256.New()
			n := rig.fill(t, p, false, gen, h, 1)
			sum := h.Sum(nil)
			errs := make(chan error, 4)
			for i := range 4 {
				go func() { errs <- slowDownload(listen2, 512<<10, uint64(300+i)) }()
			}
			for range 4 {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
			before := m.waitTCPConns(t, 2, 0).pool
			t.Logf("耗尽 fd 之前 pool %+v", before)
			if before.pipeFree == 0 || before.pipeHeld != 1 {
				t.Fatalf("期望池里有空闲 pipe、且恰有 1 个方向持有 pipe：%+v", before)
			}
			var udpc *net.UDPConn
			if where == "udp" {
				udpc = udpDial(t, "", listen2) // 先建好客户端 socket（测试进程的 fd，不受 tinymapper 的软限影响）
			}
			// 软限要高于所有已打开的 fd（包括空闲 pipe 的），关掉的 pipe 腾出的 fd 才在软限以下、能给 socket 用
			top := fillFDHoles(t, m.pid(), listen2, streamBE)
			soft := uint64(top + 1)
			if where == "socket" {
				soft++
			}
			restore := setNofile(t, m.pid(), soft)
			defer restore()
			var trigger *net.TCPConn
			if where == "udp" {
				if got := udpReplyFrom(t, udpc, "after-trim"); got != "" {
					t.Fatalf("UDP 回包前缀 %q", got)
				}
			} else {
				trigger = dial(t, listen2)
			}
			var d statsDump
			eventually(t, ioTimeout, 20*time.Millisecond, func() error {
				if d = m.statsAfterSignal(t); d.pool.pipeFree != 0 || d.pool.pipeScratch != 0 {
					return fmt.Errorf("fd 耗尽后 pool %+v：空闲与 scratch pipe 应当被关掉", d.pool)
				}
				return nil
			})
			t.Logf("耗尽 fd 之后 pool %+v", d.pool)
			if d.pool.pipeHeld != 1 || d.pool.pipeAlloc != 1 {
				t.Errorf("持有数据的 pipe 不应被关掉：pool %+v", d.pool)
			}
			m.expectPipeFDs(t, d, "关掉空闲 pipe 之后")
			line := fmt.Sprintf("[tcp]out of file descriptors, closed %d idle pipes", before.pipeFree+before.pipeScratch)
			if k := m.logLines("[DEBUG]", line); k != 1 {
				t.Errorf("%q 的 debug 行有 %d 行，期望 1 行\n%s", line, k, m.logTail(10))
			}
			wantAcceptWarn := map[string]int{"accept": 1, "socket": 0, "udp": 0}[where]
			if k := m.logLines("[tcp]accept failed"); k != wantAcceptWarn {
				t.Errorf("accept failed 的 warn 有 %d 行，期望 %d 行", k, wantAcceptWarn)
			}
			if k := m.logLines("create new_remote_fd failed") + m.logLines("but create udp fd failed"); k != 0 {
				t.Errorf("关掉空闲 pipe 之后再试应当成功，却有 %d 行建 socket 失败", k)
			}
			if trigger != nil {
				if err := transferOn(trigger, 64<<10, 64<<10, 4096, 9); err != nil {
					t.Fatalf("关掉空闲 pipe 之后的连接：%v", err)
				}
			}
			restore()
			p.srv.CloseWrite()
			if err := readThenEOF(p.cli, n, sum); err != nil {
				t.Fatalf("持有 pipe 的方向排空：%v", err)
			}
			p.cli.Close()
			m.expectPipeFDs(t, m.waitTCPConns(t, 1, 0), "全部释放之后")
		})
	}
}

const (
	spliceMoreMin   = 64 << 10  // main.cpp 的 splice_more_min（D55）
	defaultPipeSize = 256 << 10 // --pipe-size 的默认值（D55）
)

// turnBudget 是 pipe 实际容量为 size 时一次回调读进 pipe 的上限 splice_turn_max（D55、D56）：不大于 256 KiB 时 256 KiB，
// 否则 (size ÷ 256 KiB) 个满 pipe
func turnBudget(size int) int {
	if size <= 256<<10 {
		return 256 << 10
	}
	return size / (256 << 10) * size
}

// expectTurn 按 D55 推出一次读回调里各次读进 pipe 的请求长度 ins 与各次写出（读到）的字节 outs：源端此刻可读 avail 字节，其后是读不到
// 数据的事件（EAGAIN、EOF、RST、紧急标记）；每次读到的写出都整段写完
func expectTurn(size, avail int) (ins, outs []int) {
	budget, moved, req := turnBudget(size), 0, size
	for {
		ins = append(ins, req)
		n := min(req, avail)
		if n == 0 {
			return
		}
		avail -= n
		moved += n
		outs = append(outs, n)
		if moved >= budget || n < spliceMoreMin {
			return
		}
		req = min(size, budget-moved)
	}
}

// tmFD 返回 tinymapper（pid）里 socket addr（本端、对端）的 fd
func tmFD(t testing.TB, pid int, addr [2]string) int {
	t.Helper()
	b, err := sockDiag(syscall.IPPROTO_TCP, addr[0], addr[1])
	if err != nil {
		t.Fatal(err)
	}
	fd := fdOfSocket(pid, b.inode)
	if fd < 0 {
		t.Fatalf("找不到 tinymapper socket %s → %s（inode %d）的 fd", addr[0], addr[1], b.inode)
	}
	return fd
}

// spliceCall 是一次读源端（in：读进 pipe）或写目的端（!in：从 pipe 写出）的 splice，n 为请求长度（args[4]）
type spliceCall struct {
	in bool
	n  int
}

// spliceTurns 按事件循环的轮次（两次 epoll 等待之间）依次记下一个方向的 splice。读分支每次读到数据都随即写出，写出的请求恰为刚读到的
// 字节数（my_info.data_len），所以读到多少看紧跟着的写出；没有写出的读返回了 ≤ 0。同一方向在一轮里只有一个回调：持有 pipe 时源端停读，
// 写分支排空后恢复读，要到下一轮 epoll 等待才报可读，所以以写出开头的一轮是写分支。
// 同一轮里紧挨着的两次相同调用是内核重启的同一次调用（splice_to_socket 开头见到待处理的信号——statsAfterSignal 的 SIGUSR1——返回
// -ERESTARTSYS，什么都没写，SA_RESTART 重新进入系统调用、再经过一次 seccomp），只记一次：读回调里两次读之间必有写出，两次写出之间必有读
type spliceTurns struct {
	mu       sync.Mutex
	iter     int64
	reads    int64 // 读进 pipe 的 splice 总次数
	restarts int64 // 去掉的重启
	seq      map[int64][]spliceCall
}

func newSpliceTurns() *spliceTurns { return &spliceTurns{seq: map[int64][]spliceCall{}} }

// record 在 notifier 的 decide 里调用：src、dst 为 tinymapper 源一侧、目的一侧 socket 的 fd
func (s *spliceTurns) record(call notifyCall, src, dst int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case isEpollWait(call.nr):
		s.iter++
	case call.nr == syscall.SYS_SPLICE && (call.fd(0) == src || call.fd(2) == dst):
		c := spliceCall{call.fd(0) == src, int(call.args[4])}
		if seq := s.seq[s.iter]; len(seq) > 0 && seq[len(seq)-1] == c {
			s.restarts++
			return
		}
		if c.in {
			s.reads++
		}
		s.seq[s.iter] = append(s.seq[s.iter], c)
	}
}

func (s *spliceTurns) now() (iter, reads int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.iter, s.reads
}

// readTurn 是一次读回调：ins 为各次读进 pipe 的请求长度，outs 为各次读到（随即写出）的字节，moved 为其和
type readTurn struct {
	iter      int64
	ins, outs []int
	moved     int
}

// check 逐个读回调核对 D55、D56（size 为 pipe 实际容量）：第一次读请求 size；接着读的前提是上一次读到 ≥ 64 KiB、累计 < 预算，请求恰为
// min(size, 预算−累计)；每次写出不多于刚请求的；累计不超过预算。返回 after 之后各轮的读回调（按轮次）与违规描述
func (s *spliceTurns) check(after int64, size int) (turns []readTurn, errs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	budget := turnBudget(size)
	for _, it := range slices.Sorted(maps.Keys(s.seq)) {
		seq := s.seq[it]
		if it <= after || len(seq) == 0 {
			continue
		}
		bad := func(format string, a ...any) {
			errs = append(errs, fmt.Sprintf("第 %d 轮 %v：", it, seq)+fmt.Sprintf(format, a...))
		}
		if !seq[0].in {
			if slices.ContainsFunc(seq, func(c spliceCall) bool { return c.in }) {
				bad("写分支之后同一轮又读")
			}
			continue
		}
		rt := readTurn{iter: it}
		for i := 0; i < len(seq); {
			c := seq[i]
			if !c.in {
				bad("第 %d 项写出没有紧跟在读之后", i+1)
				break
			}
			if k := len(rt.ins); k == 0 {
				if c.n != size {
					bad("第 1 次读请求 %d，期望 pipe 容量 %d", c.n, size)
				}
			} else {
				if prev := rt.outs[k-1]; prev < spliceMoreMin {
					bad("上一次读到 %d B（< 64 KiB）还接着读", prev)
				}
				if rt.moved >= budget {
					bad("已读 %d B（预算 %d）还接着读", rt.moved, budget)
				}
				if want := min(size, budget-rt.moved); c.n != want {
					bad("第 %d 次读请求 %d，期望 min(%d, %d−%d)=%d", k+1, c.n, size, budget, rt.moved, want)
				}
			}
			rt.ins = append(rt.ins, c.n)
			if i+1 < len(seq) && !seq[i+1].in {
				if n := seq[i+1].n; n <= 0 || n > c.n {
					bad("请求 %d 的读之后写出 %d", c.n, n)
				}
				rt.outs = append(rt.outs, seq[i+1].n)
				rt.moved += seq[i+1].n
				i += 2
				continue
			}
			if i+1 < len(seq) {
				bad("第 %d 项读没有写出（返回 ≤ 0）却又读", i+1)
			}
			break
		}
		if rt.moved > budget {
			bad("一次回调读了 %d B，超过预算 %d", rt.moved, budget)
		}
		turns = append(turns, rt)
	}
	return turns, errs
}

// D53、D55、D56：splice 时一次回调读进 pipe 的总量至多 splice_turn_max（pipe 实际容量 P 不大于 256 KiB 时 256 KiB，否则 (P ÷ 256 KiB) × P）。
// 每次回调的第一次 splice 读请求 P；之后上一次读够 64 KiB（splice_more_min）且整段写出、本回调还没搬满预算时接着读，请求 min(P, 预算−已读)。
// 后续读到 EOF 或 EAGAIN（含紧急数据）留给下一次回调按第一次处理；后续读出错必须当场关闭（splice 已经取走 sk_err，下一次只会读到 0，
// RST 会被当成正常的 EOF）。tinymapper 经 seccomp 通知启动，spliceTurns 按事件循环的轮次记下读客户端一侧与写往上游一侧的 splice，
// check 逐个读回调核对上面的规则（每个子项都对全程核对）。
//   - count（默认 256 KiB）、count-64（--pipe-size 64）、count-1024、count-growfail（默认，但 notifier 让新 pipe 的 F_SETPIPE_SZ 都返回 EPERM，
//     pipe 保持 64 KiB，D58）：客户端连续写 32 MiB、后端全速读。64 与 growfail：一次回调最多恰为 4 次读、256 KiB（64 KiB 的 pipe 也能搬满预算，
//     growfail 的请求依次是 256、192、128、64 KiB，内核按 pipe 剩余空间截到 64 KiB）；默认：一次回调最多恰好读满 256 KiB；1024 只核对规则
//     （一次回调读多少取决于接收队列积压了多少，不固定）；
//   - 其余子项先送 1 MiB（big 为 32 MiB，让两侧 socket 缓冲自动调大），再送单独的 32 KiB 块直到某一块恰好由一次 splice 读完（splice_next
//     必为 1），暂停 tinymapper，排好数据（再接一个事件），等它们都进了 tinymapper 客户端一侧的接收队列再恢复，恢复后第一次读回调的各次请求与
//     读到的字节必须恰为 expectTurn 推出的：
//   - more、more-64、more-300、more-1024：96 KiB，没有事件。第一次读到 96 KiB（64 时读满 64 KiB）、整段写出，不到预算就接着读，第二次请求
//     恰为 min(P, 预算−96 KiB)：默认 160 KiB（读满 pipe 才接着读的写法这里不读第二次）、300（实际 512 KiB，预算 1 MiB）512 KiB（不取内核
//     取整后的容量、预算按 256 KiB 算时都不是）、1024 为 1 MiB；64 时第二次读到 32 KiB（< 64 KiB）就停，没有第三次；
//   - big-1024：1 MiB + 96 KiB：读满 1 MiB 之后接着读到 96 KiB，再请求 1 MiB（EAGAIN），一次回调读的超过一个 pipe（D56：预算 4 MiB）；
//   - rst、eof、urgent、tail（--pipe-size 64：第一次读恰为 64 KiB 要 pipe 恰为 64 KiB）：64 KiB 再接一个事件，第一次读满 64 KiB、整段写出，
//     第二次（请求 64 KiB）遇到这个事件：
//   - rst：客户端 RST：第 2 次 splice 返回 ECONNRESET，连接对当场释放（一行 recv_len=-1 的 104 关闭），后端收齐 64 KiB 后读到 EOF；
//   - eof：客户端 FIN：第 2 次读到 0，留给下一次回调走 EOF 路径：只半关闭，后端收齐后读到 EOF，反方向照常；
//   - urgent：紧急字节 + 20 KiB：第 2 次 EAGAIN，下一次回调的 splice 也 EAGAIN、改走 recv：后端恰好收到 64 KiB + 20 KiB，不空转；
//   - tail：64 KiB 后再接 10 KiB：第 2 次只读到 10 KiB（< 16 KiB），之后的 64 B 必须走 recv（后续读也要按本次字节数更新 splice_next）。
//
// 各子项的上行字节与 splice 字节都精确核对（count：up_bytes 恰为写出的字节；其余：暂停之后 splice 恰为排好的数据，tail 为 74 KiB）
func TestSpliceRounds(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	for _, c := range []struct {
		name string
		kib  int // --pipe-size，0 为不给（默认）
		size int // pipe 实际容量
	}{
		{"count", 0, defaultPipeSize},
		{"count-64", 64, 64 << 10},
		{"count-1024", 1024, 1 << 20},
		{"count-growfail", 0, defaultPipeSize},
		{"more", 0, defaultPipeSize},
		{"more-64", 64, 64 << 10},
		{"more-300", 300, 512 << 10},
		{"more-1024", 1024, 1 << 20},
		{"big-1024", 1024, 1 << 20},
		{"rst", 64, 64 << 10},
		{"eof", 64, 64 << 10},
		{"urgent", 64, 64 << 10},
		{"tail", 64, 64 << 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			kind, _, _ := strings.Cut(c.name, "-")
			args := []string{"-t"}
			if c.kib != 0 {
				args = append(args, "--pipe-size", strconv.Itoa(c.kib))
			}
			var nf *notifier
			rig := newSpliceRig(t, func(listen, remote string) *mapper {
				m, n := startMapperNotify(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", remote}, args...)...)
				nf = n
				return m
			})
			m := rig.m
			p := rig.pair(t)
			src, dst := tmFD(t, m.pid(), p.tmCli), tmFD(t, m.pid(), p.tmUp)
			turns := newSpliceTurns()
			growFail := c.name == "count-growfail"
			m.growFailOK = growFail
			nf.setDecide(func(call notifyCall) syscall.Errno {
				if growFail && isSetPipeSz(call) {
					return syscall.EPERM
				}
				turns.record(call, src, dst)
				return 0
			})
			// 全程的读回调都要符合规则
			checkAll := func() []readTurn {
				t.Helper()
				all, errs := turns.check(0, c.size)
				for i, e := range errs {
					if i == 5 {
						t.Errorf("……共 %d 处违规", len(errs))
						break
					}
					t.Error(e)
				}
				return all
			}
			var got bytes.Buffer
			recvDone := make(chan error, 1)
			go func() {
				_, err := io.Copy(&got, p.srv)
				recvDone <- err
			}()
			gen := rand.NewChaCha8(streamSeed(23, true))
			chunk := func(n int) []byte {
				b := make([]byte, n)
				gen.Read(b)
				return b
			}
			var sent []byte
			send := func(b []byte) {
				t.Helper()
				p.cli.SetWriteDeadline(time.Now().Add(ioTimeout))
				if _, err := p.cli.Write(b); err != nil {
					t.Fatal(err)
				}
				sent = append(sent, b...)
			}
			// 等 tinymapper 向上游写出 n 字节（got 由接收协程写，这里不读它）
			waitGot := func(n int) {
				t.Helper()
				eventually(t, transferTimeout(int64(n)), 5*time.Millisecond, func() error {
					if s := m.statsAfterSignal(t).tcp[1]; s.upBytes < uint64(n) {
						return fmt.Errorf("上行转发了 %d 字节，期望 %d", s.upBytes, n)
					}
					return nil
				})
			}
			if kind == "count" {
				for range 32 {
					send(chunk(1 << 20))
				}
				waitGot(len(sent))
				if s := m.statsAfterSignal(t).tcp[1]; s.upBytes != uint64(len(sent)) || s.downBytes != 0 || s.upSplice == 0 {
					t.Errorf("up_bytes=%d down_bytes=%d up_splice=%d，期望 %d/0/>0", s.upBytes, s.downBytes, s.upSplice, len(sent))
				}
				var maxReads, maxMoved int
				hist := map[int]int{}
				for _, rt := range checkAll() {
					maxReads, maxMoved = max(maxReads, len(rt.ins)), max(maxMoved, rt.moved)
					hist[len(rt.ins)]++
				}
				t.Logf("每次读回调的读次数分布：%v；一次回调最多读 %d 次、%d B（预算 %d）", hist, maxReads, maxMoved, turnBudget(c.size))
				switch {
				case (c.size == 64<<10 || growFail) && (maxReads != 4 || maxMoved != 256<<10):
					t.Errorf("64 KiB pipe：一次回调最多读 %d 次、%d B，期望恰为 4 次、256 KiB（D53 的 4 × 64 KiB）", maxReads, maxMoved)
				case c.size == defaultPipeSize && maxMoved != defaultPipeSize:
					t.Errorf("默认 256 KiB pipe：一次回调最多读 %d B，期望恰好读满 256 KiB", maxMoved)
				}
				if d := m.statsAfterSignal(t); growFail && (d.pool.resizeFail == 0 || capHist(pipeCapacities(t, m.pid()))[64<<10] != d.pool.pipeAlloc) {
					t.Errorf("growfail：resize_fail=%d，pipe 容量分布 %v，期望扩容都失败、pipe 都是 64 KiB", d.pool.resizeFail, capHist(pipeCapacities(t, m.pid())))
				}
				p.cli.CloseWrite()
				p.srv.CloseWrite()
				if err := <-recvDone; err != nil || !bytes.Equal(got.Bytes(), sent) {
					t.Fatalf("后端收到 %d/%d 字节（%v），内容一致：%v", got.Len(), len(sent), err, bytes.Equal(got.Bytes(), sent))
				}
				return
			}
			// 让最后一次读恰为一次读完 32 KiB 的 splice（读进 pipe 的 splice 只多 1 次、up_splice 恰好多 32 KiB），之后 splice_next 必为 1：
			// 前一次读若被拆成两半（< 16 KiB），这一块会走 recv，再试一块
			warm := 1
			if kind == "big" {
				warm = 32
			}
			for range warm {
				send(chunk(1 << 20))
			}
			waitGot(len(sent))
			for try := 1; ; try++ {
				_, r0 := turns.now()
				s0 := m.statsAfterSignal(t).tcp[1].upSplice
				send(chunk(32 << 10))
				waitGot(len(sent))
				if _, r1 := turns.now(); r1-r0 == 1 && m.statsAfterSignal(t).tcp[1].upSplice-s0 == 32<<10 {
					break
				}
				if try == 10 {
					t.Fatal("10 块 32 KiB 都没有恰好一次 splice 读完")
				}
			}
			pre, sentBefore := m.statsAfterSignal(t).tcp[1], len(sent)
			avail := 64 << 10 // 事件之前可读的字节
			switch kind {
			case "more":
				avail = 96 << 10
			case "big":
				avail = 1<<20 + 96<<10
			}
			b, err := sockDiag(syscall.IPPROTO_TCP, p.tmCli[0], p.tmCli[1])
			if err != nil {
				t.Fatal(err)
			}
			m.pause(t)
			send(chunk(avail))
			queued := avail
			switch kind {
			case "rst":
				waitTMQueue(t, p.tmCli, queued)
				p.cli.SetLinger(0)
				p.cli.Close()
				// RST 处理后 socket 从已建立连接的哈希表摘除：按四元组查不到它（inet_lookup 会退到同一端口的监听 socket，所以比 inode）
				eventually(t, ioTimeout, 5*time.Millisecond, func() error {
					if q, err := sockDiag(syscall.IPPROTO_TCP, p.tmCli[0], p.tmCli[1]); err == nil && q.inode == b.inode {
						return errors.New("tinymapper 客户端一侧 socket 还没处理 RST")
					}
					return nil
				})
			case "eof":
				p.cli.CloseWrite()
				queued++ // FIN 占一个序号
			case "urgent":
				if err := sendOOB(p.cli, 'U'); err != nil {
					t.Fatal(err)
				}
				tail := chunk(20 << 10)
				send(tail)
				queued += 1 + len(tail)
			case "tail":
				send(chunk(10 << 10))
				queued += 10 << 10
				avail += 10 << 10
			}
			if kind != "rst" {
				waitTMQueue(t, p.tmCli, queued)
			}
			resumeIter, _ := turns.now()
			m.resume(t)
			switch kind {
			case "rst":
				d := m.waitTCPConns(t, 1, 0)
				if err := <-recvDone; err != nil || !bytes.Equal(got.Bytes(), sent) {
					t.Fatalf("后端收到 %d/%d 字节（%v）：RST 之前的 64 KiB 应当全部送达、随后 EOF", got.Len(), len(sent), err)
				}
				if k := m.logLines("recv_len=-1,connection", "closed bc of 104:"); k != 1 {
					t.Errorf("日志里有 %d 行 ECONNRESET 的关闭，期望 1 行（第 2 次读出错要当场关闭）", k)
				}
				m.expectPipeFDs(t, d, "RST 释放之后")
			case "eof":
				eventually(t, ioTimeout, 10*time.Millisecond, func() error {
					if s := m.statsAfterSignal(t).tcp[1]; s.halfClosed != 1 || s.conns != 1 {
						return fmt.Errorf("half_closed=%d conns=%d，期望 1/1（只半关闭）", s.halfClosed, s.conns)
					}
					return nil
				})
				if err := <-recvDone; err != nil || !bytes.Equal(got.Bytes(), sent) {
					t.Fatalf("后端收到 %d/%d 字节（%v）后应读到 EOF", got.Len(), len(sent), err)
				}
				if _, err := p.srv.Write([]byte("bye")); err != nil {
					t.Fatal(err)
				}
				p.srv.CloseWrite()
				p.cli.SetReadDeadline(time.Now().Add(ioTimeout))
				if b, err := io.ReadAll(p.cli); err != nil || string(b) != "bye" {
					t.Fatalf("反方向收到 %q（%v），期望 \"bye\" 与 EOF", b, err)
				}
				m.waitTCPConns(t, 1, 0)
			default:
				waitGot(len(sent))
				if kind == "urgent" {
					m.expectIdleCPU(t, "第 2 次读在紧急标记处 EAGAIN 之后")
				}
				before := m.statsAfterSignal(t).tcp[1]
				if kind == "tail" {
					send(chunk(64))
					waitGot(len(sent))
					if after := m.statsAfterSignal(t).tcp[1]; after.upSplice != before.upSplice {
						t.Errorf("第 2 次只读到 10 KiB 之后，64 B 应当走 recv：up_splice %d → %d", before.upSplice, after.upSplice)
					}
				}
				p.cli.CloseWrite()
				p.srv.CloseWrite()
				if err := <-recvDone; err != nil || !bytes.Equal(got.Bytes(), sent) {
					t.Fatalf("后端收到 %d/%d 字节（%v），内容一致：%v", got.Len(), len(sent), err, bytes.Equal(got.Bytes(), sent))
				}
			}
			// 计数精确：暂停之后的上行字节全部计入，经 splice 的恰是事件之前可读的（tail 含第 2 次的 10 KiB），其余（紧急字节之后的 20 KiB、
			// tail 之后的 64 B）走 recv
			post := m.statsAfterSignal(t).tcp[1]
			if db, ds := post.upBytes-pre.upBytes, post.upSplice-pre.upSplice; db != uint64(len(sent)-sentBefore) || ds != uint64(avail) {
				t.Errorf("暂停之后上行计数增加 %d 字节、splice %d 字节，期望 %d / %d", db, ds, len(sent)-sentBefore, avail)
			}
			checkAll()
			after, _ := turns.check(resumeIter, c.size)
			if len(after) == 0 {
				t.Fatal("恢复之后没有读进 pipe 的 splice")
			}
			wantIns, wantOuts := expectTurn(c.size, avail)
			first := after[0]
			turns.mu.Lock()
			restarts := turns.restarts
			turns.mu.Unlock()
			t.Logf("恢复后第一次读回调：请求 %v，读到 %v（期望 %v、%v）；去掉了 %d 次重启的 splice", first.ins, first.outs, wantIns, wantOuts, restarts)
			if !slices.Equal(first.ins, wantIns) || !slices.Equal(first.outs, wantOuts) {
				t.Errorf("恢复后第一次读回调：各次读请求 %v、读到 %v，期望 %v、%v", first.ins, first.outs, wantIns, wantOuts)
			}
		})
	}
}

// waitTMQueue 等到 tinymapper 的 socket（addr 为本端、对端）接收队列（rcv_nxt−copied_seq，FIN 与紧急字节各占一个序号）恰为 n
func waitTMQueue(t testing.TB, addr [2]string, n int) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		q, err := sockDiag(syscall.IPPROTO_TCP, addr[0], addr[1])
		if err != nil {
			return err
		}
		if int(q.rqueue) != n {
			return fmt.Errorf("tinymapper %s → %s 接收队列 %d，期望 %d", addr[0], addr[1], q.rqueue, n)
		}
		return nil
	})
}

// D54（第 6 版，main.cpp md5 7c882ca9）：主机越过 tcp_mem 压力线（或 memcg 记账失败）时内核把目的 socket 的 sndbuf 缩到当时队列的一半，
// 回环上 MSS 几十 KiB 时只剩 1 段在途、接收方延迟 ACK。splice 写不完时（读分支把 scratch pipe 交给方向时对目的一侧；写分支从持有的 pipe
// 写出一部分之后对本侧）tcp_unshrink_sndbuf：没有 --sock-buf；这一侧第一次时读一次 TCP_MAXSEG 缓存在 tcp_info_t::mss；2×MSS ≤ 4608
// （SOCK_MIN_SNDBUF，网卡路径永远有 3 段以上）就不动；否则 SO_SNDBUF < 2×MSS 时 setsockopt(SO_SNDBUF, 2×MSS)（内核再翻倍、锁定），记 debug
// "[tcp]fd=N sndbuf shrunk to SB (mss MSS), set SO_SNDBUF to V"。
//
// 不能动 VM 全局的 net.ipv4.tcp_mem，容器里也建不了子 cgroup（cgroupfs 只读），所以正向用例用 seccomp 通知假造 tinymapper 对上游 socket
// 的 getsockopt(SO_SNDBUF)：不执行这次调用，经 /proc/<pid>/mem 把一个小值写进它的 optval（内核里真实的 sndbuf 不变），之后的 setsockopt
// 照常执行，锁定的结果用 sock_diag 读真实的 sk_sndbuf。notifier 按调用顺序分辨调用点：同一轮事件循环里先有读客户端一侧的 splice 的是
// 读分支（a），否则是写分支（b）。每项都是上行（客户端写 8 MiB、后端先不读）持有 pipe，目的一侧即 tinymapper 的上游 socket：
//   - read-branch：回环 MSS；从一开始假造读分支的 getsockopt 为 34816：持有建立时（后端还没读，写分支不可能写出一部分）上游 sndbuf 已锁在
//     2×V（V = 2×MSS），debug 行与 sock_diag 一致；排空之后仍是这个值（锁定后不再自动调大）；
//   - write-branch：后端监听设 TCP_MAXSEG 2400（上游 MSS 约 2388 > 2304）。写分支只在从 pipe 写出一部分之后才调用，sndbuf ≥ 192 KB 时
//     EPOLLOUT 腾出的空间（≥ 1/3）总装得下 pipe 里至多 64 KiB 的数据（B3 起默认 256 KiB 的 pipe 不一定装得下，下面的做法不受影响），
//     所以先像 read-branch 一样假造读分支、把真实 sndbuf 锁到 2×V（约 9.5 KB），
//     再改为只假造写分支：后端慢读，写分支一再只写出一部分，每次都要再查、再记一行 debug（读分支看到真实的 9.5 KB ≥ 2×MSS，不再记），
//     改假造之后 debug 行必须增加；
//   - mss-gate：后端 TCP_MAXSEG 1400（上游 MSS 约 1388，2×MSS ≤ 4608），两个调用点的 getsockopt(SO_SNDBUF) 都假造为 2000：仍然不锁，
//     整个传输都没有 debug 行，sndbuf 不是锁定值；
//   - sock-buf：--sock-buf 32（sndbuf 锁在 65536，< 2×回环 MSS）：不动，始终 65536，没有 debug 行。
//
// 各项都核对上游一侧的 getsockopt(TCP_MAXSEG) 至多一次（每方向缓存 MSS），数据都按 SHA-256 完整。没有 --sock-buf 守卫、不看 MSS、
// 只在一个调用点调用、值或比较写错、不缓存 MSS 时，至少一项失败
func TestSpliceUnshrinkSndbuf(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	withMSS := func(mss int) net.ListenConfig {
		return net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss) }); err != nil {
				return err
			}
			return serr
		}}
	}
	lineRe := regexp.MustCompile(`\[tcp\]fd=(\d+) sndbuf shrunk to (\d+) \(mss (\d+)\), set SO_SNDBUF to (\d+)`)
	for _, c := range []struct {
		name   string
		lc     net.ListenConfig
		extra  []string
		fake   string // 假造哪些调用点的 getsockopt(SO_SNDBUF)："a" 读分支、"b" 写分支，"" 不假造
		fakeSB int
		locks  bool
	}{
		{"read-branch", net.ListenConfig{}, nil, "a", 34816, true},
		{"write-branch", withMSS(2400), nil, "a", 2000, true}, // 持有建立后改为只假造写分支（"b"）
		{"mss-gate", withMSS(1400), nil, "ab", 2000, false},
		{"sock-buf", net.ListenConfig{}, []string{"--sock-buf", "32"}, "", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var nf *notifier
			rig := newSpliceRigConfig(t, c.lc, func(listen, remote string) *mapper {
				m, n := startMapperNotify(t, listenPoints("t", portOf(listen)),
					append([]string{"-l", listen, "-r", remote, "-t", "--log-level", "5"}, c.extra...)...)
				nf = n
				return m
			})
			m := rig.m
			p := rig.pair(t)
			fdOf := func(addr [2]string) int {
				t.Helper()
				b, err := sockDiag(syscall.IPPROTO_TCP, addr[0], addr[1])
				if err != nil {
					t.Fatal(err)
				}
				fd := fdOfSocket(m.pid(), b.inode)
				if fd < 0 {
					t.Fatalf("找不到 tinymapper socket %s → %s（inode %d）的 fd", addr[0], addr[1], b.inode)
				}
				return fd
			}
			src, target := fdOf(p.tmCli), fdOf(p.tmUp)
			var fakeOn, lastIn atomic.Bool
			var faked, mssQueries atomic.Int64
			var fakeSites atomic.Pointer[string]
			fakeSites.Store(&c.fake)
			nf.setDecide(func(call notifyCall) syscall.Errno {
				switch {
				case isEpollWait(call.nr):
					lastIn.Store(false)
				case call.nr == syscall.SYS_SPLICE && call.fd(0) == src:
					lastIn.Store(true)
				case call.nr == syscall.SYS_GETSOCKOPT && call.fd(0) == target && call.args[1] == syscall.IPPROTO_TCP &&
					call.args[2] == syscall.TCP_MAXSEG:
					mssQueries.Add(1)
				}
				return 0
			})
			nf.setEmulate(func(call notifyCall) (int64, bool) {
				if call.nr != syscall.SYS_GETSOCKOPT || call.fd(0) != target || call.args[1] != syscall.SOL_SOCKET ||
					call.args[2] != syscall.SO_SNDBUF || !fakeOn.Load() {
					return 0, false
				}
				if site := map[bool]string{true: "a", false: "b"}[lastIn.Load()]; !strings.Contains(*fakeSites.Load(), site) {
					return 0, false
				}
				var b [4]byte
				binary.NativeEndian.PutUint32(b[:], uint32(c.fakeSB))
				if writeTargetMem(call.pid, call.args[3], b[:]) != nil {
					return 0, false
				}
				binary.NativeEndian.PutUint32(b[:], 4)
				if writeTargetMem(call.pid, call.args[4], b[:]) != nil {
					return 0, false
				}
				faked.Add(1)
				return 0, true
			})
			fakeOn.Store(strings.Contains(c.fake, "a"))
			sndbuf := func() int {
				t.Helper()
				return int(lookupSockBuf(t, m.pid(), syscall.IPPROTO_TCP, "上游 socket", p.tmUp[0], p.tmUp[1]).snd)
			}
			// lines 返回 debug 行（统计之后 fflush，之前的行都已写出）
			lines := func() [][]string {
				t.Helper()
				m.statsAfterSignal(t)
				data, _ := os.ReadFile(m.logPath)
				return lineRe.FindAllStringSubmatch(string(data), -1)
			}
			const total = 8 << 20
			wsum := make(chan []byte, 1)
			go func() {
				h := sha256.New()
				gen := rand.NewChaCha8(streamSeed(25, true))
				buf := make([]byte, 64<<10)
				p.cli.SetWriteDeadline(time.Now().Add(60 * time.Second))
				for n := 0; n < total; n += len(buf) {
					gen.Read(buf)
					h.Write(buf)
					if _, err := p.cli.Write(buf); err != nil {
						wsum <- nil
						return
					}
				}
				p.cli.CloseWrite()
				wsum <- h.Sum(nil)
			}()
			eventually(t, 2*ioTimeout, 20*time.Millisecond, func() error {
				if d := m.statsAfterSignal(t); d.pool.pipeHeld != 1 || d.pool.held != 0 {
					return fmt.Errorf("持有 pipe %d 个、块 %d 个，期望上行持有 pipe", d.pool.pipeHeld, d.pool.held)
				}
				return nil
			})
			atHold, ls := sndbuf(), lines()
			t.Logf("持有建立时上游 sndbuf %d，debug 行 %d 行，假造 %d 次", atHold, len(ls), faked.Load())
			if c.fake == "a" && len(ls) == 0 {
				t.Errorf("持有建立时（后端还没读）读分支的 getsockopt 已假造 %d 次，却没有 debug 行：读分支应当锁定 sndbuf", faked.Load())
			}
			atSwitch := len(ls)
			if c.name == "write-branch" {
				onlyB := "b"
				fakeSites.Store(&onlyB)
			}
			// 后端读：write-branch 每 48 KiB 停 10 ms，让写分支一再只写出一部分；其余全速
			gotSum := make(chan []byte, 1)
			recv := make(chan error, 1)
			go func() {
				h := sha256.New()
				buf := make([]byte, 48<<10)
				var got int64
				p.srv.SetReadDeadline(time.Now().Add(60 * time.Second))
				for {
					n, err := p.srv.Read(buf)
					h.Write(buf[:n])
					got += int64(n)
					if err == io.EOF {
						break
					}
					if err != nil {
						recv <- fmt.Errorf("后端读到 %d 字节：%w", got, err)
						return
					}
					if c.name == "write-branch" && got%(48<<10) < int64(n) {
						time.Sleep(10 * time.Millisecond)
					}
				}
				if got != total {
					recv <- fmt.Errorf("后端收到 %d 字节，期望 %d", got, total)
					return
				}
				gotSum <- h.Sum(nil)
				recv <- nil
			}()
			if err := <-recv; err != nil {
				t.Fatal(err)
			}
			if want := <-wsum; want == nil || !bytes.Equal(<-gotSum, want) {
				t.Fatal("上行 SHA-256 不一致（或写入失败）")
			}
			after, ls := sndbuf(), lines()
			t.Logf("排空后上游 sndbuf %d，debug 行 %d 行，假造 %d 次，TCP_MAXSEG 查询 %d 次", after, len(ls), faked.Load(), mssQueries.Load())
			if q := mssQueries.Load(); q > 1 {
				t.Errorf("上游一侧的 getsockopt(TCP_MAXSEG) 调用了 %d 次，期望至多 1 次（每方向缓存 MSS）", q)
			}
			if !c.locks {
				if len(ls) != 0 {
					t.Errorf("%s：不应锁 sndbuf，却有 debug 行 %q", c.name, ls[0][0])
				}
				if c.name == "sock-buf" && (atHold != 65536 || after != 65536) {
					t.Errorf("--sock-buf 32 的上游 sndbuf 持有时 %d、排空后 %d，期望始终 65536", atHold, after)
				}
				if c.name == "mss-gate" && (after <= 4*1400 || atHold <= 4*1400) {
					t.Errorf("小 MSS 的上游 sndbuf 持有时 %d、排空后 %d：不应被锁到 4×MSS", atHold, after)
				}
				return
			}
			if len(ls) == 0 {
				t.Fatalf("假造 %d 次之后仍没有 debug 行", faked.Load())
			}
			l := ls[0]
			fd, _ := strconv.Atoi(l[1])
			sb, _ := strconv.Atoi(l[2])
			mss, _ := strconv.Atoi(l[3])
			val, _ := strconv.Atoi(l[4])
			if fd != target || sb != c.fakeSB || val != 2*mss || 2*mss <= 4608 {
				t.Errorf("debug 行 %q：期望 fd=%d、sndbuf %d、SO_SNDBUF 设为 2×MSS（MSS > 2304）", l[0], target, c.fakeSB)
			}
			if atHold != 2*val {
				t.Errorf("持有建立时上游 sndbuf %d，期望已锁在 %d", atHold, 2*val)
			}
			if c.name == "write-branch" && len(ls) <= atSwitch {
				t.Errorf("改为只假造写分支之后 debug 行没有增加（%d → %d 行）：写分支写出一部分之后应当再查 sndbuf", atSwitch, len(ls))
			}
			if after != 2*val {
				t.Errorf("排空后上游 sndbuf %d，期望仍锁在 %d", after, 2*val)
			}
		})
	}
}

// ---- B3：pipe 大小（D55–D58）----

// pipeCapacities 返回 tinymapper（pid）打开的每个 pipe 的容量，键为 /proc/<pid>/fd 的链接 pipe:[inode]（一个 pipe 的两端只算一次）：
// 经 /proc/<pid>/fd/N 另开同一个 pipe（O_RDONLY|O_NONBLOCK，新的打开文件描述，不读不写，不影响 tinymapper 的 fd），F_GETPIPE_SZ
func pipeCapacities(t testing.TB, pid int) map[string]int {
	t.Helper()
	fds, err := pipeFDList(pid)
	if err != nil {
		t.Fatal(err)
	}
	caps := map[string]int{}
	for _, fd := range fds {
		path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
		link, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := caps[link]; ok {
			continue
		}
		f, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("打开 %s（%s）失败：%v", path, link, err)
		}
		size, err := pipeSize(f)
		syscall.Close(f)
		if err != nil {
			t.Fatalf("%s 的 F_GETPIPE_SZ 失败：%v", link, err)
		}
		caps[link] = size
	}
	return caps
}

// capHist 把 pipeCapacities 的结果按容量计数
func capHist(caps map[string]int) map[int]int {
	h := map[int]int{}
	for _, c := range caps {
		h[c]++
	}
	return h
}

// need4KPages：用例里的容量都按 4 KiB 页推算（默认 pipe 16 页 = 64 KiB）；16K/64K 页内核默认 pipe 已是 256 KiB/1 MiB，--pipe-size 不再扩容
func need4KPages(t testing.TB) {
	t.Helper()
	if os.Getpagesize() != 4096 {
		t.Skipf("页大小 %d B：用例按 4 KiB 页推算 pipe 容量", os.Getpagesize())
	}
}

// pipePoolCap 是 pipe 实际容量为 size 时池里最多留的空闲 pipe 数（B3 审查 M1，main.cpp 的 tcp_pipe_pool_t::max_free）：
// 合计不超过 64 个 16 页 pipe 的 1024 页，fs.pipe-user-pages-soft 按容量计页，池里的空 pipe 也算
func pipePoolCap(size int) int { return pipePoolMaxFree * 16 / max(16, size/os.Getpagesize()) }

// pipeSizeFatal 是 --pipe-size 的值越界或不是数字时的 fatal 行
const pipeSizeFatal = "pipe-size value must be between 64 and 1024 (kbyte)"

// --pipe-size（D57）：帮助文本里有；只接受 64–1024（KiB），越界、不是数字、空串都以 fatal 退出；没给值时由 getopt_long 报错；
// 只有命令行，没有 TOML 键。64、1024 两个边界值能启动并生效，见 TestSplicePipeSize
func TestSplicePipeSizeOption(t *testing.T) {
	t.Parallel()
	t.Run("help", func(t *testing.T) {
		t.Parallel()
		out, err := exec.Command(mapperBin, "-h").Output()
		if err != nil {
			t.Fatalf("-h 退出状态异常：%v", err)
		}
		if !strings.Contains(string(out), "--pipe-size") {
			t.Errorf("帮助文本里没有 --pipe-size：\n%s", out)
		}
	})
	for _, c := range []struct{ name, value, want string }{
		{"63", "63", pipeSizeFatal},
		{"1025", "1025", pipeSizeFatal},
		{"0", "0", pipeSizeFatal},
		{"negative", "-64", pipeSizeFatal},
		{"junk", "abc", pipeSizeFatal},
		{"empty", "", pipeSizeFatal},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "--pipe-size", c.value)
			if !strings.Contains(out, c.want) {
				t.Errorf("--pipe-size %q 的输出里没有 %q：\n%s", c.value, c.want, out)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		if out := runExpectFail(t, 5*time.Second, "-l", loopback4(t), "-r", loopback4(t), "-t", "--pipe-size"); !strings.Contains(out, "requires an argument") {
			t.Errorf("--pipe-size 没给值的报错不符：\n%s", out)
		}
	})
	t.Run("toml-key", func(t *testing.T) {
		t.Parallel()
		cfg := writeConfig(t, fmt.Sprintf("[network]\npipe_size = 256\n\n[[endpoints]]\nlisten = %q\nremote = %q\n", loopback4(t), loopback4(t)))
		if out := runExpectFail(t, 5*time.Second, "-c", cfg); !strings.Contains(out, "unknown key in [network]") {
			t.Errorf("[network] pipe_size 的报错不符：\n%s", out)
		}
	})
}

// pipeSizeWatch 在 notifier 里记下每次 fcntl(F_SETPIPE_SZ) 的请求与每次读进 pipe 的 splice 的请求长度
type pipeSizeWatch struct {
	mu      sync.Mutex
	setsz   []int // 依次的 F_SETPIPE_SZ 请求；第一个是启动探测（--disable-splice 时没有探测）
	reads   int
	maxRead int
}

func (w *pipeSizeWatch) record(call notifyCall) {
	switch {
	case isSetPipeSz(call):
		w.mu.Lock()
		w.setsz = append(w.setsz, int(call.args[2]))
		w.mu.Unlock()
	case call.nr == syscall.SYS_SPLICE && isSocketFD(call.pid, call.fd(0)):
		w.mu.Lock()
		w.reads++
		w.maxRead = max(w.maxRead, int(call.args[4]))
		w.mu.Unlock()
	}
}

// checkPipes 在一次双向 8 MiB 传输、连接释放之后核对：新建的 pipe（pipes alloc 个，传输期间没有 close）实际容量都是 size；它们各有一次
// F_SETPIPE_SZ、请求都是 size（size 不超过内核默认 64 KiB 时一次都没有）；读进 pipe 的 splice 请求最大恰为 size。probe 为 setsz 里探测
// 那一项的个数（0 或 1）
func (w *pipeSizeWatch) checkPipes(t testing.TB, m *mapper, probe, size int) {
	t.Helper()
	d := m.waitTCPConns(t, 1, 0)
	s := d.tcp[1]
	if s.upSplice == 0 || s.downSplice == 0 || d.pool.pipeAlloc == 0 {
		t.Errorf("双向 8 MiB 之后 up_splice=%d down_splice=%d pipes alloc=%d，期望都非零", s.upSplice, s.downSplice, d.pool.pipeAlloc)
	}
	caps := pipeCapacities(t, m.pid())
	if h := capHist(caps); len(caps) != d.pool.pipeAlloc || h[size] != len(caps) {
		t.Errorf("tinymapper 的 pipe 容量分布 %v（共 %d 个，pipes alloc=%d），期望都是 %d", h, len(caps), d.pool.pipeAlloc, size)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	grows := w.setsz[probe:]
	wantGrows := d.pool.pipeAlloc
	if size <= 64<<10 {
		wantGrows = 0
	}
	if len(grows) != wantGrows || slices.ContainsFunc(grows, func(v int) bool { return v != size }) {
		t.Errorf("新建 %d 个 pipe 时的 F_SETPIPE_SZ 请求 %v，期望 %d 次、每次 %d", d.pool.pipeAlloc, grows, wantGrows, size)
	}
	if w.maxRead != size {
		t.Errorf("%d 次读进 pipe 的 splice 请求最大 %d，期望恰为 pipe 容量 %d", w.reads, w.maxRead, size)
	}
}

// D55、D57：新 pipe 用 F_SETPIPE_SZ 扩到 --pipe-size（默认 256 KiB），内核向上取到 2 的幂页数，以返回的实际容量为准；只扩不缩。启动时用
// 一个探测 pipe 试设一次（随即关掉），之后每个新 pipe 都请求探测得到的实际容量，每次回调的第一次 splice 读也请求它。各项经 seccomp 通知
// 启动（从 exec 起记下每次 F_SETPIPE_SZ 的请求与每次读进 pipe 的 splice 的请求长度），就绪时没有 pipe fd（探测 pipe 已关），双向各 8 MiB：
//   - default：探测请求 262144，新 pipe 都请求 262144、实际 256 KiB；
//   - 300：先在用户态按内核的规则取到 2 的幂页数（审查 L2），探测请求 524288；新 pipe 请求 524288、实际 512 KiB，读请求 524288
//     （不是 300 KiB）；
//   - 1024：1 MiB；
//   - 64：内核默认已是 64 KiB，探测与新 pipe 都不调 F_SETPIPE_SZ（只扩不缩），实际 64 KiB；
//   - disable（--disable-splice --pipe-size 300）：不探测，不建 pipe。
//
// 核对见 checkPipes；都没有 fs.pipe-max-size 的 warn，resize_fail 为 0（statsAfterSignal 也查）
func TestSplicePipeSize(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	for _, c := range []struct {
		name  string
		args  []string
		probe int // 启动探测的 F_SETPIPE_SZ 请求，0 为不探测
		size  int // 新 pipe 的实际容量，0 为不建 pipe
	}{
		{"default", nil, 256 << 10, 256 << 10},
		{"300", []string{"--pipe-size", "300"}, 512 << 10, 512 << 10},
		{"1024", []string{"--pipe-size", "1024"}, 1 << 20, 1 << 20},
		{"64", []string{"--pipe-size", "64"}, 0, 64 << 10},
		{"disable", []string{"--pipe-size", "300", "--disable-splice"}, 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			be := serveTCP(t, loopback4(t), streamHandler)
			listen := loopback4(t)
			w := &pipeSizeWatch{}
			m, _ := startMapperNotifyWith(t, func(n *notifier) {
				n.setDecide(func(call notifyCall) syscall.Errno {
					w.record(call)
					return 0
				})
			}, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, c.args...)...)
			if n := pipeFDs(t, m.pid()); n != 0 {
				t.Errorf("就绪时 tinymapper 有 %d 个 pipe fd：探测 pipe 应当已关", n)
			}
			w.mu.Lock()
			probes := slices.Clone(w.setsz)
			w.mu.Unlock()
			if want := []int{c.probe}; c.probe == 0 && len(probes) != 0 || c.probe != 0 && !slices.Equal(probes, want) {
				t.Errorf("启动时的 F_SETPIPE_SZ 请求 %v，期望 %v（0 为一次都没有）", probes, c.probe)
			}
			if err := transfer(listen, 8<<20, 8<<20, 256<<10, 1); err != nil {
				t.Fatal(err)
			}
			if c.size == 0 {
				m.waitTCPConns(t, 1, 0) // statsAfterSignal 核对 --disable-splice 下 pipes alloc 为 0、splice 计数全 0
				w.mu.Lock()
				defer w.mu.Unlock()
				if len(w.setsz) != 0 || w.reads != 0 || pipeFDs(t, m.pid()) != 0 {
					t.Errorf("--disable-splice：F_SETPIPE_SZ %v、读进 pipe 的 splice %d 次、pipe fd %d 个，期望都没有", w.setsz, w.reads, pipeFDs(t, m.pid()))
				}
				return
			}
			w.checkPipes(t, m, min(c.probe, 1), c.size)
			if n := m.logLines("fs.pipe-max-size"); n != 0 {
				t.Errorf("日志里有 %d 行提到 fs.pipe-max-size，期望没有", n)
			}
		})
	}
}

// D57 启动探测失败的各条路径。只有超过 fs.pipe-max-size 且没有 CAP_SYS_RESOURCE 时探测才因上限 EPERM，而 --pipe-size 最大 1024 KiB
// 正是默认上限（等于时可以），不改 VM 全局的 sysctl 走不到 warn。这里经 seccomp 通知让探测的那次 F_SETPIPE_SZ 返回指定错误，并在
// tinymapper 打开 /proc/sys/fs/pipe-max-size 时经 SECCOMP_IOCTL_NOTIF_ADDFD 换成测试写的文件；之后的 F_SETPIPE_SZ 照常执行（容器里的
// tinymapper 有 CAP_SYS_RESOURCE，1 MiB 以内都能扩）。双向各 8 MiB 后按 checkPipes 核对新 pipe 的容量 size：
//   - warn：--pipe-size 1024，EPERM，上限 131072：一行 warn 报出 1024、128、128 KiB，新 pipe 都请求、实际 128 KiB；
//   - default-info：不给 --pipe-size，EPERM，上限 131072：默认值降到上限只记一行 info（审查 L4，同 D40），没有 warn，128 KiB；
//   - max-equal：1024，EPERM，上限恰为 1048576：不降（比较是 >），没有那一行，仍为 1 MiB；
//   - unreadable：1024，EPERM，打开 pipe-max-size 返回 ENOENT：不降，仍为 1 MiB；
//   - enomem：1024，ENOMEM（不是上限造成的）：不读 pipe-max-size、不降，仍为 1 MiB（留给新建时逐个回退，D58）；
//   - round-300：--pipe-size 300，ENOMEM：探测没设成功，大小仍是用户态取整后的 512 KiB（审查 L2）：探测与新 pipe 都请求 524288，
//     读请求最大 524288，不是 307200
func TestSplicePipeSizeProbe(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	const maxPath = "/proc/sys/fs/pipe-max-size"
	const (
		capWarn = "--pipe-size 1024 KiB is above fs.pipe-max-size (128 KiB) and CAP_SYS_RESOURCE is missing, using 128 KiB"
		capInfo = "default pipe size 256 KiB is above fs.pipe-max-size (128 KiB) and CAP_SYS_RESOURCE is missing, using 128 KiB"
	)
	for _, c := range []struct {
		name    string
		args    []string
		probe   int           // 探测的 F_SETPIPE_SZ 请求
		errno   syscall.Errno // 探测返回的错误
		maxSize string        // 打开 maxPath 时给的内容，"" 为打开失败（ENOENT）
		opens   int           // 期望打开 maxPath 的次数
		size    int           // 之后新 pipe 的实际容量
		level   string        // 降到上限的那一行的级别与内容，level 为 "" 时没有这一行
		line    string
	}{
		{"warn", []string{"--pipe-size", "1024"}, 1 << 20, syscall.EPERM, "131072\n", 1, 128 << 10, "[WARN]", capWarn},
		{"default-info", nil, 256 << 10, syscall.EPERM, "131072\n", 1, 128 << 10, "[INFO]", capInfo},
		{"max-equal", []string{"--pipe-size", "1024"}, 1 << 20, syscall.EPERM, "1048576\n", 1, 1 << 20, "", ""},
		{"unreadable", []string{"--pipe-size", "1024"}, 1 << 20, syscall.EPERM, "", 1, 1 << 20, "", ""},
		{"enomem", []string{"--pipe-size", "1024"}, 1 << 20, syscall.ENOMEM, "131072\n", 0, 1 << 20, "", ""},
		{"round-300", []string{"--pipe-size", "300"}, 512 << 10, syscall.ENOMEM, "131072\n", 0, 512 << 10, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			fake := filepath.Join(t.TempDir(), "pipe-max-size")
			if err := os.WriteFile(fake, []byte(c.maxSize), 0o644); err != nil {
				t.Fatal(err)
			}
			ff, err := os.Open(fake)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ff.Close() })
			fakeFD := int(ff.Fd())
			be := serveTCP(t, loopback4(t), streamHandler)
			listen := loopback4(t)
			w := &pipeSizeWatch{}
			var opens atomic.Int64
			m, _ := startMapperNotifyWith(t, func(n *notifier) {
				n.setAddFD(func(call notifyCall) int {
					if path, ok := openPath(call); ok && path == maxPath && c.maxSize != "" {
						opens.Add(1)
						return fakeFD
					}
					return -1
				})
				n.setDecide(func(call notifyCall) syscall.Errno {
					if path, ok := openPath(call); ok && path == maxPath {
						opens.Add(1)
						return syscall.ENOENT
					}
					w.record(call)
					w.mu.Lock()
					first := isSetPipeSz(call) && len(w.setsz) == 1
					w.mu.Unlock()
					if first {
						return c.errno
					}
					return 0
				})
			}, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, c.args...)...)
			w.mu.Lock()
			probes := slices.Clone(w.setsz)
			w.mu.Unlock()
			if !slices.Equal(probes, []int{c.probe}) {
				t.Errorf("启动时的 F_SETPIPE_SZ 请求 %v，期望恰好一次 %d", probes, c.probe)
			}
			if n := opens.Load(); n != int64(c.opens) {
				t.Errorf("打开 %s %d 次，期望 %d 次", maxPath, n, c.opens)
			}
			want := 0
			if c.level != "" {
				want = 1
			}
			eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
				if n, all := m.logLines(c.level, c.line), m.logLines("fs.pipe-max-size"); c.level != "" && n != 1 || all != want {
					return fmt.Errorf("%s %q 有 %d 行、提到 fs.pipe-max-size 的共 %d 行，期望 %d 行", c.level, c.line, n, all, want)
				}
				return nil
			})
			if err := transfer(listen, 8<<20, 8<<20, 256<<10, 1); err != nil {
				t.Fatal(err)
			}
			w.checkPipes(t, m, 1, c.size)
		})
	}
}

// growAttempt 是 notifier 看到的一次 F_SETPIPE_SZ：请求的大小、注入的错误（0 为照常执行），以及是不是定时器对 scratch 的重试（regrow，
// 审查 M2：对象是已经读进过数据的 pipe；新建时扩容的 pipe 还没有被 splice 用过）
type growAttempt struct {
	size   int
	errno  syscall.Errno
	regrow bool
}

// growWatch 在 notifier 里记下每次 F_SETPIPE_SZ，并以 inject 中的 errno 回应；读进 pipe 的 splice（args[2] 为 pipe 写端）把这个 pipe 记为
// 用过，据此区分新建时的扩容与 regrow
type growWatch struct {
	mu       sync.Mutex
	attempts []growAttempt
	used     map[string]bool // 用过的 pipe（/proc/<pid>/fd 的链接 pipe:[inode]），只在 notifier 协程里读写
	inject   atomic.Int64
	regrowed chan struct{} // 非空时每次 regrow 之后不阻塞地通知一次
}

func (w *growWatch) decide(call notifyCall) syscall.Errno {
	link := func(fd int) string {
		l, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", call.pid, fd))
		return l
	}
	switch call.nr {
	case syscall.SYS_SPLICE:
		if l := link(call.fd(2)); strings.HasPrefix(l, "pipe:[") {
			w.used[l] = true
		}
		return 0
	case syscall.SYS_FCNTL:
		if !isSetPipeSz(call) {
			return 0
		}
		e := syscall.Errno(w.inject.Load())
		a := growAttempt{int(call.args[2]), e, w.used[link(call.fd(0))]}
		w.mu.Lock()
		w.attempts = append(w.attempts, a)
		w.mu.Unlock()
		if a.regrow && w.regrowed != nil {
			select {
			case w.regrowed <- struct{}{}:
			default:
			}
		}
		return e
	}
	return 0
}

// since 返回第 from 次之后的扩容，按新建时的与 regrow 分开
func (w *growWatch) since(from int) (creates, regrows []growAttempt) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, a := range w.attempts[from:] {
		if a.regrow {
			regrows = append(regrows, a)
		} else {
			creates = append(creates, a)
		}
	}
	return creates, regrows
}

func (w *growWatch) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.attempts)
}

// sizedStreamHandler 是背压用例的后端：读一行连接序号 i，向连接写 size 字节（种子 i），之后丢弃读到的数据，等客户端关闭
func sizedStreamHandler(size int64) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		var i int
		fmt.Sscan(strings.TrimSpace(line), &i)
		writeStream(c, size, 64<<10, streamSeed(uint64(i), true))
		io.Copy(io.Discard, r)
	}
}

// 扩容失败的日志行（D58）：第一次 info，之后 debug
const growFailLog = "new pipes keep 65536 bytes until the next timer tick"

// D58：新 pipe 扩容失败（非特权用户到了 fs.pipe-user-pages-soft 时 EPERM，或 ENOMEM）时这个 pipe 保持原来的 16 页照常用，到下一个定时器
// 周期（400 ms）之前新建的 pipe 不再试扩，第一次失败记 info、之后记 debug；stats pool 行的 resize_fail 累计没能扩到 --pipe-size 的新 pipe
// （含不再试扩期间新建的）。tinymapper 经 seccomp 通知启动（--log-level 5；容器里有 CAP_SYS_RESOURCE，真实的配额失败见
// TestSpliceGrowQuota），notifier 记下每次 F_SETPIPE_SZ 并按阶段注入错误。后端按请求向每条连接写 512 KiB，客户端用 slowReaderSocket
// 先不读：每条连接的下行方向持有一个 pipe，池一直是空的，持有的 pipe 都是新建的。
// 定时器对 scratch 的重试（regrow，审查 M2，见 TestSpliceRegrow）不记日志、不计 resize_fail，growWatch 把它与新建时的扩容分开，
// 下面的"扩容"都指新建时的：
//   - A（EPERM）：40 条连接都持有之后：所有 pipe 都是 64 KiB（/proc/<pid>/fd 另开同一个 pipe 查 F_GETPIPE_SZ），resize_fail 恰为 pipes alloc；
//     info 行恰好 1 行（报出请求的 262144、原因与保留的 65536），info+debug 行数恰为失败的扩容次数；扩容次数不超过经过的定时器周期数 + 2，
//     且少于新建的 pipe 数（失败后同一周期里不再试）；
//   - B（不再注入）：等过一个周期，再开 8 条：这期间新建的 pipe 每个都试扩且成功（扩容次数恰为新建数，256 KiB），A 的仍是 64 KiB
//     （持有中，不是 scratch，regrow 不碰），resize_fail 不变；
//   - C（ENOMEM）：再开 8 条：失败记 debug（info 仍是 1 行）、原因为 ENOMEM，扩容次数受周期限制，resize_fail 恰好加上这期间新建的 pipe 数；
//
// 最后慢读排空全部连接：SHA-256 一致、down_bytes 精确、down_splice 非零（扩容失败的 pipe 照常 splice），关闭后 pipe fd 恰为 2×alloc
func TestSpliceGrowFail(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	const S = 512 << 10
	be := serveTCP(t, loopback4(t), sizedStreamHandler(S))
	listen := loopback4(t)
	m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--log-level", "5")
	m.growFailOK = true
	w := &growWatch{used: map[string]bool{}}
	nf.setDecide(w.decide)
	reader := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
	var conns []*net.TCPConn
	// phase 让 F_SETPIPE_SZ 返回 errno，再开 k 条连接，等到所有连接都持有 pipe，返回那时的统计、这期间新建时的扩容与 regrow、用时
	phase := func(errno syscall.Errno, k int) (statsDump, []growAttempt, []growAttempt, time.Duration) {
		t.Helper()
		from := w.count()
		w.inject.Store(int64(errno))
		start := time.Now()
		for range k {
			nc, err := reader.Dial("tcp", listen)
			if err != nil {
				t.Fatalf("连接 %s 失败：%v", listen, err)
			}
			c := nc.(*net.TCPConn)
			t.Cleanup(func() { c.Close() })
			fmt.Fprintf(c, "%d\n", len(conns)) // 后端随即写 S 字节；客户端先不读
			conns = append(conns, c)
		}
		var d statsDump
		eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
			d = m.statsAfterSignal(t)
			if d.pool.pipeHeld+d.pool.held != len(conns) {
				return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望共 %d 个", d.pool.pipeHeld, d.pool.held, len(conns))
			}
			return nil
		})
		elapsed := time.Since(start)
		if d.pool.pipeHeld != len(conns) {
			t.Fatalf("只有 %d/%d 个方向持有 pipe（其余 %d 个持有块）", d.pool.pipeHeld, len(conns), d.pool.held)
		}
		creates, regrows := w.since(from)
		return d, creates, regrows, elapsed
	}
	// expectFailed 核对一个注入失败的阶段：扩容与 regrow 合计至少一次（regrow 失败也会挡住同一周期里的扩容）、都失败了，扩容受定时器周期限制
	expectFailed := func(name string, tries, regrows []growAttempt, errno syscall.Errno, created int, elapsed time.Duration) {
		t.Helper()
		all := append(slices.Clone(tries), regrows...)
		if len(all) == 0 || slices.ContainsFunc(all, func(a growAttempt) bool { return a.errno != errno || a.size != defaultPipeSize }) {
			t.Errorf("%s：扩容 %v、regrow %v，期望合计至少一次、都请求 %d 并返回 %v", name, tries, regrows, defaultPipeSize, errno)
		}
		if limit := int(elapsed/(400*time.Millisecond)) + 2; len(tries) > limit || len(tries) >= created {
			t.Errorf("%s：%v 内新建 %d 个 pipe、试了 %d 次扩容（上限 %d 次且少于新建数）：失败后到下一个定时器周期之前不应再试",
				name, elapsed.Round(time.Millisecond), created, len(tries), limit)
		}
	}
	// get_sock_error 的格式是 "errno:strerror"，strerror 的措辞 glibc 与 musl 不同（ENOMEM：Cannot allocate memory / Out of memory），只比 errno
	logged := func(level string, errno syscall.Errno) int {
		return m.logLines(level, fmt.Sprintf("[tcp]enlarging a new pipe to 262144 bytes failed (%d:", int(errno)), growFailLog)
	}

	dA, triesA, regrowA, elA := phase(syscall.EPERM, 40)
	t.Logf("A（EPERM）：%v 内 pool %+v，扩容 %d 次、regrow %d 次", elA.Round(time.Millisecond), dA.pool, len(triesA), len(regrowA))
	expectFailed("A", triesA, regrowA, syscall.EPERM, dA.pool.pipeAlloc, elA)
	if dA.pool.resizeFail != uint64(dA.pool.pipeAlloc) {
		t.Errorf("A：resize_fail=%d，期望恰为新建的 pipe 数 %d（扩容失败与不再试扩期间新建的都算）", dA.pool.resizeFail, dA.pool.pipeAlloc)
	}
	if h := capHist(pipeCapacities(t, m.pid())); h[64<<10] != dA.pool.pipeAlloc || len(h) != 1 {
		t.Errorf("A：pipe 容量分布 %v，期望 %d 个都是 65536（扩容失败的 pipe 保持原大小照常用）", h, dA.pool.pipeAlloc)
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if info, debug := logged("[INFO]", syscall.EPERM), logged("[DEBUG]", syscall.EPERM); info != 1 || info+debug != len(triesA) {
			data, _ := os.ReadFile(m.logPath)
			var lines []string
			for _, l := range strings.Split(string(data), "\n") {
				if strings.Contains(l, "enlarging") {
					lines = append(lines, l)
				}
			}
			return fmt.Errorf("A：扩容失败的 info 行 %d 行、debug 行 %d 行，期望 1 行 info、共 %d 行（每次失败一行）：%q", info, debug, len(triesA), lines)
		}
		return nil
	})

	time.Sleep(500 * time.Millisecond) // 跨过一个定时器周期，扩容不再被挡
	dB, triesB, _, elB := phase(0, 8)
	newB := dB.pool.pipeAlloc - dA.pool.pipeAlloc
	t.Logf("B（照常）：%v 内 pool %+v，新建 %d 个、扩容 %d 次", elB.Round(time.Millisecond), dB.pool, newB, len(triesB))
	if len(triesB) != newB || newB < 8 || slices.ContainsFunc(triesB, func(a growAttempt) bool { return a.size != defaultPipeSize }) {
		t.Errorf("B：新建 %d 个 pipe、扩容 %v，期望每个新 pipe 一次（≥ 8 次）、都请求 %d：下一个定时器周期起应当重新试扩", newB, triesB, defaultPipeSize)
	}
	if dB.pool.resizeFail != dA.pool.resizeFail {
		t.Errorf("B：resize_fail %d → %d，扩容成功时不应增加", dA.pool.resizeFail, dB.pool.resizeFail)
	}
	if h := capHist(pipeCapacities(t, m.pid())); h[64<<10] != dA.pool.pipeAlloc || h[defaultPipeSize] != newB {
		t.Errorf("B：pipe 容量分布 %v，期望 %d 个 65536、%d 个 262144", h, dA.pool.pipeAlloc, newB)
	}

	dC, triesC, regrowC, elC := phase(syscall.ENOMEM, 8)
	newC := dC.pool.pipeAlloc - dB.pool.pipeAlloc
	t.Logf("C（ENOMEM）：%v 内 pool %+v，新建 %d 个、扩容 %d 次、regrow %d 次", elC.Round(time.Millisecond), dC.pool, newC, len(triesC), len(regrowC))
	expectFailed("C", triesC, regrowC, syscall.ENOMEM, newC, elC)
	if dC.pool.resizeFail != dB.pool.resizeFail+uint64(newC) {
		t.Errorf("C：resize_fail %d → %d，期望加上这期间新建的 %d 个", dB.pool.resizeFail, dC.pool.resizeFail, newC)
	}
	if h := capHist(pipeCapacities(t, m.pid())); h[64<<10] != dA.pool.pipeAlloc+newC || h[defaultPipeSize] != newB {
		t.Errorf("C：pipe 容量分布 %v，期望 %d 个 65536、%d 个 262144", h, dA.pool.pipeAlloc+newC, newB)
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if info, debug := m.logLines("[INFO]", growFailLog), logged("[DEBUG]", syscall.ENOMEM); info != 1 || debug != len(triesC) {
			return fmt.Errorf("C：扩容失败的 info 行共 %d 行、ENOMEM 的 debug 行 %d 行，期望 1 行、%d 行（第一次之后都记 debug）", info, debug, len(triesC))
		}
		return nil
	})

	results := make(chan error, len(conns))
	for i, c := range conns {
		go func() { results <- slowVerify(c, S, streamSeed(uint64(i), true)) }()
	}
	for range conns {
		if err := <-results; err != nil {
			t.Fatalf("排空校验失败：%v", err)
		}
	}
	var d statsDump
	eventually(t, 3*ioTimeout, 100*time.Millisecond, func() error {
		d = m.statsAfterSignal(t)
		if d.pool.pipeHeld != 0 || d.pool.held != 0 {
			return fmt.Errorf("排空后仍有 %d 个方向持有 pipe、%d 个持有块", d.pool.pipeHeld, d.pool.held)
		}
		return nil
	})
	if s := d.tcp[1]; s.downBytes != uint64(len(conns))*S || s.downSplice == 0 {
		t.Errorf("排空后 down_bytes=%d down_splice=%d，期望 %d、非零", s.downBytes, s.downSplice, uint64(len(conns))*S)
	}
	for _, c := range conns {
		c.Close()
	}
	m.expectPipeFDs(t, m.waitTCPConns(t, 1, 0), "连接全部关闭后")
}

// pipeHogPagesEnv：占位进程只持有恰好这么多页的 pipe（runPipeHogPages），用于让同一 uid 的 tinymapper 能新建 16 页的 pipe、却扩不上去
const pipeHogPagesEnv = "TPM_PIPE_HOG_PAGES"

func init() {
	if v := os.Getenv(pipeHogPagesEnv); v != "" {
		runPipeHogPages(v)
	}
}

// runPipeHogPages 在重新执行的测试二进制里运行：持有恰好 v 页的 pipe（新 pipe 默认 16 页；零头的 pipe 用 F_SETPIPE_SZ 缩到 2 的幂页，
// 缩容不查限额），逐个核对容量，在 stdout 写一行 "ready <pipe 数>"，然后阻塞到 stdin 关闭。不返回
func runPipeHogPages(v string) {
	pages, err := strconv.Atoi(v)
	if err != nil || pages < 0 {
		fmt.Printf("error 页数 %q\n", v)
		os.Exit(1)
	}
	page, n := os.Getpagesize(), 0
	hold := func(slots int) {
		var p [2]int
		if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
			fmt.Printf("error pipe2 #%d: %v\n", n+1, err)
			os.Exit(1)
		}
		if slots != 16 {
			if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(p[1]), fSetpipeSz, uintptr(slots*page)); e != 0 {
				fmt.Printf("error F_SETPIPE_SZ %d: %v\n", slots*page, e)
				os.Exit(1)
			}
		}
		if size, err := pipeSize(p[1]); err != nil || size != slots*page {
			fmt.Printf("error pipe #%d 容量 %d（%v），期望 %d：这个 uid 已有别的 pipe？\n", n+1, size, err, slots*page)
			os.Exit(1)
		}
		n++
	}
	for range pages / 16 {
		hold(16)
	}
	for b := 8; b >= 1; b >>= 1 {
		if pages%16&b != 0 {
			hold(b)
		}
	}
	fmt.Printf("ready %d\n", n)
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// D58 的真实场景：非特权用户的 pipe 总页数接近 fs.pipe-user-pages-soft 时，新 pipe 还能按默认 16 页建成，扩到 64 页却使总数超过软限，
// F_SETPIPE_SZ 返回 EPERM。占位进程以随机的非 root uid 持有恰好 软限 − 63 页，tinymapper 以同一 uid 运行（没有任何能力）：
//   - 启动探测：16 页的探测 pipe 扩到 64 页超出软限 1 页，EPERM；请求的 256 KiB 不超过 fs.pipe-max-size，不 warn、不降；
//   - 新 pipe 建成时总数依次为 软限 − 47、− 31、− 15，扩容都失败（或在同一周期里不再试），保持 64 KiB 照常 splice；第四个只有 2 页，回退拷贝。
//
// 双向各 4 MiB：数据完整、有 splice 字节；resize_fail 恰为 pipes alloc（≥ 1，一个都没扩上去）；扩容失败恰好一行 info（默认 --log-level），
// 原因是 EPERM（1）、保留 65536；没有 fs.pipe-max-size 的 warn。读不了其他 uid 的 /proc/<pid>/fd，pipe 容量由 TestSpliceGrowFail 查
func TestSpliceGrowQuota(t *testing.T) {
	t.Parallel()
	need4KPages(t)
	if os.Getuid() != 0 {
		t.Skip("以另一个 uid 启动进程需要 root")
	}
	soft := readSysctlInt(t, "/proc/sys/fs/pipe-user-pages-soft")
	hard := readSysctlInt(t, "/proc/sys/fs/pipe-user-pages-hard")
	if soft < 64 {
		t.Skipf("fs.pipe-user-pages-soft=%d（0 为不限）：没有可用的软限", soft)
	}
	if hard != 0 && hard <= soft+64 {
		t.Skipf("fs.pipe-user-pages-hard=%d 不比软限 %d 大出足够余量", hard, soft)
	}
	uid := uint32(42000 + rand.IntN(20000))
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hog := exec.Command(self)
	hog.Env = append(os.Environ(), fmt.Sprintf("%s=%d", pipeHogPagesEnv, soft-63))
	hog.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	stdin, err := hog.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := hog.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := hog.Start(); err != nil {
		t.Fatalf("以 uid %d 启动占位进程失败：%v", uid, err)
	}
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { io.Copy(io.Discard, stdout); hog.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			hog.Process.Kill()
			<-done
		}
	})
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()
	var line string
	select {
	case line = <-lines:
	case <-time.After(30 * time.Second):
		t.Fatal("占位进程 30 s 内没有报告就绪")
	}
	var held int
	if _, err := fmt.Sscanf(line, "ready %d", &held); err != nil {
		t.Fatalf("占位进程：%q", line)
	}
	t.Logf("uid %d 的占位进程以 %d 个 pipe 持有 %d 页（fs.pipe-user-pages-soft=%d）", uid, held, soft-63, soft)

	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	m := startMapperAsUID(t, uid, portOf(listen), "-l", listen, "-r", be.addr, "-t")
	if err := transfer(listen, 4<<20, 4<<20, 256<<10, 1); err != nil {
		t.Fatal(err)
	}
	d := m.statsAfterSignal(t)
	s := d.tcp[1]
	t.Logf("%+v；pool %+v", s, d.pool)
	if s.upSplice+s.downSplice == 0 || d.pool.pipeAlloc == 0 || d.pool.resizeFail != uint64(d.pool.pipeAlloc) {
		t.Errorf("up_splice=%d down_splice=%d pipes alloc=%d resize_fail=%d：期望有 splice 字节、pipe 都没扩上去（resize_fail 恰为 alloc，≥ 1）",
			s.upSplice, s.downSplice, d.pool.pipeAlloc, d.pool.resizeFail)
	}
	eventually(t, logFlushWithin, 50*time.Millisecond, func() error {
		if n := m.logLines("[INFO]", "[tcp]enlarging a new pipe to 262144 bytes failed (1:", growFailLog); n != 1 {
			return fmt.Errorf("EPERM 的扩容失败 info 行 %d 行，期望 1 行", n)
		}
		return nil
	})
	if n := m.logLines("fs.pipe-max-size"); n != 0 {
		t.Errorf("日志里有 %d 行提到 fs.pipe-max-size：探测因配额 EPERM 时请求没超过上限，不应 warn", n)
	}
}

// B3 审查 M1：空闲池最多留 pipePoolCap 个 pipe（合计 1024 页；4 KiB 页时 --pipe-size 64 为 64 个，默认 256 KiB 为 16 个，1024 为 4 个），
// 多出的 close。每项开 上限 + 8 条慢读连接（后端各写 512 KiB，客户端用 slowReaderSocket 先不读），等所有下行方向都持有 pipe，再慢读
// 排空、逐条校验 SHA-256：持有归零，空闲 ≤ 上限且空闲 + scratch ≥ 上限（归还的多于上限，池满之后只有当 scratch 时少一个），
// alloc 比峰值少（多出的已 close），pipe fd 恰为 2×alloc
func TestSplicePoolCap(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	for _, c := range []struct {
		name string
		args []string
		size int
	}{
		{"64", []string{"--pipe-size", "64"}, 64 << 10},
		{"default", nil, defaultPipeSize},
		{"1024", []string{"--pipe-size", "1024"}, 1 << 20},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			const S = 512 << 10
			limit := pipePoolCap(c.size)
			n := limit + 8
			be := serveTCP(t, loopback4(t), sizedStreamHandler(S))
			listen := loopback4(t)
			m := startMapper(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, c.args...)...)
			reader := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
			conns := make([]*net.TCPConn, n)
			for i := range conns {
				nc, err := reader.Dial("tcp", listen)
				if err != nil {
					t.Fatalf("连接 %s 失败：%v", listen, err)
				}
				conns[i] = nc.(*net.TCPConn)
				t.Cleanup(func() { nc.Close() })
				fmt.Fprintf(conns[i], "%d\n", i) // 后端随即写 S 字节；客户端先不读
			}
			var peak statsDump
			eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
				peak = m.statsAfterSignal(t)
				if peak.pool.pipeHeld != n {
					return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望 %d 个方向都持有 pipe", peak.pool.pipeHeld, peak.pool.held, n)
				}
				return nil
			})
			results := make(chan error, n)
			for i, cn := range conns {
				go func() { results <- slowVerify(cn, S, streamSeed(uint64(i), true)) }()
			}
			for range conns {
				if err := <-results; err != nil {
					t.Fatalf("排空校验失败：%v", err)
				}
			}
			var d statsDump
			eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
				if d = m.statsAfterSignal(t); d.pool.pipeHeld != 0 || d.pool.held != 0 {
					return fmt.Errorf("排空后仍有 %d 个方向持有 pipe、%d 个持有块", d.pool.pipeHeld, d.pool.held)
				}
				return nil
			})
			t.Logf("上限 %d：峰值 pool %+v；排空后 %+v", limit, peak.pool, d.pool)
			if p := d.pool; p.pipeFree > limit || p.pipeFree+p.pipeScratch < limit || p.pipeAlloc >= peak.pool.pipeAlloc {
				t.Errorf("排空后 pipes alloc=%d free=%d scratch=%d（峰值 alloc %d）：空闲应恰好留满 %d 个（加 scratch 不少于它），多出的 close",
					p.pipeAlloc, p.pipeFree, p.pipeScratch, peak.pool.pipeAlloc, limit)
			}
			if want := uint64(n) * S; d.tcp[1].downBytes != want || d.tcp[1].downSplice == 0 {
				t.Errorf("down_bytes=%d down_splice=%d，期望 %d、非零", d.tcp[1].downBytes, d.tcp[1].downSplice, want)
			}
			m.expectPipeFDs(t, d, "排空后")
		})
	}
}

// heldDownload 按 streamHandler 的协议请求下载 size 字节（up 为 0），连接用 slowReaderSocket、先不读：tinymapper 的下行方向随即持有 pipe。
// 之后用 finishHeld 慢读校验
func heldDownload(listen string, size int64, seed uint64) (*net.TCPConn, error) {
	d := net.Dialer{Timeout: ioTimeout, Control: slowReaderSocket}
	nc, err := d.Dial("tcp", listen)
	if err != nil {
		return nil, err
	}
	var hdr [streamHeaderLen]byte
	binary.BigEndian.PutUint64(hdr[8:], uint64(size))
	binary.BigEndian.PutUint32(hdr[16:], 64<<10)
	binary.BigEndian.PutUint64(hdr[20:], seed)
	if _, err := nc.Write(hdr[:]); err != nil {
		nc.Close()
		return nil, err
	}
	return nc.(*net.TCPConn), nil
}

// finishHeld 慢读 heldDownload 的连接并核对数据与后端的校验尾（同 slowDownload）
func finishHeld(c net.Conn, size int64, seed uint64) error {
	c.SetDeadline(time.Now().Add(transferTimeout(size)))
	if err := slowVerify(c, size, streamSeed(seed, true)); err != nil {
		return err
	}
	var trailer [64]byte
	if _, err := io.ReadFull(c, trailer[:]); err != nil {
		return fmt.Errorf("读取校验尾：%w", err)
	}
	empty := sha256.Sum256(nil)
	want, _ := writeStream(io.Discard, size, 64<<10, streamSeed(seed, true))
	if !bytes.Equal(trailer[:32], empty[:]) || !bytes.Equal(trailer[32:], want) {
		return errors.New("校验尾与期望不一致")
	}
	return nil
}

// B3 审查 M2：扩容失败过之后（resize_fail ≠ 0），clear_timer_cb 每个周期对 scratch pipe 再试一次扩容（regrow）：不记日志、不计
// resize_fail，失败则到下一个周期之前不再试扩新 pipe；池里没扩上去的 pipe 轮到当 scratch 时也会扩上。tinymapper 经 seccomp 通知启动，
// growWatch 让 F_SETPIPE_SZ 返回 EPERM，另记下每次从 pipe 写出的 splice 的长度（读分支的写出恰为刚读到的字节，写分支的不超过持有的）：
//  1. 注入期间双向各 8 MiB：pipe 都是 64 KiB、resize_fail ≥ 1、从 pipe 写出的每次都不超过 64 KiB，结束时有 scratch；
//  2. 再等 1 s（两个周期以上）、没有流量：对 scratch 的 regrow 至少 2 次（每个周期一次）、都失败，没有新建时的扩容，resize_fail 与扩容失败的
//     日志行数都不变；
//  3. 仍在注入：notifier 一看到 regrow 就开 8 条持有下载（heldDownload），在同一个周期里（350 ms 内）全部持有时，这期间新建的 pipe
//     一次扩容都不试、没有新的日志行（regrow 失败已把扩容挡到下一个周期）；不论是否跨周期，resize_fail 都恰好加上新建的 pipe 数；
//     随后慢读排空，再双向各 8 MiB（仍在注入），留下一个 64 KiB 的 scratch；
//  4. 停止注入：2 s 内 scratch 扩到 256 KiB（容量为 256 KiB 的恰为 scratch 那一个，空闲池里的仍是 64 KiB：只扩 scratch）；之后 1 s 内不再
//     调 F_SETPIPE_SZ（已够大就不调）；
//  5. 再双向各 8 MiB：第一次读进 pipe 的 splice 写入的正是这个扩上去的 scratch，有从 pipe 一次写出超过 64 KiB 的，resize_fail 仍不变
//     （新建的 pipe 照常扩上去）
func TestSpliceRegrow(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	be := serveTCP(t, loopback4(t), streamHandler)
	listen := loopback4(t)
	m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), "-l", listen, "-r", be.addr, "-t", "--log-level", "5")
	m.growFailOK = true
	w := &growWatch{used: map[string]bool{}, regrowed: make(chan struct{}, 1)}
	pid := m.pid()
	var maxOut atomic.Int64            // 从 pipe 写出的 splice 的最大请求长度
	var firstIn atomic.Pointer[string] // 置为 "" 之后，第一个读进 pipe 的 splice 写入的 pipe（/proc/<pid>/fd 的链接）
	nf.setDecide(func(call notifyCall) syscall.Errno {
		if call.nr == syscall.SYS_SPLICE && !isSocketFD(pid, call.fd(0)) {
			for v := maxOut.Load(); int64(call.args[4]) > v && !maxOut.CompareAndSwap(v, int64(call.args[4])); v = maxOut.Load() {
			}
		} else if p := firstIn.Load(); call.nr == syscall.SYS_SPLICE && p != nil && *p == "" {
			link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, call.fd(2)))
			firstIn.CompareAndSwap(p, &link)
		}
		return w.decide(call)
	})
	growLines := func() int { return m.logLines("[tcp]enlarging a new pipe", growFailLog) }
	// smallScratch 在注入期间传输之后核对：有 scratch，pipe 都是 64 KiB，从 pipe 写出的每次都不超过 64 KiB
	smallScratch := func(step string) statsDump {
		t.Helper()
		d := m.waitTCPConns(t, 1, 0)
		if h := capHist(pipeCapacities(t, pid)); d.pool.resizeFail == 0 || h[64<<10] != d.pool.pipeAlloc || d.pool.pipeScratch != 1 {
			t.Fatalf("%s：pool %+v、pipe 容量分布 %v：期望 resize_fail ≥ 1、pipe 都是 64 KiB、有 scratch", step, d.pool, h)
		}
		if v := maxOut.Swap(0); v > 64<<10 {
			t.Errorf("%s：pipe 都是 64 KiB 时从 pipe 写出 %d B", step, v)
		}
		return d
	}

	w.inject.Store(int64(syscall.EPERM))
	if err := transfer(listen, 8<<20, 8<<20, 256<<10, 1); err != nil {
		t.Fatal(err)
	}
	d1 := smallScratch("1")
	lines, from := growLines(), w.count()
	time.Sleep(time.Second)
	creates, regrows := w.since(from)
	d2 := m.statsAfterSignal(t)
	t.Logf("2：注入期间空闲 1 s：扩容 %v，regrow %v；pool %+v", creates, regrows, d2.pool)
	if len(creates) != 0 || len(regrows) < 2 || slices.ContainsFunc(regrows, func(a growAttempt) bool { return a.size != defaultPipeSize || a.errno != syscall.EPERM }) {
		t.Errorf("2：空闲 1 s 内扩容 %v、regrow %v，期望没有扩容、每个周期对 scratch 一次 regrow（至少 2 次，都请求 262144）", creates, regrows)
	}
	if d2.pool.resizeFail != d1.pool.resizeFail || growLines() != lines {
		t.Errorf("2：regrow 失败后 resize_fail %d → %d、扩容失败的日志 %d → %d 行，期望都不变", d1.pool.resizeFail, d2.pool.resizeFail, lines, growLines())
	}

	const S = 512 << 10
	for len(w.regrowed) > 0 {
		<-w.regrowed
	}
	select {
	case <-w.regrowed:
	case <-time.After(2 * time.Second):
		t.Fatal("3：2 s 内没有 regrow")
	}
	start, from := time.Now(), w.count()
	held := make([]*net.TCPConn, 8)
	for i := range held {
		c, err := heldDownload(listen, S, uint64(300+i))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		held[i] = c
	}
	var d3 statsDump
	eventually(t, 3*ioTimeout, 20*time.Millisecond, func() error {
		if d3 = m.statsAfterSignal(t); d3.pool.pipeHeld != len(held) {
			return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个，期望 %d 个方向都持有 pipe", d3.pool.pipeHeld, d3.pool.held, len(held))
		}
		return nil
	})
	elapsed := time.Since(start)
	creates, _ = w.since(from)
	created := d3.pool.pipeAlloc - d2.pool.pipeAlloc
	t.Logf("3：regrow 之后 %v 内 8 个方向持有，新建 %d 个 pipe，扩容 %v；pool %+v", elapsed.Round(time.Millisecond), created, creates, d3.pool)
	if elapsed < 350*time.Millisecond && (len(creates) != 0 || growLines() != lines) {
		t.Errorf("3：regrow 失败后同一周期里新建的 pipe 试了扩容 %v、扩容失败的日志 %d → %d 行，期望都没有（regrow 失败应挡住扩容）",
			creates, lines, growLines())
	} else if elapsed >= 350*time.Millisecond {
		t.Logf("3：持有用了 %v，可能跨过了定时器周期，不判扩容次数", elapsed)
	}
	if d3.pool.resizeFail != d2.pool.resizeFail+uint64(created) {
		t.Errorf("3：resize_fail %d → %d，期望加上新建的 %d 个", d2.pool.resizeFail, d3.pool.resizeFail, created)
	}
	results := make(chan error, len(held))
	for i, c := range held {
		go func() { results <- finishHeld(c, S, uint64(300+i)) }()
	}
	for range held {
		if err := <-results; err != nil {
			t.Fatalf("3：排空校验失败：%v", err)
		}
	}
	for _, c := range held {
		c.Close()
	}
	if err := transfer(listen, 8<<20, 8<<20, 256<<10, 2); err != nil {
		t.Fatal(err)
	}
	d4 := smallScratch("3")

	w.inject.Store(0)
	var scratch string // 扩上去的 scratch（容量为 256 KiB 的唯一一个 pipe）
	eventually(t, 2*time.Second, 50*time.Millisecond, func() error {
		d := m.statsAfterSignal(t)
		caps := pipeCapacities(t, pid)
		if h := capHist(caps); d.pool.pipeScratch != 1 || h[defaultPipeSize] != 1 || h[64<<10] != d.pool.pipeFree {
			return fmt.Errorf("pool %+v，pipe 容量分布 %v：期望 scratch 扩到 262144、空闲的 %d 个仍是 65536", d.pool, h, d.pool.pipeFree)
		}
		for link, size := range caps {
			if size == defaultPipeSize {
				scratch = link
			}
		}
		return nil
	})
	from = w.count()
	time.Sleep(time.Second)
	if creates, regrows := w.since(from); len(creates)+len(regrows) != 0 {
		t.Errorf("4：scratch 扩上之后 1 s 内又有扩容 %v、regrow %v：已够大就不该再调 F_SETPIPE_SZ", creates, regrows)
	}
	empty := ""
	firstIn.Store(&empty)
	if err := transfer(listen, 8<<20, 8<<20, 256<<10, 3); err != nil {
		t.Fatal(err)
	}
	d5 := m.waitTCPConns(t, 1, 0)
	if got := *firstIn.Load(); got != scratch {
		t.Errorf("5：扩上之后第一次读进 pipe 的 splice 写入 %q，期望是扩到 256 KiB 的 scratch %q", got, scratch)
	}
	if v := maxOut.Load(); v <= 64<<10 || d5.pool.resizeFail != d4.pool.resizeFail {
		t.Errorf("5：scratch 扩上之后的传输：从 pipe 一次最多写出 %d B（期望超过 65536），resize_fail %d → %d（期望不变）",
			v, d4.pool.resizeFail, d5.pool.resizeFail)
	}
}

// 复审 R1：新 pipe 因配额只有 2 页（不到 16 槽）时置 quota_hit：到下一个定时器周期之前 put() 最多留 64 个空闲 pipe（tcp_pipe_pool_max_free），
// 不是 max_free（默认 256 KiB 时 16 个）；clear_timer_cb 清掉标志并把空闲裁回 max_free。pipe2 失败、新 pipe 的 fd 落在 RLIMIT_NOFILE 最后 1/4
// 这两种创建失败不放宽。tinymapper 经 seccomp 通知启动（--sock-buf 200，见 holdSockBuf），后端按请求向每条连接写 1 MiB，80 条客户端先不读：
// 80 个下行方向都持有数据、池是空的，其中持有 pipe 的至少 66 个（负载重时个别方向的某次读不到 16 KiB，下一次走 recv，持有的是块）。
// 然后按子项让新建 pipe 失败：
//   - quota：新建时的 F_GETPIPE_SZ 由 notifier 代答 8192（配额已满时内核给的 2 页）；
//   - emfile：pipe2 返回 EMFILE；
//   - rlimit：notifier 在每次 pipe2 执行前把软限设成让新 pipe 的 fd 落在最后 1/4（同 TestSpliceFdQuarter）。
//
// 再开第 81 条连接持续上传，它的下行先不读（这个方向随即持有，开始注入时若还有 scratch 也被它占住）：上传方向每次 splice 读都要新建 pipe，
// 失败后到下一个周期之前不再建（D47），所以开始注入之后的第二次 pipe2 紧跟在一个定时器周期之后。看到它就让 80 个客户端全速读完并校验 SHA-256，随即取统计（距那次 pipe2 不到 350 ms，仍在同一个周期里；超过时
// 不判这一项）：
//   - quota：空闲多于 max_free、不超过 64，空闲 + scratch + 持有（只剩还在上传的那条连接可能持有）不少于 64（归还了至少 66 个 pipe，上限 64）；
//   - emfile、rlimit：空闲不超过 max_free，空闲 + scratch + 持有不少于 max_free（不放宽）；
//
// 各子项还核对确实走到了对应的失败分支（日志）。停止上传、等过一个周期：空闲 ≤ max_free 且空闲 + scratch ≥ max_free（quota：多留的已裁掉、
// close），pipe fd 恰为 2×alloc
func TestSplicePoolQuota(t *testing.T) {
	t.Parallel()
	needPipeQuotaExempt(t)
	need4KPages(t)
	for _, c := range []struct{ mode, log string }{
		{"quota", "new pipe has only 8192 bytes"},
		{"emfile", fmt.Sprintf("pipe2 failed (%d:", int(syscall.EMFILE))},
		{"rlimit", "is in the last quarter of RLIMIT_NOFILE"},
	} {
		t.Run(c.mode, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			const n, S = 80, 1 << 20
			limit := pipePoolCap(defaultPipeSize)
			be := serveTCP(t, loopback4(t), sizedStreamHandler(S))
			listen := loopback4(t)
			m, nf := startMapperNotify(t, listenPoints("t", portOf(listen)), append([]string{"-l", listen, "-r", be.addr, "-t"}, holdSockBuf...)...)
			pid := m.pid()
			var oldNofile syscall.Rlimit
			if err := prlimit(pid, rlimitNofile, nil, &oldNofile); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { prlimit(pid, rlimitNofile, &oldNofile, nil) })
			var armed atomic.Bool
			var pipe2s atomic.Int64
			afterTick := make(chan struct{}, 1)
			nf.setEmulate(func(call notifyCall) (int64, bool) {
				return 8192, c.mode == "quota" && armed.Load() && isGetPipeSz(call)
			})
			nf.setDecide(func(call notifyCall) syscall.Errno {
				if call.nr != syscall.SYS_PIPE2 || !armed.Load() {
					return 0
				}
				if pipe2s.Add(1) == 2 {
					afterTick <- struct{}{}
				}
				switch c.mode {
				case "emfile":
					return syscall.EMFILE
				case "rlimit":
					// tinymapper 停在这次 pipe2 上，fd 表不变：pipe2 将拿到最小的两个空闲 fd f1<f2，软限设为 f2/3*4 时 f2 ≥ 软限/4*3
					ents, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
					open := map[int]bool{}
					for _, e := range ents {
						fd, _ := strconv.Atoi(e.Name())
						open[fd] = true
					}
					var free []int
					for fd := 0; len(free) < 2; fd++ {
						if !open[fd] {
							free = append(free, fd)
						}
					}
					prlimit(pid, rlimitNofile, &syscall.Rlimit{Cur: uint64(free[1] / 3 * 4), Max: oldNofile.Max}, nil)
				}
				return 0
			})
			conns := make([]*net.TCPConn, n)
			for i := range conns {
				conns[i] = dial(t, listen)
				fmt.Fprintf(conns[i], "%d\n", i) // 后端随即写 S 字节；客户端先不读
			}
			var d0 statsDump
			eventually(t, 3*ioTimeout, 50*time.Millisecond, func() error {
				if d0 = m.statsAfterSignal(t); d0.pool.pipeHeld+d0.pool.held != n || d0.pool.pipeHeld <= pipePoolMaxFree+1 || d0.pool.pipeFree != 0 {
					return fmt.Errorf("持有 pipe 的方向 %d 个、持有块的 %d 个、空闲 pipe %d 个，期望 %d 个方向都持有、其中持有 pipe 的多于 %d 个、池是空的",
						d0.pool.pipeHeld, d0.pool.held, d0.pool.pipeFree, n, pipePoolMaxFree+1)
				}
				return nil
			})
			armed.Store(true)
			up := dial(t, listen)
			fmt.Fprintf(up, "%d\n", n)
			stop := make(chan struct{})
			upDone := make(chan error, 2)
			go func() { // 持续上传，后端丢弃
				buf := make([]byte, 64<<10)
				for {
					select {
					case <-stop:
						upDone <- nil
						return
					default:
					}
					up.SetWriteDeadline(time.Now().Add(ioTimeout))
					if _, err := up.Write(buf); err != nil {
						upDone <- err
						return
					}
				}
			}()
			select {
			case <-afterTick:
			case <-time.After(5 * time.Second):
				t.Fatalf("开始注入之后 5 s 内只有 %d 次 pipe2（pool %+v）", pipe2s.Load(), m.statsAfterSignal(t).pool)
			}
			start := time.Now()
			results := make(chan error, n)
			for i, cn := range conns {
				go func() {
					cn.SetReadDeadline(time.Now().Add(transferTimeout(S)))
					h, err := readStream(cn, S)
					if err == nil {
						if want, _ := writeStream(io.Discard, S, 64<<10, streamSeed(uint64(i), true)); !bytes.Equal(h.Sum(nil), want) {
							err = errors.New("SHA-256 不一致")
						}
					}
					results <- err
				}()
			}
			for range conns {
				if err := <-results; err != nil {
					t.Fatalf("读第 %d 条之前的连接：%v", n, err)
				}
			}
			d := m.statsAfterSignal(t)
			elapsed := time.Since(start)
			t.Logf("%s：周期开始后 %v 内 %d 个方向排空，pool %+v", c.mode, elapsed.Round(time.Millisecond), n, d.pool)
			switch p := d.pool; {
			case elapsed >= 350*time.Millisecond:
				t.Logf("排空到取统计用了 %v，可能跨过了定时器周期，不判周期内的空闲数", elapsed)
			case p.pipeHeld > 2:
				t.Errorf("排空后仍有 %d 个方向持有 pipe（只有还在上传的那条连接的两个方向可以）", p.pipeHeld)
			case c.mode == "quota" && (p.pipeFree <= limit || p.pipeFree > pipePoolMaxFree || p.pipeFree+p.pipeScratch+p.pipeHeld < pipePoolMaxFree):
				t.Errorf("quota：配额满的周期里归还 %d 个 pipe 之后空闲 %d、scratch %d、持有 %d，期望空闲多于 %d、不超过 %d，三者合计不少于 %d",
					d0.pool.pipeHeld, p.pipeFree, p.pipeScratch, p.pipeHeld, limit, pipePoolMaxFree, pipePoolMaxFree)
			case c.mode != "quota" && (p.pipeFree > limit || p.pipeFree+p.pipeScratch+p.pipeHeld < limit):
				t.Errorf("%s：归还 %d 个 pipe 之后空闲 %d、scratch %d、持有 %d，期望空闲不超过 %d（只有配额满才放宽）、三者合计不少于它",
					c.mode, d0.pool.pipeHeld, p.pipeFree, p.pipeScratch, p.pipeHeld, limit)
			}
			go func() { // 现在才读它的下行：此前这个方向持有着数据，把开始注入时可能还在的 scratch 占住，之后的 splice 读都要新建 pipe
				_, err := io.CopyN(io.Discard, up, S)
				upDone <- err
			}()
			close(stop)
			for range 2 {
				if err := <-upDone; err != nil {
					t.Fatalf("第 %d 条连接：%v", n+1, err)
				}
			}
			prlimit(pid, rlimitNofile, &oldNofile, nil)
			time.Sleep(500 * time.Millisecond) // 跨过一个定时器周期
			d2 := m.statsAfterSignal(t)
			t.Logf("%s：一个周期之后 pool %+v", c.mode, d2.pool)
			if p := d2.pool; p.pipeFree > limit || p.pipeFree+p.pipeScratch+p.pipeHeld < limit || c.mode == "quota" && p.pipeAlloc >= d.pool.pipeAlloc {
				t.Errorf("%s：一个周期之后空闲 %d、scratch %d、alloc %d（之前 %d），期望空闲裁回不超过 %d、空闲 + scratch 不少于它（quota：多留的已 close）",
					c.mode, p.pipeFree, p.pipeScratch, p.pipeAlloc, d.pool.pipeAlloc, limit)
			}
			if k := m.logLines(c.log); k == 0 {
				t.Errorf("日志里没有 %q：没有走到%s的失败分支", c.log, c.mode)
			}
			m.expectPipeFDs(t, d2, "一个周期之后")
		})
	}
}
