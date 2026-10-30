// U5（D41–D43）的测试设施：带 UDP_SEGMENT cmsg 的 GSO 发送、开 UDP_GRO 的接收与 cmsg 解析、记录合并包的 UDP 后端，以及 tun 设备
// （读出内核发往 tun 的 IPv4/UDP 包并重组分片、向 tun 写入自造的 IPv4/UDP 包）。只用标准库。
//
// 内核语义（build/u5/probe/，Docker VM 6.8.0-117）：经 lo 的 GSO 发送（5.11 起不在发送端切分）到开了 UDP_GRO 的 socket 整包收到，
// 带 SOL_UDP/UDP_GRO cmsg（int 段长），没开的 socket 收到切开的数据报；lo 自己从不聚合普通数据报；只有 1 段的 GSO 发送不标记为
// GSO（5.4 起），收到的是普通数据报。tun 没有 TX 校验和 offload：6.11 以前任何带 UDP_SEGMENT 的发送经 tun 出去都返回 EIO（单段也是），
// 段长超过出口 MTU 时返回 EMSGSIZE（这个内核回移了 6.14 的改动；原版 6.13 及以前为 EINVAL），且先于 EIO 检查。
package tests

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	solUDP        = 17  // SOL_UDP（syscall 包没有定义）
	udpSegmentOpt = 103 // UDP_SEGMENT：发送 cmsg（或 setsockopt）的数据是 u16 段长
	udpGROOpt     = 104 // UDP_GRO：setsockopt 开启；接收 cmsg 的数据是 int 段长
	gsoMaxSegs    = 64  // tinymapper 一次 GSO 发送至多这么多段，多出的拆开发（D41）
)

// udpSegmentCmsg 返回带 UDP_SEGMENT 的控制消息（长度必须是 CMSG_LEN(sizeof(u16))，否则内核返回 EINVAL）
func udpSegmentCmsg(gso int) []byte {
	b := make([]byte, syscall.CmsgSpace(2))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = solUDP, udpSegmentOpt
	h.SetLen(syscall.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[syscall.CmsgLen(0):], uint16(gso))
	return b
}

// sendGSO 从 c 发出 msg：gso>0 时带 UDP_SEGMENT cmsg（内核按 gso 字节切段，最后一段可以更短），否则是普通数据报。
// to 为 nil 时 c 必须已 connect
func sendGSO(c *net.UDPConn, to *net.UDPAddr, msg []byte, gso int) error {
	var oob []byte
	if gso > 0 {
		oob = udpSegmentCmsg(gso)
	}
	_, _, err := c.WriteMsgUDP(msg, oob, to)
	return err
}

// setUDPOpt 在 c 上 setsockopt(SOL_UDP, opt, v)：opt 为 udpGROOpt 时开 GRO，为 udpSegmentOpt 时此后每次发送都按 v 切段
func setUDPOpt(c *net.UDPConn, opt, v int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), solUDP, opt, v) }); err != nil {
		return err
	}
	return serr
}

// readGRO 从 c 读一个消息（buf 至少 65536 字节），返回长度、UDP_GRO cmsg 里的段长（不是合并包时为 0）与源地址。
// 段长按 int 读（大端机器上按 u16 读会读错半边）；MSG_TRUNC/MSG_CTRUNC 报错
func readGRO(c *net.UDPConn, buf []byte) (n, gso int, from netip.AddrPort, err error) {
	oob := make([]byte, 128)
	n, oobn, flags, from, err := c.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		return 0, 0, from, err
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return n, 0, from, fmt.Errorf("来自 %s 的 %d 字节消息被截断（flags %#x）", from, n, flags)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return n, 0, from, err
	}
	for _, cm := range cmsgs {
		if cm.Header.Level == solUDP && cm.Header.Type == udpGROOpt && len(cm.Data) >= 4 {
			gso = int(int32(binary.NativeEndian.Uint32(cm.Data)))
		}
	}
	return n, gso, from, nil
}

// gsoPkt 是一次发出的内容：gso>0 时带 UDP_SEGMENT 发出，否则是普通数据报
type gsoPkt struct {
	data []byte
	gso  int
}

// segs 返回 p 在不开 GRO 的接收端看到的数据报：段数多于 1 时按 gso 切开，否则就是 data 本身（0 字节的包也算一个）
func (p gsoPkt) segs() [][]byte {
	if !p.merged() {
		return [][]byte{p.data}
	}
	var out [][]byte
	d := p.data
	for len(d) > p.gso {
		out = append(out, d[:p.gso])
		d = d[p.gso:]
	}
	return append(out, d)
}

// merged 报告 p 经 lo 到达开了 UDP_GRO 的 socket 时是不是一个合并包（多于 1 段的 GSO 发送；单段的不标记为 GSO）。
// 用例里的合并包都不超过 64400 字节：接近 65507 的 GSO 包在 lo 上可能已被切开（探针），不能精确预期 up_gro
func (p gsoPkt) merged() bool { return p.gso > 0 && len(p.data) > p.gso }

// forwarded 返回 tinymapper 转发 p 之后开了 UDP_GRO 的接收端看到的消息：合并包按 gsoMaxSegs 段一组拆开，各组带同样的段长发出，
// 只剩 1 段的一组不带 cmsg（普通数据报）；普通数据报原样
func (p gsoPkt) forwarded() []groMsg {
	if !p.merged() {
		return []groMsg{{data: p.data}}
	}
	var out []groMsg
	for d := p.data; len(d) > 0; {
		n := min(len(d), gsoMaxSegs*p.gso)
		m := groMsg{data: d[:n], gso: p.gso}
		if n <= p.gso {
			m.gso = 0
		}
		out = append(out, m)
		d = d[n:]
	}
	return out
}

// pktsSegs 把一串发送展开成数据报
func pktsSegs(pkts []gsoPkt) [][]byte {
	var out [][]byte
	for _, p := range pkts {
		out = append(out, p.segs()...)
	}
	return out
}

// pktsForwarded 把一串发送展开成 tinymapper 转发后 GRO 接收端看到的消息
func pktsForwarded(pkts []gsoPkt) []groMsg {
	var out []groMsg
	for _, p := range pkts {
		out = append(out, p.forwarded()...)
	}
	return out
}

// gsoTotals 返回一串发送的数据报数、字节数与以合并包到达的数据报数（tinymapper 的 pkts、bytes、gro 计数口径）
func gsoTotals(pkts ...[]gsoPkt) (n, nbytes, merged uint64) {
	for _, ps := range pkts {
		for _, p := range ps {
			s := uint64(len(p.segs()))
			n += s
			nbytes += uint64(len(p.data))
			if p.merged() {
				merged += s
			}
		}
	}
	return
}

// gsoData 返回 size 字节的内容：每个字节随 seed 与偏移变化，同一个包切出的各段内容各不相同，段边界或顺序错了逐字节比较能发现
func gsoData(seed, size int) []byte {
	b := make([]byte, size)
	x := uint32(seed) * 2654435761 // seed 的各位都散到 4 个字节里：seed 只差 256 的倍数时内容也不同
	for i := range b {
		b[i] = byte(x>>(8*(i%4))) ^ byte(i*31) ^ byte(i>>7)
	}
	return b
}

// gsoSend 是暂停期间从客户端 c 发出的一个包（gso>0 时带 UDP_SEGMENT）；to 为 nil 时 c 必须已 connect
type gsoSend struct {
	c  *net.UDPConn
	to *net.UDPAddr
	p  gsoPkt
}

// queueGSO 同 queueUDP，但每个包可以带 UDP_SEGMENT：开了 UDP_GRO 的监听 socket 把一个合并包整包收进队列
func queueGSO(t testing.TB, m *mapper, listen string, sends []gsoSend) {
	t.Helper()
	queueListen(t, m, listen, len(sends), func(i int) int { return len(sends[i].p.data) }, func(i int) error {
		return sendGSO(sends[i].c, sends[i].to, sends[i].p.data, sends[i].p.gso)
	})
}

// gsoReply 是暂停期间后端 be 发往会话 socket session 的一个回包（gso>0 时带 UDP_SEGMENT）
type gsoReply struct {
	be      *groRecorder
	session string
	p       gsoPkt
}

// queueGSOReplies 同 queueReplies，但回包可以带 UDP_SEGMENT：开了 UDP_GRO 的会话 socket 把一个合并包整包收进队列
func queueGSOReplies(t testing.TB, m *mapper, replies []gsoReply) {
	t.Helper()
	queueSessions(t, m, len(replies), func(i int) (string, string, int) {
		return replies[i].session, replies[i].be.addr, len(replies[i].p.data)
	}, func(i int) { replies[i].be.sendTo(t, replies[i].session, replies[i].p) })
}

// groMsg 是开了 UDP_GRO 的接收端读到的一个消息：gso 为 cmsg 里的段长，普通数据报为 0
type groMsg struct {
	data []byte
	gso  int
}

func (m groMsg) String() string { return fmt.Sprintf("%d B gso=%d", len(m.data), m.gso) }

// groRecorder 是按到达顺序记录每个消息（源地址、内容、段长）的 UDP 后端，不回显。gro 为 true 时 socket 开 UDP_GRO，
// 收到合并包时记下 cmsg 里的段长；否则每个数据报一个消息、段长为 0
type groRecorder struct {
	addr string
	conn *net.UDPConn
	mu   sync.Mutex
	msgs []recvMsg
	bad  []string // 截断等异常
}

type recvMsg struct {
	from string
	groMsg
}

func newGRORecorder(t testing.TB, addr string, gro bool) *groRecorder {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatalf("UDP 后端监听 %s 失败：%v", addr, err)
	}
	forceRcvBuf(conn)
	conn.SetWriteBuffer(4 << 20)
	if gro {
		if err := setUDPOpt(conn, udpGROOpt, 1); err != nil {
			t.Fatalf("后端 %s 开 UDP_GRO 失败：%v", addr, err)
		}
	}
	r := &groRecorder{addr: conn.LocalAddr().String(), conn: conn}
	go func() {
		buf := make([]byte, 70000)
		for {
			n, gso, from, err := readGRO(conn, buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			r.mu.Lock()
			if err != nil {
				r.bad = append(r.bad, err.Error())
			} else {
				r.msgs = append(r.msgs, recvMsg{from.String(), groMsg{append([]byte(nil), buf[:n]...), gso}})
			}
			r.mu.Unlock()
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return r
}

// forceRcvBuf 把测试自己的 UDP socket 的接收缓冲设为 8 MiB：不开 UDP_GRO 的 socket 收到 tinymapper 的 GSO 包时由内核切成数据报
// 再入队（udp_rcv_segment），一批几百个数据报的 truesize 之和超过 SetReadBuffer 受 rmem_max 截断后的 416 KiB，后面的被静默丢弃
// （sk_drops）。测试进程有 CAP_NET_ADMIN（tests/run.sh）时用 SO_RCVBUFFORCE，否则退回 SetReadBuffer
func forceRcvBuf(c *net.UDPConn) {
	rc, err := c.SyscallConn()
	if err == nil {
		var serr error
		rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 8<<20)
		})
		if serr == nil {
			return
		}
	}
	c.SetReadBuffer(8 << 20)
}

// drops 返回后端 socket 的 sk_drops（接收队列满时丢弃的包数），查不到时返回 -1
func (r *groRecorder) drops() int {
	ap := netip.MustParseAddrPort(r.addr)
	remote := "0.0.0.0:0"
	if ap.Addr().Is6() {
		remote = "[::]:0"
	}
	b, err := sockDiag(syscall.IPPROTO_UDP, r.addr, remote)
	if err != nil {
		return -1
	}
	return int(b.drops)
}

// count 返回收到的数据报数（合并包按段数计）
func (r *groRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.msgs {
		n += len(gsoPkt{m.data, m.gso}.segs())
	}
	return n
}

// wait 等到收到至少 n 个数据报，并要求没有截断的消息
func (r *groRecorder) wait(t testing.TB, n int) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		if got := r.count(); got < n {
			return fmt.Errorf("后端 %s 收到 %d 个数据报，期望 %d（后端 socket 的 sk_drops=%d）", r.addr, got, n, r.drops())
		}
		return nil
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bad) != 0 {
		t.Fatalf("后端 %s 收到异常的消息：%v", r.addr, r.bad)
	}
}

// bySource 等到收到至少 n 个数据报，返回按源地址分组、合并包按段切开的数据报（保持到达顺序），以及总数据报数与总字节数
func (r *groRecorder) bySource(t testing.TB, n int) (got map[string][][]byte, pkts, nbytes uint64) {
	t.Helper()
	r.wait(t, n)
	r.mu.Lock()
	defer r.mu.Unlock()
	got = map[string][][]byte{}
	for _, m := range r.msgs {
		for _, s := range (gsoPkt{m.data, m.gso}).segs() {
			got[m.from] = append(got[m.from], s)
			pkts++
			nbytes += uint64(len(s))
		}
	}
	return got, pkts, nbytes
}

// msgsBySource 等到收到至少 n 个数据报，返回按源地址分组的消息（保持到达顺序）
func (r *groRecorder) msgsBySource(t testing.TB, n int) map[string][]groMsg {
	t.Helper()
	r.wait(t, n)
	r.mu.Lock()
	defer r.mu.Unlock()
	got := map[string][]groMsg{}
	for _, m := range r.msgs {
		got[m.from] = append(got[m.from], m.groMsg)
	}
	return got
}

// sourceOf 返回第一个内容为 msg 的消息的源地址，没有则返回空串
func (r *groRecorder) sourceOf(msg []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if string(m.data) == string(msg) {
			return m.from
		}
	}
	return ""
}

// sendTo 从后端 socket 向 to（会话 socket 的地址）发出 p
func (r *groRecorder) sendTo(t testing.TB, to string, p gsoPkt) {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	if err := sendGSO(r.conn, ua, p.data, p.gso); err != nil {
		t.Fatalf("后端向 %s 发 %d 字节（gso %d）失败：%v", to, len(p.data), p.gso, err)
	}
}

// helloGRO 是 helloSession 用于 groRecorder 后端的写法：经 send 发出 msg，等后端收到后返回会话 socket 的地址
func helloGRO(t testing.TB, be *groRecorder, msg []byte, send func([]byte) error) string {
	t.Helper()
	for range 8 {
		if err := send(msg); err != nil {
			t.Fatalf("发送 %q 失败：%v", msg, err)
		}
		for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if src := be.sourceOf(msg); src != "" {
				return src
			}
		}
	}
	t.Fatalf("后端一直没收到 %q：会话没有建立", msg)
	return ""
}

// describeMsgs 概括一串消息：个数与前几个的长度、段长
func describeMsgs(msgs []groMsg) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d 个消息：", len(msgs))
	for i, m := range msgs {
		if i == 8 {
			b.WriteString(" …")
			break
		}
		fmt.Fprintf(&b, " [%v]", m)
	}
	return b.String()
}

func msgsEqual(a, b []groMsg) bool {
	return slices.EqualFunc(a, b, func(x, y groMsg) bool { return x.gso == y.gso && string(x.data) == string(y.data) })
}

// expectMsgsBySource 同 expectBySource，但比较的是 GRO 接收端看到的消息（内容与段长都要相同）。返回各客户端对应的源地址
func expectMsgsBySource(t testing.TB, got map[string][]groMsg, want [][]groMsg) []string {
	t.Helper()
	srcs := make([]string, len(want))
	used := map[string]bool{}
	ok := len(got) == len(want)
	if !ok {
		t.Errorf("后端看到 %d 个源地址，期望每个客户端一个（%d）", len(got), len(want))
	}
	for i, w := range want {
		for src, g := range got {
			if !used[src] && msgsEqual(g, w) {
				used[src], srcs[i] = true, src
				break
			}
		}
		if srcs[i] == "" {
			ok = false
			t.Errorf("客户端 %d 的消息（期望 %s）没有原样、按序、完整地出现在任何一个源地址上", i, describeMsgs(w))
		}
	}
	if !ok {
		for src, g := range got {
			t.Logf("后端源地址 %s：%s", src, describeMsgs(g))
		}
	}
	return srcs
}

// groClient 是开了 UDP_GRO、没有 connect 的客户端 socket：经 WriteToUDP 发往 tinymapper 的监听地址，回包按消息读出并核对源地址
type groClient struct {
	c      *net.UDPConn
	listen *net.UDPAddr
}

func newGROClient(t testing.TB, local, listen string) *groClient {
	t.Helper()
	to, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(local)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	forceRcvBuf(c)
	if err := setUDPOpt(c, udpGROOpt, 1); err != nil {
		t.Fatalf("客户端开 UDP_GRO 失败：%v", err)
	}
	return &groClient{c, to}
}

func (g *groClient) send(p gsoPkt) error { return sendGSO(g.c, g.listen, p.data, p.gso) }

// expect 依次读消息，要求与 want 的内容、段长、顺序都相同，且都来自监听地址
func (g *groClient) expect(t testing.TB, want []groMsg, who string) {
	t.Helper()
	buf := make([]byte, 70000)
	lp := netip.MustParseAddrPort(g.listen.String())
	lp = netip.AddrPortFrom(lp.Addr().Unmap(), lp.Port())
	for j, w := range want {
		g.c.SetReadDeadline(time.Now().Add(ioTimeout))
		n, gso, from, err := readGRO(g.c, buf)
		if err != nil {
			t.Fatalf("%s的第 %d 个消息（期望 %v）：%v", who, j, w, err)
		}
		if from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port()); from != lp && !lp.Addr().IsUnspecified() {
			t.Errorf("%s的第 %d 个消息来自 %s，期望来自监听地址 %s", who, j, from, lp)
		}
		if got := (groMsg{buf[:n], gso}); !msgsEqual([]groMsg{got}, []groMsg{w}) {
			t.Fatalf("%s的第 %d 个消息为 [%v]，期望 [%v]", who, j, got, w)
		}
	}
}

// ---- tun 设备 ----

// tunSeq 给每个 tun 设备分配不重复的名字与子网（用例并行）：第 n 个为 tpm5t<n>、10.55.<n>.0/24，本端 .1
var tunSeq atomic.Int32

// tunDev 是一个 IFF_TUN|IFF_NO_PI 设备：本端地址 local（10.55.n.1/24），内核把发往子网里其他地址的包交给它；后台读出
// IPv4/UDP 包、重组分片后按到达顺序记下（tunDatagram），也可以写入自造的 IPv4/UDP 包，内核当作从这块网卡收到的
type tunDev struct {
	name  string
	f     *os.File
	local netip.Addr
	ipID  atomic.Uint32

	mu     sync.Mutex
	dgrams []tunDatagram
	frags  int // 收到的 IP 分片数
	parts  map[[10]byte][]ipFrag
}

// tunDatagram 是内核从 tun 发出的一个 UDP 数据报（分片已重组），frags 为它的 IP 分片数（没分片为 0）
type tunDatagram struct {
	src, dst netip.AddrPort
	data     []byte
	frags    int
}

type ipFrag struct {
	off  int
	more bool
	data []byte
}

const (
	tunSetIff     = 0x400454ca // TUNSETIFF：_IOW('T', 202, int)，amd64、arm64 相同
	iffTun        = 0x0001
	iffNoPI       = 0x1000
	siocGIFFlags  = 0x8913
	siocSIFFlags  = 0x8914
	siocSIFAddr   = 0x8916
	siocSIFNetmsk = 0x891c
	siocSIFMTU    = 0x8922
	iffUp         = 0x1
	iffRunning    = 0x40
)

// needTun 用于要建 tun 设备的用例：没有 /dev/net/tun 时，容器中（TPM_IN_CONTAINER=1）判为失败（tests/run.sh 应以
// --device /dev/net/tun 启动容器），否则跳过
func needTun(t testing.TB) {
	t.Helper()
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		return
	}
	if os.Getenv("TPM_IN_CONTAINER") == "1" {
		t.Fatal("没有 /dev/net/tun：tests/run.sh 应以 --device /dev/net/tun 启动容器")
	}
	t.Skip("没有 /dev/net/tun，跳过 tun 用例")
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// newTun 建一个 tun 设备，配本端地址 10.55.n.1/24、MTU mtu 并 up，开始在后台读包；用例结束时关闭（设备随之删除）
func newTun(t testing.TB, mtu int) *tunDev {
	t.Helper()
	needTun(t)
	needNetAdmin(t)
	n := int(tunSeq.Add(1))
	if n > 250 {
		t.Fatal("tun 子网已分配完")
	}
	d := &tunDev{name: fmt.Sprintf("tpm5t%d", n), local: netip.AddrFrom4([4]byte{10, 55, byte(n), 1}), parts: map[[10]byte][]ipFrag{}}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("打开 /dev/net/tun 失败：%v", err)
	}
	var ifr [40]byte // struct ifreq：ifr_name[16]，联合体从偏移 16 起
	copy(ifr[:15], d.name)
	binary.NativeEndian.PutUint16(ifr[16:], iffTun|iffNoPI)
	if err := ioctl(fd, tunSetIff, unsafe.Pointer(&ifr[0])); err != nil {
		syscall.Close(fd)
		t.Fatalf("TUNSETIFF %s 失败：%v", d.name, err)
	}
	// 非阻塞 fd 交给 os.NewFile 时登记进 Go 的 netpoller，Read 可以带期限、Close 能唤醒阻塞的 Read
	d.f = os.NewFile(uintptr(fd), "/dev/net/tun:"+d.name)
	t.Cleanup(func() { d.f.Close() })

	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(s)
	setAddr := func(req uintptr, a [4]byte, what string) {
		var r [40]byte
		copy(r[:15], d.name)
		binary.NativeEndian.PutUint16(r[16:], syscall.AF_INET) // struct sockaddr_in：sin_family、sin_port、sin_addr（偏移 20）
		copy(r[20:24], a[:])
		if err := ioctl(s, req, unsafe.Pointer(&r[0])); err != nil {
			t.Fatalf("%s %s 失败：%v", what, d.name, err)
		}
	}
	setAddr(siocSIFAddr, d.local.As4(), "SIOCSIFADDR")
	setAddr(siocSIFNetmsk, [4]byte{255, 255, 255, 0}, "SIOCSIFNETMASK")
	var r [40]byte
	copy(r[:15], d.name)
	binary.NativeEndian.PutUint32(r[16:], uint32(mtu))
	if err := ioctl(s, siocSIFMTU, unsafe.Pointer(&r[0])); err != nil {
		t.Fatalf("SIOCSIFMTU %s %d 失败：%v", d.name, mtu, err)
	}
	if err := ioctl(s, siocGIFFlags, unsafe.Pointer(&r[0])); err != nil {
		t.Fatalf("SIOCGIFFLAGS %s 失败：%v", d.name, err)
	}
	binary.NativeEndian.PutUint16(r[16:], binary.NativeEndian.Uint16(r[16:])|iffUp|iffRunning)
	if err := ioctl(s, siocSIFFlags, unsafe.Pointer(&r[0])); err != nil {
		t.Fatalf("SIOCSIFFLAGS %s 失败：%v", d.name, err)
	}
	go d.readLoop()
	return d
}

// peer 返回子网里的第 host 个地址（10.55.n.host），host≥2 的都经这个 tun 出去
func (d *tunDev) peer(host byte) netip.Addr {
	a := d.local.As4()
	a[3] = host
	return netip.AddrFrom4(a)
}

// readLoop 读出内核发往 tun 的包：只要 IPv4/UDP（启用 IPv6 的网卡 up 后内核还会发路由器请求等），分片按 (源, 目的, ID) 重组
func (d *tunDev) readLoop() {
	buf := make([]byte, 70000)
	for {
		n, err := d.f.Read(buf)
		if err != nil {
			return
		}
		p := buf[:n]
		if n < 20 || p[0]>>4 != 4 || p[9] != syscall.IPPROTO_UDP {
			continue
		}
		ihl, total := int(p[0]&0xf)*4, int(binary.BigEndian.Uint16(p[2:]))
		if total > n || ihl < 20 || ihl > total {
			continue
		}
		fl := binary.BigEndian.Uint16(p[6:])
		frag := ipFrag{off: int(fl&0x1fff) * 8, more: fl&0x2000 != 0, data: append([]byte(nil), p[ihl:total]...)}
		var key [10]byte
		copy(key[:8], p[12:20])
		copy(key[8:], p[4:6])
		src, dst := netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		d.mu.Lock()
		nfrags := 0
		whole := frag.data
		if frag.off != 0 || frag.more {
			d.frags++
			d.parts[key] = append(d.parts[key], frag)
			whole = reassemble(d.parts[key])
			if whole == nil {
				d.mu.Unlock()
				continue
			}
			nfrags = len(d.parts[key])
			delete(d.parts, key)
		}
		if len(whole) >= 8 {
			ulen := int(binary.BigEndian.Uint16(whole[4:]))
			if ulen >= 8 && ulen <= len(whole) {
				d.dgrams = append(d.dgrams, tunDatagram{
					src:   netip.AddrPortFrom(src, binary.BigEndian.Uint16(whole[0:])),
					dst:   netip.AddrPortFrom(dst, binary.BigEndian.Uint16(whole[2:])),
					data:  whole[8:ulen],
					frags: nfrags,
				})
			}
		}
		d.mu.Unlock()
	}
}

// reassemble 在分片收齐（有末片且从 0 起连续）时返回重组后的 IP 载荷，否则返回 nil
func reassemble(fs []ipFrag) []byte {
	s := slices.Clone(fs)
	slices.SortFunc(s, func(a, b ipFrag) int { return a.off - b.off })
	var out []byte
	for _, f := range s {
		if f.off != len(out) {
			return nil
		}
		out = append(out, f.data...)
		if !f.more {
			return out
		}
	}
	return nil
}

// datagrams 等到 tun 上收到至少 n 个 UDP 数据报，返回全部（按到达顺序）与 IP 分片总数
func (d *tunDev) datagrams(t testing.TB, n int) ([]tunDatagram, int) {
	t.Helper()
	eventually(t, ioTimeout, 10*time.Millisecond, func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.dgrams) < n {
			return fmt.Errorf("tun %s 上收到 %d 个 UDP 数据报（%d 个 IP 分片未重组），期望 %d", d.name, len(d.dgrams), len(d.parts), n)
		}
		return nil
	})
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dgrams), d.frags
}

// bySource 把 tun 上收到的数据报按源地址分组（保持到达顺序），只要发往 dst 端口的
func tunBySource(dgrams []tunDatagram, dstPort uint16) map[netip.AddrPort][][]byte {
	got := map[netip.AddrPort][][]byte{}
	for _, g := range dgrams {
		if g.dst.Port() == dstPort {
			got[g.src] = append(got[g.src], g.data)
		}
	}
	return got
}

// inetChecksum 是 IP/UDP 的反码和校验
func inetChecksum(parts ...[]byte) uint16 {
	var s uint32
	for _, b := range parts {
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			s += uint32(b[len(b)-1]) << 8
		}
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

// writeUDP 向 tun 写入一个 src → dst 的 IPv4/UDP 包（IP 头与 UDP 校验和都正确，不分片），内核当作从这块网卡收到
func (d *tunDev) writeUDP(t testing.TB, src, dst netip.AddrPort, data []byte) {
	t.Helper()
	pkt := make([]byte, 28+len(data))
	ip := pkt[:20]
	ip[0], ip[8], ip[9] = 0x45, 64, syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(ip[4:], uint16(d.ipID.Add(1)))
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:], inetChecksum(ip))
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], data)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], s4[:])
	copy(pseudo[4:8], d4[:])
	pseudo[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
	cs := inetChecksum(pseudo, udp)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], cs)
	if _, err := d.f.Write(pkt); err != nil {
		t.Fatalf("向 tun %s 写入 %s → %s 的 %d 字节失败：%v", d.name, src, dst, len(data), err)
	}
}
