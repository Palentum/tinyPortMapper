package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const ioTimeout = 5 * time.Second

// tcpServer 是进程内的 TCP 后端，每个连接交给 handle 处理
type tcpServer struct {
	addr     string
	accepted atomic.Int64
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

func serveTCP(t testing.TB, addr string, handle func(net.Conn)) *tcpServer {
	t.Helper()
	return serveTCPConfig(t, net.ListenConfig{}, addr, handle)
}

// serveTCPConfig 同 serveTCP，监听 socket 由 lc 创建（lc.Control 可在 listen 之前设 socket 选项，accept 得到的连接继承它们）
func serveTCPConfig(t testing.TB, lc net.ListenConfig, addr string, handle func(net.Conn)) *tcpServer {
	t.Helper()
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("后端监听 %s 失败：%v；该端口上的 socket：%s", addr, err, portHolders(portOf(addr)))
	}
	s := &tcpServer{addr: ln.Addr().String(), conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.accepted.Add(1)
			s.mu.Lock()
			s.conns[c] = struct{}{}
			s.mu.Unlock()
			go func() {
				defer func() {
					c.Close()
					s.mu.Lock()
					delete(s.conns, c)
					s.mu.Unlock()
				}()
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	return s
}

// echoHandler 先发送 banner（可为空）再原样回显；读到 EOF 后关闭写方向
func echoHandler(banner string) func(net.Conn) {
	return func(c net.Conn) {
		if banner != "" {
			if _, err := io.WriteString(c, banner); err != nil {
				return
			}
		}
		io.Copy(c, c)
		c.(*net.TCPConn).CloseWrite()
	}
}

// udpServer 是进程内的 UDP 回显后端：回包 = prefix + 原数据，并按首次出现顺序记录源地址
type udpServer struct {
	addr  string
	mu    sync.Mutex
	peers []string
	seen  map[string]bool
}

func serveUDP(t testing.TB, addr, prefix string) *udpServer {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatalf("UDP 后端监听 %s 失败：%v", addr, err)
	}
	conn.SetReadBuffer(4 << 20)
	conn.SetWriteBuffer(4 << 20)
	s := &udpServer{addr: conn.LocalAddr().String(), seen: map[string]bool{}}
	go func() {
		buf := make([]byte, 70000)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				continue
			}
			s.mu.Lock()
			if !s.seen[from.String()] {
				s.seen[from.String()] = true
				s.peers = append(s.peers, from.String())
			}
			s.mu.Unlock()
			conn.WriteToUDP(append([]byte(prefix), buf[:n]...), from)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return s
}

func (s *udpServer) peerList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.peers...)
}

func dial(t testing.TB, addr string) *net.TCPConn {
	t.Helper()
	return dialFrom(t, "", addr)
}

// dialFrom 以本地地址 local（仅 IP，可为空）连接 addr
func dialFrom(t testing.TB, local, addr string) *net.TCPConn {
	t.Helper()
	d := net.Dialer{Timeout: ioTimeout}
	if local != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接 %s 失败：%v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*net.TCPConn)
}

func readLine(t testing.TB, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	defer c.SetReadDeadline(time.Time{})
	var line []byte
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			t.Fatalf("读取 banner 失败（已读 %q）：%v", line, err)
		}
		if b[0] == '\n' {
			return string(line)
		}
		line = append(line, b[0])
	}
}

// echo 写入 msg 并读回，要求回显内容完全一致
func echo(c net.Conn, msg []byte) error {
	c.SetDeadline(time.Now().Add(ioTimeout))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(msg); err != nil {
		return fmt.Errorf("写入失败：%w", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("读回显失败：%w", err)
	}
	if !bytes.Equal(got, msg) {
		return fmt.Errorf("回显内容不一致")
	}
	return nil
}

func mustEcho(t testing.TB, c net.Conn, msg string) {
	t.Helper()
	if err := echo(c, []byte(msg)); err != nil {
		t.Fatal(err)
	}
}

// closedWithin 等待对端关闭连接（EOF 或 RST），期间收到数据视为错误
func closedWithin(c net.Conn, within time.Duration) error {
	c.SetReadDeadline(time.Now().Add(within))
	defer c.SetReadDeadline(time.Time{})
	n, err := c.Read(make([]byte, 4096))
	switch {
	case n > 0:
		return fmt.Errorf("期望连接被关闭，却收到 %d 字节数据", n)
	case isTimeout(err):
		return fmt.Errorf("连接未在 %v 内被关闭", within)
	}
	return nil // EOF、RST 或其他读错误都说明连接已被关闭
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func expectClosed(t testing.TB, c net.Conn, within time.Duration) {
	t.Helper()
	if err := closedWithin(c, within); err != nil {
		t.Fatal(err)
	}
}

func udpDial(t testing.TB, local, addr string) *net.UDPConn {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var la *net.UDPAddr
	if local != "" {
		la = &net.UDPAddr{IP: net.ParseIP(local)}
	}
	c, err := net.DialUDP("udp", la, ra)
	if err != nil {
		t.Fatalf("UDP 连接 %s 失败：%v", addr, err)
	}
	c.SetReadBuffer(1 << 20)
	t.Cleanup(func() { c.Close() })
	return c
}

// udpRoundTrip 发送 msg 并返回回包
func udpRoundTrip(c *net.UDPConn, msg []byte) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	if _, err := c.Write(msg); err != nil {
		return nil, fmt.Errorf("UDP 发送 %d 字节失败：%w", len(msg), err)
	}
	buf := make([]byte, 70000)
	n, err := c.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("UDP 等待 %d 字节包的回包失败：%w", len(msg), err)
	}
	return buf[:n], nil
}

// udpReplyFrom 发送 msg，返回回包里后端的 prefix（回包 = prefix + msg）
func udpReplyFrom(t testing.TB, c *net.UDPConn, msg string) string {
	t.Helper()
	got, err := udpRoundTrip(c, []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	prefix, ok := strings.CutSuffix(string(got), msg)
	if !ok {
		t.Fatalf("UDP 回包 %q 不以 %q 结尾", got, msg)
	}
	return prefix
}

// 数据完整性协议：客户端先发 28 字节头（上行字节数、下行字节数、写块大小、种子），
// 随后双方并发收发伪随机数据；服务端收完后回 64 字节尾：sha256(收到的数据) + sha256(发出的数据)。
const streamHeaderLen = 28

func streamSeed(seed uint64, down bool) [32]byte {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:], seed)
	if down {
		s[8] = 1
	}
	return s
}

func transferTimeout(size int64) time.Duration {
	return 30*time.Second + time.Duration(size/(10<<20))*time.Second
}

// writeStream 以 chunk 为单位写出 size 字节伪随机数据，返回其 SHA-256
func writeStream(w io.Writer, size int64, chunk int, seed [32]byte) ([]byte, error) {
	gen := rand.NewChaCha8(seed)
	h := sha256.New()
	buf := make([]byte, chunk)
	for size > 0 {
		b := buf[:min(int64(chunk), size)]
		gen.Read(b)
		h.Write(b)
		if _, err := w.Write(b); err != nil {
			return nil, err
		}
		size -= int64(len(b))
	}
	return h.Sum(nil), nil
}

func readStream(r io.Reader, size int64) (hash.Hash, error) {
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.LimitReader(r, size), make([]byte, 256<<10))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, fmt.Errorf("收到 %d/%d 字节：%w", n, size, err)
	}
	return h, nil
}

func streamHandler(c net.Conn) {
	var hdr [streamHeaderLen]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	up := int64(binary.BigEndian.Uint64(hdr[0:]))
	down := int64(binary.BigEndian.Uint64(hdr[8:]))
	chunk := int(binary.BigEndian.Uint32(hdr[16:]))
	seed := binary.BigEndian.Uint64(hdr[20:])
	c.SetDeadline(time.Now().Add(transferTimeout(max(up, down))))
	sent := make(chan []byte, 1)
	go func() {
		sum, _ := writeStream(c, down, chunk, streamSeed(seed, true))
		sent <- sum
	}()
	recv, err := readStream(c, up)
	sum := <-sent
	if err != nil || sum == nil {
		return
	}
	if _, err := c.Write(append(recv.Sum(nil), sum...)); err != nil {
		return
	}
	io.Copy(io.Discard, c) // 由客户端先关闭
}

// transfer 经 addr 与 streamHandler 后端双向并发传输，比对两个方向的 SHA-256
func transfer(addr string, up, down int64, chunk int, seed uint64) error {
	c, err := net.DialTimeout("tcp", addr, ioTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	return transferOn(c, up, down, chunk, seed)
}

func transferOn(c net.Conn, up, down int64, chunk int, seed uint64) error {
	c.SetDeadline(time.Now().Add(transferTimeout(max(up, down))))
	var hdr [streamHeaderLen]byte
	binary.BigEndian.PutUint64(hdr[0:], uint64(up))
	binary.BigEndian.PutUint64(hdr[8:], uint64(down))
	binary.BigEndian.PutUint32(hdr[16:], uint32(chunk))
	binary.BigEndian.PutUint64(hdr[20:], seed)
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	type result struct {
		sum []byte
		err error
	}
	sent := make(chan result, 1)
	go func() {
		sum, err := writeStream(c, up, chunk, streamSeed(seed, false))
		sent <- result{sum, err}
	}()
	recv, err := readStream(c, down)
	if err != nil {
		return fmt.Errorf("下行：%w", err)
	}
	s := <-sent
	if s.err != nil {
		return fmt.Errorf("上行写入失败：%w", s.err)
	}
	var trailer [64]byte
	if _, err := io.ReadFull(c, trailer[:]); err != nil {
		return fmt.Errorf("读取校验尾失败：%w", err)
	}
	if !bytes.Equal(trailer[:32], s.sum) {
		return errors.New("上行（客户端→后端）SHA-256 不一致")
	}
	if !bytes.Equal(trailer[32:], recv.Sum(nil)) {
		return errors.New("下行（后端→客户端）SHA-256 不一致")
	}
	return nil
}
