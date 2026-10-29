// fwdbench: minimal TCP/UDP benchmark tool for port forwarders.
//
//	fwdbench server -l 127.0.0.1:9000        （TCP 与 UDP 回显）
//	fwdbench rr   -c HOST:PORT -n 64 -s 64 -d 10s -w 1s
//	fwdbench crr  -c HOST:PORT -n 64 -s 64 -d 10s -w 1s
//	fwdbench hold -c HOST:PORT -n 5000 -s 64 -d 15s
//	fwdbench udp-rr -c HOST:PORT -n 64 -s 64 -d 10s -w 1s -timeout 200ms
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const dialTimeout = 2 * time.Second

var firstErr sync.Once

// countErr increments the error counter and reports the first error on stderr.
func countErr(errs *int64, err error) {
	atomic.AddInt64(errs, 1)
	firstErr.Do(func() { fmt.Fprintln(os.Stderr, "first error:", err) })
}

type result struct {
	Mode      string  `json:"mode"`
	Conns     int     `json:"conns"`
	Size      int     `json:"size"`
	DurationS float64 `json:"duration_s"`
	Ops       int     `json:"ops"`
	OpsPerSec float64 `json:"ops_per_sec"`
	Errors    int64   `json:"errors"`
	P50       float64 `json:"p50_us"`
	P90       float64 `json:"p90_us"`
	P99       float64 `json:"p99_us"`
	P999      float64 `json:"p999_us"`
	Max       float64 `json:"max_us"`
}

// udp-rr 的结果：ops 与各分位数同 rr；sent、lost 只计预热之后发出的请求（sent = ops + lost），
// late 是全程收到的迟到回显（其请求已按超时记为丢失）
type udpResult struct {
	result
	Sent    int64   `json:"sent"`
	Lost    int64   `json:"lost"`
	LostPct float64 `json:"lost_pct"`
	Late    int64   `json:"late"`
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fwdbench server|rr|crr|hold|udp-rr [flags]")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	listen := fs.String("l", "127.0.0.1:9000", "listen address (server)")
	target := fs.String("c", "127.0.0.1:9000", "target address")
	n := fs.Int("n", 64, "connections / workers")
	size := fs.Int("s", 64, "message size in bytes")
	dur := fs.Duration("d", 10*time.Second, "measure duration (hold: hold time)")
	warm := fs.Duration("w", time.Second, "warmup excluded from stats")
	timeout := fs.Duration("timeout", 200*time.Millisecond, "udp-rr: 等回显的超时，超时记为丢失")
	fs.Parse(os.Args[2:])

	switch mode {
	case "server":
		runServer(*listen)
	case "rr", "crr":
		runLoad(mode, *target, *n, *size, *dur, *warm)
	case "hold":
		runHold(*target, *n, *size, *dur)
	case "udp-rr":
		runUDPRR(*target, *n, *size, *dur, *warm, *timeout)
	default:
		usage()
	}
}

func runServer(addr string) {
	serveUDP(addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go echo(c)
	}
}

func echo(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 64<<10)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// serveUDP 在 addr 上做 UDP 回显（udp-rr 的后端）：每个包原样发回发送方。Go 对同一 socket 的读、写各自串行，
// 所以开 GOMAXPROCS 个 SO_REUSEPORT socket（内核按四元组把各流分到不同 socket），每个 socket 两个 goroutine，
// 一个在发时另一个能收
func serveUDP(addr string) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	for i := 0; i < max(runtime.GOMAXPROCS(0), 2); i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen udp:", err)
			os.Exit(1)
		}
		for j := 0; j < 2; j++ {
			go udpEcho(pc.(*net.UDPConn))
		}
	}
}

func udpEcho(c *net.UDPConn) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "udp read:", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if _, err := c.WriteToUDPAddrPort(buf[:n], from); err != nil {
			fmt.Fprintln(os.Stderr, "udp write:", err)
		}
	}
}

// roundTrip writes wbuf and reads back len(rbuf) bytes.
func roundTrip(c net.Conn, wbuf, rbuf []byte) error {
	if _, err := c.Write(wbuf); err != nil {
		return err
	}
	_, err := io.ReadFull(c, rbuf)
	return err
}

func crrOnce(addr string, wbuf, rbuf []byte) error {
	c, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return roundTrip(c, wbuf, rbuf)
}

func runLoad(mode, addr string, n, size int, dur, warm time.Duration) {
	start := time.Now().Add(warm)
	end := start.Add(dur)
	perWorker := max(1<<20/n, 16<<10)
	lats := make([][]int64, n)
	var errs int64
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		lats[i] = make([]int64, 0, perWorker)
		wg.Add(1)
		go func(lat *[]int64) {
			defer wg.Done()
			wbuf, rbuf := make([]byte, size), make([]byte, size)
			if mode == "rr" {
				c, err := net.DialTimeout("tcp", addr, dialTimeout)
				if err != nil {
					countErr(&errs, err)
					return
				}
				defer c.Close()
				c.SetDeadline(end.Add(5 * time.Second))
				for {
					t0 := time.Now()
					if t0.After(end) {
						return
					}
					if err := roundTrip(c, wbuf, rbuf); err != nil {
						countErr(&errs, err)
						return
					}
					if t0.After(start) {
						*lat = append(*lat, time.Since(t0).Nanoseconds())
					}
				}
			}
			for {
				t0 := time.Now()
				if t0.After(end) {
					return
				}
				if err := crrOnce(addr, wbuf, rbuf); err != nil {
					countErr(&errs, err)
					time.Sleep(time.Millisecond)
					continue
				}
				if t0.After(start) {
					*lat = append(*lat, time.Since(t0).Nanoseconds())
				}
			}
		}(&lats[i])
	}
	wg.Wait()

	out, _ := json.Marshal(summarize(mode, n, size, dur, lats, errs))
	fmt.Println(string(out))
}

// summarize 合并各工作者的延迟样本，算吞吐与分位数（rr、crr、udp-rr 共用）
func summarize(mode string, n, size int, dur time.Duration, lats [][]int64, errs int64) result {
	var all []int64
	for _, l := range lats {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	r := result{Mode: mode, Conns: n, Size: size, DurationS: dur.Seconds(), Ops: len(all), Errors: errs}
	r.OpsPerSec = round1(float64(len(all)) / dur.Seconds())
	if len(all) > 0 {
		r.P50, r.P90, r.P99, r.P999 = pct(all, 0.50), pct(all, 0.90), pct(all, 0.99), pct(all, 0.999)
		r.Max = us(all[len(all)-1])
	}
	return r
}

// udp-rr 请求的前 12 字节：工作者编号（4 字节）+ 序号（8 字节），其余为 0
const udpHdr = 12

// runUDPRR：n 个工作者各用一个 connected UDP socket（经转发器即一个会话），循环发 size 字节、等回显，计时同 rr。
// 超过 timeout 没等到回显就记一次丢失，接着发下一个请求；迟到的旧回显按序号识别并丢弃，不会算到新请求头上。
// 其他收发错误同 rr：计数后该工作者退出
func runUDPRR(addr string, n, size int, dur, warm, timeout time.Duration) {
	if size < udpHdr {
		fmt.Fprintf(os.Stderr, "udp-rr: -s 至少为 %d\n", udpHdr)
		os.Exit(2)
	}
	start := time.Now().Add(warm)
	end := start.Add(dur)
	perWorker := max(1<<20/n, 16<<10)
	lats := make([][]int64, n)
	sent, lost, late := make([]int64, n), make([]int64, n), make([]int64, n)
	var errs int64
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// 计数与样本放在局部变量里，退出时再写回，免得各工作者每次往返都写同一缓存行
			lat := make([]int64, 0, perWorker)
			var s, l, lt int64
			defer func() { lats[id], sent[id], lost[id], late[id] = lat, s, l, lt }()
			c, err := net.Dial("udp", addr)
			if err != nil {
				countErr(&errs, err)
				return
			}
			defer c.Close()
			wbuf, rbuf := make([]byte, size), make([]byte, 64<<10)
			binary.LittleEndian.PutUint32(wbuf, uint32(id))
			for seq := uint64(1); ; seq++ {
				t0 := time.Now()
				if t0.After(end) {
					return
				}
				in := t0.After(start)
				binary.LittleEndian.PutUint64(wbuf[4:], seq)
				if _, err := c.Write(wbuf); err != nil {
					countErr(&errs, err)
					return
				}
				if in {
					s++
				}
				c.SetReadDeadline(t0.Add(timeout))
				for {
					m, err := c.Read(rbuf)
					if errors.Is(err, os.ErrDeadlineExceeded) {
						if in {
							l++
						}
						break
					}
					if err != nil {
						countErr(&errs, err)
						return
					}
					if bytes.Equal(rbuf[:m], wbuf) {
						if in {
							lat = append(lat, time.Since(t0).Nanoseconds())
						}
						break
					}
					if m == size && binary.LittleEndian.Uint32(rbuf) == uint32(id) && binary.LittleEndian.Uint64(rbuf[4:]) < seq {
						lt++
						continue
					}
					countErr(&errs, fmt.Errorf("worker %d seq %d: unexpected reply of %d bytes: %x", id, seq, m, rbuf[:min(m, udpHdr)]))
				}
			}
		}(i)
	}
	wg.Wait()

	r := udpResult{result: summarize("udp-rr", n, size, dur, lats, errs)}
	for i := 0; i < n; i++ {
		r.Sent += sent[i]
		r.Lost += lost[i]
		r.Late += late[i]
	}
	if r.Sent > 0 {
		r.LostPct = math.Round(float64(r.Lost)/float64(r.Sent)*1e6) / 1e4
	}
	out, _ := json.Marshal(r)
	fmt.Println(string(out))
}

func runHold(addr string, n, size int, dur time.Duration) {
	sem := make(chan struct{}, 200)
	var mu sync.Mutex
	var conns []net.Conn
	var errs int64
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := net.DialTimeout("tcp", addr, dialTimeout)
			if err != nil {
				countErr(&errs, err)
				return
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if err := roundTrip(c, make([]byte, size), make([]byte, size)); err != nil {
				c.Close()
				countErr(&errs, err)
				return
			}
			c.SetDeadline(time.Time{})
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}()
	}
	wg.Wait()

	out, _ := json.Marshal(struct {
		Mode        string `json:"mode"`
		Established int    `json:"established"`
		Errors      int64  `json:"errors"`
	}{"hold", len(conns), errs})
	fmt.Println(string(out))
	time.Sleep(dur)
	for _, c := range conns {
		c.Close()
	}
}

func pct(sorted []int64, p float64) float64 {
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	return us(sorted[max(idx, 0)])
}

func us(ns int64) float64 { return round1(float64(ns) / 1e3) }

func round1(x float64) float64 { return math.Round(x*10) / 10 }
