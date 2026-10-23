// fwdbench: minimal TCP benchmark tool for port forwarders.
//
//	fwdbench server -l 127.0.0.1:9000
//	fwdbench rr   -c HOST:PORT -n 64 -s 64 -d 10s -w 1s
//	fwdbench crr  -c HOST:PORT -n 64 -s 64 -d 10s -w 1s
//	fwdbench hold -c HOST:PORT -n 5000 -s 64 -d 15s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fwdbench server|rr|crr|hold [flags]")
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
	fs.Parse(os.Args[2:])

	switch mode {
	case "server":
		runServer(*listen)
	case "rr", "crr":
		runLoad(mode, *target, *n, *size, *dur, *warm)
	case "hold":
		runHold(*target, *n, *size, *dur)
	default:
		usage()
	}
}

func runServer(addr string) {
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
