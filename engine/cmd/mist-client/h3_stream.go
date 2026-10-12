package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"

	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/flowhash"
	"github.com/sanderstripa/vpn/mist/internal/h2frame"
	"github.com/sanderstripa/vpn/mist/internal/streambuf"
)

const clientH3LaneCount = 4

const (
	fastInitialStreamWindow = 4 << 20
	fastMaxStreamWindow     = 32 << 20
	fastInitialConnWindow   = 16 << 20
	fastMaxConnWindow       = 64 << 20
)

type h3Lane struct {
	requestBody   *io.PipeWriter
	requestWriter *streambuf.Writer
	responseBody  io.ReadCloser
	reader        *bufio.Reader
}

type lanePacket struct { buf []byte; n int }

type h3LanePacketConn struct {
	ctx context.Context
	cancel context.CancelFunc
	transport *http3.Transport
	lanes []*h3Lane
	readCh chan lanePacket
	errCh chan error
	closeOnce sync.Once
	pool sync.Pool
}

func dialMISTH3Stream(ctx context.Context, cfg config.ClientConfig) (packetTunnel, netip.Prefix, error) {
	assigned, err := netip.ParsePrefix(cfg.FallbackClientCIDR)
	if err != nil || !assigned.Addr().Is4() { return nil, netip.Prefix{}, fmt.Errorf("invalid fallback_client_cidr %q", cfg.FallbackClientCIDR) }
	tlsConf, err := makeClientTLSConfig(cfg, []string{http3.NextProtoH3})
	if err != nil { return nil, netip.Prefix{}, err }
	tr := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{
			InitialPacketSize: 1200,
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout: 60 * time.Second,
			KeepAlivePeriod: 20 * time.Second,
			DisablePathMTUDiscovery: cfg.PMTUMode == "off",
			InitialStreamReceiveWindow: fastInitialStreamWindow,
			MaxStreamReceiveWindow: fastMaxStreamWindow,
			InitialConnectionReceiveWindow: fastInitialConnWindow,
			MaxConnectionReceiveWindow: fastMaxConnWindow,
			Tracer: qlog.DefaultConnectionTracer,
		},
		Dial: func(dialCtx context.Context, _ string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
			return connectDialQUIC(dialCtx, cfg.Endpoint.DialAddress, tlsCfg, quicCfg)
		},
		DisableCompression: true,
	}
	laneCtx, cancel := context.WithCancel(ctx)
	conn := &h3LanePacketConn{ctx: laneCtx, cancel: cancel, transport: tr, readCh: make(chan lanePacket, 1024), errCh: make(chan error, 1)}
	conn.pool.New = func() any { return make([]byte, 2048) }
	var sidRaw [16]byte
	if _, err := rand.Read(sidRaw[:]); err != nil { cancel(); _ = tr.Close(); return nil, netip.Prefix{}, err }
	sessionID := hex.EncodeToString(sidRaw[:])
	for laneID := 0; laneID < clientH3LaneCount; laneID++ {
		lane, err := openH3Lane(laneCtx, tr, cfg, sessionID, laneID)
		if err != nil { _ = conn.Close(); return nil, netip.Prefix{}, fmt.Errorf("open H3 lane %d: %w", laneID, err) }
		conn.lanes = append(conn.lanes, lane)
		go conn.readLane(laneID, lane)
	}
	return conn, assigned, nil
}

func openH3Lane(ctx context.Context, tr *http3.Transport, cfg config.ClientConfig, sessionID string, laneID int) (*h3Lane, error) {
	pr, pw := io.Pipe()
	url := "https://" + cfg.Endpoint.Authority + cfg.Endpoint.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil { _ = pr.Close(); _ = pw.Close(); return nil, err }
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("X-MIST-Transport", "lanes")
	req.Header.Set("X-MIST-Session", sessionID)
	req.Header.Set("X-MIST-Lane", strconv.Itoa(laneID))
	rsp, err := tr.RoundTrip(req)
	if err != nil { _ = pr.Close(); _ = pw.Close(); return nil, err }
	if rsp.ProtoMajor != 3 { _ = rsp.Body.Close(); _ = pw.Close(); return nil, fmt.Errorf("HTTP/3 lane negotiated %s", rsp.Proto) }
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 { _ = rsp.Body.Close(); _ = pw.Close(); return nil, fmt.Errorf("HTTP/3 lane failed: %s", rsp.Status) }
	return &h3Lane{requestBody: pw, requestWriter: streambuf.New(pw, 64<<10, time.Millisecond, nil), responseBody: rsp.Body, reader: bufio.NewReaderSize(rsp.Body, 64<<10)}, nil
}

func (c *h3LanePacketConn) readLane(laneID int, lane *h3Lane) {
	for {
		buf := c.pool.Get().([]byte)
		n, err := h2frame.Read(lane.reader, buf)
		if err != nil {
			c.pool.Put(buf)
			select { case c.errCh <- fmt.Errorf("H3 lane %d: %w", laneID, err): default: }
			c.cancel(); return
		}
		select { case c.readCh <- lanePacket{buf: buf, n: n}: case <-c.ctx.Done(): c.pool.Put(buf); return }
	}
}

func (c *h3LanePacketConn) ReadPacketBatch(bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) { return 0, errors.New("invalid H3 batch buffers") }
	var first lanePacket
	select { case first = <-c.readCh: case err := <-c.errCh: return 0, err; case <-c.ctx.Done(): return 0, context.Cause(c.ctx) }
	if first.n > len(bufs[0]) { c.pool.Put(first.buf); return 0, fmt.Errorf("H3 lane packet %d exceeds buffer %d", first.n, len(bufs[0])) }
	copy(bufs[0][:first.n], first.buf[:first.n]); sizes[0] = first.n; c.pool.Put(first.buf); n := 1
	for n < len(bufs) {
		select {
		case p := <-c.readCh:
			if p.n > len(bufs[n]) { c.pool.Put(p.buf); return n, fmt.Errorf("H3 lane packet %d exceeds buffer %d", p.n, len(bufs[n])) }
			copy(bufs[n][:p.n], p.buf[:p.n]); sizes[n] = p.n; c.pool.Put(p.buf); n++
		default: return n, nil
		}
	}
	return n, nil
}

func (c *h3LanePacketConn) ReadPacket(dst []byte) (int, error) {
	select {
	case p := <-c.readCh:
		if p.n > len(dst) { c.pool.Put(p.buf); return 0, fmt.Errorf("H3 lane packet %d exceeds buffer %d", p.n, len(dst)) }
		copy(dst[:p.n], p.buf[:p.n]); c.pool.Put(p.buf); return p.n, nil
	case err := <-c.errCh: return 0, err
	case <-c.ctx.Done(): return 0, context.Cause(c.ctx)
	}
}

func (c *h3LanePacketConn) WritePacket(packet []byte) ([]byte, error) {
	if len(c.lanes) == 0 { return nil, errors.New("no H3 lanes") }
	lane := c.lanes[flowhash.Index(packet, len(c.lanes))]
	return nil, h2frame.Write(lane.requestWriter, packet, false)
}

func (c *h3LanePacketConn) Close() error {
	var out error
	c.closeOnce.Do(func() {
		c.cancel()
		for _, lane := range c.lanes { out = errors.Join(out, lane.requestWriter.Close(), lane.requestBody.Close(), lane.responseBody.Close()) }
		out = errors.Join(out, c.transport.Close())
	})
	return out
}
