package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/h2frame"
)

type h2PacketConn struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	transport    *http.Transport
	readMu       sync.Mutex
	writeMu      sync.Mutex
	closeOnce    sync.Once
}

func dialMISTH2(ctx context.Context, cfg config.ClientConfig) (packetTunnel, netip.Prefix, error) {
	assigned, err := netip.ParsePrefix(cfg.FallbackClientCIDR)
	if err != nil || !assigned.Addr().Is4() { return nil, netip.Prefix{}, fmt.Errorf("invalid fallback_client_cidr %q", cfg.FallbackClientCIDR) }

	tlsConf, err := makeClientTLSConfig(cfg, []string{"h2"})
	if err != nil { return nil, netip.Prefix{}, err }
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsConf,
		DialTLSContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialH2TLS(dialCtx, cfg, tlsConf)
		},
	}

	pr, pw := io.Pipe()
	url := "https://" + cfg.Endpoint.Authority + cfg.Endpoint.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil { _ = pr.Close(); _ = pw.Close(); tr.CloseIdleConnections(); return nil, netip.Prefix{}, err }
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")

	client := &http.Client{Transport: tr}
	rsp, err := client.Do(req)
	if err != nil { _ = pr.Close(); _ = pw.Close(); tr.CloseIdleConnections(); return nil, netip.Prefix{}, fmt.Errorf("HTTP/2 fallback connect: %w", err) }
	if rsp.ProtoMajor != 2 { _ = rsp.Body.Close(); _ = pr.Close(); _ = pw.Close(); tr.CloseIdleConnections(); return nil, netip.Prefix{}, fmt.Errorf("HTTP/2 fallback negotiated %s", rsp.Proto) }
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 { _ = rsp.Body.Close(); _ = pr.Close(); _ = pw.Close(); tr.CloseIdleConnections(); return nil, netip.Prefix{}, fmt.Errorf("HTTP/2 fallback failed: %s", rsp.Status) }
	return &h2PacketConn{requestBody: pw, responseBody: rsp.Body, transport: tr}, assigned, nil
}

func dialH2TLS(ctx context.Context, cfg config.ClientConfig, tlsConf *tls.Config) (net.Conn, error) {
	directRaw := func() (net.Conn, error) {
		return connectDialer().DialContext(ctx, "tcp", cfg.Endpoint.DialAddress)
	}
	conn, directErr := dialAndVerifyH2(ctx, tlsConf, directRaw)
	if directErr == nil { return conn, nil }
	if cfg.RealityFallbackSOCKS5 == "" { return nil, directErr }

	// Retry through the external adapter on any direct-path failure, including
	// TCP connect, TLS handshake, certificate/SNI interference and ALPN failure.
	// A censor can allow TCP/443 yet disrupt TLS, so falling back only on the
	// raw TCP dial error would miss an important failure mode.
	log.Printf("MIST: direct H2/TLS path failed; trying configured external Reality SOCKS5 adapter: %v", directErr)
	proxyRaw := func() (net.Conn, error) {
		return dialSOCKS5(ctx, cfg.RealityFallbackSOCKS5, cfg.Endpoint.DialAddress)
	}
	conn, proxyErr := dialAndVerifyH2(ctx, tlsConf, proxyRaw)
	if proxyErr != nil {
		return nil, errors.Join(fmt.Errorf("direct H2/TLS: %w", directErr), fmt.Errorf("Reality adapter H2/TLS: %w", proxyErr))
	}
	return conn, nil
}

func dialAndVerifyH2(ctx context.Context, tlsConf *tls.Config, rawDial func() (net.Conn, error)) (net.Conn, error) {
	raw, err := rawDial()
	if err != nil { return nil, err }
	tc := tls.Client(raw, tlsConf.Clone())
	if err := tc.HandshakeContext(ctx); err != nil { _ = raw.Close(); return nil, err }
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		got := tc.ConnectionState().NegotiatedProtocol
		_ = tc.Close()
		return nil, fmt.Errorf("server did not negotiate HTTP/2 (ALPN=%q)", got)
	}
	return tc, nil
}

// dialSOCKS5 implements the small no-auth CONNECT subset needed by the
// external Reality adapter. Reality itself remains owned by the configured
// local core; MIST only asks its SOCKS5 listener for a TCP stream to the edge.
func dialSOCKS5(ctx context.Context, proxyAddress, targetAddress string) (net.Conn, error) {
	conn, err := connectDialer().DialContext(ctx, "tcp", proxyAddress)
	if err != nil { return nil, fmt.Errorf("Reality SOCKS5 dial: %w", err) }
	fail := func(e error) (net.Conn, error) { _ = conn.Close(); return nil, e }
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline { _ = conn.SetDeadline(deadline); defer conn.SetDeadline(time.Time{}) }
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil { return fail(err) }
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil { return fail(err) }
	if hello != [2]byte{5, 0} { return fail(fmt.Errorf("Reality SOCKS5 proxy rejected no-auth method: %v", hello)) }

	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil { return fail(err) }
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil { return fail(err) }
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil { req = append(req, 1); req = append(req, v4...) } else { req = append(req, 4); req = append(req, ip.To16()...) }
	} else {
		if len(host) > 255 { return fail(errors.New("Reality SOCKS5 target hostname too long")) }
		req = append(req, 3, byte(len(host))); req = append(req, host...)
	}
	var port [2]byte; binary.BigEndian.PutUint16(port[:], uint16(port64)); req = append(req, port[:]...)
	if _, err := conn.Write(req); err != nil { return fail(err) }
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil { return fail(err) }
	if head[0] != 5 || head[1] != 0 { return fail(fmt.Errorf("Reality SOCKS5 CONNECT failed: reply=%d", head[1])) }
	var discard int
	switch head[3] {
	case 1: discard = 4
	case 4: discard = 16
	case 3:
		var n [1]byte; if _, err := io.ReadFull(conn, n[:]); err != nil { return fail(err) }; discard = int(n[0])
	default: return fail(fmt.Errorf("Reality SOCKS5 invalid address type %d", head[3]))
	}
	buf := make([]byte, discard+2)
	if _, err := io.ReadFull(conn, buf); err != nil { return fail(err) }
	return conn, nil
}

func (c *h2PacketConn) ReadPacket(dst []byte) (int, error) {
	c.readMu.Lock(); defer c.readMu.Unlock(); return h2frame.Read(c.responseBody, dst)
}
func (c *h2PacketConn) WritePacket(packet []byte) ([]byte, error) {
	c.writeMu.Lock(); defer c.writeMu.Unlock(); return nil, h2frame.Write(c.requestBody, packet, true)
}
func (c *h2PacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = errors.Join(c.requestBody.Close(), c.responseBody.Close()); c.transport.CloseIdleConnections() })
	return err
}
