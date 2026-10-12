//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/yosida95/uritemplate/v3"

	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/platform"
	"github.com/sanderstripa/vpn/mist/internal/tunio"
)

func main() {
	configPath := flag.String("config", "/etc/mist/server.json", "path to server config")
	checkConfig := flag.Bool("check-config", false, "validate and migrate server config compatibility without starting the Edge")
	flag.Parse()
	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *checkConfig {
		log.Printf("MIST config OK: listen=%s authority=%s tun=%s client=%s mtu=%d", cfg.Listen, cfg.Authority, cfg.TUNCIDR, cfg.ClientCIDR, cfg.MTU)
		return
	}
	configureDecoy(cfg.DecoyRoot)
	authorizer := newEdgeAuthorizer(cfg)

	fallbackPrefix, err := netip.ParsePrefix(cfg.ClientCIDR)
	if err != nil || !fallbackPrefix.Addr().Is4() {
		log.Fatalf("client_cidr must be a valid IPv4 prefix: %q", cfg.ClientCIDR)
	}
	routePrefix, err := netip.ParsePrefix(cfg.AdvertiseCIDR)
	if err != nil || !routePrefix.Addr().Is4() {
		log.Fatalf("advertise_cidr must be a valid IPv4 prefix: %q", cfg.AdvertiseCIDR)
	}
	var clientV6, routeV6 netip.Prefix
	ipv6Enabled := cfg.ClientIPv6CIDR != ""
	if ipv6Enabled {
		clientV6, _ = netip.ParsePrefix(cfg.ClientIPv6CIDR)
		routeV6, _ = netip.ParsePrefix(cfg.AdvertiseIPv6CIDR)
	}

	dev, err := tunio.Create(cfg.TUNName, cfg.MTU)
	if err != nil {
		log.Fatalf("TUN: %v", err)
	}
	defer dev.Close()
	actualName := dev.Name()
	if actualName == "" {
		actualName = cfg.TUNName
	}
	state, err := platform.SetupEdgeDual(actualName, cfg.TUNCIDR, cfg.TUNIPv6CIDR, cfg.MTU, cfg.EnableNAT)
	if err != nil {
		log.Fatalf("edge network setup: %v", err)
	}
	defer platform.CleanupEdge(state)
	if err := platform.SetupPortHops(cfg.Listen, cfg.PortHopPorts); err != nil {
		log.Fatalf("port-hop setup: %v", err)
	}
	if len(cfg.PortHopPorts) > 0 {
		log.Printf("MIST: experimental TCP/UDP port-hop front doors enabled: %v -> %s", cfg.PortHopPorts, cfg.Listen)
	}

	cert, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		log.Fatalf("TLS certificate: %v", err)
	}
	echKeys, err := loadECHKeys(cfg.ECHKeys)
	if err != nil {
		log.Fatalf("ECH keys: %v", err)
	}

	proxy := connectip.Proxy{}
	template, err := uritemplate.New("https://" + cfg.Authority + cfg.Path)
	if err != nil {
		log.Fatalf("endpoint template: %v", err)
	}
	dispatcher := newEdgeDispatcher(dev)
	dispatcher.subnet, _ = netip.ParsePrefix(cfg.TUNCIDR)
	dispatcher.publish(cfg.StatsFile)
	unauthorized := func(w http.ResponseWriter, r *http.Request) {
		if !authorizer.AllowPublic(r) {
			http.NotFound(w, r)
			return
		}
		serveOrdinarySite(w, r)
	}

	h3Mux := http.NewServeMux()
	h3Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == cfg.Path && r.Method == http.MethodPost && r.Header.Get("X-MIST-Transport") == "lanes" {
			if !authorizer.Valid(r) {
				unauthorized(w, r)
				return
			}
			clientPrefix := authorizedPrefix(r)
			lane, err := parseLane(r)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			laneHub := dispatcher.laneHub(clientPrefix.Addr())
			release, err := laneHub.register(r.Header.Get("X-MIST-Session"), lane, w)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer release()
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			log.Printf("MIST: lane connected; assigned=%s transport=h3-lanes lane=%d", clientPrefix, lane)
			defer watchAccess(r, func() { _ = http.NewResponseController(w).SetWriteDeadline(time.Now()); _ = r.Body.Close() })()
			if err := pumpFramedInbound(r.Body, dispatcher, clientPrefix.Addr()); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("MIST: lane %d disconnected: %v", lane, err)
			}
			return
		}
		if r.URL.Path == cfg.Path && r.Method == http.MethodPost && r.Header.Get("X-MIST-Transport") == "stream" {
			if !authorizer.Valid(r) {
				unauthorized(w, r)
				return
			}
			clientPrefix := authorizedPrefix(r)
			log.Printf("MIST: client connected; assigned=%s transport=h3-stream", clientPrefix)
			if err := serveSingleStreamTransport(dispatcher, w, r, dev, false); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("MIST: h3-stream client disconnected: %v", err)
			}
			return
		}
		if r.URL.Path != cfg.Path || r.Method != http.MethodConnect {
			serveOrdinarySite(w, r)
			return
		}
		if !authorizer.Valid(r) {
			unauthorized(w, r)
			return
		}
		clientPrefix := authorizedPrefix(r)
		proxyReq, err := connectip.ParseProxyRequest(r, template)
		if err != nil {
			var parseErr *connectip.ProxyRequestParseError
			if errors.As(err, &parseErr) {
				w.WriteHeader(parseErr.HTTPStatus)
				return
			}
			http.NotFound(w, r)
			return
		}
		conn, err := proxy.Proxy(w, proxyReq)
		if err != nil {
			log.Printf("CONNECT-IP accept failed: %v", err)
			return
		}
		defer conn.Close()
		assignments := []netip.Prefix{clientPrefix}
		if ipv6Enabled {
			assignments = append(assignments, clientV6)
		}
		if err := conn.AssignAddresses(assignments); err != nil {
			log.Printf("address assignment failed: %v", err)
			return
		}
		routes := []connectip.IPRoute{{StartIP: routePrefix.Masked().Addr(), EndIP: lastIP(routePrefix), IPProtocol: 0}}
		if ipv6Enabled {
			routes = append(routes, connectip.IPRoute{StartIP: routeV6.Masked().Addr(), EndIP: lastIPv6(routeV6), IPProtocol: 0})
		}
		if err := conn.AdvertiseRoute(routes); err != nil {
			log.Printf("route advertisement failed: %v", err)
			return
		}
		release, err := dispatcher.register(clientPrefix.Addr(), &connectIPSink{conn: conn, dev: dev})
		if err != nil {
			log.Printf("CONNECT-IP rejected: %v", err)
			return
		}
		defer release()
		log.Printf("MIST: client connected; assigned=%s transport=h3-connect-ip ipv6=%v", clientPrefix, ipv6Enabled)
		defer watchAccess(r, func() { _ = conn.Close(); _ = r.Body.Close() })()
		if err := pumpConnectIPInbound(conn, dispatcher, clientPrefix.Addr()); err != nil {
			log.Printf("MIST: client disconnected: %v", err)
		}
	})

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}, EncryptedClientHelloKeys: echKeys}
	quicConfig := &quic.Config{
		EnableDatagrams:                true,
		InitialPacketSize:              1200,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
		DisablePathMTUDiscovery:        false,
		InitialStreamReceiveWindow:     fastInitialStreamWindow,
		MaxStreamReceiveWindow:         fastMaxStreamWindow,
		InitialConnectionReceiveWindow: fastInitialConnWindow,
		MaxConnectionReceiveWindow:     fastMaxConnWindow,
		MaxIncomingStreams:             cfg.MaxIncomingStreams,
		MaxIncomingUniStreams:          16,
		Tracer:                         qlog.DefaultConnectionTracer,
	}
	h3Server := &http3.Server{Addr: cfg.Listen, TLSConfig: tlsConfig, QUICConfig: quicConfig, Handler: h3Mux, EnableDatagrams: true, MaxHeaderBytes: 16 << 10, IdleTimeout: 90 * time.Second}
	h3Resources, err := openH3Listener(cfg.Listen, tlsConfig, quicConfig, authorizer.VerifyQUICSource)
	if err != nil {
		log.Fatalf("HTTP/3 listener: %v", err)
	}
	defer h3Resources.Close()

	webMux := http.NewServeMux()
	webMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cfg.Path || r.Method != http.MethodPost || r.ProtoMajor != 2 {
			serveOrdinarySite(w, r)
			return
		}
		if !authorizer.Valid(r) {
			unauthorized(w, r)
			return
		}
		clientPrefix := authorizedPrefix(r)
		log.Printf("MIST: client connected; assigned=%s transport=h2", clientPrefix)
		if err := serveSingleStreamTransport(dispatcher, w, r, dev, true); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("MIST: h2 client disconnected: %v", err)
		}
	})
	tcpServer := &http.Server{Addr: cfg.Listen, Handler: webMux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 0, WriteTimeout: 0, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, EncryptedClientHelloKeys: echKeys}}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 2)
	go func() {
		log.Printf("MIST web endpoint listening on TCP %s", cfg.Listen)
		if err := tcpServer.ListenAndServeTLS(cfg.Certificate, cfg.PrivateKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("TCP HTTPS server: %w", err)
		}
	}()
	go func() {
		log.Printf("MIST edge listening on UDP %s; authority=%s; adaptive-retry=%d/min", cfg.Listen, cfg.Authority, cfg.QUICRetryThresholdPerMinute)
		if err := h3Server.ServeListener(h3Resources.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP/3 server: %w", err)
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		log.Printf("server stopped: %v", err)
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tcpServer.Shutdown(shutdownCtx)
	_ = h3Server.Shutdown(shutdownCtx)
	h3Resources.Close()
}

func loadECHKeys(keys []config.ECHServerKeyConfig) ([]tls.EncryptedClientHelloKey, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	out := make([]tls.EncryptedClientHelloKey, 0, len(keys))
	for i, k := range keys {
		configBytes, err := base64.StdEncoding.DecodeString(k.ConfigBase64)
		if err != nil {
			return nil, fmt.Errorf("key %d config: %w", i, err)
		}
		privateKey, err := base64.StdEncoding.DecodeString(k.PrivateKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("key %d private key: %w", i, err)
		}
		if len(configBytes) == 0 || len(privateKey) == 0 {
			return nil, fmt.Errorf("key %d is empty", i)
		}
		out = append(out, tls.EncryptedClientHelloKey{Config: configBytes, PrivateKey: privateKey, SendAsRetry: k.SendAsRetry})
	}
	return out, nil
}

func serveOrdinarySite(w http.ResponseWriter, r *http.Request) { serveDecoyContent(w, r) }

func lastIP(prefix netip.Prefix) netip.Addr {
	p := prefix.Masked()
	a := p.Addr().As4()
	v := binary.BigEndian.Uint32(a[:])
	hostBits := uint(32 - p.Bits())
	if hostBits == 32 {
		v = ^uint32(0)
	} else if hostBits > 0 {
		v |= (uint32(1) << hostBits) - 1
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

func lastIPv6(prefix netip.Prefix) netip.Addr {
	p := prefix.Masked()
	out := p.Addr().As16()
	bits := p.Bits()
	for bit := bits; bit < 128; bit++ {
		byteIndex := bit / 8
		shift := 7 - uint(bit%8)
		out[byteIndex] |= 1 << shift
	}
	return netip.AddrFrom16(out)
}
