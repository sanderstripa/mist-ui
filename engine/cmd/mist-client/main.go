package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/yosida95/uritemplate/v3"

	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/packetpolicy"
	"github.com/sanderstripa/vpn/mist/internal/platform"
	"github.com/sanderstripa/vpn/mist/internal/telemetry"
	"github.com/sanderstripa/vpn/mist/internal/tunio"
)

type packetTunnel interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

type packetBatchReader interface { ReadPacketBatch([][]byte, []int) (int, error) }

func main() {
	configPath := flag.String("config", "client.json", "path to client config")
	recoverOnly := flag.Bool("recover", false, "restore MIST network changes and exit")
	transportMode := flag.String("transport", "auto", "transport mode: auto, h3s, h3, or h2")
	socksListen := flag.String("socks", "", "Connect loopback SOCKS listener (no OS routing)")
	flag.Parse()
	if *transportMode != "auto" && *transportMode != "h3s" && *transportMode != "h3" && *transportMode != "h2" { log.Fatalf("transport: expected auto, h3s, h3, or h2; got %q", *transportMode) }
	if *recoverOnly {
		if err := platform.RecoverClient(); err != nil { log.Fatalf("recover network: %v", err) }
		log.Printf("MIST: network settings restored"); return
	}

	cfg, err := config.LoadClient(*configPath)
	if err != nil { log.Fatalf("config: %v", err) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM); defer stop()
	metrics := telemetry.New(); startTelemetry(ctx, metrics, time.Duration(cfg.TelemetryIntervalSeconds)*time.Second)
	if *socksListen != "" { if err := runConnectSOCKS(ctx,cfg,*transportMode,*socksListen,metrics); err != nil { log.Printf("SOCKS stopped: %v",err); os.Exit(1) }; return }
	out, err := dialMISTMulti(ctx, cfg, *transportMode, metrics)
	if err != nil { log.Fatalf("connect: %v", err) }
	log.Printf("MIST: connected to %s via %s", out.endpoint.Authority, out.endpoint.DialAddress)

	dev, err := tunio.Create(cfg.TUNName, cfg.MTU)
	if err != nil { _ = out.conn.Close(); log.Fatalf("TUN: %v", err) }
	defer dev.Close()
	actualName := dev.Name(); if actualName == "" { actualName = cfg.TUNName }

	netState, err := platform.SetupClientMulti(actualName, out.assigned, endpointDialAddresses(cfg), cfg.DNS, cfg.MTU)
	if err != nil { _ = out.conn.Close(); log.Fatalf("network setup: %v", err) }
	defer platform.CleanupClientMulti(netState)
	if cfg.IPv6Mode == "tunnel" {
		v6, _ := netip.ParsePrefix(cfg.FallbackClientIPv6CIDR)
		if err := platform.ConfigureClientIPv6(actualName, v6); err != nil {
			platform.CleanupClientMulti(netState); _ = out.conn.Close(); log.Fatalf("IPv6 network setup: %v", err)
		}
		defer platform.CleanupClientIPv6(actualName)
		log.Printf("MIST: IPv6 tunnel enabled; address=%s", v6)
	} else {
		log.Printf("MIST: IPv6 leak protection active; native IPv6 is blocked")
	}

	policy := packetpolicy.Policy{InnerQUIC: cfg.InnerQUICPolicy, MSSClamp: cfg.MSSClamp, IPv6Mode: cfg.IPv6Mode}
	log.Printf("MIST: interface=%s address=%s transport=%s mtu=%d mss=%d inner-quic=%s pmtu=%s kill-switch=%s", actualName, out.assigned, out.transport, cfg.MTU, cfg.MSSClamp, cfg.InnerQUICPolicy, cfg.PMTUMode, cfg.KillSwitch)
	if err := runWithReconnect(ctx, cfg, *transportMode, out, dev, actualName, policy, metrics); err != nil && !errors.Is(err, context.Canceled) { log.Printf("MIST: tunnel stopped: %v", err) }
}

func runWithReconnect(ctx context.Context, cfg config.ClientConfig, transportMode string, current dialOutcome, dev *tunio.Device, tunName string, policy packetpolicy.Policy, metrics *telemetry.Metrics) error {
	assigned := current.assigned
	for {
		err := bridgeWithPolicy(ctx, current.conn, dev, policy, metrics)
		_ = current.conn.Close()
		if ctx.Err() != nil { return context.Cause(ctx) }
		if err == nil { err = errors.New("tunnel closed") }
		log.Printf("MIST: connection lost: %v", err)
		if cfg.KillSwitch == "fail_open" { log.Printf("MIST: fail-open policy selected; restoring direct network and exiting"); return err }
		log.Printf("MIST: kill switch remains active; direct traffic is blocked")
		for attempt := 0; ; attempt++ {
			delay := jitteredReconnectDelay(attempt); log.Printf("MIST: reconnecting in %s", delay)
			timer := time.NewTimer(delay)
			select { case <-ctx.Done(): if !timer.Stop() { <-timer.C }; return context.Cause(ctx); case <-timer.C: }
			next, dialErr := dialMISTMulti(ctx, cfg, transportMode, metrics)
			if dialErr != nil { if ctx.Err() != nil { return context.Cause(ctx) }; log.Printf("MIST: reconnect failed: %v", dialErr); continue }
			if next.assigned != assigned { _ = next.conn.Close(); return fmt.Errorf("server changed assigned address from %s to %s during reconnect", assigned, next.assigned) }
			metrics.Reconnect(); current = next
			log.Printf("MIST: reconnected; endpoint=%s interface=%s address=%s transport=%s", next.endpoint.DialAddress, tunName, assigned, next.transport); break
		}
	}
}

func reconnectDelay(attempt int) time.Duration {
	switch { case attempt <= 0: return time.Second; case attempt == 1: return 2*time.Second; case attempt == 2: return 4*time.Second; case attempt == 3: return 8*time.Second; default: return 15*time.Second }
}

func dialMIST(ctx context.Context, cfg config.ClientConfig, mode string) (packetTunnel, netip.Prefix, string, error) {
	if mode == "h2" {
		if !cfg.H2Fallback { return nil, netip.Prefix{}, "", errors.New("HTTP/2 fallback is disabled in client config") }
		conn, assigned, err := dialMISTH2(ctx, cfg); return conn, assigned, "h2", err
	}
	if mode == "h3s" { conn, assigned, err := dialMISTH3Stream(ctx, cfg); return conn, assigned, "h3-lanes", err }
	if mode == "auto" {
		streamConn, streamAssigned, streamErr := dialMISTH3Stream(ctx, cfg)
		if streamErr == nil { return streamConn, streamAssigned, "h3-lanes", nil }
		log.Printf("MIST: HTTP/3 lanes unavailable: %v", streamErr); log.Printf("MIST: trying standard CONNECT-IP over HTTP/3")
	}
	conn, assigned, err := dialMISTH3(ctx, cfg)
	if err == nil { return conn, assigned, "h3-connect-ip", nil }
	if mode == "h3" { return nil, netip.Prefix{}, "", err }
	h3Err := err
	if !cfg.H2Fallback { return nil, netip.Prefix{}, "", h3Err }
	log.Printf("MIST: CONNECT-IP HTTP/3 unavailable: %v", h3Err); log.Printf("MIST: trying HTTP/2 fallback over TCP/443")
	h2Conn, h2Assigned, h2Err := dialMISTH2(ctx, cfg)
	if h2Err != nil { return nil, netip.Prefix{}, "", errors.Join(fmt.Errorf("HTTP/3 CONNECT-IP: %w", h3Err), fmt.Errorf("HTTP/2 fallback: %w", h2Err)) }
	return h2Conn, h2Assigned, "h2", nil
}

func dialMISTH3(ctx context.Context, cfg config.ClientConfig) (packetTunnel, netip.Prefix, error) {
	tlsConf, err := makeClientTLSConfig(cfg, []string{http3.NextProtoH3}); if err != nil { return nil, netip.Prefix{}, err }
	tr := &connectip.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, HandshakeIdleTimeout: 10*time.Second, MaxIdleTimeout: 60*time.Second, KeepAlivePeriod: 20*time.Second, DisablePathMTUDiscovery: cfg.PMTUMode == "off", Tracer: qlog.DefaultConnectionTracer},
		DialAddr: func(ctx context.Context, _ string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) { return connectDialQUIC(ctx, cfg.Endpoint.DialAddress, tlsConf, quicConf) },
	}
	template, err := uritemplate.New("https://"+cfg.Endpoint.Authority+cfg.Endpoint.Path); if err != nil { return nil, netip.Prefix{}, fmt.Errorf("endpoint template: %w", err) }
	req, err := connectip.NewRequest(ctx, template); if err != nil { return nil, netip.Prefix{}, err }; req.Header().Set("Authorization", "Bearer "+cfg.Token)
	conn, rsp, err := tr.Dial(req)
	if err != nil { if rsp != nil { return nil, netip.Prefix{}, fmt.Errorf("CONNECT-IP failed (%s): %w", rsp.Status, err) }; return nil, netip.Prefix{}, err }
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second); defer cancel()
	if _, err := conn.Routes(waitCtx); err != nil { _ = conn.Close(); return nil, netip.Prefix{}, fmt.Errorf("receive route advertisement: %w", err) }
	assignments, err := conn.ReceiveAddressAssignment(waitCtx); if err != nil { _ = conn.Close(); return nil, netip.Prefix{}, fmt.Errorf("receive address assignment: %w", err) }
	var gotV4 netip.Prefix
	var gotV6 netip.Prefix
	for _, a := range assignments {
		if a.Rejected() { continue }
		if a.IPPrefix.Addr().Is4() { gotV4 = a.IPPrefix }
		if a.IPPrefix.Addr().Is6() { gotV6 = a.IPPrefix }
	}
	if !gotV4.IsValid() { _ = conn.Close(); return nil, netip.Prefix{}, errors.New("server did not assign an IPv4 address") }
	if cfg.IPv6Mode == "tunnel" {
		wantV6, _ := netip.ParsePrefix(cfg.FallbackClientIPv6CIDR)
		if !gotV6.IsValid() || gotV6 != wantV6 { _ = conn.Close(); return nil, netip.Prefix{}, fmt.Errorf("server IPv6 assignment %s does not match configured %s", gotV6, wantV6) }
	}
	return conn, gotV4, nil
}

func makeClientTLSConfig(cfg config.ClientConfig, nextProtos []string) (*tls.Config, error) {
	tlsConf := &tls.Config{ServerName: serverName(cfg.Endpoint.Authority), MinVersion: tls.VersionTLS13, NextProtos: nextProtos}
	if cfg.Endpoint.ECHConfigBase64 != "" { ech, err := base64.StdEncoding.DecodeString(cfg.Endpoint.ECHConfigBase64); if err != nil { return nil, fmt.Errorf("decode ECH config: %w", err) }; tlsConf.EncryptedClientHelloConfigList = ech }
	return tlsConf, nil
}

func serverName(authority string) string { if host, _, err := net.SplitHostPort(authority); err == nil { return host }; return strings.Trim(authority, "[]") }
