package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/packetpolicy"
	"github.com/sanderstripa/vpn/mist/internal/telemetry"
	"github.com/sanderstripa/vpn/mist/internal/tunio"
)

type dialOutcome struct {
	conn      packetTunnel
	assigned  netip.Prefix
	transport string
	endpoint  config.EndpointConfig
}

// dialMISTMulti resolves the signed startup manifest (when configured), then
// tries endpoints serially in health-aware order. Serial dialing deliberately
// avoids a parallel TLS/QUIC handshake burst.
func dialMISTMulti(ctx context.Context, cfg config.ClientConfig, mode string, metrics *telemetry.Metrics) (dialOutcome, error) {
	eps, discoveryErr := resolvedEndpointCandidates(ctx, cfg)
	if discoveryErr != nil && len(eps) == 0 { return dialOutcome{}, discoveryErr }
	if discoveryErr != nil { log.Printf("MIST: endpoint discovery unavailable, using static endpoints: %v", discoveryErr) }

	var joined error
	for _, ep := range orderedEndpoints(eps) {
		attempt := cfg
		attempt.Endpoint = ep
		started := time.Now()
		conn, assigned, transport, err := dialMIST(ctx, attempt, mode)
		dialTime := time.Since(started)
		metrics.DialLatency(dialTime)
		if err == nil {
			recordEndpointSuccess(ep, dialTime)
			metrics.Active(ep.DialAddress, transport)
			if mode == "auto" && transport != "h3-lanes" { metrics.Fallback("h3-lanes unavailable; selected " + transport) }
			return dialOutcome{conn: conn, assigned: assigned, transport: transport, endpoint: ep}, nil
		}
		recordEndpointFailure(ep, dialTime)
		metrics.DialFailure()
		joined = errors.Join(joined, fmt.Errorf("%s via %s: %w", ep.Authority, ep.DialAddress, err))
		if ctx.Err() != nil { break }
	}
	if joined == nil { joined = errors.New("no MIST endpoints configured") }
	return dialOutcome{}, joined
}

func endpointDialAddresses(cfg config.ClientConfig) []string {
	eps := knownEndpointCandidates(cfg)
	out := make([]string, 0, len(eps))
	seen := make(map[string]struct{}, len(eps))
	for _, ep := range eps {
		if _, ok := seen[ep.DialAddress]; ok { continue }
		seen[ep.DialAddress] = struct{}{}
		out = append(out, ep.DialAddress)
	}
	return out
}

func jitteredReconnectDelay(attempt int) time.Duration {
	base := reconnectDelay(attempt)
	x := time.Now().UnixNano()%4001 - 2000
	factor := 1.0 + float64(x)/10000.0
	return time.Duration(float64(base) * factor)
}

func startTelemetry(ctx context.Context, m *telemetry.Metrics, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done(): return
			case <-t.C: log.Printf("MIST telemetry: %s", m.JSON())
			}
		}
	}()
}

func bridgeWithPolicy(ctx context.Context, conn packetTunnel, dev *tunio.Device, policy packetpolicy.Policy, metrics *telemetry.Metrics) error {
	errCh := make(chan error, 2)
	go func() {
		for {
			packets, err := dev.ReadBatch()
			if err != nil { errCh <- fmt.Errorf("read TUN: %w", err); return }
			for _, packet := range packets {
				decision := policy.Apply(packet)
				if decision.Drop || !decision.Proxy { metrics.Drop(decision.Reason); continue }
				icmp, err := conn.WritePacket(packet)
				if err != nil { errCh <- fmt.Errorf("send MIST packet: %w", err); return }
				metrics.TX(len(packet))
				if len(icmp) > 0 {
					if err := dev.WritePacket(icmp); err != nil { errCh <- fmt.Errorf("write local ICMP: %w", err); return }
					metrics.RX(len(icmp))
				}
			}
		}
	}()
	go func() {
		if br, ok := conn.(packetBatchReader); ok {
			const batchSize = 64
			bufs := make([][]byte, batchSize)
			sizes := make([]int, batchSize)
			views := make([][]byte, batchSize)
			for i := range bufs { bufs[i] = make([]byte, 65535) }
			for {
				n, err := br.ReadPacketBatch(bufs, sizes)
				if n > 0 {
					for i := 0; i < n; i++ { views[i] = bufs[i][:sizes[i]]; metrics.RX(sizes[i]) }
					if writeErr := dev.WriteBatch(views[:n]); writeErr != nil { errCh <- fmt.Errorf("write TUN batch: %w", writeErr); return }
				}
				if err != nil { errCh <- fmt.Errorf("receive H3 packet batch: %w", err); return }
			}
		}
		buf := make([]byte, 65535)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil { errCh <- fmt.Errorf("receive MIST packet: %w", err); return }
			metrics.RX(n)
			if err := dev.WritePacket(buf[:n]); err != nil { errCh <- fmt.Errorf("write TUN: %w", err); return }
		}
	}()
	select {
	case <-ctx.Done(): return context.Cause(ctx)
	case err := <-errCh: metrics.BridgeError(err); return err
	}
}

// shouldProxyPacket is retained for the existing regression tests. Production
// traffic uses the richer packetpolicy.Policy directly.
func shouldProxyPacket(packet []byte) bool {
	return packetpolicy.Policy{InnerQUIC: "allow", IPv6Mode: "block"}.Apply(packet).Proxy
}
