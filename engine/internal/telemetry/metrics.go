package telemetry

import (
	"encoding/json"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	startedUnixNano atomic.Int64
	txPackets       atomic.Uint64
	txBytes         atomic.Uint64
	rxPackets       atomic.Uint64
	rxBytes         atomic.Uint64
	droppedPackets  atomic.Uint64
	innerQUICDrops  atomic.Uint64
	ipv6Drops       atomic.Uint64
	reconnects      atomic.Uint64
	dialFailures    atomic.Uint64
	fallbacks       atomic.Uint64
	bridgeErrors    atomic.Uint64
	lastDialMS      atomic.Int64
	lastErrorUnix   atomic.Int64
	lastTXUnixNano  atomic.Int64
	lastRXUnixNano  atomic.Int64

	mu        sync.RWMutex
	endpoint  string
	transport string
	lastFallbackReason string
	lastBridgeError    string
}

type Snapshot struct {
	StartedAt          time.Time `json:"started_at"`
	UptimeSeconds      int64     `json:"uptime_seconds"`
	Endpoint           string    `json:"endpoint,omitempty"`
	Transport          string    `json:"transport,omitempty"`
	TXPackets          uint64    `json:"tx_packets"`
	TXBytes            uint64    `json:"tx_bytes"`
	RXPackets          uint64    `json:"rx_packets"`
	RXBytes            uint64    `json:"rx_bytes"`
	DroppedPackets     uint64    `json:"dropped_packets"`
	InnerQUICDrops     uint64    `json:"inner_quic_drops"`
	IPv6Drops          uint64    `json:"ipv6_drops"`
	Reconnects         uint64    `json:"reconnects"`
	DialFailures       uint64    `json:"dial_failures"`
	Fallbacks          uint64    `json:"fallbacks"`
	BridgeErrors       uint64    `json:"bridge_errors"`
	LastDialMS         int64     `json:"last_dial_ms"`
	LastTXAgeMS        int64     `json:"last_tx_age_ms,omitempty"`
	LastRXAgeMS        int64     `json:"last_rx_age_ms,omitempty"`
	LastFallbackReason string    `json:"last_fallback_reason,omitempty"`
	LastBridgeError    string    `json:"last_bridge_error,omitempty"`
	Quality            int       `json:"quality"`
}

func New() *Metrics {
	m := &Metrics{}
	now := time.Now().UnixNano()
	m.startedUnixNano.Store(now)
	return m
}

func (m *Metrics) TX(n int) {
	if n <= 0 { return }
	m.txPackets.Add(1)
	m.txBytes.Add(uint64(n))
	m.lastTXUnixNano.Store(time.Now().UnixNano())
}
func (m *Metrics) RX(n int) {
	if n <= 0 { return }
	m.rxPackets.Add(1)
	m.rxBytes.Add(uint64(n))
	m.lastRXUnixNano.Store(time.Now().UnixNano())
}
func (m *Metrics) Drop(reason string) {
	m.droppedPackets.Add(1)
	switch reason {
	case "inner_quic":
		m.innerQUICDrops.Add(1)
	case "ipv6_blocked", "short_ipv6", "bad_ipv6_source", "local_or_invalid_ipv6":
		m.ipv6Drops.Add(1)
	}
}
func (m *Metrics) Reconnect() { m.reconnects.Add(1) }
func (m *Metrics) DialFailure() { m.dialFailures.Add(1); m.lastErrorUnix.Store(time.Now().Unix()) }
func (m *Metrics) DialLatency(d time.Duration) { m.lastDialMS.Store(d.Milliseconds()) }
func (m *Metrics) Active(endpoint, transport string) {
	m.mu.Lock(); defer m.mu.Unlock()
	m.endpoint, m.transport = endpoint, transport
}
func (m *Metrics) Fallback(reason string) {
	m.fallbacks.Add(1)
	m.mu.Lock(); m.lastFallbackReason = reason; m.mu.Unlock()
}
func (m *Metrics) BridgeError(err error) {
	if err == nil { return }
	m.bridgeErrors.Add(1)
	m.lastErrorUnix.Store(time.Now().Unix())
	m.mu.Lock(); m.lastBridgeError = err.Error(); m.mu.Unlock()
}

func (m *Metrics) Snapshot() Snapshot {
	now := time.Now()
	start := time.Unix(0, m.startedUnixNano.Load())
	m.mu.RLock()
	endpoint, transport := m.endpoint, m.transport
	fallbackReason, bridgeErr := m.lastFallbackReason, m.lastBridgeError
	m.mu.RUnlock()
	s := Snapshot{
		StartedAt: start,
		UptimeSeconds: int64(now.Sub(start).Seconds()),
		Endpoint: endpoint, Transport: transport,
		TXPackets: m.txPackets.Load(), TXBytes: m.txBytes.Load(),
		RXPackets: m.rxPackets.Load(), RXBytes: m.rxBytes.Load(),
		DroppedPackets: m.droppedPackets.Load(), InnerQUICDrops: m.innerQUICDrops.Load(), IPv6Drops: m.ipv6Drops.Load(),
		Reconnects: m.reconnects.Load(), DialFailures: m.dialFailures.Load(), Fallbacks: m.fallbacks.Load(), BridgeErrors: m.bridgeErrors.Load(), LastDialMS: m.lastDialMS.Load(),
		LastFallbackReason: fallbackReason, LastBridgeError: bridgeErr,
	}
	if v := m.lastTXUnixNano.Load(); v > 0 { s.LastTXAgeMS = now.Sub(time.Unix(0, v)).Milliseconds() }
	if v := m.lastRXUnixNano.Load(); v > 0 { s.LastRXAgeMS = now.Sub(time.Unix(0, v)).Milliseconds() }
	s.Quality = qualityScore(s)
	return s
}

func (m *Metrics) JSON() string {
	b, _ := json.Marshal(m.Snapshot())
	return string(b)
}

func qualityScore(s Snapshot) int {
	score := 100.0
	total := float64(s.TXPackets + s.DroppedPackets)
	if total > 0 {
		dropRate := float64(s.DroppedPackets) / total
		intentional := float64(s.InnerQUICDrops+s.IPv6Drops) / total
		effective := math.Max(0, dropRate-intentional)
		score -= math.Min(45, effective*500)
	}
	score -= math.Min(25, float64(s.Reconnects)*5)
	score -= math.Min(20, float64(s.DialFailures)*2)
	score -= math.Min(10, float64(s.BridgeErrors)*2)
	if s.LastDialMS > 0 {
		switch {
		case s.LastDialMS > 5000: score -= 10
		case s.LastDialMS > 2000: score -= 6
		case s.LastDialMS > 1000: score -= 3
		}
	}
	if score < 0 { score = 0 }
	if score > 100 { score = 100 }
	return int(math.Round(score))
}
