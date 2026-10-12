package telemetry

import (
	"testing"
	"time"
)

func TestMetricsSnapshot(t *testing.T) {
	m := New()
	m.TX(100)
	m.RX(200)
	m.Drop("inner_quic")
	m.Reconnect()
	m.DialFailure()
	m.DialLatency(1500 * time.Millisecond)
	s := m.Snapshot()
	if s.TXPackets != 1 || s.TXBytes != 100 || s.RXPackets != 1 || s.RXBytes != 200 { t.Fatalf("bad counters: %+v", s) }
	if s.InnerQUICDrops != 1 || s.DroppedPackets != 1 || s.Reconnects != 1 || s.DialFailures != 1 { t.Fatalf("bad event counters: %+v", s) }
	if s.Quality <= 0 || s.Quality > 100 { t.Fatalf("bad quality=%d", s.Quality) }
}

func TestIntentionalQUICDropDoesNotTankQuality(t *testing.T) {
	m := New()
	for i := 0; i < 10; i++ { m.TX(100) }
	for i := 0; i < 10; i++ { m.Drop("inner_quic") }
	if q := m.Snapshot().Quality; q < 90 { t.Fatalf("intentional policy drops should be discounted, quality=%d", q) }
}
