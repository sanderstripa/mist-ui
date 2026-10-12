package clientrouter

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type sink struct{ packets atomic.Int64 }

func (s *sink) WritePacket([]byte) error { s.packets.Add(1); return nil }
func wait(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("delivery did not complete")
}
func packet(src, dst string) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	p[8] = 64
	from := netip.MustParseAddr(src).As4()
	to := netip.MustParseAddr(dst).As4()
	copy(p[12:16], from[:])
	copy(p[16:20], to[:])
	return p
}
func TestIndependentClientsAndSourceIsolation(t *testing.T) {
	r := Router{}
	a, b := &sink{}, &sink{}
	ipA, ipB := netip.MustParseAddr("10.77.43.2"), netip.MustParseAddr("10.77.43.3")
	release, err := r.Register(ipA, a)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Register(ipB, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Register(ipA, &sink{}); err == nil {
		t.Fatal("same address attached twice")
	}
	_ = r.Deliver(packet("8.8.8.8", ipA.String()))
	_ = r.Deliver(packet("8.8.8.8", ipB.String()))
	wait(t, func() bool { return a.packets.Load() == 1 && b.packets.Load() == 1 })
	if a.packets.Load() != 1 || b.packets.Load() != 1 {
		t.Fatal("response routed to wrong device")
	}
	sub := netip.MustParsePrefix("10.77.43.0/24")
	if ValidInbound(packet(ipB.String(), "8.8.8.8"), ipA, sub) {
		t.Fatal("source spoof accepted")
	}
	if ValidInbound(packet(ipA.String(), ipB.String()), ipA, sub) {
		t.Fatal("cross-device traffic accepted")
	}
	if !ValidInbound(packet(ipA.String(), "8.8.8.8"), ipA, sub) {
		t.Fatal("valid traffic rejected")
	}
	release()
	release()
	_ = r.Deliver(packet("8.8.8.8", ipA.String()))
	_ = r.Deliver(packet("8.8.8.8", ipB.String()))
	wait(t, func() bool { return b.packets.Load() == 2 })
	if a.packets.Load() != 1 || b.packets.Load() != 2 {
		t.Fatal("disconnect affected other device")
	}
}

type blockedSink struct{ allow chan struct{} }

func (s *blockedSink) WritePacket([]byte) error { <-s.allow; return nil }
func TestSlowDeviceDoesNotBlockOtherDevices(t *testing.T) {
	r := Router{}
	slow := &blockedSink{make(chan struct{})}
	fast := &sink{}
	a, b := netip.MustParseAddr("10.77.43.2"), netip.MustParseAddr("10.77.43.3")
	releaseA, _ := r.Register(a, slow)
	releaseB, _ := r.Register(b, fast)
	defer releaseA()
	defer releaseB()
	defer close(slow.allow)
	finished := make(chan struct{})
	go func() {
		_ = r.Deliver(packet("8.8.8.8", a.String()))
		_ = r.Deliver(packet("8.8.8.8", b.String()))
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("slow peer blocked TUN dispatcher")
	}
	wait(t, func() bool { return fast.packets.Load() == 1 })
}
