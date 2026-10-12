package clientrouter

import (
	"net/netip"
	"testing"
)

type sink struct{ packets int }

func (s *sink) WritePacket([]byte) error { s.packets++; return nil }
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
	if a.packets != 1 || b.packets != 1 {
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
	if a.packets != 1 || b.packets != 2 {
		t.Fatal("disconnect affected other device")
	}
}
