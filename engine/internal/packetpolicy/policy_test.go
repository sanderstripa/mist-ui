package packetpolicy

import (
	"encoding/binary"
	"testing"
)

func TestBlocksInnerQUICOnUDP443(t *testing.T) {
	p := makeIPv4UDP443QUIC()
	r := (Policy{InnerQUIC: "auto", MSSClamp: 1200, IPv6Mode: "block"}).Apply(p)
	if !r.Drop || r.Reason != "inner_quic" {
		t.Fatalf("expected inner QUIC drop, got %+v", r)
	}
	r = (Policy{InnerQUIC: "allow", MSSClamp: 1200, IPv6Mode: "block"}).Apply(p)
	if !r.Proxy || r.Drop {
		t.Fatalf("expected QUIC to pass in allow mode, got %+v", r)
	}
}

func TestIPv6BlockedByDefault(t *testing.T) {
	p := make([]byte, 40)
	p[0] = 0x60
	p[6] = 59
	p[7] = 64
	p[8+15] = 2
	p[24] = 0x20
	p[25] = 0x01
	p[39] = 1
	r := (Policy{IPv6Mode: "block"}).Apply(p)
	if !r.Drop || r.Reason != "ipv6_blocked" {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestMSSClamp(t *testing.T) {
	p := makeIPv4TCPSYN(1460)
	r := (Policy{InnerQUIC: "allow", MSSClamp: 1200, IPv6Mode: "block"}).Apply(p)
	if !r.Proxy || !r.Modified {
		t.Fatalf("expected modified proxied packet, got %+v", r)
	}
	mss := binary.BigEndian.Uint16(p[20+22 : 20+24])
	if mss != 1200 {
		t.Fatalf("mss=%d, want 1200", mss)
	}
	if binary.BigEndian.Uint16(p[20+16:20+18]) == 0 {
		t.Fatalf("TCP checksum was not recomputed")
	}
}

func makeIPv4UDP443QUIC() []byte {
	p := make([]byte, 20+8+8)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	copy(p[12:16], []byte{10, 64, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:22], 50000)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-20))
	q := p[28:]
	q[0] = 0xC0
	binary.BigEndian.PutUint32(q[1:5], 1)
	q[5] = 8
	return p
}

func makeIPv4TCPSYN(mss uint16) []byte {
	p := make([]byte, 20+24)
	p[0] = 0x45
	p[8] = 64
	p[9] = 6
	copy(p[12:16], []byte{10, 64, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	tcp := p[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 6 << 4
	tcp[13] = 0x02
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	return p
}
