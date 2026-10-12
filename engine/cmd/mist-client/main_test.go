package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func ipv4Packet(src, dst string, ttl byte) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	p[8] = ttl
	p[9] = 17
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	return p
}

func TestShouldProxyPacket(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"normal IPv4", ipv4Packet("10.64.0.2", "1.1.1.1", 128), true},
		{"ttl one", ipv4Packet("10.64.0.2", "1.1.1.1", 1), false},
		{"multicast", ipv4Packet("10.64.0.2", "224.0.0.251", 255), false},
		{"link local", ipv4Packet("10.64.0.2", "169.254.1.1", 64), false},
		{"broadcast", ipv4Packet("10.64.0.2", "255.255.255.255", 64), false},
		{"ipv6", append([]byte{0x60}, make([]byte, 39)...), false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldProxyPacket(tc.pkt); got != tc.want {
				t.Fatalf("shouldProxyPacket() = %v, want %v", got, tc.want)
			}
		})
	}
}


func TestReconnectDelayCapsAt15Seconds(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 15 * time.Second},
		{20, 15 * time.Second},
	}
	for _, tc := range cases {
		if got := reconnectDelay(tc.attempt); got != tc.want {
			t.Fatalf("attempt %d: got %s want %s", tc.attempt, got, tc.want)
		}
	}
}
