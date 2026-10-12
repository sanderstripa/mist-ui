package packetpolicy

import (
	"encoding/binary"
	"net/netip"
)

type Policy struct {
	InnerQUIC string
	MSSClamp  int
	IPv6Mode string
}

type Result struct {
	Proxy    bool
	Drop     bool
	Modified bool
	Reason   string
}

// Apply evaluates and, when safe, normalizes an outbound packet before it is
// handed to the outer MIST transport. packet may be modified in place.
func (p Policy) Apply(packet []byte) Result {
	if len(packet) == 0 {
		return Result{Drop: true, Reason: "empty"}
	}
	switch packet[0] >> 4 {
	case 4:
		return p.applyIPv4(packet)
	case 6:
		return p.applyIPv6(packet)
	default:
		return Result{Drop: true, Reason: "unknown_ip_version"}
	}
}

func (p Policy) applyIPv4(packet []byte) Result {
	if len(packet) < 20 {
		return Result{Drop: true, Reason: "short_ipv4"}
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return Result{Drop: true, Reason: "bad_ipv4_header"}
	}
	if packet[8] <= 1 {
		return Result{Drop: true, Reason: "ttl_exhausted"}
	}
	src := netip.AddrFrom4([4]byte(packet[12:16]))
	dst := netip.AddrFrom4([4]byte(packet[16:20]))
	if !validUnicastV4Source(src) || !validUnicastV4Destination(dst) {
		return Result{Drop: true, Reason: "local_or_invalid_ipv4"}
	}

	if packet[9] == 17 && blocksInnerQUIC(p.InnerQUIC) && isUDP443QUIC(packet[ihl:]) {
		return Result{Drop: true, Reason: "inner_quic"}
	}
	modified := false
	if packet[9] == 6 && p.MSSClamp > 0 {
		modified = clampTCPMSSIPv4(packet, ihl, p.MSSClamp)
	}
	return Result{Proxy: true, Modified: modified}
}

func (p Policy) applyIPv6(packet []byte) Result {
	if len(packet) < 40 {
		return Result{Drop: true, Reason: "short_ipv6"}
	}
	if p.IPv6Mode != "tunnel" {
		return Result{Drop: true, Reason: "ipv6_blocked"}
	}
	src, ok := netip.AddrFromSlice(packet[8:24])
	if !ok {
		return Result{Drop: true, Reason: "bad_ipv6_source"}
	}
	dst, ok := netip.AddrFromSlice(packet[24:40])
	if !ok || src.IsUnspecified() || src.IsLoopback() || src.IsLinkLocalUnicast() || dst.IsUnspecified() || dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsMulticast() {
		return Result{Drop: true, Reason: "local_or_invalid_ipv6"}
	}

	// The MVP handles the fixed IPv6 header. Extension-header traversal is kept
	// deliberately conservative: such packets are proxied unchanged rather than
	// being rewritten incorrectly.
	next := packet[6]
	if next == 17 && blocksInnerQUIC(p.InnerQUIC) && isUDP443QUIC(packet[40:]) {
		return Result{Drop: true, Reason: "inner_quic"}
	}
	modified := false
	if next == 6 && p.MSSClamp > 0 {
		modified = clampTCPMSSIPv6(packet, 40, p.MSSClamp)
	}
	return Result{Proxy: true, Modified: modified}
}

func blocksInnerQUIC(mode string) bool {
	return mode == "block" || mode == "auto" || mode == ""
}

func isUDP443QUIC(udp []byte) bool {
	if len(udp) < 8+6 || binary.BigEndian.Uint16(udp[2:4]) != 443 {
		return false
	}
	payload := udp[8:]
	first := payload[0]
	// QUIC long header: Header Form=1 and Fixed Bit=1. A non-zero version is
	// required. Blocking all long-header packets here catches Initial / Retry /
	// Handshake across QUIC versions without hardcoding v1 packet-type bits.
	if first&0xC0 != 0xC0 || len(payload) < 6 {
		return false
	}
	return binary.BigEndian.Uint32(payload[1:5]) != 0
}

func validUnicastV4Source(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast()
}

func validUnicastV4Destination(a netip.Addr) bool {
	return validUnicastV4Source(a) && a != netip.MustParseAddr("255.255.255.255")
}

func clampTCPMSSIPv4(packet []byte, ipHeaderLen, clamp int) bool {
	if len(packet) < ipHeaderLen+20 {
		return false
	}
	tcp := packet[ipHeaderLen:]
	if tcp[13]&0x02 == 0 { // SYN
		return false
	}
	if !clampMSSOption(tcp, clamp) {
		return false
	}
	// Recompute TCP checksum.
	tcp[16], tcp[17] = 0, 0
	sum := uint32(0)
	sum = addWords(sum, packet[12:20])
	sum += uint32(packet[9])
	sum += uint32(len(tcp))
	sum = addWords(sum, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], finalizeChecksum(sum))
	return true
}

func clampTCPMSSIPv6(packet []byte, ipHeaderLen, clamp int) bool {
	if len(packet) < ipHeaderLen+20 {
		return false
	}
	tcp := packet[ipHeaderLen:]
	if tcp[13]&0x02 == 0 {
		return false
	}
	if !clampMSSOption(tcp, clamp) {
		return false
	}
	tcp[16], tcp[17] = 0, 0
	sum := uint32(0)
	sum = addWords(sum, packet[8:40])
	l := uint32(len(tcp))
	sum += uint32(l >> 16)
	sum += uint32(l & 0xffff)
	sum += 6 // next header TCP
	sum = addWords(sum, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], finalizeChecksum(sum))
	return true
}

func clampMSSOption(tcp []byte, clamp int) bool {
	hlen := int(tcp[12]>>4) * 4
	if hlen < 20 || hlen > len(tcp) {
		return false
	}
	for i := 20; i < hlen; {
		kind := tcp[i]
		switch kind {
		case 0:
			return false
		case 1:
			i++
			continue
		}
		if i+1 >= hlen {
			return false
		}
		ln := int(tcp[i+1])
		if ln < 2 || i+ln > hlen {
			return false
		}
		if kind == 2 && ln == 4 {
			old := int(binary.BigEndian.Uint16(tcp[i+2 : i+4]))
			if old > clamp {
				binary.BigEndian.PutUint16(tcp[i+2:i+4], uint16(clamp))
				return true
			}
			return false
		}
		i += ln
	}
	return false
}

func addWords(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func finalizeChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
