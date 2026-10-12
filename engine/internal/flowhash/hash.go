package flowhash

import (
	"encoding/binary"
	"hash/fnv"
)

// Index returns a stable, direction-independent lane for an IPv4 packet.
// Reverse traffic of the same TCP/UDP flow maps to the same lane.
func Index(packet []byte, lanes int) int {
	if lanes <= 1 {
		return 0
	}
	h := fnv.New64a()
	if len(packet) < 20 || packet[0]>>4 != 4 {
		_, _ = h.Write(packet)
		return int(h.Sum64() % uint64(lanes))
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		_, _ = h.Write(packet)
		return int(h.Sum64() % uint64(lanes))
	}

	proto := packet[9]
	var srcPort, dstPort uint16
	frag := binary.BigEndian.Uint16(packet[6:8])
	fragmentOffset := frag & 0x1fff
	if fragmentOffset == 0 && (proto == 6 || proto == 17) && len(packet) >= ihl+4 {
		srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	}

	var a, b [6]byte
	copy(a[:4], packet[12:16])
	copy(b[:4], packet[16:20])
	binary.BigEndian.PutUint16(a[4:], srcPort)
	binary.BigEndian.PutUint16(b[4:], dstPort)

	if less(b[:], a[:]) {
		a, b = b, a
	}
	_, _ = h.Write([]byte{proto})
	_, _ = h.Write(a[:])
	_, _ = h.Write(b[:])
	return int(h.Sum64() % uint64(lanes))
}

func less(a, b []byte) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}
