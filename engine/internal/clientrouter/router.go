package clientrouter

import (
	"errors"
	"net/netip"
	"sync"
)

type Sink interface{ WritePacket([]byte) error }
type Stats struct {
	RX     uint64 `json:"rx"`
	TX     uint64 `json:"tx"`
	Active bool   `json:"active"`
}
type Router struct {
	mu    sync.RWMutex
	sinks map[netip.Addr]Sink
	stats map[netip.Addr]Stats
}

func (r *Router) Register(ip netip.Addr, s Sink) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sinks == nil {
		r.sinks = map[netip.Addr]Sink{}
		r.stats = map[netip.Addr]Stats{}
	}
	if !ip.Is4() || s == nil {
		return nil, errors.New("IPv4 client required")
	}
	if r.sinks[ip] != nil {
		return nil, errors.New("device already connected")
	}
	r.sinks[ip] = s
	st := r.stats[ip]
	st.Active = true
	r.stats[ip] = st
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			delete(r.sinks, ip)
			st := r.stats[ip]
			st.Active = false
			r.stats[ip] = st
		})
	}, nil
}
func IPv4(p []byte, source bool) (netip.Addr, bool) {
	if len(p) < 20 || p[0]>>4 != 4 || int(p[0]&15)*4 < 20 || int(p[0]&15)*4 > len(p) {
		return netip.Addr{}, false
	}
	n := 16
	if source {
		n = 12
	}
	return netip.AddrFrom4([4]byte(p[n : n+4])), true
}
func ValidInbound(p []byte, ip netip.Addr, subnet netip.Prefix) bool {
	src, ok := IPv4(p, true)
	dst, dok := IPv4(p, false)
	return ok && dok && src == ip && p[8] > 1 && !dst.IsUnspecified() && !dst.IsLoopback() && !dst.IsMulticast() && !dst.IsLinkLocalUnicast() && !subnet.Contains(dst)
}
func (r *Router) Inbound(ip netip.Addr, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats[ip]
	s.RX += uint64(n)
	r.stats[ip] = s
}
func (r *Router) Deliver(p []byte) error {
	ip, ok := IPv4(p, false)
	if !ok {
		return nil
	}
	r.mu.RLock()
	sink := r.sinks[ip]
	r.mu.RUnlock()
	if sink == nil {
		return nil
	}
	if err := sink.WritePacket(p); err != nil {
		return err
	}
	r.mu.Lock()
	s := r.stats[ip]
	s.TX += uint64(len(p))
	r.stats[ip] = s
	r.mu.Unlock()
	return nil
}
func (r *Router) Snapshot() map[string]Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]Stats{}
	for ip, s := range r.stats {
		out[ip.String()] = s
	}
	return out
}
