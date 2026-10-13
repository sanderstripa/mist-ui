package clientrouter

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

type Sink interface{ WritePacket([]byte) error }
type Stats struct {
	RX       uint64 `json:"rx"`
	TX       uint64 `json:"tx"`
	Active   bool   `json:"active"`
	Dropped  uint64 `json:"dropped"`
	LastSeen int64  `json:"last_seen"`
	Epoch    int64  `json:"epoch"`
}
type delivery struct {
	sink  Sink
	queue chan []byte
	done  chan struct{}
}
type Router struct {
	mu    sync.RWMutex
	sinks map[netip.Addr]*delivery
	stats map[netip.Addr]Stats
	epoch int64
}

func (r *Router) Register(ip netip.Addr, s Sink) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sinks == nil {
		r.sinks = map[netip.Addr]*delivery{}
		r.stats = map[netip.Addr]Stats{}
		r.epoch = time.Now().UnixNano()
	}
	if !ip.Is4() || s == nil {
		return nil, errors.New("IPv4 client required")
	}
	if r.sinks[ip] != nil {
		return nil, errors.New("device already connected")
	}
	e := &delivery{sink: s, queue: make(chan []byte, 256), done: make(chan struct{})}
	r.sinks[ip] = e
	go r.deliverWorker(ip, e)
	st := r.stats[ip]
	st.Active = true
	st.Epoch = r.epoch
	st.LastSeen = time.Now().Unix()
	r.stats[ip] = st
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			close(e.done)
			if r.sinks[ip] == e {
				delete(r.sinks, ip)
				st := r.stats[ip]
				st.Active = false
				r.stats[ip] = st
			}
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
	s.LastSeen = time.Now().Unix()
	r.stats[ip] = s
}
func (r *Router) Deliver(p []byte) error {
	ip, ok := IPv4(p, false)
	if !ok {
		return nil
	}
	r.mu.RLock()
	e := r.sinks[ip]
	r.mu.RUnlock()
	if e == nil {
		return nil
	}
	copyPacket := append([]byte(nil), p...)
	select {
	case <-e.done:
		return nil
	case e.queue <- copyPacket:
	default:
		r.mu.Lock()
		s := r.stats[ip]
		s.Dropped++
		r.stats[ip] = s
		r.mu.Unlock()
	}
	return nil
}
func (r *Router) deliverWorker(ip netip.Addr, e *delivery) {
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.sinks[ip] == e {
			delete(r.sinks, ip)
			s := r.stats[ip]
			s.Active = false
			r.stats[ip] = s
		}
	}()
	for {
		select {
		case <-e.done:
			return
		default:
		}
		select {
		case <-e.done:
			return
		case packet := <-e.queue:
			select {
			case <-e.done:
				return
			default:
			}
			if err := e.sink.WritePacket(packet); err != nil {
				return
			}
			r.mu.Lock()
			s := r.stats[ip]
			s.TX += uint64(len(packet))
			s.LastSeen = time.Now().Unix()
			r.stats[ip] = s
			r.mu.Unlock()
		}
	}
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
