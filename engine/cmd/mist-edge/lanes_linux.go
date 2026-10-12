//go:build linux

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/flowhash"
	"github.com/sanderstripa/vpn/mist/internal/h2frame"
	"github.com/sanderstripa/vpn/mist/internal/streambuf"
)

const (
	h3LaneCount              = 4
	h3LaneQueueDepth         = 2048
	h3LaneBackpressureWindow = 2 * time.Millisecond
	h3LaneFlushInterval      = 4 * time.Millisecond
	h3LaneWriteBuffer        = 256 << 10
)

type laneOutput struct {
	writer *streambuf.Writer
	queue  chan []byte
	done   chan struct{}

	mu     sync.RWMutex
	closed bool
}

type laneHub struct {
	dispatcher *edgeDispatcher
	address    netip.Addr

	mu         sync.RWMutex
	sessionID  string
	lanes      map[int]*laneOutput
	release    func()
	packetPool sync.Pool
	queueDrops atomic.Uint64
}

func newLaneHub(d *edgeDispatcher) *laneHub {
	h := &laneHub{
		dispatcher: d,
		lanes:      make(map[int]*laneOutput),
	}
	h.packetPool.New = func() any {
		return make([]byte, 2048)
	}
	return h
}

func (out *laneOutput) enqueue(buf []byte) bool {
	out.mu.RLock()
	defer out.mu.RUnlock()
	if out.closed {
		return false
	}

	// Fast path: almost every packet should enter the bounded queue without
	// waiting. If a short H3 scheduling stall fills the queue, apply a tiny
	// amount of backpressure instead of immediately destroying an inner TCP
	// congestion window by silently dropping the packet.
	select {
	case out.queue <- buf:
		return true
	default:
	}

	timer := time.NewTimer(h3LaneBackpressureWindow)
	defer timer.Stop()
	select {
	case out.queue <- buf:
		return true
	case <-timer.C:
		return false
	}
}

func (out *laneOutput) closeQueue() {
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.closed {
		return
	}
	out.closed = true
	close(out.queue)
}

func (h *laneHub) WritePacket(packet []byte) error {
	h.mu.RLock()
	if len(h.lanes) == 0 {
		h.mu.RUnlock()
		return nil
	}
	idx := flowhash.Index(packet, h3LaneCount)
	out := h.lanes[idx]
	if out == nil {
		for _, candidate := range h.lanes {
			out = candidate
			break
		}
	}
	h.mu.RUnlock()
	if out == nil {
		return nil
	}

	buf := h.packetPool.Get().([]byte)
	if cap(buf) < len(packet) {
		buf = make([]byte, len(packet))
	} else {
		buf = buf[:len(packet)]
	}
	copy(buf, packet)

	if out.enqueue(buf) {
		return nil
	}
	h.packetPool.Put(buf[:cap(buf)])
	drops := h.queueDrops.Add(1)
	if drops == 1 || drops%256 == 0 {
		log.Printf("MIST: h3-lanes server queue drops=%d lane=%d depth=%d", drops, idx, h3LaneQueueDepth)
	}
	return nil
}

func (h *laneHub) runLane(out *laneOutput) {
	defer close(out.done)
	defer out.writer.Close()

	failed := false
	for packet := range out.queue {
		if !failed {
			if err := h2frame.Write(out.writer, packet, false); err != nil {
				failed = true
			}
		}
		h.packetPool.Put(packet[:cap(packet)])
	}
}

func (h *laneHub) register(sessionID string, lane int, w http.ResponseWriter) (func(), error) {
	if sessionID == "" {
		return nil, fmt.Errorf("missing lane session")
	}
	if lane < 0 || lane >= h3LaneCount {
		return nil, fmt.Errorf("invalid lane %d", lane)
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("response writer cannot flush")
	}

	// The previous 1 ms / 64 KiB response flush cadence turned sustained
	// downloads into a large number of tiny HTTP/3 writes. Keep interactive
	// latency low, but give the lane enough time and buffer space to batch packet
	// records into efficient QUIC writes under load.
	writer := streambuf.New(w, h3LaneWriteBuffer, h3LaneFlushInterval, flusher.Flush)
	out := &laneOutput{
		writer: writer,
		queue:  make(chan []byte, h3LaneQueueDepth),
		done:   make(chan struct{}),
	}

	h.mu.Lock()
	if h.sessionID == "" {
		release, err := h.dispatcher.register(h.address, h)
		if err != nil {
			h.mu.Unlock()
			_ = writer.Close()
			return nil, err
		}
		h.sessionID = sessionID
		h.release = release
	} else if h.sessionID != sessionID {
		h.mu.Unlock()
		_ = writer.Close()
		return nil, fmt.Errorf("another lane session is active")
	}
	if _, exists := h.lanes[lane]; exists {
		h.mu.Unlock()
		_ = writer.Close()
		return nil, fmt.Errorf("lane %d already active", lane)
	}
	h.lanes[lane] = out
	h.mu.Unlock()

	go h.runLane(out)

	return func() {
		var release func()
		var removed *laneOutput

		h.mu.Lock()
		if cur := h.lanes[lane]; cur == out {
			delete(h.lanes, lane)
			removed = out
		}
		if len(h.lanes) == 0 {
			release = h.release
			h.release = nil
			h.sessionID = ""
		}
		h.mu.Unlock()

		if removed != nil {
			removed.closeQueue()
			<-removed.done
		}
		if release != nil {
			release()
		}
	}, nil
}

func parseLane(r *http.Request) (int, error) {
	v := r.Header.Get("X-MIST-Lane")
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid lane %q", v)
	}
	return n, nil
}
