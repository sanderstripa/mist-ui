//go:build linux

package main

import (
	"encoding/json"
	"github.com/sanderstripa/vpn/mist/internal/clientrouter"
	"github.com/sanderstripa/vpn/mist/internal/tunio"
	"net/netip"
	"os"
	"sync"
	"time"
)

type edgeDispatcher struct {
	dev    *tunio.Device
	router clientrouter.Router
	subnet netip.Prefix
	mu     sync.Mutex
	hubs   map[netip.Addr]*laneHub
}

func newEdgeDispatcher(dev *tunio.Device) *edgeDispatcher {
	d := &edgeDispatcher{dev: dev, hubs: map[netip.Addr]*laneHub{}}
	go d.run()
	return d
}
func (d *edgeDispatcher) register(ip netip.Addr, s clientrouter.Sink) (func(), error) {
	return d.router.Register(ip, s)
}
func (d *edgeDispatcher) laneHub(ip netip.Addr) *laneHub {
	d.mu.Lock()
	defer d.mu.Unlock()
	h := d.hubs[ip]
	if h == nil {
		h = newLaneHub(d)
		h.address = ip
		d.hubs[ip] = h
	}
	return h
}
func (d *edgeDispatcher) inbound(p []byte, ip netip.Addr) error {
	if !clientrouter.ValidInbound(p, ip, d.subnet) {
		return nil
	}
	if err := d.dev.WritePacket(p); err != nil {
		return err
	}
	d.router.Inbound(ip, len(p))
	return nil
}
func (d *edgeDispatcher) run() {
	for {
		packets, err := d.dev.ReadBatch()
		if err != nil {
			return
		}
		for _, p := range packets {
			_ = d.router.Deliver(p)
		}
	}
}
func (d *edgeDispatcher) publish(path string) {
	if path == "" {
		return
	}
	go func() {
		for {
			b, _ := json.Marshal(d.router.Snapshot())
			tmp := path + ".tmp"
			if os.WriteFile(tmp, b, 0600) == nil {
				_ = os.Rename(tmp, path)
			}
			time.Sleep(2 * time.Second)
		}
	}()
}
