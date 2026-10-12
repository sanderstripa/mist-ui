package tunio

import (
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

type Device struct {
	dev    tun.Device
	mtu    int
	offset int

	readBufs    [][]byte
	readSizes   []int
	readPackets [][]byte
	writePool sync.Pool
}

func Create(name string, mtu int) (*Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}
	d := &Device{dev: dev, mtu: mtu, offset: packetOffset()}
	batch := dev.BatchSize()
	d.readBufs = make([][]byte, batch)
	d.readSizes = make([]int, batch)
	d.readPackets = make([][]byte, batch)
	for i := range d.readBufs {
		d.readBufs[i] = make([]byte, d.offset+d.mtu+256)
	}
	d.writePool.New = func() any {
		return make([]byte, d.offset+d.mtu+256)
	}
	return d, nil
}

func (d *Device) Name() string {
	name, err := d.dev.Name()
	if err != nil {
		return ""
	}
	return name
}

func (d *Device) Close() error { return d.dev.Close() }

// ReadBatch returns packet views backed by reusable TUN buffers.
// The returned slices stay valid only until the next ReadBatch call.
// MIST consumes every packet synchronously before reading the next batch,
// avoiding per-packet allocation and copy on the hot path.
func (d *Device) ReadBatch() ([][]byte, error) {
	n, err := d.dev.Read(d.readBufs, d.readSizes, d.offset)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		d.readPackets[i] = d.readBufs[i][d.offset : d.offset+d.readSizes[i]]
	}
	return d.readPackets[:n], nil
}

func (d *Device) WriteBatch(packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	if d.offset == 0 {
		_, err := d.dev.Write(packets, 0)
		return err
	}
	for _, packet := range packets {
		if err := d.WritePacket(packet); err != nil {
			return err
		}
	}
	return nil
}

func (d *Device) WritePacket(packet []byte) error {
	// Wintun has no platform headroom requirement. Let the driver consume the
	// packet directly instead of copying it into a temporary buffer.
	if d.offset == 0 {
		_, err := d.dev.Write([][]byte{packet}, 0)
		return err
	}

	// Linux TUN with IFF_VNET_HDR needs headroom. Reuse a pooled buffer instead
	// of allocating a new one for every packet.
	need := d.offset + len(packet)
	buf := d.writePool.Get().([]byte)
	if cap(buf) < need {
		buf = make([]byte, need)
	} else {
		buf = buf[:need]
	}
	for i := 0; i < d.offset; i++ {
		buf[i] = 0
	}
	copy(buf[d.offset:], packet)
	_, err := d.dev.Write([][]byte{buf}, d.offset)
	d.writePool.Put(buf[:cap(buf)])
	return err
}
