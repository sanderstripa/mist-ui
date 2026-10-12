//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/h2frame"
	"github.com/sanderstripa/vpn/mist/internal/streambuf"
	"github.com/sanderstripa/vpn/mist/internal/tunio"
)

type framedResponseSink struct {
	writer *streambuf.Writer
	pad    bool
}

func (s *framedResponseSink) WritePacket(packet []byte) error {
	return h2frame.Write(s.writer, packet, s.pad)
}

func serveSingleStreamTransport(d *edgeDispatcher, w http.ResponseWriter, r *http.Request, dev *tunio.Device, pad bool) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("HTTP response writer does not support flushing")
	}
	writer := streambuf.New(w, 64<<10, time.Millisecond, flusher.Flush)
	defer writer.Close()

	sink := &framedResponseSink{writer: writer, pad: pad}
	release, err := d.register(authorizedPrefix(r).Addr(), sink)
	if err != nil {
		return err
	}
	defer release()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	defer watchAccess(r, func() { _ = r.Body.Close() })()
	return pumpFramedInbound(r.Body, d, authorizedPrefix(r).Addr())
}

func pumpFramedInbound(body io.ReadCloser, d *edgeDispatcher, ip netip.Addr) error {
	defer body.Close()
	reader := bufio.NewReaderSize(body, 64<<10)
	buf := make([]byte, 65535)
	for {
		n, err := h2frame.Read(reader, buf)
		if err != nil {
			return fmt.Errorf("read stream packet: %w", err)
		}
		if err := d.inbound(buf[:n], ip); err != nil {
			return fmt.Errorf("inject stream packet into edge TUN: %w", err)
		}
	}
}
