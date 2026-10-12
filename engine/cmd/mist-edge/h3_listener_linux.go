//go:build linux

package main

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

type h3ListenerResources struct {
	packet    net.PacketConn
	transport *quic.Transport
	listener  *quic.Listener
}

func openH3Listener(addr string, tlsConf *tls.Config, quicConf *quic.Config, verify func(net.Addr) bool) (*h3ListenerResources, error) {
	packet, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	tr := &quic.Transport{Conn: packet, VerifySourceAddress: verify}
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		_ = tr.Close()
		_ = packet.Close()
		return nil, fmt.Errorf("listen QUIC: %w", err)
	}
	return &h3ListenerResources{packet: packet, transport: tr, listener: ln}, nil
}

func (r *h3ListenerResources) Close() {
	if r == nil {
		return
	}
	if r.listener != nil {
		_ = r.listener.Close()
	}
	if r.transport != nil {
		_ = r.transport.Close()
	}
	if r.packet != nil {
		_ = r.packet.Close()
	}
}
