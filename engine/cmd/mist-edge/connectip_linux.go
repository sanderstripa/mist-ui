//go:build linux

package main

import (
	"fmt"
	"net/netip"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/sanderstripa/vpn/mist/internal/tunio"
)

type connectIPSink struct {
	conn *connectip.Conn
	dev  *tunio.Device
}

func (s *connectIPSink) WritePacket(packet []byte) error {
	icmp, err := s.conn.WritePacket(packet)
	if err != nil {
		return err
	}
	if len(icmp) > 0 {
		_ = s.dev.WritePacket(icmp)
	}
	return nil
}

func pumpConnectIPInbound(conn *connectip.Conn, d *edgeDispatcher, ip netip.Addr) error {
	buf := make([]byte, 65535)
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			return fmt.Errorf("read CONNECT-IP: %w", err)
		}
		if err := d.inbound(buf[:n], ip); err != nil {
			return fmt.Errorf("inject CONNECT-IP packet into edge TUN: %w", err)
		}
	}
}
