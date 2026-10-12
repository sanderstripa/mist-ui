package main

import (
	"context"
	"crypto/tls"
	"github.com/quic-go/quic-go"
	"net"
	"time"
)

func connectDialQUIC(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	remote, e := net.ResolveUDPAddr("udp", address)
	if e != nil {
		return nil, e
	}
	network, listen := "udp4", "0.0.0.0:0"
	if remote.IP.To4() == nil {
		network, listen = "udp6", "[::]:0"
	}
	lc := net.ListenConfig{Control: connectOutboundControl()}
	packet, e := lc.ListenPacket(ctx, network, listen)
	if e != nil {
		return nil, e
	}
	tr := &quic.Transport{Conn: packet}
	conn, e := tr.Dial(ctx, remote, tlsConfig, config)
	if e != nil {
		tr.Close()
		packet.Close()
		return nil, e
	}
	go func() { <-conn.Context().Done(); tr.Close(); packet.Close() }()
	return conn, nil
}
func connectDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: connectOutboundControl()}
}
