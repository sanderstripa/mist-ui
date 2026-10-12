package main

// Connect's user-space adapter keeps MIST independent of Windows routes and
// privileges. Desktop HEV and Chrome both use this loopback SOCKS endpoint.
import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/telemetry"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

func runConnectSOCKS(ctx context.Context, cfg config.ClientConfig, mode, listen string, metrics *telemetry.Metrics) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("SOCKS must bind to 127.0.0.1")
	}
	out, err := dialMISTMulti(ctx, cfg, mode, metrics)
	if err != nil {
		return err
	}
	defer out.conn.Close()
	addresses := []netip.Addr{out.assigned.Addr()}
	if cfg.IPv6Mode == "tunnel" {
		p, e := netip.ParsePrefix(cfg.FallbackClientIPv6CIDR)
		if e != nil {
			return e
		}
		addresses = append(addresses, p.Addr())
	}
	dns := []netip.Addr{}
	for _, s := range cfg.DNS {
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return e
		}
		dns = append(dns, ip)
	}
	dev, stack, err := netstack.CreateNetTUN(addresses, dns, cfg.MTU)
	if err != nil {
		return err
	}
	var closeStack sync.Once
	closeDevice := func() { closeStack.Do(func() { dev.Close() }) }
	defer closeDevice()
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	session, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-session.Done(); listener.Close(); out.conn.Close(); closeDevice() }()
	// The adapter fails closed on transport loss. Its owner reconnects explicitly.
	go func() {
		defer cancel()
		buf := make([]byte, 65535)
		sizes := []int{0}
		for {
			n, e := dev.Read([][]byte{buf}, sizes, 0)
			if e != nil {
				return
			}
			if n > 0 {
				icmp, e := out.conn.WritePacket(buf[:sizes[0]])
				if e != nil {
					return
				}
				metrics.TX(sizes[0])
				if len(icmp) > 0 {
					if _, e = dev.Write([][]byte{icmp}, 0); e != nil {
						return
					}
				}
			}
		}
	}()
	go func() {
		defer cancel()
		buf := make([]byte, 65535)
		for {
			n, e := out.conn.ReadPacket(buf)
			if e != nil {
				return
			}
			if n > 0 {
				if _, e = dev.Write([][]byte{buf[:n]}, 0); e != nil {
					return
				}
				metrics.RX(n)
			}
		}
	}()
	log.Printf("CONNECT_READY MIST SOCKS %s transport=%s", listen, out.transport)
	for {
		c, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("MIST transport stopped")
		}
		go serveConnectSOCKS(session, c, stack)
	}
}
func readSOCKSAddress(r io.Reader) (string, []byte, error) {
	var t [1]byte
	if _, e := io.ReadFull(r, t[:]); e != nil {
		return "", nil, e
	}
	raw := []byte{t[0]}
	var host string
	switch t[0] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", nil, e
		}
		raw = append(raw, b...)
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", nil, e
		}
		raw = append(raw, b...)
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, e := io.ReadFull(r, l[:]); e != nil {
			return "", nil, e
		}
		b := make([]byte, int(l[0]))
		if _, e := io.ReadFull(r, b); e != nil {
			return "", nil, e
		}
		raw = append(raw, l[0])
		raw = append(raw, b...)
		host = string(b)
	default:
		return "", nil, fmt.Errorf("bad address")
	}
	var p [2]byte
	if _, e := io.ReadFull(r, p[:]); e != nil {
		return "", nil, e
	}
	raw = append(raw, p[:]...)
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(p[:]))), raw, nil
}
func serveConnectSOCKS(ctx context.Context, c net.Conn, stack *netstack.Net) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var greeting [2]byte
	if _, e := io.ReadFull(c, greeting[:]); e != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{5, 255})
		return
	}
	c.Write([]byte{5, 0})
	var req [3]byte
	if _, e := io.ReadFull(c, req[:]); e != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	_, _, e := handleConnectSOCKSRequest(c, req, ctx, stack)
	if e != nil {
		return
	}
}
func handleConnectSOCKSRequest(c net.Conn, req [3]byte, ctx context.Context, stack *netstack.Net) (string, []byte, error) {
	address, raw, e := readSOCKSAddress(c)
	if e != nil {
		return "", nil, e
	}
	if req[1] == 3 {
		return "", nil, serveConnectUDP(ctx, c, stack)
	}
	if req[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", nil, fmt.Errorf("unsupported command")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	remote, e := stack.DialContext(dialCtx, "tcp", address)
	cancel()
	if e != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", nil, e
	}
	defer remote.Close()
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
			remote.Close()
		case <-done:
		}
	}()
	go func() { io.Copy(remote, c); remote.Close() }()
	io.Copy(c, remote)
	close(done)
	return address, raw, nil
}
func serveConnectUDP(ctx context.Context, c net.Conn, stack *netstack.Net) error {
	udp, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return e
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	c.SetDeadline(time.Time{})
	session, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { io.Copy(io.Discard, c); cancel(); udp.Close() }()
	var mu sync.Mutex
	flows := map[string]net.Conn{}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range flows {
			f.Close()
		}
	}()
	buf := make([]byte, 65535)
	var owner *net.UDPAddr
	for {
		udp.SetReadDeadline(time.Now().Add(time.Second))
		n, from, e := udp.ReadFromUDP(buf)
		if e != nil {
			if session.Err() != nil {
				return nil
			}
			if t, ok := e.(net.Error); ok && t.Timeout() {
				continue
			}
			return e
		}
		if !from.IP.IsLoopback() || n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		if owner != nil && owner.String() != from.String() {
			continue
		}
		if owner == nil {
			owner = from
		}
		reader := &sliceReader{data: buf[3:n]}
		address, raw, e := readSOCKSAddress(reader)
		if e != nil {
			continue
		}
		payload := append([]byte(nil), reader.data...)
		mu.Lock()
		remote := flows[address]
		mu.Unlock()
		if remote == nil {
			dialCtx, stop := context.WithTimeout(session, 10*time.Second)
			remote, e = stack.DialContext(dialCtx, "udp", address)
			stop()
			if e != nil {
				continue
			}
			mu.Lock()
			flows[address] = remote
			mu.Unlock()
			go func(r net.Conn, header []byte, target *net.UDPAddr) {
				defer r.Close()
				defer func() { mu.Lock(); delete(flows, address); mu.Unlock() }()
				reply := make([]byte, 65535)
				for {
					r.SetReadDeadline(time.Now().Add(90 * time.Second))
					n, e := r.Read(reply)
					if e != nil {
						return
					}
					packet := append([]byte{0, 0, 0}, header...)
					packet = append(packet, reply[:n]...)
					if _, e = udp.WriteToUDP(packet, target); e != nil {
						return
					}
				}
			}(remote, raw, from)
		}
		remote.Write(payload)
	}
}

type sliceReader struct{ data []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
