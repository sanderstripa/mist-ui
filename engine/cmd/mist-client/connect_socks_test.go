package main

import (
	"context"
	"encoding/binary"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConnectSOCKSAddress(t *testing.T) {
	for _, b := range [][]byte{{1, 127, 0, 0, 1, 1, 187}, {3, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 1, 187}, {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187}} {
		r := &sliceReader{data: b}
		address, raw, e := readSOCKSAddress(r)
		if e != nil || len(raw) != len(b) || address == "" {
			t.Fatalf("%s %v", address, e)
		}
	}
	if _, _, e := readSOCKSAddress(&sliceReader{data: []byte{9}}); e == nil {
		t.Fatal("accepted unsupported address")
	}
}
func pumpConnectPackets(from, to tun.Device) {
	buf := make([]byte, 65535)
	sizes := []int{0}
	for {
		n, e := from.Read([][]byte{buf}, sizes, 0)
		if e != nil {
			return
		}
		if n > 0 {
			if _, e = to.Write([][]byte{buf[:sizes[0]]}, 0); e != nil {
				return
			}
		}
	}
}
func TestConnectSOCKSTCPAndUDPThroughUserspaceIP(t *testing.T) {
	client, clientNet, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.64.0.2")}, nil, 1280)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, serverNet, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.64.0.1")}, nil, 1280)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go pumpConnectPackets(client, server)
	go pumpConnectPackets(server, client)
	listener, e := serverNet.ListenTCPAddrPort(netip.MustParseAddrPort("10.64.0.1:8080"))
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer a.Close()
	go serveConnectSOCKS(ctx, b, clientNet)
	a.SetDeadline(time.Now().Add(5 * time.Second))
	a.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	io.ReadFull(a, reply)
	if reply[1] != 0 {
		t.Fatal(reply)
	}
	a.Write([]byte{5, 1, 0, 1, 10, 64, 0, 1, 31, 144})
	reply = make([]byte, 10)
	if _, e = io.ReadFull(a, reply); e != nil || reply[1] != 0 {
		t.Fatalf("TCP handshake %v %v", reply, e)
	}
	a.Write([]byte("connect-tcp"))
	echo := make([]byte, 11)
	if _, e = io.ReadFull(a, echo); e != nil || string(echo) != "connect-tcp" {
		t.Fatalf("TCP echo %s %v", echo, e)
	}
	a.Close()
	udpServer, e := serverNet.ListenUDPAddrPort(netip.MustParseAddrPort("10.64.0.1:8081"))
	if e != nil {
		t.Fatal(e)
	}
	defer udpServer.Close()
	go func() {
		buf := make([]byte, 100)
		n, addr, e := udpServer.ReadFrom(buf)
		if e == nil {
			udpServer.WriteTo(buf[:n], addr)
		}
	}()
	c, d := net.Pipe()
	defer c.Close()
	go serveConnectSOCKS(ctx, d, clientNet)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, reply[:2])
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, e = io.ReadFull(c, reply); e != nil || reply[1] != 0 {
		t.Fatalf("UDP handshake %v %v", reply, e)
	}
	socket, e := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(reply[8:]))})
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(5 * time.Second))
	payload := append([]byte{0, 0, 0, 1, 10, 64, 0, 1, 31, 145}, []byte("connect-udp")...)
	socket.Write(payload)
	buf := make([]byte, 100)
	n, e := socket.Read(buf)
	if e != nil || n < 10 || string(buf[10:n]) != "connect-udp" {
		t.Fatalf("UDP echo %v %v", buf[:n], e)
	}
}
