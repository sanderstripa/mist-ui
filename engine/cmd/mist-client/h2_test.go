package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialSOCKS5NoAuthIPv4(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil { serverErr <- err; return }
		defer c.Close()

		var hello [3]byte
		if _, err := io.ReadFull(c, hello[:]); err != nil { serverErr <- err; return }
		if hello != [3]byte{5,1,0} { serverErr <- &testError{"unexpected SOCKS greeting"}; return }
		if _, err := c.Write([]byte{5,0}); err != nil { serverErr <- err; return }

		var head [4]byte
		if _, err := io.ReadFull(c, head[:]); err != nil { serverErr <- err; return }
		if head != [4]byte{5,1,0,1} { serverErr <- &testError{"unexpected SOCKS CONNECT header"}; return }
		var addr [4]byte
		var port [2]byte
		if _, err := io.ReadFull(c, addr[:]); err != nil { serverErr <- err; return }
		if _, err := io.ReadFull(c, port[:]); err != nil { serverErr <- err; return }
		if net.IP(addr[:]).String() != "203.0.113.10" || binary.BigEndian.Uint16(port[:]) != 443 {
			serverErr <- &testError{"unexpected SOCKS target"}; return
		}
		_, err = c.Write([]byte{5,0,0,1,127,0,0,1,0,1})
		serverErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialSOCKS5(ctx, ln.Addr().String(), "203.0.113.10:443")
	if err != nil { t.Fatal(err) }
	_ = conn.Close()
	if err := <-serverErr; err != nil { t.Fatal(err) }
}

type testError struct{ s string }
func (e *testError) Error() string { return e.s }
