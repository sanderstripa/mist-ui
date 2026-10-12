//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func connectOutboundControl() func(string, string, syscall.RawConn) error {
	value := os.Getenv("CONNECT_OUTBOUND_IFINDEX")
	if value == "" {
		return nil
	}
	index, e := strconv.Atoi(value)
	if e != nil || index <= 0 {
		return func(string, string, syscall.RawConn) error { return fmt.Errorf("invalid physical interface") }
	}
	return func(network, address string, c syscall.RawConn) error {
		var inner error
		e := c.Control(func(fd uintptr) {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(index))
			v4 := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(*(*uint32)(unsafe.Pointer(&b[0]))))
			v6 := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, 31, index)
			if v4 != nil && v6 != nil {
				inner = fmt.Errorf("bind physical interface: %v; %v", v4, v6)
			}
		})
		if e != nil {
			return e
		}
		return inner
	}
}
