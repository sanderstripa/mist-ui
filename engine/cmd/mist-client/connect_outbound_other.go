//go:build !windows

package main

import "syscall"

func connectOutboundControl() func(string, string, syscall.RawConn) error { return nil }
