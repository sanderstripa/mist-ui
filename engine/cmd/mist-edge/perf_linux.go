//go:build linux

package main

const (
	fastInitialStreamWindow = 4 << 20
	fastMaxStreamWindow     = 32 << 20
	fastInitialConnWindow   = 16 << 20
	fastMaxConnWindow       = 64 << 20
)
