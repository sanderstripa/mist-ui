//go:build !linux && !windows

package platform

import (
	"errors"
	"net/netip"
)

func ConfigureClientIPv6(string, netip.Prefix) error { return errors.New("IPv6 tunnel currently supports Windows and Linux") }
func CleanupClientIPv6(string) {}
