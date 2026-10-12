//go:build !linux && !windows

package platform

import (
	"errors"
	"net/netip"
)

func SetupClient(string, netip.Prefix, string, []string, int) (*ClientState, error) {
	return nil, errors.New("MIST MVP client currently supports Windows and Linux")
}
func RecoverClient() error { return nil }
func CleanupClient(*ClientState) {}
