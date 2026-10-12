//go:build !linux && !windows

package platform

import (
	"errors"
	"net/netip"
)

func SetupClientMulti(string, netip.Prefix, []string, []string, int) (*ClientState, error) {
	return nil, errors.New("MIST client currently supports Windows and Linux")
}
func CleanupClientMulti(*ClientState) {}
