//go:build !linux

package platform

import "errors"

type EdgeState struct{}

func SetupEdge(string, string, int, bool) (*EdgeState, error) {
	return nil, errors.New("MIST edge currently supports Linux only")
}
func CleanupEdge(*EdgeState) {}
