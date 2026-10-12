//go:build !linux

package tunio

func packetOffset() int { return 0 }
