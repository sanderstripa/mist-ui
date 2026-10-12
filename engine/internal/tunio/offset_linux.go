//go:build linux

package tunio

// wireguard-go enables IFF_VNET_HDR for Linux TUN devices.
// Its Write path requires at least sizeof(virtio_net_hdr) bytes of headroom.
func packetOffset() int { return 10 }
