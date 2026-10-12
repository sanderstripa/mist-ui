package platform

import "net/netip"

type ClientState struct {
	TUNName         string
	ServerIP        netip.Addr   // first endpoint, kept for compatibility
	ServerIPs       []netip.Addr // all endpoint IPs excluded from the tunnel
	PhysicalIf      string
	PhysicalIfIndex string
	Gateway         string
	DNS             []string
}
