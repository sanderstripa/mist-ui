//go:build linux

package platform

import (
	"fmt"
	"net"
	"net/netip"
)

func SetupClientMulti(tunName string, assigned netip.Prefix, dialAddresses []string, dns []string, mtu int) (*ClientState, error) {
	if len(dialAddresses) == 0 { return nil, fmt.Errorf("no endpoint dial addresses") }
	state, err := SetupClient(tunName, assigned, dialAddresses[0], dns, mtu)
	if err != nil { return nil, err }
	state.ServerIPs = nil
	for _, addr := range dialAddresses {
		host, _, err := net.SplitHostPort(addr); if err != nil { CleanupClient(state); return nil, err }
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() { CleanupClient(state); return nil, fmt.Errorf("endpoint requires IPv4 literal in dial_address, got %q", host) }
		state.ServerIPs = append(state.ServerIPs, ip)
	}
	for _, ip := range state.ServerIPs[1:] {
		prefix := ip.String()+"/32"
		if state.Gateway != "" {
			if err := run("ip", "route", "replace", prefix, "via", state.Gateway, "dev", state.PhysicalIf); err != nil { CleanupClientMulti(state); return nil, err }
		} else if err := run("ip", "route", "replace", prefix, "dev", state.PhysicalIf); err != nil { CleanupClientMulti(state); return nil, err }
	}
	// Until the optional IPv6 dataplane is configured end-to-end, fail closed
	// for native IPv6 as well. Without these routes a dual-stack host could
	// bypass the IPv4 tunnel through its physical interface.
	_ = run("ip", "-6", "route", "replace", "blackhole", "::/1", "metric", "32760")
	_ = run("ip", "-6", "route", "replace", "blackhole", "8000::/1", "metric", "32760")
	return state, nil
}

func CleanupClientMulti(state *ClientState) {
	if state == nil { return }
	for _, ip := range state.ServerIPs[1:] { _ = run("ip", "route", "del", ip.String()+"/32") }
	_ = run("ip", "-6", "route", "del", "blackhole", "::/1", "metric", "32760")
	_ = run("ip", "-6", "route", "del", "blackhole", "8000::/1", "metric", "32760")
	CleanupClient(state)
}
