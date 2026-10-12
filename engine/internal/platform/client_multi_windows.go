//go:build windows

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
		script := fmt.Sprintf("New-NetRoute -DestinationPrefix %s -InterfaceIndex %s -NextHop %s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null", psq(ip.String()+"/32"), state.PhysicalIfIndex, psq(state.Gateway))
		if err := ps(script); err != nil { CleanupClientMulti(state); return nil, err }
	}
	return state, nil
}

func CleanupClientMulti(state *ClientState) {
	if state == nil { return }
	for _, ip := range state.ServerIPs[1:] {
		_ = ps(fmt.Sprintf("Get-NetRoute -AddressFamily IPv4 -DestinationPrefix %s -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -eq %s -and $_.NextHop -eq %s} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", psq(ip.String()+"/32"), state.PhysicalIfIndex, psq(state.Gateway)))
	}
	CleanupClient(state)
}
