//go:build linux

package platform

import "fmt"

func SetupEdgeDual(tunName, tunCIDR, tunIPv6CIDR string, mtu int, enableNAT bool) (*EdgeState, error) {
	state, err := SetupEdge(tunName, tunCIDR, mtu, enableNAT)
	if err != nil { return nil, err }
	if tunIPv6CIDR == "" { return state, nil }
	if err := runEdge("ip", "-6", "addr", "replace", tunIPv6CIDR, "dev", tunName); err != nil { return nil, err }
	if err := runEdge("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil { return nil, err }
	if enableNAT {
		if err := ensureIP6Tables("-t", "nat", "POSTROUTING", "-s", tunIPv6CIDR, "-j", "MASQUERADE"); err != nil { return nil, fmt.Errorf("IPv6 NAT: %w", err) }
		if err := ensureIP6Tables("FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil { return nil, err }
		if err := ensureIP6Tables("FORWARD", "-o", tunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil { return nil, err }
	}
	return state, nil
}

func ensureIP6Tables(rule ...string) error {
	check := append([]string{}, rule...)
	if len(check) > 0 && check[0] == "-t" { check = append(check[:2], append([]string{"-C"}, check[2:]...)...) } else { check = append([]string{"-C"}, check...) }
	if runEdge("ip6tables", check...) == nil { return nil }
	add := append([]string{}, rule...)
	if len(add) > 0 && add[0] == "-t" { add = append(add[:2], append([]string{"-A"}, add[2:]...)...) } else { add = append([]string{"-A"}, add...) }
	return runEdge("ip6tables", add...)
}
