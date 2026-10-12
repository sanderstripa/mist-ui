//go:build linux

package platform

import (
	"fmt"
	"net"
	"strconv"
)

// SetupPortHops exposes additional TCP+UDP destination ports and redirects
// them to the primary MIST listener. Rules are idempotent and intentionally
// persistent for the same reason as the edge NAT rules: an edge process crash
// must not leave a half-mutated firewall that differs from installer state.
func SetupPortHops(listen string, ports []int) error {
	if len(ports) == 0 { return nil }
	_, target, err := net.SplitHostPort(listen)
	if err != nil { return fmt.Errorf("port hop listen address: %w", err) }
	targetPort, err := strconv.Atoi(target)
	if err != nil || targetPort < 1 || targetPort > 65535 { return fmt.Errorf("invalid primary listen port %q", target) }
	for _, p := range ports {
		if p == targetPort { continue }
		port := strconv.Itoa(p)
		to := strconv.Itoa(targetPort)
		for _, proto := range []string{"udp", "tcp"} {
			if err := ensureIptables("-t", "nat", "PREROUTING", "-p", proto, "--dport", port, "-j", "REDIRECT", "--to-ports", to); err != nil {
				return fmt.Errorf("install %s port-hop %d -> %d: %w", proto, p, targetPort, err)
			}
		}
	}
	return nil
}
