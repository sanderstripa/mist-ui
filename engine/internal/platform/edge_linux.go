//go:build linux

package platform

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type EdgeState struct {
	TUNName string
	TUNCIDR string
	NAT     bool
}

func SetupEdge(tunName, tunCIDR string, mtu int, enableNAT bool) (*EdgeState, error) {
	if err := runEdge("ip", "link", "set", "dev", tunName, "up"); err != nil {
		return nil, err
	}
	if err := runEdge("ip", "addr", "replace", tunCIDR, "dev", tunName); err != nil {
		return nil, err
	}
	if err := runEdge("ip", "link", "set", "dev", tunName, "mtu", fmt.Sprint(mtu)); err != nil {
		return nil, err
	}
	if err := runEdge("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return nil, err
	}

	// quic-go raises UDP socket buffers for high-throughput QUIC, but Linux
	// caps the value an application may request with net.core.{r,w}mem_max.
	// Keep the kernel ceiling comfortably above quic-go's requested buffers.
	// These are maximums, not permanently allocated memory.
	for _, key := range []string{"net.core.rmem_max", "net.core.wmem_max"} {
		out, err := exec.Command("sysctl", "-n", key).Output()
		value, parseErr := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err == nil && parseErr == nil && value < 16777216 { _ = runEdge("sysctl", "-w", key+"=16777216") }
	}
	if enableNAT {
		if err := ensureIptables("-t", "nat", "POSTROUTING", "-s", tunCIDR, "-j", "MASQUERADE"); err != nil {
			return nil, err
		}
		if err := ensureIptables("FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil {
			return nil, err
		}
		if err := ensureIptables("FORWARD", "-o", tunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			return nil, err
		}
	}
	return &EdgeState{TUNName: tunName, TUNCIDR: tunCIDR, NAT: enableNAT}, nil
}

func CleanupEdge(*EdgeState) {
	// The MVP deliberately leaves forwarding/NAT rules in place. The installer
	// manages their lifecycle so an unexpected process exit cannot strand users
	// behind a half-reconfigured server firewall.
}

func ensureIptables(rule ...string) error {
	check := append([]string{}, rule...)
	if len(check) > 0 && check[0] == "-t" {
		check = append(check[:2], append([]string{"-C"}, check[2:]...)...)
	} else {
		check = append([]string{"-C"}, check...)
	}
	if exec.Command("iptables", check...).Run() == nil {
		return nil
	}
	add := append([]string{}, rule...)
	if len(add) > 0 && add[0] == "-t" {
		add = append(add[:2], append([]string{"-A"}, add[2:]...)...)
	} else {
		add = append([]string{"-A"}, add...)
	}
	return runEdge("iptables", add...)
}

func runEdge(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
