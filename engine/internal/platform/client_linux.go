//go:build linux

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

func SetupClient(tunName string, assigned netip.Prefix, dialAddress string, dns []string, mtu int) (*ClientState, error) {
	host, _, err := net.SplitHostPort(dialAddress)
	if err != nil { return nil, err }
	serverIP, err := netip.ParseAddr(host)
	if err != nil || !serverIP.Is4() { return nil, fmt.Errorf("MVP requires an IPv4 literal in dial_address, got %q", host) }
	gateway, dev, err := linuxDefaultRoute()
	if err != nil { return nil, err }
	state := &ClientState{TUNName: tunName, ServerIP: serverIP, PhysicalIf: dev, Gateway: gateway, DNS: dns}

	if err := run("ip", "link", "set", "dev", tunName, "up"); err != nil { return nil, err }
	if err := run("ip", "addr", "replace", assigned.String(), "dev", tunName); err != nil { return nil, err }
	if err := run("ip", "link", "set", "dev", tunName, "mtu", fmt.Sprint(mtu)); err != nil { return nil, err }
	serverPrefix := serverIP.String() + "/32"
	if gateway != "" {
		if err := run("ip", "route", "replace", serverPrefix, "via", gateway, "dev", dev); err != nil { return nil, err }
	} else if err := run("ip", "route", "replace", serverPrefix, "dev", dev); err != nil { return nil, err }
	if err := run("ip", "route", "replace", "0.0.0.0/1", "dev", tunName); err != nil { return nil, err }
	if err := run("ip", "route", "replace", "128.0.0.0/1", "dev", tunName); err != nil { return nil, err }
	if len(dns) > 0 {
		args := append([]string{"dns", tunName}, dns...)
		_ = run("resolvectl", args...)
		_ = run("resolvectl", "domain", tunName, "~.")
	}
	return state, nil
}

func RecoverClient() error {
	_ = run("ip", "route", "del", "0.0.0.0/1")
	_ = run("ip", "route", "del", "128.0.0.0/1")
	_ = run("ip", "-6", "route", "del", "blackhole", "::/1", "metric", "32760")
	_ = run("ip", "-6", "route", "del", "blackhole", "8000::/1", "metric", "32760")
	return nil
}

func CleanupClient(state *ClientState) {
	if state == nil { return }
	_ = run("ip", "route", "del", "0.0.0.0/1", "dev", state.TUNName)
	_ = run("ip", "route", "del", "128.0.0.0/1", "dev", state.TUNName)
	_ = run("ip", "route", "del", state.ServerIP.String()+"/32")
	_ = run("resolvectl", "revert", state.TUNName)
}

func linuxDefaultRoute() (gateway, dev string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil { return "", "", fmt.Errorf("read default route: %w", err) }
	fields := strings.Fields(string(out))
	for i := range fields {
		if fields[i] == "via" && i+1 < len(fields) { gateway = fields[i+1] }
		if fields[i] == "dev" && i+1 < len(fields) { dev = fields[i+1] }
	}
	if dev == "" { return "", "", fmt.Errorf("could not determine physical default-route interface") }
	return gateway, dev, nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil { return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out))) }
	return nil
}
