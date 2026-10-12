//go:build linux

package platform

import (
	"fmt"
	"net/netip"
)

func ConfigureClientIPv6(tunName string, assigned netip.Prefix) error {
	if !assigned.Addr().Is6() { return fmt.Errorf("IPv6 assignment required") }
	_ = run("ip", "-6", "route", "del", "blackhole", "::/1", "metric", "32760")
	_ = run("ip", "-6", "route", "del", "blackhole", "8000::/1", "metric", "32760")
	if err := run("ip", "-6", "addr", "replace", assigned.String(), "dev", tunName); err != nil { return err }
	if err := run("ip", "-6", "route", "replace", "::/1", "dev", tunName, "metric", "5"); err != nil { return err }
	if err := run("ip", "-6", "route", "replace", "8000::/1", "dev", tunName, "metric", "5"); err != nil { return err }
	return nil
}

func CleanupClientIPv6(tunName string) {
	_ = run("ip", "-6", "route", "del", "::/1", "dev", tunName)
	_ = run("ip", "-6", "route", "del", "8000::/1", "dev", tunName)
	_ = run("ip", "-6", "addr", "flush", "dev", tunName)
}
