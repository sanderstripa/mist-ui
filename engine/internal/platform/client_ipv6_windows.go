//go:build windows

package platform

import (
	"fmt"
	"net/netip"
)

func ConfigureClientIPv6(tunName string, assigned netip.Prefix) error {
	if !assigned.Addr().Is6() { return fmt.Errorf("IPv6 assignment required") }
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';
$mist=%s; $ip=%s; $prefix=%d;
Enable-NetAdapterBinding -Name $mist -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null;
Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {($_.DestinationPrefix -eq '::/1' -or $_.DestinationPrefix -eq '8000::/1') -and $_.InterfaceIndex -eq 1 -and $_.RouteMetric -eq 60000} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;
Get-NetIPAddress -InterfaceAlias $mist -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.PrefixOrigin -ne 'WellKnown'} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue;
New-NetIPAddress -InterfaceAlias $mist -IPAddress $ip -PrefixLength $prefix | Out-Null;
Set-NetIPInterface -InterfaceAlias $mist -AddressFamily IPv6 -InterfaceMetric 5;
foreach($route in @('::/1','8000::/1')){ New-NetRoute -DestinationPrefix $route -InterfaceAlias $mist -NextHop '::' -RouteMetric 5 -PolicyStore ActiveStore | Out-Null; }
`, psq(tunName), psq(assigned.Addr().String()), assigned.Bits())
	return ps(script)
}

func CleanupClientIPv6(tunName string) {
	_ = ps(fmt.Sprintf(`$mist=%s;
Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {($_.DestinationPrefix -eq '::/1' -or $_.DestinationPrefix -eq '8000::/1') -and $_.InterfaceAlias -eq $mist} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;
Get-NetIPAddress -InterfaceAlias $mist -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.PrefixOrigin -ne 'WellKnown'} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue;
Disable-NetAdapterBinding -Name $mist -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null;`, psq(tunName)))
}
