//go:build windows

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

func SetupClient(tunName string, assigned netip.Prefix, dialAddress string, dns []string, mtu int) (*ClientState, error) {
	host, _, err := net.SplitHostPort(dialAddress)
	if err != nil {
		return nil, err
	}
	serverIP, err := netip.ParseAddr(host)
	if err != nil || !serverIP.Is4() {
		return nil, fmt.Errorf("MVP requires an IPv4 literal in dial_address, got %q", host)
	}
	idx, gateway, err := windowsDefaultRoute(tunName)
	if err != nil {
		return nil, err
	}
	state := &ClientState{TUNName: tunName, ServerIP: serverIP, PhysicalIfIndex: idx, Gateway: gateway, DNS: dns}

	// Restore DNS left by an unclean previous run before taking a fresh backup.
	_ = restorePhysicalDNSBackup()

	quotedDNS := make([]string, 0, len(dns))
	for _, d := range dns {
		quotedDNS = append(quotedDNS, psq(d))
	}
	dnsArray := "@()"
	if len(quotedDNS) > 0 {
		dnsArray = "@(" + strings.Join(quotedDNS, ",") + ")"
	}

	ip := assigned.Addr().String()
	prefix := assigned.Bits()
	serverPrefix := serverIP.String() + "/32"

	// Apply the complete Windows network setup in one PowerShell process.
	// Spawning PowerShell once per route / DNS action added tens of seconds to
	// startup on real Windows machines.
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';
$mist=%s;
$ip=%s;
$prefix=%d;
$mtu=%d;
$serverPrefix=%s;
$idx=%s;
$gateway=%s;
$dns=%s;

Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
	Where-Object {$_.Name -like 'MIST-DNS-Guard-*'} |
	Remove-NetFirewallRule -ErrorAction SilentlyContinue;
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
	Where-Object {($_.DestinationPrefix -eq '0.0.0.0/1' -or $_.DestinationPrefix -eq '128.0.0.0/1') -and $_.InterfaceAlias -like 'MIST*'} |
	Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;

Disable-NetAdapterBinding -Name $mist -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null;
Get-NetIPAddress -InterfaceAlias $mist -AddressFamily IPv4 -ErrorAction SilentlyContinue |
	Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue;
New-NetIPAddress -InterfaceAlias $mist -IPAddress $ip -PrefixLength $prefix | Out-Null;
Set-NetIPInterface -InterfaceAlias $mist -AddressFamily IPv4 -NlMtuBytes $mtu -InterfaceMetric 5;

New-NetRoute -DestinationPrefix $serverPrefix -InterfaceIndex $idx -NextHop $gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
foreach($route in @('0.0.0.0/1','128.0.0.0/1')){
	New-NetRoute -DestinationPrefix $route -InterfaceIndex 1 -NextHop '0.0.0.0' -RouteMetric 60000 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
}
foreach($route in @('::/1','8000::/1')){
	New-NetRoute -DestinationPrefix $route -InterfaceIndex 1 -NextHop '::' -RouteMetric 60000 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
}
foreach($route in @('0.0.0.0/1','128.0.0.0/1')){
	New-NetRoute -DestinationPrefix $route -InterfaceAlias $mist -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore | Out-Null;
}
if($dns.Count -gt 0){
	Set-DnsClientServerAddress -InterfaceAlias $mist -ServerAddresses $dns;
}

$ifs=@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -ne $mist} | Select-Object -ExpandProperty Name);
if($ifs.Count -gt 0){
	New-NetFirewallRule -Name 'MIST-DNS-Guard-UDP' -DisplayName 'MIST DNS Guard UDP' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol UDP -RemotePort 53 -InterfaceAlias $ifs -PolicyStore PersistentStore | Out-Null;
	New-NetFirewallRule -Name 'MIST-DNS-Guard-TCP' -DisplayName 'MIST DNS Guard TCP' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol TCP -RemotePort 53 -InterfaceAlias $ifs -PolicyStore PersistentStore | Out-Null;
}

$dir=Join-Path $env:ProgramData 'MIST';
$path=Join-Path $dir 'dns-backup.json';
New-Item -ItemType Directory -Force -Path $dir | Out-Null;
$items=@();
Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -ne $mist} | ForEach-Object {
	$a=$_;
	$servers=@(Get-DnsClientServerAddress -InterfaceAlias $a.Name -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses} | Where-Object {$_});
	$guid=[string]$a.InterfaceGuid;
	if($guid -notmatch '^\\{'){ $guid='{'+$guid+'}' };
	$reg='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\'+$guid;
	$manual=(Get-ItemProperty -Path $reg -Name NameServer -ErrorAction SilentlyContinue).NameServer;
	$items += [pscustomobject]@{Alias=$a.Name; Servers=$servers; Static=(-not [string]::IsNullOrWhiteSpace($manual))};
};
@($items) | ConvertTo-Json -Compress | Set-Content -Path $path -Encoding UTF8;
foreach($i in $items){
	Set-DnsClientServerAddress -InterfaceAlias $i.Alias -ServerAddresses @('127.0.0.1','::1') -ErrorAction Stop;
}`, psq(tunName), psq(ip), prefix, mtu, psq(serverPrefix), idx, psq(gateway), dnsArray)

	if err := ps(script); err != nil {
		CleanupClient(state)
		return nil, fmt.Errorf("apply Windows network setup: %w", err)
	}
	return state, nil
}

func CleanupClient(state *ClientState) {
	if state == nil {
		return
	}
	_ = restorePhysicalDNSBackup()
	_ = ps("Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'MIST-DNS-Guard-*'} | Remove-NetFirewallRule -ErrorAction SilentlyContinue")
	for _, route := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_ = ps(fmt.Sprintf("Get-NetRoute -AddressFamily IPv4 -DestinationPrefix %s -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceAlias -eq %s -or ($_.InterfaceIndex -eq 1 -and $_.RouteMetric -eq 60000)} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", psq(route), psq(state.TUNName)))
	}
	for _, route := range []string{"::/1", "8000::/1"} {
		_ = ps(fmt.Sprintf("Get-NetRoute -AddressFamily IPv6 -DestinationPrefix %s -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -eq 1 -and $_.RouteMetric -eq 60000} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", psq(route)))
	}
	_ = ps(fmt.Sprintf("Get-NetRoute -AddressFamily IPv4 -DestinationPrefix %s -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -eq %s -and $_.NextHop -eq %s} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", psq(state.ServerIP.String()+"/32"), state.PhysicalIfIndex, psq(state.Gateway)))
	_ = ps(fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses -ErrorAction SilentlyContinue", psq(state.TUNName)))
	_ = ps(fmt.Sprintf("Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue", psq(state.TUNName)))
}

func RecoverClient() error {
	var firstErr error
	if err := restorePhysicalDNSBackup(); err != nil {
		firstErr = err
	}
	_ = ps("Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'MIST-DNS-Guard-*'} | Remove-NetFirewallRule -ErrorAction SilentlyContinue")
	_ = ps("Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {($_.DestinationPrefix -eq '0.0.0.0/1' -or $_.DestinationPrefix -eq '128.0.0.0/1') -and ($_.InterfaceAlias -like 'MIST*' -or ($_.InterfaceIndex -eq 1 -and $_.RouteMetric -eq 60000))} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")
	_ = ps("Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {($_.DestinationPrefix -eq '::/1' -or $_.DestinationPrefix -eq '8000::/1') -and $_.InterfaceIndex -eq 1 -and $_.RouteMetric -eq 60000} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")
	return firstErr
}

func blackholePhysicalDNS(tunName string) error {
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';
$dir=Join-Path $env:ProgramData 'MIST';
$path=Join-Path $dir 'dns-backup.json';
New-Item -ItemType Directory -Force -Path $dir | Out-Null;
$mist=%s;
$items=@();
Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -ne $mist} | ForEach-Object {
	$a=$_;
	$servers=@(Get-DnsClientServerAddress -InterfaceAlias $a.Name -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses} | Where-Object {$_});
	$guid=[string]$a.InterfaceGuid; if($guid -notmatch '^\\{'){ $guid='{'+$guid+'}' }; $reg='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$guid;
	$manual=(Get-ItemProperty -Path $reg -Name NameServer -ErrorAction SilentlyContinue).NameServer;
	$items += [pscustomobject]@{Alias=$a.Name; Servers=$servers; Static=(-not [string]::IsNullOrWhiteSpace($manual))};
};
@($items) | ConvertTo-Json -Compress | Set-Content -Path $path -Encoding UTF8;
foreach($i in $items){
	Set-DnsClientServerAddress -InterfaceAlias $i.Alias -ServerAddresses @('127.0.0.1','::1') -ErrorAction Stop;
}`, psq(tunName))
	return ps(script)
}

func restorePhysicalDNSBackup() error {
	script := `$ErrorActionPreference='Stop';
$path=Join-Path (Join-Path $env:ProgramData 'MIST') 'dns-backup.json';
if(Test-Path $path){
	$items=@(Get-Content -Raw -Path $path | ConvertFrom-Json);
	foreach($i in $items){
		if(-not (Get-NetAdapter -Name $i.Alias -ErrorAction SilentlyContinue)){ continue };
		$servers=@($i.Servers | Where-Object {$_});
		if($i.Static -and $servers.Count -gt 0){
			Set-DnsClientServerAddress -InterfaceAlias $i.Alias -ServerAddresses $servers -ErrorAction SilentlyContinue;
		}else{
			Set-DnsClientServerAddress -InterfaceAlias $i.Alias -ResetServerAddresses -ErrorAction SilentlyContinue;
		}
	};
	Remove-Item -Force -Path $path -ErrorAction SilentlyContinue;
}`
	return ps(script)
}

func windowsDefaultRoute(excludeAlias string) (string, string, error) {
	script := fmt.Sprintf("$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.InterfaceAlias -ne %s -and $_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if(-not $r){exit 2}; Write-Output ($r.InterfaceIndex.ToString()+'|'+$r.NextHop)", psq(excludeAlias))
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("determine default route: %w: %s", err, strings.TrimSpace(string(out)))
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unexpected default route output: %q", strings.TrimSpace(string(out)))
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return "", "", fmt.Errorf("invalid interface index %q", parts[0])
	}
	return parts[0], parts[1], nil
}

func ps(script string) error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
