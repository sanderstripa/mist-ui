param(
    [string]$InterfaceName = "MIST",
    [string]$ServerIP = "",
    [string[]]$ServerIPs = @(),
    [int]$ExpectedMTU = 1280,
    [ValidateSet("block","tunnel")][string]$IPv6Mode = "block",
    [string[]]$ExpectedDNS = @(),
    [string]$ProbeHost = "example.com"
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Check([bool]$ok, [string]$name, [string]$detail = "") {
    if ($ok) { Write-Host "[PASS] $name $detail" -ForegroundColor Green }
    else { Write-Host "[FAIL] $name $detail" -ForegroundColor Red; $script:failures.Add($name) }
}
function Warn([string]$name, [string]$detail = "") {
    Write-Host "[WARN] $name $detail" -ForegroundColor Yellow
    $script:warnings.Add($name)
}

Write-Host "MIST Windows verification" -ForegroundColor Cyan
Write-Host "Interface=$InterfaceName MTU=$ExpectedMTU IPv6=$IPv6Mode"

$adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
Check ($null -ne $adapter -and $adapter.Status -eq "Up") "MIST adapter is up"
if ($null -eq $adapter) { exit 2 }

$ipv4if = Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
Check ($null -ne $ipv4if) "IPv4 interface exists"
if ($ipv4if) { Check ($ipv4if.NlMtuBytes -eq $ExpectedMTU) "MTU" "actual=$($ipv4if.NlMtuBytes)" }

$mistIndex = $adapter.ifIndex
foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
    $r = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -eq $mistIndex})
    Check ($r.Count -gt 0) "IPv4 tunnel route $prefix"
}

$targets = New-Object System.Collections.Generic.List[string]
if ($ServerIP) { $targets.Add($ServerIP) }
foreach ($ip in $ServerIPs) { if ($ip -and -not $targets.Contains($ip)) { $targets.Add($ip) } }
if ($targets.Count -gt 0) {
    foreach ($ip in $targets) {
        $route = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue
        if ($route) {
            Check ($route.InterfaceIndex -ne $mistIndex) "Server endpoint $ip bypasses tunnel" "ifIndex=$($route.InterfaceIndex)"
        } else { Check $false "Server endpoint route $ip" }
    }
} else { Warn "Server route check skipped" "pass -ServerIPs x.x.x.x,y.y.y.y" }

$dns = @(Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses} | Where-Object {$_})
Check ($dns.Count -gt 0) "MIST DNS configured" ($dns -join ',')
foreach ($expected in $ExpectedDNS) { Check ($dns -contains $expected) "Expected DNS $expected" }

$guards = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'MIST-DNS-Guard-*' -and $_.Enabled -eq 'True'})
Check ($guards.Count -ge 2) "Physical-interface DNS leak guard"

try {
    $resolved = Resolve-DnsName -Name $ProbeHost -Type A -DnsOnly -ErrorAction Stop
    Check ($resolved.Count -gt 0) "DNS resolution through active policy" $ProbeHost
} catch { Check $false "DNS resolution through active policy" $_.Exception.Message }

$v6black = @(
    Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object {($_.DestinationPrefix -eq '::/1' -or $_.DestinationPrefix -eq '8000::/1') -and $_.InterfaceIndex -eq 1 -and $_.RouteMetric -eq 60000}
)
$v6mist = @(
    Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object {($_.DestinationPrefix -eq '::/1' -or $_.DestinationPrefix -eq '8000::/1') -and $_.InterfaceIndex -eq $mistIndex}
)
if ($IPv6Mode -eq "block") {
    Check ($v6black.Count -eq 2) "IPv6 fail-closed routes"
    $binding = Get-NetAdapterBinding -Name $InterfaceName -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Check ($null -eq $binding -or -not $binding.Enabled) "IPv6 disabled on MIST in block mode"
} else {
    Check ($v6mist.Count -eq 2) "IPv6 tunnel routes"
    $v6addr = @(Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -notlike 'fe80::*'})
    Check ($v6addr.Count -gt 0) "IPv6 address assigned to MIST"
}

# The physical DNS addresses are deliberately blackholed while MIST is active.
$physical = @(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -ne $InterfaceName})
$dnsLeak = $false
foreach ($a in $physical) {
    $servers = @(Get-DnsClientServerAddress -InterfaceAlias $a.Name -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses} | Where-Object {$_})
    if ($servers | Where-Object {$_ -ne '127.0.0.1' -and $_ -ne '::1'}) { $dnsLeak = $true }
}
Check (-not $dnsLeak) "No usable plaintext DNS configured on physical adapters"

Write-Host ""
Write-Host "Failures: $($failures.Count), warnings: $($warnings.Count)" -ForegroundColor $(if($failures.Count){'Red'}else{'Green'})
if ($failures.Count) { exit 1 }
exit 0
