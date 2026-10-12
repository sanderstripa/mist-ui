param(
    [string]$Config = ".\client.json",
    [string]$OutputDirectory = ".\mist-debug",
    [int]$EventHours = 2
)

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$root = Join-Path $OutputDirectory "mist-$stamp"
New-Item -ItemType Directory -Force -Path $root | Out-Null

function Save-Text([string]$Name, [scriptblock]$Block) {
    $path = Join-Path $root $Name
    try { & $Block 2>&1 | Out-String -Width 4096 | Set-Content -Encoding UTF8 $path }
    catch { $_ | Out-String | Set-Content -Encoding UTF8 $path }
}

function Redact-Config([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    try {
        $cfg = Get-Content -Raw -Path $Path | ConvertFrom-Json
        foreach ($name in @('token','token_secret','private_key','ech_config_base64')) {
            if ($cfg.PSObject.Properties.Name -contains $name) { $cfg.$name = '<redacted>' }
        }
        if ($cfg.endpoint -and ($cfg.endpoint.PSObject.Properties.Name -contains 'ech_config_base64')) { $cfg.endpoint.ech_config_base64 = '<redacted>' }
        if ($cfg.endpoints) {
            foreach ($e in $cfg.endpoints) { if ($e.PSObject.Properties.Name -contains 'ech_config_base64') { $e.ech_config_base64 = '<redacted>' } }
        }
        $cfg | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 (Join-Path $root 'client-config-redacted.json')
    } catch {
        "Config parse failed: $($_.Exception.Message)" | Set-Content -Encoding UTF8 (Join-Path $root 'client-config-redacted.txt')
    }
}

Redact-Config $Config
Save-Text 'system.txt' { Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture,CsTotalPhysicalMemory }
Save-Text 'adapters.txt' { Get-NetAdapter | Sort-Object ifIndex | Format-Table -Auto Name,InterfaceDescription,ifIndex,Status,LinkSpeed,MacAddress }
Save-Text 'ip-addresses.txt' { Get-NetIPAddress | Sort-Object InterfaceIndex,AddressFamily | Format-Table -Auto InterfaceAlias,InterfaceIndex,AddressFamily,IPAddress,PrefixLength,AddressState }
Save-Text 'routes-v4.txt' { Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix,RouteMetric | Format-Table -Auto DestinationPrefix,InterfaceAlias,InterfaceIndex,NextHop,RouteMetric,State }
Save-Text 'routes-v6.txt' { Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix,RouteMetric | Format-Table -Auto DestinationPrefix,InterfaceAlias,InterfaceIndex,NextHop,RouteMetric,State }
Save-Text 'dns.txt' { Get-DnsClientServerAddress | Format-List InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses }
Save-Text 'dns-guards.txt' { Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'MIST-*'} | Format-List Name,DisplayName,Enabled,Direction,Action,Profile }
Save-Text 'tcp.txt' { Get-NetTCPConnection -ErrorAction SilentlyContinue | Sort-Object State,RemoteAddress | Format-Table -Auto State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess }
Save-Text 'udp.txt' { Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalAddress,LocalPort | Format-Table -Auto LocalAddress,LocalPort,OwningProcess }
Save-Text 'proxy.txt' { netsh winhttp show proxy }
Save-Text 'winsock.txt' { netsh winsock show catalog }
Save-Text 'ipconfig.txt' { ipconfig /all }
Save-Text 'mist-process.txt' { Get-Process | Where-Object {$_.ProcessName -like 'mist-*'} | Format-List Id,ProcessName,Path,StartTime,CPU,WorkingSet64 }

$since = (Get-Date).AddHours(-[math]::Abs($EventHours))
Save-Text 'network-events.txt' {
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} -ErrorAction SilentlyContinue |
        Where-Object {$_.ProviderName -match 'Tcpip|DNS|NetworkProfile|NlaSvc|WLAN|Dhcp'} |
        Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message
}

$summary = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    hostname = $env:COMPUTERNAME
    qlog_directory = $env:QLOGDIR
    note = 'Secrets are redacted from the copied JSON config. Review the bundle before sharing; system/network metadata can still be sensitive.'
}
$summary | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $root 'README.json')

$zip = "$root.zip"
Compress-Archive -Path (Join-Path $root '*') -DestinationPath $zip -Force
Write-Host "MIST debug bundle: $zip" -ForegroundColor Green
Write-Host "Review its contents before sharing." -ForegroundColor Yellow
