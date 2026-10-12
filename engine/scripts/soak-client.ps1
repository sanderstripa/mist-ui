param(
    [int]$DurationMinutes = 60,
    [string]$SmallUrl = "https://example.com/",
    [string]$DownloadUrl = "https://speed.cloudflare.com/__down?bytes=10485760",
    [string]$DnsName = "example.com",
    [int]$PauseSeconds = 3,
    [string]$Output = ".\mist-soak.jsonl"
)

$ErrorActionPreference = "Continue"
$until = (Get-Date).AddMinutes($DurationMinutes)
$iteration = 0
$ok = 0
$failed = 0

function Emit($obj) {
    $line = $obj | ConvertTo-Json -Compress -Depth 5
    Add-Content -Path $Output -Value $line -Encoding UTF8
    $line
}

"" | Set-Content -Path $Output -Encoding UTF8
Write-Host "MIST soak test for $DurationMinutes minute(s). Log: $Output" -ForegroundColor Cyan

while ((Get-Date) -lt $until) {
    $iteration++
    $started = Get-Date
    $record = [ordered]@{
        time = $started.ToString("o")
        iteration = $iteration
        dns_ok = $false
        small_http_ok = $false
        download_ok = $false
        download_bytes = 0
        elapsed_ms = 0
        error = ""
    }
    try {
        $dns = Resolve-DnsName -Name $DnsName -Type A -DnsOnly -ErrorAction Stop
        $record.dns_ok = ($dns.Count -gt 0)

        $small = Invoke-WebRequest -UseBasicParsing -Uri $SmallUrl -TimeoutSec 20 -ErrorAction Stop
        $record.small_http_ok = ($small.StatusCode -ge 200 -and $small.StatusCode -lt 500)

        $tmp = [System.IO.Path]::GetTempFileName()
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $DownloadUrl -OutFile $tmp -TimeoutSec 60 -ErrorAction Stop
            $record.download_bytes = (Get-Item $tmp).Length
            $record.download_ok = ($record.download_bytes -gt 0)
        } finally { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }

        if ($record.dns_ok -and $record.small_http_ok -and $record.download_ok) { $ok++ } else { $failed++ }
    } catch {
        $failed++
        $record.error = $_.Exception.Message
    }
    $record.elapsed_ms = [int]((Get-Date) - $started).TotalMilliseconds
    Emit ([pscustomobject]$record) | Out-Null
    $rate = if (($ok+$failed) -gt 0) { [math]::Round(100*$ok/($ok+$failed),2) } else { 0 }
    Write-Host ("[{0}] ok={1} failed={2} success={3}% last={4}ms" -f $iteration,$ok,$failed,$rate,$record.elapsed_ms)
    Start-Sleep -Seconds $PauseSeconds
}

$successRate = if (($ok+$failed) -gt 0) { 100*$ok/($ok+$failed) } else { 0 }
$summary = [pscustomobject]@{
    completed_at = (Get-Date).ToString("o")
    iterations = $iteration
    ok = $ok
    failed = $failed
    success_percent = [math]::Round($successRate,3)
}
Emit $summary
if ($failed -gt 0) { exit 1 }
exit 0
