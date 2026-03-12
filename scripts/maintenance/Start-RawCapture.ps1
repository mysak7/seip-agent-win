#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Runs Fluent Bit without any Lua filters and captures all events to a file.
    Runs until stopped with Ctrl+C. No services involved.

.DESCRIPTION
    Uses the same Windows Event Log inputs as the production config but strips
    all Lua filters and replaces the Kafka output with a local file output.
    SQLite DB files are written to a temp directory to avoid conflicting with
    any running SentinelAgent service.
    Prints events/second to the console every 5 seconds.

.PARAMETER FbExe
    Path to the Fluent Bit executable. Defaults to the standard install location.

.EXAMPLE
    .\Start-RawCapture.ps1
    .\Start-RawCapture.ps1 -FbExe "C:\custom\fluent-bit.exe"
#>
param(
    [string]$FbExe = 'C:\ProgramData\SEIP\.tools\fluent-bit\bin\fluent-bit.exe'
)

$ErrorActionPreference = 'Stop'
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutputFile = Join-Path $ScriptDir "raw-capture-$Timestamp.log"
$TempDir    = Join-Path $env:TEMP "seip-raw-$Timestamp"
$TempConfig = Join-Path $env:TEMP "fb-raw-$Timestamp.conf"

if (-not (Test-Path $FbExe)) {
    Write-Error "Fluent Bit not found at: $FbExe`nRun Install-Prerequisites.ps1 first or pass -FbExe with the correct path."
    exit 1
}

New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# Build a minimal config: same inputs as production, zero Lua filters, file output.
# 'out_file' format: "<unix-ts>, <tag>: <JSON-record>"  — supported in all FB 3.x versions.
# Uses a separate temp DB dir so the capture does not conflict with a running service.
$config = @"
[SERVICE]
    Flush        1
    Log_Level    info

# Sysmon
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-Sysmon/Operational
    Interval_Sec 1
    DB           $TempDir\sysmon.sqlite
    Tag          sysmon

# Windows Security log
[INPUT]
    Name         winevtlog
    Channels     Security
    Interval_Sec 1
    DB           $TempDir\security.sqlite
    Tag          winsec

# System log (service installs etc.)
[INPUT]
    Name         winevtlog
    Channels     System
    Interval_Sec 5
    DB           $TempDir\system.sqlite
    Tag          winsys

# PowerShell Script Block Logging
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-PowerShell/Operational
    Interval_Sec 1
    DB           $TempDir\powershell.sqlite
    Tag          winps

# Windows Defender detections
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-Windows Defender/Operational
    Interval_Sec 5
    DB           $TempDir\defender.sqlite
    Tag          windef

# WMI Activity
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-WMI-Activity/Operational
    Interval_Sec 5
    DB           $TempDir\wmi.sqlite
    Tag          winwmi

# Task Scheduler
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-TaskScheduler/Operational
    Interval_Sec 5
    DB           $TempDir\taskscheduler.sqlite
    Tag          wints

# No Lua filters - raw pass-through

[OUTPUT]
    Name    file
    Match   *
    Path    $ScriptDir
    File    raw-capture-$Timestamp.log
    Format  out_file
"@

$config | Set-Content -Path $TempConfig -Encoding UTF8

Write-Host "Starting raw Fluent Bit capture (no Lua filters)..."
Write-Host "Output : $OutputFile"
Write-Host "Config : $TempConfig"
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# Count lines in a file without loading it all into memory.
function Get-LineCount([string]$Path) {
    $count = 0
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $reader = [System.IO.StreamReader]::new($stream)
        while ($null -ne $reader.ReadLine()) { $count++ }
        $reader.Dispose()
        $stream.Dispose()
    } catch { }
    return $count
}

# Start Fluent Bit as a background process (output goes to the same console window).
$fbProc = Start-Process -FilePath $FbExe -ArgumentList "-c `"$TempConfig`"" `
    -PassThru -NoNewWindow

$lastCount  = 0
$lastTime   = [DateTime]::UtcNow
$startTime  = $lastTime

try {
    while (-not $fbProc.HasExited) {
        Start-Sleep -Seconds 5

        $now       = [DateTime]::UtcNow
        $total     = if (Test-Path $OutputFile) { Get-LineCount $OutputFile } else { 0 }
        $delta     = $total - $lastCount
        $lastCount = $total
        $lastTime  = $now

        # Average ev/s since capture started (more meaningful than per-interval rate).
        $totalElapsed = ($now - $startTime).TotalSeconds
        $avgRate = if ($totalElapsed -gt 0) {
            [math]::Round($total / $totalElapsed, 2)
        } else { 0 }

        $deltaStr = if ($delta -gt 0) { "+$delta" } else { ' 0' }
        Write-Host ("--- [{0}] {1} total | {2} new in 5s | avg {3} ev/s ---" -f `
            $now.ToLocalTime().ToString('HH:mm:ss'), $total, $deltaStr, $avgRate) `
            -ForegroundColor Cyan
    }
} catch [System.Management.Automation.PipelineStoppedException] {
    # Ctrl+C — fall through to finally
} finally {
    if (-not $fbProc.HasExited) { $fbProc.Kill() }
    $fbProc.WaitForExit(3000) | Out-Null

    Remove-Item -Path $TempConfig -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

    $total = if (Test-Path $OutputFile) { Get-LineCount $OutputFile } else { 0 }
    $totalSec = ([DateTime]::UtcNow - $startTime).TotalSeconds
    $finalAvg = if ($totalSec -gt 0) { [math]::Round($total / $totalSec, 2) } else { 0 }
    Write-Host ""
    Write-Host "Stopped. $total events saved (avg $finalAvg ev/s) -> $OutputFile"
}
