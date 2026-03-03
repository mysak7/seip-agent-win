#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Captures identity, command line and parent of powershell.exe processes that contact S3.
    Run this while the Sentinel services are active to catch who actually owns the download.

.DESCRIPTION
    Polls every second for powershell.exe processes.
    For each new PID found, logs:
      - Process owner (domain\user)
      - Full command line
      - Parent PID + parent image
      - Service name if the process belongs to a Windows service
    Also does a one-time dump of current SentinelAgent / SentinelLuaWatcher service config.

.OUTPUTS
    Logs to: .\process-identity.log  (same directory as this script)

.EXAMPLE
    # Run for 15 minutes, then stop with Ctrl+C
    powershell -ExecutionPolicy Bypass -File Watch-ProcessIdentity.ps1
#>

$LogFile    = Join-Path $PSScriptRoot "process-identity.log"
$SeenPids   = @{}          # track PIDs we already logged so we don't spam
$PollMs     = 1000         # poll interval in milliseconds

# ── helpers ──────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ss"), $Level, $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Get-ProcessOwner([int]$ProcId) {
    try {
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction Stop
        if (-not $wmi) { return "N/A (process gone)" }
        $owner = $wmi.GetOwner()
        if ($owner.ReturnValue -eq 0) {
            return "$($owner.Domain)\$($owner.User)"
        }
        return "GetOwner() failed (rv=$($owner.ReturnValue))"
    } catch { return "WMI error: $_" }
}

function Get-ProcessCommandLine([int]$ProcId) {
    try {
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction Stop
        return if ($wmi.CommandLine) { $wmi.CommandLine.Trim() } else { "<empty>" }
    } catch { return "N/A" }
}

function Get-ParentInfo([int]$ProcId) {
    try {
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction Stop
        if (-not $wmi) { return "N/A" }
        $ppid = $wmi.ParentProcessId
        $parent = Get-WmiObject Win32_Process -Filter "ProcessId=$ppid" -ErrorAction SilentlyContinue
        $parentName = if ($parent) { $parent.Name } else { "<gone>" }
        return "PID=$ppid ($parentName)"
    } catch { return "N/A" }
}

function Get-ServiceForPid([int]$ProcId) {
    try {
        $svc = Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq $ProcId }
        if ($svc) { return "$($svc.Name) [$($svc.StartName)]" }
        # Check parent PID too
        $wmi   = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue
        $ppid  = if ($wmi) { $wmi.ParentProcessId } else { 0 }
        $psvc  = Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq $ppid }
        if ($psvc) { return "via parent svc: $($psvc.Name) [$($psvc.StartName)]" }
        return "-"
    } catch { return "N/A" }
}

# ── one-time service config dump ──────────────────────────────────────────────

Write-Log "=== Watch-ProcessIdentity started ==="
Write-Log "Logging to: $LogFile"

foreach ($svcName in @("SentinelAgent", "SentinelLuaWatcher")) {
    $svc = Get-WmiObject Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log ("SERVICE DUMP  Name={0}  StartName={1}  State={2}  PathName={3}" -f `
            $svc.Name, $svc.StartName, $svc.State, $svc.PathName)
    } else {
        Write-Log "SERVICE DUMP  $svcName  NOT FOUND" "WARN"
    }
}

Write-Log "Polling for powershell.exe every ${PollMs}ms — press Ctrl+C to stop."

# ── main polling loop ─────────────────────────────────────────────────────────

while ($true) {
    $procs = Get-Process -Name "powershell" -ErrorAction SilentlyContinue

    foreach ($p in $procs) {
        $procId = $p.Id

        # skip already-logged PIDs
        if ($SeenPids.ContainsKey($procId)) { continue }
        $SeenPids[$procId] = $true

        $owner  = Get-ProcessOwner      $procId
        $cmd    = Get-ProcessCommandLine $procId
        $parent = Get-ParentInfo        $procId
        $svc    = Get-ServiceForPid     $procId

        Write-Log "NEW powershell.exe PID=$procId"
        Write-Log "  Owner  : $owner"
        Write-Log "  Parent : $parent"
        Write-Log "  Service: $svc"
        Write-Log "  CmdLine: $cmd"
        Write-Log "  ---"
    }

    # prune dead PIDs from tracking set to avoid memory growth on long runs
    $alivePids = ($procs | ForEach-Object { $_.Id })
    $deadKeys  = $SeenPids.Keys | Where-Object { $_ -notin $alivePids }
    foreach ($k in $deadKeys) { $SeenPids.Remove($k) }

    Start-Sleep -Milliseconds $PollMs
}
