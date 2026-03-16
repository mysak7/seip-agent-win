#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Start, stop, or check status of Sentinel services.

.DESCRIPTION
    Manages the two Windows services that make up the Sentinel EDR agent:
      - SentinelAgent      : Fluent Bit log collector → Kafka (threats topic)
      - SentinelLuaWatcher : Lua filter bundle watcher (polls S3, hot-reloads filters)

    Stopping the agent immediately halts all Kafka output.

.PARAMETER Action
    start   – Start both services (watcher first, then agent/Fluent Bit).
    stop    – Stop both services; SentinelAgent is stopped first to cut Kafka output immediately.
    restart – Stop then start.
    status  – Show current service states and Kafka output status.

.EXAMPLE
    .\Manage-Sentinel.ps1 start
    .\Manage-Sentinel.ps1 stop
    .\Manage-Sentinel.ps1 status
    .\Manage-Sentinel.ps1 -Action start
#>

param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('start', 'stop', 'restart', 'status')]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── helpers ────────────────────────────────────────────────────────────────────

function Get-SvcStatus([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return 'NOT INSTALLED' }
    return $svc.Status.ToString()
}

function Start-Svc([string]$Name) {
    $status = Get-SvcStatus $Name
    if ($status -eq 'NOT INSTALLED') { Write-Warning "  $Name — not installed, skipping."; return }
    if ($status -eq 'Running')       { Write-Host "  $Name — already running." -ForegroundColor Green; return }

    Write-Host "  Starting $Name ..." -NoNewline
    try {
        if ($status -eq 'Paused') {
            Resume-Service -Name $Name
        } else {
            Start-Service -Name $Name
        }
        Write-Host ' OK' -ForegroundColor Green
    } catch {
        Write-Host ' FAILED' -ForegroundColor Red
        Write-Error $_
    }
}

function Stop-Svc([string]$Name) {
    $status = Get-SvcStatus $Name
    if ($status -eq 'NOT INSTALLED') { Write-Warning "  $Name — not installed, skipping."; return }
    if ($status -eq 'Stopped')       { Write-Host "  $Name — already stopped." -ForegroundColor DarkYellow; return }

    Write-Host "  Stopping $Name ..." -NoNewline
    try {
        Stop-Service -Name $Name -Force
        Write-Host ' OK' -ForegroundColor DarkYellow
    } catch {
        Write-Host ' FAILED' -ForegroundColor Red
        Write-Error $_
    }
}

# ── actions ────────────────────────────────────────────────────────────────────

function Invoke-Start {
    Write-Host ''
    Write-Host '[ START ]' -ForegroundColor Cyan
    # Watcher first so it is ready to manage the agent; then agent starts Fluent Bit / Kafka
    Start-Svc 'SentinelLuaWatcher'
    Start-Svc 'SentinelAgent'
    Write-Host ''
    Write-Host 'Kafka output: ACTIVE — Fluent Bit is forwarding events to the broker.' -ForegroundColor Green
    Write-Host ''
}

function Invoke-Stop {
    Write-Host ''
    Write-Host '[ STOP ]' -ForegroundColor Cyan
    # Agent first → Fluent Bit exits → Kafka output stops immediately
    Stop-Svc 'SentinelAgent'
    Stop-Svc 'SentinelLuaWatcher'
    Write-Host ''
    Write-Host 'Kafka output: STOPPED — no events are being forwarded.' -ForegroundColor DarkYellow
    Write-Host ''
}

function Invoke-Status {
    Write-Host ''
    Write-Host '[ STATUS ]' -ForegroundColor Cyan
    $pad = -25
    foreach ($name in @('SentinelAgent', 'SentinelLuaWatcher')) {
        $s = Get-SvcStatus $name
        $color = switch ($s) {
            'Running'       { 'Green'      }
            'Stopped'       { 'DarkYellow' }
            'NOT INSTALLED' { 'Red'        }
            default         { 'Gray'       }
        }
        Write-Host ("  {0,$pad}  {1}" -f $name, $s) -ForegroundColor $color
    }

    Write-Host ''
    if ((Get-SvcStatus 'SentinelAgent') -eq 'Running') {
        Write-Host '  Kafka output:  ACTIVE' -ForegroundColor Green
    } else {
        Write-Host '  Kafka output:  STOPPED' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

# ── dispatch ───────────────────────────────────────────────────────────────────

switch ($Action) {
    'start'   { Invoke-Start  }
    'stop'    { Invoke-Stop   }
    'restart' { Invoke-Stop; Invoke-Start }
    'status'  { Invoke-Status }
}
