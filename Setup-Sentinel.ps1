#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-shot bootstrap: clones the repo (if needed) and runs all setup scripts in order.

.DESCRIPTION
    Run this script once on a fresh endpoint after cloning the repository.
    It will:
      1. Configure Windows audit policy and event log sizes
      2. Install Sysmon, Fluent Bit, and NSSM
      3. Install SentinelAgent as a Windows service
      4. Install SentinelLuaWatcher as a Windows service
      5. Verify both services are running

.PARAMETER SkipLogResize
    Pass -SkipLogResize to skip event log size increases in the Windows Audit Setup step.
    Useful when log sizes are already managed by GPO or a previous run.

.NOTES
    Must be run as Administrator.
    Credentials must be set as environment variables (or in a .env file in the repo root):
        PRODUCER_API_KEY
        PRODUCER_API_SECRET
        BOOTSTRAP_SERVER
#>
param(
    [switch]$SkipLogResize
)

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Sentinel Agent — Full Setup" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Repo: $RepoRoot"
Write-Host ""

# ── Guard: config must exist ──────────────────────────────────────────────────
if (-not (Test-Path (Join-Path $RepoRoot "config.yaml"))) {
    Write-Error "config.yaml not found in $RepoRoot. Make sure you are running this from the repo root."
    exit 1
}

# ── Helper ────────────────────────────────────────────────────────────────────
function Invoke-Step {
    param([string]$Label, [string]$ScriptPath, [hashtable]$ScriptArgs = @{})
    Write-Host ""
    Write-Host "--- $Label ---" -ForegroundColor Yellow
    if (-not (Test-Path $ScriptPath)) {
        Write-Error "Script not found: $ScriptPath"
        exit 1
    }
    & $ScriptPath @ScriptArgs
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Error "$Label failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Host "  OK $Label" -ForegroundColor Green
}

# ── Step 1: Windows audit policy (run first — idempotent, no deps) ────────────
Invoke-Step "Windows Audit Setup" (Join-Path $RepoRoot "scripts\maintenance\Initialize-WindowsAudit.ps1") @{ SkipLogResize = $SkipLogResize }

# ── Step 2: Install Sysmon, Fluent Bit, NSSM ─────────────────────────────────
Invoke-Step "Install Prerequisites" (Join-Path $RepoRoot "scripts\Install-Prerequisites.ps1")

# ── Step 3: Install SentinelAgent service ─────────────────────────────────────
Invoke-Step "Install Sentinel Service" (Join-Path $RepoRoot "scripts\Install-SentinelService.ps1")

# ── Step 4: Install SentinelLuaWatcher service ────────────────────────────────
Invoke-Step "Install Lua Watcher Service" (Join-Path $RepoRoot "scripts\Install-LuaWatcherService.ps1")

# ── Step 5: Verify ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- Service Status ---" -ForegroundColor Yellow
Get-Service SentinelAgent, SentinelLuaWatcher -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "  Manage services with:" -ForegroundColor Cyan
Write-Host "    nssm stop/start/restart SentinelAgent" -ForegroundColor Cyan
Write-Host "    nssm stop/start/restart SentinelLuaWatcher" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
