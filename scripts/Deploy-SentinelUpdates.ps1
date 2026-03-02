#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploy repo changes to a running Sentinel installation.

.DESCRIPTION
    1. Copies Lua filter files from the repo to $AgentPath.
       SentinelAgent is restarted only when at least one file actually changed.
    2. Re-applies all audit subcategory policies (auditpol, idempotent).
    3. Re-applies all registry SACLs (Set-Acl, idempotent).

    Run after every git pull that touches:
      fluent-bit/sysmon_security.lua
      fluent-bit/sysmon_pack.lua
      scripts/maintenance/Initialize-WindowsAudit.ps1
#>

$ErrorActionPreference = "Stop"

# ── Paths ─────────────────────────────────────────────────────────────────────
$RepoRoot   = Resolve-Path (Join-Path $PSScriptRoot "..")
$ConfigPath = Join-Path $RepoRoot "config.yaml"

$AgentPath = "C:\APPS\Sentinel"
if (Test-Path $ConfigPath) {
    $cfg = Get-Content $ConfigPath -Raw
    if    ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
    elseif ($cfg -match "AgentPath:\s*'(.*)'")        { $AgentPath = $matches[1] }
    elseif ($cfg -match 'AgentPath:\s*([^"\s\r\n]+)') { $AgentPath = $matches[1] }
}

$DeployLuaDir = Join-Path $AgentPath "fluent-bit"
$RepoLuaDir   = Join-Path $RepoRoot  "fluent-bit"

Write-Host "`n=== Sentinel Update Deployment ===" -ForegroundColor Cyan
Write-Host "  Repo:   $RepoRoot"
Write-Host "  Deploy: $AgentPath"

# ── 1. LUA FILES ──────────────────────────────────────────────────────────────
Write-Host "`n[1/3] Deploying Lua filter files..." -ForegroundColor Yellow

$luaFiles    = @("sysmon_security.lua", "sysmon_pack.lua")
$needRestart = $false

foreach ($file in $luaFiles) {
    $src = Join-Path $RepoLuaDir  $file
    $dst = Join-Path $DeployLuaDir $file

    if (-not (Test-Path $src)) {
        Write-Host "  SKIP $file (not in repo)" -ForegroundColor DarkGray
        continue
    }

    $changed = $true
    if (Test-Path $dst) {
        $srcHash = (Get-FileHash $src -Algorithm SHA256).Hash
        $dstHash = (Get-FileHash $dst -Algorithm SHA256).Hash
        if ($srcHash -eq $dstHash) { $changed = $false }
    }

    if ($changed) {
        if (-not (Test-Path $DeployLuaDir)) {
            New-Item -ItemType Directory -Path $DeployLuaDir -Force | Out-Null
        }
        Copy-Item $src $dst -Force
        Write-Host "  UPDATED $file" -ForegroundColor Green
        $needRestart = $true
    } else {
        Write-Host "  OK      $file (unchanged)" -ForegroundColor DarkGray
    }
}

# Restart Fluent Bit only when something actually changed
if ($needRestart) {
    $svc = Get-Service "SentinelAgent" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "`n  Restarting SentinelAgent..." -ForegroundColor Yellow
        Restart-Service "SentinelAgent" -Force
        Start-Sleep -Seconds 2
        $svc = Get-Service "SentinelAgent"
        Write-Host "  SentinelAgent status: $($svc.Status)" -ForegroundColor $(
            if ($svc.Status -eq "Running") { "Green" } else { "Red" }
        )
    } else {
        Write-Host "  WARN SentinelAgent service not found — skipping restart." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n  SentinelAgent restart not needed." -ForegroundColor DarkGray
}

# ── 2. AUDIT POLICIES ─────────────────────────────────────────────────────────
Write-Host "`n[2/3] Re-applying audit policies (auditpol)..." -ForegroundColor Yellow

$auditPolicies = @(
    @{ sub = "Logon";                     sf = "success,failure" }
    @{ sub = "Special Logon";             sf = "success"         }
    @{ sub = "Sensitive Privilege Use";   sf = "success,failure" }
    @{ sub = "Process Creation";          sf = "success"         }
    @{ sub = "Process Termination";       sf = "success"         }
    @{ sub = "Registry";                  sf = "success,failure" }
    @{ sub = "Other Object Access Events";sf = "success,failure" }
    @{ sub = "Security System Extension"; sf = "success,failure" }
    @{ sub = "Security State Change";     sf = "success,failure" }
    @{ sub = "Audit Policy Change";       sf = "success,failure" }
)

foreach ($p in $auditPolicies) {
    if ($p.sf -eq "success,failure") {
        $args = @("/success:enable", "/failure:enable")
    } else {
        $args = @("/success:enable", "/failure:disable")
    }
    & auditpol /set /subcategory:"$($p.sub)" @args | Out-Null
    Write-Host "  OK $($p.sub) [$($p.sf)]" -ForegroundColor Green
}

# Include command line in EID 4688
$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item $auditRegPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty $auditRegPath -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord -Force
Write-Host "  OK Command line in EID 4688 enabled" -ForegroundColor Green

# ── 3. REGISTRY SACLs ─────────────────────────────────────────────────────────
Write-Host "`n[3/3] Re-applying registry SACLs (EID 4657)..." -ForegroundColor Yellow

function Set-RegistryAudit {
    param([string]$KeyPath, [string]$Description)
    try {
        $acl  = Get-Acl -Path $KeyPath -Audit -ErrorAction Stop
        $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
            "Everyone",
            "SetValue,CreateSubKey,Delete,ChangePermissions",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success"
        )
        $acl.AddAuditRule($rule)
        Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction Stop
        Write-Host "  OK $Description" -ForegroundColor Green
    } catch {
        Write-Host "  FAIL $Description - $_" -ForegroundColor Red
    }
}

Set-RegistryAudit "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    "Run keys  (startup persistence)"
Set-RegistryAudit "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" `
    "AppInit_DLLs  (DLL injection)"
Set-RegistryAudit "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
    "LSA secrets  (credential store)"
Set-RegistryAudit "HKLM:\SYSTEM\CurrentControlSet\Services" `
    "Services  (DACL tampering / hidden persistence)"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n=== Done ===" -ForegroundColor Cyan
if ($needRestart) {
    Write-Host "  Lua filters updated and SentinelAgent restarted." -ForegroundColor Green
} else {
    Write-Host "  Lua filters already up-to-date. No restart performed." -ForegroundColor DarkGray
}
Write-Host "  Audit policies and SACLs applied." -ForegroundColor Green
