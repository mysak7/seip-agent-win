#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reverses everything Setup-Sentinel.ps1 installed.

.DESCRIPTION
    Removes the Sentinel Agent installation in reverse order:
      1. Stops and removes SentinelLuaWatcher and SentinelAgent services
      2. Removes NT SERVICE\SentinelAgent from Event Log Readers
      3. Uninstalls Sysmon
      4. Removes PATH entries and the C:\ProgramData\SEIP directory
      5. Optionally uninstalls NSSM
      6. Reverts audit policies, PowerShell SBL, registry SACLs, WMI log

.PARAMETER RemoveNSSM
    Also uninstall NSSM via winget. Skipped by default — NSSM may be used by
    other services on the machine.

.PARAMETER KeepLogs
    Copy C:\ProgramData\SEIP\logs to the repo root before deletion.

.NOTES
    Must be run as Administrator.
#>
param(
    [switch]$RemoveNSSM,
    [switch]$KeepLogs
)

$ErrorActionPreference = "Continue"
$RepoRoot = $PSScriptRoot

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Sentinel Agent — Uninstall" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ── Read config (paths may have been customised) ───────────────────────────────
$AgentPath = "C:\ProgramData\SEIP"
$ToolsPath = "C:\ProgramData\SEIP\.tools"

$ConfigPath = Join-Path $RepoRoot "config.yaml"
if (Test-Path $ConfigPath) {
    $cfg = Get-Content $ConfigPath -Raw
    if      ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
    elseif  ($cfg -match "AgentPath:\s*'(.*)'")        { $AgentPath = $matches[1] }
    elseif  ($cfg -match 'AgentPath:\s*([^"\s]+)')     { $AgentPath = $matches[1] }

    if      ($cfg -match 'ToolsPath:\s*"(.*)"')        { $ToolsPath = $matches[1] }
    elseif  ($cfg -match "ToolsPath:\s*'(.*)'")        { $ToolsPath = $matches[1] }
    elseif  ($cfg -match 'ToolsPath:\s*([^"\s]+)')     { $ToolsPath = $matches[1] }
} else {
    Write-Host "config.yaml not found — using default paths." -ForegroundColor Yellow
}

Write-Host "  AgentPath : $AgentPath"
Write-Host "  ToolsPath : $ToolsPath"
Write-Host ""

# ── Helper: strip a directory from the machine-wide PATH ──────────────────────
function Remove-FromPath {
    param([string]$Dir)
    $current = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    $parts   = $current -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $Dir.TrimEnd('\')) }
    $newPath = $parts -join ';'
    if ($newPath -ne $current) {
        [Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Host "  Removed from PATH: $Dir" -ForegroundColor Green
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# 1. Stop and remove services  (LuaWatcher first — it depends on SentinelAgent)
# ────────────────────────────────────────────────────────────────────────────────
Write-Host "--- [1/6] Removing services ---" -ForegroundColor Yellow

foreach ($svcName in @("SentinelLuaWatcher", "SentinelAgent")) {
    if (Get-Service $svcName -ErrorAction SilentlyContinue) {
        Write-Host "  Stopping $svcName..."
        & sc.exe stop $svcName 2>&1 | Out-Null
        Start-Sleep -Seconds 2

        # Prefer the tools-directory copy of nssm (VSA-accessible)
        $NssmExe = Join-Path $ToolsPath "nssm.exe"
        if (Test-Path $NssmExe) {
            & $NssmExe remove $svcName confirm
        } elseif (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm remove $svcName confirm
        } else {
            & sc.exe delete $svcName | Out-Null
        }
        Write-Host "  OK $svcName removed" -ForegroundColor Green
    } else {
        Write-Host "  $svcName not found — skipping" -ForegroundColor DarkGray
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# 2. Remove NT SERVICE\SentinelAgent from Event Log Readers
# ────────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [2/6] Event Log Readers ---" -ForegroundColor Yellow

try {
    Remove-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SentinelAgent" -ErrorAction Stop
    Write-Host "  OK NT SERVICE\SentinelAgent removed from Event Log Readers" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "not a member|not found|no such member|The specified account name is not a member") {
        Write-Host "  Already removed — skipping" -ForegroundColor DarkGray
    } else {
        Write-Host "  WARN $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# 3. Uninstall Sysmon
# ────────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [3/6] Uninstalling Sysmon ---" -ForegroundColor Yellow

$OsBuild = [System.Environment]::OSVersion.Version.Build
$SysmonDir = Join-Path $ToolsPath "Sysmon"
$SysmonExe = Join-Path $SysmonDir "Sysmon.exe"
if (-not (Test-Path $SysmonExe)) { $SysmonExe = Join-Path $SysmonDir "Sysmon64.exe" }

$uninstalledSysmon = $false

# Native optional feature (Windows 11 24H2+ / Server 2025+, build ≥ 26100)
if ($OsBuild -ge 26100) {
    $NativeFeature = Get-WindowsOptionalFeature -Online -FeatureName "Sysmon" -ErrorAction SilentlyContinue
    if ($NativeFeature -and $NativeFeature.State -eq "Enabled") {
        Write-Host "  Disabling native Sysmon optional feature..."
        Disable-WindowsOptionalFeature -Online -FeatureName "Sysmon" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  OK Native Sysmon feature disabled" -ForegroundColor Green
        $uninstalledSysmon = $true
    }

    # Native binary present but not via optional feature
    if (-not $uninstalledSysmon -and (Test-Path "$env:SystemRoot\Sysmon.exe")) {
        $SysmonSvc = Get-Service "Sysmon" -ErrorAction SilentlyContinue
        if (-not $SysmonSvc) { $SysmonSvc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue }
        if ($SysmonSvc) {
            Start-Process -FilePath "$env:SystemRoot\Sysmon.exe" -ArgumentList "-u -force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            Write-Host "  OK Native Sysmon service uninstalled" -ForegroundColor Green
            $uninstalledSysmon = $true
        }
    }
}

# Sysinternals Sysmon fallback
if (-not $uninstalledSysmon) {
    $SysmonSvc = Get-Service "Sysmon" -ErrorAction SilentlyContinue
    if (-not $SysmonSvc) { $SysmonSvc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue }

    if ($SysmonSvc) {
        Write-Host "  Uninstalling Sysmon service..."
        if (Test-Path $SysmonExe) {
            Start-Process -FilePath $SysmonExe -ArgumentList "-u -force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            Write-Host "  OK Sysmon uninstalled via $SysmonExe" -ForegroundColor Green
        } elseif (Get-Command sysmon -ErrorAction SilentlyContinue) {
            Start-Process "sysmon" -ArgumentList "-u -force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            Write-Host "  OK Sysmon uninstalled via PATH" -ForegroundColor Green
        } else {
            Write-Host "  WARN Sysmon service found but executable not located — service may remain" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Sysmon service not found — skipping" -ForegroundColor DarkGray
    }
}

Remove-FromPath $SysmonDir

# ────────────────────────────────────────────────────────────────────────────────
# 4. Remove agent directory and PATH entries
# ────────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [4/6] Removing agent directory ---" -ForegroundColor Yellow

if ($KeepLogs) {
    $LogDir = Join-Path $AgentPath "logs"
    if (Test-Path $LogDir) {
        $Backup = Join-Path $RepoRoot "seip-logs-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item -Path $LogDir -Destination $Backup -Recurse -Force
        Write-Host "  Logs saved to $Backup" -ForegroundColor Cyan
    }
}

Remove-FromPath (Join-Path $ToolsPath "fluent-bit\bin")
Remove-FromPath $ToolsPath

if (Test-Path $AgentPath) {
    Remove-Item $AgentPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  OK $AgentPath removed" -ForegroundColor Green
} else {
    Write-Host "  $AgentPath not found — skipping" -ForegroundColor DarkGray
}

# ────────────────────────────────────────────────────────────────────────────────
# 5. NSSM (optional)
# ────────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [5/6] NSSM ---" -ForegroundColor Yellow

if ($RemoveNSSM) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "  Uninstalling NSSM via winget..."
        winget uninstall NSSM.NSSM --silent 2>&1 | Out-Null
        Write-Host "  OK NSSM uninstalled" -ForegroundColor Green
    } else {
        Write-Host "  WARN winget not available — uninstall NSSM manually" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Skipped (pass -RemoveNSSM to also uninstall NSSM)" -ForegroundColor DarkGray
}

# ────────────────────────────────────────────────────────────────────────────────
# 6. Revert Windows audit configuration
# ────────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [6/6] Reverting Windows audit configuration ---" -ForegroundColor Yellow

# 6a. Audit policies → No Auditing
$auditPolicies = @(
    @{ sub = "Logon";                      guid = "{0CCE9215-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Special Logon";              guid = "{0CCE921B-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Sensitive Privilege Use";    guid = "{0CCE9228-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Process Creation";           guid = "{0CCE922B-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Process Termination";        guid = "{0CCE922C-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Registry";                   guid = "{0CCE921E-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Other Object Access Events"; guid = "{0CCE9227-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Security System Extension";  guid = "{0CCE9211-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Security State Change";      guid = "{0CCE9210-69AE-11D9-BED3-505054503030}" },
    @{ sub = "Audit Policy Change";        guid = "{0CCE922F-69AE-11D9-BED3-505054503030}" }
)

foreach ($policy in $auditPolicies) {
    & auditpol /set /subcategory:$($policy.guid) /success:disable /failure:disable | Out-Null
    Write-Host "  OK $($policy.sub) — No Auditing" -ForegroundColor Green
}

# Revert SCENoApplyLegacyAuditPolicy to default (0)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name SCENoApplyLegacyAuditPolicy -Value 0 -Type DWord -Force
Write-Host "  OK SCENoApplyLegacyAuditPolicy reset to 0" -ForegroundColor Green

# 6b. Process command-line logging (EID 4688)
$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (Test-Path $auditRegPath) {
    Remove-ItemProperty -Path $auditRegPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
    Write-Host "  OK ProcessCreationIncludeCmdLine_Enabled removed" -ForegroundColor Green
}

# 6c. PowerShell Script Block Logging
$sbPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (Test-Path $sbPath) {
    Set-ItemProperty $sbPath -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force
    Write-Host "  OK Script Block Logging (EID 4104) disabled" -ForegroundColor Green
}

# 6d. Registry SACLs
function Remove-RegistryAudit {
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
        $acl.RemoveAuditRule($rule) | Out-Null
        Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction Stop
        Write-Host "  OK $Description" -ForegroundColor Green
    } catch {
        Write-Host "  WARN $Description — $_" -ForegroundColor Yellow
    }
}

Write-Host "  Removing registry SACLs..." -ForegroundColor Yellow
Remove-RegistryAudit "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "Run keys SACL removed"
Remove-RegistryAudit "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "AppInit_DLLs SACL removed"
Remove-RegistryAudit "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" "LSA SACL removed"
Remove-RegistryAudit "HKLM:\SYSTEM\CurrentControlSet\Services" "Services SACL removed"

# 6e. WMI Activity log
$wmiLog = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction SilentlyContinue
if ($wmiLog -and $wmiLog.IsEnabled) {
    $wmiLog.IsEnabled = $false
    $wmiLog.SaveChanges()
    Write-Host "  OK WMI-Activity/Operational log disabled" -ForegroundColor Green
}

# ── Final status ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- Service status ---" -ForegroundColor Yellow
$remaining = Get-Service SentinelAgent, SentinelLuaWatcher -ErrorAction SilentlyContinue
if ($remaining) {
    $remaining | Format-Table Name, Status, StartType -AutoSize
} else {
    Write-Host "  No Sentinel services found." -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Uninstall complete!" -ForegroundColor Green
if (-not $RemoveNSSM) {
Write-Host "  NSSM was left in place. Pass -RemoveNSSM to uninstall it." -ForegroundColor Cyan
}
Write-Host "  Note: icacls grants on the repo scripts directory" -ForegroundColor Cyan
Write-Host "        are harmless but can be cleaned manually with icacls /reset." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
