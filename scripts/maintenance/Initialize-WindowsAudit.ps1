#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Production-Ready Windows Security Audit Setup
    Optimized for high-signal / low-noise SIEM ingestion (Fluent Bit).

.DESCRIPTION
    Configures Windows to emit exactly the event IDs consumed by the Sentinel
    Fluent Bit agent. Run once per endpoint before deploying the agent.

    What it sets up:
      1. Event log sizes  — prevents data loss under load
      2. Audit policies   — enables only high-signal subcategories
      3. PowerShell SBL   — EID 4104 (Script Block Logging)
      4. Registry SACLs   — EID 4657 on persistence / credential keys
      5. WMI log          — enables Microsoft-Windows-WMI-Activity/Operational
#>

Write-Host "=== Windows Security Audit Setup (PRODUCTION) ===" -ForegroundColor Cyan

# ─────────────────────────────────────────────
# 1. RESIZE EVENT LOGS (Prevents data loss)
# ─────────────────────────────────────────────
Write-Host "`n[1/5] Increasing Event Log sizes..." -ForegroundColor Yellow

# Classic Logs (PowerShell cmdlet)
$logsToResize = @(
    @{ Name = "Security";            SizeMB = 1024 },
    @{ Name = "System";              SizeMB = 500  },
    @{ Name = "Windows PowerShell";  SizeMB = 500  }
)
foreach ($log in $logsToResize) {
    if (Get-EventLog -List | Where-Object Log -eq $log.Name) {
        Limit-EventLog -LogName $log.Name -MaximumSize ($log.SizeMB * 1MB) -OverflowAction OverwriteAsNeeded
        Write-Host "  OK $($log.Name) resized to $($log.SizeMB) MB" -ForegroundColor Green
    }
}

# Operational Logs (wevtutil - values in bytes)
$operationalLogs = @{
    "Microsoft-Windows-PowerShell/Operational"    = 524288000   # 500 MB
    "Microsoft-Windows-WMI-Activity/Operational"  = 104857600   # 100 MB
    "Microsoft-Windows-TaskScheduler/Operational" = 104857600   # 100 MB
}
foreach ($logName in $operationalLogs.Keys) {
    $size = $operationalLogs[$logName]
    & wevtutil sl "$logName" /ms:$size
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK $logName resized to $([math]::Round($size/1MB)) MB" -ForegroundColor Green
    }
}

# ─────────────────────────────────────────────
# 2. AUDIT POLICIES (High Signal Only)
# ─────────────────────────────────────────────
Write-Host "`n[2/5] Configuring Audit Policies..." -ForegroundColor Yellow

# Force advanced audit policy (overrides legacy policy settings)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord -Force

# Each entry: subcategory name + which outcomes to capture
# Emits the EIDs listed in the comment → matched by sysmon_security.lua
$auditPolicies = @(
    # ── Logon / Authentication ────────────────────────────────────────────────
    @{ sub = "Logon";              sf = "success,failure" },  # 4624, 4625, 4634
    @{ sub = "Special Logon";     sf = "success"          },  # 4672 — admin-eq priv on logon
    # ── Credential Use ────────────────────────────────────────────────────────
    @{ sub = "Sensitive Privilege Use"; sf = "success,failure" },  # 4673, 4674
    # ── Process Tracking ──────────────────────────────────────────────────────
    @{ sub = "Process Creation";    sf = "success"          },  # 4688 (with cmdline)
    @{ sub = "Process Termination"; sf = "success"          },  # 4689 (enables Create→Delete→StillRunning correlation for Process Ghosting)
    # ── Object Access ─────────────────────────────────────────────────────────
    @{ sub = "Registry";          sf = "success,failure"  },  # 4657 (requires SACL, see step 4)
    # ── Persistence ───────────────────────────────────────────────────────────
    @{ sub = "Other Object Access Events"; sf = "success,failure" },  # 4698-4702 (tasks)
    @{ sub = "Security System Extension";  sf = "success,failure" },  # 4697 (services)
    # ── Anti-Forensics / Tampering ────────────────────────────────────────────
    @{ sub = "Security State Change"; sf = "success,failure" },  # 1102 (log cleared)
    @{ sub = "Audit Policy Change";   sf = "success,failure" }   # 4719 (policy tampered)
)

foreach ($policy in $auditPolicies) {
    if ($policy.sf -eq "success,failure") {
        $sfArgs = "/success:enable /failure:enable"
    } else {
        $sfArgs = "/success:enable /failure:disable"
    }
    & auditpol /set /subcategory:"$($policy.sub)" $sfArgs.Split(" ") | Out-Null
    Write-Host "  OK $($policy.sub) [$($policy.sf)]" -ForegroundColor Green
}

# Include command line in EID 4688
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item $auditPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty $auditPath -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord -Force
Write-Host "  OK Command line in EID 4688 enabled" -ForegroundColor Green

# ─────────────────────────────────────────────
# 3. POWERSHELL LOGGING (Script Block Only)
# ─────────────────────────────────────────────
Write-Host "`n[3/5] Configuring PowerShell logging..." -ForegroundColor Yellow

$sbPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $sbPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty $sbPath -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force
Write-Host "  OK Script Block Logging (EID 4104) enabled" -ForegroundColor Green
# Note: EnableScriptBlockInvocationLogging is intentionally NOT set — it floods the log
# with 4105/4106 start/stop events that the Lua filter drops anyway.

# ─────────────────────────────────────────────
# 4. REGISTRY SACLs (Persistence & Credentials)
# ─────────────────────────────────────────────
Write-Host "`n[4/5] Setting Registry SACLs (EID 4657)..." -ForegroundColor Yellow

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
    "Run keys  (HKLM RunOnce/Run — startup persistence)"
Set-RegistryAudit "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" `
    "AppInit_DLLs  (DLL injection via registry)"
Set-RegistryAudit "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
    "LSA secrets  (credential store tampering)"
Set-RegistryAudit "HKLM:\SYSTEM\CurrentControlSet\Services" `
    "Services (DACL tampering / hidden persistence via Security-descriptor deletion)"

# ─────────────────────────────────────────────
# 5. WMI LOGGING
# ─────────────────────────────────────────────
Write-Host "`n[5/5] Enabling WMI Activity logging..." -ForegroundColor Yellow

$wmiLog = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction SilentlyContinue
if ($wmiLog) {
    $wmiLog.IsEnabled = $true
    $wmiLog.SaveChanges()
    Write-Host "  OK WMI-Activity/Operational log enabled" -ForegroundColor Green
} else {
    Write-Host "  WARN WMI-Activity/Operational log not found (WMI service may be disabled)" -ForegroundColor Yellow
}

Write-Host "`nProduction setup complete." -ForegroundColor Cyan
Write-Host "Logs resized. High-signal auditing enabled." -ForegroundColor Cyan
Write-Host "Deploy the Sentinel agent (Install-SentinelService.ps1) now." -ForegroundColor Cyan
