#Requires -RunAsAdministrator
# --- Install SentinelLuaWatcher as a Windows Service (via NSSM) ---
# Runs Watch-LuaFilter.ps1 under its own Virtual Service Account (NT SERVICE\SentinelLuaWatcher).
# Grants it ONLY the permissions it needs:
#   - Modify on $AgentPath  (write lua file, state file, watcher logs)
#   - Start + Stop + QueryStatus on SentinelAgent service (via SDDL)
#
# Run order: Install-SentinelService.ps1  →  Install-LuaWatcherService.ps1
# (SentinelAgent must already exist so we can update its SDDL.)

$ServiceName  = "SentinelLuaWatcher"
$AgentService = "SentinelAgent"
$WatcherScript = Join-Path $PSScriptRoot "Watch-LuaFilter.ps1"

# --- Read config ---
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) { throw "Config file not found at $ConfigPath" }

$cfg       = Get-Content $ConfigPath -Raw
$AgentPath = "C:\ProgramData\SEIP"
if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

# Use the NSSM copy from the tools directory if present.
# winget installs NSSM to C:\Users\...\AppData — NT SERVICE\* VSAs cannot execute it
# (CreateProcessAsUser checks the binary is readable by the target user token).
# Prepend the tools path so 'nssm install' registers a VSA-accessible binary path.
$ToolsNssm = Join-Path $AgentPath ".tools\nssm.exe"
if (Test-Path $ToolsNssm) { $env:Path = "$(Split-Path $ToolsNssm);" + $env:Path }

# --- Guard: SentinelAgent must exist first ---
if (-not (Get-Service $AgentService -ErrorAction SilentlyContinue)) {
    Write-Error "$AgentService service not found. Run Install-SentinelService.ps1 first."
    exit 1
}

# --- Check NSSM ---
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "NSSM is not installed. Please install NSSM first."
    exit 1
}

# --- Remove old service if present ---
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing $ServiceName service..."
    nssm stop $ServiceName
    nssm remove $ServiceName confirm
}

# --- Ensure log directory exists ---
$LogDir = Join-Path $AgentPath "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# --- Deploy watcher script to $AgentPath ---
# Running Watch-LuaFilter.ps1 from C:\Users\...\Documents\... while executing as a privileged VSA
# is a Local Privilege Escalation vector: any process running as the installing user can modify
# the script and have it executed with the VSA's privileges. $AgentPath is admin-only writable.
Write-Host "Deploying Watch-LuaFilter.ps1 to $AgentPath..."
Copy-Item -Path $WatcherScript -Destination (Join-Path $AgentPath "Watch-LuaFilter.ps1") -Force
$WatcherScript = Join-Path $AgentPath "Watch-LuaFilter.ps1"

# --- Create service ---
Write-Host "Installing $ServiceName..."
nssm install $ServiceName "powershell.exe" "-ExecutionPolicy Bypass -NoProfile -File `"$WatcherScript`""

nssm set $ServiceName DisplayName  "Sentinel Lua Filter Watcher"
nssm set $ServiceName Description  "Polls S3 for updated noise_filter.lua and hot-reloads SentinelAgent when a new version is detected."
nssm set $ServiceName Start        SERVICE_AUTO_START

# ── Least-privilege: run under Virtual Service Account ────────────────────────
# IMPORTANT: Do NOT use `nssm set ObjectName` for Virtual Service Accounts.
# NSSM calls LogonUser() which requires a password — VSAs have none, so it
# returns Access Denied when SCM tries to start the service.
# Use sc.exe config instead; SCM handles VSAs natively (no password needed).
Write-Host "Configuring Virtual Service Account (NT SERVICE\$ServiceName) via sc.exe..."
# Omit password= entirely: passing password= "" sends an empty string to ChangeServiceConfig
# which Windows rejects for VSAs (error 1057). Omitting it passes lpPassword=NULL, which is correct.
$scResult = & sc.exe config $ServiceName obj= "NT SERVICE\$ServiceName"
if ($LASTEXITCODE -ne 0) {
    Write-Error "sc.exe config failed (exit $LASTEXITCODE): $scResult"
    exit 1
}
$startName = (& sc.exe qc $ServiceName | Select-String "SERVICE_START_NAME").ToString().Trim()
if ($startName -notmatch [regex]::Escape("NT SERVICE\$ServiceName")) {
    Write-Error "VSA not applied — sc.exe qc reports: $startName"
    exit 1
}
Write-Host "  Verified: $startName" -ForegroundColor Green

# sc.exe config obj= calls ChangeServiceConfig() which replaces the service SDDL,
# stripping the standard Builtin Administrators (BA) and SYSTEM (SY) ACEs.
# Restore the default DACL so Administrators can start/stop/manage the service.
$defaultSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
Write-Host "  Restoring default service SDDL (ensuring admin access)..." -ForegroundColor Yellow
$sdResult = & sc.exe sdset $ServiceName $defaultSddl
if ($LASTEXITCODE -ne 0) {
    Write-Error "sc.exe sdset failed (exit $LASTEXITCODE): $sdResult"
    exit 1
}
Write-Host "  SDDL restored." -ForegroundColor Green

# Restart on failure
nssm set $ServiceName AppExit Default Restart
nssm set $ServiceName AppRestartDelay 10000

# Logs
nssm set $ServiceName AppStdout     "$LogDir\lua-watcher-svc.log"
nssm set $ServiceName AppStderr     "$LogDir\lua-watcher-svc-error.log"
nssm set $ServiceName AppRotateFiles 1
nssm set $ServiceName AppRotateBytes 5242880  # 5MB

# ── File system permissions ───────────────────────────────────────────────────
# Modify (not Full) — watcher writes Lua + state + logs, but cannot change ACLs.
Write-Host "Granting NT SERVICE\$ServiceName Modify on $AgentPath..."
& icacls $AgentPath /grant "NT SERVICE\${ServiceName}:(OI)(CI)M" /T | Out-Null

# ── SDDL: delegate Start+Stop+QueryStatus on SentinelAgent ───────────────────
# This is the key least-privilege grant: the watcher can ONLY restart SentinelAgent,
# nothing else. No admin, no other services.
Write-Host "Delegating restart rights over $AgentService to NT SERVICE\$ServiceName..."

# Resolve the Virtual Service Account SID.
# The SID exists as soon as the service is registered in SCM (no first-run needed).
try {
    $principal = New-Object System.Security.Principal.NTAccount("NT SERVICE\$ServiceName")
    $watcherSID = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "  Watcher SID: $watcherSID"
} catch {
    Write-Warning "Could not resolve SID for NT SERVICE\$($ServiceName): $_"
    Write-Warning "Start the service once manually, then re-run this installer to apply SDDL."
    $watcherSID = $null
}

if ($watcherSID) {
    # Fetch current SDDL of SentinelAgent
    $rawSDDL = (& sc.exe sdshow $AgentService) | Where-Object { $_ -match '\S' }
    $currentSDDL = ($rawSDDL -join "").Trim()

    if ($currentSDDL -notmatch '^D:') {
        Write-Warning "Unexpected SDDL from sc sdshow $AgentService ('$currentSDDL'). Skipping SDDL update."
    } else {
        # ACE rights:  RP=Start  WP=Stop  LC=QueryStatus
        $ace     = "(A;;RPWPLC;;;$watcherSID)"

        # Insert new ACE right after "D:" (before any existing ACEs)
        $newSDDL = $currentSDDL -replace '(D:[^(]*)', "`$1$ace"

        $result = & sc.exe sdset $AgentService $newSDDL
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  SDDL updated. $ServiceName can now Start/Stop $AgentService." -ForegroundColor Green
        } else {
            Write-Warning "  sc.exe sdset returned $LASTEXITCODE. Output: $result"
            Write-Warning "  You may need to apply the SDDL manually."
        }
    }
}

# --- Start service ---
# Use sc.exe start, not nssm start: nssm tries to grant SeServiceLogonRight via LSA before
# starting, which fails for Virtual Service Accounts (error: Access is denied).
# sc.exe routes through the SCM which handles VSA logon rights natively.
Write-Host "Starting $ServiceName..."
& sc.exe start $ServiceName

Get-Service $ServiceName | Format-List Name, Status, StartType

Write-Host "`nDone! Least-privilege summary:" -ForegroundColor Green
Write-Host "  NT SERVICE\SentinelAgent     — Full Control on $AgentPath, Event Log Readers"
Write-Host "  NT SERVICE\SentinelLuaWatcher — Modify on $AgentPath, Start/Stop SentinelAgent only"
Write-Host "`nCommands:"
Write-Host "  Stop:    nssm stop $ServiceName"
Write-Host "  Start:   nssm start $ServiceName"
Write-Host "  Restart: nssm restart $ServiceName"
Write-Host "  Remove:  nssm remove $ServiceName confirm"

# See Install-SentinelService.ps1 for the rationale.
exit 0
