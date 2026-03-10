#Requires -RunAsAdministrator
# --- Install SentinelAgent as a Windows Service (via NSSM) ---
# Runs Fluent Bit under its own Virtual Service Account (NT SERVICE\SentinelAgent)
# with least-privilege file and event-log permissions.
#
# Run order: Install-SentinelService.ps1  →  Install-LuaWatcherService.ps1

$ServiceName   = "SentinelAgent"
$LauncherScript = Join-Path $PSScriptRoot "launcher.ps1"

# --- Read config ---
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) { throw "Config file not found at $ConfigPath" }

$cfg       = Get-Content $ConfigPath -Raw
$AgentPath = "C:\ProgramData\SEIP"
if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

# Use the NSSM copy from the tools directory if present.
# winget installs NSSM to C:\Users\...\AppData  -  NT SERVICE\* VSAs cannot execute it
# (CreateProcessAsUser checks the binary is readable by the target user token).
# Prepend the tools path so 'nssm install' registers a VSA-accessible binary path.
$ToolsNssm = Join-Path $AgentPath ".tools\nssm.exe"
if (Test-Path $ToolsNssm) { $env:Path = "$(Split-Path $ToolsNssm);" + $env:Path }

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

# --- Ensure agent directory and logs exist ---
$LogDir = Join-Path $AgentPath "logs"
foreach ($dir in @($AgentPath, $LogDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# --- Deploy launcher and Fluent Bit assets to $AgentPath ---
# Running scripts from C:\Users\...\Documents\... while executing as a privileged VSA
# is a Local Privilege Escalation vector: any process running as the installing user
# can modify the script. $AgentPath (C:\ProgramData\SEIP) is admin-only writable.
Write-Host "Deploying launcher and config assets to $AgentPath..."
$FluentBitSrcDir = Join-Path $PSScriptRoot "..\fluent-bit"
Copy-Item -Path $LauncherScript -Destination (Join-Path $AgentPath "launcher.ps1") -Force
$FetchScript = Join-Path $PSScriptRoot "fetch_lua_filters.py"
if (Test-Path $FetchScript) {
    Copy-Item -Path $FetchScript -Destination (Join-Path $AgentPath "fetch_lua_filters.py") -Force
    Write-Host "  Deployed fetch_lua_filters.py" -ForegroundColor DarkGray
} else {
    Write-Warning "  fetch_lua_filters.py not found at $FetchScript  -  Lua filter bundle fetch will fail at runtime."
}
foreach ($asset in @("agent-config.tpl", "sysmon_security.lua", "sysmon_pack.lua")) {
    $src = Join-Path $FluentBitSrcDir $asset
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $AgentPath $asset) -Force
        Write-Host "  Deployed $asset" -ForegroundColor DarkGray
    }
}
# Point the service registration at the deployed (admin-controlled) copy
$LauncherScript = Join-Path $AgentPath "launcher.ps1"

# --- Create service ---
Write-Host "Installing $ServiceName..."
nssm install $ServiceName "powershell.exe" "-ExecutionPolicy Bypass -NoProfile -File `"$LauncherScript`""

nssm set $ServiceName DisplayName  "Sentinel Security Agent"
nssm set $ServiceName Description  "Fluent Bit log collector for Sentinel SEIP"
nssm set $ServiceName Start        SERVICE_AUTO_START

# ── Least-privilege: run under Virtual Service Account ────────────────────────
# IMPORTANT: Do NOT use `nssm set ObjectName` for Virtual Service Accounts.
# NSSM calls LogonUser() which requires a password  -  VSAs have none, so it
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
    Write-Error "VSA not applied  -  sc.exe qc reports: $startName"
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
nssm set $ServiceName AppRestartDelay 5000

# Logs
nssm set $ServiceName AppStdout     "$LogDir\service.log"
nssm set $ServiceName AppStderr     "$LogDir\service-error.log"
nssm set $ServiceName AppRotateFiles 1
nssm set $ServiceName AppRotateBytes 10485760  # 10MB

# ── File system permissions ───────────────────────────────────────────────────
# Full control on $AgentPath so the agent can read config/Lua and write its logs.
Write-Host "Granting NT SERVICE\$ServiceName Full Control on $AgentPath..."
& icacls $AgentPath /grant "NT SERVICE\${ServiceName}:(OI)(CI)F" /T | Out-Null

# Read+Execute on the repo scripts directory so the VSA can run launcher.ps1.
# Read on the fluent-bit directory for the config template and Lua sources.
# Read on config.yaml for AgentPath/ToolsPath resolution.
# These are read-only grants; no secrets are in the repo (credentials are in .env,
# which is deployed separately to $AgentPath).
Write-Host "Granting NT SERVICE\$ServiceName Read on repo script directories..."
$FluentBitDir = Join-Path $PSScriptRoot "..\fluent-bit"
$ConfigFile   = Join-Path $PSScriptRoot "..\config.yaml"
& icacls $PSScriptRoot /grant "NT SERVICE\${ServiceName}:(OI)(CI)RX" | Out-Null
if (Test-Path $FluentBitDir) { & icacls $FluentBitDir /grant "NT SERVICE\${ServiceName}:(OI)(CI)R" /T | Out-Null }
if (Test-Path $ConfigFile)   { & icacls $ConfigFile   /grant "NT SERVICE\${ServiceName}:R"           | Out-Null }

# ── Event Log Readers ─────────────────────────────────────────────────────────
# Fluent Bit must read Windows Event Logs (Sysmon, Security, etc.)
# Adding to the built-in group is the standard least-privilege approach.
Write-Host "Adding NT SERVICE\$ServiceName to 'Event Log Readers'..."
try {
    Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\$ServiceName" -ErrorAction Stop
    Write-Host "  Done." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "already a member") {
        Write-Host "  Already a member  -  skipping." -ForegroundColor Yellow
    } else {
        Write-Warning "Could not add to Event Log Readers: $_"
    }
}

# ── Deploy credentials ────────────────────────────────────────────────────────
# NT SERVICE\SentinelAgent cannot read the repo directory (user profile), so copy
# .env into $AgentPath where the VSA already has Full Control.
$RepoEnv = Join-Path $PSScriptRoot "..\.env"
$AgentEnv = Join-Path $AgentPath ".env"
if (Test-Path $RepoEnv) {
    Copy-Item -Path $RepoEnv -Destination $AgentEnv -Force
    Write-Host "Copied .env to $AgentEnv (readable by NT SERVICE\$ServiceName)."
} else {
    Write-Warning ".env not found at $RepoEnv  -  service will fail to load credentials."
    Write-Warning "Create .env in the repo root with PRODUCER_API_KEY, PRODUCER_API_SECRET, BOOTSTRAP_SERVER."
}

# --- Start service ---
# Use sc.exe start, not nssm start: nssm tries to grant SeServiceLogonRight via LSA before
# starting, which fails for Virtual Service Accounts (error: Access is denied).
# sc.exe routes through the SCM which handles VSA logon rights natively.
Write-Host "Starting $ServiceName..."
& sc.exe start $ServiceName

Get-Service $ServiceName | Format-List Name, Status, StartType
Write-Host "`nDone! SentinelAgent runs as NT SERVICE\$ServiceName (least-privilege)." -ForegroundColor Green
Write-Host "`nNext step: run Install-LuaWatcherService.ps1 to install the filter watcher."
Write-Host "Commands:"
Write-Host "  Stop:    nssm stop $ServiceName"
Write-Host "  Start:   nssm start $ServiceName"
Write-Host "  Restart: nssm restart $ServiceName"
Write-Host "  Remove:  nssm remove $ServiceName confirm"

# Service configuration succeeded. If the service is not Running, it is a runtime issue
# (e.g. missing credentials)  -  check C:\ProgramData\SEIP\logs\service-error.log.
# Exit 0 so that callers (e.g. Setup-Sentinel.ps1) do not treat a startup failure as an
# install failure; nssm start's non-zero exit code must not bleed into $LASTEXITCODE.
exit 0
