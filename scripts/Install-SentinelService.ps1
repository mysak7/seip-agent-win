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
$AgentPath = "C:\APPS\Sentinel"
if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

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

# --- Create service ---
Write-Host "Installing $ServiceName..."
nssm install $ServiceName "powershell.exe" "-ExecutionPolicy Bypass -NoProfile -File `"$LauncherScript`""

nssm set $ServiceName DisplayName  "Sentinel Security Agent"
nssm set $ServiceName Description  "Fluent Bit log collector for Sentinel SEIP"
nssm set $ServiceName Start        SERVICE_AUTO_START

# ── Least-privilege: run under Virtual Service Account ────────────────────────
# IMPORTANT: Do NOT use `nssm set ObjectName` for Virtual Service Accounts.
# NSSM calls LogonUser() which requires a password — VSAs have none, so it
# returns Access Denied when SCM tries to start the service.
# Use sc.exe config instead; SCM handles VSAs natively (no password needed).
Write-Host "Configuring Virtual Service Account (NT SERVICE\$ServiceName) via sc.exe..."
$scResult = & sc.exe config $ServiceName obj= "NT SERVICE\$ServiceName" password= ""
if ($LASTEXITCODE -ne 0) {
    Write-Warning "sc.exe config returned $LASTEXITCODE. Output: $scResult"
}

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

# ── Event Log Readers ─────────────────────────────────────────────────────────
# Fluent Bit must read Windows Event Logs (Sysmon, Security, etc.)
# Adding to the built-in group is the standard least-privilege approach.
Write-Host "Adding NT SERVICE\$ServiceName to 'Event Log Readers'..."
try {
    Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\$ServiceName" -ErrorAction Stop
    Write-Host "  Done." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "already a member") {
        Write-Host "  Already a member — skipping." -ForegroundColor Yellow
    } else {
        Write-Warning "Could not add to Event Log Readers: $_"
    }
}

# --- Start service ---
Write-Host "Starting $ServiceName..."
nssm start $ServiceName

Get-Service $ServiceName | Format-List Name, Status, StartType
Write-Host "`nDone! SentinelAgent runs as NT SERVICE\$ServiceName (least-privilege)." -ForegroundColor Green
Write-Host "`nNext step: run Install-LuaWatcherService.ps1 to install the filter watcher."
Write-Host "Commands:"
Write-Host "  Stop:    nssm stop $ServiceName"
Write-Host "  Start:   nssm start $ServiceName"
Write-Host "  Restart: nssm restart $ServiceName"
Write-Host "  Remove:  nssm remove $ServiceName confirm"
