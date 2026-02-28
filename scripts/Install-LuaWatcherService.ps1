#Requires -RunAsAdministrator
# --- Install Sentinel Lua Filter Watcher as a Windows Service (via NSSM) ---

$ServiceName   = "SentinelLuaWatcher"
$WatcherScript = Join-Path $PSScriptRoot "Watch-LuaFilter.ps1"

# Read AgentPath from config
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) { throw "Config file not found at $ConfigPath" }

$cfg       = Get-Content $ConfigPath -Raw
$AgentPath = "C:\APPS\Sentinel"
if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

# Check NSSM
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "NSSM is not installed. Please install NSSM first."
    exit 1
}

# Remove old service if present
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing $ServiceName service..."
    nssm stop $ServiceName
    nssm remove $ServiceName confirm
}

# Create service
Write-Host "Installing $ServiceName..."
nssm install $ServiceName "powershell.exe" "-ExecutionPolicy Bypass -NoProfile -File `"$WatcherScript`""

nssm set $ServiceName DisplayName  "Sentinel Lua Filter Watcher"
nssm set $ServiceName Description  "Polls S3 for updated noise_filter.lua and hot-reloads SentinelAgent when a new version is detected."
nssm set $ServiceName Start        SERVICE_AUTO_START

# Restart on failure
nssm set $ServiceName AppExit Default Restart
nssm set $ServiceName AppRestartDelay 10000

# Logs
$LogDir = Join-Path $AgentPath "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

nssm set $ServiceName AppStdout     "$LogDir\lua-watcher-svc.log"
nssm set $ServiceName AppStderr     "$LogDir\lua-watcher-svc-error.log"
nssm set $ServiceName AppRotateFiles 1
nssm set $ServiceName AppRotateBytes 5242880  # 5MB

# Start
Write-Host "Starting $ServiceName..."
nssm start $ServiceName

Get-Service $ServiceName | Format-List Name, Status, StartType
Write-Host "`nDone! The watcher service will start automatically on every boot." -ForegroundColor Green
Write-Host "Commands:"
Write-Host "  Stop:    nssm stop $ServiceName"
Write-Host "  Start:   nssm start $ServiceName"
Write-Host "  Restart: nssm restart $ServiceName"
Write-Host "  Remove:  nssm remove $ServiceName confirm"
