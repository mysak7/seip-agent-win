#Requires -RunAsAdministrator

# Read Config from YAML (Simple Parse)
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) { throw "Config file not found at $ConfigPath" }

$ConfigContent = Get-Content $ConfigPath -Raw

$AgentPath = "C:\APPS\Sentinel"
if ($ConfigContent -match 'AgentPath:\s*"(.*)"') { $AgentPath = $matches[1] }
elseif ($ConfigContent -match "AgentPath:\s*'(.*)'") { $AgentPath = $matches[1] }
elseif ($ConfigContent -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

$ServiceName = "SentinelAgent"
$LauncherScript = Join-Path $PSScriptRoot "launcher.ps1"

# Check if NSSM exists
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "NSSM is not installed. Please install NSSM manually."
    exit 1
}

# Remove older service if it exists
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing older service..."
    nssm stop $ServiceName
    nssm remove $ServiceName confirm
}

# Create service
Write-Host "Creating service $ServiceName..."
nssm install $ServiceName "powershell.exe" "-ExecutionPolicy Bypass -NoProfile -File `"$LauncherScript`""

# Set parameters
nssm set $ServiceName DisplayName "Sentinel Security Agent"
nssm set $ServiceName Description "Fluent Bit log collector for Sentinel"
nssm set $ServiceName Start SERVICE_AUTO_START

# Restart on failure
nssm set $ServiceName AppExit Default Restart
nssm set $ServiceName AppRestartDelay 5000

# Log output (optional)
# Ensure log directory exists
$LogDir = Join-Path $AgentPath "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force
}

nssm set $ServiceName AppStdout "$LogDir\service.log"
nssm set $ServiceName AppStderr "$LogDir\service-error.log"
nssm set $ServiceName AppRotateFiles 1
nssm set $ServiceName AppRotateBytes 10485760  # 10MB

# Start service
Write-Host "Starting service..."
nssm start $ServiceName

# Status
Get-Service $ServiceName | Format-List Name, Status, StartType

Write-Host "`nDone! The service will run on every system startup." -ForegroundColor Green
Write-Host "Commands:"
Write-Host "  Stop:    nssm stop $ServiceName"
Write-Host "  Start:   nssm start $ServiceName"
Write-Host "  Restart: nssm restart $ServiceName"
Write-Host "  Remove:  nssm remove $ServiceName confirm"
