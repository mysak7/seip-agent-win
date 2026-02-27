# Enable PowerShell Script Block Logging
# This script must be run as Administrator

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "Enabling PowerShell Script Block Logging..." -ForegroundColor Cyan

# Registry path for PowerShell logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# Create the registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    Write-Host "Creating registry key: $regPath" -ForegroundColor Yellow
    New-Item -Path $regPath -Force | Out-Null
}

# Enable Script Block Logging
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Write-Host "✓ Script Block Logging enabled" -ForegroundColor Green

# Optional: Enable logging of invocation start/stop events (more detailed)
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
Write-Host "✓ Script Block Invocation Logging enabled (detailed mode)" -ForegroundColor Green

Write-Host "`nPowerShell Script Block Logging is now ENABLED!" -ForegroundColor Green
Write-Host "`nLogs will appear in:" -ForegroundColor Cyan
Write-Host "  Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational" -ForegroundColor White
Write-Host "  Look for Event ID 4104" -ForegroundColor White

Write-Host "`nTest it by running:" -ForegroundColor Cyan
Write-Host '  powershell -Command "Write-Host ''Test logging''"' -ForegroundColor White
Write-Host "Then check Event Viewer for the logged command." -ForegroundColor White
