#Requires -RunAsAdministrator

$ServiceName = "SentinelAgent"

# Remove Sentinel service
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
        Write-Error "NSSM is not installed. Cannot remove service."
        exit 1
    }

    Write-Host "Stopping and removing $ServiceName service..."
    nssm stop $ServiceName
    nssm remove $ServiceName confirm
    Write-Host "$ServiceName service removed." -ForegroundColor Green
} else {
    Write-Host "$ServiceName service not found. Nothing to remove." -ForegroundColor Yellow
}
