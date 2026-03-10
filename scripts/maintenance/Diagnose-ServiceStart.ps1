#Requires -RunAsAdministrator
# Diagnoses why SentinelAgent fails to start.

foreach ($svcName in @("SentinelAgent", "SentinelLuaWatcher")) {
    Write-Host "`n══ $svcName ══════════════════════════════════" -ForegroundColor Cyan

    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warning "$svcName not found  -  skipping."; continue }

    Write-Host "Current status : $($svc.Status)"
    Write-Host "Start type     : $($svc.StartType)"

    $qc = & sc.exe qc $svcName
    ($qc | Select-String "SERVICE_START_NAME|BINARY_PATH_NAME|START_TYPE") |
        ForEach-Object { Write-Host "  $_" }

    Write-Host "`nAttempting sc.exe start $svcName ..." -ForegroundColor Yellow
    & sc.exe start $svcName
    Write-Host "sc.exe exit code: $LASTEXITCODE"

    Start-Sleep -Seconds 3
    $status = (Get-Service $svcName).Status
    Write-Host "Status after 3s : $status"
}

Write-Host "`n══ NSSM service logs ══════════════════════════════════" -ForegroundColor Cyan
foreach ($log in @(
    "C:\ProgramData\SEIP\logs\service-error.log",
    "C:\ProgramData\SEIP\logs\service.log",
    "C:\ProgramData\SEIP\logs\lua-watcher-svc-error.log",
    "C:\ProgramData\SEIP\logs\lua-watcher-svc.log"
)) {
    if (Test-Path $log) {
        Write-Host "`n-- $log (last 30 lines) --" -ForegroundColor Yellow
        Get-Content $log -Tail 30
    } else {
        Write-Host "`n-- $log : not found (service may never have started)" -ForegroundColor DarkGray
    }
}

Write-Host "`n══ Windows Application event log (NSSM / service entries) ══" -ForegroundColor Cyan
Get-WinEvent -LogName Application -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'nssm|Sentinel' -or $_.Message -match 'SentinelAgent|SentinelLua' } |
    Select-Object -First 10 |
    Format-List TimeCreated, ProviderName, Id, Message
