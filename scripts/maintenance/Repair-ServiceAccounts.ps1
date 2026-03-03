#Requires -RunAsAdministrator
# Opraví stávající instalaci: nastaví VSA místo LocalSystem pro obě Sentinel služby.

foreach ($svcName in @("SentinelAgent", "SentinelLuaWatcher")) {
    Write-Host "`n── $svcName ──────────────────────────────────"

    if (-not (Get-Service $svcName -ErrorAction SilentlyContinue)) {
        Write-Warning "$svcName not found — skipping."
        continue
    }

    Write-Host "Stopping $svcName..."
    & sc.exe stop $svcName | Out-Null
    Start-Sleep -Seconds 3

    Write-Host "Setting NT SERVICE\$svcName as logon account..."
    $result = & sc.exe config $svcName obj= "NT SERVICE\$svcName" password= ""
    if ($LASTEXITCODE -ne 0) {
        Write-Error "sc.exe config failed (exit $LASTEXITCODE): $result"
        continue
    }

    $startName = (& sc.exe qc $svcName | Select-String "SERVICE_START_NAME").ToString().Trim()
    if ($startName -notmatch [regex]::Escape("NT SERVICE\$svcName")) {
        Write-Error "VSA not applied — sc.exe qc reports: $startName"
        continue
    }
    Write-Host "  Verified: $startName" -ForegroundColor Green

    Write-Host "Starting $svcName..."
    & sc.exe start $svcName | Out-Null
}

Write-Host "`nDone. Run 'sc.exe qc SentinelAgent' and 'sc.exe qc SentinelLuaWatcher' to confirm." -ForegroundColor Green
