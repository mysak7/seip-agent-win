# Nastavení hledaného ID a Logu
$LogName  = 'Microsoft-Windows-WMI-Activity/Operational'
$RecordId = 598942

# XML dotaz pro přímé vytažení konkrétního RecordID (velmi rychlé)
$xmlQuery = @"
<QueryList>
  <Query Id="0" Path="$LogName">
    <Select Path="$LogName">*[System[(EventRecordID=$RecordId)]]</Select>
  </Query>
</QueryList>
"@

try {
    # Získání eventu
    $event = Get-WinEvent -FilterXml $xmlQuery -ErrorAction Stop

    Write-Host "✅ Event s RecordID $RecordId nalezen!" -ForegroundColor Green
    Write-Host "----------------------------------------"
    
    # 1. Základní výpis (Čas, ID události, Celá zpráva)
    $event | Format-List TimeCreated, Id, LevelDisplayName, RecordId, MachineName, Message

    # 2. Detailní parsování dat (pro přesné ověření PID, Providera atd.)
    Write-Host "--- Přesná data (EventData) pro porovnání ---" -ForegroundColor Cyan
    
    # Převedení do XML pro čitelný výpis jednotlivých polí
    [xml]$xmlContent = $event.ToXml()
    $xmlContent.Event.EventData.Data | 
        Select-Object @{N='Název';E={$_.Name}}, @{N='Hodnota';E={$_.'#text'}} | 
        Format-Table -AutoSize

} catch {
    Write-Warning "Event s RecordID $RecordId nebyl v logu '$LogName' nalezen."
    Write-Host "Tip: Ověřte, zda spouštíte PowerShell jako Administrátor a zda log nebyl promazán/přepsán (retence)."
}
