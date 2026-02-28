#Requires -RunAsAdministrator
# --- Sentinel Lua Filter Watcher ---
# Polls noise_filter.meta from S3, downloads new Lua if ts changed, restarts SentinelAgent.

$MetaUrl    = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/noise_filter.meta"
$LuaUrl     = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/noise_filter.lua"
$ServiceName = "SentinelAgent"

# --- Read config ---
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
$AgentPath  = "C:\APPS\Sentinel"
$PollSec    = 300  # default 5 minutes

if (Test-Path $ConfigPath) {
    $cfg = Get-Content $ConfigPath -Raw
    if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
    elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
    elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

    if ($cfg -match 'LuaWatcherInterval:\s*(\d+)') { $PollSec = [int]$matches[1] }
}

$LocalLuaPath  = Join-Path $AgentPath "llm_filter.lua"
$StateFilePath = Join-Path $AgentPath "lua_filter.state"
$LogDir        = Join-Path $AgentPath "logs"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path (Join-Path $LogDir "lua-watcher.log") -Value $line
}

Write-Log "Lua filter watcher started. Poll interval: ${PollSec}s"

while ($true) {
    try {
        # 1. Fetch meta
        $metaJson = Invoke-WebRequest -Uri $MetaUrl -UseBasicParsing -TimeoutSec 15 |
                    Select-Object -ExpandProperty Content
        $meta = $metaJson | ConvertFrom-Json

        $remoteTsRaw = $meta.ts
        if (-not $remoteTsRaw) { throw "Meta response missing 'ts' field." }

        # 2. Read last known ts
        $lastTs = if (Test-Path $StateFilePath) { Get-Content $StateFilePath -Raw | ForEach-Object { $_.Trim() } } else { "" }

        if ($remoteTsRaw -ne $lastTs) {
            Write-Log "New Lua version detected. Remote ts=$remoteTsRaw  Last ts=$lastTs"

            # 3. Download new Lua
            Invoke-WebRequest -Uri $LuaUrl -OutFile $LocalLuaPath -UseBasicParsing -TimeoutSec 30
            Write-Log "Downloaded noise_filter.lua (archive_key=$($meta.archive_key))"

            # 4. Persist new ts
            Set-Content -Path $StateFilePath -Value $remoteTsRaw -Encoding ASCII

            # 5. Restart SentinelAgent so Fluent Bit picks up the new filter
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Log "Restarting $ServiceName..."
                Restart-Service -Name $ServiceName -Force
                Write-Log "$ServiceName restarted successfully."
            } else {
                Write-Log "$ServiceName not found — skipping restart." "WARN"
            }
        } else {
            Write-Log "Lua filter up-to-date (ts=$remoteTsRaw)."
        }
    } catch {
        Write-Log "Error during check: $_" "ERROR"
    }

    Start-Sleep -Seconds $PollSec
}
