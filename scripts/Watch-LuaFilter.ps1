# --- Sentinel Lua Filter Watcher ---
# Polls noise_filter.meta from S3, downloads new Lua if ts changed, restarts SentinelAgent.
# Runs every 5 minutes, clock-aligned to :07/:12/:17/:22/... (minute % 5 == 2).

$MetaUrl     = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/noise_filter.meta"
$LuaUrl      = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/noise_filter.lua"
$ServiceName = "SentinelAgent"

# --- Read config ---
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
$AgentPath  = "C:\APPS\Sentinel"

if (Test-Path $ConfigPath) {
    $cfg = Get-Content $ConfigPath -Raw
    if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
    elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
    elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }
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

# Returns seconds to sleep until the next clock minute where (minute % 5 == 2).
# Produces the schedule: :02, :07, :12, :17, :22, :27, :32, :37, :42, :47, :52, :57
function Get-SecondsUntilNextRun {
    $now       = Get-Date
    $minMod    = $now.Minute % 5
    $minToNext = (2 - $minMod + 5) % 5
    if ($minToNext -eq 0 -and $now.Second -gt 0) { $minToNext = 5 }
    return $minToNext * 60 - $now.Second
}

Write-Log "Lua filter watcher started. Schedule: every 5 min, aligned to :07/:12/:17/..."

while ($true) {
    $waitSec  = Get-SecondsUntilNextRun
    $nextTime = (Get-Date).AddSeconds($waitSec).ToString("HH:mm")
    Write-Log "Next check at $nextTime (in ${waitSec}s)."
    Start-Sleep -Seconds $waitSec

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
                Write-Log "$ServiceName not found - skipping restart." "WARN"
            }
        } else {
            Write-Log "Lua filter up-to-date (ts=$remoteTsRaw)."
        }
    } catch {
        Write-Log "Error during check: $_" "ERROR"
    }
}
