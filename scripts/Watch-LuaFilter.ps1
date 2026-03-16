# --- Sentinel Lua Filter Watcher ---
# Polls bundle/manifest.json from S3, verifies KMS RSA-4096 PKCS#1v1.5-SHA256 signature,
# and writes both noise_filter (noise_filter.lua) and user_filter (user_filter.lua).
# Runs every 5 minutes, clock-aligned to :02/:07/:12/:17/:22/...

$BundleUrl   = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/bundle/manifest.json"
$ServiceName = "SentinelAgent"
$FetchScript = Join-Path $PSScriptRoot "fetch_lua_filters.py"

# --- Read public key from .env (written by Terraform) ---
# When deployed to $AgentPath the script is no longer under the repo root, so check
# the same directory first (deployed copy) then fall back to ..\.env (dev/source tree).
$LuaPublicKeyB64 = $null
foreach ($candidate in @(
    (Join-Path $PSScriptRoot ".env"),
    (Join-Path $PSScriptRoot "..\.env")
)) {
    if (Test-Path $candidate) {
        foreach ($line in (Get-Content $candidate)) {
            if ($line -match '^LUA_PUBLIC_KEY_B64=(.+)$') { $LuaPublicKeyB64 = $matches[1]; break }
        }
        if ($LuaPublicKeyB64) { break }
    }
}

# --- Read config ---
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
$AgentPath  = "C:\ProgramData\SEIP"

if (Test-Path $ConfigPath) {
    $cfg = Get-Content $ConfigPath -Raw
    if ($cfg -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
    elseif ($cfg -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
    elseif ($cfg -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }
}

$LocalNoiseFilterPath  = Join-Path $AgentPath "noise_filter.lua"
$LocalUserFilterPath   = Join-Path $AgentPath "user_filter.lua"
$LocalStaticFilterPath = Join-Path $AgentPath "static_filter.lua"
$StateFilePath         = Join-Path $AgentPath "noise_filter.state"
$LogDir            = Join-Path $AgentPath "logs"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path (Join-Path $LogDir "noise-watcher.log") -Value $line
}

# Returns seconds until the next clock minute where (minute % 5 == 2).
# Schedule: :02, :07, :12, :17, :22, :27, :32, :37, :42, :47, :52, :57
function Get-SecondsUntilNextRun {
    $now       = Get-Date
    $minMod    = $now.Minute % 5
    $minToNext = (2 - $minMod + 5) % 5
    if ($minToNext -eq 0 -and $now.Second -gt 0) { $minToNext = 5 }
    return $minToNext * 60 - $now.Second
}

if (-not $LuaPublicKeyB64) {
    Write-Log "LUA_PUBLIC_KEY_B64 not found in .env - cannot verify bundles." "ERROR"
    exit 1
}

Write-Log "Lua filter watcher started. Schedule: every 5 min, aligned to :02/:07/:12/..."

while ($true) {
    $waitSec  = Get-SecondsUntilNextRun
    $nextTime = (Get-Date).AddSeconds($waitSec).ToString("HH:mm")
    Write-Log "Next check at $nextTime (in ${waitSec}s)."
    Start-Sleep -Seconds $waitSec

    try {
        $_venvPy = @(
            (Join-Path $PSScriptRoot ".venv\Scripts\python.exe"),
            (Join-Path $AgentPath    ".venv\Scripts\python.exe")
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1
        $pyExe = if ($_venvPy) { $_venvPy } else {
            @('python', 'python3', 'py') | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
        }
        if (-not $pyExe) { throw "Python not found. Create a .venv with 'python -m venv .venv && .venv\Scripts\pip install cryptography' or install Python 3 on PATH." }
        $pyOut = & $pyExe $FetchScript `
            --bundle-url   $BundleUrl `
            --pub-key-b64  $LuaPublicKeyB64 `
            --noise-path   $LocalNoiseFilterPath `
            --user-path    $LocalUserFilterPath `
            --static-path  $LocalStaticFilterPath `
            --state-file   $StateFilePath 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Log $pyOut
            # Restart SentinelAgent so Fluent Bit picks up the new filters
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Log "Restarting $ServiceName..."
                Restart-Service -Name $ServiceName -Force
                Write-Log "$ServiceName restarted successfully."
            } else {
                Write-Log "$ServiceName not found - skipping restart." "WARN"
            }
        } elseif ($LASTEXITCODE -eq 2) {
            Write-Log $pyOut  # up-to-date
        } else {
            Write-Log "fetch_lua_filters.py error: $pyOut" "ERROR"
        }
    } catch {
        Write-Log "Error during check: $_" "ERROR"
    }
}
