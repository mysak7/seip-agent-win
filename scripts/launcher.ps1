# --- Sentinel Agent Launcher ---

# Read Config from YAML (Simple Parse)
$AgentPath = "C:\ProgramData\SEIP"
$ToolsPath = "C:\ProgramData\SEIP\.tools"
$AllowStartWithoutLatestFilters = $false
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) {
    Write-Warning "Config file not found at $ConfigPath. Using defaults."
} else {
    $ConfigContent = Get-Content $ConfigPath -Raw

    if ($ConfigContent -match 'AgentPath:\s*"(.*)"') { $AgentPath = $matches[1] }
    elseif ($ConfigContent -match "AgentPath:\s*'(.*)'") { $AgentPath = $matches[1] }
    elseif ($ConfigContent -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

    if ($ConfigContent -match 'ToolsPath:\s*"(.*)"') { $ToolsPath = $matches[1] }
    elseif ($ConfigContent -match "ToolsPath:\s*'(.*)'") { $ToolsPath = $matches[1] }
    elseif ($ConfigContent -match 'ToolsPath:\s*([^"\s]+)') { $ToolsPath = $matches[1] }

    if ($ConfigContent -match 'AllowStartWithoutLatestFilters:\s*(true|false)') {
        $AllowStartWithoutLatestFilters = ($matches[1] -eq 'true')
    }
}

# 1. Define paths
# Template and Lua sources: prefer repo location (interactive dev runs), fall back to
# $AgentPath (deployed service runs where $PSScriptRoot IS $AgentPath and no repo exists).
$_repoFbDir        = Join-Path $PSScriptRoot "..\fluent-bit"
$LocalTemplatePath = if (Test-Path (Join-Path $_repoFbDir "agent-config.tpl")) {
                         Join-Path $_repoFbDir "agent-config.tpl"
                     } else { Join-Path $AgentPath "agent-config.tpl" }
$LocalConfigPath   = Join-Path $AgentPath "fluent-bit.conf"
$LocalLuaPath      = Join-Path $AgentPath "sysmon_security.lua"
$RepoLuaPath       = Join-Path $_repoFbDir "sysmon_security.lua"
$LocalPackLuaPath  = Join-Path $AgentPath "sysmon_pack.lua"
$RepoPackLuaPath   = Join-Path $_repoFbDir "sysmon_pack.lua"
$LocalNoiseFilterPath = Join-Path $AgentPath "noise_filter.lua"
$LocalUserFilterPath  = Join-Path $AgentPath "user_filter.lua"
$StateFilePath        = Join-Path $AgentPath "noise_filter.state"
$BundleUrl         = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/bundle/manifest.json"
$FluentBitExe      = Join-Path $ToolsPath "fluent-bit\bin\fluent-bit.exe"
$FetchScript       = Join-Path $PSScriptRoot "fetch_lua_filters.py"

# --- Pre-flight Checks ---
# Check if Sysmon is available (Required for agent-config.tpl)
if (-not (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue)) {
    Write-Warning "CRITICAL: Sysmon is not detected!"
    Write-Warning "The 'Microsoft-Windows-Sysmon/Operational' event log channel is missing."
    Write-Warning "Fluent Bit cannot function without Sysmon."
    Write-Warning "ACTION REQUIRED: Run 'Install-Prerequisites.ps1' as Administrator to install Sysmon."
    exit 1
}

# Ensure target directory exists
if (!(Test-Path $AgentPath)) {
    New-Item -ItemType Directory -Path $AgentPath -Force | Out-Null
}

# 2. Load Credentials
Write-Host "Loading credentials..."
try {
    $KafkaUser       = $env:PRODUCER_API_KEY
    $KafkaPass       = $env:PRODUCER_API_SECRET
    $BrokerUrl       = $env:BOOTSTRAP_SERVER
    $LuaPublicKeyB64 = $env:LUA_PUBLIC_KEY_B64

    if (-not $KafkaUser -or -not $KafkaPass -or -not $BrokerUrl -or -not $LuaPublicKeyB64) {
        # Fallback to .env file. Check two locations:
        #   1. Repo root   -  works when running manually as an interactive user
        #   2. $AgentPath  -  works when running as NT SERVICE\SentinelAgent (VSA has Full Control
        #      on $AgentPath but no access to the user-profile repo directory)
        $envCandidates = @("$PSScriptRoot\..\.env", (Join-Path $AgentPath ".env"))
        $envFile = $envCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($envFile) {
            Write-Host "Loading credentials from .env file ($envFile)..."
            foreach ($line in Get-Content $envFile) {
                if ($line -match "^PRODUCER_API_KEY=(.*)") { $KafkaUser = $matches[1].Trim() }
                if ($line -match "^PRODUCER_API_SECRET=(.*)") { $KafkaPass = $matches[1].Trim() }
                if ($line -match "^BOOTSTRAP_SERVER=(.*)") { $BrokerUrl = $matches[1].Trim() }
                if ($line -match "^LUA_PUBLIC_KEY_B64=(.*)") { $LuaPublicKeyB64 = $matches[1].Trim() }
            }
        }
    }

    $missing = @()
    if (-not $KafkaUser)       { $missing += "PRODUCER_API_KEY" }
    if (-not $KafkaPass)       { $missing += "PRODUCER_API_SECRET" }
    if (-not $BrokerUrl)       { $missing += "BOOTSTRAP_SERVER" }
    if (-not $LuaPublicKeyB64) { $missing += "LUA_PUBLIC_KEY_B64" }
    if ($missing.Count -gt 0) {
        throw "Missing credentials: $($missing -join ', '). Set them as environment variables or add to .env file."
    }

    Write-Host "Credentials successfully loaded." -ForegroundColor Green
} catch {
    Write-Error "Error loading credentials: $_"
    exit 1
}

# 3. Load configuration template
Write-Host "Loading configuration template..."
try {
    if (Test-Path $LocalTemplatePath) {
        $Template = Get-Content -Path $LocalTemplatePath -Raw
        Write-Host "Configuration loaded from local file."
    } else {
        throw "Configuration template not found at $LocalTemplatePath"
    }
} catch {
    Write-Error "Cannot load config template. $_"
    exit 1
}

# 4. Injecting Secrets and Paths
# This ensures passwords are not in Git, but are present in the running process.
$FinalConfig = $Template -replace "{{BROKER_URL}}",  $BrokerUrl `
                         -replace "{{KAFKA_USER}}",  $KafkaUser `
                         -replace "{{KAFKA_PASS}}",  $KafkaPass `
                         -replace "{{AGENT_PATH}}",  $AgentPath

# 5. Deploy Lua filter scripts alongside the config
if (Test-Path $RepoLuaPath) {
    Copy-Item -Path $RepoLuaPath -Destination $LocalLuaPath -Force
} elseif (-not (Test-Path $LocalLuaPath)) {
    Write-Warning "Lua filter script not found at $RepoLuaPath - security filtering will be disabled."
}
if (Test-Path $RepoPackLuaPath) {
    Copy-Item -Path $RepoPackLuaPath -Destination $LocalPackLuaPath -Force
} elseif (-not (Test-Path $LocalPackLuaPath)) {
    Write-Warning "Lua pack script not found at $RepoPackLuaPath - payload compaction will be disabled."
}

# Download, verify and write noise_filter.lua + user_filter.lua via Python
Write-Host "Fetching Lua filter bundle..."
$_venvPy = @(
    (Join-Path $PSScriptRoot   ".venv\Scripts\python.exe"),
    (Join-Path $AgentPath      ".venv\Scripts\python.exe")
) | Where-Object {
    if (-not (Test-Path $_)) { return $false }
    # Verify the venv python is actually executable by this account
    try { & $_ --version 2>&1 | Out-Null; $LASTEXITCODE -eq 0 } catch { $false }
} | Select-Object -First 1
$pyExe = if ($_venvPy) { $_venvPy } else {
    @('python', 'python3', 'py') | ForEach-Object {
        $cmd = Get-Command $_ -ErrorAction SilentlyContinue
        if ($cmd) {
            # Verify the resolved executable actually runs under this account.
            # File-read access is not sufficient: e.g. `py.exe` (the Python launcher)
            # may be readable but delegate to a user-profile python.exe that the
            # service account (NT SERVICE\SentinelAgent) cannot execute.
            try {
                & $cmd.Source --version 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $cmd.Source }
            } catch { <# not executable - skip #> }
        }
    } | Where-Object { $_ } | Select-Object -First 1
}
if (-not $pyExe) {
    $pyMsg = "Python not found. Create a .venv with 'python -m venv .venv && .venv\Scripts\pip install cryptography' or install Python 3 on PATH."
    if ($AllowStartWithoutLatestFilters) { Write-Warning $pyMsg } else { Write-Error $pyMsg; exit 1 }
}
$pyOut = & $pyExe $FetchScript `
    --bundle-url  $BundleUrl `
    --pub-key-b64 $LuaPublicKeyB64 `
    --noise-path  $LocalNoiseFilterPath `
    --user-path   $LocalUserFilterPath `
    --state-file  $StateFilePath 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host $pyOut -ForegroundColor Green
} elseif ($LASTEXITCODE -eq 2) {
    Write-Host $pyOut  # up-to-date, not an error
} else {
    if ($AllowStartWithoutLatestFilters) {
        Write-Warning "Failed to fetch/verify Lua filters: $pyOut"
    } else {
        Write-Error "Failed to fetch/verify Lua filters: $pyOut"
        exit 1
    }
}

# 6. Saving final config (only for this run)
$FinalConfig | Out-File -FilePath $LocalConfigPath -Encoding ascii

# 7. Starting Agent
Write-Host "Starting Sentinel Agent (Fluent Bit)..."
if (Test-Path $FluentBitExe) {
    & $FluentBitExe -c $LocalConfigPath
} else {
    Write-Warning "Fluent Bit executable not found at $FluentBitExe. Please install Fluent Bit using Install-Prerequisites.ps1"
    Write-Host "Generated Config content:"
    Write-Host $FinalConfig
}
