# --- Sentinel Agent Launcher ---

# Read Config from YAML (Simple Parse)
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) { 
    Write-Warning "Config file not found at $ConfigPath. Using defaults."
    $AgentPath = "C:\APPS\Sentinel"
    $ToolsPath = "C:\APPS\Sentinel\.tools"
} else {
    $ConfigContent = Get-Content $ConfigPath -Raw
    
    $AgentPath = "C:\APPS\Sentinel"
    if ($ConfigContent -match 'AgentPath:\s*"(.*)"') { $AgentPath = $matches[1] }
    elseif ($ConfigContent -match "AgentPath:\s*'(.*)'") { $AgentPath = $matches[1] }
    elseif ($ConfigContent -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }
    
    $ToolsPath = "C:\APPS\Sentinel\.tools"
    if ($ConfigContent -match 'ToolsPath:\s*"(.*)"') { $ToolsPath = $matches[1] }
    elseif ($ConfigContent -match "ToolsPath:\s*'(.*)'") { $ToolsPath = $matches[1] }
    elseif ($ConfigContent -match 'ToolsPath:\s*([^"\s]+)') { $ToolsPath = $matches[1] }
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
$LocalLlmLuaPath    = Join-Path $AgentPath "llm_filter.lua"
$LlmLuaUrl          = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/noise_filter.lua"
$FluentBitExe       = Join-Path $ToolsPath "fluent-bit\bin\fluent-bit.exe"

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
    $KafkaUser = $env:PRODUCER_API_KEY
    $KafkaPass = $env:PRODUCER_API_SECRET
    $BrokerUrl = $env:BOOTSTRAP_SERVER

    if (-not $KafkaUser -or -not $KafkaPass -or -not $BrokerUrl) {
        # Fallback to .env file. Check two locations:
        #   1. Repo root  — works when running manually as an interactive user
        #   2. $AgentPath — works when running as NT SERVICE\SentinelAgent (VSA has Full Control
        #      on $AgentPath but no access to the user-profile repo directory)
        $envCandidates = @("$PSScriptRoot\..\.env", (Join-Path $AgentPath ".env"))
        $envFile = $envCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($envFile) {
            Write-Host "Loading credentials from .env file ($envFile)..."
            foreach ($line in Get-Content $envFile) {
                if ($line -match "^PRODUCER_API_KEY=(.*)") { $KafkaUser = $matches[1].Trim() }
                if ($line -match "^PRODUCER_API_SECRET=(.*)") { $KafkaPass = $matches[1].Trim() }
                if ($line -match "^BOOTSTRAP_SERVER=(.*)") { $BrokerUrl = $matches[1].Trim() }
            }
        }
    }

    if (-not $KafkaUser -or -not $KafkaPass -or -not $BrokerUrl) {
        throw "Credentials could not be loaded from Environment Variables or .env file."
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
try {
    Invoke-WebRequest -Uri $LlmLuaUrl -OutFile $LocalLlmLuaPath -UseBasicParsing
} catch {
    Write-Warning "Failed to download LLM noise filter from $LlmLuaUrl - LLM noise filtering will be disabled."
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
