# --- Sentinel Agent Launcher ---

# Read Config from YAML (Simple Parse)
$AgentPath = "C:\ProgramData\SEIP"
$ToolsPath = "C:\ProgramData\SEIP\.tools"
$AllowStartWithoutLatestFilters = $true

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
$LocalLlmLuaPath    = Join-Path $AgentPath "llm_filter.lua"
$LocalAlertLuaPath  = Join-Path $AgentPath "alert_filter.lua"
$BundleUrl          = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/bundle/manifest.json"
$FluentBitExe       = Join-Path $ToolsPath "fluent-bit\bin\fluent-bit.exe"


function _Read-DerLength {
    param([byte[]]$b, [ref]$idx)
    $first = $b[$idx.Value]; $idx.Value++
    if ($first -lt 0x80) { return [int]$first }
    $n = $first -band 0x7F; $len = 0
    for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor $b[$idx.Value]; $idx.Value++ }
    return $len
}

function _New-RSAFromSpki {
    param([string]$Base64Spki)
    $der = [Convert]::FromBase64String(($Base64Spki -replace '\s+', ''))
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $read = 0; $rsa.ImportSubjectPublicKeyInfo([byte[]]$der, [ref]$read); return $rsa
    } catch { }
    $i = [ref]0
    $der[$i.Value++] | Out-Null                          # outer SEQUENCE tag
    _Read-DerLength $der $i | Out-Null
    $der[$i.Value++] | Out-Null                          # AlgorithmIdentifier tag
    $i.Value += _Read-DerLength $der $i                  # skip AlgorithmIdentifier
    $der[$i.Value++] | Out-Null                          # BIT STRING tag
    _Read-DerLength $der $i | Out-Null; $i.Value++       # BIT STRING length + unused bits
    $der[$i.Value++] | Out-Null                          # RSAPublicKey SEQUENCE tag
    _Read-DerLength $der $i | Out-Null
    $der[$i.Value++] | Out-Null; $nLen = _Read-DerLength $der $i  # modulus tag + length
    $nBytes = $der[$i.Value..($i.Value + $nLen - 1)]; $i.Value += $nLen
    $der[$i.Value++] | Out-Null; $eLen = _Read-DerLength $der $i  # exponent tag + length
    $eBytes = $der[$i.Value..($i.Value + $eLen - 1)]
    while ($nBytes.Length -gt 1 -and $nBytes[0] -eq 0x00) { $nBytes = $nBytes[1..($nBytes.Length-1)] }
    while ($eBytes.Length -gt 1 -and $eBytes[0] -eq 0x00) { $eBytes = $eBytes[1..($eBytes.Length-1)] }
    $p = New-Object System.Security.Cryptography.RSAParameters
    $p.Modulus = [byte[]]$nBytes; $p.Exponent = [byte[]]$eBytes
    # PROV_RSA_AES (type 24) supports 4096-bit keys on .NET Framework; NoPrompt for non-interactive use
    $csp = New-Object System.Security.Cryptography.CspParameters(24)
    $csp.Flags = [System.Security.Cryptography.CspProviderFlags]::NoPrompt
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(([int]$nBytes.Count * 8), $csp)
    $rsa.PersistKeyInCsp = $false
    $rsa.ImportParameters($p); return $rsa
}

function _Test-BundleSignature {
    param([PSCustomObject]$Bundle)
    $ordered = [ordered]@{ generated_at=$Bundle.generated_at; noise_filter=$Bundle.noise_filter; user_filter=$Bundle.user_filter }
    $canonical = ($ordered | ConvertTo-Json -Compress -Depth 10) -replace '\\u003c','<' -replace '\\u003e','>' -replace '\\u0026','&'
    $rsa = _New-RSAFromSpki -Base64Spki $LuaPublicKeyB64
    try {
        return $rsa.VerifyData([System.Text.Encoding]::UTF8.GetBytes($canonical),
            [Convert]::FromBase64String($Bundle.signature),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } finally { $rsa.Dispose() }
}

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

    $LuaPublicKeyB64 = $env:LUA_PUBLIC_KEY_B64
    if (-not $KafkaUser -or -not $KafkaPass -or -not $BrokerUrl -or -not $LuaPublicKeyB64) {
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
                if ($line -match "^LUA_PUBLIC_KEY_B64=(.*)") { $LuaPublicKeyB64 = $matches[1].Trim() }
            }
        }
    }

    $missing = @()
    if (-not $KafkaUser) { $missing += "PRODUCER_API_KEY" }
    if (-not $KafkaPass) { $missing += "PRODUCER_API_SECRET" }
    if (-not $BrokerUrl) { $missing += "BOOTSTRAP_SERVER" }
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
try {
    $bundleJson   = Invoke-WebRequest -Uri $BundleUrl -UseBasicParsing -TimeoutSec 15 | Select-Object -ExpandProperty Content
    $bundleObj    = $bundleJson | ConvertFrom-Json
    $sigValid     = _Test-BundleSignature -Bundle $bundleObj
    if (-not $sigValid) { throw "Bundle signature verification FAILED - filters NOT written." }
    [IO.File]::WriteAllText($LocalLlmLuaPath,   $bundleObj.noise_filter, [System.Text.Encoding]::UTF8)
    [IO.File]::WriteAllText($LocalAlertLuaPath, $bundleObj.user_filter, [System.Text.Encoding]::UTF8)
    Write-Host "Lua filters loaded and verified from signed bundle (ts=$($bundleObj.generated_at))." -ForegroundColor Green
} catch {
    if (-not $AllowStartWithoutLatestFilters) {
        Write-Error "Failed to download/verify Lua filter bundle: $_ - LLM filtering cannot fall back to cached files (AllowStartWithoutLatestFilters=false)."
        exit 1
    }
    Write-Warning "Failed to download/verify Lua filter bundle: $_ - LLM filtering will use last cached files."
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
