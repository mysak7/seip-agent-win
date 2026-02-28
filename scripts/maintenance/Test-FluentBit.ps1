#Requires -RunAsAdministrator
# Run Fluent Bit locally with stdout output and HTTP metrics.
# No Kafka credentials needed.
# After starting, check filter stats: curl http://localhost:2020/api/v1/metrics

$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (Test-Path $ConfigPath) {
    $ConfigContent = Get-Content $ConfigPath -Raw
    $AgentPath = "C:\APPS\Sentinel"
    if ($ConfigContent -match 'AgentPath:\s*"(.*)"') { $AgentPath = $matches[1] }
    elseif ($ConfigContent -match "AgentPath:\s*'(.*)'") { $AgentPath = $matches[1] }
    elseif ($ConfigContent -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }
    $ToolsPath = "C:\APPS\Sentinel\.tools"
    if ($ConfigContent -match 'ToolsPath:\s*"(.*)"') { $ToolsPath = $matches[1] }
    elseif ($ConfigContent -match "ToolsPath:\s*'(.*)'") { $ToolsPath = $matches[1] }
    elseif ($ConfigContent -match 'ToolsPath:\s*([^"\s]+)') { $ToolsPath = $matches[1] }
} else {
    $AgentPath = "C:\APPS\Sentinel"
    $ToolsPath  = "C:\APPS\Sentinel\.tools"
}

$TemplatePath    = Join-Path $PSScriptRoot "..\fluent-bit\agent-config-debug.tpl"
$RepoLuaPath     = Join-Path $PSScriptRoot "..\fluent-bit\sysmon_security.lua"
$LocalLuaPath    = Join-Path $AgentPath "sysmon_security.lua"
$RepoPackLuaPath = Join-Path $PSScriptRoot "..\fluent-bit\sysmon_pack.lua"
$LocalPackLuaPath = Join-Path $AgentPath "sysmon_pack.lua"
$DebugConfPath   = Join-Path $AgentPath "fluent-bit-debug.conf"
$FluentBitExe    = Join-Path $ToolsPath "fluent-bit\bin\fluent-bit.exe"

if (-not (Test-Path $TemplatePath)) { Write-Error "Debug template not found: $TemplatePath"; exit 1 }
if (-not (Test-Path $FluentBitExe)) { Write-Error "fluent-bit.exe not found: $FluentBitExe"; exit 1 }

if (!(Test-Path $AgentPath)) { New-Item -ItemType Directory -Path $AgentPath -Force | Out-Null }

# Deploy Lua scripts
Copy-Item -Path $RepoLuaPath     -Destination $LocalLuaPath     -Force
Copy-Item -Path $RepoPackLuaPath -Destination $LocalPackLuaPath -Force

# Generate debug config
$Config = (Get-Content $TemplatePath -Raw) -replace "{{AGENT_PATH}}", $AgentPath
$Config | Out-File -FilePath $DebugConfPath -Encoding ascii

Write-Host "Debug config written to: $DebugConfPath" -ForegroundColor Cyan
Write-Host "HTTP metrics: http://localhost:2020/api/v1/metrics" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop.`n"

& $FluentBitExe -c $DebugConfPath
