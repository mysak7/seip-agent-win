# --- Sentinel Lua Filter Watcher ---
# Polls bundle/manifest.json from S3, verifies KMS RSA-4096 PKCS#1v1.5-SHA256 signature,
# and writes both noise_filter (llm_filter.lua) and alert_filter (alert_filter.lua).
# Runs every 5 minutes, clock-aligned to :02/:07/:12/:17/:22/...

$BundleUrl   = "https://mysak7-seip-lua.s3.eu-central-1.amazonaws.com/bundle/manifest.json"
$ServiceName = "SentinelAgent"

# RSA-4096 SubjectPublicKeyInfo (DER, base64) — KMS alias: dev-seip-lua-signing
# Rotate this value if the KMS key is rotated.
# This default is overridden by LUA_PUBLIC_KEY_B64 in ..\.env (written by Terraform).
$LuaPublicKeyB64 = @"
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq2patvrcDkKx62yMFhYI
WBLFuDu84yw3XJyvlfCwKFtoLEYgYSICMbNbjoT8U6I4dHMWiGPQKsGCJjGT3Ovq
aFMPGWEjxWr6yMTtO731gha27ODlUehQeBec2n17gwjL5oW5GCGZGwQkvv62Q5Xe
cQNqW1V3n43RUXMIskxp6GwoFGaDZUCY2YuLtWs0Nh2mkTKVDexO9wCcbPnN9oEM
iIu6jhoVJr2ogTV71Q+BbGsvNfDU4lbk+s6e/N4iewCsUBJG29+9lR7a7c9cAPzw
TURlX+SSMJFXSEl3aQfxvHOTUNo73OF6jwfBw+hoOolucDotewZOs21L4KylUQad
0LKV/RsXdJBZaYViSdlmdmAUyP/rv4xDHWR5LFuJH7rKcAd9JNR4iXzGHdp9gAMt
nA2xsISB3DLYUrv2HpEcZS4bDr94WOh5ELhhFKGIMaVwAgoat0GSrgNnEZnyA83o
RMb4GTpxMwNomDH4OAc4firtr5V+Motz3ez+4upraBE/2b2a6Iwuwvq+d2IfPDUW
NqccOeKwlWcGtYSXPOZwVhJ/xRXbaXnaylCP+sZ72y0I0WW+7ltChKdkpyt7F7tt
Oumwwq0qQKRevQIdYHNTK9IjkPzLb4lxNimPPdNQFpOEcd+gPxGB9iy0sd6DHsxj
JAdET6rKkCvB1PbXrK+kxekCAwEAAQ==
"@

# Override public key from ..\.env if present (written by `terraform apply`)
$EnvFilePath = Join-Path $PSScriptRoot "..\.env"
if (Test-Path $EnvFilePath) {
    foreach ($line in (Get-Content $EnvFilePath)) {
        if ($line -match '^LUA_PUBLIC_KEY_B64=(.+)$') {
            $LuaPublicKeyB64 = $matches[1]
            break
        }
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

$LocalNoiseLuaPath = Join-Path $AgentPath "llm_filter.lua"
$LocalAlertLuaPath = Join-Path $AgentPath "alert_filter.lua"
$StateFilePath     = Join-Path $AgentPath "lua_filter.state"
$LogDir            = Join-Path $AgentPath "logs"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path (Join-Path $LogDir "lua-watcher.log") -Value $line
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

# Parses a DER length field; advances $idx past the length bytes; returns the length value.
function Read-DerLength {
    param([byte[]]$b, [ref]$idx)
    $first = $b[$idx.Value]; $idx.Value++
    if ($first -lt 0x80) { return [int]$first }
    $n = $first -band 0x7F
    $len = 0
    for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor $b[$idx.Value]; $idx.Value++ }
    return $len
}

# Imports an RSA public key from a SubjectPublicKeyInfo DER (base64).
# Compatible with both PS 5.1 (.NET Framework 4.6+) and PS 7+ (.NET 5+).
function New-RSAFromSpki {
    param([string]$Base64Spki)
    $der = [Convert]::FromBase64String(($Base64Spki -replace '\s+', ''))

    # Try .NET Core 3+ / .NET 5+ path
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $read = 0
        $rsa.ImportSubjectPublicKeyInfo([byte[]]$der, [ref]$read)
        return $rsa
    } catch { }

    # Fallback: parse SPKI DER manually to extract RSAParameters (works on .NET Framework 4.6+)
    $i = [ref]0
    if ($der[$i.Value] -ne 0x30) { throw "SPKI: expected outer SEQUENCE" }; $i.Value++
    Read-DerLength $der $i | Out-Null          # outer SEQUENCE length
    if ($der[$i.Value] -ne 0x30) { throw "SPKI: expected AlgorithmIdentifier" }; $i.Value++
    $algLen = Read-DerLength $der $i
    $i.Value += $algLen                         # skip AlgorithmIdentifier contents
    if ($der[$i.Value] -ne 0x03) { throw "SPKI: expected BIT STRING" }; $i.Value++
    Read-DerLength $der $i | Out-Null          # BIT STRING length
    $i.Value++                                  # skip unused-bits byte (0x00)
    if ($der[$i.Value] -ne 0x30) { throw "RSAPublicKey: expected SEQUENCE" }; $i.Value++
    Read-DerLength $der $i | Out-Null          # RSAPublicKey SEQUENCE length
    # modulus
    if ($der[$i.Value] -ne 0x02) { throw "RSAPublicKey: expected modulus INTEGER" }; $i.Value++
    $nLen = Read-DerLength $der $i
    $nBytes = $der[$i.Value..($i.Value + $nLen - 1)]; $i.Value += $nLen
    # exponent
    if ($der[$i.Value] -ne 0x02) { throw "RSAPublicKey: expected exponent INTEGER" }; $i.Value++
    $eLen = Read-DerLength $der $i
    $eBytes = $der[$i.Value..($i.Value + $eLen - 1)]

    # Strip DER positive-integer leading zero
    while ($nBytes.Length -gt 1 -and $nBytes[0] -eq 0x00) { $nBytes = $nBytes[1..($nBytes.Length-1)] }
    while ($eBytes.Length -gt 1 -and $eBytes[0] -eq 0x00) { $eBytes = $eBytes[1..($eBytes.Length-1)] }

    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus  = [byte[]]$nBytes
    $params.Exponent = [byte[]]$eBytes
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.ImportParameters($params)
    return $rsa
}

# Verifies the bundle signature. Returns $true if valid, throws on invalid.
# Canonical payload mirrors Python: json.dumps({"generated_at":…,"noise_filter":…,"alert_filter":…},
#   separators=(',',':'), ensure_ascii=False)
function Test-BundleSignature {
    param([PSCustomObject]$Bundle)

    if (-not $Bundle.signature) { throw "Bundle missing 'signature' field." }

    $ordered = [ordered]@{
        generated_at = $Bundle.generated_at
        noise_filter = $Bundle.noise_filter
        user_filter  = $Bundle.user_filter
    }
    $canonical = $ordered | ConvertTo-Json -Compress -Depth 10
    # PowerShell 7 / System.Text.Json escapes <, >, & as \uXXXX — undo to match Python output
    $canonical = $canonical -replace '\\u003c','<' -replace '\\u003e','>' -replace '\\u0026','&'

    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    $sigBytes     = [Convert]::FromBase64String($Bundle.signature)

    $rsa = New-RSAFromSpki -Base64Spki $LuaPublicKeyB64
    try {
        return $rsa.VerifyData(
            [byte[]]$payloadBytes,
            [byte[]]$sigBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    } finally {
        $rsa.Dispose()
    }
}

Write-Log "Lua filter watcher started. Schedule: every 5 min, aligned to :02/:07/:12/..."

while ($true) {
    $waitSec  = Get-SecondsUntilNextRun
    $nextTime = (Get-Date).AddSeconds($waitSec).ToString("HH:mm")
    Write-Log "Next check at $nextTime (in ${waitSec}s)."
    Start-Sleep -Seconds $waitSec

    try {
        # 1. Fetch signed bundle manifest
        $json   = Invoke-WebRequest -Uri $BundleUrl -UseBasicParsing -TimeoutSec 15 |
                  Select-Object -ExpandProperty Content
        $bundle = $json | ConvertFrom-Json

        $remoteTs = $bundle.generated_at
        if (-not $remoteTs) { throw "Bundle missing 'generated_at' field." }

        # 2. Compare against last known timestamp
        $lastTs = if (Test-Path $StateFilePath) {
            Get-Content $StateFilePath -Raw | ForEach-Object { $_.Trim() }
        } else { "" }

        if ($remoteTs -ne $lastTs) {
            Write-Log "New bundle detected. Remote ts=$remoteTs  Last ts=$lastTs"

            # 3. Verify RSA-4096 PKCS#1v1.5-SHA256 signature
            $valid = Test-BundleSignature -Bundle $bundle
            if (-not $valid) {
                Write-Log "SECURITY: Bundle signature verification FAILED — discarding update." "ERROR"
                continue
            }
            Write-Log "Signature verified OK (key_id=$($bundle.key_id))"

            # 4. Write both Lua filters atomically
            [IO.File]::WriteAllText($LocalNoiseLuaPath,  $bundle.noise_filter, [System.Text.Encoding]::UTF8)
            [IO.File]::WriteAllText($LocalAlertLuaPath, $bundle.user_filter,   [System.Text.Encoding]::UTF8)
            Write-Log "Written: llm_filter.lua + alert_filter.lua"

            # 5. Persist new timestamp
            Set-Content -Path $StateFilePath -Value $remoteTs -Encoding ASCII

            # 6. Restart SentinelAgent so Fluent Bit picks up the new filters
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Log "Restarting $ServiceName..."
                Restart-Service -Name $ServiceName -Force
                Write-Log "$ServiceName restarted successfully."
            } else {
                Write-Log "$ServiceName not found — skipping restart." "WARN"
            }
        } else {
            Write-Log "Lua filters up-to-date (ts=$remoteTs)."
        }
    } catch {
        Write-Log "Error during check: $_" "ERROR"
    }
}
