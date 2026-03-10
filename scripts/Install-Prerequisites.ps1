# --- Install Prerequisites Script ---
# Installs/Updates Sysmon and Fluent Bit, and sets up the Master Key in Credential Manager

param(
    [string]$FluentBitVersion = "3.2.3"
)

# Read Config from YAML (Simple Parse)
$ConfigPath = Join-Path $PSScriptRoot "..\config.yaml"
if (-not (Test-Path $ConfigPath)) { throw "Config file not found at $ConfigPath" }

$ConfigContent = Get-Content $ConfigPath -Raw
$InstallPath = "C:\ProgramData\SEIP\.tools" # Default
if ($ConfigContent -match 'ToolsPath:\s*"(.*)"') { $InstallPath = $matches[1] }
elseif ($ConfigContent -match "ToolsPath:\s*'(.*)'") { $InstallPath = $matches[1] }
elseif ($ConfigContent -match 'ToolsPath:\s*([^"\s]+)') { $InstallPath = $matches[1] }

Write-Host "Configuration loaded. Utilities path: $InstallPath"

# Ensure Admin Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    exit
}

# --- Helper Functions ---

function Get-ExeVersion {
    param([string]$Path)
    if (Test-Path $Path) {
        return (Get-Item $Path).VersionInfo.FileVersion
    }
    return $null
}

function Add-ToPath {
    param([string]$Dir)
    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    if ($CurrentPath -split ';' -notcontains $Dir) {
        Write-Host "Adding $Dir to System PATH..."
        [Environment]::SetEnvironmentVariable("Path", $CurrentPath + ";$Dir", [System.EnvironmentVariableTarget]::Machine)
        $env:Path += ";$Dir"
    } else {
        Write-Host "Path already contains $Dir. Skipping." -ForegroundColor DarkGray
    }
}

function Expand-ZIP {
    param($ZipPath, $Dest)
    Expand-Archive -Path $ZipPath -DestinationPath $Dest -Force
}

function Test-ShouldDownload {
    param($Url, $LocalPath)
    
    # If local file doesn't exist, we must download
    if (-not (Test-Path $LocalPath)) { return $true }
    
    try {
        # Check remote headers
        $Response = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -ErrorAction Stop
        $LastMod = $Response.Headers['Last-Modified']
        
        if ([string]::IsNullOrWhiteSpace($LastMod)) { 
            Write-Warning "Could not determine remote file date. Forcing download."
            return $true 
        }
        
        $RemoteDate = [DateTime]::Parse($LastMod)
        $LocalDate = (Get-Item $LocalPath).LastWriteTime
        
        # If remote file is newer than our local cached zip, download it.
        # Otherwise, our local zip is current enough to check for updates.
        if ($RemoteDate -gt $LocalDate) {
            Write-Host "Newer version detected on server ($RemoteDate) vs Local ($LocalDate)." -ForegroundColor Cyan
            return $true
        }
        
        Write-Host "Local cached file is up to date." -ForegroundColor Gray
        return $false
    } catch {
        Write-Warning "Failed to check remote version: $_. Skipping download and using local cache if available."
        return $false
    }
}

# Create Tools Directory
if (!(Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
$TempDir = Join-Path $InstallPath "_temp_install"
if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }

# --- 1. Install/Update Sysmon ---
Write-Host "`n--- Checking Sysmon ---" -ForegroundColor Cyan
$SysmonConfig = Join-Path $PSScriptRoot "..\sysmon\sysmon-config.xml"

# ── Native Sysmon path (Windows 11 24H2+ / Server 2025+, build ≥ 26100) ──────
$OsBuild = [System.Environment]::OSVersion.Version.Build
$UseNative = $false

if ($OsBuild -ge 26100) {
    $NativeFeature = Get-WindowsOptionalFeature -Online -FeatureName "Sysmon" -ErrorAction SilentlyContinue
    if (-not $NativeFeature -and (Test-Path "$env:SystemRoot\Sysmon.exe")) {
        # Binary present but optional feature not registered (e.g. pre-release build)  -  treat as native
        $UseNative = $true
        Write-Host "  Native Sysmon binary found at $env:SystemRoot\Sysmon.exe (build $OsBuild)." -ForegroundColor Cyan

        $SysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        if (-not $SysmonSvc) { $SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue }
        if (-not $SysmonSvc) {
            Write-Host "  Installing Sysmon service..."
            $installArgs = if (Test-Path $SysmonConfig) { "-accepteula -i `"$SysmonConfig`"" } else { "-accepteula -i" }
            $p = Start-Process -FilePath "$env:SystemRoot\Sysmon.exe" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
            if ($p.ExitCode -ne 0) { Write-Warning "  sysmon -i exited with code $($p.ExitCode)." }
            else { Write-Host "  OK Sysmon service installed" -ForegroundColor Green }
        } else {
            if ($SysmonSvc.Status -ne 'Running') { Start-Service $SysmonSvc.Name }
            if (Test-Path $SysmonConfig) {
                Start-Process -FilePath "$env:SystemRoot\Sysmon.exe" -ArgumentList "-c `"$SysmonConfig`"" -Wait -NoNewWindow | Out-Null
                Write-Host "  OK Sysmon config updated" -ForegroundColor Green
            } else {
                Write-Host "  OK Sysmon already running (no config change)" -ForegroundColor Green
            }
        }
    } elseif ($NativeFeature) {
        $UseNative = $true
        Write-Host "  Native Sysmon optional feature detected (build $OsBuild)." -ForegroundColor Cyan

        if ($NativeFeature.State -ne "Enabled") {
            Write-Host "  Enabling native Sysmon optional feature..."
            Enable-WindowsOptionalFeature -Online -FeatureName "Sysmon" -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "  OK Sysmon feature enabled" -ForegroundColor Green
        } else {
            Write-Host "  OK Sysmon feature already enabled" -ForegroundColor Green
        }

        # Start/reconfigure service
        # Native Sysmon uses the same CLI surface as Sysinternals Sysmon
        $SysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        if (-not $SysmonSvc) { $SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue }

        if (-not $SysmonSvc) {
            Write-Host "  Installing Sysmon service..."
            $installArgs = if (Test-Path $SysmonConfig) { "-accepteula -i `"$SysmonConfig`"" } else { "-accepteula -i" }
            $p = Start-Process -FilePath "sysmon" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
            if ($p.ExitCode -ne 0) { Write-Warning "  sysmon -i exited with code $($p.ExitCode)." }
            else { Write-Host "  OK Sysmon service installed" -ForegroundColor Green }
        } else {
            if ($SysmonSvc.Status -ne 'Running') { Start-Service $SysmonSvc.Name }
            if (Test-Path $SysmonConfig) {
                Write-Host "  Updating Sysmon config..."
                Start-Process -FilePath "sysmon" -ArgumentList "-c `"$SysmonConfig`"" -Wait -NoNewWindow | Out-Null
                Write-Host "  OK Sysmon config updated" -ForegroundColor Green
            } else {
                Write-Host "  OK Sysmon already running (no config change)" -ForegroundColor Green
            }
        }

        # Verify
        Start-Sleep -Seconds 2
        if (-not (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue)) {
            Write-Warning "  Sysmon Operational log not yet visible - a reboot may be required after feature install."
        } else {
            Write-Host "  OK Microsoft-Windows-Sysmon/Operational log active" -ForegroundColor Green
        }
    }
}

# ── Sysinternals fallback (older OS or native feature not yet shipped) ─────────
if (-not $UseNative) {
    if ($OsBuild -ge 26100) {
        Write-Host "  Native Sysmon feature not available on this build/edition - falling back to Sysinternals." -ForegroundColor Yellow
    }

    $SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $SysmonInstallDir = Join-Path $InstallPath "Sysmon"
    $SysmonExeInstalled = Join-Path $SysmonInstallDir "Sysmon.exe"
    $SysmonZipCached = Join-Path $InstallPath "Sysmon.zip"
    $SysmonExtractTemp = Join-Path $TempDir "Sysmon"

    try {
        # 1. Decide if we need to download the ZIP
        if (Test-ShouldDownload -Url $SysmonUrl -LocalPath $SysmonZipCached) {
            Write-Host "Downloading Sysmon..."
            Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonZipCached
        }

        # 2. Extract cached ZIP to temp to check internal EXE version
        if (Test-Path $SysmonExtractTemp) { Remove-Item $SysmonExtractTemp -Recurse -Force }
        Expand-ZIP -ZipPath $SysmonZipCached -Dest $SysmonExtractTemp

        # 3. Determine architecture for check
        $NewSysmonExe = Join-Path $SysmonExtractTemp "Sysmon.exe"
        if (-not (Test-Path $NewSysmonExe)) { $NewSysmonExe = Join-Path $SysmonExtractTemp "Sysmon64.exe" }

        # 4. Compare Versions
        $NewVersion = Get-ExeVersion $NewSysmonExe
        $CurrentVersion = Get-ExeVersion $SysmonExeInstalled
        $SysmonService = Get-Service "Sysmon" -ErrorAction SilentlyContinue

        $Action = "None"
        if (-not (Test-Path $SysmonExeInstalled)) {
            $Action = "Install"
            Write-Host "Sysmon not found. Installing version $NewVersion..."
        } elseif ($null -eq $SysmonService) {
            $Action = "Register"
            Write-Host "Sysmon files present but service missing. Registering..."
        } elseif ([version]$CurrentVersion -ne [version]$NewVersion) {
            $Action = "Update"
            Write-Host "Sysmon update found ($CurrentVersion -> $NewVersion). Updating..."
        } else {
            Write-Host "Sysmon is already up to date ($CurrentVersion)." -ForegroundColor Green
        }

        # 5. Apply Install/Update if needed
        if ($Action -ne "None") {
            if ($SysmonService -and $SysmonService.Status -eq 'Running') {
                Write-Host "Stopping Sysmon service..."
                Stop-Service "Sysmon" -Force -ErrorAction SilentlyContinue
            }

            if ($SysmonService -and ($Action -in "Install", "Register")) {
                Write-Host "Sysmon service detected. Attempting to uninstall previous instance..."
                $TempSysmon = Join-Path $SysmonExtractTemp "Sysmon.exe"
                if (-not (Test-Path $TempSysmon)) { $TempSysmon = Join-Path $SysmonExtractTemp "Sysmon64.exe" }
                if (Test-Path $TempSysmon) {
                    Start-Process -FilePath $TempSysmon -ArgumentList "-u -force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                } else {
                    Start-Process -FilePath "sysmon" -ArgumentList "-u -force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds 3
            }

            if ($Action -in "Install", "Update") {
                if (!(Test-Path $SysmonInstallDir)) { New-Item -ItemType Directory -Path $SysmonInstallDir -Force | Out-Null }
                Copy-Item -Path "$SysmonExtractTemp\*" -Destination $SysmonInstallDir -Recurse -Force
            }

            Add-ToPath $SysmonInstallDir

            $SysmonBinary = Join-Path $SysmonInstallDir "Sysmon.exe"
            if (-not (Test-Path $SysmonBinary)) { $SysmonBinary = Join-Path $SysmonInstallDir "Sysmon64.exe" }

            if ($Action -eq "Update") {
                Start-Service "Sysmon"
                if (Test-Path $SysmonConfig) {
                    Write-Host "Updating Sysmon config..."
                    Start-Process -FilePath $SysmonBinary -ArgumentList "-c `"$SysmonConfig`"" -Wait -NoNewWindow
                }
            } else {
                Write-Host "Installing Sysmon Service..."
                $ArgsList = "-i -accepteula"
                if (Test-Path $SysmonConfig) { $ArgsList = "-i `"$SysmonConfig`" -accepteula" }
                $Process = Start-Process -FilePath $SysmonBinary -ArgumentList $ArgsList -Wait -NoNewWindow -PassThru
                if ($Process.ExitCode -ne 0) { Write-Warning "Sysmon installer exited with code $($Process.ExitCode)." }
            }

            Start-Sleep -Seconds 2
            if (-not (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue)) {
                Write-Error "Sysmon installation failed to register the Event Log channel."
                Write-Error "Please try running 'C:\Tools\Sysmon\Sysmon.exe -u force' manually, rebooting, and running this script again."
            } else {
                Write-Host "Sysmon $Action complete."
            }
        } else {
            $Svc = Get-Service "Sysmon" -ErrorAction SilentlyContinue
            if ($Svc -and $Svc.Status -ne 'Running') {
                Start-Service "Sysmon"
                Write-Host "Sysmon service started."
            }
        }

    } catch {
        Write-Error "Failed to process Sysmon: $_"
    }
}

# --- 2. Install/Update Fluent Bit ---
Write-Host "`n--- Checking Fluent Bit ---" -ForegroundColor Cyan
$FluentBitUrl = "https://packages.fluentbit.io/windows/fluent-bit-$FluentBitVersion-win64.zip" 
$FluentBitDir = Join-Path $InstallPath "fluent-bit"
$FluentBitBin = Join-Path $FluentBitDir "bin\fluent-bit.exe"

$CurrentFBVersion = $null
if (Test-Path $FluentBitBin) {
    $CurrentFBVersion = (Get-Item $FluentBitBin).VersionInfo.ProductVersion
    if ([string]::IsNullOrWhiteSpace($CurrentFBVersion)) { $CurrentFBVersion = (Get-Item $FluentBitBin).VersionInfo.FileVersion }
}

$FBAction = "None"
if (-not (Test-Path $FluentBitBin)) {
    $FBAction = "Install"
    Write-Host "Fluent Bit not found. Installing version $FluentBitVersion..."
} else {
    # Ensure both are parsed as [version] objects for accurate comparison (e.g. 3.2.3.0 == 3.2.3)
    # Using try/catch in case parsing fails (e.g. if version string has non-numeric chars)
    try {
        $vCurrent = [version]$CurrentFBVersion
        $vTarget = [version]$FluentBitVersion
        
        # Normalize versions to 4 components (Major.Minor.Build.Revision)
        # because [version]"3.2.3" (Revision -1) is not equal to [version]"3.2.3.0" (Revision 0)
        if ($vCurrent.Revision -lt 0) { 
            $vCurrent = [version]::new($vCurrent.Major, $vCurrent.Minor, [Math]::Max(0, $vCurrent.Build), 0) 
        }
        if ($vTarget.Revision -lt 0) { 
            $vTarget = [version]::new($vTarget.Major, $vTarget.Minor, [Math]::Max(0, $vTarget.Build), 0) 
        }

        if ($vCurrent -ne $vTarget) {
            $FBAction = "Update"
            Write-Host "Fluent Bit version mismatch ($vCurrent -> $vTarget). Updating..."
        } else {
            Write-Host "Fluent Bit is already at target version ($vCurrent)." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Version parsing failed. Fallback to string comparison."
        if ($CurrentFBVersion -ne $FluentBitVersion) {
            $FBAction = "Update"
            Write-Host "Fluent Bit version mismatch ($CurrentFBVersion -> $FluentBitVersion). Updating..."
        }
    }
}

if ($FBAction -ne "None") {
    $FluentBitZip = Join-Path $TempDir "fluent-bit.zip"

    try {
        # Download
        Write-Host "Downloading Fluent Bit $FluentBitVersion..."
        Invoke-WebRequest -Uri $FluentBitUrl -OutFile $FluentBitZip

        # Extract
        Expand-ZIP -ZipPath $FluentBitZip -Dest $TempDir

        $ExtractedRoot = Get-ChildItem -Path $TempDir -Filter "fluent-bit*-win64" | Select-Object -First 1
        if ($ExtractedRoot) {
            if (!(Test-Path $FluentBitDir)) { New-Item -ItemType Directory -Path $FluentBitDir -Force | Out-Null }
            Copy-Item -Path "$($ExtractedRoot.FullName)\*" -Destination $FluentBitDir -Recurse -Force
        } else {
            throw "Could not locate extracted Fluent Bit folder structure."
        }

        # Add to PATH
        Add-ToPath (Join-Path $FluentBitDir "bin")

        Write-Host "Fluent Bit $FBAction complete."

    } catch {
        Write-Error "Failed to install/update Fluent Bit: $_"
    }
}

# --- 3. Install/Update NSSM (via winget) ---
Write-Host "`n--- Checking NSSM ---" -ForegroundColor Cyan

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Host "NSSM not found. Installing via winget..."
    try {
        winget install NSSM.NSSM --silent --accept-package-agreements --accept-source-agreements

        # Refresh PATH in current session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path", "User")

        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            Write-Host "NSSM installed successfully." -ForegroundColor Green
        } else {
            Write-Error "NSSM was not found in PATH after winget install."
        }
    } catch {
        Write-Error "Failed to install NSSM: $_"
    }
} else {
    Write-Host "NSSM is already installed." -ForegroundColor Green
}

# ── Deploy NSSM to tools directory (required for VSA service accounts) ────────
# winget installs NSSM to C:\Users\...\AppData which NT SERVICE\* Virtual Service
# Accounts cannot access. The SCM calls CreateProcessAsUser() with the VSA token,
# and Windows checks that the VSA can read the service binary  -  if not, StartService
# fails with ERROR_ACCESS_DENIED (5). Copying nssm.exe to $InstallPath
# (C:\ProgramData\SEIP\.tools) which VSAs already have Full Control on fixes this.
$NssmCmd = Get-Command nssm -ErrorAction SilentlyContinue
if ($NssmCmd) {
    $NssmDest = Join-Path $InstallPath "nssm.exe"
    if (-not (Test-Path $NssmDest)) {
        Write-Host "  Deploying NSSM to $NssmDest for VSA service accounts..."
        Copy-Item -Path $NssmCmd.Source -Destination $NssmDest -Force
        Write-Host "  OK NSSM deployed to tools directory" -ForegroundColor Green
    } else {
        Write-Host "  NSSM already deployed at $NssmDest" -ForegroundColor DarkGray
    }
    Add-ToPath $InstallPath
}

# --- 4. Python venv for fetch_lua_filters.py ---
Write-Host "`n--- Checking Python venv ---" -ForegroundColor Cyan

$AgentPath = "C:\ProgramData\SEIP"
if ($ConfigContent -match 'AgentPath:\s*"(.*)"')        { $AgentPath = $matches[1] }
elseif ($ConfigContent -match "AgentPath:\s*'(.*)'")    { $AgentPath = $matches[1] }
elseif ($ConfigContent -match 'AgentPath:\s*([^"\s]+)') { $AgentPath = $matches[1] }

$VenvPath  = Join-Path $AgentPath ".venv"
$VenvPy    = Join-Path $VenvPath "Scripts\python.exe"
$VenvPip   = Join-Path $VenvPath "Scripts\pip.exe"

# Returns $true if the path lives inside a user-profile directory.
# Venvs built from a user-profile Python cannot be executed by
# NT SERVICE\SentinelAgent because the base interpreter is inaccessible
# to the Virtual Service Account's restricted token.
function Test-IsUserProfilePath([string]$path) {
    $lpath = $path.ToLower()
    foreach ($base in @($env:LOCALAPPDATA, $env:APPDATA, $env:USERPROFILE)) {
        if ($base -and $lpath.StartsWith($base.ToLower())) { return $true }
    }
    return $false
}

# Check if an existing venv was built from a user-profile Python
$venvNeedsRebuild = $false
$venvCfg = Join-Path $VenvPath "pyvenv.cfg"
if (Test-Path $venvCfg) {
    $cfgHomeLine = Get-Content $venvCfg | Where-Object { $_ -match '^home\s*=' } | Select-Object -First 1
    if ($cfgHomeLine) {
        $cfgHome = ($cfgHomeLine -replace '^home\s*=\s*', '').Trim()
        if (Test-IsUserProfilePath $cfgHome) {
            Write-Warning "  Existing venv uses a user-profile Python ($cfgHome)."
            Write-Warning "  NT SERVICE\SentinelAgent cannot access that path - venv will be rebuilt."
            $venvNeedsRebuild = $true
        }
    }
}

# Find a system-wide Python (not inside the current user's profile).
# User-profile Pythons are invisible to NT SERVICE\* virtual service accounts.
# Also probe well-known system-wide install directories in case Python was
# installed for all users but its bin dir was not added to the machine PATH.
function Find-SystemPython {
    # 1. Check PATH entries
    $fromPath = @('python', 'python3', 'py') | ForEach-Object {
        $cmd = Get-Command $_ -ErrorAction SilentlyContinue
        if ($cmd -and -not (Test-IsUserProfilePath $cmd.Source)) { $cmd.Source }
    } | Where-Object { $_ } | Select-Object -First 1
    if ($fromPath) { return $fromPath }

    # 2. Probe standard system-wide install roots
    $searchRoots = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "C:\Python3",   # legacy single-dir installs
        "C:\Python"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $searchRoots) {
        # Matches Python313, Python3, Python314, etc.
        $candidates = Get-ChildItem -Path $root -Filter "Python3*" -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending  # prefer newer versions
        foreach ($dir in $candidates) {
            $exe = Join-Path $dir.FullName "python.exe"
            if (Test-Path $exe) { return $exe }
        }
        # Also check directly under root (e.g. C:\Python3\python.exe)
        $direct = Join-Path $root "python.exe"
        if (Test-Path $direct) { return $direct }
    }
    return $null
}

$SysPy = Find-SystemPython

if (-not $SysPy) {
    # Try winget with versioned package IDs (unversioned 'Python.Python.3' resolves to
    # the Microsoft Store stub which lacks a machine-scope installer and returns 0x8A150014).
    Write-Host "  No system-wide Python found. Installing Python 3 for all users via winget..."
    $installed = $false
    foreach ($pkgId in @('Python.Python.3.14', 'Python.Python.3.13', 'Python.Python.3.12')) {
        Write-Host "  Trying $pkgId ..."
        winget install $pkgId --scope machine --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) { $installed = $true; break }
    }
    if (-not $installed) {
        Write-Warning "  winget install failed for all tried Python versions."
    }
    $global:LASTEXITCODE = 0  # winget failure is non-fatal; don't let it poison the script exit code
    # Refresh PATH in the current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    $SysPy = Find-SystemPython
}

if (-not $SysPy) {
    Write-Warning "Python not found in system locations  -  skipping venv setup."
    Write-Warning "Install Python 3 for all users (e.g. 'winget install Python.Python.3.13 --scope machine') and re-run."
} else {
    Write-Host "  Using system Python: $SysPy" -ForegroundColor DarkGray

    if ($venvNeedsRebuild -and (Test-Path $VenvPath)) {
        Write-Host "  Removing stale user-profile-based venv..."
        Remove-Item $VenvPath -Recurse -Force
    }

    if (Test-Path $VenvPy) {
        Write-Host "  Python venv already exists at $VenvPath" -ForegroundColor DarkGray
    } else {
        Write-Host "  Creating Python venv at $VenvPath..."
        & $SysPy -m venv $VenvPath
        if (-not (Test-Path $VenvPy)) {
            Write-Warning "  venv creation failed  -  Lua filter fetch may not work at runtime."
        } else {
            Write-Host "  OK venv created" -ForegroundColor Green
        }
    }

    if (Test-Path $VenvPip) {
        Write-Host "  Installing/verifying 'cryptography' package..."
        & $VenvPip install --quiet --upgrade cryptography
        Write-Host "  OK cryptography package ready" -ForegroundColor Green
    }
}

# Cleanup Temp
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "`nPrerequisites check/installation complete." -ForegroundColor Green
exit 0

