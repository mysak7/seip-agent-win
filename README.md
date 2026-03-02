# seip-agent-win

Windows agent for the Sentinel SEIP platform. Collects security events via Sysmon + Fluent Bit and streams them to Kafka.

---

## Prerequisites

> All commands below must be run in **PowerShell as Administrator**.

### 1. Install Git (via winget)

```powershell
winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements
```

Reload PATH in the current session:

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path","User")
```

### 2. Clone the repository

```powershell
git clone https://github.com/mysak7/seip-agent-win.git
cd seip-agent-win
```

### 3. Set credentials

The agent needs three environment variables (or a `.env` file in the repo root):

```
PRODUCER_API_KEY=<your-api-key>
PRODUCER_API_SECRET=<your-api-secret>
BOOTSTRAP_SERVER=<kafka-broker-url>
```

**Option A — environment variables (recommended for production):**

```powershell
[System.Environment]::SetEnvironmentVariable("PRODUCER_API_KEY",    "xxx", "Machine")
[System.Environment]::SetEnvironmentVariable("PRODUCER_API_SECRET", "xxx", "Machine")
[System.Environment]::SetEnvironmentVariable("BOOTSTRAP_SERVER",    "xxx", "Machine")
```

**Option B — `.env` file (local dev only, never commit this file):**

```
# .env
PRODUCER_API_KEY=xxx
PRODUCER_API_SECRET=xxx
BOOTSTRAP_SERVER=xxx
```

---

## Quick Install (single command)

After cloning, run the all-in-one bootstrap script from the repo root:

```powershell
.\Setup-Sentinel.ps1
```

This runs all four setup scripts in the correct order and verifies the services at the end.

---

## Manual Step-by-Step Install

If you prefer to run each step individually:

```powershell
# 1. Harden Windows audit policy (event log sizes, auditpol, SACLs, PS logging)
.\scripts\maintenance\Initialize-WindowsAudit.ps1

# 2. Install Sysmon, Fluent Bit, and NSSM
.\scripts\Install-Prerequisites.ps1

# 3. Install SentinelAgent as a least-privilege Windows service
.\scripts\Install-SentinelService.ps1

# 4. Install SentinelLuaWatcher (hot-reloads Lua filter from S3)
.\scripts\Install-LuaWatcherService.ps1

# 5. Verify
Get-Service SentinelAgent, SentinelLuaWatcher | Format-Table Name, Status, StartType
```

---

## Post-install — Deploy updates

After a `git pull` that changes Lua filters or audit policy:

```powershell
.\scripts\Deploy-SentinelUpdates.ps1
```

This re-deploys Lua files, re-applies audit policies and SACLs, and restarts the service only when something actually changed.

---

## Service management

```powershell
nssm stop    SentinelAgent
nssm start   SentinelAgent
nssm restart SentinelAgent
nssm remove  SentinelAgent confirm

nssm stop    SentinelLuaWatcher
nssm start   SentinelLuaWatcher
nssm restart SentinelLuaWatcher
nssm remove  SentinelLuaWatcher confirm
```

Logs are in `C:\APPS\Sentinel\logs\` by default (configurable via `config.yaml`).

---

## Scripts reference

| Script | Run as | Purpose |
|---|---|---|
| `Setup-Sentinel.ps1` | Admin | All-in-one bootstrap — calls all scripts below in order |
| `scripts/maintenance/Initialize-WindowsAudit.ps1` | Admin | One-time audit policy hardening (event log sizes, auditpol, registry SACLs, PS Script Block Logging) |
| `scripts/Install-Prerequisites.ps1` | Admin | Installs/updates Sysmon, Fluent Bit, and NSSM |
| `scripts/Install-SentinelService.ps1` | Admin | Installs `SentinelAgent` service (Fluent Bit, least-privilege VSA) |
| `scripts/Install-LuaWatcherService.ps1` | Admin | Installs `SentinelLuaWatcher` service (S3 hot-reload watcher) |
| `scripts/Deploy-SentinelUpdates.ps1` | Admin | Deploys repo changes to a running installation |
| `scripts/launcher.ps1` | Service | Started by NSSM — injects credentials and runs Fluent Bit |
| `scripts/Watch-LuaFilter.ps1` | Service | Polls S3 for updated `noise_filter.lua`, hot-reloads on change |
| `scripts/maintenance/Test-FluentBit.ps1` | Admin | Debug mode — runs Fluent Bit to stdout (no Kafka) |
| `scripts/maintenance/Uninstall-SentinelService.ps1` | Admin | Removes the `SentinelAgent` service |

---

## Configuration

Edit `config.yaml` before first install to change install paths:

```yaml
AgentPath: "C:\APPS\Sentinel"       # agent config, Lua files, logs
ToolsPath: "C:\APPS\Sentinel\.tools" # Sysmon, Fluent Bit binaries
```

---

## Further reading

- [docs/audit-setup.md](docs/audit-setup.md) — full EID mapping and security model
- [docs/testing.md](docs/testing.md) — using `Test-FluentBit.ps1`
