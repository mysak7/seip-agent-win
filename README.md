# seip-agent-win

Windows agent for the Sentinel SEIP platform. Collects security events via Sysmon + Fluent Bit and streams them to Kafka.

---

## Prerequisites

winget install --id Microsoft.PowerShell --source winget

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

The agent needs the following environment variables (or a `.env` file in the repo root):

```
PRODUCER_API_KEY=<your-api-key>
PRODUCER_API_SECRET=<your-api-secret>
BOOTSTRAP_SERVER=<kafka-broker-url>
LUA_PUBLIC_KEY_B64=<base64-encoded-RSA-public-key>
```

**`LUA_PUBLIC_KEY_B64`** is the RSA-4096 public key (DER format, base64-encoded) used to verify the signature of every Lua filter bundle downloaded from the server. Before the agent writes any Lua file to disk, `fetch_lua_filters.py` checks the bundle's RSA-PKCS#1v15/SHA-256 signature against this key. If the signature does not match, the download is rejected and the existing filters are left unchanged. This prevents tampered or injected filter bundles from reaching the endpoint.

**Option A — environment variables (recommended for production):**

```powershell
[System.Environment]::SetEnvironmentVariable("PRODUCER_API_KEY",    "xxx", "Machine")
[System.Environment]::SetEnvironmentVariable("PRODUCER_API_SECRET", "xxx", "Machine")
[System.Environment]::SetEnvironmentVariable("BOOTSTRAP_SERVER",    "xxx", "Machine")
[System.Environment]::SetEnvironmentVariable("LUA_PUBLIC_KEY_B64",  "xxx", "Machine")
```

**Option B — `.env` file (local dev only, never commit this file):**

```
# .env
PRODUCER_API_KEY=xxx
PRODUCER_API_SECRET=xxx
BOOTSTRAP_SERVER=xxx
LUA_PUBLIC_KEY_B64=xxx
```

---

## Quick Install (single command)

After cloning, run the all-in-one bootstrap script from the repo root:

```powershell
.\Setup-Sentinel.ps1
```

This script:
1. Removes any existing `SentinelAgent` / `SentinelLuaWatcher` services (idempotent re-install).
2. Hardens Windows audit policy (event log sizes, `auditpol`, registry SACLs, PS Script Block Logging).
3. Installs Sysmon, Fluent Bit, and NSSM.
4. Installs `SentinelAgent` as a least-privilege Windows service.
5. Installs `SentinelLuaWatcher` — a watcher that periodically downloads signed Lua filter bundles and hot-reloads them without restarting the agent.
6. Verifies both services are running.

Optional flag:

```powershell
.\Setup-Sentinel.ps1 -ResizeLogs   # also increase Windows event log sizes
```

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

## Uninstall

To fully reverse the installation:

```powershell
.\Uninstall-Sentinel.ps1
```

This reverses everything `Setup-Sentinel.ps1` did, in order:
1. Stops and removes `SentinelLuaWatcher` and `SentinelAgent` services.
2. Removes `NT SERVICE\SentinelAgent` from the *Event Log Readers* group.
3. Uninstalls Sysmon (supports both native Windows 11 24H2+ optional feature and the Sysinternals binary).
4. Removes the `C:\ProgramData\SEIP` directory and cleans up PATH entries.
5. Optionally uninstalls NSSM (skipped by default — NSSM may be shared with other services).
6. Reverts all audit policy changes (auditpol, registry SACLs, PS Script Block Logging, WMI log).

Optional flags:

```powershell
.\Uninstall-Sentinel.ps1 -RemoveNSSM   # also uninstall NSSM via winget
.\Uninstall-Sentinel.ps1 -KeepLogs     # copy logs to repo root before deleting
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

Logs are in `C:\ProgramData\SEIP\logs\` by default (configurable via `config.yaml`).

---

## Scripts reference

| Script | Run as | Purpose |
|---|---|---|
| `Setup-Sentinel.ps1` | Admin | All-in-one install — calls all setup scripts in order, verifies services |
| `Uninstall-Sentinel.ps1` | Admin | Full uninstall — reverses everything `Setup-Sentinel.ps1` did |
| `scripts/maintenance/Initialize-WindowsAudit.ps1` | Admin | One-time audit policy hardening (event log sizes, auditpol, registry SACLs, PS Script Block Logging) |
| `scripts/Install-Prerequisites.ps1` | Admin | Installs/updates Sysmon, Fluent Bit, and NSSM |
| `scripts/Install-SentinelService.ps1` | Admin | Installs `SentinelAgent` service (Fluent Bit, least-privilege VSA) |
| `scripts/Install-LuaWatcherService.ps1` | Admin | Installs `SentinelLuaWatcher` service (downloads and verifies signed Lua bundles, hot-reloads on change) |
| `scripts/Deploy-SentinelUpdates.ps1` | Admin | Deploys repo changes to a running installation |
| `scripts/launcher.ps1` | Service | Started by NSSM — injects credentials and runs Fluent Bit |
| `scripts/Watch-LuaFilter.ps1` | Service | Polls the bundle URL, verifies RSA signature via `fetch_lua_filters.py`, hot-reloads Lua filters on change |
| `scripts/fetch_lua_filters.py` | Service | Downloads the signed Lua filter bundle, verifies RSA-4096 PKCS#1v15/SHA-256 signature, writes filter files |
| `scripts/maintenance/Test-FluentBit.ps1` | Admin | Debug mode — runs Fluent Bit to stdout (no Kafka) |
| `scripts/maintenance/Uninstall-SentinelService.ps1` | Admin | Removes only the `SentinelAgent` service (low-level, prefer `Uninstall-Sentinel.ps1`) |

---

## Configuration

Edit `config.yaml` before first install to change install paths:

```yaml
AgentPath: "C:\ProgramData\SEIP"       # agent config, Lua files, logs
ToolsPath: "C:\ProgramData\SEIP\.tools" # Sysmon, Fluent Bit binaries
```

---

## Lua filter updates

The `SentinelLuaWatcher` service keeps Fluent Bit's Lua filters up to date without any manual intervention.

**How it works:**

1. `Watch-LuaFilter.ps1` runs on a polling interval and calls `scripts/fetch_lua_filters.py`.
2. `fetch_lua_filters.py` downloads a signed JSON bundle from the configured URL.
   The bundle contains:
   - `noise_filter` — the main Lua script that drops noisy/low-value events before they reach Kafka.
   - `user_filter` — a secondary Lua script for custom per-tenant rules.
   - `generated_at` — timestamp used as a cache key (download is skipped if the local state file already has this timestamp).
   - `signature` — RSA-4096 PKCS#1v15/SHA-256 signature over the canonical JSON payload.
3. The script verifies the signature using `LUA_PUBLIC_KEY_B64` (the RSA public key from `.env`).
   **If verification fails, the files are not written and the old filters remain active.**
4. On success, the new `.lua` files are written and Fluent Bit picks them up on its next reload (no service restart required).

**`LUA_PUBLIC_KEY_B64`** must contain the DER-encoded RSA-4096 public key, base64-encoded (no PEM headers). It is provided by the SEIP platform team alongside the bundle URL.

---

## Further reading

- [docs/audit-setup.md](docs/audit-setup.md) — full EID mapping and security model
- [docs/testing.md](docs/testing.md) — using `Test-FluentBit.ps1`
