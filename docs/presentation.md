# SEIP Windows Agent — Platform Overview

## What is it?

**seip-agent-win** is a lightweight, security-focused telemetry agent for Windows endpoints.
It collects high-signal security events, filters out noise at the edge, and streams structured
data to a central Kafka topic — all without requiring elevated privileges at runtime.

---

## Architecture at a Glance

```
Windows Event Logs  +  Sysmon
          │
          ▼
    Fluent Bit  (7 channels in parallel)
          │
          ▼
  Lua filter — sysmon_security.lua
  (drops ~75–85 % of raw volume)
          │
          ▼
  Lua filter — sysmon_pack.lua
  (strips redundant bulk fields, renames keys)
          │
          ▼
  Kafka topic: threats  (lz4 compressed)
```

Two Windows services work together:

| Service | Role |
|---|---|
| `SentinelAgent` | Runs Fluent Bit — reads events, applies Lua filters, publishes to Kafka |
| `SentinelLuaWatcher` | Polls for signed Lua filter bundles and hot-reloads them without a restart |

---

## Top Features

### 1. Broad, Multi-Source Telemetry

The agent reads **7 Windows event channels in parallel**, each with a dedicated SQLite
bookmark so collection always resumes from the last position after a restart:

| Channel | Tag | Captures |
|---|---|---|
| Microsoft-Windows-Sysmon/Operational | `sysmon` | Process, network, file, registry, pipe, DNS |
| Security | `winsec` | Logons, privilege use, account changes, policy changes |
| System | `winsys` | Service installs, start-type changes |
| PowerShell/Operational | `winps` | Script Block Logging (EID 4104) — de-obfuscated code |
| WMI-Activity/Operational | `winwmi` | WMI persistence subscriptions |
| TaskScheduler/Operational | `wints` | Scheduled task create / modify / delete |
| Windows Defender/Operational | `windef` | Detections, real-time protection changes |

---

### 2. Intelligent Edge Filtering (75–85 % Noise Reduction)

Raw Windows telemetry is extremely noisy. `sysmon_security.lua` applies per-source
logic before anything leaves the endpoint — keeping Kafka costs and analyst fatigue low.

**Selected examples:**

- **Sysmon EID 1 (Process Create)** — a 10-step decision tree: drops browser sub-processes
  (renderer/GPU/crashpad), trusted system parent→child chains, OEM vendor binaries, and
  Medium/Low integrity noise; passes LOLBAS binaries, CLI tools, and anything spawned from
  Office or Acrobat.
- **Sysmon EID 3 (Network Connection)** — an in-memory dedup cache suppresses heartbeat
  connections from VPN and RDP tools (e.g. `wireguard.exe`, `rustdesk.exe`) for 5 minutes.
- **Security EID 4624 (Logon Success)** — drops the highest-volume logon types (Network,
  Batch, Service); passes only interactive, RDP, RunAs, and cached logons.
- **WMI EIDs 5857/5858** — dropped entirely (routine query noise); 5859–5861 (persistence
  subscriptions) always pass.
- **Task Scheduler EID 200/201** — only forwarded when the task path or name contains
  `powershell`, `cmd.exe`, `wscript`, `mshta`, `rundll32`, `temp`, `appdata`, or `programdata`.

`sysmon_pack.lua` runs on every passing record and strips redundant bulk fields
(`StringInserts`, GUIDs, opcodes, etc.) — `StringInserts` alone accounts for ~40 % of
raw payload size.

---

### 3. Signed Lua Filter Hot-Reload

Security filters can be updated across the entire fleet **without touching the agent**:

1. The `SentinelLuaWatcher` service polls the bundle endpoint on a configurable interval
   (default: 5 minutes).
2. `fetch_lua_filters.py` downloads the JSON bundle and verifies its
   **RSA-4096 PKCS#1v15/SHA-256 signature** against `LUA_PUBLIC_KEY_B64`.
3. If verification fails, the download is **rejected** and the existing filters remain active —
   a tampered or injected bundle can never reach the endpoint.
4. On success, new `.lua` files are written and Fluent Bit picks them up on its next reload —
   **no service restart, no downtime**.

The bundle carries two scripts: `noise_filter` (global rules) and `user_filter`
(per-tenant custom rules), plus a `generated_at` timestamp used as a cache key to avoid
redundant downloads.

---

### 4. Least-Privilege Service Accounts

Both services run as **Windows Virtual Service Accounts** — no human credentials, no
LocalSystem, no stored passwords:

| Service | Account | Permissions |
|---|---|---|
| `SentinelAgent` | `NT SERVICE\SentinelAgent` | Full Control on `C:\ProgramData\SEIP`; member of Event Log Readers |
| `SentinelLuaWatcher` | `NT SERVICE\SentinelLuaWatcher` | Modify on `C:\ProgramData\SEIP`; Start/Stop/QueryStatus on `SentinelAgent` only (SDDL-scoped) |

The watcher can restart the agent when a new filter arrives — but has no other elevated
access. The agent reads event logs — but cannot modify audit policy or system configuration.

---

### 5. Endpoint Audit Hardening

`Initialize-WindowsAudit.ps1` configures the endpoint to emit exactly the events the
agent consumes — and nothing more:

- **Enlarged event log buffers** (Security → 1 GB, others 100–500 MB) to prevent data loss
  during high-volume attacks.
- **Targeted `auditpol` subcategories** — only high-signal categories enabled
  (Logon, Sensitive Privilege Use, Process Creation, Registry, Scheduled Tasks, Service
  Installation, Audit Policy Change).
- **Registry SACLs** on three high-value keys: `Run` (startup persistence),
  `AppInit_DLLs` (DLL injection), and `LSA` (credential store).
- **PowerShell Script Block Logging** (EID 4104) — captures de-obfuscated script content
  at execution time.
- **WMI Activity log** enabled for EIDs 5859–5861 (WMI persistence subscriptions).

---

### 6. Single-Command Install and Uninstall

```powershell
# Full install — idempotent, safe to re-run
.\Setup-Sentinel.ps1

# Full uninstall — reverses every change made by setup
.\Uninstall-Sentinel.ps1
```

`Setup-Sentinel.ps1` runs all steps in order (audit hardening → prerequisites →
agent service → watcher service) and verifies both services are running before it exits.
`Uninstall-Sentinel.ps1` reverses everything: stops services, removes NSSM entries,
removes the service account from Event Log Readers, uninstalls Sysmon, deletes
`C:\ProgramData\SEIP`, and reverts all audit policy changes.

---

### 7. Zero-Downtime Updates

After a `git pull` that changes Lua filters or audit policy:

```powershell
.\scripts\Deploy-SentinelUpdates.ps1
```

The script re-deploys Lua files, re-applies audit policies and SACLs, and restarts
the service **only when something actually changed**. No restart occurs if the deployed
state already matches the repository.

---

## Deployment Requirements

| Requirement | Notes |
|---|---|
| PowerShell 7+ | Install via `winget install Microsoft.PowerShell` |
| Admin shell | All setup scripts require elevation |
| Kafka credentials | `PRODUCER_API_KEY`, `PRODUCER_API_SECRET`, `BOOTSTRAP_SERVER` |
| Lua public key | `LUA_PUBLIC_KEY_B64` — provided by the SEIP platform team |

---

## Further Reading

- [README.md](../README.md) — quick-start and scripts reference
- [docs/audit-setup.md](audit-setup.md) — full EID mapping, service account model, SDDL details
- [docs/events.md](events.md) — per-source filtering logic and known volume challenges
- [docs/testing.md](testing.md) — running Fluent Bit in debug mode (no Kafka)
