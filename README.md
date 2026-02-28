# SentAgentWin

This project provides the Windows agent component for the Sentinel system, handling the installation, configuration, and orchestration of security monitoring tools (Sysmon and Fluent Bit).

## Quick start (all commands as Administrator)

```powershell
# 1. Install dependencies (Sysmon, Fluent Bit, NSSM)
.\scripts\Install-Prerequisites.ps1

# 2. One-time audit policy hardening
.\scripts\maintenance\Initialize-WindowsAudit.ps1

# 3. Install Fluent Bit as a least-privilege service
.\scripts\Install-SentinelService.ps1

# 4. Install the Lua filter watcher (hot-reload from S3)
.\scripts\Install-LuaWatcherService.ps1

# 5. Verify
Get-Service SentinelAgent, SentinelLuaWatcher | Format-Table Name, Status, StartType
```

For the full security model and runtime management commands see
[docs/audit-setup.md](docs/audit-setup.md).

---

## Scripts Overview

### Configuration
*   **`config.yaml`**
    *   Defines installation paths and watcher tuning:
        *   `AgentPath`: Root directory for agent configuration and logs (default: `C:\APPS\Sentinel`).
        *   `ToolsPath`: Directory for utility binaries (default: `C:\APPS\Sentinel\.tools`).
        *   `LuaWatcherInterval`: Seconds between S3 metadata polls (default: `300`).

### Installation & Setup

*   **`scripts/Install-Prerequisites.ps1`**
    *   **Purpose:** Prepares the system with necessary dependencies.
    *   **What it does:**
        *   Checks for and acquires Administrator privileges.
        *   Downloads and installs/updates **Sysmon**, **Fluent Bit**, and **NSSM**.

*   **`scripts/Install-SentinelService.ps1`**
    *   **Purpose:** Installs the Sentinel Agent as a Windows Service (least-privilege).
    *   **Prerequisites:** NSSM must be installed and in PATH.
    *   **What it does:**
        *   **Requires Administrator privileges** (installer only — service itself runs as a limited account).
        *   Installs `SentinelAgent` service that runs `launcher.ps1` under the **`NT SERVICE\SentinelAgent`** Virtual Service Account.
        *   Grants the account Full Control on `$AgentPath` and adds it to the **Event Log Readers** group.
        *   Configures auto-start, restart-on-failure, and log rotation.
        *   Removes any previous installation before re-installing.

*   **`scripts/Watch-LuaFilter.ps1`**
    *   **Purpose:** Background watcher that hot-reloads the LLM noise filter when a new version is published to S3.
    *   **What it does:**
        *   Polls `noise_filter.meta` on S3 every `LuaWatcherInterval` seconds.
        *   Compares the `ts` field against `$AgentPath\lua_filter.state`.
        *   On change: downloads `noise_filter.lua`, saves the new `ts`, restarts `SentinelAgent`.
        *   Runs continuously as a service; managed by `Install-LuaWatcherService.ps1`.

*   **`scripts/Install-LuaWatcherService.ps1`**
    *   **Purpose:** Installs `Watch-LuaFilter.ps1` as a Windows Service (least-privilege).
    *   **Prerequisites:** NSSM installed; `SentinelAgent` service must already exist.
    *   **What it does:**
        *   **Requires Administrator privileges** (installer only).
        *   Installs `SentinelLuaWatcher` service under the **`NT SERVICE\SentinelLuaWatcher`** Virtual Service Account.
        *   Grants the account Modify on `$AgentPath` (for Lua file, state file, logs).
        *   Delegates **Start + Stop + QueryStatus** rights on `SentinelAgent` via SDDL — no other elevated privileges.
        *   See [docs/audit-setup.md](docs/audit-setup.md) for the full installation walkthrough.

### Runtime & Orchestration

*   **`scripts/launcher.ps1`**
    *   **Purpose:** A bootstrapper to securely launch the Fluent Bit agent.
    *   **What it does:**
        *   Verifies Sysmon availability.
        *   Retrieves sensitive credentials (API keys, secrets) from the `.env` file.
        *   Generates a runtime configuration file by injecting secrets into a template.
        *   Starts the Fluent Bit process with the generated configuration.

### Utility / Maintenance

*   **`scripts/maintenance/Initialize-WindowsAudit.ps1`**
    *   **Purpose:** One-time endpoint hardening — configures Windows to emit the exact event IDs consumed by the agent.
    *   **Requires Administrator privileges.**
    *   **What it does:**
        *   Resizes Security / System / PowerShell / WMI / TaskScheduler logs to prevent rotation data-loss.
        *   Enables high-signal audit subcategories only (Logon, Sensitive Privilege Use, Process Creation, Registry, Scheduled Tasks, Services, Anti-Forensics).
        *   Enables PowerShell Script Block Logging (EID 4104).
        *   Places Registry SACLs on Run keys, AppInit_DLLs, and LSA secrets so EID 4657 fires on writes.
        *   Enables the WMI-Activity/Operational log (EIDs 5859–5861).
    *   See [docs/audit-setup.md](docs/audit-setup.md) for the full EID mapping.

*   **`copy_to_rbac.bat`**
    *   **Purpose:** Backs up or deploys the current local project to a remote network location.
    *   **What it does:**
        *   Copies the current directory contents to `\\rbac\home\Github\[ProjectName]`.
        *   Uses `robocopy` for efficient mirroring.
        *   Excludes hidden directories (like `.git`).

*   **`copy_from_rbac.bat`**
    *   **Purpose:** Restores or updates the local project from the remote network location.
    *   **What it does:**
        *   Copies contents *from* `\\rbac\home\Github\[ProjectName]` to the current local directory.
        *   Uses `robocopy` to mirror the remote state locally.
