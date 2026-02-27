# SentAgentWin

This project provides the Windows agent component for the Sentinel system, handling the installation, configuration, and orchestration of security monitoring tools (Sysmon and Fluent Bit).

## Scripts Overview

### Configuration
*   **`config.yaml`**
    *   Defines the installation paths:
        *   `AgentPath`: Root directory for agent configuration and logs (default: `C:\APPS\Sentinel`).
        *   `ToolsPath`: Directory for utility binaries (default: `C:\APPS\Sentinel\.tools`).

### Installation & Setup

*   **`scripts/Install-Prerequisites.ps1`**
    *   **Purpose:** Prepares the system with necessary dependencies.
    *   **What it does:**
        *   Checks for and acquires Administrator privileges.
        *   Downloads and installs/updates **Sysmon**, **Fluent Bit**, and **NSSM**.

*   **`scripts/Install-SentinelService.ps1`**
    *   **Purpose:** Installs the Sentinel Agent as a Windows Service.
    *   **Prerequisites:**
        *   **NSSM** (Non-Sucking Service Manager) must be installed and available in PATH.
    *   **What it does:**
        *   **Requires Administrator privileges.**
        *   Installs a Windows Service named "SentinelAgent" that runs `launcher.ps1`.
        *   Configures the service to start automatically and restart on failure.
        *   Sets up log rotation for service stdout/stderr.
        *   Removes any previous installation of the service before installing the new one.

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
