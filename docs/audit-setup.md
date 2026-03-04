# Windows Audit Setup

## Purpose

`scripts/maintenance/Initialize-WindowsAudit.ps1` is a **one-time, run-as-Admin** script
that configures a Windows endpoint to emit exactly the event IDs consumed by the Sentinel
Fluent Bit agent. Run it before (or alongside) deploying the agent.

---

## What the script configures

### 1. Event log sizes

Prevents data loss when the system is under attack (high event volume).

| Log                                            | New size |
|------------------------------------------------|----------|
| Security                                       | 1 GB     |
| System                                         | 500 MB   |
| Windows PowerShell (classic)                   | 500 MB   |
| Microsoft-Windows-PowerShell/Operational       | 500 MB   |
| Microsoft-Windows-WMI-Activity/Operational     | 100 MB   |
| Microsoft-Windows-TaskScheduler/Operational    | 100 MB   |

### 2. Audit policies

Only high-signal subcategories are enabled. Verbose subcategories (Account Logoff,
Kerberos Service Ticket Operations, etc.) are left off intentionally.

| Subcategory                  | Outcomes          | Key EIDs emitted           | Signal                         |
|------------------------------|-------------------|----------------------------|--------------------------------|
| Logon                        | Success + Failure | 4624, 4625                 | Interactive/remote logons, brute-force |
| Special Logon                | Success           | 4672                       | Admin-equivalent privilege on logon |
| Sensitive Privilege Use      | Success + Failure | 4673, 4674                 | SeDebugPrivilege, SeTcbPrivilege etc. |
| Process Creation             | Success           | 4688 (+ cmdline)           | Backup for when Sysmon EID 1 is unavailable |
| Registry                     | Success + Failure | 4657                       | Writes to audited keys (see SACLs below) |
| Other Object Access Events   | Success + Failure | 4698–4702                  | Scheduled task create/modify/delete |
| Security System Extension    | Success + Failure | 4697                       | Service installed via SCM |
| Security State Change        | Success + Failure | 1102                       | Security log cleared (anti-forensics) |
| Audit Policy Change          | Success + Failure | 4719                       | Audit policy tampered |

### 3. PowerShell Script Block Logging

Enables EID 4104 in `Microsoft-Windows-PowerShell/Operational`.
Invocation logging (4105/4106) is intentionally **not** enabled — it is dropped by the
Lua filter anyway and would add noise.

### 4. Registry SACLs

Places audit rules on three keys so that EID 4657 fires on any write:

| Key                                                              | Why it matters                |
|------------------------------------------------------------------|-------------------------------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`            | Startup persistence           |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`     | AppInit_DLLs — DLL injection  |
| `HKLM\SYSTEM\CurrentControlSet\Control\LSA`                     | LSA secrets / credential store |

> Registry audit policy (`auditpol /subcategory:"Registry"`) must also be enabled
> (done in step 2) for EID 4657 to fire.

### 5. WMI Activity log

Enables `Microsoft-Windows-WMI-Activity/Operational` so that EIDs 5859–5861
(WMI subscriptions — a common persistence mechanism) are recorded.

---

## Fluent Bit coverage

All channels the script activates are already captured by the agent:

| Channel                                         | FB tag   | Lua filter function     |
|-------------------------------------------------|----------|-------------------------|
| Security                                        | `winsec` | `filter_security`       |
| System                                          | `winsys` | `filter_system`         |
| Microsoft-Windows-PowerShell/Operational        | `winps`  | `filter_powershell`     |
| Microsoft-Windows-WMI-Activity/Operational      | `winwmi` | `filter_wmi`            |
| Microsoft-Windows-TaskScheduler/Operational     | `wints`  | `filter_task_scheduler` |
| Microsoft-Windows-Sysmon/Operational            | `sysmon` | `filter_sysmon`         |
| Microsoft-Windows-Windows Defender/Operational  | `windef` | `filter_defender`       |

### EIDs passed through by `sysmon_security.lua`

**Security log (`winsec`)**

| EID  | Event                                    |
|------|------------------------------------------|
| 1102 | Audit log cleared                        |
| 4624 | Successful logon (interactive types only: 2, 7, 9, 10, 11) |
| 4625 | Failed logon                             |
| 4648 | Logon with explicit credentials (RunAs)  |
| 4657 | Registry value modified                  |
| 4672 | Special privileges assigned to new logon |
| 4673 | Sensitive privilege use                  |
| 4674 | Operation on privileged object           |
| 4697 | Service installed                        |
| 4698–4702 | Scheduled task created/deleted/modified |
| 4703 | Token rights adjusted                    |
| 4719 | System audit policy changed              |
| 4720–4726 | User account lifecycle                 |
| 4728–4733 | Group membership changes               |
| 4738 | User account changed                     |
| 4740 | Account locked out                       |
| 4756 | Member added to universal group          |
| 4764 | Group type changed                       |
| 4771 | Kerberos pre-auth failed                 |
| 4776 | NTLM authentication attempt              |
| 4794 | DSRM password change attempt             |
| 4964 | Special groups logon                     |

**System log (`winsys`)**

| EID  | Event                         |
|------|-------------------------------|
| 7045 | New service installed         |
| 7040 | Service start type changed    |

**PowerShell (`winps`)**

| EID  | Event                         |
|------|-------------------------------|
| 4104 | Script block executed         |

**WMI Activity (`winwmi`)**

| EID  | Event                                   |
|------|-----------------------------------------|
| 5859 | WMI subscription created                |
| 5860 | Temporary WMI event subscription        |
| 5861 | Permanent WMI event subscription (persistence!) |

**Task Scheduler (`wints`)**

| EID  | Event                                                |
|------|------------------------------------------------------|
| 106  | Task registered                                      |
| 140  | Task updated                                         |
| 141  | Task deleted                                         |
| 200/201 | Task executed — only if path looks suspicious     |

**Windows Defender (`windef`)**

| EID  | Event                                   |
|------|-----------------------------------------|
| 1006–1008 | Malware detected / action taken / failed |
| 1116–1120 | Real-time protection events            |
| 5001–5012 | Protection disabled / config changed   |

**Sysmon (`sysmon`)**

All Sysmon events pass through a per-EID filter in `sysmon_security.lua`.
See the source comments for the full list.

---

## How to run

```powershell
# Right-click → Run as Administrator, or from an elevated shell:
.\scripts\maintenance\Initialize-WindowsAudit.ps1
```

Expected output: five numbered sections, each line starting with `OK`.
Any `FAIL` line means a key or log was not accessible — check permissions.

After the script completes, deploy or restart the Sentinel agent:

```powershell
.\scripts\Install-SentinelService.ps1   # first time
# or
nssm restart SentinelAgent              # already installed
```

---

## Full installation — agent + Lua filter watcher (recommended)

This mode runs both services under dedicated **Virtual Service Accounts** with
least-privilege permissions. Neither service requires LocalSystem or a human
admin account at runtime.

### Service account model

| Service | Account | Permissions |
|---|---|---|
| `SentinelAgent` | `NT SERVICE\SentinelAgent` | Full Control on `$AgentPath`, member of **Event Log Readers** |
| `SentinelLuaWatcher` | `NT SERVICE\SentinelLuaWatcher` | Modify on `$AgentPath`, Start+Stop+QueryStatus on `SentinelAgent` only (SDDL) |

### Step-by-step (all commands as Administrator)

**1. Prerequisites — Sysmon, Fluent Bit, NSSM**

```powershell
.\scripts\Install-Prerequisites.ps1
```

**2. Audit policy — one-time endpoint hardening**

```powershell
.\scripts\maintenance\Initialize-WindowsAudit.ps1
```

**3. Install SentinelAgent service**

Creates the `NT SERVICE\SentinelAgent` virtual account, grants it file and
event-log permissions, and starts Fluent Bit.

```powershell
.\scripts\Install-SentinelService.ps1
```

**4. Install SentinelLuaWatcher service**

Creates the `NT SERVICE\SentinelLuaWatcher` virtual account, grants it Modify
on the agent directory, and delegates Start/Stop rights over `SentinelAgent`
via SDDL — without giving it any other elevated privileges.

```powershell
.\scripts\Install-LuaWatcherService.ps1
```

> **Order matters.** The watcher installer reads `SentinelAgent`'s current
> SDDL to extend it. Run step 3 before step 4.

**5. Verify**

```powershell
Get-Service SentinelAgent, SentinelLuaWatcher | Format-Table Name, Status, StartType
```

Both services should show `Running` / `Automatic`.

Watcher log (poll results, download events, restarts):

```powershell
Get-Content "C:\ProgramData\SEIP\logs\lua-watcher.log" -Tail 30 -Wait
```

### How the watcher works

```
every LuaWatcherInterval seconds (default: 300 s)
  │
  ├─ GET noise_filter.meta  ──► parse { ts, archive_key }
  │
  ├─ compare ts  vs  C:\ProgramData\SEIP\lua_filter.state
  │
  ├─ [no change] → log "up-to-date", sleep
  │
  └─ [new ts] → download noise_filter.lua
               → overwrite C:\ProgramData\SEIP\llm_filter.lua
               → save new ts to lua_filter.state
               → Restart-Service SentinelAgent
```

### Runtime management

```powershell
# Stop everything
nssm stop SentinelLuaWatcher ; nssm stop SentinelAgent

# Start everything
nssm start SentinelAgent ; nssm start SentinelLuaWatcher

# Remove everything
nssm stop SentinelLuaWatcher  ; nssm remove SentinelLuaWatcher confirm
nssm stop SentinelAgent       ; nssm remove SentinelAgent confirm

# Change poll interval — edit config.yaml, then restart watcher
nssm restart SentinelLuaWatcher
```

### Tune the poll interval

Edit `config.yaml` and restart the watcher:

```yaml
LuaWatcherInterval: 120   # poll every 2 minutes
```

```powershell
nssm restart SentinelLuaWatcher
```
