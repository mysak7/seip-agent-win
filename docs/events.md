# What Gets Logged — Event Sources and Filtering Logic

## Architecture overview

```
Windows Event Logs
       │
       ▼
 Fluent Bit (winevtlog inputs, one per source)
       │
       ▼
 Lua filter 1 — sysmon_security.lua (cb_filter) — security filter
       │
       ├── drop (~75-85% of raw volume)
       │
       └── pass
              │
              ▼
 Lua filter 2 — sysmon_pack.lua (cb_pack) — noise drop
       │   Drops: StringInserts, GUIDs, Keywords, Opcode, Qualifiers,
       │           Task, ProviderGuid, Version, ActivityID, RuleName,
       │           SourceIsIpv6, DestinationIsIpv6
       │   Renames: EventID → eid, Computer → host
       │   Keeps: Message (whole), Channel, Level, TimeCreated,
       │           EventRecordID, all remaining fields
       │
       ▼
 Kafka topic: threats  (lz4 compressed)
```

Fluent Bit reads from 7 Windows event log channels in parallel.
Each channel gets its own tag and SQLite bookmark DB so Fluent Bit
can resume from the last read position after a restart.

`sysmon_security.lua` (`cb_filter`) receives every record and dispatches
to a per-source function based on the Fluent Bit tag.

`sysmon_pack.lua` (`cb_pack`) runs on all passing records, drops redundant
bulk fields (StringInserts alone is ~40% of raw payload), and renames two
top-level keys for consumer compatibility. The `Message` field is kept whole
— no parsing or reconstruction is done.

---

## Event sources

### 1. Sysmon — tag: `sysmon`

The primary telemetry source. Sysmon provides richer process, network,
and file data than the native Security log.

| EventID | Name | Filter logic |
|---------|------|--------------|
| 1 | Process Create | Complex — see below |
| 3 | Network Connection | Pass, with dedup for known VPN/RDP tools |
| 5 | Process Terminated | **Always dropped** — pure noise |
| 7 | Image Loaded (DLL) | Always pass |
| 8 | CreateRemoteThread | Always pass |
| 9 | RawAccessRead | Always pass |
| 10 | ProcessAccess | Always pass (LSASS dump indicator) |
| 11 | File Created | Pass if suspicious extension or path |
| 12–14 | Registry CRUD | Always pass |
| 15 | FileCreateStreamHash (ADS) | Always pass |
| 17–18 | Pipe Created/Connected | Always pass |
| 22 | DNS Query | Always pass |
| 23 | File Delete | Always pass |
| 25 | Process Tampering | Always pass |
| 26 | File Delete Logged | Always pass |
| everything else | — | Dropped |

**EventID 1 (Process Create) logic** — in order:
1. Drop if image is in noise list (`git.exe`, `conhost.exe`, etc.)
2. Drop if browser spawning itself with `--type=renderer/gpu/utility/crashpad`
3. Pass if image is a LOLBAS binary (`powershell.exe`, `rundll32.exe`, `certutil.exe`, ...)
4. Pass if image is a CLI tool (`cmd.exe`, `net.exe`, `schtasks.exe`, ...)
5. Drop if it matches a trusted system parent→child chain (`svchost → ctfmon`, etc.)
6. Pass if parent is Office or Acrobat (anything spawned from there is suspicious)
7. Pass if browser spawns a non-browser process and it's not a known browser helper
8. Drop OEM vendor binaries (`\Program Files\Dell\`, AMD, Intel, HP, etc.) launched by system services
9. Pass if integrity level is High or System
10. Drop everything else (Medium/Low integrity noise)

**EventID 3 (Network Connection) dedup:**
Processes like `rustdesk.exe`, `wireguard.exe`, `tailscale.exe` generate a
heartbeat connection every few seconds to the same IP:port. The dedup cache
suppresses re-logging the same image+IP+port combination for 5 minutes.

---

### 2. Windows Security log — tag: `winsec`

Native Windows authentication and account management events.

| EventID | Name | Notes |
|---------|------|-------|
| 4624 | Logon success | **Filtered** — only types 2/7/9/10/11 (see below) |
| 4625 | Logon failure | Always pass |
| 4648 | Logon with explicit credentials | RunAs, lateral movement indicator |
| 4657 | Registry value modified | Pass |
| 4697 | Service installed | Pass |
| 4698–4702 | Scheduled task CRUD | Pass |
| 4703 | Token rights adjusted | Pass |
| 4719 | Audit policy changed | Pass |
| 4720–4726 | User account management | Created, enabled, disabled, deleted, password changes |
| 4728–4733 | Group membership changes | Add/remove members from security groups |
| 4738 | User account changed | Pass |
| 4740 | Account locked out | Pass |
| 4756 | Universal group member added | Pass |
| 4764 | Group type changed | Pass |
| 4771 | Kerberos pre-auth failed | Pass |
| 4776 | NTLM auth attempt | Pass-the-hash indicator |
| 4794 | DSRM password change attempt | Pass |
| 4964 | Special groups logon | Pass |
| everything else | — | Dropped |

**4624 logon type filtering:**

| Type | Name | Decision |
|------|------|----------|
| 2 | Interactive | Pass |
| 3 | Network | **Drop** — biggest source of noise (every SMB/IPC$ access) |
| 4 | Batch | Drop |
| 5 | Service | Drop |
| 7 | Unlock | Pass |
| 8 | NetworkCleartext | Drop |
| 9 | NewCredentials | Pass (RunAs /netonly — lateral movement) |
| 10 | RemoteInteractive (RDP) | Pass |
| 11 | CachedInteractive | Pass |

Note: EventID 4688 (process creation) is intentionally excluded — Sysmon
EventID 1 provides the same data with richer fields (command line, hashes,
parent process, integrity level).

---

### 3. System log — tag: `winsys`

Only two event IDs are relevant here; everything else is dropped.

| EventID | Name |
|---------|------|
| 7040 | Service start type changed |
| 7045 | New service installed |

---

### 4. PowerShell — tag: `winps`

Source: `Microsoft-Windows-PowerShell/Operational`

| EventID | Name | Decision |
|---------|------|----------|
| 4104 | Script Block Logging | **Always pass** |
| 4100 | Engine lifecycle | Drop |
| 4103 | Module logging | **Drop** — extremely verbose, thousands of events per session |
| 4105–4106 | Command pipeline start/stop | Drop |

Script Block Logging (4104) captures the actual PowerShell code being executed,
including after de-obfuscation. It is the single highest-value PowerShell telemetry.

**Requirement:** Script Block Logging must be enabled via GPO or the included
`PowerShellScriptBlockLogging.ps1` script.

---

### 5. Windows Defender — tag: `windef`

Source: `Microsoft-Windows-Windows Defender/Operational`

| EventID | Description |
|---------|-------------|
| 1006–1008 | Malware scan detection / action taken / action failed |
| 1010 | Cannot update definitions (possible tampering) |
| 1116–1120 | Real-time detection and remediation events |
| 5001 | Real-time protection disabled |
| 5004 | Real-time protection config changed |
| 5007 | Configuration changed (possible tampering) |
| 5010 | Scanning disabled |
| 5012 | Scanning disabled |

Everything else (routine scan start/complete, definition updates) is dropped.

---

### 6. WMI Activity — tag: `winwmi`

Source: `Microsoft-Windows-WMI-Activity/Operational`

| EventID | Description | Decision |
|---------|-------------|----------|
| 5857 | WMI provider loaded | **Dropped** — fires on any WMI query, dozens/minute, zero signal |
| 5858 | WMI query error / timeout | **Dropped** — debug noise |
| 5859 | WMI event subscription created | Pass |
| 5860 | Temporary WMI event subscription | Pass |
| 5861 | **Permanent WMI event subscription** | Pass — classic persistence mechanism |

5861 (permanent subscription) is the critical one — it is how fileless malware
achieves persistence via WMI event filters bound to consumer scripts.

5857 and 5858 are dropped: 5857 fires on every routine WMI query (network
adapter enumeration, hardware inventory, etc.) and generates dozens to hundreds
of events per minute with no security signal. 5858 is a query timeout/error
diagnostic, not an indicator of compromise.

---

### 7. Task Scheduler — tag: `wints`

Source: `Microsoft-Windows-TaskScheduler/Operational`

| EventID | Description | Decision |
|---------|-------------|----------|
| 106 | Task registered | Always pass |
| 140 | Task updated | Always pass |
| 141 | Task deleted | Always pass |
| 200 | Task action launched | Pass only if suspicious path/name |
| 201 | Task action completed | Pass only if suspicious path/name |

For EventID 200/201 (task execution), only events where the task name or
action path contains `powershell`, `cmd.exe`, `wscript`, `temp`, `appdata`,
`public`, `programdata`, `mshta`, or `rundll32` are forwarded. Legitimate
scheduled maintenance tasks (Windows Update, Defender scans, etc.) are dropped.

---

## Known challenges

### Volume from Security log (4624)
Even with logon type filtering, busy machines (domain controllers, RDP servers)
can still produce hundreds of 4624 events per hour for type 2/10/11 logons.
Consider adding a further filter on `SubjectUserName` to drop known service
accounts if the volume is excessive.

### PowerShell 4104 size
Script Block Logging captures the full script text. Large scripts or modules
(e.g. PSReadLine, Az PowerShell) can produce 4104 events with several KB of
text each. The Kafka message size limit may need to be raised (`message.max.bytes`
on the broker side, `rdkafka.message.max.bytes` on the producer side).

### Sysmon EventID 3 on servers
On machines with many outbound connections (servers, RDP gateways), EventID 3
without the dedup cache would flood the pipeline. The current dedup TTL is 5
minutes — adjust `NET_DEDUP_TTL_SEC` in `sysmon_security.lua` for your environment.

### Sysmon EventID 22 (DNS)
DNS queries are passed unconditionally. On busy machines this can be noisy.
If needed, add a filter to drop queries to known-good domains (Windows Update,
Microsoft CDN, etc.) or apply a similar dedup by image+domain.

### WMI provider load delay (5857)
5857 fires when a WMI provider takes >5 seconds to load. This can be noisy on
slow hardware or at startup. If needed, filter by ProviderName to only pass
unknown or unsigned providers.

### Lua dedup cache is in-memory only
The `net_dedup_cache` for EventID 3 is reset every time the service restarts.
After a restart, all deduplicated connections will be logged once before the
cache repopulates. This is acceptable behaviour.

### Sysmon config dependency
The Lua filter assumes Sysmon is configured to generate all relevant EventIDs.
If Sysmon's XML config (`sysmon/sysmon-config.xml`) excludes certain event types
at the Sysmon level, the Lua filter will never see them. Always audit both
the Sysmon config and the Lua filter together.
