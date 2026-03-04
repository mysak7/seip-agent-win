# Testing the Fluent Bit / Lua Filter Configuration

## Prerequisites

- Sysmon installed and running (`Microsoft-Windows-Sysmon/Operational` log channel must exist)
- Fluent Bit installed via `Install-Prerequisites.ps1`
- PowerShell running as **Administrator**

---

## Running the test

```powershell
.\scripts\maintenance\Test-FluentBit.ps1
```

This script:
1. Reads paths from `config.yaml`
2. Copies `fluent-bit\sysmon_security.lua` to `C:\ProgramData\SEIP\`
3. Generates `C:\ProgramData\SEIP\fluent-bit-debug.conf` from `fluent-bit\agent-config-debug.tpl`
   (stdout output instead of Kafka, separate SQLite DB so it does not interfere with production)
4. Starts Fluent Bit — filtered events stream to the console as JSON lines

Press **Ctrl+C** to stop.

---

## Where to look for results

### 1. Console output — filtered events (JSON)

Events that pass the Lua filter print directly to the terminal, one JSON object per line:

```
{"EventID":1,"Image":"C:\\Windows\\System32\\cmd.exe", ...}
{"EventID":10,"SourceImage":"...lsass.exe", ...}
```

Only security-relevant events appear here. Everything else is silently dropped.

### 2. Filter statistics — HTTP metrics endpoint

While the test is running, open a second terminal:

```powershell
curl http://localhost:2020/api/v1/metrics | ConvertFrom-Json | ConvertTo-Json -Depth 5
```

Key fields to read:

| Field | Meaning |
|---|---|
| `filter.lua.0.records` | Total records seen by the Lua filter |
| `filter.lua.0.drop_records` | Records dropped (noise) |
| `output.stdout.0.proc_records` | Records that passed through to output |

Example output from a healthy run:

```json
{
  "input":  { "winevtlog.0": { "records": 154, "bytes": 270234 } },
  "filter": { "lua.0": { "drop_records": 120, "add_records": 0, "records": 154 } },
  "output": { "stdout.0": { "proc_records": 34, "errors": 0 } }
}
```

Drop rate of ~75-85% is expected. If drop rate is 0%, the Lua script likely failed to load
(check the console for `[error]` lines from Fluent Bit on startup).

### 3. Generated debug config

Inspect what config Fluent Bit actually received:

```powershell
cat C:\ProgramData\SEIP\fluent-bit-debug.conf
```

Verify that `{{AGENT_PATH}}` was substituted with the real path and the `[FILTER]` block is present.

### 4. Lua script deployed to agent path

```powershell
cat C:\ProgramData\SEIP\sysmon_security.lua
```

This is the copy the running Fluent Bit instance reads. It is overwritten on every test/service start
from `fluent-bit\sysmon_security.lua` in the repo — edit the repo file, not this one.

---

## Switching back to production (Kafka output)

Stop the test script (Ctrl+C), then restart the service:

```powershell
nssm restart SentinelAgent
```

The service runs `launcher.ps1`, which regenerates `C:\ProgramData\SEIP\fluent-bit.conf`
with real Kafka credentials and starts Fluent Bit against that config.
