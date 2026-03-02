-- sysmon_security.lua v3
-- Multi-source Windows security event filter.
-- Dispatches by Fluent Bit tag: sysmon | winsec | winsys | winps | windef | winwmi | wints

-- ── EventID 3: dedup cache ────────────────────────────────────────────────
local net_dedup_cache = {}
local NET_DEDUP_TTL_SEC = 300

-- ── Global event dedup cache ──────────────────────────────────────────────
-- Drops identical events (same EID + PID + Message prefix) within 60 s.
-- Bounded to DEDUP_MAX_KEYS to prevent unbounded memory growth.
local DEDUP_TTL_SEC  = 60
local DEDUP_MAX_KEYS = 8000
local dedup_cache    = {}
local dedup_size     = 0

-- ── Helpers ───────────────────────────────────────────────────────────────
local function icontains(str, sub)
    if not str or not sub then return false end
    return str:lower():find(sub:lower(), 1, true) ~= nil
end

local function iends_with(str, suffix)
    if not str or not suffix then return false end
    return str:lower():sub(-#suffix) == suffix:lower()
end

local function matches_any(str, list)
    for _, item in ipairs(list) do
        if icontains(str, item) then return true end
    end
    return false
end

local function dedup_key(record)
    -- Stable fingerprint: EventID + ProcessId + first 128 chars of Message.
    -- Keeps keys short enough to avoid huge memory per entry.
    local eid = tostring(record["EventID"] or "")
    local pid = tostring(record["ProcessId"] or "")
    local msg = (record["Message"] or ""):sub(1, 128)
    return eid .. "|" .. pid .. "|" .. msg
end

local function dedup_seen(key, now)
    local t = dedup_cache[key]
    if t and (now - t) < DEDUP_TTL_SEC then
        return true  -- identical event already sent recently
    end
    if not t then dedup_size = dedup_size + 1 end
    dedup_cache[key] = now
    -- Prune expired entries when the table is full
    if dedup_size > DEDUP_MAX_KEYS then
        for k, v in pairs(dedup_cache) do
            if (now - v) >= DEDUP_TTL_SEC then
                dedup_cache[k] = nil
                dedup_size = dedup_size - 1
            end
        end
    end
    return false
end

local function extract_field(msg, field_name)
    if not msg then return nil end
    return msg:match(field_name .. ": ([^\r\n]+)")
end

-- ── SYSMON constants ──────────────────────────────────────────────────────
local SYSMON_HIGH_VALUE = {
    [6]=true,  -- Driver Loaded (BYOVD: vulnerable Anti-Cheat / kernel driver dropped by attacker)
    [7]=true, [8]=true, [9]=true, [10]=true,
    [12]=true, [13]=true, [14]=true, [15]=true,
    [17]=true, [18]=true, [22]=true,
    [23]=true, [25]=true, [26]=true,
}

local LOLBAS = {
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "msiexec.exe",
    "psexec.exe", "psexec64.exe",
    "whoami.exe", "nltest.exe",
    "mimikatz.exe", "procdump.exe",
    -- 2025/2026: native Win11 binaries now preferred by attackers to evade PS scrutiny
    "curl.exe",      -- download payloads: curl.exe -o payload.exe http://...
    "tar.exe",       -- unpack staged archives: tar -xf loot.zip
    "forfiles.exe",  -- execute per-file commands; used for LOLBin chains
    "expand.exe",    -- decompress cabinet files; staging technique
    "bash.exe",      -- WSL1/WSL2 shell escape from Win32 monitoring
    "wsl.exe",       -- WSL entry point; can exec Linux ELFs and bypass AMSI
}

local SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrobat.exe", "acrord32.exe", "msaccess.exe",
}

local ALWAYS_DROP_IMAGES = {
    "git.exe", "conhost.exe",
    "backgroundtaskhost.exe", "searchprotocolhost.exe",
    "searchfilterhost.exe",
}

local BROWSER_SUBPROCESS_TYPES = {
    "--type=renderer", "--type=gpu-process",
    "--type=utility", "--type=crashpad-handler",
    "--type=gpu-broker",
}

local TRUSTED_SYSTEM_CHAINS = {
    {p="svchost.exe",    c="ctfmon.exe"},
    {p="svchost.exe",    c="dllhost.exe"},
    {p="svchost.exe",    c="audiodg.exe"},
    {p="svchost.exe",    c="werfault.exe"},
    {p="svchost.exe",    c="runtimebroker.exe"},
    {p="svchost.exe",    c="settingsynchost.exe"},
    {p="svchost.exe",    c="smartscreen.exe"},
    {p="dpmservice.exe", c="dpm.exe"},
    {p="services.exe",   c="hpaudioanalytics.exe"},
    {p="rustdesk.exe",   c="rustdesk.exe"},
    {p="svchost.exe",    c="rsservcmd.exe"},
    {p="svchost.exe",    c="rselogs.exe"},
}

local NET_DEDUP_PROCESSES = {
    "rustdesk.exe", "wireguard.exe", "netbird.exe",
    "zerotier-one_x64.exe", "tailscale.exe",
}

-- ── SECURITY LOG constants ────────────────────────────────────────────────
-- 4624 logon types to keep: Interactive, Unlock, NewCredentials, RemoteInteractive, CachedInteractive
local KEEP_LOGON_TYPES = { ["2"]=true, ["7"]=true, ["9"]=true, ["10"]=true, ["11"]=true }

local SECURITY_HIGH_VALUE = {
    [1102]=true,  -- Audit log cleared (anti-forensics)
    [4625]=true,  -- Failed logon
    [4648]=true,  -- Logon with explicit credentials (RunAs / lateral movement)
    [4657]=true,  -- Registry value modified (requires SACL on key)
    [4672]=true,  -- Special privileges assigned to new logon (admin-equivalent)
    [4673]=true,  -- Sensitive privilege use
    [4674]=true,  -- Operation attempted on privileged object
    [4697]=true,  -- Service installed
    [4698]=true,  -- Scheduled task created
    [4699]=true,  -- Scheduled task deleted
    [4700]=true,  -- Scheduled task enabled
    [4701]=true,  -- Scheduled task disabled
    [4702]=true,  -- Scheduled task updated
    [4703]=true,  -- Token rights adjusted
    [4719]=true,  -- System audit policy changed
    [4720]=true,  -- User account created
    [4722]=true,  -- User account enabled
    [4723]=true,  -- Password change attempt
    [4724]=true,  -- Password reset attempt
    [4725]=true,  -- User account disabled
    [4726]=true,  -- User account deleted
    [4728]=true,  -- Member added to global group
    [4729]=true,  -- Member removed from global group
    [4732]=true,  -- Member added to local group
    [4733]=true,  -- Member removed from local group
    [4738]=true,  -- User account changed
    [4740]=true,  -- Account locked out
    [4756]=true,  -- Member added to universal group
    [4764]=true,  -- Group type changed
    [4771]=true,  -- Kerberos pre-auth failed
    [4776]=true,  -- NTLM auth attempt (pass-the-hash indicator)
    [4794]=true,  -- DSRM password change attempt
    [4964]=true,  -- Special groups logon
}

-- ── SYSTEM LOG constants ──────────────────────────────────────────────────
local SYSTEM_HIGH_VALUE = {
    [7045]=true,  -- New service installed
    [7040]=true,  -- Service start type changed
}

-- ── WINDOWS DEFENDER constants ────────────────────────────────────────────
local DEFENDER_HIGH_VALUE = {
    [1006]=true,  -- Malware detected (scan)
    [1007]=true,  -- Action taken on malware
    [1008]=true,  -- Failed to take action on malware
    [1010]=true,  -- Cannot update definitions
    [1116]=true,  -- Malware detected (real-time)
    [1117]=true,  -- Action taken to protect from malware
    [1118]=true,  -- Failed to take action (real-time)
    [1119]=true,  -- Critical error taking action
    [1120]=true,  -- Error taking action
    [5001]=true,  -- Real-time protection disabled
    [5004]=true,  -- Real-time protection config changed
    [5007]=true,  -- Config changed (possible tampering)
    [5010]=true,  -- Scanning for malware disabled
    [5012]=true,  -- Scanning disabled
}

-- ── WMI ACTIVITY constants ────────────────────────────────────────────────
local WMI_HIGH_VALUE = {
    -- 5857 (provider load) and 5858 (query error/timeout) are pure noise — dropped
    [5859]=true,  -- Subscription created
    [5860]=true,  -- Temporary event subscription
    [5861]=true,  -- Permanent event subscription (persistence!)
}

-- ── TASK SCHEDULER constants ──────────────────────────────────────────────
local TASKSCHEDULER_HIGH_VALUE = {
    [106]=true,  -- Task registered
    [140]=true,  -- Task updated
    [141]=true,  -- Task deleted
}

-- Paths that make task execution events (200/201) suspicious
local SUSPICIOUS_TASK_PATHS = {
    "\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\",
    "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
}

-- ═════════════════════════════════════════════════════════════════════════════
-- SYSMON FILTERS
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_network(timestamp, record)
    local msg        = record["Message"] or ""
    local image      = extract_field(msg, "Image") or ""
    local dest_ip    = extract_field(msg, "DestinationIp") or ""
    local dest_port  = extract_field(msg, "DestinationPort") or ""
    local image_base = image:lower():match("([^\\]+)$") or ""

    local should_dedup = false
    for _, proc in ipairs(NET_DEDUP_PROCESSES) do
        if image_base == proc then should_dedup = true; break end
    end

    if should_dedup then
        local key = image_base .. "|" .. dest_ip .. "|" .. dest_port
        local now = math.floor(timestamp)
        local last = net_dedup_cache[key]
        if last and (now - last) < NET_DEDUP_TTL_SEC then
            return -1, 0, 0
        end
        net_dedup_cache[key] = now
        if math.random(1, 50) == 1 then
            for k, v in pairs(net_dedup_cache) do
                if (now - v) > NET_DEDUP_TTL_SEC * 2 then net_dedup_cache[k] = nil end
            end
        end
    end

    return 0, timestamp, record
end

local function filter_process_create(timestamp, record)
    local msg         = record["Message"] or ""
    local image       = extract_field(msg, "Image") or ""
    local cmdline     = extract_field(msg, "CommandLine") or ""
    local parent      = extract_field(msg, "ParentImage") or ""
    local integrity   = extract_field(msg, "IntegrityLevel") or ""
    local image_base  = image:lower():match("([^\\]+)$") or ""
    local parent_base = parent:lower():match("([^\\]+)$") or ""

    if matches_any(image_base, ALWAYS_DROP_IMAGES) then return -1, 0, 0 end

    local browser_images = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"}
    local is_browser_img = matches_any(image_base, browser_images)
    local is_browser_par = matches_any(parent_base, browser_images)
    if is_browser_img and is_browser_par then
        for _, bt in ipairs(BROWSER_SUBPROCESS_TYPES) do
            if icontains(cmdline, bt) then return -1, 0, 0 end
        end
    end

    if matches_any(image_base, LOLBAS) then return 0, timestamp, record end

    local interesting_tools = {
        "cmd.exe", "net.exe", "net1.exe", "schtasks.exe",
        "taskkill.exe", "sc.exe", "reg.exe", "at.exe",
        "werfaultsecure.exe",  -- EDR-Freeze: secure error-reporting can be abused to suspend/dump EDR process
    }
    if matches_any(image_base, interesting_tools) then return 0, timestamp, record end

    for _, chain in ipairs(TRUSTED_SYSTEM_CHAINS) do
        if iends_with(parent, chain.p) and iends_with(image, chain.c) then return -1, 0, 0 end
    end

    if matches_any(parent_base, SUSPICIOUS_PARENTS) then return 0, timestamp, record end

    if is_browser_par and not is_browser_img then
        local browser_helpers = {
            "\\google\\chrome\\", "\\microsoft\\edge\\", "\\mozilla firefox\\",
            "\\crashreporter.exe", "\\browser_broker.exe",
        }
        if not matches_any(image:lower(), browser_helpers) then return 0, timestamp, record end
    end

    if integrity == "High" or integrity == "System" then
        local benign_system_parents = {"services.exe", "svchost.exe", "wininit.exe", "winlogon.exe", "smss.exe"}
        local benign_vendor_paths = {
            "\\driverstore\\filerepository\\", "\\program files\\dell\\",
            "\\program files\\hp\\", "\\program files\\amd\\",
            "\\program files\\intel\\", "\\program files\\realtek\\",
            "\\program files\\windowsapps\\advancedmicrodevices",
        }
        if matches_any(parent_base, benign_system_parents) and matches_any(image:lower(), benign_vendor_paths) then
            return -1, 0, 0
        end
        return 0, timestamp, record
    end

    return -1, 0, 0
end

local function filter_file_create(timestamp, record)
    local msg    = record["Message"] or ""
    local target = extract_field(msg, "TargetFilename") or ""
    local suspicious_ext   = {".exe",".dll",".ps1",".bat",".vbs",".js",".hta",".scr",".cpl",".msi",".lnk"}
    local suspicious_paths = {"\\Temp\\","\\AppData\\Roaming\\","\\AppData\\Local\\Temp\\",
                               "\\Public\\","\\ProgramData\\","\\Windows\\Temp\\"}
    if matches_any(target, suspicious_ext) or matches_any(target, suspicious_paths) then
        return 0, timestamp, record
    end
    return -1, 0, 0
end

local function filter_sysmon(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end
    if SYSMON_HIGH_VALUE[eid] then return 0, timestamp, record end
    if eid == 3  then return filter_network(timestamp, record) end
    if eid == 1  then return filter_process_create(timestamp, record) end
    if eid == 5  then return -1, 0, 0 end  -- Process Terminated: pure noise
    if eid == 11 then return filter_file_create(timestamp, record) end
    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- WINDOWS SECURITY LOG
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_security(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end

    -- 4624: only interactive, unlock, new-credentials, remote-interactive, cached-interactive
    if eid == 4624 then
        local logon_type = extract_field(record["Message"] or "", "Logon Type") or ""
        if KEEP_LOGON_TYPES[logon_type] then return 0, timestamp, record end
        return -1, 0, 0
    end

    if SECURITY_HIGH_VALUE[eid] then return 0, timestamp, record end
    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- SYSTEM LOG
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_system(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end
    if SYSTEM_HIGH_VALUE[eid] then return 0, timestamp, record end
    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- POWERSHELL
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_powershell(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end
    -- 4104 = Script Block Logging (the only one worth keeping)
    if eid == 4104 then return 0, timestamp, record end
    -- Drop 4100 (engine started), 4103 (module logging), 4105/4106 (pipeline noise)
    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- WINDOWS DEFENDER
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_defender(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end
    if DEFENDER_HIGH_VALUE[eid] then return 0, timestamp, record end
    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- WMI ACTIVITY
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_wmi(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end
    if WMI_HIGH_VALUE[eid] then return 0, timestamp, record end
    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- TASK SCHEDULER
-- ═════════════════════════════════════════════════════════════════════════════

local function filter_task_scheduler(timestamp, record)
    local eid = tonumber(record["EventID"])
    if not eid then return -1, 0, 0 end

    if TASKSCHEDULER_HIGH_VALUE[eid] then return 0, timestamp, record end

    -- Task execution: only when the task name or action path looks suspicious
    if eid == 200 or eid == 201 then
        local msg  = record["Message"] or ""
        local name = (extract_field(msg, "Task Name") or "") .. (extract_field(msg, "Action Name") or "")
        if matches_any(name:lower(), SUSPICIOUS_TASK_PATHS) then return 0, timestamp, record end
        return -1, 0, 0
    end

    return -1, 0, 0
end

-- ═════════════════════════════════════════════════════════════════════════════
-- MAIN CALLBACK — dispatch by tag
-- ═════════════════════════════════════════════════════════════════════════════

function cb_filter(tag, timestamp, record)
    local now = math.floor(timestamp)
    if dedup_seen(dedup_key(record), now) then return -1, 0, 0 end

    if tag == "sysmon"  then return filter_sysmon(timestamp, record) end
    if tag == "winsec"  then return filter_security(timestamp, record) end
    if tag == "winsys"  then return filter_system(timestamp, record) end
    if tag == "winps"   then return filter_powershell(timestamp, record) end
    if tag == "windef"  then return filter_defender(timestamp, record) end
    if tag == "winwmi"  then return filter_wmi(timestamp, record) end
    if tag == "wints"   then return filter_task_scheduler(timestamp, record) end
    return -1, 0, 0  -- unknown source: drop
end
