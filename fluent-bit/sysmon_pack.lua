-- sysmon_pack.lua
-- Minimal post-filter: drops redundant bulk fields, keeps everything else as-is.
-- Message is kept whole. No field parsing or reconstruction.
-- lz4 compression is applied at the Kafka output layer.
--
-- Payload reduction breakdown (approximate):
--   StringInserts removed  → ~40% size reduction (raw array duplicates Message content)
--   GUIDs + noise removed  → ~10-15% additional reduction
--   lz4 compression        → further 60-70% on top

local NOISE_KEYS = {
    -- Biggest win: raw ordered array that duplicates Message
    "StringInserts",

    -- Analyst-useless metadata
    "Keywords",             -- hex bitmask (e.g. 0x8000000000000000)
    "Opcode",               -- always "Info" for these events
    "Qualifiers",           -- legacy field, always 0
    "Task",                 -- numeric category, redundant with EventID
    "ProviderGuid",         -- UUID, duplicates Channel/Provider info
    "Version",              -- event schema version, not needed at query time
    "ActivityID",
    "RelatedActivityID",
    "SourceIsIpv6",         -- always false in IPv4 environments
    "DestinationIsIpv6",
    "RuleName",             -- Sysmon: always "-" when no rule matched

    -- Process/session GUIDs — PIDs are sufficient for correlation
    "ProcessGuid",
    "ParentProcessGuid",
    "TargetProcessGuid",
    "SourceProcessGuid",
    "LogonGuid",
    "TargetLogonGuid",
}

function cb_pack(tag, timestamp, record)
    for _, k in ipairs(NOISE_KEYS) do
        record[k] = nil
    end

    -- Simple renames for consumer compatibility
    if record["EventID"] ~= nil then
        record["eid"]      = record["EventID"]
        record["EventID"]  = nil
    end
    if record["Computer"] ~= nil then
        record["host"]     = record["Computer"]
        record["Computer"] = nil
    end

    return 1, timestamp, record
end
