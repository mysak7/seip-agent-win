-- llm_filter.lua
-- Tento skript zahazuje (suppress) bezny "Severity 1" sum na urovni Fluent Bitu (Edge)

-- Vytvorime index pravidel rozdelenych primarne podle EventID pro maximalni rychlost
-- Hledani klice v tabulce je O(1), takze nezatezujeme procesor slozitym matchovanim,
-- pokud to neni absolutne nutne.
local filters = {
    -- PowerShell ScriptBlock (EID 4104)
    [4104] = {
        -- Pattern 42: PowerShell ScriptBlock Execution Checking Cmdlet Status (1281 hits)
        "echo \"cmdlet status is\" %$?",

        -- Pattern 29 & 61: PowerShell Execution Checking Hyper-V Virtual Machine State (1064 + 205 hits)
        -- Toto pokryva oba varianty: Get-VM -Name cokoliv | Select-Object -ExpandProperty State
        "Get%-VM %-Name [^|]+%| Select%-Object %-ExpandProperty State"
    },

    -- Security Auditing (EID 4672)
    [4672] = {
        -- Pattern 6: Windows OS Special Privileges Assigned to New Logon (SYSTEM) (207 hits)
        -- Tohle je obrovsky sum pro systemove logony. Pozor na encoding, hledame SYSTEM a S-1-5-18.
        -- Fluent Bit predava Message jako jeden dlouhy string.
        "ID zabezpe.en.:%s*S%-1%-5%-18.+N.zev .ctu:%s*SYSTEM"
    },

    -- Sysmon Process Creation (EID 1)
    [1] = {
        -- Pattern 17: Dropbox Updater Executed as a Windows Service (60 hits)
        "Image: C:\\Program Files\\Dropbox\\DropboxUpdater\\[^\\]+\\updater%.exe.+ParentImage: C:\\Windows\\System32\\services%.exe",

        -- Pattern 13: Routine Microsoft Edge Installer Update Execution via Setup.exe (23 hits)
        "Image: C:\\Program Files %(x86%)\\Microsoft\\EdgeUpdate\\[^\\]+\\setup%.exe.+ParentImage: C:\\Windows\\System32\\svchost%.exe",

        -- Pattern 31: Windows Defender MpCmdRun WMI Schema Registration (21 hits)
        "Image: C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[^\\]+\\MpCmdRun%.exe.+GetDeviceTicket %-AccessKey",

        -- Z tveho souboru jsem nasel i dalsi bezne veci - napriklad Claude Code registry check
        "CommandLine: reg query HKLM\\SOFTWARE\\Policies\\ClaudeCode"
    },

    -- Sysmon File Create (EID 11)
    [11] = {
        -- Pattern 119: Microsoft VS Code Created Extension Cache Lock File (47 hits)
        "TargetFilename: C:\\Users\\[^\\]+\\AppData\\Roaming\\Code\\User\\globalStorage\\.+\\.lock"
    }
}

-- Hlavni filtrovaci funkce volana Fluent Bitem
function drop_noise(tag, timestamp, record)
    local eid = tonumber(record["eid"] or record["EventID"])
    local msg = record["message"] or record["Message"]

    -- Pokud log nema EventID nebo Message, propustime ho (return 0,0,0 = keep)
    if not eid or not msg then
        return 0, 0, 0
    end

    -- Podivame se, jestli mame pro dane EventID nejaka pravidla
    local eid_rules = filters[eid]
    if eid_rules then
        -- Projdeme jen pravidla pro toto konkretni EventID
        for _, pattern in ipairs(eid_rules) do
            -- Lua string.find je mnohem rychlejsi nez plnohodnotny regex
            if string.find(msg, pattern) then
                -- Match nalezen -> Zahodit (Drop) event
                return -1, 0, 0
            end
        end
    end

    -- Zadny match nebyl nalezen, event jde do dalsi pipeline (na server)
    return 0, 0, 0
end
