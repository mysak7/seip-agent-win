[SERVICE]
    Flush        1
    Log_Level    info
    HTTP_Server  On
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020

# Sysmon
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-Sysmon/Operational
    Interval_Sec 1
    DB           {{AGENT_PATH}}\sysmon-debug.sqlite
    Tag          sysmon

# Windows Security log
[INPUT]
    Name         winevtlog
    Channels     Security
    Interval_Sec 1
    DB           {{AGENT_PATH}}\security-debug.sqlite
    Tag          winsec

# System log
[INPUT]
    Name         winevtlog
    Channels     System
    Interval_Sec 5
    DB           {{AGENT_PATH}}\system-debug.sqlite
    Tag          winsys

# PowerShell Script Block Logging
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-PowerShell/Operational
    Interval_Sec 1
    DB           {{AGENT_PATH}}\powershell-debug.sqlite
    Tag          winps

# Windows Defender detections
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-Windows Defender/Operational
    Interval_Sec 5
    DB           {{AGENT_PATH}}\defender-debug.sqlite
    Tag          windef

# WMI Activity
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-WMI-Activity/Operational
    Interval_Sec 5
    DB           {{AGENT_PATH}}\wmi-debug.sqlite
    Tag          winwmi

# Task Scheduler
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-TaskScheduler/Operational
    Interval_Sec 5
    DB           {{AGENT_PATH}}\taskscheduler-debug.sqlite
    Tag          wints

[FILTER]
    Name    lua
    Match   *
    script  {{AGENT_PATH}}\llm_filter.lua
    call    drop_noise

[FILTER]
    Name    lua
    Match   *
    script  {{AGENT_PATH}}\sysmon_security.lua
    call    cb_filter

[FILTER]
    Name    lua
    Match   *
    script  {{AGENT_PATH}}\sysmon_pack.lua
    call    cb_pack

[OUTPUT]
    Name    stdout
    Match   *
    Format  json_lines
