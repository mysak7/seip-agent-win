[SERVICE]
    Flush        1
    Log_Level    info

# Sysmon
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-Sysmon/Operational
    Interval_Sec 1
    DB           {{AGENT_PATH}}\sysmon.sqlite
    Tag          sysmon

# Windows Security log
[INPUT]
    Name         winevtlog
    Channels     Security
    Interval_Sec 1
    DB           {{AGENT_PATH}}\security.sqlite
    Tag          winsec

# System log (service installs etc.)
[INPUT]
    Name         winevtlog
    Channels     System
    Interval_Sec 5
    DB           {{AGENT_PATH}}\system.sqlite
    Tag          winsys

# PowerShell Script Block Logging
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-PowerShell/Operational
    Interval_Sec 1
    DB           {{AGENT_PATH}}\powershell.sqlite
    Tag          winps

# Windows Defender detections
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-Windows Defender/Operational
    Interval_Sec 5
    DB           {{AGENT_PATH}}\defender.sqlite
    Tag          windef

# WMI Activity (persistence via subscriptions)
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-WMI-Activity/Operational
    Interval_Sec 5
    DB           {{AGENT_PATH}}\wmi.sqlite
    Tag          winwmi

# Task Scheduler (persistence via scheduled tasks)
[INPUT]
    Name         winevtlog
    Channels     Microsoft-Windows-TaskScheduler/Operational
    Interval_Sec 5
    DB           {{AGENT_PATH}}\taskscheduler.sqlite
    Tag          wints

[FILTER]
    Name    lua
    Match   *
    script  noise_filter.lua
    call    drop_noise

[FILTER]
    Name    lua
    Match   *
    script  static_filter.lua
    call    drop_noise

[FILTER]
    Name    lua
    Match   *
    script  sysmon_security.lua
    call    cb_filter

[FILTER]
    Name    lua
    Match   *
    script  sysmon_pack.lua
    call    cb_pack

[OUTPUT]
    Name                          kafka
    Match                         *
    Brokers                       {{BROKER_URL}}
    Topics                        threats
    Timestamp_Key                 ts
    rdkafka.security.protocol     SASL_SSL
    rdkafka.sasl.mechanism        PLAIN
    rdkafka.sasl.username         {{KAFKA_USER}}
    rdkafka.sasl.password         {{KAFKA_PASS}}
    rdkafka.compression.codec        lz4
    rdkafka.socket.keepalive.enable  true
    rdkafka.connections.max.idle.ms  180000
