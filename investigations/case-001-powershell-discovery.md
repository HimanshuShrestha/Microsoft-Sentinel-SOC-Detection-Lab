# Case #001 — PowerShell Discovery Command Investigation

## Case Overview

**Date:** September 9, 2026  
**Endpoint:** SOC-WIN11  
**User:** SOC-WIN11\socanalyst  
**Severity:** Informational / Lab Investigation  
**Final Verdict:** Benign  
**MITRE ATT&CK Tactic:** Discovery

## Investigation Summary
Multiple Windows discovery commands were observed on the `SOC-WIN11` endpoint under the `SOC-WIN11\socanalyst` account. The activity included `whoami`, `hostname`, `ipconfig`, `net user`, and `net localgroup administrators`.

The investigation focused on determining whether the command sequence represented legitimate interactive activity or suspicious post-compromise discovery. Sysmon process telemetry was analyzed in Microsoft Sentinel using KQL to reconstruct process ancestry and correlate surrounding network, file, registry, and process-access activity.

The commands were traced back through PowerShell to an interactive Windows session originating from `explorer.exe`. No suspicious network connections, file creation, persistence behavior, or other malicious follow-on activity was identified. Based on the available evidence, the activity was classified as benign.

## Observed Activity
| Command / Process | Investigation Purpose |
|---|---|
| `whoami.exe` | Identify the current user |
| `hostname.exe` | Identify the system hostname |
| `ipconfig.exe` | Discover network configuration |
| `net user` | Enumerate local/domain user information |
| `net localgroup administrators` | Enumerate members of the local Administrators group |

## Process Ancestry

Process creation telemetry was analyzed using Sysmon Event ID 1. `ProcessGuid` and `ParentProcessGuid` were used to reconstruct the process lineage rather than relying only on process names.

The discovery commands were traced to a PowerShell parent process, which originated from `explorer.exe`:

```text
explorer.exe
└── powershell.exe
    ├── whoami.exe
    ├── hostname.exe
    ├── ipconfig.exe
    ├── net.exe user
    └── net.exe localgroup administrators
```
## Investigation Queries
### Query 1 — Discovery Process Identification

This query parses Sysmon Event ID 1 telemetry and identifies common Windows discovery commands.

```kusto
Event
| where EventID == 1
| where TimeGenerated > ago(14d)
| extend ParseValue = parse_xml(EventData)
| mv-expand Data = ParseValue.DataItem.EventData.Data
| extend Field = tostring(Data["@Name"]), Value = tostring(Data["#text"])
| summarize Events = make_bag(bag_pack(Field, Value)) by TimeGenerated, EventID
| evaluate bag_unpack(Events)
| where Image endswith @"\whoami.exe"
    or Image endswith @"\hostname.exe"
    or Image endswith @"\ipconfig.exe"
    or Image endswith @"\net.exe"
    or Image endswith @"\net1.exe"
| project TimeGenerated, User, Image, CommandLine, ParentImage, ProcessGuid, ParentProcessGuid
| sort by TimeGenerated asc
```

## Correlated Telemetry

After identifying the discovery activity and reconstructing the process ancestry, additional Sysmon and Windows telemetry was reviewed to determine whether the PowerShell activity was associated with suspicious follow-on behavior.

| Telemetry | Investigation Result |
|---|---|
| Sysmon Event ID 3 — Network Connection | No suspicious network connection associated with the investigated PowerShell process. A separate Defender connection (`MpDefenderCoreService.exe → 52.123.250.130:443`) was observed but was unrelated to the discovery process. |
| Sysmon Event ID 10 — Process Access | Process-access activity involving `OneDrive.exe` and processes including `explorer.exe`, `powershell.exe`, `hostname.exe`, and `whoami.exe` was reviewed. No evidence was identified that changed the assessment of the discovery activity. |
| Sysmon Event ID 11 — File Create | No relevant file creation associated with the investigated discovery activity was identified. |
| Sysmon Event ID 13 — Registry Value Set | BAM-related registry activity associated with PowerShell was observed and reviewed. No suspicious persistence-related registry modification was identified. |
| PowerShell Event ID 4104 — Script Block Logging | Script-block telemetry was reviewed. The observed activity was consistent with benign Windows/IME-related PowerShell activity rather than the discovery commands indicating malicious scripting. |
| Windows Event ID 4624 — Successful Logon | An interactive logon (`LogonType 2`) for `socanalyst` was identified, providing additional context that the activity occurred during an interactive user session. |

## MITRE ATT&CK Mapping
The observed commands were mapped to the MITRE ATT&CK Discovery tactic based on the information each command attempted to obtain.

| Observed Activity | MITRE ATT&CK Technique |
|---|---|
| `whoami.exe` | T1033 — System Owner/User Discovery |
| `hostname.exe` | T1082 — System Information Discovery |
| `ipconfig.exe` | T1016 — System Network Configuration Discovery |
| `net user` | T1087.001 — Account Discovery: Local Account |
| `net localgroup administrators` | T1069.001 — Permission Groups Discovery: Local Groups |

## Analyst Assessment

The investigation began by reviewing activity surrounding the discovery-command burst, identifying the user and executed commands, and examining their `ProcessGuid` and `ParentProcessGuid` values. Process ancestry was reconstructed using Sysmon process creation telemetry to determine where the discovery commands originated.

The burst warranted investigation because multiple system and user discovery commands executed within a short period can also be observed during post-compromise reconnaissance. Further analysis of associated network connections, file creation, registry modifications, process access, and PowerShell telemetry did not identify suspicious follow-on behavior. The activity also occurred within an interactive user session and the process ancestry was consistent with user-initiated PowerShell activity.

Based on the process ancestry, surrounding telemetry, and absence of evidence indicating malicious follow-on activity, the case was classified as **benign**.

## Lessons Learned

- **Process ancestry provides critical context.** I learned that identifying a suspicious command is only the beginning of an investigation. Using `ProcessGuid` and `ParentProcessGuid` to reconstruct the process ancestry helps determine where a process originated and what other activity is related to it.

- **Discovery activity is not automatically malicious.** Commands such as `whoami`, `ipconfig`, and `net user` can be used by attackers, but they are also commonly used for legitimate administration and troubleshooting. Their presence should trigger further investigation rather than an immediate malicious verdict.

- **Conclusions should be evidence-based.** An analyst should consider supporting and contradicting evidence before reaching a verdict. Process ancestry, user context, authentication activity, network connections, file creation, registry modifications, and other surrounding telemetry can strengthen or weaken an initial hypothesis. The absence of one suspicious indicator alone is not enough to prove that activity is benign.
