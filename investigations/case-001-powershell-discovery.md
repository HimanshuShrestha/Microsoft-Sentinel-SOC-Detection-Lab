# Case #001 — PowerShell Discovery Command Investigation

## Case Overview

**Date:** September 22, 2026  
**Endpoint:** SOC-WIN11  
**User:** SOC-WIN11\socanalyst  
**Severity:** Informational / Lab Investigation  
**Final Verdict:** Benign / Expected Test Activity  
**MITRE ATT&CK Tactic:** Discovery  

## Investigation Summary

A burst of Windows discovery commands was observed on the `SOC-WIN11` endpoint under the `SOC-WIN11\socanalyst` account. The activity included `whoami`, `net user`, `ipconfig`, and `net localgroup administrators`, all executed within approximately 18 seconds.

Because rapid execution of multiple discovery commands can occur during post-compromise reconnaissance, the activity warranted further investigation rather than being classified based only on the commands themselves.

Sysmon process creation telemetry was analyzed in Microsoft Sentinel using KQL. `ProcessGuid` and `ParentProcessGuid` were used to correlate the processes and reconstruct their ancestry. All four discovery processes shared the same `ParentProcessGuid` and identified `powershell.exe` as their parent process, establishing that they originated from the same PowerShell process rather than being unrelated commands that happened to execute close together.

Additional telemetry was reviewed for network connections, process access, file creation, registry modification, PowerShell script-block activity, and authentication context. The investigation did not identify additional evidence indicating malicious follow-on activity.

The analyst assessment was therefore Benign / Expected Test Activity. This assessment was then consistent with the known ground truth that the discovery activity had been intentionally generated as part of the controlled SOC lab.

## Observed Activity

Four discovery commands were observed within approximately 18 seconds. The approximate intervals between the commands were 4 seconds, 10 seconds, and 4 seconds. In addition to their temporal proximity, all four processes shared the same `ParentProcessGuid` and reported `powershell.exe` as their `ParentImage`, providing stronger correlation than timing alone.

| Command / Process | Investigation Purpose |
|---|---|
| `whoami.exe` | Identify the current user |
| `net user` | Enumerate user accounts on the system |
| `ipconfig.exe` | Discover network configuration |
| `net localgroup administrators` | Enumerate members of the local Administrators group |

The rapid sequence was treated as potentially suspicious discovery behavior because similar native Windows utilities can be used during post-compromise reconnaissance. However, the commands themselves were not considered sufficient evidence of compromise.

## Process Ancestry

Sysmon Event ID 1 process-creation telemetry was used to investigate the origin of the discovery activity.

The four discovery processes shared the same `ParentProcessGuid`, and their `ParentImage` was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This established that the commands originated from the same PowerShell process rather than representing independent activity occurring within the same time window.

Process ancestry analysis performed during the investigation traced the activity through an interactive Windows session:

```text
explorer.exe
└── powershell.exe
    ├── whoami.exe
    ├── net.exe user
    ├── ipconfig.exe
    └── net.exe localgroup administrators
```

This process tree was important because temporal proximity alone does not establish a relationship between processes. The shared parent process provided direct process-level correlation between the discovery commands.

## Investigation Queries

### Query 1 — Discovery Process Identification

The following KQL parses Sysmon Event ID 1 telemetry and identifies common Windows discovery utilities.

```kusto
Event
| where EventID == 1
| where TimeGenerated > ago(14d)
| extend ParseValue = parse_xml(EventData)
| mv-expand Data = ParseValue.DataItem.EventData.Data
| extend Field = tostring(Data["@Name"]), Value = tostring(Data["#text"])
| summarize Events = make_bag(bag_pack(Field, Value)) by TimeGenerated, EventID, Computer
| evaluate bag_unpack(Events)
| where Image endswith @"\whoami.exe"
    or Image endswith @"\hostname.exe"
    or Image endswith @"\ipconfig.exe"
    or Image endswith @"\net.exe"
    or Image endswith @"\net1.exe"
| project TimeGenerated, Computer, User, Image, CommandLine,
          ParentImage, ProcessGuid, ParentProcessGuid
| sort by TimeGenerated asc
```

The query was used to identify discovery-related process creation and expose the fields needed for process correlation and ancestry analysis.

## Correlated Telemetry

After identifying the discovery burst, additional telemetry was reviewed to determine whether the activity was accompanied by behavior that would increase the likelihood of malicious post-compromise activity.

| Telemetry | Investigation Result |
|---|---|
| **Sysmon Event ID 3 — Network Connection** | Network telemetry surrounding the investigated activity was reviewed. No suspicious network connection attributable to the investigated PowerShell discovery activity was identified. A separate connection from `MpDefenderCoreService.exe` to `52.123.250.130:443` was observed but was not attributed to the discovery process. |
| **Sysmon Event ID 10 — Process Access** | Process-access telemetry involving processes such as `OneDrive.exe`, `explorer.exe`, `powershell.exe`, and discovery utilities was reviewed. No process-access activity was identified that materially increased suspicion of the discovery burst. |
| **Sysmon Event ID 11 — File Create** | File-creation telemetry was reviewed for relevant activity surrounding the investigation. No relevant file creation was identified that could be confidently attributed to the discovery sequence. |
| **Sysmon Event ID 13 — Registry Value Set** | Registry telemetry was reviewed for persistence-related or otherwise suspicious modification. BAM-related PowerShell registry activity was observed, but no suspicious persistence modification attributable to the discovery activity was identified. |
| **PowerShell Event ID 4104 — Script Block Logging** | Available PowerShell script-block telemetry was reviewed for additional scripting context. No script-block evidence was identified that materially increased suspicion of the investigated discovery sequence. |
| **Windows Event ID 4624 — Successful Logon** | An interactive logon (`LogonType 2`) for `socanalyst` was observed and provided supporting context that the endpoint had an active interactive user session. |

### Interpretation of Negative Evidence

The absence of suspicious supporting events was not treated as proof that the activity was benign.

Negative findings are meaningful only within the visibility provided by the configured telemetry. The lab's Sysmon configuration and Data Collection Rules determine which events are available for analysis, and some event categories use selective filtering.

During later telemetry validation, known test activity was successfully observed end-to-end for Sysmon Event ID 1, Sysmon Event ID 13, and PowerShell Event ID 4104. A previous controlled file-creation test had also successfully produced Sysmon Event ID 11 telemetry. However, file-creation monitoring is selectively filtered, so the absence of an Event ID 11 record cannot be interpreted as proof that no file was created.

For this reason, the final assessment relied on the combination of process ancestry, user/session context, available correlated telemetry, and subsequent comparison with known lab ground truth rather than on the absence of any single event type.

## MITRE ATT&CK Mapping

The observed commands were mapped to the MITRE ATT&CK Discovery tactic according to the information each command attempted to obtain.

| Observed Activity | MITRE ATT&CK Technique |
|---|---|
| `whoami.exe` | T1033 — System Owner/User Discovery |
| `ipconfig.exe` | T1016 — System Network Configuration Discovery |
| `net user` | T1087.001 — Account Discovery: Local Account |
| `net localgroup administrators` | T1069.001 — Permission Groups Discovery: Local Groups |

## Analyst Assessment

### Evidence-Based Assessment

The discovery burst warranted investigation because several native Windows discovery utilities executed in rapid succession from the same PowerShell parent process. Similar behavior may occur during legitimate administration, troubleshooting, or post-compromise reconnaissance.

The initial hypothesis was therefore that the activity could represent suspicious discovery and required additional context.

Process analysis established that the four discovery processes shared the same PowerShell parent through a common `ParentProcessGuid`. This provided stronger correlation than the short time window alone.

Supporting telemetry was then reviewed for evidence that would increase or decrease suspicion. The investigation did not identify attributable suspicious network communication, persistence-related registry modification, relevant file creation, or other follow-on behavior that materially increased suspicion. Authentication telemetry also showed an interactive user session associated with the `socanalyst` account.

Based on the telemetry available to the analyst, the activity was assessed as **Benign / Expected Test Activity**.

### Ground Truth

After the analyst assessment, the result was compared with the known ground truth of the lab.

The discovery commands had been intentionally executed under the `SOC-WIN11\socanalyst` account as part of a controlled SOC investigation exercise. Therefore, the analyst assessment was consistent with the known origin of the activity.

Ground truth was treated separately from the investigative reasoning so that the benign classification was not based solely on prior knowledge that the commands had been intentionally generated.

### Escalation Criteria

The assessment would have changed if additional evidence had been identified, such as:

- an unexpected or suspicious parent process;
- encoded or obfuscated PowerShell activity;
- suspicious external network communication attributable to the same process lineage;
- unexpected file creation or payload staging;
- registry modification consistent with persistence;
- credential-access behavior;
- execution under an unexpected user or logon context; or
- additional suspicious activity correlated to the same process lineage.

The presence of one or more of these indicators would have justified expanding the investigation and potentially escalating the case.

## Lessons Learned

- **Process relationships are stronger evidence than timing alone.** Four commands executing within approximately 18 seconds created an initial behavioral correlation, but the shared `ParentProcessGuid` established that the processes originated from the same PowerShell process.

- **Discovery activity is not automatically malicious.** Utilities such as `whoami`, `ipconfig`, and `net` have legitimate administrative uses but can also appear during attacker reconnaissance. Their presence should generate investigative questions rather than an immediate malicious verdict.

- **Process ancestry provides important investigative context.** `ProcessGuid` and `ParentProcessGuid` allowed the activity to be reconstructed beyond individual process names and helped establish how the discovery processes were related.

- **Negative evidence has limits.** The absence of a network, file, or registry event is meaningful only when the relevant telemetry is configured and capable of observing the behavior. Visibility must be considered before interpreting missing events.

- **Ground truth and analyst reasoning should remain separate.** In a controlled lab, knowing that activity was intentionally generated can make a benign conclusion obvious. A stronger investigation reaches an assessment from telemetry first and then compares that assessment with the known ground truth.

- **An investigation should define what would change the verdict.** Identifying escalation criteria makes the reasoning more defensible and demonstrates what additional evidence would cause the analyst to reassess the case.
