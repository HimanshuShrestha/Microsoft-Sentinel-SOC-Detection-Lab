# Microsoft Sentinel SOC Detection Lab

## Project Overview
This project simulates a SOC investigation workflow using Microsoft Sentinel in a controlled Windows 11 lab environment. I generated controlled system and account discovery activity on the endpoint and collected Sysmon telemetry in Microsoft Sentinel for detection and investigation. I developed and validated KQL detection logic to identify bursts of discovery commands and used the resulting activity as the starting point for analyst triage. During the investigation, I examined multiple telemetry sources, including Sysmon Event IDs 1, 3, 7, 11, and 13, and reconstructed process ancestry using ProcessGuid and ParentProcessGuid. I then correlated network, file, registry, and process activity surrounding the detection to determine whether supporting evidence indicated malicious behavior and document an analyst verdict.

## Lab Architecture
## Lab Architecture

```text
SOC-WIN11 (Windows 11 Endpoint)
│
├── Azure Arc
│   └── Connects and manages the endpoint in Azure
│
└── Sysmon
     │
     │  Generates endpoint telemetry
     ▼
Azure Monitor Agent (AMA)
     │
     │  Collects telemetry according to DCRs
     ▼
Data Collection Rules (DCR)
     │
     │  Defines what telemetry is collected
     ▼
Log Analytics Workspace
     │
     │  Stores and enables querying of telemetry
     ▼
Microsoft Sentinel
     │
     ├── KQL Detection
     ├── Alert / Incident Triage
     └── Investigation
```
         
## Core Technologies
| Technology | How you used it |
|---|---|
| **Microsoft Sentinel** | SIEM platform for detection, alert triage, log investigation, and incident analysis |
| **Sysmon** | Endpoint telemetry for process creation, network connections, image loads, file creation, process access, and registry changes |
| **Windows Security Events** | Windows authentication/security telemetry, including logon activity |
| **KQL** | Queried telemetry, reconstructed activity, correlated events, and developed detection logic |
| **MITRE ATT&CK** | Mapped observed discovery activity to corresponding adversary techniques |

## Telemetry Sources
| Event | Telemetry |
|---|---|
| Sysmon 1 | Process creation |
| Sysmon 3 | Network connection |
| Sysmon 7 | Image loaded |
| Sysmon 10 | Process access |
| Sysmon 11 | File creation |
| Sysmon 13 | Registry value set |
| Windows 4624 | Successful account logon |
| PowerShell 4104 | PowerShell script block content |

## Detection Engineering
### Discovery Burst Detection

I developed a KQL detection to identify potential discovery activity on the Windows endpoint. The detection uses Sysmon Event ID 1 process-creation telemetry and looks for multiple discovery utilities executed by the same user on the same endpoint within a two-minute window.

The detection monitors utilities including `whoami.exe`, `hostname.exe`, `ipconfig.exe`, and discovery-related uses of `net.exe`. Because `net.exe` can perform many legitimate functions, its command-line arguments are inspected to identify specific discovery behavior such as `net user` and `net localgroup administrators`.

The events are aggregated by computer, user, and two-minute time window. `dcount(Image)` is used to count distinct discovery utilities rather than total process executions, preventing repeated execution of a single utility from unnecessarily increasing the detection count. A burst is identified when three or more distinct discovery utilities are observed within the defined window.

### Detection Validation and Tuning

During validation, the initial detection returned no results even though discovery activity was known to exist in the telemetry. Rather than lowering the detection threshold, I examined the query pipeline and raw Sysmon Event ID 1 telemetry to identify where events were being excluded.

The investigation revealed that the initial `net.exe` command-line filter was too specific. The detection expected the literal string `net user`, while the actual Sysmon telemetry contained variations such as full executable paths and additional spacing. I adjusted the command-line matching based on the observed telemetry and reran the detection.

After tuning, the detection successfully identified the controlled discovery bursts with three distinct discovery utilities occurring within the two-minute threshold.
### Detection Result

<img width="940" height="437" alt="image" src="https://github.com/user-attachments/assets/430a145a-0a3e-45be-9d20-74824c03ff10" />


## Controlled Attack Simulation

To generate realistic telemetry for detection and investigation, I performed controlled discovery activity on the Windows 11 endpoint. The simulation represented reconnaissance that could occur after an attacker gains access to a system and begins gathering information about the compromised environment.

The following discovery commands were executed:

| Command | Discovery Purpose |
|---|---|
| `whoami` | Identify the currently logged-in user |
| `whoami /priv` | Enumerate privileges assigned to the current user's access token |
| `whoami /groups` | Enumerate the current user's group memberships |
| `ipconfig` | Examine the endpoint's network configuration |
| `net user` | Enumerate local user accounts |
| `net localgroup administrators` | Identify members of the local Administrators group |

Multiple discovery commands were intentionally executed within a short period rather than relying on a single command. This created a behavioral pattern representing how an attacker may gather several types of information about a compromised endpoint, including user identity, privileges, group memberships, network configuration, available accounts, and administrator membership.

The generated activity produced Sysmon process-creation telemetry that was ingested into Microsoft Sentinel and used to validate the discovery-burst detection and practice the subsequent SOC investigation workflow.

## SOC Investigation

### Initial Triage
After the discovery-burst activity was identified, I began triage by reviewing the detection timestamp, affected endpoint, user, and the command lines associated with the discovery activity. This established the initial scope of the investigation and identified the processes requiring further analysis.

### Process Ancestry Analysis
I examined the `Image`, `ParentImage`, `ProcessGuid`, and `ParentProcessGuid` fields from Sysmon Event ID 1 telemetry to reconstruct the process ancestry associated with the discovery commands. Process GUID relationships were used to determine which processes initiated the observed discovery activity rather than relying only on temporal proximity between events.

The analysis showed the relationship between the interactive shell and the discovery utilities executed during the controlled simulation, allowing the activity to be reconstructed as a process chain.
### Supporting Telemetry
Process ancestry alone was not considered sufficient to determine whether the discovery activity represented malicious behavior. After reconstructing the process chain, I examined additional endpoint telemetry for activity that could support or increase the initial suspicion.

The investigation included Sysmon Event ID 3 for network connections, Event ID 10 for process access, Event ID 11 for file creation, Event ID 13 for registry modifications, and additional Event ID 1 process-creation activity. PowerShell Script Block Logging (Event ID 4104) was also available to provide visibility into PowerShell activity.

Events were evaluated using the affected endpoint, user, timestamps, process relationships, and event-specific fields. Temporal proximity was treated as investigative context rather than proof that two events were causally related.

### MITRE ATT&CK Mapping

The discovery activity was mapped to the MITRE ATT&CK framework to connect the observed Windows commands with recognized adversary discovery behaviors.

| Activity | MITRE ATT&CK Technique |
|---|---|
| `whoami` / `whoami /priv` | System Owner/User Discovery (T1033) |
| `ipconfig` | System Network Configuration Discovery (T1016) |
| `net user` | Account Discovery: Local Account (T1087.001) |
| `net localgroup administrators` | Permission Groups Discovery: Local Groups (T1069.001) |

MITRE ATT&CK mapping provided additional context for understanding why the observed commands could be relevant during a SOC investigation. The presence of discovery techniques alone was not treated as proof of malicious activity; the surrounding telemetry and process relationships were also investigated.

### Analyst Verdict

**Verdict: Benign / Expected Test Activity**

The discovery burst warranted investigation because several discovery commands were executed within a short period and represented behavior that could also occur during post-compromise reconnaissance.

The investigation began with Sysmon Event ID 1 process-creation telemetry and expanded into process ancestry analysis using `ProcessGuid`, `ParentProcessGuid`, `Image`, `ParentImage`, and command-line information. Additional telemetry was reviewed for network connections, process access, file creation, registry modifications, and PowerShell activity.

The activity was ultimately classified as benign because it originated from the controlled lab simulation, and the investigation did not identify malicious follow-on behavior supporting a compromise. This investigation reinforced that discovery activity should be evaluated in context rather than classified as malicious based only on the execution of administrative or discovery commands.

## Key Findings and Lessons Learned

- A burst of discovery commands can justify investigation but does not independently establish malicious activity.
- Process ancestry provides stronger investigative context than relying only on events occurring close together in time.
- `ProcessGuid` and `ParentProcessGuid` can be used to reconstruct relationships between processes and understand how activity was initiated.
- Detection logic should be validated against actual telemetry rather than assumptions about how command-line data will appear.
- Repeated execution of one discovery utility should not necessarily carry the same detection weight as several distinct discovery behaviors.
- Supporting telemetry such as network connections, file creation, registry modifications, process access, and PowerShell logging can help determine whether suspicious discovery activity is followed by additional malicious behavior.
- Detection engineering is iterative. The initial discovery-burst query produced a false negative because the `net.exe` command-line filter did not match the actual telemetry. Examining the raw events allowed the detection logic to be corrected and successfully validated.

## Future Improvements

The current discovery-burst detection counts distinct executable images using `dcount(Image)`. This approach has a limitation because one executable can represent multiple discovery behaviors. For example, `net user` and `net localgroup administrators` both execute through `net.exe`, while `whoami` and `whoami /priv` both execute through `whoami.exe`.

A future version of the detection could normalize command lines into behavioral categories before aggregation. This would allow distinct discovery behaviors to be counted rather than only distinct executable images.

The current detection also uses fixed two-minute time bins. Activity occurring near the boundary between two bins could be separated even when the commands were executed close together. A future version could evaluate a rolling time window or another correlation strategy to reduce this limitation.

Additional improvements could include correlating a discovery burst with subsequent suspicious network connections, file creation, registry modifications, or other endpoint activity associated with the same user, endpoint, or process ancestry. This would provide higher-confidence behavioral detection while reducing reliance on discovery commands alone.
