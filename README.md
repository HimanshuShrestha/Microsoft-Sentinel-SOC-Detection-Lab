# Microsoft Sentinel SOC Detection Lab

## Project Overview

This project demonstrates a SOC detection and investigation workflow using Microsoft Sentinel in a controlled Windows 11 lab environment. I generated controlled Windows discovery activity, collected endpoint telemetry using Sysmon, and investigated the resulting activity in Microsoft Sentinel.

I developed a KQL detection query to identify bursts of discovery utilities executed by the same user and endpoint within a short time window. During investigation, I used Sysmon process-creation telemetry to reconstruct process relationships with `ProcessGuid` and `ParentProcessGuid` and reviewed additional network, process-access, file, registry, PowerShell, and authentication telemetry for supporting evidence.

The project focuses on the complete analyst workflow:

**Generate activity → Detect → Triage → Reconstruct process ancestry → Correlate telemetry → Map to MITRE ATT&CK → Determine verdict**

The investigation demonstrated an important SOC principle: discovery commands may justify investigation, but their presence alone does not establish malicious activity.

---

## Lab Architecture

```text
SOC-WIN11 (Windows 11 Endpoint)
│
├── Azure Arc
│   └── Connects and manages the endpoint in Azure
│
└── Sysmon
     │
     │ Generates endpoint telemetry
     ▼
Azure Monitor Agent (AMA)
     │
     │ Collects telemetry according to DCRs
     ▼
Data Collection Rules (DCR)
     │
     │ Defines what telemetry is collected
     ▼
Log Analytics Workspace
     │
     │ Stores and enables querying of telemetry
     ▼
Microsoft Sentinel
     │
     ├── KQL Detection Queries
     ├── Triage
     └── Investigation
```

Azure Arc provides management and onboarding capabilities for the Windows endpoint, while the telemetry pipeline uses the Azure Monitor Agent and Data Collection Rules to send configured events to the Log Analytics workspace used by Microsoft Sentinel.

---

## Core Technologies

| Technology | How It Was Used |
|---|---|
| **Microsoft Sentinel** | SIEM platform for detection queries, triage, log investigation, and analysis |
| **Sysmon** | Endpoint telemetry for process creation, network connections, image loads, process access, file creation, and registry changes |
| **Windows Security Events** | Authentication and logon context |
| **PowerShell Script Block Logging** | Visibility into PowerShell script execution through Event ID 4104 |
| **KQL** | Parsed telemetry, filtered events, reconstructed activity, correlated evidence, and developed detection logic |
| **MITRE ATT&CK** | Mapped observed discovery behaviors to recognized adversary techniques |

---

## Telemetry Sources

The lab collected multiple telemetry sources. Not every event type contributed equally to every investigation.

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

Sysmon Event ID 1 provided the primary evidence for the discovery-burst investigation because it exposed process names, command lines, users, and process relationships. Other telemetry sources were reviewed as supporting context where applicable.

---

## Detection Engineering

### Discovery Burst Detection

I developed a KQL detection query to identify potential discovery activity using Sysmon Event ID 1 process-creation telemetry.

The query searches for multiple discovery utilities executed by the same user on the same endpoint within a two-minute time window.

The detection monitors:

- `whoami.exe`
- `hostname.exe`
- `ipconfig.exe`
- discovery-related execution of `net.exe`

Because `net.exe` supports many legitimate functions, command-line arguments are inspected to identify discovery behavior such as:

- `net user`
- `net localgroup administrators`

Events are aggregated by computer, user, and two-minute time bin. `dcount(Image)` counts distinct discovery executable images rather than total executions.

A burst is returned when three or more distinct discovery utilities are observed within the defined window.

### Detection Validation and False-Negative Troubleshooting

During functional validation, the initial query returned no results even though controlled discovery activity was known to exist in the telemetry.

Instead of immediately changing the threshold, I examined the query pipeline and raw Sysmon Event ID 1 events to determine where the expected activity was being excluded.

The issue was traced to an overly specific `net.exe` command-line filter. The original logic expected a literal command-line pattern such as `net user`, while the actual Sysmon telemetry contained executable paths and formatting differences.

The filter was corrected based on the observed telemetry and the query was rerun.

After the correction, the KQL query successfully identified the controlled discovery burst.

This testing demonstrated functional validation and false-negative troubleshooting of the query. More extensive positive, negative, and boundary testing would be required before describing the detection as production-ready.

### Detection Result

<img width="940" height="437" alt="Discovery burst detection result" src="https://github.com/user-attachments/assets/430a145a-0a3e-45be-9d20-74824c03ff10" />

> **Implementation note:** The discovery logic documented in this repository was executed and validated as a KQL detection query against Microsoft Sentinel telemetry. The repository does not represent the query as a production-deployed analytics rule.

---

## Controlled Discovery Simulation

To generate telemetry for detection and investigation, I intentionally executed Windows discovery commands on the controlled Windows 11 endpoint.

The activity represented behaviors that could be observed when a user, administrator, or attacker gathers information about a system.

Commands used during controlled testing included:

| Command | Discovery Purpose |
|---|---|
| `whoami` | Identify the currently logged-in user |
| `whoami /priv` | Enumerate privileges assigned to the current access token |
| `whoami /groups` | Enumerate group memberships |
| `ipconfig` | Examine endpoint network configuration |
| `net user` | Enumerate local user accounts |
| `net localgroup administrators` | Identify members of the local Administrators group |

Multiple discovery commands were intentionally executed within short periods to create behavioral patterns for detection and investigation rather than relying on a single command.

The generated activity produced Sysmon process-creation telemetry that was ingested into Microsoft Sentinel and used for KQL detection development and SOC investigation practice.

---

## SOC Investigation

### Initial Triage

One investigated discovery burst contained four discovery commands executed within approximately **18 seconds**:

```text
whoami
   ↓ ~4 seconds
net user
   ↓ ~10 seconds
ipconfig
   ↓ ~4 seconds
net localgroup administrators
```

The rapid sequence warranted investigation because multiple discovery utilities executed in close succession can occur during post-compromise reconnaissance.

Timing alone, however, was not treated as proof that the processes were related or malicious.

### Process Ancestry Analysis

Sysmon Event ID 1 telemetry was used to examine:

- `Image`
- `CommandLine`
- `User`
- `ParentImage`
- `ProcessGuid`
- `ParentProcessGuid`

All four discovery processes shared the same `ParentProcessGuid`, and their `ParentImage` was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This provided direct process-level correlation showing that the discovery commands originated from the same PowerShell parent process.

The reconstructed activity was:

```text
explorer.exe
└── powershell.exe
    ├── whoami.exe
    ├── net.exe user
    ├── ipconfig.exe
    └── net.exe localgroup administrators
```

The common PowerShell parent was stronger correlation evidence than temporal proximity alone.

### Supporting Telemetry

After reconstructing the discovery activity, additional telemetry was reviewed to determine whether supporting evidence increased suspicion.

| Telemetry | Investigation Result |
|---|---|
| **Sysmon 3 — Network Connection** | No suspicious network connection attributable to the investigated PowerShell discovery activity was identified. A separate Defender connection was observed but was not attributed to the discovery process. |
| **Sysmon 10 — Process Access** | Process-access activity was reviewed. No observed activity materially increased suspicion of the discovery sequence. |
| **Sysmon 11 — File Create** | No relevant file creation was identified that could be confidently attributed to the discovery sequence. |
| **Sysmon 13 — Registry Value Set** | BAM-related PowerShell registry activity was reviewed. No suspicious persistence-related modification attributable to the discovery activity was identified. |
| **PowerShell 4104** | Available script-block telemetry was reviewed for additional PowerShell context. No script-block evidence materially increased suspicion of the investigated discovery sequence. |
| **Windows 4624** | An interactive logon (`LogonType 2`) for `socanalyst` provided supporting user-session context. |

The absence of a supporting event was **not treated as proof of benign activity**. Conclusions were limited by the telemetry collected by the configured Sysmon rules and Data Collection Rules.

During later telemetry validation, known test activity was successfully observed end-to-end for Sysmon Event ID 1, Sysmon Event ID 13, and PowerShell Event ID 4104. A previous controlled test also successfully generated Sysmon Event ID 11 telemetry. File-creation monitoring uses selective filtering, so the absence of Event ID 11 cannot be interpreted as proof that no file was created.

---

## MITRE ATT&CK Mapping

The observed discovery behaviors were mapped to MITRE ATT&CK.

| Activity | MITRE ATT&CK Technique |
|---|---|
| `whoami` | T1033 — System Owner/User Discovery |
| `ipconfig` | T1016 — System Network Configuration Discovery |
| `net user` | T1087.001 — Account Discovery: Local Account |
| `net localgroup administrators` | T1069.001 — Permission Groups Discovery: Local Groups |

Additional controlled testing also included privilege and group discovery commands. MITRE ATT&CK mapping was used to explain why the observed behaviors could be relevant during a SOC investigation, not to establish that the activity was malicious.

---

## Analyst Verdict

**Verdict: Benign / Expected Test Activity**

### Analyst Assessment

The discovery burst warranted investigation because several native Windows discovery utilities executed within approximately 18 seconds from the same PowerShell parent process.

Process relationships established through `ProcessGuid` and `ParentProcessGuid` provided stronger correlation than timing alone.

Supporting telemetry was reviewed for suspicious network communication, process access, file creation, registry modification, PowerShell activity, and authentication context. The available evidence did not identify follow-on behavior that materially increased suspicion.

Based on the telemetry available to the analyst, the activity was assessed as **Benign / Expected Test Activity**.

### Ground Truth

After the analyst assessment, the conclusion was compared with the known ground truth of the lab.

The discovery activity had been intentionally generated under the `SOC-WIN11\socanalyst` account as part of the controlled SOC exercise.

Separating ground truth from the analyst assessment prevents the known origin of the test activity from becoming the primary justification for the verdict.

### What Would Have Increased Suspicion?

The case would have required further investigation or escalation if supporting evidence had included:

- an unexpected or suspicious parent process;
- encoded or obfuscated PowerShell;
- suspicious external network communication associated with the process lineage;
- unexpected file or payload creation;
- registry modification consistent with persistence;
- credential-access behavior;
- an unexpected user or authentication context; or
- additional suspicious activity correlated through process ancestry.

---

## Key Findings and Lessons Learned

- A burst of discovery commands can justify investigation without independently establishing malicious activity.
- Four commands occurring within approximately 18 seconds provided temporal correlation, while the shared `ParentProcessGuid` established a stronger process relationship.
- `ProcessGuid` and `ParentProcessGuid` are valuable for reconstructing process ancestry and correlating related endpoint activity.
- Detection logic should be tested against actual telemetry rather than assumptions about how command-line fields will appear.
- The initial KQL query produced a false negative because the `net.exe` filter did not match the actual telemetry. Examining raw events allowed the logic to be corrected.
- Negative evidence must be interpreted in the context of telemetry coverage. The absence of an event does not prove that an action did not occur.
- Ground truth should be separated from analyst reasoning when evaluating controlled security simulations.
- MITRE ATT&CK techniques describe behavior; they do not by themselves establish malicious intent.

---

## Future Improvements

The current discovery-burst detection counts distinct executable images using `dcount(Image)`. This creates a limitation because one executable can represent multiple discovery behaviors.

For example:

- `net user` and `net localgroup administrators` both execute through `net.exe`.
- `whoami` and `whoami /priv` both execute through `whoami.exe`.

A future version could normalize command lines into behavioral categories before aggregation. This would allow the detection to count distinct discovery behaviors rather than only distinct executable images.

The current detection also uses fixed two-minute time bins. Activity occurring near the boundary between two bins could be separated even when the commands occurred close together. A future version could evaluate a rolling time window or another correlation strategy.

Additional improvements could correlate discovery activity with subsequent suspicious network connections, file creation, registry modifications, PowerShell activity, or other endpoint telemetry associated with the same user, endpoint, or process lineage.

Before production use, the detection would also require broader validation against positive, negative, repeated-command, formatting-variation, and boundary test cases.
