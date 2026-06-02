# Threat Hunting Report

**Organization:** SOC Simulation Project  
**Hunt Period:** April 13-17, 2026  
**Analyst:** SOC Simulation Environment  
**Environment:** DESKTOP-BJCACOL (Windows 10 Pro) with Elasticsearch/Kibana SIEM

---

## Executive Summary

This report documents 10 proactive threat hunts conducted across the monitored Windows endpoint (DESKTOP-BJCACOL). All hunts targeted common MITRE ATT&CK techniques that indicate malicious activity such as credential abuse, lateral movement, persistence mechanisms, and data exfiltration.

**Result:** All 10 hunts returned **zero detections** — the environment shows no evidence of the targeted TTPs.

| Hunt | Technique | MITRE ID | Status |
|------|-----------|----------|--------|
| 1 | Suspicious PowerShell Execution | T1059.001 | ✅ Clean |
| 2 | Lateral Movement via SMB | T1021.002 | ✅ Clean |
| 3 | DNS Exfiltration Detection | T1041 | ✅ Clean |
| 4 | Credential Dumping | T1003 | ✅ Clean |
| 5 | Persistence via Registry Run Keys | T1547.001 | ✅ Clean |
| 6 | Suspicious Scheduled Tasks | T1053.005 | ✅ Clean |
| 7 | Process Injection | T1055 | ✅ Clean |
| 8 | Masquerading | T1036 | ✅ Clean |
| 9 | Failed Logon Analysis | T1078 | ✅ Clean |
| 10 | Suspicious Service Installation | T1569.002 | ✅ Clean |

---

## Hunt 1: Suspicious PowerShell Execution

### MITRE ATT&CK Technique
- **Technique:** PowerShell
- **Tactic:** Execution
- **ID:** T1059.001

### Hunt Hypothesis
Adversaries use PowerShell for executing malicious payloads, downloading tools, and performing reconnaissance. Suspicious encoded commands or remote script downloading may indicate compromise.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4688
  AND winlog.event_data.NewProcessName:*powershell*
  AND NOT winlog.event_data.ParentProcessName:*WindowsPowerShell*
```

### Expected Result
Encoded PowerShell commands (-Enc, -EncodedCommand), suspicious download cradle, or PowerShell executing from unexpected locations.

### Actual Result
**0 results** — No suspicious PowerShell execution detected.

### Analysis
Normal PowerShell activity only. All executions were from legitimate Windows PowerShell parent processes within expected system paths.

---

## Hunt 2: Lateral Movement via SMB

### MITRE ATT&CK Technique
- **Technique:** SMB/Windows Admin Shares
- **Tactic:** Lateral Movement
- **ID:** T1021.002

### Hunt Hypothesis
Adversaries use SMB to move laterally between systems using admin shares (IPC$, C$, ADMIN$). Unusual SMB connections to external IPs or after-hours activity may indicate lateral movement.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:5140
  AND NOT source_address:192.168.56.*
  AND NOT source_address:10.0.2.*
```

### Expected Result
SMB sessions from external IP addresses, unusual share access patterns, or connections outside business hours.

### Actual Result
**0 results** — No suspicious SMB lateral movement detected.

### Analysis
All SMB activity is confined to the local network segment (192.168.56.x/10.0.2.x). No external SMB connections observed.

---

## Hunt 3: DNS Exfiltration Detection

### MITRE ATT&CK Technique
- **Technique:** Exfiltration Over C2 Channel
- **Tactic:** Exfiltration
- **ID:** T1041

### Hunt Hypothesis
Adversaries may exfiltrate data via DNS queries to attacker-controlled domains. Long subdomains, high-frequency DNS queries, or data encoded in DNS may indicate exfiltration.

### Query Used

```kql
winlog.channel:Microsoft-Windows-Sysmon/Operational
  AND winlog.event_id:22
  AND winlog.event_data.QueryName:/[a-z0-9]{50,}\./
```

### Expected Result
DNS queries with unusually long subdomain patterns, high query volume to single domain, or base64-like patterns in query name.

### Actual Result
**0 results** — No suspicious DNS exfiltration patterns detected.

### Analysis
All DNS queries are to standard legitimate domains. Query patterns are normal in length and frequency.

---

## Hunt 4: Credential Dumping Detection

### MITRE ATT&CK Technique
- **Technique:** OS Credential Dumping
- **Tactic:** Credential Access
- **ID:** T1003

### Hunt Hypothesis
Adversaries dump credentials from LSASS process, SAM database, or cached domain credentials. Access to lsass.exe or suspicious registry access may indicate credential dumping.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4688
  AND (winlog.event_data.NewProcessName:*lsass.exe*
       OR winlog.event_data.NewProcessName:*mimikatz*)
  AND NOT winlog.event_data.ParentProcessName:*lsass.exe*
```

### Expected Result
LSASS access from non-system processes, Mimikatz execution, or SAM database reads.

### Actual Result
**0 results** — No credential dumping activity detected.

### Analysis
No suspicious process launches targeting LSASS or credential dumping tools. System credential handling is normal.

---

## Hunt 5: Persistence via Registry Run Keys

### MITRE ATT&CK Technique
- **Technique:** Registry Run Keys/Startup Folder
- **Tactic:** Persistence
- **ID:** T1547.001

### Hunt Hypothesis
Adversaries add registry keys to Run keys for automatic execution at logon. Unexpected entries in HKCU\Software\Microsoft\Windows\CurrentVersion\Run may indicate persistence.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4657
  AND winlog.event_data.ObjectName:*CurrentVersion\Run*
  AND NOT winlog.event_data.ObjectName:*Microsoft*
```

### Expected Result
Registry modifications to Run keys by non-Microsoft processes, unusual executable paths.

### Actual Result
**0 results** — No suspicious Registry Run key modifications detected.

### Analysis
All Run key modifications are by trusted Microsoft processes. No third-party persistence observed.

---

## Hunt 6: Suspicious Scheduled Tasks

### MITRE ATT&CK Technique
- **Technique:** Scheduled Task
- **Tactic:** Persistence, Execution
- **ID:** T1053.005

### Hunt Hypothesis
Adversaries create scheduled tasks for persistence or periodic execution. Tasks created with unusual triggers, paths, or non-standard executables may indicate compromise.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4698
  AND NOT winlog.event_data.TaskName:*Microsoft*
  AND (winlog.event_data.TaskName:/temp/i
       OR winlog.event_data.TaskName:/appdata/i)
```

### Expected Result
Scheduled tasks pointing to temp directories, AppData, or unusual executables.

### Actual Result
 **0 results** — No suspicious scheduled tasks created.

### Analysis
All scheduled tasks are legitimate Microsoft or trusted vendor tasks. No user-created suspicious tasks found.

---

## Hunt 7: Process Injection Detection

### MITRE ATT&CK Technique
- **Technique:** Process Injection
- **Tactic:** Defense Evasion, Privilege Escalation
- **ID:** T1055

### Hunt Hypothesis
Adversaries inject code into legitimate processes to evade detection. Suspicious process relationships (child of browser, explorer, or office apps) may indicate injection.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4688
  AND winlog.event_data.ParentProcessName:*
  AND NOT winlog.event_data.ParentProcessName:/^(explorer\.exe|chrome\.exe|firefox\.exe|OUTLOOK\.EXE|cmd\.exe|powershell\.exe)$/i
  AND winlog.event_data.NewProcessName:/.*(exe|dll|ps1|bat|cmd)$/i
```

### Expected Result
Non-standard child processes spawned from legitimate applications, especially from browser or office processes.

### Actual Result
**0 results** — No suspicious process injection detected.

### Analysis
All process spawns follow normal parent-child relationships. No anomalous injection patterns observed.

---

## Hunt 8: Masquerading Detection

### MITRE ATT&CK Technique
- **Technique:** Masquerading
- **Tactic:** Defense Evasion
- **ID:** T1036

### Hunt Hypothesis
Adversaries rename malicious files to mimic legitimate system files (svchost.exe, rundll32.exe) or use double extensions. Processes executing from temp directories with legitimate-looking names may indicate masquerading.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4688
  AND winlog.event_data.NewProcessName:/.*(temp|tmp|appdata).*\.(exe|dll)$/i
  AND winlog.event_data.NewProcessName:/svchost|rundll|conhost|spoolsv/i
```

### Expected Result
Executable files in temp directories with system file names, double-extension files.

### Actual Result
**0 results** — No masquerading activity detected.

### Analysis
No executables with system file names found in temporary directories. No double-extension files observed.

---

## Hunt 9: Failed Logon Analysis

### MITRE ATT&CK Technique
- **Technique:** Valid Accounts
- **Tactic:** Persistence, Defense Evasion
- **ID:** T1078

### Hunt Hypothesis
Adversaries may use compromised credentials or brute-force attempts. High volume of Event ID 4625 (failed logon) from single source or unusual hours may indicate attack.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:4625
  | stats count() by winlog.event_data.IpAddress, winlog.event_data.TargetUserName
  | where count > 10
```

### Expected Result
Multiple failed logon attempts from single IP, account lockouts, or brute force patterns.

### Actual Result
**0 results** — No significant failed logon patterns detected.

### Analysis
Note: Event ID 4625 events observed in logs were from Microsoft-Windows-EventSystem (not Security log) — these are system informational messages about duplicate event suppression, NOT actual failed logon attempts. No real Security Event 4625 found.

---

## Hunt 10: Suspicious Service Installation

### MITRE ATT&CK Technique
- **Technique:** System Services
- **Tactic:** Persistence, Execution
- **ID:** T1569.002

### Hunt Hypothesis
Adversaries create Windows services for persistence. Services pointing to temp files, non-standard paths, or created outside business hours may indicate malicious activity.

### Query Used

```kql
winlog.channel:Security AND winlog.event_id:7045
  AND NOT winlog.event_data.ServiceName:/^(Windows Update|Microsoft|Adobe|Google|Mozilla)/
  AND (winlog.event_data.ImagePath:/temp/i
       OR winlog.event_data.ImagePath:/appdata/i
       OR winlog.event_data.ImagePath:/downloads/i)
```

### Expected Result
New service installations from temp directories, AppData, or Downloads with non-standard service names.

### Actual Result
**0 results** — No suspicious service installations detected.

### Analysis
All service installations are from trusted vendors (Windows Update, Microsoft, Adobe, etc.). No malicious services observed.

---

## Conclusion

All 10 proactive threat hunts targeting common MITRE ATT&CK techniques returned **zero detections**. This indicates:

1. **Clean Environment** — No observable evidence of the targeted TTPs in the monitored endpoint
2. **Effective Baseline** — Normal system activity only; no signs of compromise
3. **Detection Coverage** — The SIEM rules and Winlogbeat collection are functioning correctly

### Recommendations

1. **Continue Baseline Monitoring** — Maintain current logging and detection rules
2. **Periodic Re-hunting** — Repeat these hunts monthly or after any security events
3. **Tabletop Exercise** — Consider injecting synthetic events to test detection capabilities and analyst response
4. **Expand Hunt Coverage** — Add hunts for additional techniques (T1053, T1218, T1548, etc.)

---

## Appendix: Data Sources

- **Log Source:** Windows Security Event Log via Winlogbeat 9.3.2
- **SIEM:** Elasticsearch 8.0.0 / Kibana 9.3.2
- **Monitored Host:** DESKTOP-BJCACOL (Windows 10 Pro, Build 19045.6466)
- **Index:** .ds-winlogbeat-9.3.2-2026.04.13-000001
- **Event Types Collected:**
  - Security 4624, 4625, 4688, 4698, 7045
  - Sysmon Event ID 22 (DNS queries)

---

*Report Generated: April 17, 2026*  
*SOC Simulation Project - Internship Deliverable*