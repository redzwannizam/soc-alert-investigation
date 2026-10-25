# SOC Alert Investigation and Incident Response Report

## 1. Executive Summary

A simulated Windows workstation investigation identified several
security events requiring further review. These included repeated
failed logon attempts, a suspicious process execution chain, a new
service installation, and a cleared Security audit log.

The available evidence raises suspicion of potentially malicious
activity. However, the dataset does not establish that a compromise
occurred. Further validation is required.

## 2. Investigation Scope

- Host: WS-01
- Dataset: sample_security_events.json
- Total events reviewed: 9
- Event IDs: 4624, 4625, 4688, 4697, 1102
- Data type: Synthetic security-event records
- Initial severity: Medium, pending further investigation

## 3. Key Findings

### Finding 1: Repeated Failed Logons

Three failed logon events (Event ID 4625) targeted the administrator
account from 192.168.1.88 between 09:12:04 and 09:12:15.

Assessment:
Repeated failures may indicate account guessing or another
authentication problem. The available records do not establish
whether a successful compromise followed.

### Finding 2: Suspicious Process Execution

At 09:14:20, PowerShell was recorded as a child of WINWORD.EXE.
At 09:15:03, rundll32.exe was recorded as a child of PowerShell.

Assessment:
This process chain warrants investigation because Office applications
launching scripting tools can occur during malicious document activity.
However, the records lack command-line arguments, file paths, hashes,
and network telemetry needed to establish malicious execution.

### Finding 3: New Service Installation

At 09:17:41, a service named UpdaterService was recorded as installed
(Event ID 4697).

Assessment:
Services can provide persistence, but this record alone does not prove
that the service is unauthorized or malicious. Its executable path,
configuration, signer, and installation context must be verified.

### Finding 4: Security Audit Log Cleared

At 09:20:11, an audit-log-clearing event (Event ID 1102) was recorded.

Assessment:
Clearing the Security audit log can reduce available investigation
evidence and warrants prompt review. The actor and reason are not
established by the supplied record.

## 4. Initial Timeline

| Time | Event | Observation |
|---|---|---|
| 09:00:12 | 4624 | Successful logon |
| 09:12:04–09:12:15 | 4625 | Three failed administrator logons |
| 09:14:20 | 4688 | Word launches PowerShell |
| 09:15:03 | 4688 | PowerShell launches Rundll32 |
| 09:17:41 | 4697 | UpdaterService installed |
| 09:20:11 | 1102 | Security audit log cleared |
| 09:30:00 | 4624 | Successful logon |

All times are from the simulated dataset. The relationship between
the events has not been independently verified.

## 5. Recommended Response

1. Preserve available logs and supporting evidence.
2. Review the process command lines, executable paths, file hashes,
   signatures, and associated network connections.
3. Validate UpdaterService against approved software and service records.
4. Investigate the failed logons and determine whether any account
   was successfully accessed from the same source.
5. Review other available endpoint and authentication logs around
   the relevant timestamps.
6. If malicious activity is corroborated, follow the organization's
   incident-response process for containment, eradication, and recovery.

## 6. Evidence Gaps

- No process command-line arguments or executable hashes.
- No service binary path or service configuration.
- No authentication details beyond the supplied event summaries.
- No network telemetry or corroborating endpoint alerts.
- No evidence establishing the actor responsible for clearing the log.

## 7. Conclusion

The synthetic evidence contains multiple suspicious indicators and
justifies continued investigation. The appropriate current conclusion
is possible malicious activity, not confirmed compromise.

The initial severity is Medium for this exercise and should be
reassessed against organizational criteria as additional evidence
becomes available.

## 8. Dataset Disclaimer

This report analyzes synthetic data created for a cybersecurity
portfolio exercise. It does not describe a confirmed real-world
security incident.

## 9. MITRE ATT&CK Mapping

The following mappings are preliminary behavioral hypotheses.
They do not confirm that an adversary performed these actions.

| Evidence | Technique | Assessment |
|---|---|---|
| Repeated failed logons | T1110 - Brute Force | Candidate; insufficient evidence to confirm |
| Word-to-PowerShell execution | T1059.001 - PowerShell | Candidate; malicious execution unconfirmed |
| Security audit log cleared | T1070.001 - Clear Windows Event Logs | Behavioral match; intent unconfirmed |
| Service installation | Unassigned | More evidence needed |

Reference: https://attack.mitre.org/techniques/T1110/
Reference: https://attack.mitre.org/techniques/T1059/001/
Reference: https://attack.mitre.org/techniques/T1070/001/

