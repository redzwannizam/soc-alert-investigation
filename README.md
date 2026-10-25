# SOC Alert Investigation & Incident Response

A hands-on blue team portfolio project demonstrating security log
analysis, Python-based detection rules, incident investigation, and
MITRE ATT&CK mapping using a synthetic Windows security-event dataset.

## Project Objectives

- Analyze Windows-style security events.
- Identify suspicious authentication and process activity.
- Detect potential service installation and audit-log clearing.
- Generate a chronological investigation timeline.
- Automate alert generation using Python.
- Document findings, limitations, and response recommendations.

## Tools and Technologies

- Python
- PowerShell
- JSON and CSV
- Git and GitHub
- MITRE ATT&CK

## Project Structure

```text
SOC-Alert-Investigation/
├── dataset/
│   └── sample_security_events.json
├── evidence/
│   ├── detection_alerts.csv
│   ├── investigation_timeline.csv
│   └── mitre_attack_mapping.csv
├── reports/
│   └── incident_report.md
├── scripts/
│   ├── detect_suspicious_activity.py
│   └── test_detection.py
├── screenshots/
└── README.md
```

## Investigation Scenario

A simulated Windows workstation contains several events requiring
investigation:

- Repeated failed logons targeting an administrator account.
- Microsoft Word launching PowerShell.
- A subsequent Rundll32 process launch.
- Installation of a service named UpdaterService.
- Clearing of the Windows Security audit log.

These observations are suspicious, but they do not independently
prove that a compromise occurred.

## Detection Rules

| Rule | Description | Initial Severity |
|---|---|---|
| DET-001 | Three or more failed logons for the same account and source IP within five minutes | Medium |
| DET-002 | Office application launches PowerShell | High |
| DET-003 | Service installation event observed | Medium |
| DET-004 | Security audit log cleared | High |

The severity values are preliminary lab classifications, not universal
severity ratings. Real deployments require tuning and contextual analysis.

## How to Run

Requirements: Python 3.10 or later.

From the project root, run:

```powershell
python .\scripts\detect_suspicious_activity.py
```

The script reads the synthetic JSON dataset and generates:

`evidence/detection_alerts.csv`

To validate expected detection outputs, run:

```powershell
python .\scripts\test_detection.py
```

The basic validation test checks for four expected rules and four
alerts. It does not measure detection accuracy or false-positive rates.

## Investigation Workflow

1. Load and inspect the security-event dataset.
2. Review failed logons and process creation events.
3. Investigate the service installation and audit-log clearing.
4. Build a chronological evidence timeline.
5. Map supported behaviors to potential MITRE ATT&CK techniques.
6. Generate alerts automatically with Python.
7. Validate expected outputs.
8. Document findings and recommended response actions.

## Key Findings

The synthetic dataset generated four alerts:

- Repeated failed logons.
- Office application launching PowerShell.
- Service installation.
- Security audit log clearing.

These alerts identify behaviors for further investigation. They do not
confirm an attacker, successful compromise, persistence, or data theft.

## MITRE ATT&CK References

- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

These are preliminary behavioral mappings. Additional evidence is
required to determine whether the observed activity was malicious.

## Limitations and Future Improvements

- Use real Windows event exports from an authorized lab.
- Add tests for benign activity and detection threshold boundaries.
- Improve event correlation and time-window handling.
- Add command-line, process-path, and file-hash analysis.
- Introduce configurable severity and allowlisting.
- Evaluate false positives and false negatives.
- Consider integration with a SIEM such as Wazuh.

## Disclaimer

This project uses synthetic security-event data for educational and
portfolio purposes. It does not represent a confirmed real-world
incident and is not a production-ready security monitoring system.
