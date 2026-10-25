import json
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET = BASE_DIR / "dataset" / "sample_security_events.json"
OUTPUT = BASE_DIR / "evidence" / "detection_alerts.csv"

with DATASET.open("r", encoding="utf-8-sig") as file:
    events = json.load(file)

alerts = []

def add_alert(timestamp, host, rule, severity, description, evidence):
    alerts.append({
        "timestamp": timestamp,
        "host": host,
        "rule": rule,
        "severity": severity,
        "description": description,
        "evidence": evidence,
    })

# Rule 1: Repeated failed logons from the same source
failed_groups = defaultdict(list)

for event in events:
    if event.get("event_id") == 4625:
        key = (event.get("host"), event.get("username"), event.get("source_ip"))
        failed_groups[key].append(event)

for (host, username, source_ip), group in failed_groups.items():
    group.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))

    for start in range(len(group)):
        window = [
            event for event in group[start:]
            if (
                datetime.fromisoformat(event["timestamp"])
                - datetime.fromisoformat(group[start]["timestamp"])
            ).total_seconds() <= 300
        ]

        if len(window) >= 3:
            add_alert(
                window[-1]["timestamp"],
                host,
                "DET-001",
                "Medium",
                "Three or more failed logons within five minutes",
                f"Account={username}; SourceIP={source_ip}; Count={len(window)}",
            )
            break

# Rule 2: Office application launches PowerShell
office_apps = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

for event in events:
    parent = (event.get("parent_process") or "").lower()
    process = (event.get("process") or "").lower()

    if parent in office_apps and process == "powershell.exe":
        add_alert(
            event["timestamp"],
            event.get("host", ""),
            "DET-002",
            "High",
            "Office application launched PowerShell",
            f"Parent={event['parent_process']}; Process={event['process']}",
        )

# Rule 3: Service installation
for event in events:
    if event.get("event_id") == 4697:
        add_alert(
            event["timestamp"],
            event.get("host", ""),
            "DET-003",
            "Medium",
            "New service installation observed",
            f"Service={event.get('process')}",
        )

# Rule 4: Security audit log cleared
for event in events:
    if event.get("event_id") == 1102:
        add_alert(
            event["timestamp"],
            event.get("host", ""),
            "DET-004",
            "High",
            "Security audit log cleared",
            event.get("details", ""),
        )

alerts.sort(key=lambda alert: alert["timestamp"])

with OUTPUT.open("w", newline="", encoding="utf-8") as file:
    fields = [
        "timestamp", "host", "rule", "severity",
        "description", "evidence"
    ]
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(alerts)

print(f"Events analyzed: {len(events)}")
print(f"Alerts generated: {len(alerts)}")
print(f"Alert report: {OUTPUT}")

for alert in alerts:
    print(
        f"[{alert['severity']}] {alert['rule']} | "
        f"{alert['timestamp']} | {alert['description']}"
    )
