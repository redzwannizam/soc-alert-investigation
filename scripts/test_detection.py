import csv
import sys
from pathlib import Path

project_dir = Path(__file__).resolve().parent.parent
alerts_file = project_dir / "evidence" / "detection_alerts.csv"

expected_rules = {"DET-001", "DET-002", "DET-003", "DET-004"}

if not alerts_file.exists():
    print("FAIL: Detection output not found. Run the detection script first.")
    sys.exit(1)

with alerts_file.open("r", encoding="utf-8-sig", newline="") as file:
    alerts = list(csv.DictReader(file))

actual_rules = {alert["rule"] for alert in alerts}
missing_rules = expected_rules - actual_rules

if missing_rules:
    print(f"FAIL: Missing expected rules: {sorted(missing_rules)}")
    sys.exit(1)

if len(alerts) != 4:
    print(f"FAIL: Expected 4 alerts, found {len(alerts)}")
    sys.exit(1)

print("PASS: All four expected detection rules generated alerts.")
print(f"PASS: Total alerts = {len(alerts)}")
print("Note: This validates expected outputs, not false-positive performance.")
