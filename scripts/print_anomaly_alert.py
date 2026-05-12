#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/print_anomaly_alert.py
# Extracted from storage-governance.yml (RULE 5 compliance)
# Reads anomaly report and triggers alert if anomalies detected.
# =============================================================================
import json
import pathlib
import sys

ar_path = pathlib.Path("data/telemetry/anomaly_report.json")
if not ar_path.exists():
    print("[ANOMALY] No anomaly report found -- platform nominal")
    sys.exit(0)

try:
    ar = json.loads(ar_path.read_text(encoding="utf-8"))
except Exception as e:
    print(f"[ANOMALY] Could not parse anomaly report: {e}")
    sys.exit(0)

if ar.get("total_anomalies", 0) > 0:
    print(f"[ANOMALY] {ar['total_anomalies']} anomalies detected -- alerting ops")
    for a in ar.get("anomalies", []):
        print(f"  [{a.get('severity', 'UNKNOWN')}] {a.get('type', '')} {a.get('endpoint', '')}")
else:
    print("[ANOMALY] No anomalies -- platform nominal")
