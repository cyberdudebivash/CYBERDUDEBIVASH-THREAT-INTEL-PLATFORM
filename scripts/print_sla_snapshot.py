#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/print_sla_snapshot.py
# Extracted from enterprise-alerts.yml (RULE 5 compliance)
# Reads SLA status JSON and prints alert summary.
# =============================================================================
import json
import pathlib
import sys

sla_path = pathlib.Path("data/health/sla_status.json")
if not sla_path.exists():
    print("[SLA] No SLA status file -- skipping snapshot")
    sys.exit(0)

try:
    sla = json.loads(sla_path.read_text(encoding="utf-8"))
    score = sla.get("sla_evaluation", {}).get("sla_score", 100)
    grade = sla.get("sla_evaluation", {}).get("grade", "A")
    violations = sla.get("sla_evaluation", {}).get("violations", [])
    print(f"[SLA] Score: {score}/100  Grade: {grade}  Violations: {len(violations)}")
    if grade in ("C", "D"):
        print(f"[SLA] WARNING: SLA grade {grade} -- alerting ops team")
except Exception as e:
    print(f"[SLA] Could not parse SLA status: {e}")
    sys.exit(0)
