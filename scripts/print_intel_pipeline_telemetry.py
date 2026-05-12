#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/print_intel_pipeline_telemetry.py
# Extracted from enterprise-intel-quality.yml Print Pipeline Telemetry (RULE 5)
# Reads pipeline report and prints structured telemetry summary.
# =============================================================================
import json
from pathlib import Path

report_path = Path("data/intelligence/pipeline_report.json")
if report_path.exists():
    try:
        with open(report_path, encoding="utf-8") as f:
            r = json.load(f)
        print("=" * 60)
        print("SENTINEL APEX Enterprise Pipeline Summary")
        print(f"Status:       {r.get('status', 'N/A')}")
        print(f"Pipeline ID:  {r.get('pipeline_id', 'N/A')}")
        print(f"Duration:     {r.get('total_ms', '?')}ms")
        print(f"Advisories:   {r.get('advisories_in', '?')}")
        print(f"Rollback:     {r.get('rollback_taken', '?')}")
        print("Steps:")
        for s in r.get("steps", []):
            icon = "OK" if s["status"] == "SUCCESS" else "FAIL"
            print(f"  [{icon}] {s['step_name']}: {s['status']} ({s['duration_ms']}ms)")
        print("=" * 60)
    except Exception as e:
        print(f"[TELEMETRY] Could not parse pipeline report: {e}")
else:
    print("[TELEMETRY] No pipeline report found -- pipeline may not have run yet")

ioc_mem = Path("data/threat_memory/ioc_memory.json")
if ioc_mem.exists():
    try:
        with open(ioc_mem, encoding="utf-8") as f:
            d = json.load(f)
        print(f"IOC Memory: {d.get('total_iocs', '?')} total IOCs tracked")
    except Exception:
        pass

conf_path = Path("data/intelligence/explainable_confidence_scores.json")
if conf_path.exists():
    try:
        with open(conf_path, encoding="utf-8") as f:
            d = json.load(f)
        print(f"Mean Confidence: {d.get('mean_confidence', '?')}%")
        print(f"Tier Distribution: {d.get('tier_distribution', '?')}")
    except Exception:
        pass
