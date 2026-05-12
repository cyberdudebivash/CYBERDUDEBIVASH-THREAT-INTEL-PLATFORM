#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/run_weekly_ai_predictions.py
# Extracted from weekly-analyst-briefing.yml v148.0 (RULE 5 compliance)
# Runs AI predictive analysis on weekly threat data.
# =============================================================================
import sys
import os
import json

sys.path.insert(0, os.getcwd())

os.makedirs("data/weekly_briefings", exist_ok=True)

try:
    from agent.ai.predictive_models import PredictiveIntelligenceEngine

    manifest_path = "data/stix/feed_manifest.json"
    if not os.path.exists(manifest_path):
        print("AI analysis skipped: no manifest found.")
        sys.exit(0)

    with open(manifest_path, encoding="utf-8") as f:
        raw = json.load(f)
    entries = raw if isinstance(raw, list) else raw.get("advisories", raw.get("entries", []))
    entries = entries[:20]

    engine = PredictiveIntelligenceEngine()
    summary = engine.generate_executive_summary(entries)
    summary_path = "data/weekly_briefings/ai_executive_summary.json"
    tmp_path = summary_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    os.replace(tmp_path, summary_path)

    print(f"AI Executive Summary generated: {summary_path}")
    print(f"  Avg exploit probability: {summary.get('avg_exploit_probability', 0)}%")
    print(f"  Sectors at risk: {summary.get('sectors_at_risk', [])}")
    print(f"  Max financial exposure: {summary.get('max_financial_formatted', 'N/A')}")
except Exception as e:
    print(f"AI analysis skipped (non-critical): {e}")
    sys.exit(0)
