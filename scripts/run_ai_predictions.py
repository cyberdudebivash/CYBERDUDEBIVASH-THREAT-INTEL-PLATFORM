#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/run_ai_predictions.py
# Extracted from ai-predictions.yml (RULE 5 compliance)
# Runs AI predictive models on latest feed manifest.
# Exit 0 = OK (even on prediction error - non-critical) | Exit 1 = fatal
# =============================================================================
import sys
import os
import json
from datetime import datetime, timezone

sys.path.insert(0, os.getcwd())

os.makedirs("data/ai_predictions", exist_ok=True)

manifest_path = "data/stix/feed_manifest.json"
if not os.path.exists(manifest_path):
    print("No manifest found. AI predictions skipped.")
    sys.exit(0)

try:
    with open(manifest_path, encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    print(f"Could not read manifest: {e}. AI predictions skipped.")
    sys.exit(0)

# v75.1 FIX: Handle both flat list and v70 dict envelope
entries = raw if isinstance(raw, list) else raw.get("advisories", raw.get("entries", []))
print(f"Processing {len(entries)} manifest entries...")

try:
    from agent.ai.predictive_models import PredictiveIntelligenceEngine

    engine = PredictiveIntelligenceEngine()
    enriched = engine.enrich_manifest(entries)
    summary = engine.generate_executive_summary(entries)
    top_risks = engine.get_top_risks(entries, top_n=5)

    output = {
        "executive_summary": summary,
        "top_5_risks": [
            {
                "title": e.get("title", ""),
                "severity": e.get("severity", ""),
                "risk_score": e.get("risk_score", 0),
                "triage_score": e.get("ai_predictions", {}).get("triage", {}).get("triage_score", 0),
                "exploit_probability": e.get("ai_predictions", {}).get("exploit_probability", {}).get("exploit_probability_pct", 0),
                "financial_exposure": e.get("ai_predictions", {}).get("financial_impact", {}).get("loss_range_label", "N/A"),
                "primary_sector": e.get("ai_predictions", {}).get("industry_impact", {}).get("primary_sector", "N/A"),
            }
            for e in top_risks
        ],
        "model_version": "v24.0",
        "entries_scored": len(enriched),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    output_path = "data/ai_predictions/latest.json"
    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    os.replace(tmp_path, output_path)

    print(f"\n[OK] AI Predictions Complete:")
    print(f"   Entries scored: {output['entries_scored']}")
    print(f"   Critical threats: {summary['critical_threat_count']}")
    print(f"   Avg exploit prob: {summary['avg_exploit_probability']}%")
    print(f"   Max financial exposure: {summary['max_financial_formatted']}")
    print(f"   Sectors at risk: {', '.join(summary['sectors_at_risk'])}")
    print(f"\n   Top 5 Risks:")
    for i, risk in enumerate(output["top_5_risks"], 1):
        print(
            f"   {i}. [{risk['severity']}] {risk['title'][:55]}... "
            f"| Triage: {risk['triage_score']}/100 | Prob: {risk['exploit_probability']}%"
        )

except Exception as e:
    print(f"AI predictions failed (non-critical): {e}")
    import traceback
    traceback.print_exc()
    # Non-critical: exit 0 so pipeline continues
    sys.exit(0)
