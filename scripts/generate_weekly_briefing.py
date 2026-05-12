#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/generate_weekly_briefing.py
# Extracted from weekly-analyst-briefing.yml v148.0 (RULE 5 compliance)
# Generates weekly threat intelligence briefing JSON from manifest.
# =============================================================================
import sys
import os
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.getcwd())

manifest_path = "data/stix/feed_manifest.json"
os.makedirs("data/weekly_briefings", exist_ok=True)

if not os.path.exists(manifest_path):
    print("No manifest found. Skipping briefing.")
    sys.exit(0)

try:
    with open(manifest_path, encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    print(f"WARN: Could not read manifest: {e}. Skipping briefing.")
    sys.exit(0)

# v75.1 FIX: Handle both flat list and v70 dict envelope
entries = raw if isinstance(raw, list) else raw.get("advisories", raw.get("entries", []))

# Filter to last 7 days
cutoff = datetime.now(timezone.utc) - timedelta(days=7)
recent = []
for e in entries:
    try:
        ts_str = e.get("generated_at") or e.get("timestamp") or ""
        if ts_str:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts >= cutoff:
                recent.append(e)
        else:
            recent.append(e)
    except Exception:
        recent.append(e)

# Generate briefing summary
week = datetime.now(timezone.utc).strftime("W%V-%Y")
critical = [e for e in recent if e.get("severity") == "CRITICAL"]
high = [e for e in recent if e.get("severity") == "HIGH"]
kev_hits = [e for e in recent if e.get("kev_present")]

briefing = {
    "week": week,
    "period": (
        f"{(datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')} "
        f"to {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    ),
    "total_advisories": len(recent),
    "critical_count": len(critical),
    "high_count": len(high),
    "kev_count": len(kev_hits),
    "avg_risk_score": round(
        sum(float(e.get("risk_score", 0)) for e in recent) / max(len(recent), 1), 2
    ),
    "top_threats": sorted(
        recent, key=lambda x: float(x.get("risk_score", 0)), reverse=True
    )[:5],
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "platform": "CYBERDUDEBIVASH SENTINEL APEX",
}

briefing_path = f"data/weekly_briefings/briefing-{week}.json"
tmp_path = briefing_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(briefing, f, indent=2)
os.replace(tmp_path, briefing_path)

print(f"Weekly Briefing {week}:")
print(f"  Total advisories: {briefing['total_advisories']}")
print(f"  Critical:         {briefing['critical_count']}")
print(f"  High:             {briefing['high_count']}")
print(f"  KEV confirmed:    {briefing['kev_count']}")
print(f"  Avg risk score:   {briefing['avg_risk_score']}")
print(f"  Saved: {briefing_path}")
