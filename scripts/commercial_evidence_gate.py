#!/usr/bin/env python3
"""Offline, fail-closed CTI commercial evidence gate. Never calls network or Cloudflare."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = ("chronology", "publication", "delivery", "entitlement", "revocation",
            "publisher_cycles", "security", "cloudflare_budget", "payment")


def evaluate(evidence):
    defects = []
    if not isinstance(evidence, dict):
        return {"verdict": "NO_GO", "production_go": False,
                "defects": ["Evidence must be an object"]}
    for name in REQUIRED:
        item = evidence.get(name)
        if not isinstance(item, dict) or item.get("passed") is not True:
            defects.append(f"{name}: missing or not explicitly passed")
            continue
        if not isinstance(item.get("reference"), str) or not item["reference"].strip():
            defects.append(f"{name}: missing evidence reference")
        timestamp = item.get("verified_at")
        try:
            if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
                raise ValueError()
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if dt.tzinfo is None or dt > datetime.now(timezone.utc):
                raise ValueError()
        except ValueError:
            defects.append(f"{name}: invalid UTC verification timestamp")
    candidates = evidence.get("report_candidates")
    ready = evidence.get("customer_ready")
    if type(candidates) is not int or candidates < 1:
        defects.append("Invalid report candidate count")
    if type(ready) is not int or ready < 1:
        defects.append("No certified customer-ready reports")
    if type(candidates) is int and type(ready) is int and ready > candidates:
        defects.append("Customer-ready count exceeds report candidates")
    return {"verdict": "NO_GO" if defects else "EVIDENCE_PRECHECK_ONLY",
            "defects": defects, "production_go": False,
            "note": "Never authorizes merge, deployment, payment capture or customer release"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.evidence.stat().st_size > 1_000_000:
            raise ValueError("Oversized evidence")
        result = evaluate(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (OSError, ValueError, UnicodeError) as exc:
        result = {"verdict": "NO_GO", "production_go": False,
                  "defects": [f"Unreadable evidence: {type(exc).__name__}"]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "EVIDENCE_PRECHECK_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
