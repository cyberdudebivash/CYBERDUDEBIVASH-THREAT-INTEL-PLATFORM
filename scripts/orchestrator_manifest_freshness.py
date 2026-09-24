#!/usr/bin/env python3
"""
scripts/orchestrator_manifest_freshness.py -- master-deployment-orchestrator
Gate 2 (warning-only manifest freshness).

Classifies a downloaded /api/v1/intel/latest.json with the ONE canonical
freshness contract (scripts/public_freshness_contract.py ->
config/public_freshness_contract.json). The workflow used to carry its own
MAX_MANIFEST_AGE_HOURS: 6 and treat an unparseable timestamp as age 0, i.e.
FRESH.

stdout: exactly one GITHUB_OUTPUT line, `fresh=true|stale|warn` (the values
the orchestrator summary already consumes). Diagnostics go to stderr.
Always exits 0: Gate 2 is a warning gate; STAGE 5.9.10 is the hard gate.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_freshness_contract as pfc  # noqa: E402


def classify(body_text: str) -> tuple[str, str]:
    """-> (output value, human message)."""
    try:
        body = json.loads(body_text) if body_text.strip() else {}
    except ValueError:
        body = {}
    raw = body.get("generated_at") if isinstance(body, dict) else None
    r = pfc.classify_manifest_freshness(raw)
    limit_h = r["max_age_seconds"] / 3600
    if r["state"] == pfc.FRESH:
        return "true", f"Manifest fresh: {r['age_seconds'] / 3600:.1f}h old (limit {limit_h:g}h)"
    if r["state"] == pfc.STALE:
        return "stale", f"WARNING: Manifest is {r['age_seconds'] / 3600:.1f}h old (limit {limit_h:g}h)"
    return "warn", f"WARNING: generated_at {r['state']} ({raw!r})"


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else None
    text = path.read_text(encoding="utf-8", errors="replace") if path and path.exists() else ""
    value, msg = classify(text)
    print(f"[GATE 2] {msg}", file=sys.stderr)
    print(f"fresh={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
