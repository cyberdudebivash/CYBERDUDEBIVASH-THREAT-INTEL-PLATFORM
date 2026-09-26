#!/usr/bin/env python3
"""
scripts/openphish_source_link_guard.py
SENTINEL APEX -- OpenPhish source links (STAGE 1-3c)

Production 2026-09-26T08:04Z: 47 of 50 OpenPhish items published the live
phishing URL as their source_url (the other 3 were blanked by a blogspot
filter), so every "source" link and the evidence chain's "Source URL
verified" line sent customers to an active phishing site.

The ingestor (scripts/true_intel_ingestor.py) now writes the OpenPhish feed
as the source and repairs the manifest it merges into. This step repairs the
publisher's own copies right after the orchestrator -- before the evidence
chain, reports and R2 uploads read them -- using the same function
(repair_openphish_source_links). Items of other feeds are untouched.
Exit code is always 0.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from stale_source_guard import TARGET_PATHS, _items_of  # noqa: E402
from true_intel_ingestor import repair_openphish_source_links  # noqa: E402


def guard_file(path: Path) -> int:
    if not path.exists():
        return 0
    raw = json.loads(path.read_text(encoding="utf-8").rstrip("\x00"))
    items, _ = _items_of(raw)
    if not items:
        return 0
    changed = repair_openphish_source_links(items)
    if changed:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(raw, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        tmp.replace(path)
    return changed


def main() -> int:
    for rel in TARGET_PATHS:
        try:
            n = guard_file(REPO_ROOT / rel)
            print(f"[OPENPHISH-SOURCE] {rel}: {n} source link(s) repaired")
        except Exception as exc:  # never fail the pipeline
            print(f"[OPENPHISH-SOURCE] {rel}: skipped ({exc})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
