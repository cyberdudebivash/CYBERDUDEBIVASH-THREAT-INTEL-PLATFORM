#!/usr/bin/env python3
"""
scripts/capability_registry_gate.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Capability Classification + Placeholder
Regression CI Gate

WHY THIS EXISTS
----------------
data/quality/frontend_capability_registry.json (built by
scripts/build_capability_registry.py) is the platform's canonical
CUSTOMER_UI / API_ONLY / ADMIN / INTERNAL / DEPRECATED classification for
every top-level *.html page. A registry nobody enforces drifts the moment
a new page is added and nobody remembers to classify it -- exactly the
"backend engines existed without customer UI, and nobody noticed for
months" failure mode this repo's own P34-P38 forensic history (see
scripts/capability_coverage_audit.py's docstring) already lived through
once for backend routes. This script is the frontend-page half of closing
that loop permanently, per CLAUDE.md's mandatory CI regression guard
requirement.

TWO REAL GATES, BOTH BLOCKING (unlike the observability-only
frontend_api_coverage_gate.py and capability_coverage_audit.py this script
sits alongside and reuses data from -- see "non-blocking by design" in
their own docstrings for why those stayed soft launches. This script is
deliberately narrower than either, which is what makes it safe to be hard):

  GATE 1 -- Unclassified page
    Every top-level *.html file must have a matching entry in
    frontend_capability_registry.json's `entries` array. A new page with
    no entry fails CI immediately -- "classify it or don't ship it" is a
    much cheaper conversation at PR time than a customer finding an
    orphan dashboard six months later. Fails closed: an unrecognized file
    is a blocker, not a warning.

  GATE 2 -- Placeholder regression
    A CUSTOMER_UI page whose registry status is "live" (this platform's
    own term for "genuinely calls the API, per
    frontend_api_coverage_report.json's fetch()+/api/ literal heuristic")
    must STILL be dynamic on the current commit. A page that regresses
    from live to static -- e.g. someone reverts a fetch() call while
    editing unrelated markup, or a merge conflict resolution drops the
    <script src> that made it dynamic -- is caught here before it reaches
    production. This is the "narrowly scoped regression protection against
    transformed production pages reverting to static placeholders" the
    mission text asks for by name. Scope is deliberately narrow: it only
    ever fires for a page this repo has ALREADY certified as live (a
    concrete, previously-observed regression), never for a page that was
    always static or was always an untouched orphan -- so it cannot block
    unrelated work the way a broad "all pages must be dynamic" gate would.

WHAT THIS DOES NOT DO
----------------------
- Does not re-derive dynamic/static classification itself -- reads
  data/quality/frontend_api_coverage_report.json (regenerate it first via
  scripts/frontend_api_coverage_gate.py, which CI already runs one stage
  earlier in sentinel-apex.yml -- Single Source of Truth, this script
  is not a second heuristic).
- Does not classify NEW capabilities on its own. A human (or a future
  PR) adding a page must also add a data/quality/frontend_capability_registry.json
  entry -- this script only checks that one exists, per this repo's own
  CLAUDE.md "NEVER ... Invent" instruction.
- Does not gate backend routes -- scripts/capability_coverage_audit.py
  (observability-only, unchanged by this script) covers that surface.

USAGE
-----
    python3 scripts/frontend_api_coverage_gate.py   # regenerate the coverage report first
    python3 scripts/capability_registry_gate.py
    python3 scripts/capability_registry_gate.py --json   # machine-readable only

Exit code 0 = both gates pass. Exit code 1 = at least one blocking finding.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "data" / "quality" / "frontend_capability_registry.json"
COVERAGE_REPORT_PATH = REPO_ROOT / "data" / "quality" / "frontend_api_coverage_report.json"


def evaluate(registry: dict, coverage: dict, actual_pages: list[str]) -> dict:
    """Pure evaluation of both gates given already-loaded registry/coverage
    JSON and the current list of top-level *.html filenames on disk. No I/O --
    kept separate from main() so tests can exercise gate logic directly
    against constructed fixtures instead of writing real files to disk."""
    registry_ids = {e["id"] for e in registry["entries"]}
    valid_categories = set(registry["taxonomy"])
    actual_set = set(actual_pages)

    # GATE 1: every top-level *.html file on disk right now has a registry entry.
    unclassified = [p for p in sorted(actual_set) if p not in registry_ids]

    # Also catch a malformed registry entry (missing/unknown category) --
    # a page "classified" with a typo'd category is functionally unclassified.
    malformed = [
        e["id"] for e in registry["entries"]
        if e.get("category") not in valid_categories
    ]

    # GATE 2: placeholder regression -- registry says "live", current coverage
    # report disagrees.
    dynamic_now = {p["file"] for p in coverage.get("dynamic_pages", [])}
    live_in_registry = [e["id"] for e in registry["entries"] if e.get("status") == "live"]
    regressed = sorted(p for p in live_in_registry if p not in dynamic_now and p in actual_set)

    findings = []
    if unclassified:
        findings.append({
            "gate": "unclassified_page",
            "severity": "BLOCKER",
            "pages": unclassified,
            "detail": (
                "These top-level *.html pages have no entry in "
                "data/quality/frontend_capability_registry.json. Classify each as "
                "CUSTOMER_UI / API_ONLY / ADMIN / INTERNAL / DEPRECATED in "
                "scripts/build_capability_registry.py's CLASSIFICATIONS dict "
                "(or let it fall through to 'dynamic' / 'allowlisted-static' "
                "if that's genuinely what it is) and re-run "
                "scripts/build_capability_registry.py before merging."
            ),
        })
    if malformed:
        findings.append({
            "gate": "malformed_classification",
            "severity": "BLOCKER",
            "pages": malformed,
            "detail": f"Registry entries with a category outside {sorted(valid_categories)}.",
        })
    if regressed:
        findings.append({
            "gate": "placeholder_regression",
            "severity": "BLOCKER",
            "pages": regressed,
            "detail": (
                "These pages are recorded in the capability registry as 'live' "
                "(genuinely calling the platform's own API) but no longer show "
                "as dynamic in the current frontend_api_coverage_report.json run. "
                "A previously-fixed page appears to have regressed to static/"
                "placeholder content -- restore its live API call(s) before merging, "
                "or if this was an intentional deprecation, update its registry "
                "entry's status via scripts/build_capability_registry.py."
            ),
        })

    return {
        "schema_version": "1",
        "gates": ["unclassified_page", "malformed_classification", "placeholder_regression"],
        "total_pages_on_disk": len(actual_pages),
        "total_registry_entries": len(registry["entries"]),
        "unclassified_count": len(unclassified),
        "customer_ui_orphan_count": registry.get("customer_ui_orphan_count", 0),
        "findings": findings,
        "passed": len(findings) == 0,
    }


def main() -> int:
    json_only = "--json" in sys.argv

    if not REGISTRY_PATH.exists():
        print(f"[FATAL] {REGISTRY_PATH.relative_to(REPO_ROOT)} does not exist. "
              f"Run scripts/build_capability_registry.py first.")
        return 1
    if not COVERAGE_REPORT_PATH.exists():
        print(f"[FATAL] {COVERAGE_REPORT_PATH.relative_to(REPO_ROOT)} does not exist. "
              f"Run scripts/frontend_api_coverage_gate.py first.")
        return 1

    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    coverage = json.loads(COVERAGE_REPORT_PATH.read_text(encoding="utf-8"))
    actual_pages = sorted(p.name for p in REPO_ROOT.glob("*.html"))

    result = evaluate(registry, coverage, actual_pages)
    findings = result["findings"]

    if json_only:
        print(json.dumps(result, indent=2))
        return 0 if result["passed"] else 1

    print("=" * 70)
    print("CAPABILITY REGISTRY GATE -- classification + placeholder regression")
    print("=" * 70)
    print(f"Pages on disk:            {result['total_pages_on_disk']}")
    print(f"Registry entries:         {result['total_registry_entries']}")
    print(f"Unclassified:             {result['unclassified_count']}  (target: 0)")
    print(f"Known CUSTOMER_UI orphans: {result['customer_ui_orphan_count']}  (tracked, non-blocking)")
    if findings:
        print("\nBLOCKING FINDINGS:")
        for f in findings:
            print(f"  [{f['severity']}] {f['gate']}: {', '.join(f['pages'][:10])}"
                  f"{' (+' + str(len(f['pages']) - 10) + ' more)' if len(f['pages']) > 10 else ''}")
            print(f"    {f['detail']}")
        print(f"\nFAIL -- {len(findings)} blocking finding(s).")
    else:
        print("\nPASS -- every page classified, no placeholder regressions.")
    print("=" * 70)

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
