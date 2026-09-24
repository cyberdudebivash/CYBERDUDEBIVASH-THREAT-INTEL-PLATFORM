#!/usr/bin/env python3
"""
Negative controls for the pinned-clock health/freshness tests.

Each control copies scripts/, tests/ and config/ to a temp directory, applies
ONE deliberate defect, runs the named test files there, and requires them to
FAIL. A control whose defect leaves the tests green means the property is not
really covered, and this script exits 1. The working tree is never modified.

    python3 scripts/health_clock_negative_controls.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = ["tests/test_health_consumer_clock_parity.py", "tests/test_deployment_health_contract.py",
         "tests/test_post_rollback_canary.py"]

CONTROLS = [
    {
        # The original bug: canary A ignores the pinned clock (wall clock).
        "id": "deployment_canary_wall_clock_restored",
        "file": "scripts/deployment_canary.py",
        "find": "    ev = _deploy_health.evaluate_deployment(live, health, now=now)\n",
        "replace": "    ev = _deploy_health.evaluate_deployment(live, health)\n",
    },
    {
        "id": "post_rollback_canary_wall_clock_restored",
        "file": "scripts/post_rollback_canary.py",
        "find": "    hv = dhc.evaluate_health(*health, now=now, expected_version=",
        "replace": "    hv = dhc.evaluate_health(*health, expected_version=",
    },
    {
        "id": "six_hour_threshold_weakened_to_24h",
        "file": "config/public_freshness_contract.json",
        "find": '"max_public_manifest_age_hours": 6,',
        "replace": '"max_public_manifest_age_hours": 24,',
    },
    {
        "id": "boundary_made_exclusive",
        "file": "scripts/public_freshness_contract.py",
        "find": "    state = FRESH if age <= limit_h * 3600 else STALE\n",
        "replace": "    state = FRESH if age < limit_h * 3600 else STALE\n",
    },
]


def run(root: Path) -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *TESTS],
                       cwd=root, capture_output=True, text=True)
    return p.returncode, (p.stdout.strip().splitlines() or [""])[-1]


def stage() -> Path:
    root = Path(tempfile.mkdtemp(prefix="health-neg-"))
    for d in ("scripts", "tests", "config"):
        shutil.copytree(REPO / d, root / d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # tests that shell out to the Worker read these
    for extra in ("workers/intel-gateway/src", ".github/workflows"):
        shutil.copytree(REPO / extra, root / extra, ignore=shutil.ignore_patterns("node_modules"))
    for page in REPO.glob("*.html"):  # status/trust-center pages some tests read
        shutil.copy2(page, root / page.name)
    return root


def main() -> int:
    base = stage()
    code, summary = run(base)
    shutil.rmtree(base, ignore_errors=True)
    if code != 0:
        print(json.dumps({"result": "BASELINE_NOT_GREEN", "summary": summary}, indent=2))
        return 1
    results = []
    for c in CONTROLS:
        root = stage()
        try:
            target = root / c["file"]
            src = target.read_text()
            if c["find"] not in src:
                results.append({"id": c["id"], "status": "MUTATION_ANCHOR_MISSING"})
                continue
            target.write_text(src.replace(c["find"], c["replace"], 1))
            code, summary = run(root)
            results.append({"id": c["id"], "status": "CAUGHT" if code != 0 else "NOT_CAUGHT", "pytest": summary})
        finally:
            shutil.rmtree(root, ignore_errors=True)
    bad = [r for r in results if r["status"] != "CAUGHT"]
    print(json.dumps({"baseline": "green", "controls": len(results), "caught": len(results) - len(bad), "results": results}, indent=2))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
