#!/usr/bin/env python3
"""
tests/test_public_freshness_contract.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- single-source-of-truth guard for
customer-visible intelligence freshness.

Same timestamp + same MAX_PUBLIC_MANIFEST_AGE_HOURS must produce the same
classification everywhere:
  * scripts/public_freshness_contract.py (R2 upload guard, release gate)
  * workers/intel-gateway/src/freshness-contract.js (/api/health)
Both are run against config/public_freshness_contract_vectors.json here, and
every constant is compared against config/public_freshness_contract.json.
"""
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import public_freshness_contract as contract  # noqa: E402
import r2_upload  # noqa: E402

CONTRACT = json.loads((REPO / "config/public_freshness_contract.json").read_text(encoding="utf-8"))
VECTORS = json.loads((REPO / "config/public_freshness_contract_vectors.json").read_text(encoding="utf-8"))
JS_MODULE = REPO / "workers/intel-gateway/src/freshness-contract.js"
NOW = datetime.fromisoformat(VECTORS["now"].replace("Z", "+00:00"))


def _js_const(name: str) -> str:
    m = re.search(rf"export const {name} =\s*(.+?);", JS_MODULE.read_text(encoding="utf-8"), re.S)
    assert m, f"{name} not found in {JS_MODULE}"
    return m.group(1).strip()


def test_python_constants_come_from_contract_file():
    assert contract.DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS == CONTRACT["max_public_manifest_age_hours"]
    assert contract.MAX_FUTURE_SKEW_HOURS == CONTRACT["max_future_skew_hours"]
    assert contract.GENERATED_AT_RE.pattern == CONTRACT["generated_at_pattern"]


def test_pr485_upload_guard_uses_the_same_authority():
    assert r2_upload.DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS == CONTRACT["max_public_manifest_age_hours"]
    assert r2_upload.max_public_manifest_age_hours is contract.max_public_manifest_age_hours


def test_report_window_future_skew_matches_contract():
    import generate_intel_reports as gir
    assert gir.DEFAULT_REPORT_FUTURE_SKEW_HOURS == CONTRACT["max_future_skew_hours"]


def test_js_constants_match_contract_file():
    assert float(_js_const("MAX_PUBLIC_MANIFEST_AGE_HOURS")) == CONTRACT["max_public_manifest_age_hours"]
    assert float(_js_const("MAX_FUTURE_SKEW_HOURS")) == CONTRACT["max_future_skew_hours"]
    js_pattern = json.loads("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', _js_const("GENERATED_AT_PATTERN"))).join(['"', '"']))
    assert js_pattern == CONTRACT["generated_at_pattern"]


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_python_classifier_matches_shared_vectors(vector):
    r = contract.classify_manifest_freshness(vector["generated_at"], now=NOW)
    assert (r["state"], r["age_seconds"]) == (vector["state"], vector["age_seconds"])


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed (the gateway node suite runs the same vectors)")
def test_js_classifier_matches_shared_vectors_bit_for_bit():
    script = (
        "import fs from 'node:fs';"
        f"import {{ classifyManifestFreshness }} from '{JS_MODULE.as_uri()}';"
        f"const v = JSON.parse(fs.readFileSync('{(REPO / 'config/public_freshness_contract_vectors.json').as_posix()}','utf8'));"
        "const now = Date.parse(v.now);"
        "console.log(JSON.stringify(v.vectors.map(t => { const r = classifyManifestFreshness(t.generated_at, now); return [t.name, r.state, r.age_seconds]; })));"
    )
    out = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, check=True).stdout
    js = {name: (state, age) for name, state, age in json.loads(out.strip().splitlines()[-1])}
    for v in VECTORS["vectors"]:
        py = contract.classify_manifest_freshness(v["generated_at"], now=NOW)
        assert js[v["name"]] == (py["state"], py["age_seconds"]) == (v["state"], v["age_seconds"]), v["name"]


def test_env_override_is_honoured_and_invalid_values_fall_back(monkeypatch):
    monkeypatch.setenv("MAX_PUBLIC_MANIFEST_AGE_HOURS", "1")
    assert contract.classify_manifest_freshness("2026-09-24T04:30:00Z", now=NOW)["state"] == contract.STALE
    for bad in ("junk", "0", "-5"):
        monkeypatch.setenv("MAX_PUBLIC_MANIFEST_AGE_HOURS", bad)
        assert contract.max_public_manifest_age_hours() == CONTRACT["max_public_manifest_age_hours"]
