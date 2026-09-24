"""
ONE freshness threshold, ONE canonical contract, MULTIPLE consumers (P0 Phase 3E).

master-deployment-orchestrator.yml Gate 2 carried its own
`MAX_MANIFEST_AGE_HOURS: 6` and, when generated_at failed to parse, fell back
to age "0" -> reported FRESH. Gate 2 now runs
scripts/orchestrator_manifest_freshness.py, which classifies with
scripts/public_freshness_contract.py (config/public_freshness_contract.json).
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import orchestrator_manifest_freshness as omf  # noqa: E402
import public_freshness_contract as pfc  # noqa: E402

WF = REPO / ".github" / "workflows" / "master-deployment-orchestrator.yml"
CONTRACT_H = json.loads((REPO / "config" / "public_freshness_contract.json").read_text())["max_public_manifest_age_hours"]


def _body(delta: timedelta | None = None, raw: str | None = None) -> str:
    if raw is None:
        raw = (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps({"generated_at": raw, "count": 1, "items": [{"id": "x"}]})


def test_orchestrator_defines_no_freshness_threshold_of_its_own():
    src = WF.read_text(encoding="utf-8")
    assert not re.search(r"^\s*MAX_MANIFEST_AGE_HOURS\s*:", src, re.MULTILINE)
    assert "env.MAX_MANIFEST_AGE_HOURS" not in src
    assert "python3 scripts/orchestrator_manifest_freshness.py" in src


def test_no_workflow_redefines_a_manifest_age_threshold():
    offenders = []
    for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        for m in re.finditer(r"^\s*(MAX_(?:PUBLIC_)?MANIFEST_AGE_HOURS)\s*:\s*\S+", wf.read_text(encoding="utf-8"), re.MULTILINE):
            offenders.append(f"{wf.name}: {m.group(0).strip()}")
    assert not offenders, offenders


@pytest.mark.parametrize("delta,expected", [
    (timedelta(minutes=10), "true"),
    (timedelta(hours=CONTRACT_H) - timedelta(minutes=1), "true"),
    (timedelta(hours=CONTRACT_H) + timedelta(minutes=1), "stale"),
    (timedelta(days=29), "stale"),
    (timedelta(hours=-10), "warn"),          # future beyond skew
])
def test_gate2_matches_canonical_classifier(delta, expected):
    assert omf.classify(_body(delta))[0] == expected


@pytest.mark.parametrize("text", ["", "{}", "not json", _body(raw="yesterday"), _body(raw="2026-02-30T00:00:00Z"),
                                  _body(raw="2026-09-24T07:00:00")])  # no offset
def test_unusable_timestamp_is_never_fresh(text):
    # Regression: the old step turned a parse failure into age 0 -> "fresh".
    assert omf.classify(text)[0] == "warn"


def test_threshold_follows_the_contract_not_a_literal(monkeypatch):
    body = _body(timedelta(hours=CONTRACT_H + 1))
    assert omf.classify(body)[0] == "stale"
    monkeypatch.setenv("MAX_PUBLIC_MANIFEST_AGE_HOURS", str(CONTRACT_H + 2))
    assert omf.classify(body)[0] == "true", "Gate 2 must read the contract accessor, not a local 6"


def test_cli_emits_one_github_output_line(tmp_path, capsys):
    f = tmp_path / "latest.json"
    f.write_text(_body(timedelta(minutes=5)))
    assert omf.main(["x", str(f)]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out == ["fresh=true"]
