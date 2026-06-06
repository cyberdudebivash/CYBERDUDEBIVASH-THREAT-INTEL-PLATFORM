#!/usr/bin/env python3
"""
tests/test_mandate_enforcer_log_truthfulness.py — Forensic-audit regression suite

ORIGIN: Forensic production audit of run `sentinel-blogger #1551`.

ROOT CAUSE (verified, traced to source + runtime logs — see
FORENSIC-AUDIT-REPORT.md, Finding F2 / Observability Finding O1):
`sentinel_apex_mandate_enforcer.run_enforcement()`, when called with
`report_only=True`, logged:

    [MANDATE ENFORCER] ██ DEPLOYMENT BLOCKED ██
    [MANDATE ENFORCER] 274 blocking violations across mandates
    ...
    [REPORT-ONLY] ... Exiting 0 — this run does not gate deployment.

— i.e. it announced, at ERROR severity, that deployment was BLOCKED, on
the exact code path that is GUARANTEED to `return 0` two lines later
(that is this flag's documented purpose: "--report  Report only — do
not block deployment"). Same data, contradictory framing, in the same
breath. This is "governance theater": a real finding, computed
correctly, presented in a way that actively misleads readers about
its consequence — and trains them to distrust ERROR-level output
generally, including the times it's reporting something that DOES
block deployment.

MANDATE: These tests pin down the truthfulness contract directly:
  - `report_only=True` must NEVER claim "DEPLOYMENT BLOCKED" — it
    cannot block anything, by the flag's own definition — and must
    return 0.
  - `report_only=False` (audit / enforce mode) must continue to log
    "DEPLOYMENT BLOCKED" at ERROR and return a non-zero code, so a
    real block is never silently downgraded either.
  - The VIOLATION COUNTS reported in both modes must be identical —
    because only the framing should change here, never the substance.

These tests run `run_enforcement()` against a fully isolated, synthetic
feed (no dependency on the real api/feed.json or its current contents),
with the mandate-check functions stubbed to return a deterministic,
known violation set — so the assertions are about LOGGING TRUTHFULNESS
and RETURN-CODE CONTRACTS only, not about today's feed quality.
"""

import json
import logging
import os
import sys

import pytest

# ── Ensure scripts/ is importable (matches tests/test_severity_governance_p0.py) ──
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import sentinel_apex_mandate_enforcer as enforcer  # noqa: E402

MandateViolation = enforcer.MandateViolation
LOGGER_NAME = "sentinel.mandate"   # matches `log = logging.getLogger("sentinel.mandate")`

# Number of synthetic *blocking* violations we'll inject (mandate=1, which is
# != 6, so it lands in `blocking_violations` — exactly like the 274 in #1551).
SYNTHETIC_VIOLATION_COUNT = 7


def _synthetic_violations(n=SYNTHETIC_VIOLATION_COUNT):
    return [
        MandateViolation(
            mandate=1,
            item_id=f"synthetic-{i:03d}",
            title=f"Synthetic test item {i}",
            description="Injected by test_mandate_enforcer_log_truthfulness for "
                        "deterministic, isolated exercise of run_enforcement().",
            risk="HIGH",
            remediation="N/A — test fixture",
            auto_fixable=False,
        )
        for i in range(n)
    ]


@pytest.fixture
def isolated_repo(tmp_path, monkeypatch):
    """Point the enforcer at a throwaway repo root with a minimal, valid feed,
    and stub every check_mandate_* function so `run_enforcement` is exercised
    end-to-end (real code, real control flow, real logging) without touching
    the real api/feed.json or depending on its current contents."""
    api_dir = tmp_path / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    feed_path = api_dir / "feed.json"
    feed_path.write_text(json.dumps([
        {"id": "synthetic-001", "title": "Synthetic feed item one",
         "source_url": "https://example.com/a", "source_name": "Example",
         "severity": "LOW", "trust_score": 7.0,
         "retrieval_timestamp": "2026-01-01T00:00:00Z",
         "publication_timestamp": "2026-01-01T00:00:00Z"},
        {"id": "synthetic-002", "title": "Synthetic feed item two",
         "source_url": "https://example.com/b", "source_name": "Example",
         "severity": "LOW", "trust_score": 7.0,
         "retrieval_timestamp": "2026-01-01T00:00:00Z",
         "publication_timestamp": "2026-01-01T00:00:00Z"},
    ], indent=2), encoding="utf-8")

    report_out = tmp_path / "data" / "health" / "mandate_enforcement_report.json"

    monkeypatch.setattr(enforcer, "REPO_ROOT", tmp_path, raising=True)
    monkeypatch.setattr(enforcer, "REPORT_OUT", report_out, raising=True)

    # Deterministic stand-ins for the eight mandate checks `run_enforcement`
    # calls directly. Only mandate 1 produces violations (and mandate != 6,
    # so they are *blocking* — the same shape as run #1551's 274).
    monkeypatch.setattr(enforcer, "check_mandate_1",  lambda items: _synthetic_violations())
    monkeypatch.setattr(enforcer, "check_mandate_3",  lambda items: [])
    monkeypatch.setattr(enforcer, "check_mandate_4",  lambda items: [])
    monkeypatch.setattr(enforcer, "check_mandate_6",  lambda repo_root: [])
    monkeypatch.setattr(enforcer, "check_mandate_7",  lambda items: [])
    monkeypatch.setattr(enforcer, "check_mandate_8",  lambda items: [])
    monkeypatch.setattr(enforcer, "check_mandate_9",  lambda items: [])
    monkeypatch.setattr(enforcer, "check_mandate_10", lambda items: [])
    monkeypatch.setattr(enforcer, "check_mandate_11", lambda items: [])

    return {"tmp_path": tmp_path, "feed_path": feed_path, "report_out": report_out}


def _messages_at(records, levelno):
    return [r.getMessage() for r in records if r.levelno == levelno]


# ─────────────────────────────────────────────────────────────────────────────
# The core truthfulness contract: report_only must never cry "BLOCKED"
# ─────────────────────────────────────────────────────────────────────────────

def test_report_only_never_claims_deployment_blocked(isolated_repo, caplog):
    """This is the literal #1551 log contradiction, pinned down as a test.

    Pre-fix, this exact scenario (blocking_violations > 0, report_only=True)
    produced an ERROR-level "██ DEPLOYMENT BLOCKED ██" line immediately
    before the guaranteed `return 0` — telling the reader the opposite of
    what the code was about to do. Post-fix, the report-only path must
    describe its own findings as advisory/non-blocking, at WARNING (not
    ERROR) severity, and must say nothing implying deployment is blocked.
    """
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        rc = enforcer.run_enforcement(fix_mode=False, report_only=True)

    assert rc == 0, (
        "report_only=True is documented as 'do not block deployment' — it "
        "must always return 0 regardless of how many violations it finds."
    )

    all_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "DEPLOYMENT BLOCKED" not in all_text, (
        "report_only=True logged 'DEPLOYMENT BLOCKED' while guaranteed to "
        "return 0 — this is the exact self-contradiction from run #1551 "
        "('██ DEPLOYMENT BLOCKED ██' / '274 blocking violations' immediately "
        "followed by 'Exiting 0'). A run that cannot block deployment must "
        "never claim that it has."
    )

    error_messages = _messages_at(caplog.records, logging.ERROR)
    assert not any("BLOCKED" in m for m in error_messages), (
        f"report_only mode logged ERROR-severity message(s) implying a "
        f"block: {error_messages!r}. Advisory findings on a non-blocking "
        f"path must be logged at WARNING, not ERROR — ERROR must be "
        f"reserved for things that actually stop deployment, or readers "
        f"learn (correctly, from bitter experience) to ignore it."
    )

    warning_messages = _messages_at(caplog.records, logging.WARNING)
    assert any("advisory" in m.lower() and "not enforced" in m.lower()
               for m in warning_messages), (
        f"Expected a WARNING-level message describing the violations as "
        f"advisory/non-blocking (matching the --report flag's actual "
        f"effect). Got WARNING messages: {warning_messages!r}"
    )
    assert any(str(SYNTHETIC_VIOLATION_COUNT) in m for m in warning_messages), (
        f"Expected the advisory WARNING to report the actual violation "
        f"count ({SYNTHETIC_VIOLATION_COUNT}) — the fix must change *framing* "
        f"only, never suppress or alter the underlying finding. "
        f"Got: {warning_messages!r}"
    )


def test_enforce_mode_still_blocks_and_says_so(isolated_repo, caplog):
    """The flip side of the contract: a run that CAN gate deployment
    (report_only=False) must still loudly say so when it finds blocking
    violations, at ERROR severity, with a non-zero return code. The P2
    fix must change *only* the report-only framing — never weaken the
    real enforcement path's signal or its exit code.
    """
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        rc = enforcer.run_enforcement(fix_mode=False, report_only=False)

    assert rc == 1, (
        "Non-fix, non-report-only run with blocking violations must "
        "return 1 (the documented 'violations found' code)."
    )

    error_messages = _messages_at(caplog.records, logging.ERROR)
    assert any("DEPLOYMENT BLOCKED" in m for m in error_messages), (
        f"Enforcement-mode runs with real blocking violations must still "
        f"log 'DEPLOYMENT BLOCKED' at ERROR — this is the one path where "
        f"that claim is TRUE. Got ERROR messages: {error_messages!r}"
    )
    assert any(str(SYNTHETIC_VIOLATION_COUNT) in m for m in error_messages), (
        f"The ERROR-level summary must report the actual violation count "
        f"({SYNTHETIC_VIOLATION_COUNT}). Got: {error_messages!r}"
    )


def test_fix_mode_with_violations_returns_2(isolated_repo, caplog):
    """Exit-code matrix completeness: fix_mode=True + unresolved blocking
    violations must return 2 (distinct from the plain-audit '1'), exactly
    as documented in run_enforcement's own docstring
    ('2 = violations after fix attempt'). The P2 fix touches only log
    framing — this pins down that the return-code matrix itself is
    untouched and intact."""
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        rc = enforcer.run_enforcement(fix_mode=True, report_only=False)
    assert rc == 2, (
        "fix_mode=True with remaining blocking violations must return 2 "
        "('violations after fix attempt'), not 1 — callers (e.g. CI "
        "workflow conditionals keyed on exit code) distinguish these."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Cross-mode consistency: only the FRAMING may differ, never the SUBSTANCE
# ─────────────────────────────────────────────────────────────────────────────

def test_violation_counts_identical_across_report_only_and_enforce_modes(
        isolated_repo, caplog, monkeypatch):
    """The whole point of the P2 fix is that report_only changes how a
    finding is FRAMED, never what is FOUND. Run the exact same synthetic
    feed through both modes and assert the reported violation counts are
    byte-identical — proving the fix didn't (and a future edit shouldn't)
    quietly start suppressing or padding findings based on the flag."""

    caplog.set_level(logging.INFO, logger=LOGGER_NAME)

    caplog.clear()
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        rc_report = enforcer.run_enforcement(fix_mode=False, report_only=True)
    report_text = "\n".join(r.getMessage() for r in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        rc_enforce = enforcer.run_enforcement(fix_mode=False, report_only=False)
    enforce_text = "\n".join(r.getMessage() for r in caplog.records)

    assert rc_report == 0
    assert rc_enforce == 1

    # Both modes must surface the SAME total violation count somewhere in
    # their output — substance constant, only framing (and exit code) changes.
    needle = f"{SYNTHETIC_VIOLATION_COUNT} "
    assert any(needle in line for line in report_text.splitlines()
               if "violations" in line.lower()), (
        f"report-only output never mentions the {SYNTHETIC_VIOLATION_COUNT} "
        f"injected violations:\n{report_text}"
    )
    assert any(needle in line for line in enforce_text.splitlines()
               if "violations" in line.lower()), (
        f"enforce-mode output never mentions the {SYNTHETIC_VIOLATION_COUNT} "
        f"injected violations:\n{enforce_text}"
    )


def test_report_artifact_written_and_substantively_identical(isolated_repo):
    """The persisted JSON report (data/health/mandate_enforcement_report.json)
    is what downstream tooling and dashboards actually read — not the log
    stream. Assert it's written in both modes and that its substantive
    content (violation totals, per-mandate breakdown, deployment_approved)
    is identical aside from the `mode` label itself. This guarantees the
    log-truthfulness fix has zero effect on the actual audit artifact."""
    report_path = isolated_repo["report_out"]

    rc1 = enforcer.run_enforcement(fix_mode=False, report_only=True)
    assert report_path.exists(), "Expected report JSON to be written in report-only mode"
    report_only_doc = json.loads(report_path.read_text(encoding="utf-8"))

    rc2 = enforcer.run_enforcement(fix_mode=False, report_only=False)
    assert report_path.exists(), "Expected report JSON to be written in audit mode"
    audit_doc = json.loads(report_path.read_text(encoding="utf-8"))

    assert rc1 == 0 and rc2 == 1

    for key in ("total_items", "total_violations", "violations_by_mandate",
                "violations_by_risk", "mandate_compliance", "deployment_approved"):
        assert report_only_doc[key] == audit_doc[key], (
            f"Report field `{key}` differs between report_only and audit "
            f"modes ({report_only_doc[key]!r} vs {audit_doc[key]!r}) — the "
            f"persisted artifact's substance must be mode-independent; "
            f"only `mode` itself should differ."
        )

    assert report_only_doc["mode"] == "report_only"
    assert audit_doc["mode"] == "audit"
    assert report_only_doc["total_violations"] == SYNTHETIC_VIOLATION_COUNT


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
