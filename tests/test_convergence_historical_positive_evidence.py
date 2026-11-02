"""Hermetic Phase 5 release-governance regression: denied-only history is not proof.

The production publisher #120 (2026-11-02) reported 0/0 historical
reports accessible and five expected publication denials, yet awarded
Phase 5 PASS and 100/100 convergence. No live requests or paid services.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deployment_convergence_validator as dcv  # noqa: E402


def _run(monkeypatch, probes, urls=None):
    urls = urls or [
        f"https://intel.cyberdudebivash.com/reports/2026/10/intel--{i:024x}.html"
        for i in range(len(probes))
    ]
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *a: ([], urls))
    monkeypatch.setattr(
        dcv, "_probe_batch",
        lambda *a: (probes, sum(p.success for p in probes),
                    sum(not p.success for p in probes)),
    )
    monkeypatch.setattr(
        dcv, "_http_probe",
        lambda *a, **kw: pytest.fail("No network probe permitted"),
    )
    return dcv.phase5_historical_report_audit([], {})


def _probe(i, *, delivered=False, denied=False):
    return dcv.ProbeResult(
        url=f"https://intel.cyberdudebivash.com/reports/2026/10/intel--{i:024x}.html",
        status_code=200 if delivered else 404,
        latency_ms=1.0,
        success=delivered or denied,
        gate_rejected=denied,
    )


def test_all_five_expected_denials_cannot_certify_history(monkeypatch):
    result = _run(monkeypatch, [_probe(i, denied=True) for i in range(5)])
    assert result.success is False
    assert len(result.probes) == 5
    assert "0/0 historical reports accessible (0%)" in result.message
    assert "5 excluded as expected publication-gate rejections" in result.message
    assert "HISTORICAL POSITIVE EVIDENCE MISSING" in result.message


def test_mixed_delivered_and_gate_denied_history_passes(monkeypatch):
    result = _run(monkeypatch, [_probe(1, delivered=True), _probe(2, denied=True)])
    assert result.success is True
    assert "1/1 historical reports accessible (100%)" in result.message
    assert "PASS" in result.message


def test_incomplete_probe_cohort_still_fails(monkeypatch):
    result = _run(
        monkeypatch,
        [_probe(1, delivered=True)],
        urls=[_probe(1).url, _probe(2).url],
    )
    assert result.success is False
    assert "1 unprobed" in result.message


def test_actual_unavailable_historical_report_still_fails(monkeypatch):
    result = _run(monkeypatch, [_probe(1, delivered=True), _probe(2)])
    assert result.success is False
    assert "HISTORICAL VERIFICATION INCOMPLETE" in result.message
