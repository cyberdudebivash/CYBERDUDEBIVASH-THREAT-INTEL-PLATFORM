"""
STAGE 5.8.1c ran 28 minutes (2026-09-26T05:27 -> 05:55, run 36218583926).

Phases 2-4 of scripts/deployment_convergence_validator.py retried report URLs
the Worker 404s on purpose (publication gate: customer_ready false) for 8
rounds each with backoff up to 180s; Phase 5 already knew those were not
failures. The probes also tripped the site's rate limit (429) and treated it
as permanent. These tests drive the real phase functions with a fake network
and a fake clock.
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import deployment_convergence_validator as dcv  # noqa: E402

BASE = dcv.PAGES_BASE_URL
REJECTED = [f"{BASE}/reports/2026/09/intel--{c * 24}.html" for c in "ab"]
OK_REPORTS = [f"{BASE}/reports/2026/09/intel--{c * 24}.html" for c in "cdefghijklmno"]
MANIFEST = {"files": {u[len(BASE) + 1:]: {} for u in REJECTED + OK_REPORTS}}


class FakeNet:
    def __init__(self, status):
        self.status = status          # url -> int or list of ints (per call)
        self.calls = []

    def probe(self, url, timeout=None):
        self.calls.append(url)
        st = self.status.get(url, 200)
        if isinstance(st, list):
            st = st.pop(0) if len(st) > 1 else st[0]
        ok = st in (200, 401)
        return dcv.ProbeResult(url=url, status_code=st, latency_ms=1.0, success=ok,
                               is_transient=(st >= 500 or st == 429),
                               error=None if ok else f"HTTPError {st}")


@pytest.fixture
def clock():
    slept = []
    with patch.object(dcv.time, "sleep", side_effect=lambda s: slept.append(s)):
        yield slept


def _run(net, rejected=frozenset(REJECTED)):
    dcv._GATE_VERDICTS.clear()
    with patch.object(dcv, "_http_probe", side_effect=net.probe), \
         patch.object(dcv, "_is_expected_publication_rejection", side_effect=lambda u: u in rejected):
        return (dcv.phase2_cdn_readiness_probe([], MANIFEST),
                dcv.phase3_incremental_retry([], MANIFEST),
                dcv.phase4_convergence_confirmation([], MANIFEST))


def _sort_first(urls):
    # _extract_report_urls sorts manifest paths; the sample is the newest 15.
    return sorted(urls)


def test_gate_rejected_404s_do_not_stall_the_stage(clock):
    net = FakeNet({u: 404 for u in REJECTED})
    p2, p3, p4 = _run(net)
    assert p2.success and p3.success and p4.success
    # Phase 4's fixed 30s gap between confirmation passes is by design.
    backoff = [s for s in clock if s > 30]
    assert backoff == [], f"backoff waits on a healthy deployment: {backoff}"
    assert sum(clock) < 120, sum(clock)
    assert any(r.gate_rejected for r in p3.probes)


def test_before_the_fix_the_same_deployment_took_over_20_minutes(clock):
    """Negative control: without the gate verdict, the same responses cost
    Phase 2+3 the backoff schedule that ran in production."""
    net = FakeNet({u: 404 for u in REJECTED})
    with patch.object(dcv, "PERMANENT_STOP_ROUND", 99):
        _run(net, rejected=frozenset())
    assert sum(clock) > 20 * 60, sum(clock)


def test_gate_verdict_is_asked_once_per_url(clock):
    net = FakeNet({u: 404 for u in REJECTED})
    asked = []
    dcv._GATE_VERDICTS.clear()
    with patch.object(dcv, "_http_probe", side_effect=net.probe), \
         patch.object(dcv, "_is_expected_publication_rejection",
                      side_effect=lambda u: asked.append(u) or u in REJECTED):
        dcv.phase2_cdn_readiness_probe([], MANIFEST)
        dcv.phase3_incremental_retry([], MANIFEST)
        dcv.phase4_convergence_confirmation([], MANIFEST)
    assert sorted(asked) == sorted(set(asked))


def test_429_is_transient_and_retried(clock):
    target = _sort_first(REJECTED + OK_REPORTS)[-1]
    net = FakeNet({target: [429, 200]})
    p2, p3, _ = _run(net, rejected=frozenset())
    assert p3.success
    first = next(r for r in p3.probes + p2.probes if r.url == target and r.status_code == 429)
    assert first.is_transient


def test_http_probe_classifies_429_as_transient():
    import urllib.error
    err = urllib.error.HTTPError("https://x", 429, "Too Many Requests", {}, None)
    with patch.object(dcv.urllib.request, "urlopen", side_effect=err):
        r = dcv._http_probe("https://x")
    assert r.status_code == 429 and not r.success and r.is_transient


def test_genuinely_missing_report_still_fails_but_stops_retrying(clock):
    missing = _sort_first(REJECTED + OK_REPORTS)[-1]
    net = FakeNet({missing: 404})
    p2, p3, _ = _run(net, rejected=frozenset())
    assert not any(r.success for r in p3.probes if r.url == missing)
    rounds = sum(1 for u in net.calls if u == missing)
    # Phase 2 (5-URL sample) + Phase 3 stop after PERMANENT_STOP_ROUND+1 rounds each.
    assert rounds <= 2 * (dcv.PERMANENT_STOP_ROUND + 1) + 3 * dcv.CONFIRM_RUNS


def test_phase5_still_excludes_gate_rejections_from_continuity():
    extra = [f"{BASE}/reports/2026/08/intel--{c * 24}.html" for c in "pqrstu"]
    manifest = {"files": {u[len(BASE) + 1:]: {} for u in REJECTED + OK_REPORTS + extra}}
    hist = sorted(REJECTED + OK_REPORTS + extra)[:dcv.HIST_PROBE_COUNT]
    net = FakeNet({hist[0]: 404, hist[1]: 404})
    dcv._GATE_VERDICTS.clear()
    with patch.object(dcv, "_http_probe", side_effect=net.probe), \
         patch.object(dcv, "_is_expected_publication_rejection", side_effect=lambda u: u == hist[0]), \
         patch.object(dcv.time, "sleep"):
        p5 = dcv.phase5_historical_report_audit([], manifest)
    total = len(hist) - 1
    assert f"{total - 1}/{total} historical reports accessible" in p5.message
    assert "1 excluded as expected publication-gate rejections" in p5.message


def test_workflow_timeout_unchanged_budget_is_a_ceiling_not_a_schedule():
    wf = (REPO / ".github" / "workflows" / "sentinel-blogger.yml").read_text(encoding="utf-8")
    assert "timeout 1680 python3 scripts/deployment_convergence_validator.py" in wf
