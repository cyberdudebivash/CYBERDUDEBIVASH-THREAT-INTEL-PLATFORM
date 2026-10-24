"""
STAGE 5.8.1c ran 28 minutes (2026-09-26T05:27 -> 05:55, run 36218583926).

Phases 2-4 of scripts/deployment_convergence_validator.py retried report URLs
the Worker 404s on purpose (publication gate: customer_ready false) for 8
rounds each with backoff up to 180s; Phase 5 already knew those were not
failures. The probes also tripped the site's rate limit (429) and treated it
as permanent. These tests drive the real phase functions with a fake network
and a fake clock.
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import deployment_convergence_validator as dcv  # noqa: E402

BASE = dcv.PAGES_BASE_URL
# Canonical report slugs use lowercase hexadecimal (never arbitrary letters).
# Keep these ranges distinct so publication-gated, deliverable and historical
# reports remain independently testable with strict UTC selection.
REJECTED = [f"{BASE}/reports/2026/09/intel--{i:024x}.html" for i in range(0, 2)]
OK_REPORTS = [f"{BASE}/reports/2026/09/intel--{i:024x}.html" for i in range(2, 15)]
HISTORY = [f"{BASE}/reports/2026/08/intel--{i:024x}.html" for i in range(15, 20)]
MANIFEST = {"files": {u[len(BASE) + 1:]: {} for u in HISTORY + REJECTED + OK_REPORTS}}


def _write_catalog(monkeypatch, tmp_path, urls):
    """Create a canonical UTC catalog; no network, R2 or publication writes."""
    records = []
    for position, url in enumerate(sorted(set(urls))):
        assert url.startswith(BASE + "/reports/")
        path = url[len(BASE):]
        parts = path.split("/")
        slug = parts[-1].removesuffix(".html")
        records.append({
            "id": slug, "path": path, "url": url,
            "timestamp": f"{parts[2]}-{parts[3]}-{1 + position // 24:02}T{position % 24:02}:00:00Z",
        })
    catalog = tmp_path / "api" / "reports" / "index.json"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(json.dumps({"reports": records}), encoding="utf-8")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    return catalog


@pytest.fixture(autouse=True)
def _canonical_catalog(monkeypatch, tmp_path):
    # Real strict selection is used by every convergence phase test.
    _write_catalog(monkeypatch, tmp_path, HISTORY + REJECTED + OK_REPORTS)


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
    # This deterministic fixture orders canonical timestamps in path order.
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


def test_without_gate_verdict_burns_over_15_minutes_of_retry_budget(clock):
    """Negative control: unclassified 404s still trigger costly repeated backoff.

    The current strict-UTC canonical sample and bounded phase protocol simulate
    approximately 17 minutes here, not the historical 28-minute production run.
    The separate gate-rejection test requires the accepted case to stay <120s.
    """
    net = FakeNet({u: 404 for u in REJECTED})
    with patch.object(dcv, "PERMANENT_STOP_ROUND", 99):
        _run(net, rejected=frozenset())
    assert sum(clock) > 15 * 60, sum(clock)


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
    with patch.object(dcv, "_platform_open", side_effect=err):
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


def test_unverified_permanent_report_404s_hard_fail_after_bounded_two_rounds(clock):
    """Uncertified missing assets never become a pass and never cause 8 CDN retries."""
    latest = _sort_first(REJECTED + OK_REPORTS)[-dcv.MAX_REPORT_PROBES:]
    net = FakeNet({u: 404 for u in latest})
    dcv._GATE_VERDICTS.clear()
    with patch.object(dcv, "_http_probe", side_effect=net.probe), \
         patch.object(dcv, "_is_expected_publication_rejection", return_value=False):
        p2 = dcv.phase2_cdn_readiness_probe([], MANIFEST)
        p3 = dcv.phase3_incremental_retry([], MANIFEST)
    assert not p2.success
    assert not p3.success
    assert dcv.PERMANENT_STOP_ROUND == 1
    assert len(p2.probes) <= 2 * (2 + 5)
    assert len(p3.probes) <= 2 * len(latest)
    assert all(not result.success for result in p3.probes)
    assert all(result.status_code == 404 for result in p3.probes)
    assert max(net.calls.count(url) for url in latest) <= 4
    assert sum(s for s in clock if s > dcv.PROBE_INTERVAL) < 180


def test_phase5_still_excludes_gate_rejections_from_continuity(monkeypatch, tmp_path):
    extra = [f"{BASE}/reports/2026/08/intel--{i:024x}.html" for i in range(20, 26)]
    manifest = {"files": {u[len(BASE) + 1:]: {} for u in REJECTED + OK_REPORTS + extra}}
    _write_catalog(monkeypatch, tmp_path, REJECTED + OK_REPORTS + extra)
    hist = sorted(extra)[:dcv.HIST_PROBE_COUNT]
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
    wf = (REPO / ".github" / "workflows" / "sentinel-apex.yml").read_text(encoding="utf-8")
    assert "timeout 1680 python3 scripts/deployment_convergence_validator.py" in wf


# --- no fixed waits (2026-09-26, run 36228313439: 90s + 2x30s of sleeps on a
# --- deployment that was STABLE 100/100 on the first probe) -----------------

def test_healthy_deployment_has_no_fixed_waits(clock):
    net = FakeNet({u: 404 for u in REJECTED})
    dcv._GATE_VERDICTS.clear()
    with patch.object(dcv, "_http_probe", side_effect=net.probe), \
         patch.object(dcv, "_is_expected_publication_rejection", side_effect=lambda u: u in REJECTED):
        p1 = dcv.phase1_pages_push_detection()
        p4 = dcv.phase4_convergence_confirmation([], MANIFEST)
    assert p1.success and p4.success
    # only the 1s spacing between probes remains
    assert all(s <= dcv.PROBE_INTERVAL for s in clock), clock


def test_unreachable_platform_still_waits_for_pages(clock):
    net = FakeNet({f"{BASE}/": 0, f"{BASE}/api/feed.json": 0})
    with patch.object(dcv, "_http_probe", side_effect=net.probe):
        dcv.phase1_pages_push_detection()
    assert sum(clock) >= dcv.PHASE1_WAIT


def test_confirmation_pauses_only_after_a_failed_pass(clock):
    home = f"{BASE}/"
    net = FakeNet({home: [503, 200]})
    with patch.object(dcv, "_http_probe", side_effect=net.probe), \
         patch.object(dcv, "_is_expected_publication_rejection", return_value=False), \
         patch.dict(dcv.os.environ, {"CONVERGENCE_CONFIRM_RETRY_WAIT": "30"}):
        dcv._GATE_VERDICTS.clear()
        p4 = dcv.phase4_convergence_confirmation([], MANIFEST)
    assert p4.success
    assert [s for s in clock if s > dcv.PROBE_INTERVAL] == [30]


def test_r2_backed_reports_catalog_supplies_historical_evidence_when_pages_manifest_is_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(dcv, "REPO_ROOT", tmp_path)
    urls = [
        f"{BASE}/reports/2026/10/intel--{i:024x}.html"
        for i in range(20, 0, -1)
    ]
    _write_catalog(monkeypatch, tmp_path, urls)

    latest, historical = dcv._extract_report_urls([], {"files": {}})
    assert len(latest) == dcv.MAX_REPORT_PROBES
    assert len(historical) == dcv.HIST_PROBE_COUNT
    assert all(url.startswith(BASE + "/reports/") for url in latest + historical)
    # Verified UTC timestamps, not lexical hash order, establish precedence.
    assert historical[0].endswith("000000000000000000000001.html")
    assert latest[0].endswith("000000000000000000000014.html")
    assert latest[-1].endswith("000000000000000000000006.html")


def test_r2_catalog_rejects_untrusted_external_url(monkeypatch, tmp_path):
    urls = [
        f"{BASE}/reports/2026/10/intel--{i:024x}.html"
        for i in range(20, 0, -1)
    ]
    catalog = _write_catalog(monkeypatch, tmp_path, urls)
    payload = json.loads(catalog.read_text(encoding="utf-8"))
    payload["reports"][0]["url"] = "https://attacker.invalid/report.html"
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([], {"files": {}})


def test_malformed_reports_catalog_cannot_create_synthetic_history(monkeypatch, tmp_path):
    monkeypatch.setattr(dcv, "REPO_ROOT", tmp_path)
    catalog = tmp_path / "api" / "reports" / "index.json"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(__import__("json").dumps({
        "reports": [
            {"path": "https://attacker.invalid/reports/x.html"},
            {"path": "/reports/../../admin.html"},
            {"path": "/api/feed.json"},
        ]
    }), encoding="utf-8")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([], {"files": {}})


def test_missing_historical_evidence_fails_without_requests(monkeypatch):
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *a: ([OK_REPORTS[0]], []))
    monkeypatch.setattr(dcv, "_probe_batch", lambda *a: pytest.fail("no history must not probe"))
    result = dcv.phase5_historical_report_audit([], {})
    assert not result.success
    assert result.probes == []
    assert "HISTORICAL EVIDENCE MISSING" in result.message


def test_small_catalog_cannot_certify_history_or_spend_extra_budget(monkeypatch, tmp_path):
    monkeypatch.setattr(dcv, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(dcv, "_REQUESTS_USED", 23)
    monkeypatch.setattr(dcv, "_probe_batch", lambda *a: pytest.fail("no history must not probe"))
    manifest = {"files": {u[len(BASE) + 1:]: {} for u in OK_REPORTS[:2]}}
    _write_catalog(monkeypatch, tmp_path, OK_REPORTS[:2])
    result = dcv.phase5_historical_report_audit([], manifest)
    assert not result.success
    assert result.probes == []
    assert dcv._REQUESTS_USED == 23


def test_missing_historical_evidence_blocks_high_score_protocol(monkeypatch, tmp_path):
    for number, name in enumerate(("phase1_pages_push_detection",
                                   "phase2_cdn_readiness_probe",
                                   "phase3_incremental_retry",
                                   "phase4_convergence_confirmation"), 1):
        phase = dcv.PhaseResult(phase=number, name=name, success=True,
                                probes=[], duration_s=0, message="offline healthy fixture")
        monkeypatch.setattr(dcv, name, lambda *a, result=phase: result)
    monkeypatch.setattr(dcv, "_load_feed", lambda: [{"title": "offline fixture"}])
    monkeypatch.setattr(dcv, "_load_manifest", lambda: {"files": {}})
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *a: (OK_REPORTS[:2], []))
    monkeypatch.setattr(dcv, "_probe_batch", lambda *a: pytest.fail("no HTTP expected"))
    target = tmp_path / "confidence.json"
    monkeypatch.setattr(dcv, "CONFIDENCE_OUT", target)
    assert dcv.run_convergence_protocol() == 1
    import json
    report = json.loads(target.read_text())
    assert report["confidence_score"] >= dcv.CONFIDENCE_STABLE
    assert report["classification"] == "DEPLOYMENT_FAILED"
    assert report["signals"]["historical_continuity"]["status"] == "FAIL"
    assert report["signals"]["historical_continuity"]["score"] == 0
    assert report["phases"][-1]["success"] is False
    assert report["phases"][-1]["probe_count"] == 0


def test_complete_historical_sample_still_passes(monkeypatch):
    history = OK_REPORTS[:dcv.HIST_PROBE_COUNT]
    net = FakeNet({})
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *a: ([], history))
    monkeypatch.setattr(dcv, "_http_probe", net.probe)
    monkeypatch.setattr(dcv.time, "sleep", lambda *a: None)
    result = dcv.phase5_historical_report_audit([], {})
    assert result.success
    assert net.calls == history
    assert len(result.probes) == dcv.HIST_PROBE_COUNT
