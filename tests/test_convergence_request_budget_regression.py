"""Regression proof for run 37548915398's Phase-5 request-budget exhaustion."""

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import deployment_convergence_validator as dcv  # noqa: E402


class Response:
    status = 200
    headers = {}

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, size):
        return json.dumps(self.value).encode("utf-8")


@pytest.fixture
def clean_budget(monkeypatch):
    monkeypatch.setattr(dcv, "_REQUESTS_USED", 0)
    monkeypatch.setattr(dcv, "_PROTOCOL_STARTED", None)
    monkeypatch.setattr(dcv, "_RETRY_NOT_BEFORE", 0.0)
    monkeypatch.setattr(dcv.time, "monotonic", lambda: 1000.0)
    monkeypatch.setattr(dcv.time, "sleep", lambda _seconds: None)


def test_publication_status_uses_one_bounded_get(monkeypatch, clean_budget):
    calls = []

    def urlopen(req, **kwargs):
        calls.append((req.get_method(), req.full_url))
        return Response({"state": "REJECTED", "customer_ready": False})

    monkeypatch.setattr(dcv, "_platform_open", urlopen)
    result = dcv.query_publication_status("intel--0123456789abcdef")

    assert result == {"state": "REJECTED", "customer_ready": False}
    assert calls == [
        (
            "GET",
            f"{dcv.PAGES_BASE_URL}/api/v1/reports/"
            "intel--0123456789abcdef/publication-status",
        )
    ]
    assert dcv._REQUESTS_USED == 1


def test_last_request_slot_can_classify_gate_rejection(monkeypatch, clean_budget):
    monkeypatch.setattr(dcv, "_REQUESTS_USED", dcv.MAX_TOTAL_REQUESTS - 1)
    calls = []

    def urlopen(req, **kwargs):
        calls.append(req.get_method())
        return Response({"state": "REJECTED", "customer_ready": False})

    monkeypatch.setattr(dcv, "_platform_open", urlopen)
    result = dcv.query_publication_status("intel--fedcba9876543210")

    assert result == {"state": "REJECTED", "customer_ready": False}
    assert calls == ["GET"]
    assert dcv._REQUESTS_USED == dcv.MAX_TOTAL_REQUESTS


def test_exhausted_budget_still_fails_closed(monkeypatch, clean_budget):
    monkeypatch.setattr(dcv, "_REQUESTS_USED", dcv.MAX_TOTAL_REQUESTS)
    monkeypatch.setattr(
        dcv,
        "_platform_open",
        lambda *args, **kwargs: pytest.fail("network must not run"),
    )

    assert dcv.query_publication_status("intel--deadbeefdeadbeef") is None


def test_rate_limited_status_get_preserves_global_cooldown(
    monkeypatch, clean_budget
):
    error = urllib.error.HTTPError(
        "https://example.test/status",
        429,
        "limited",
        {"Retry-After": "90"},
        io.BytesIO(),
    )

    def rate_limited(*args, **kwargs):
        raise error

    monkeypatch.setattr(dcv, "_platform_open", rate_limited)

    assert dcv.query_publication_status("intel--cafebabecafebabe") is None
    assert dcv._REQUESTS_USED == 1
    assert dcv._RETRY_NOT_BEFORE == 1090.0


def test_incomplete_historical_sample_is_explicit_and_fail_closed(
    monkeypatch, clean_budget
):
    urls = [
        f"{dcv.PAGES_BASE_URL}/reports/2026/10/intel--{i:024x}.html"
        for i in range(5)
    ]
    results = [
        dcv.ProbeResult(
            url=urls[0],
            status_code=404,
            latency_ms=1,
            success=True,
            gate_rejected=True,
        ),
        dcv.ProbeResult(
            url=urls[1],
            status_code=200,
            latency_ms=1,
            success=True,
        ),
        dcv.ProbeResult(
            url=urls[2],
            status_code=404,
            latency_ms=1,
            success=True,
            gate_rejected=True,
        ),
        dcv.ProbeResult(
            url=urls[3],
            status_code=0,
            latency_ms=0,
            success=False,
            error="NOT_PROBED: shared request/time budget exhausted",
        ),
    ]
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *args: ([], urls))
    monkeypatch.setattr(dcv, "_probe_batch", lambda *args: (results, 3, 1))

    phase = dcv.phase5_historical_report_audit([], {})

    assert not phase.success
    assert "1/2 historical reports accessible" in phase.message
    assert "1 unprobed" in phase.message
    assert "2 excluded as expected publication-gate rejections" in phase.message


def test_full_healthy_protocol_completes_phase5_within_existing_cap(
    monkeypatch, clean_budget
):
    paths = [
        f"reports/2026/10/intel--{i:024x}.html"
        for i in range(20)
    ]
    manifest = {"files": {path: {} for path in paths}}
    publication_reads = []

    def urlopen(req, **kwargs):
        if req.full_url.endswith("/publication-status"):
            publication_reads.append(req.full_url)
            return Response({"state": "REJECTED", "customer_ready": False})
        if "/reports/" in req.full_url:
            raise urllib.error.HTTPError(
                req.full_url, 404, "not published", {}, io.BytesIO()
            )
        return Response({})

    monkeypatch.setattr(dcv, "_platform_open", urlopen)
    dcv._GATE_VERDICTS.clear()

    phase1 = dcv.phase1_pages_push_detection()
    phase2 = dcv.phase2_cdn_readiness_probe([], manifest)
    phase3 = dcv.phase3_incremental_retry([], manifest)
    phase4 = dcv.phase4_convergence_confirmation([], manifest)
    phase5 = dcv.phase5_historical_report_audit([], manifest)

    assert all(phase.success for phase in (phase1, phase2, phase3, phase4, phase5))
    assert len(phase5.probes) == dcv.HIST_PROBE_COUNT
    assert dcv._REQUESTS_USED <= dcv.MAX_TOTAL_REQUESTS
    assert len(publication_reads) == 20


def test_not_probed_is_distinct_from_permanent_404(monkeypatch, clean_budget):
    monkeypatch.setattr(dcv, "_REQUESTS_USED", dcv.MAX_TOTAL_REQUESTS)
    monkeypatch.setattr(
        dcv, "_platform_open",
        lambda *args, **kwargs: pytest.fail("request budget exhaustion must make zero HTTP calls"),
    )
    result = dcv._http_probe(dcv.PAGES_BASE_URL + "/reports/2026/10/intel--deadbeef.html")
    assert result.status_code == 0
    assert result.success is False
    assert result.error.startswith("NOT_PROBED:")
    assert result.is_transient is True, "cannot classify unattempted request as permanent HTTP failure"
    assert dcv._unprobed_budget_exhausted([result])
    assert not dcv._only_permanent_failures([result])


def test_only_actual_nontransient_http_failures_are_permanent():
    permanent = dcv.ProbeResult(
        url=dcv.PAGES_BASE_URL + "/reports/missing.html",
        status_code=404, latency_ms=1, success=False,
        is_transient=False, error="HTTPError 404",
    )
    assert dcv._only_permanent_failures([permanent])
    unprobed = dcv.ProbeResult(
        url=dcv.PAGES_BASE_URL + "/reports/unprobed.html",
        status_code=0, latency_ms=0, success=False,
        is_transient=False, error="NOT_PROBED: shared request/time budget exhausted",
    )
    assert not dcv._only_permanent_failures([permanent, unprobed])
    assert dcv._unprobed_budget_exhausted([permanent, unprobed])


def test_phase2_budget_exhaustion_fails_closed_without_retries(monkeypatch, clean_budget):
    calls = []
    missing = dcv.ProbeResult(
        url=dcv.PAGES_BASE_URL + "/reports/pending.html", status_code=0,
        latency_ms=0, success=False, is_transient=True,
        error="NOT_PROBED: shared request/time budget exhausted",
    )
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *args: ([missing.url], []))
    monkeypatch.setattr(dcv, "_probe_batch", lambda *args: (calls.append(args) or [missing], 0, 1))
    monkeypatch.setattr(dcv, "_backoff_wait", lambda _: pytest.fail("no retry when budget exhausted"))
    result = dcv.phase2_cdn_readiness_probe([], {})
    assert result.success is False
    assert len(calls) == 1
    assert result.probes[0].status_code == 0


def test_phase3_budget_exhaustion_fails_closed_without_retry(monkeypatch, clean_budget):
    url = dcv.PAGES_BASE_URL + "/reports/2026/10/intel--feed123.html"
    missing = dcv.ProbeResult(
        url=url, status_code=0, latency_ms=0, success=False, is_transient=True,
        error="NOT_PROBED: shared request/time budget exhausted",
    )
    calls = []
    monkeypatch.setattr(dcv, "_extract_report_urls", lambda *args: ([url], []))
    monkeypatch.setattr(dcv, "_probe_batch", lambda *args: (calls.append(args) or [missing], 0, 1))
    monkeypatch.setattr(dcv, "_backoff_wait", lambda _: pytest.fail("must not claim a retry occurred"))
    result = dcv.phase3_incremental_retry([], {})
    assert result.success is False
    assert len(calls) == 1
    assert not any(r.success for r in result.probes)
