"""Offline regression tests for complete NVD window retrieval in the scheduled collector."""
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
import scripts.true_intel_ingestor as ingestor

@pytest.fixture(autouse=True)
def avoid_network_pacing_in_offline_tests(monkeypatch):
    monkeypatch.setattr(ingestor.time, "sleep", lambda seconds: None)

class FakeState:
    def __init__(self):
        self.updated = []
    def get_last_seen(self, key):
        return None
    def is_new(self, key, ts):
        return True
    def update_last_seen(self, key, ts):
        self.updated.append((key, ts))

def record(i):
    return {"cve": {"id": f"CVE-2026-{10000+i}", "published": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "descriptions": [{"lang": "en", "value": "fixture"}], "metrics": {}}}

def test_nvd_two_pages_complete_before_cursor_update():
    state = FakeState()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if "startIndex=0" in url:
            return {"totalResults": 2001, "vulnerabilities": [record(i) for i in range(2000)]}
        if "startIndex=2000" in url:
            return {"totalResults": 2001, "vulnerabilities": [record(2000)]}
        raise AssertionError(url)
    with patch.object(ingestor, "_get_json", side_effect=fetch), patch.object(
        ingestor, "_normalize_item", side_effect=lambda **kw: kw):
        items = ingestor.ingest_nvd_cves(state)
    assert len(items) == 2001
    assert len(calls) == 2
    assert len(state.updated) == 1

def test_nvd_second_page_failure_preserves_checkpoint():
    state = FakeState()
    def fetch(url, **kwargs):
        if "startIndex=0" in url:
            return {"totalResults": 2001, "vulnerabilities": [record(i) for i in range(2000)]}
        return None
    with patch.object(ingestor, "_get_json", side_effect=fetch):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_malformed_total_preserves_checkpoint():
    state = FakeState()
    with patch.object(ingestor, "_get_json", return_value={"vulnerabilities": [record(1)]}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_inconsistent_total_preserves_checkpoint():
    state = FakeState()
    def fetch(url, **kwargs):
        if "startIndex=0" in url:
            return {"totalResults": 2001, "vulnerabilities": [record(i) for i in range(2000)]}
        return {"totalResults": 2002, "vulnerabilities": [record(2000)]}
    with patch.object(ingestor, "_get_json", side_effect=fetch):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_duplicate_page_rejected_without_checkpoint_advance():
    state = FakeState()
    def fetch(url, **kwargs):
        if "startIndex=0" in url:
            return {"totalResults": 2001, "vulnerabilities": [record(i) for i in range(2000)]}
        return {"totalResults": 2001, "vulnerabilities": [record(1999)]}
    with patch.object(ingestor, "_get_json", side_effect=fetch):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_empty_complete_window_is_not_an_error():
    state = FakeState()
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 0, "vulnerabilities": []}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_pagination_limit_fails_closed():
    state = FakeState()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        start = int(url.split("startIndex=")[1])
        return {"totalResults": 20001, "vulnerabilities": [record(i) for i in range(start, start + 2000)]}
    with patch.object(ingestor, "_get_json", side_effect=fetch):
        assert ingestor.ingest_nvd_cves(state) == []
    assert len(calls) == 10
    assert state.updated == []

def test_nvd_bad_cve_shape_preserves_checkpoint():
    state = FakeState()
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 1, "vulnerabilities": [{"cve": {}}]}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_malformed_timestamp_preserves_checkpoint():
    state = FakeState()
    bad = record(1)
    bad["cve"]["published"] = "not-a-timestamp"
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 1, "vulnerabilities": [bad]}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_future_timestamp_preserves_checkpoint():
    state = FakeState()
    bad = record(1)
    bad["cve"]["published"] = "2099-01-01T00:00:00.000"
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 1, "vulnerabilities": [bad]}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []

def test_nvd_invalid_page_exposes_source_health_reason():
    state = FakeState()
    with patch.object(ingestor, "_get_json", return_value={"vulnerabilities": []}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert ingestor.get_last_http_reason_code() == "NVD_INCOMPLETE_WINDOW"

def test_nvd_valid_empty_page_has_no_failure_reason():
    state = FakeState()
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 0, "vulnerabilities": []}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert ingestor.get_last_http_reason_code() is None

def test_nvd_stale_cursor_requires_reconciliation_without_network():
    state = FakeState()
    state.get_last_seen = lambda key: datetime.now(timezone.utc) - timedelta(days=121)
    with patch.object(ingestor, "_get_json", side_effect=AssertionError("network forbidden")):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []
    assert ingestor.get_last_http_reason_code() == "NVD_RECONCILIATION_REQUIRED"

def test_nvd_future_cursor_requires_reconciliation_without_network():
    state = FakeState()
    state.get_last_seen = lambda key: datetime.now(timezone.utc) + timedelta(days=1)
    with patch.object(ingestor, "_get_json", side_effect=AssertionError("network forbidden")):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []
    assert ingestor.get_last_http_reason_code() == "NVD_RECONCILIATION_REQUIRED"

@pytest.mark.parametrize("field,value", [
    ("descriptions", {"lang": "en", "value": "bad shape"}),
    ("descriptions", [{"lang": "en"}]),
    ("metrics", {"cvssMetricV31": [{"cvssData": "bad shape"}]}),
    ("metrics", []),
])
def test_nvd_malformed_metadata_fails_closed(field, value):
    state = FakeState()
    bad = record(1)
    bad["cve"][field] = value
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 1, "vulnerabilities": [bad]}):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []
    assert ingestor.get_last_http_reason_code() == "NVD_INCOMPLETE_WINDOW"

@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf"), "not-a-number"])
def test_nvd_nonfinite_cvss_uses_finite_fallback(score):
    state = FakeState()
    item = record(1)
    item["cve"]["metrics"] = {
        "cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]
    }
    with patch.object(ingestor, "_get_json", return_value={"totalResults": 1, "vulnerabilities": [item]}), patch.object(
        ingestor, "_normalize_item", side_effect=lambda **kw: kw):
        result = ingestor.ingest_nvd_cves(state)
    assert len(result) == 1
    assert result[0]["risk_score"] == 5.0

def test_nvd_rate_limit_reason_is_preserved():
    state = FakeState()
    def rate_limited(*args, **kwargs):
        ingestor._last_http_reason_code = "HTTP_429"
        return None
    with patch.object(ingestor, "_get_json", side_effect=rate_limited):
        assert ingestor.ingest_nvd_cves(state) == []
    assert state.updated == []
    assert ingestor.get_last_http_reason_code() == "HTTP_429"
