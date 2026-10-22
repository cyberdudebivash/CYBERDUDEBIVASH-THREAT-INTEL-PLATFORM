"""Offline regression tests for complete NVD window retrieval in the scheduled collector."""
from datetime import datetime, timezone
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
    return {"cve": {"id": f"CVE-2026-{10000+i}", "published": "2026-10-23T00:00:00.000",
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
