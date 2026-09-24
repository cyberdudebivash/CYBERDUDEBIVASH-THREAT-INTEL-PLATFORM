"""
feed_contract_validator.py: bounded reads + bounded /api/preview (P0 Phase 3D).

The live validator read at most 131072 bytes, and a default /api/preview page
is ~300 KB, so it parsed truncated JSON. Fix without raising the limit:
  - the preview contract is probed on an explicit bounded page (?limit=5) and
    the Worker must honour it (CONTRACT-PREVIEW-BOUND);
  - any over-limit body is an explicit CONTRACT-SIZE hard fail, not a JSON
    parse error.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import feed_contract_validator as fcv  # noqa: E402

ITEM = {"id": "intel--1", "title": "t", "severity": "HIGH", "risk_score": 7.0, "stix_id": "intel--1"}


def _preview_body(n: int, limit: int | None):
    p = {"items": [dict(ITEM, id=f"intel--{i}") for i in range(n)], "total_preview": n}
    if limit is not None:
        p["limit"] = limit
    return json.dumps({"status": "ok", "preview": p})


def _run(monkeypatch, tmp_path, responder):
    seen = []

    def fake_fetch(url, timeout, token=None):
        seen.append(url)
        return responder(url)

    monkeypatch.setattr(fcv, "_fetch", fake_fetch)
    monkeypatch.setattr(fcv, "CONTRACTS", {"/api/preview": fcv.CONTRACTS["/api/preview"]})
    v = fcv.FeedContractValidator("https://x", 5, True, tmp_path)
    v.check_live_endpoints()
    return v, seen


def _cids(vs):
    return {v.contract_id for v in vs}


def test_preview_is_probed_with_an_explicit_bounded_query(monkeypatch, tmp_path):
    _, seen = _run(monkeypatch, tmp_path, lambda u: (200, _preview_body(5, 5), {"Content-Type": "application/json"}))
    assert seen == ["https://x/api/preview?limit=5"]


def test_bounded_page_that_honours_the_limit_passes(monkeypatch, tmp_path):
    v, _ = _run(monkeypatch, tmp_path, lambda u: (200, _preview_body(5, 5), {"Content-Type": "application/json"}))
    assert not v.report.hard_fails, [x.message for x in v.report.hard_fails]


def test_worker_ignoring_the_limit_is_a_hard_fail(monkeypatch, tmp_path):
    # e.g. a Worker that predates ?limit support returns the full 25 items.
    v, _ = _run(monkeypatch, tmp_path, lambda u: (200, _preview_body(25, None), {"Content-Type": "application/json"}))
    assert "CONTRACT-PREVIEW-BOUND" in _cids(v.report.hard_fails)


def test_over_limit_body_is_reported_as_size_not_json(monkeypatch, tmp_path):
    hdrs = {"Content-Type": "application/json", fcv.TRUNCATED_MARKER: "1"}
    v, _ = _run(monkeypatch, tmp_path, lambda u: (200, '{"status":"ok","preview":{"items":[{"id"', hdrs))
    cids = _cids(v.report.hard_fails)
    assert "CONTRACT-SIZE" in cids
    assert "CONTRACT-JSON" not in cids


class _Resp:
    def __init__(self, payload: bytes):
        self._b = io.BytesIO(payload)
        self.status = 200
        self.headers = {"Content-Type": "application/json"}

    def read(self, n=-1):
        return self._b.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.mark.parametrize("size,truncated", [(fcv.READ_LIMIT_BYTES, False), (fcv.READ_LIMIT_BYTES + 1, True), (300_000, True)])
def test_fetch_reads_at_most_the_limit_and_flags_truncation(monkeypatch, size, truncated):
    monkeypatch.setattr(fcv.urllib.request, "urlopen", lambda req, timeout: _Resp(b"a" * size))
    status, body, hdrs = fcv._fetch("https://x/y", 5)
    assert status == 200
    assert len(body) == min(size, fcv.READ_LIMIT_BYTES)
    assert bool(hdrs.get(fcv.TRUNCATED_MARKER)) is truncated


def test_read_limit_was_not_raised():
    assert fcv.READ_LIMIT_BYTES == 131072
