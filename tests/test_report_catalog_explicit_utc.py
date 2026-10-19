"""Customer catalog timestamps must never inherit guessed timezones or filesystem mtimes."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_reports_index as bri


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    feed = tmp_path / "api" / "feed.json"
    feed.parent.mkdir(parents=True)
    out = tmp_path / "api" / "reports"
    monkeypatch.setattr(bri, "REPORTS_ROOT", reports)
    monkeypatch.setattr(bri, "API_FEED", feed)
    monkeypatch.setattr(bri, "API_REPORTS", out)
    monkeypatch.setattr(bri, "PUBLISH_STATE", tmp_path / "missing-publish-state.json")

    def build(items):
        feed.write_text(json.dumps(items), encoding="utf-8")
        for item in items:
            current = datetime.now(timezone.utc)
            p = reports / current.strftime("%Y") / current.strftime("%m") / (item["id"] + ".html")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("<html>" + "x" * 600 + "</html>", encoding="utf-8")
        assert bri.main() == 0
        return json.loads((out / "index.json").read_text(encoding="utf-8"))

    return build


def test_explicit_offset_timestamp_is_serialized_as_utc(isolated):
    current = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
    offset_ts = current.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat()
    payload = isolated([{"id": "intel--" + "a" * 24, "timestamp": offset_ts}])
    assert len(payload["reports"]) == 1
    output = payload["reports"][0]["timestamp"]
    assert output.endswith("Z")
    assert datetime.fromisoformat(output.replace("Z", "+00:00")) == current


def test_timezone_naive_feed_entry_is_not_published_as_if_utc(isolated):
    current = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
    payload = isolated([
        {"id": "intel--" + "b" * 24, "timestamp": current.isoformat().replace("+00:00", "")},
    ])
    assert payload["reports"] == []
    assert payload["total_reports"] == 0


def test_proven_utc_timestamp_never_falls_back_to_file_mtime(isolated):
    current = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=2)
    payload = isolated([{"id": "intel--" + "c" * 24, "timestamp": current.isoformat().replace("+00:00", "Z")}])
    assert len(payload["reports"]) == 1
    assert payload["reports"][0]["timestamp"] == current.isoformat().replace("+00:00", "Z")
    assert payload["reports"][0]["timestamp"] != payload["generated_at"]
