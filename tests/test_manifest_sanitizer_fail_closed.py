"""Exercise publication with missing/broken sanitizer dependencies in isolation."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

ROOT = Path(__file__).resolve().parents[1]
ELIGIBILITY_DEPENDENCIES = ("p0_r44_publication_boundary.py", "p0_r35_feed_prewrite_guard.py",
                            "sentinel_apex_mandate_enforcer.py", "manifest_reconciler.py", "safe_io.py",
                            "evidence_score_enforcer.py")


@pytest.mark.parametrize("dependency", ["missing", "broken", "healthy"])
def test_publication_requires_working_sanitizer(tmp_path, dependency):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("generate_api_manifests.py", "severity_epss_truth.py", "tlp_policy.py") + ELIGIBILITY_DEPENDENCIES:
        shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    sanitizer = scripts / "public_api_sanitizer.py"
    if dependency == "healthy":
        shutil.copyfile(ROOT / "scripts" / sanitizer.name, sanitizer)
    elif dependency == "broken":
        sanitizer.write_text("raise ImportError('dependency unavailable')\n")
    api = tmp_path / "api"
    api.mkdir()
    (api / "feed.json").write_text(json.dumps([_adv("test", report_url="https://example.com/private", tlp="TLP:CLEAR")]))
    out = api / "v1" / "intel"
    out.mkdir(parents=True)
    existing = out / "latest.json"
    existing.write_text('{"last_known_good":true}')
    result = subprocess.run([sys.executable, str(scripts / "generate_api_manifests.py")],
                            cwd=tmp_path, capture_output=True, text=True)
    if dependency != "healthy":
        assert result.returncode == 1
        assert "publication refused" in result.stderr
        assert existing.read_text() == '{"last_known_good":true}'
        assert list(out.iterdir()) == [existing]
        assert not (tmp_path / "reports").exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        payload = json.loads(existing.read_text())
        assert payload["count"] == 1
        assert "report_url" not in payload["items"][0]
        assert (out / "latest_pro.json").exists()


def test_missing_public_evidence_enforcer_fails_closed(tmp_path):
    """A real missing production dependency must refuse publication, not bypass risk truth."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("generate_api_manifests.py", "severity_epss_truth.py", "tlp_policy.py",
                 "public_api_sanitizer.py", *ELIGIBILITY_DEPENDENCIES):
        if name != "evidence_score_enforcer.py":
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    api = tmp_path / "api"
    (api / "v1" / "intel").mkdir(parents=True)
    (api / "feed.json").write_text(json.dumps([_adv("enforcer", tlp="TLP:CLEAR")]))
    existing = api / "v1" / "intel" / "latest.json"
    existing.write_text('{"last_known_good":true}')
    result = subprocess.run([sys.executable, str(scripts / "generate_api_manifests.py")],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1
    assert "evidence_score_enforcer" in result.stdout + result.stderr
    assert existing.read_text() == '{"last_known_good":true}'
    assert list(existing.parent.iterdir()) == [existing]


# ── P0 #721: TLP last-mile gate on the anonymously served immutable manifests ──────────────────────────────
def _run_manifests(tmp_path, feed, copy_policy=True):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    names = ["generate_api_manifests.py", "severity_epss_truth.py", "public_api_sanitizer.py", *ELIGIBILITY_DEPENDENCIES]
    if copy_policy:
        names.append("tlp_policy.py")
    for name in names:
        shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    api = tmp_path / "api"
    (api / "v1" / "intel").mkdir(parents=True)
    (api / "feed.json").write_text(json.dumps(feed))
    existing = api / "v1" / "intel" / "latest.json"
    existing.write_text('{"last_known_good":true}')
    result = subprocess.run([sys.executable, str(scripts / "generate_api_manifests.py")],
                            cwd=tmp_path, capture_output=True, text=True)
    return result, existing


def _adv(i, **kw):
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dict({"id": f"adv-{i}", "stix_id": f"adv-{i}", "title": f"Fixture {i}",
                 "source": "Fixture Publisher", "source_name": "publisher.example",
                 "source_url": f"https://publisher.example/{i}", "severity": "MEDIUM", "risk_score": 5.0,
                 "timestamp": stamp, "published_at": stamp, "publication_timestamp": stamp,
                 "retrieval_timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "content_hash": "a" * 64,
                 "content_hash_scope": "rss_entry_fields_sha256", "trust_score": 8.2,
                 "evidence_count": 1, "evidence_basis": ["captured_rss_entry"]}, **kw)


def test_manifests_withhold_every_non_clear_item(tmp_path):
    feed = [_adv(1, tlp="TLP:CLEAR"), _adv(2, tlp="TLP:GREEN"), _adv(3, tlp="TLP:AMBER"), _adv(4, tlp="TLP:RED"),
            _adv(5), _adv(6, tlp="TLP:PURPLE"), _adv(7, tlp="TLP:WHITE"),
            _adv(8, tlp="TLP:CLEAR", evidence_chain=[{"tlp": "TLP:GREEN"}])]
    result, existing = _run_manifests(tmp_path, feed)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "withheld from public manifests" in result.stdout
    emitted = set()
    for f in (tmp_path / "api" / "v1" / "intel").glob("*.json"):
        if f.name == "registry.json":
            continue
        raw = f.read_text(encoding="utf-8")
        emitted |= {i for i in range(1, 9) if f'"adv-{i}"' in raw}
    assert emitted == {1}, f"only the TLP:CLEAR, un-contradicted item may be emitted; got {sorted(emitted)}"
    assert json.loads(existing.read_text())["count"] == 1


def test_all_withheld_replaces_stale_public_bundles_with_tombstones_then_fails(tmp_path):
    """P0 #725: exiting without a write left the previous (possibly restricted) bundles served. Deny-first instead."""
    result, existing = _run_manifests(tmp_path, [_adv(1), _adv(2, tlp="TLP:RED", description="LEAKMARKER-BODY")])
    assert result.returncode == 1
    assert "REPLACED by empty tombstones" in result.stdout
    out = existing.parent
    for name in ("latest", "latest_pro", "top10", "apex"):
        payload = json.loads((out / f"{name}.json").read_text())
        assert payload["count"] == 0 and payload["items"] == []
        assert payload["tlp_boundary"]["withheld_all"] is True
        assert payload["sha256"]
    reg = json.loads((out / "manifest.json").read_text())
    assert set(reg["bundles"]) == {"latest", "latest_pro", "top10", "apex"}
    assert all(b["count"] == 0 for b in reg["bundles"].values())
    blob = "".join(p.read_text() for p in out.glob("*.json"))
    assert "last_known_good" not in blob, "the stale bundle was overwritten"
    assert "LEAKMARKER-BODY" not in blob


def test_manifests_refuse_when_policy_module_unavailable(tmp_path):
    result, existing = _run_manifests(tmp_path, [_adv(1, tlp="TLP:CLEAR")], copy_policy=False)
    assert result.returncode == 1
    assert "TLP policy module unavailable" in result.stdout
    assert existing.read_text() == '{"last_known_good":true}'
