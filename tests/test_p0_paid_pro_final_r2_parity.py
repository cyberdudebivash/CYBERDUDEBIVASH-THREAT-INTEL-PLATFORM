"""P0 paid product: one final PRO R2 writer, generation parity, and no extra PUT.

Synthetic local source and mocked R2 only. Never calls Cloudflare.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

from scripts import r2_upload, r2_resync_manifests as resync


PRO_KEY = "api/v1/intel/latest_pro.json"


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def _pair(root: Path, *, moment: datetime | None = None) -> tuple[Path, Path]:
    generated = _iso(moment or datetime.now(timezone.utc))
    directory = root / "api" / "v1" / "intel"
    directory.mkdir(parents=True, exist_ok=True)
    public = {"id": "intel--fixture-1", "title": "Reviewed public advisory", "tlp": "TLP:CLEAR"}
    pro = {**public, "iocs": [{"type": "domain", "value": "example.test"}],
           "technical_analysis": "PAID_ONLY_REVIEWED_DETAIL"}
    free_payload = {"generated_at": generated, "count": 1, "items": [public]}
    paid_payload = {"generated_at": generated, "tier": "PRO", "count": 1, "items": [pro]}
    free = directory / "latest.json"
    paid = directory / "latest_pro.json"
    free.write_text(json.dumps(free_payload), encoding="utf-8")
    paid.write_text(json.dumps(paid_payload), encoding="utf-8")
    feed = root / "api" / "feed.json"
    feed.parent.mkdir(parents=True, exist_ok=True)
    feed.write_text(json.dumps([public]), encoding="utf-8")
    return free, paid


def _edit(path: Path, mutator) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    mutator(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_final_pair_proves_tlp_freshness_identity_and_preserves_original_bytes(tmp_path):
    free, paid = _pair(tmp_path)
    originals = (free.read_bytes(), paid.read_bytes())
    resync.assert_final_paid_pro_pair(tmp_path)
    assert (free.read_bytes(), paid.read_bytes()) == originals


@pytest.mark.parametrize("target,mutation,expected", [
    ("pro", lambda d: d.update(generated_at="2026-08-26T09:55:27Z"), "FRESHNESS_UNVERIFIED"),
    ("pro", lambda d: d.update(generated_at="not-a-timestamp"), "FRESHNESS_UNVERIFIED"),
    ("pro", lambda d: d.update(generated_at=_iso(datetime.now(timezone.utc) + timedelta(days=7))), "FRESHNESS_UNVERIFIED"),
    ("pro", lambda d: d.update(count=2), "COUNT_UNVERIFIED"),
    ("pro", lambda d: d.update(tier="FREE"), "SOURCE_DRIFT"),
    ("pro", lambda d: d["items"][0].update(id="intel--other"), "SOURCE_DRIFT"),
    ("pro", lambda d: d["items"][0].update(tlp="TLP:RED"), "TLP_MODIFIED"),
    ("free", lambda d: d["items"].append(dict(d["items"][0])), "COUNT_UNVERIFIED"),
])
def test_final_paid_publish_rejects_stale_invalid_and_cross_tier_drift(tmp_path, target, mutation, expected):
    free, paid = _pair(tmp_path)
    _edit(paid if target == "pro" else free, mutation)
    with pytest.raises(ValueError, match=expected):
        resync.assert_final_paid_pro_pair(tmp_path)


def test_paid_missing_or_malformed_never_passes_as_a_fresh_release(tmp_path):
    _, paid = _pair(tmp_path)
    paid.unlink()
    with pytest.raises(ValueError, match="MISSING_ARTIFACT"):
        resync.assert_final_paid_pro_pair(tmp_path)
    paid.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="UNREADABLE_ARTIFACT"):
        resync.assert_final_paid_pro_pair(tmp_path)


def test_early_stage_plan_no_longer_publishes_previous_run_pro_artifact(tmp_path):
    _pair(tmp_path)
    with mock.patch.object(r2_upload, "REPO_ROOT", tmp_path):
        plan = r2_upload.build_upload_plan()
    assert PRO_KEY not in {key for _src, key in plan}


def test_only_explicit_final_stage_uploads_one_paid_blob_with_private_no_store(tmp_path):
    _pair(tmp_path)
    uploads = []
    def fake_put(src, bucket, key, endpoint, cache_control=""):
        uploads.append((key, cache_control, json.loads(Path(src).read_text(encoding="utf-8"))))
        return True

    def run(flag):
        with mock.patch.dict(os.environ, {resync.PAID_FINAL_SYNC_ENV: flag}), \
             mock.patch.object(resync, "REPO_ROOT", tmp_path), \
             mock.patch.object(resync, "RESYNC_FILES", [
                 (PRO_KEY, PRO_KEY, "private, no-store")]), \
             mock.patch.object(resync, "get_credentials", return_value=("fixture", "key", "secret")), \
             mock.patch.object(resync, "assert_worker_deliverable_latest"), \
             mock.patch.object(resync, "s3_cp", side_effect=fake_put), \
             mock.patch("os.chdir"):
            with pytest.raises(SystemExit) as e:
                resync.main()
            assert e.value.code == 0

    run("0")
    assert uploads == [], "early Stage 3.93.6 must not re-PUT paid manifest"
    run("1")
    assert len(uploads) == 1
    key, cc, payload = uploads[0]
    assert key == PRO_KEY
    assert cc == "private, no-store"
    assert payload["tier"] == "PRO"
    assert payload["items"][0]["technical_analysis"] == "PAID_ONLY_REVIEWED_DETAIL"


def test_mismatched_final_pair_fails_before_credentials_or_any_r2_put(tmp_path):
    _, paid = _pair(tmp_path)
    _edit(paid, lambda d: d["items"][0].update(id="intel--other"))
    with mock.patch.dict(os.environ, {resync.PAID_FINAL_SYNC_ENV: "1"}), \
         mock.patch.object(resync, "REPO_ROOT", tmp_path), \
         mock.patch.object(resync, "get_credentials") as credentials, \
         mock.patch.object(resync, "s3_cp") as put, \
         mock.patch("os.chdir"):
        with pytest.raises(SystemExit) as error:
            resync.main()
    assert error.value.code == 1
    credentials.assert_not_called()
    put.assert_not_called()


def test_workflow_enables_paid_only_in_final_post_commit_sync():
    source = (Path(__file__).resolve().parents[1] /
              ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    stage_early = source.split('STAGE 3.93.6 - R2 Re-sync Final API Manifests', 1)[1].split(
        'STAGE 3.93.7 - Global Version Governance', 1)[0]
    stage_final = source.split('STAGE 4.1 - Final R2 Full Sync', 1)[1].split(
        'Upload Intel State to R2', 1)[0]
    assert "CDB_FINAL_PAID_R2_SYNC" not in stage_early
    assert "CDB_FINAL_PAID_R2_SYNC: '1'" in stage_final
    assert sum(1 for row in resync.RESYNC_FILES if row[1] == PRO_KEY) == 1


def test_final_paid_publication_failure_is_a_release_blocker_not_a_green_warning():
    """Live PRO parity/TLP failure must not be swallowed by the workflow."""
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    stage = workflow.split(
        '- name: "STAGE 4.1 - Final R2 Full Sync', 1
    )[1].split('P0 FIX: Upload Intel State to R2', 1)[0]
    assert "set -euo pipefail" in stage
    assert "python3 scripts/r2_resync_manifests.py" in stage
    assert "if ! python3 scripts/r2_resync_manifests.py" not in stage
    assert "|| true" not in stage
    assert "::warning::STAGE 4.1" not in stage
