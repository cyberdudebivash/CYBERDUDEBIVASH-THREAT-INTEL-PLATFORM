"""P0: R2 resync cannot publish a feed the real Worker will reject.

Tests use synthetic local fixtures only; never access Cloudflare or accounts.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from scripts import r2_resync_manifests as resync


def latest(tmp_path, *, items=None, generated_at=None):
    path = tmp_path / "api/v1/intel/latest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "count": len(items if items is not None else [{"id": "intel--valid", "title": "Test advisory", "tlp": "TLP:CLEAR"}]),
        "items": items if items is not None else [{"id": "intel--valid", "title": "Test advisory", "tlp": "TLP:CLEAR"}],
    }), encoding="utf-8")
    return path


def test_real_worker_verifies_sanitized_local_clear_latest(tmp_path):
    resync.assert_worker_deliverable_latest(latest(tmp_path))


def test_unlabeled_nested_title_and_id_block_before_r2(tmp_path):
    # Python's publication sanitizer historically does not classify a
    # title/id-only nested object as an advisory; Worker rejects it.
    record = {"id": "intel--valid", "title": "Public item", "tlp": "TLP:CLEAR",
              "related": {"id": "intel--secret", "title": "Unverified nested advisory"}}
    with pytest.raises(ValueError, match="P0_PUBLIC_LATEST_WORKER_REJECTED"):
        resync.assert_worker_deliverable_latest(latest(tmp_path, items=[record]))


def test_unlabeled_public_advisory_blocked(tmp_path):
    with pytest.raises(ValueError, match="P0_PUBLIC_LATEST_WORKER_REJECTED"):
        resync.assert_worker_deliverable_latest(
            latest(tmp_path, items=[{"id": "intel--unclassified", "title": "No label"}])
        )


def test_mismatched_item_count_never_certified(tmp_path):
    path = latest(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["count"] = 2
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="P0_PUBLIC_LATEST_WORKER_REJECTED"):
        resync.assert_worker_deliverable_latest(path)


def test_invalid_local_json_is_never_uploaded(tmp_path):
    path = latest(tmp_path)
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError):
        resync.assert_worker_deliverable_latest(path)


def test_main_aborts_without_credentials_or_r2_writes_on_failed_preflight(tmp_path):
    root = tmp_path
    latest(root)  # a fresh candidate must exercise the mandatory preflight
    previous = Path.cwd()
    with mock.patch.object(resync, "REPO_ROOT", root), \
         mock.patch.object(resync, "build_parent_index", return_value={}), \
         mock.patch.object(resync, "assert_worker_deliverable_latest", side_effect=ValueError("P0_TEST_REJECTED")), \
         mock.patch.object(resync, "get_credentials") as creds, \
         mock.patch.object(resync, "s3_cp") as upload:
        try:
            with pytest.raises(SystemExit) as error:
                resync.main()
            assert error.value.code == 1
            creds.assert_not_called()
            upload.assert_not_called()
        finally:
            os.chdir(previous)
