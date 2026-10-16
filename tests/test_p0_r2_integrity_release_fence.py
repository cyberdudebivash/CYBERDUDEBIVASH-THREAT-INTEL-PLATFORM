"""P0 #725: integrity verifier and release-surface gates must fail CLOSED.

Run #2520 reported a failed Stage 3.6 verifier followed by a successful
Stage 3.7 KV cache bust. The old verifier also had soft-pass paths for
missing S3 credentials and private-bucket HTTP 403 responses. No production
credentials, R2 I/O or network are used by these contract tests.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import r2_upload_verifier as verifier


def test_missing_verifier_credentials_are_a_hard_failure():
    with patch.object(verifier, "CF_ACCOUNT_ID", ""), \
         patch.object(verifier, "ACCESS_KEY", ""), \
         patch.object(verifier, "SECRET_KEY", ""):
        verified, message, details = verifier.verify_r2_object()
    assert verified is False
    assert details["reason_code"] == "MISSING_AUTHORITY"
    assert "UNVERIFIED" in message


def test_unavailable_authenticated_s3_head_cannot_soft_pass():
    with patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(verifier, "R2_ENDPOINT", "https://r2.example.invalid"), \
         patch.object(verifier, "_s3api_head_object", return_value=None), \
         patch.object(verifier, "_boto3_head_object", return_value=None):
        verified, message, details = verifier.verify_r2_object()
    assert verified is False, "private R2 denial cannot certify object presence"
    assert details["reason_code"] == "AUTHENTICATED_READ_UNAVAILABLE"
    assert "http_diagnostic" not in details
    assert "Cannot verify R2 upload" in message


def test_authenticated_object_missing_is_hard_failure():
    with patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(verifier, "_s3api_head_object",
                      return_value={"status": 404, "content_length": 0, "etag": "", "source": "fake-s3"}):
        verified, message, details = verifier.verify_r2_object()
    assert verified is False
    assert "NOT FOUND" in message


def test_authenticated_matching_s3_head_remains_eligible(tmp_path):
    source = tmp_path / "feed_manifest.json"
    body = b'{"items":[]}' + b" " * 2048
    source.write_bytes(body)
    md5 = hashlib.md5(body, usedforsecurity=False).hexdigest()
    with patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(verifier, "MANIFEST_PATH", source), \
         patch.object(verifier, "_expected_public_manifest_bytes",
                      return_value=(body, {"removed": [], "withheld": False})), \
         patch.object(verifier, "_s3api_head_object",
                      return_value={"status": 200, "content_length": len(body),
                                    "etag": md5, "source": "fake-s3"}):
        verified, _, details = verifier.verify_r2_object()
    assert verified is True
    assert details["etag_check"] == "PASS"


def test_release_workflow_requires_verified_r2_for_every_distribution_boundary():
    workflow = yaml.safe_load((ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["generate-and-sync"]["steps"]
    by_name = {s.get("name"): (i, s) for i, s in enumerate(steps)}
    integrity_name = "STAGE 3.6 - R2 Upload Integrity Verifier (HARD FAIL)"
    i_integrity, verifier_step = by_name[integrity_name]
    assert verifier_step["id"] == "r2-manifest-integrity"
    assert "scripts/r2_upload_verifier.py" in verifier_step["run"]
    assert verifier_step.get("continue-on-error") is not True
    protected = (
        "STAGE 3.7 - Bust Worker KV Cache",
        "STAGE 4.1 - Final R2 Full Sync (v184.0 -- post-git-push complete feed)",
        "Upload Intel State to R2 (final, post-enrichment)",
        "STAGE 4.9.9 - Capture pre-deploy timestamp",
        "STAGE 5 - Deploy to GitHub Pages",
        "STAGE 5.4.9.1 - GitHub Pages Deployment Freshness Gate (v184.1)",
    )
    for name in protected:
        index, step = by_name[name]
        assert index > i_integrity, name
        condition = str(step.get("if", ""))
        assert "steps.r2-manifest-integrity.outcome == 'success'" in condition, name
        assert "!cancelled()" in condition, name


def test_workflow_cannot_treat_r2_integrity_step_as_soft_warning():
    contents = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    assert 'id: r2-manifest-integrity' in contents
    assert 'if: always()\n        run: python3 scripts/bust_kv_cache.py' not in contents


def test_upload_and_verifier_share_private_runner_temp_metadata_contract():
    upload_source = (ROOT / "scripts/r2_upload.py").read_text(encoding="utf-8")
    verifier_source = (ROOT / "scripts/r2_upload_verifier.py").read_text(encoding="utf-8")
    for content in (upload_source, verifier_source):
        assert '"RUNNER_TEMP"' in content
        assert "sentinel-apex-r2" in content
        assert '"/tmp/sync_meta.json"' not in content
    assert "_http_head_diagnostic" not in verifier_source
    assert "urllib.request.urlopen" not in verifier_source


def test_sanitized_manifest_expected_bytes_match_uploader_public_boundary(tmp_path):
    # The uploader invokes this same sanitizer on the same canonical source;
    # the verifier must reconstruct those bytes, not compare against raw.
    import tlp_public_boundary as boundary

    root = tmp_path / "workspace"
    (root / "api").mkdir(parents=True)
    (root / "data" / "stix").mkdir(parents=True)
    src = root / "data" / "stix" / "feed_manifest.json"
    src.write_text(json.dumps({
        "items": [
            {"id": "intel--clear", "title": "Public advisory", "tlp": "TLP:CLEAR"},
            {"id": "intel--red", "title": "Do not publish", "tlp": "TLP:RED",
             "restricted_sentinel": "NEVER_IN_R2"},
        ]
    }), encoding="utf-8")
    parent_paths = [root / "api" / "feed.json",
                    root / "data" / "feed_manifest.json", src]
    parents = boundary.build_parent_index(parent_paths)
    uploader_safe = tmp_path / "upload-sanitized.json"
    boundary.sanitize_json_file(src, uploader_safe, parents=parents)
    with patch.object(verifier, "REPO", root), patch.object(verifier, "MANIFEST_PATH", src):
        expected_bytes, metadata = verifier._expected_public_manifest_bytes()
    assert expected_bytes == uploader_safe.read_bytes()
    assert expected_bytes != src.read_bytes()
    assert b"NEVER_IN_R2" not in expected_bytes
    assert len(metadata["removed"]) >= 1


def test_sanitized_public_bytes_not_raw_producer_are_the_etag_authority(tmp_path):
    raw = tmp_path / "feed_manifest.json"
    raw.write_bytes(b'{"restricted":"internal-source-bytes"}' + b" " * 1500)
    public = b'{"items":[{"id":"intel--approved","tlp":"TLP:CLEAR"}]}' + b" " * 1500
    public_md5 = hashlib.md5(public, usedforsecurity=False).hexdigest()
    with patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(verifier, "MANIFEST_PATH", raw), \
         patch.object(verifier, "_expected_public_manifest_bytes",
                      return_value=(public, {"removed": [{"id": "hidden"}], "withheld": False})), \
         patch.object(verifier, "_s3api_head_object",
                      return_value={"status": 200, "content_length": len(public),
                                    "etag": public_md5, "source": "fake-s3"}):
        ok, _, details = verifier.verify_r2_object()
    assert ok is True
    assert details["etag_check"] == "PASS"
    assert details["expected_public_sha256"] == hashlib.sha256(public).hexdigest()
    assert details["sanitized_records_removed"] == 1
    assert details["expected_public_bytes"] != len(raw.read_bytes())


def test_same_size_but_wrong_public_bytes_cannot_soft_pass():
    body = b"x" * 2048
    with patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(verifier, "_expected_public_manifest_bytes",
                      return_value=(body, {"removed": [], "withheld": False})), \
         patch.object(verifier, "_s3api_head_object",
                      return_value={"status": 200, "content_length": len(body),
                                    "etag": "0" * 32, "source": "fake-s3"}):
        ok, _, details = verifier.verify_r2_object()
    assert ok is False
    assert details["reason_code"] == "PUBLIC_ETAG_MISMATCH"


def test_multipart_etag_without_authenticated_hash_proof_fails_closed():
    body = b"x" * 2048
    with patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(verifier, "_expected_public_manifest_bytes",
                      return_value=(body, {"removed": [], "withheld": False})), \
         patch.object(verifier, "_s3api_head_object",
                      return_value={"status": 200, "content_length": len(body),
                                    "etag": "abcd-2", "source": "fake-s3"}):
        ok, _, details = verifier.verify_r2_object()
    assert ok is False
    assert details["reason_code"] == "ETAG_UNVERIFIABLE"


def test_workflow_verifies_uploaded_manifest_before_report_retirement(tmp_path):
    """Replay the real workflow order: retirement mutates canonical upload input."""
    import r2_report_publisher as publisher

    root = tmp_path / "workspace"
    manifest = root / "data" / "stix" / "feed_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"items": [{
        "id": "intel--retired", "title": "Public source advisory " * 100,
        "tlp": "TLP:CLEAR", "report_url": "/reports/retired.html",
        "internal_report_url": "/reports/retired.html", "pdf_url": "/reports/retired.pdf",
    }]}), encoding="utf-8")
    workflow = yaml.safe_load((ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8"))
    names = [step.get("name") for step in workflow["jobs"]["generate-and-sync"]["steps"]]
    uploaded = None
    verified_upload = False

    with patch.object(verifier, "REPO", root), \
         patch.object(verifier, "MANIFEST_PATH", manifest), \
         patch.object(verifier, "CF_ACCOUNT_ID", "account-fixture"), \
         patch.object(verifier, "ACCESS_KEY", "fake-key"), \
         patch.object(verifier, "SECRET_KEY", "fake-secret"), \
         patch.object(publisher, "REPORT_URL_MANIFESTS", [manifest]):
        for name in names:
            if name == "STAGE 3.5 - Upload Intel to Cloudflare R2 (MANDATORY)":
                uploaded, _ = verifier._expected_public_manifest_bytes()
            elif name == "STAGE 3.5a - Bounded 24h Report Publisher (P0 R2 Cost Fix)":
                assert publisher.clear_report_urls({"intel--retired"}, {"intel--retired"}) == []
            elif name == "STAGE 3.6 - R2 Upload Integrity Verifier (HARD FAIL)":
                assert uploaded is not None, "verify only after the mandatory upload"
                head = {"status": 200, "content_length": len(uploaded),
                        "etag": hashlib.md5(uploaded, usedforsecurity=False).hexdigest(),
                        "source": "fixture-s3"}
                with patch.object(verifier, "_s3api_head_object", return_value=head):
                    ok, message, details = verifier.verify_r2_object()
                assert ok, message
                assert details["etag_check"] == "PASS"
                verified_upload = True
        assert verified_upload
        item = json.loads(manifest.read_text(encoding="utf-8"))["items"][0]
        assert all(item[field] == "" for field in ("report_url", "internal_report_url", "pdf_url"))
        # The same strict verifier still rejects changed local input afterward.
        # No uploader-provided checksum or same-size soft pass is introduced.
        with patch.object(verifier, "_s3api_head_object", return_value=head):
            ok, _, details = verifier.verify_r2_object()
        assert ok is False
        assert details["reason_code"] in ("PUBLIC_BYTE_LENGTH_MISMATCH", "PUBLIC_ETAG_MISMATCH")
