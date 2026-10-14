"""No-network P0 negative controls for optional Cloudflare KV/R2 backup spend."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "ops"))

import cloudflare_metered_backup_guard as fence  # noqa: E402
import backup_kv_to_r2 as kv  # noqa: E402
import backup_r2 as r2  # noqa: E402
from r2_cost_guard import R2OperationPlan  # noqa: E402

POLICY = json.loads((ROOT / "config/cloudflare_shared_account_zero_overage.json").read_text())


def attestation():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = (now - timedelta(days=1)).isoformat()
    end = (now + timedelta(days=5)).isoformat()
    deltas = {"r2_class_a": "105", "r2_class_b": "500",
              "kv_reads": "4000", "kv_lists": "8",
              "r2_standard_storage_gb_month": "0.1"}
    return {
        "schema_version": 1, "source": "cloudflare_account_billing_and_analytics",
        "owner_verified": True, "current_account_plan_verified": True,
        "all_billing_products_accounted_for": True,
        "all_platforms_accounted_for": True,
        "platform_ids": [f"p{i}" for i in range(10)],
        "plan_change": False, "new_paid_resource": False,
        "new_cron_trigger": False, "unbounded_r2_sync": False,
        "manual_override": False,
        "usage_based_overage_usd": "0", "projected_usage_overage_usd": "0",
        "as_of_utc": now.isoformat(),
        "metrics": {
            key: {
                "included": "1000000", "used_account_wide": "100",
                "forecast_all_platforms_until_reset": "1000",
                "proposed_increment_until_reset": deltas.get(key, "0"),
                "unit": "source-verified metric units",
                "window_start_utc": start, "window_end_utc": end,
                "usage_measured_through_utc": now.isoformat()
            } for key in POLICY["minimum_required_metrics"]
        }
    }


def test_no_approval_blocks_before_billing_snapshot_read():
    with pytest.raises(fence.MeteredBackupDenied):
        fence.require_metered_backup_permit(environ={})


def test_approval_without_real_snapshot_still_blocks():
    with pytest.raises(fence.MeteredBackupDenied):
        fence.require_metered_backup_permit(
            environ={"CDB_CF_METERED_BACKUP_APPROVED": "true"})


def test_complete_fresh_ten_platform_snapshot_conditionally_admits():
    fence.require_metered_backup_permit(environ={
        "CDB_CF_METERED_BACKUP_APPROVED": "true",
        "CDB_CF_ACCOUNT_ATTESTATION_JSON": json.dumps(attestation()),
    })


@pytest.mark.parametrize("metric,amount", [
    ("r2_class_a", "104"), ("r2_class_b", "499"),
    ("kv_reads", "3999"), ("kv_lists", "7"),
    ("r2_standard_storage_gb_month", "0.09")])
def test_understated_metered_cost_estimates_block(metric, amount):
    report = attestation()
    report["metrics"][metric]["proposed_increment_until_reset"] = amount
    with pytest.raises(fence.MeteredBackupDenied):
        fence.require_metered_backup_permit(environ={
            "CDB_CF_METERED_BACKUP_APPROVED": "true",
            "CDB_CF_ACCOUNT_ATTESTATION_JSON": json.dumps(report)})


def test_telemetry_stale_even_with_fresh_owner_export_blocks():
    report = attestation()
    report["metrics"]["r2_class_a"]["usage_measured_through_utc"] = (
        datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(fence.MeteredBackupDenied):
        fence.require_metered_backup_permit(environ={
            "CDB_CF_METERED_BACKUP_APPROVED": "true",
            "CDB_CF_ACCOUNT_ATTESTATION_JSON": json.dumps(report)})


def test_r2_without_permit_cannot_obtain_client(monkeypatch):
    monkeypatch.setattr(r2, "r2_credentials_configured", lambda: True)
    monkeypatch.setattr(r2, "require_metered_backup_permit",
                        lambda: (_ for _ in ()).throw(fence.MeteredBackupDenied("blocked")))
    monkeypatch.setattr(r2, "get_s3",
                        lambda: pytest.fail("Cloudflare client must not be created"))
    with pytest.raises(SystemExit) as ex:
        r2.main()
    assert ex.value.code == 2


def test_kv_without_permit_cannot_list_or_fetch(monkeypatch):
    monkeypatch.setattr(kv, "require_metered_backup_permit",
                        lambda: (_ for _ in ()).throw(fence.MeteredBackupDenied("blocked")))
    monkeypatch.setattr(kv, "cf_get",
                        lambda *a, **k: pytest.fail("Cloudflare must not be called"))
    with pytest.raises(SystemExit) as ex:
        kv.main()
    assert ex.value.code == 2


def test_r2_inventory_terminates_after_at_most_100_pages_and_no_upload(monkeypatch):
    class Paginator:
        def paginate(self, **kwargs):
            for i in range(150):
                yield {"Contents": []}
    class Client:
        def get_paginator(self, what):
            assert what == "list_objects_v2"
            return Paginator()
        def put_object(self, **kwargs):
            pytest.fail("Oversize R2 inventory must not upload")
    plan = R2OperationPlan(label="test")
    assert r2.list_objects(Client(), "sentinel-apex-data", plan=plan) is None
    assert plan.list_calls == 100


def test_kv_oversize_cursor_denies_before_fetching_any_values(monkeypatch):
    calls = []
    def fake_get(path, params):
        calls.append(path)
        return {"success": True, "result": [{"name": f"k{i}"} for i in range(500)],
                "result_info": {"cursor": "more-data"}}
    monkeypatch.setattr(kv, "cf_get", fake_get)
    monkeypatch.setattr(kv, "get_kv_value",
                        lambda *args: pytest.fail("oversize namespace must not GET"))
    assert kv.backup_namespace("SECURITY_HUB_KV", "test-ns", False) is None
    assert len(calls) == 1


def test_transient_kv_value_failure_refuses_incomplete_snapshot(monkeypatch):
    monkeypatch.setattr(kv, "list_kv_keys", lambda *args: ["k1", "k2"])
    monkeypatch.setattr(kv, "get_kv_value",
                        lambda _ns, key: None if key == "k2" else "verified")
    assert kv.backup_namespace("API_KEYS_KV", "fake", False) is None


def test_optional_cloudflare_backup_job_is_dormant_by_default():
    wf = (ROOT / ".github/workflows/automated-backup.yml").read_text(encoding="utf-8")
    assert "vars.CDB_CF_METERED_BACKUP_APPROVED == 'true'" in wf
    assert "secrets.CDB_CF_ACCOUNT_ATTESTATION_JSON" in wf
    assert "python3 scripts/cloudflare_metered_backup_guard.py" in wf
    assert wf.index("python3 scripts/cloudflare_metered_backup_guard.py") < wf.index("python3 scripts/backup_kv_to_r2.py")
    assert wf.index("python3 scripts/cloudflare_metered_backup_guard.py") < wf.index("python3 scripts/backup_r2.py")
    # Core encrypted backup is independent and continues normally.
    assert "full-backup:" in wf
    assert "CDB_BACKUP_ENABLED:" in wf


def test_scripts_fail_before_cloudflare_network_without_valid_budget():
    r2_src = (ROOT / "scripts/backup_r2.py").read_text(encoding="utf-8")
    kv_src = (ROOT / "scripts/backup_kv_to_r2.py").read_text(encoding="utf-8")
    assert r2_src.index("require_metered_backup_permit()") < r2_src.index("s3 = get_s3()")
    assert kv_src.index("require_metered_backup_permit()") < kv_src.index("today = datetime.datetime.utcnow()")
    assert '"/tmp/kv_backup_' not in kv_src



def test_oversized_kv_payload_never_sends_r2_put(monkeypatch):
    class Client:
        def put_object(self, **kwargs):
            pytest.fail("Oversized KV payload must not touch Cloudflare")
    monkeypatch.setattr(kv.boto3, "client", lambda *args, **kwargs: Client())
    monkeypatch.setattr(kv, "CF_R2_ACCESS_KEY", "test")
    monkeypatch.setattr(kv, "CF_R2_SECRET_KEY", "test")
    monkeypatch.setattr(kv, "CF_R2_ENDPOINT", "https://example.invalid")
    too_big = {"entries": {"k": "x" * (kv.MAX_SNAPSHOT_BYTES + 1)}}
    assert kv.upload_to_r2("test.json", too_big) is False


def test_oversized_r2_manifest_never_sends_put(monkeypatch):
    class Client:
        def put_object(self, **kwargs):
            pytest.fail("Oversized R2 manifest must not be written")
    plan = R2OperationPlan(label="test")
    too_big = {"bucket": "sentinel-apex-data",
               "objects": [{"k": "z" * (r2.MAX_MANIFEST_BYTES + 1)}]}
    assert r2.upload_manifest(Client(), too_big, "sentinel-apex-data", "2026-10-14", plan) is False
    assert plan.put == 0



def test_primary_encrypted_backup_r2_target_needs_same_permit(monkeypatch):
    from agent.backup import backup_engine
    monkeypatch.setattr(backup_engine, "_BACKUP_DESTINATION", "r2")
    monkeypatch.delenv("CDB_CF_METERED_BACKUP_APPROVED", raising=False)
    monkeypatch.delenv("CDB_CF_ACCOUNT_ATTESTATION_JSON", raising=False)
    with pytest.raises(fence.ReleaseBlocked):
        backup_engine._get_storage()
    # Existing local encrypted-backup route never needs a Cloudflare permit.
    monkeypatch.setattr(backup_engine, "_BACKUP_DESTINATION", "local")
    assert backup_engine._get_storage().__class__.__name__ == "_LocalStorage"


def test_full_backup_includes_private_account_evidence_when_r2_opted_in():
    wf = (ROOT / ".github/workflows/automated-backup.yml").read_text(encoding="utf-8")
    primary = wf[wf.index("  full-backup:"):wf.index("  cf-data-backup:")]
    assert "CDB_CF_ACCOUNT_ATTESTATION_JSON:" in primary
    assert "CDB_CF_METERED_BACKUP_APPROVED:" in primary
    source = (ROOT / "agent/backup/backup_engine.py").read_text(encoding="utf-8")
    start = source.index('elif dest in ("r2", "cloudflare"):')
    assert source.index("require_metered_backup_permit()", start) < source.index(
        "return _S3Storage(_BACKUP_R2_BUCKET", start)



@pytest.mark.parametrize("url", [
    "http://api.cloudflare.com/client/v4/accounts/xxx/storage/kv",
    "https://evil.example/client/v4/accounts/xxx/storage/kv",
    "https://api.cloudflare.com.evil.example/client/v4/accounts/xxx/storage/kv",
    "https://api.cloudflare.com@evil.example/client/v4/accounts/xxx/storage/kv",
    "https://api.cloudflare.com/public/other",
    "ftp://api.cloudflare.com/client/v4/accounts/xxx",
])
def test_authenticated_cloudflare_kv_request_denies_untrusted_origin(monkeypatch, url):
    from urllib.request import Request
    monkeypatch.setattr(
        kv.urllib.request, "build_opener",
        lambda *args: pytest.fail("Rejected URL must not open network transport"))
    req = Request(url, headers={"Authorization": "Bearer canary-not-real"})
    with pytest.raises(ValueError, match="fixed HTTPS origin"):
        kv._cloudflare_open(req, timeout=1)


def test_authenticated_cloudflare_kv_request_uses_only_no_redirect_opener(monkeypatch):
    from urllib.request import Request
    captured = {}
    class LocalOpener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return "injected-local-only"
    def fake_builder(handler):
        captured["handler_class"] = handler
        return LocalOpener()
    monkeypatch.setattr(kv.urllib.request, "build_opener", fake_builder)
    url = "https://api.cloudflare.com/client/v4/accounts/test/storage/kv"
    result = kv._cloudflare_open(Request(url, headers={"Authorization": "Bearer canary-not-real"}), timeout=3)
    assert result == "injected-local-only"
    assert captured["timeout"] == 3
    assert issubclass(captured["handler_class"], kv.urllib.request.HTTPRedirectHandler)
    assert captured["handler_class"]().redirect_request(None, None, 302, "redirect", {}, "https://evil.example") is None


def test_r2_manifest_put_failure_has_no_plaintext_temp_fallback(tmp_path, monkeypatch):
    class RejectPut:
        def put_object(self, **kw):
            raise r2.ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "PutObject")
    monkeypatch.chdir(tmp_path)
    plan = R2OperationPlan(label="r2_backup_failure")
    assert not r2.upload_manifest(RejectPut(), {"bucket": "sentinel-apex-data", "objects": []},
                                  "sentinel-apex-data", "2026-10-14", plan)
    assert plan.put == 0
    assert not list(tmp_path.glob("**/*.json"))
    assert "/tmp/r2_manifest_" not in (ROOT / "scripts/backup_r2.py").read_text()
