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
              "kv_reads": "4000", "kv_lists": "8"}
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
    ("kv_reads", "3999"), ("kv_lists", "7")])
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
