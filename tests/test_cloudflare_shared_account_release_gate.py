"""No-network negative controls for the shared Cloudflare account release decision."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ops/cloudflare_shared_account_release_gate.py"
POLICY = ROOT / "config/cloudflare_shared_account_zero_overage.json"
spec = importlib.util.spec_from_file_location("shared_cloudflare_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@pytest.fixture
def policy():
    return json.loads(POLICY.read_text(encoding="utf-8"))


@pytest.fixture
def snapshot(policy):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = (now - timedelta(days=1)).isoformat()
    end = (now + timedelta(days=15)).isoformat()
    return {
        "schema_version": 1,
        "source": "cloudflare_account_billing_and_analytics",
        "owner_verified": True,
        "current_account_plan_verified": True,
        "all_platforms_accounted_for": True,
        "all_billing_products_accounted_for": True,
        "platform_ids": [f"platform-{i}" for i in range(10)],
        "plan_change": False,
        "new_paid_resource": False,
        "new_cron_trigger": False,
        "unbounded_r2_sync": False,
        "manual_override": False,
        "usage_based_overage_usd": "0",
        "projected_usage_overage_usd": "0",
        "as_of_utc": now.isoformat(),
        "metrics": {
            metric: {
                "included": "1000", "used_account_wide": "100",
                "forecast_all_platforms_until_reset": "200",
                "proposed_increment_until_reset": "10",
                "unit": "per-billing-metric",
                "window_start_utc": start, "window_end_utc": end
            } for metric in policy["minimum_required_metrics"]
        },
    }


def test_static_policy_is_pinned_fail_closed(policy):
    assert gate.validate_policy(policy)["max_usage_based_overage_usd"] == "0"
    assert gate.main(["--validate-policy"]) == 0
    assert gate.main([]) == 2  # Missing actual account evidence never means GO.


def test_synthetic_ten_platform_snapshot_is_conditionally_admissible(policy, snapshot):
    result = gate.certify(policy, snapshot)
    assert result["verdict"] == "CONDITIONAL_ALLOW_ON_REVIEWED_SNAPSHOT"
    assert result["metrics"]["r2_class_a"]["unallocated_after_forecast"] == "490.0"
    assert "NOT" in result["qualification"]


@pytest.mark.parametrize("change", [
    ("owner_verified", False),
    ("current_account_plan_verified", False),
    ("all_platforms_accounted_for", False),
    ("all_billing_products_accounted_for", False),
    ("plan_change", True),
    ("new_paid_resource", True),
    ("new_cron_trigger", True),
    ("unbounded_r2_sync", True),
    ("manual_override", True),
    ("usage_based_overage_usd", "0.01"),
    ("projected_usage_overage_usd", "0.01"),
    ("source", "self_report_unverified")
])
def test_unauthorized_or_incomplete_account_claims_are_blocked(policy, snapshot, change):
    snapshot[change[0]] = change[1]
    with pytest.raises(gate.ReleaseBlocked):
        gate.certify(policy, snapshot)


def test_only_nine_platforms_rejected(policy, snapshot):
    snapshot["platform_ids"].pop()
    with pytest.raises(gate.ReleaseBlocked, match="ten"):
        gate.certify(policy, snapshot)


def test_missing_metric_rejected(policy, snapshot):
    del snapshot["metrics"]["r2_class_a"]
    with pytest.raises(gate.ReleaseBlocked, match="r2_class_a"):
        gate.certify(policy, snapshot)


def test_stale_snapshot_rejected(policy, snapshot):
    snapshot["as_of_utc"] = (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
    with pytest.raises(gate.ReleaseBlocked, match="too old"):
        gate.certify(policy, snapshot)


def test_future_dated_snapshot_rejected(policy, snapshot):
    snapshot["as_of_utc"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with pytest.raises(gate.ReleaseBlocked, match="future"):
        gate.certify(policy, snapshot)


@pytest.mark.parametrize("key,value", [
    ("included", 0), ("included", "NaN"), ("included", "-1"),
    ("used_account_wide", "Infinity"), ("used_account_wide", True),
    ("forecast_all_platforms_until_reset", "-0.1"),
    ("proposed_increment_until_reset", "700")
])
def test_invalid_or_excessive_metric_blocks(policy, snapshot, key, value):
    snapshot["metrics"]["r2_class_a"][key] = value
    with pytest.raises(gate.ReleaseBlocked):
        gate.certify(policy, snapshot)


def test_unused_no_included_allowance_is_safe_but_any_usage_blocks(policy, snapshot):
    zero = snapshot["metrics"]["r2_class_a"]
    zero.update(included="0", used_account_wide="0",
                forecast_all_platforms_until_reset="0",
                proposed_increment_until_reset="0")
    assert gate.certify(policy, snapshot)["metrics"]["r2_class_a"]["included"] == "0"
    zero["proposed_increment_until_reset"] = "0.01"
    with pytest.raises(gate.ReleaseBlocked, match="no included allowance"):
        gate.certify(policy, snapshot)


def test_missing_billing_unit_rejected(policy, snapshot):
    snapshot["metrics"]["r2_class_a"].pop("unit")
    with pytest.raises(gate.ReleaseBlocked, match="unit"):
        gate.certify(policy, snapshot)


def test_insufficient_headroom_after_ten_platform_forecast_is_blocked(policy, snapshot):
    snapshot["metrics"]["r2_class_a"]["used_account_wide"] = 599
    snapshot["metrics"]["r2_class_a"]["forecast_all_platforms_until_reset"] = 200
    snapshot["metrics"]["r2_class_a"]["proposed_increment_until_reset"] = 2
    with pytest.raises(gate.ReleaseBlocked, match="safety envelope"):
        gate.certify(policy, snapshot)


def test_quota_window_expired_blocks(policy, snapshot):
    snapshot["metrics"]["r2_class_a"]["window_end_utc"] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    with pytest.raises(gate.ReleaseBlocked):
        gate.certify(policy, snapshot)


def test_policy_cannot_be_relaxed_silently(policy):
    policy["controls"]["allow_plan_upgrade"] = True
    with pytest.raises(gate.ReleaseBlocked):
        gate.validate_policy(policy)
    policy["controls"]["allow_plan_upgrade"] = False
    policy["minimum_unallocated_headroom_percent"] = 0
    with pytest.raises(gate.ReleaseBlocked):
        gate.validate_policy(policy)


def test_cli_is_read_only_and_never_contacts_cloudflare(tmp_path, policy, snapshot):
    file = tmp_path / "snapshot.json"
    file.write_text(json.dumps(snapshot))
    completed = subprocess.run([sys.executable, str(SCRIPT), "--attestation", str(file)],
                               capture_output=True, text=True, timeout=8)
    assert completed.returncode == 0, completed.stderr
    assert "CONDITIONAL_ALLOW" in completed.stdout
    assert "NOT a live Cloudflare spending cap" in completed.stdout
    snapshot["metrics"]["kv_writes"]["proposed_increment_until_reset"] = "10000"
    file.write_text(json.dumps(snapshot))
    blocked = subprocess.run([sys.executable, str(SCRIPT), "--attestation", str(file)],
                             capture_output=True, text=True, timeout=8)
    assert blocked.returncode == 2
    assert "BLOCK:" in blocked.stderr


def test_existing_finops_gate_cannot_skip_shared_account_zero_overage_contract():
    workflow = (ROOT / ".github/workflows/r2-finops-regression-gate.yml").read_text(encoding="utf-8")
    assert "ops/cloudflare_shared_account_release_gate.py --validate-policy" in workflow
    assert "tests/test_cloudflare_shared_account_release_gate.py" in workflow
    assert "'config/cloudflare_shared_account_zero_overage.json'" in workflow
    assert "'ops/cloudflare_shared_account_release_gate.py'" in workflow
    assert "'tests/test_cloudflare_shared_account_release_gate.py'" in workflow
