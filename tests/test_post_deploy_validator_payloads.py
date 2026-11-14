"""Offline post-deploy contract checks; never contact Cloudflare."""
import sys
from pathlib import Path
from datetime import datetime, timezone
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import post_deploy_validator as validator

@pytest.mark.parametrize('body,valid,count', [
    ({'count': 10}, True, 10), ({'count': 0}, True, 0),
    ({'count': '10'}, False, None), ({'count': True}, False, None),
    ({'count': -1}, False, None), ({'count': 10.5}, False, None),
    ({'count': {}}, False, None), ({'count': None}, False, None),
    ({}, False, None), ([], False, None), ('unexpected', False, None),
])
def test_untrusted_feed_payloads_and_single_snapshot(tmp_path, monkeypatch, body, valid, count):
    calls = []
    if isinstance(body, dict):
        body = dict(body, generated_at=datetime.now(timezone.utc).isoformat())
    def probe(url, **kwargs):
        calls.append(url)
        payload = body
        if url.endswith('/api/health/live'):
            payload = {'version': 'test'}
        elif url.endswith('/api/health'):
            payload = {'checks': {'jwt_configured': True, 'r2_intel': 'ok'}}
        return {'ok': True, 'body': payload, 'status': 200, 'latency_ms': 1, 'error': None}
    monkeypatch.setattr(validator, 'probe_json', probe)
    monkeypatch.setattr(validator, 'REPO_ROOT', tmp_path)
    monkeypatch.setenv('ADMIN_SECRET', 'offline-test')
    monkeypatch.setattr(validator._deploy_health, 'probe', lambda base: (None, None))
    monkeypatch.setattr(validator._deploy_health, 'evaluate_deployment', lambda *args: {
        'health': {'http_status': 200}, 'deployment_operational': True,
        'failures': [], 'customer_intelligence_state': 'fresh',
        'customer_intelligence_healthy': True, 'liveness': {'alive': True},
    })
    result, code = validator.run_validation('test')
    gate = result['gates']['D']
    assert gate['measurement_valid'] is valid
    assert gate.get('count') == count
    assert ('count' in gate) is valid
    assert gate['measurement_state'] == ('MEASURED' if valid else 'INVALID_OR_UNAVAILABLE')
    assert gate['passed'] is (valid and count >= validator.MIN_ADVISORY_COUNT)
    assert calls.count(f'{validator.WORKER_BASE}/api/v1/intel/latest.json') == 1
    assert result['overall'] == ('ALL_PASSED' if valid and count >= 10 else 'SOFT_WARNINGS')
    assert code == 0  # Existing operational gate policy is preserved.
    assert (tmp_path / 'data/health/last_deploy_validation.json').is_file()


APPROVED_SHA = "a" * 40
OLD_DEPLOY_SHA = "b" * 40


def _all_good_gates():
    return {key: {"passed": True} for key in ("A", "B", "C", "D", "E", "F")}


@pytest.mark.parametrize("approved,live,healthy,gates_ok,expected", [
    (APPROVED_SHA, APPROVED_SHA, True, True, True),
    (APPROVED_SHA, OLD_DEPLOY_SHA, True, True, False),
    (APPROVED_SHA, APPROVED_SHA, False, True, False),
    (APPROVED_SHA, APPROVED_SHA, True, False, False),
    ("", APPROVED_SHA, True, True, False),
    ("not-a-commit", "not-a-commit", True, True, False),
])
def test_strict_readiness_requires_exact_deployed_sha_fresh_intel_and_all_gates(
    approved, live, healthy, gates_ok, expected
):
    gates = _all_good_gates()
    if not gates_ok:
        gates["F"]["passed"] = False
    result = validator.evaluate_customer_intel_readiness(
        gates, {"customer_intelligence_healthy": healthy}, approved, live
    )
    assert result["gateway_readiness_passed"] is expected
    assert result["worldwide_customer_release_certified"] is False
    assert result["paid_entitlement_certified"] is False
    assert result["all_customer_reports_certified"] is False


def test_strict_mode_refuses_invalid_sha_without_network(monkeypatch):
    monkeypatch.setattr(validator, "probe_json", lambda *a, **k: pytest.fail("must not call network"))
    with pytest.raises(ValueError, match="EXACT_40_CHAR_APPROVED_SHA"):
        validator.run_validation("201.0", expected_deploy_sha="short",
                                 strict_customer_readiness=True)


def test_old_worker_sha_blocks_strict_release_but_not_operational_gate(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    def probe(url, **kwargs):
        if url.endswith("/api/health/live"):
            payload = {"version": "201.0", "deploy_commit_sha": OLD_DEPLOY_SHA}
        elif url.endswith("/api/health"):
            payload = {"checks": {"jwt_configured": True, "r2_intel": "ok"}}
        else:
            payload = {"count": 15, "generated_at": datetime.now(timezone.utc).isoformat()}
        return {"ok": True, "body": payload, "status": 200, "latency_ms": 1, "error": None}

    monkeypatch.setattr(validator, "probe_json", probe)
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    monkeypatch.setenv("ADMIN_SECRET", "offline-test")
    monkeypatch.setattr(validator._deploy_health, "probe", lambda base: (None, None))
    monkeypatch.setattr(validator._deploy_health, "evaluate_deployment", lambda *args: {
        "health": {"http_status": 200}, "deployment_operational": True,
        "failures": [], "customer_intelligence_state": "fresh",
        "customer_intelligence_healthy": True, "liveness": {"alive": True},
    })

    normal, normal_code = validator.run_validation("201.0")
    assert normal_code == 0
    assert normal["worldwide_customer_release_certified"] is False

    strict, strict_code = validator.run_validation(
        "201.0", expected_deploy_sha=APPROVED_SHA, strict_customer_readiness=True
    )
    assert strict_code == 1
    assert strict["overall"] == "GATEWAY_READINESS_BLOCKED"
    assert strict["gates"]["G"]["passed"] is False
    assert strict["gateway_readiness"]["failures"] == [
        "DEPLOYED_WORKER_SHA_UNVERIFIED_OR_MISMATCH"
    ]


def test_strict_mode_is_only_gateway_evidence_not_paid_delivery(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    def probe(url, **kwargs):
        if url.endswith("/api/health/live"):
            payload = {"version": "201.0", "deploy_commit_sha": APPROVED_SHA}
        elif url.endswith("/api/health"):
            payload = {"checks": {"jwt_configured": True, "r2_intel": "ok"}}
        else:
            payload = {"count": 15, "generated_at": datetime.now(timezone.utc).isoformat()}
        return {"ok": True, "body": payload, "status": 200, "latency_ms": 1, "error": None}

    monkeypatch.setattr(validator, "probe_json", probe)
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    monkeypatch.setenv("ADMIN_SECRET", "offline-test")
    monkeypatch.setattr(validator._deploy_health, "probe", lambda base: (None, None))
    monkeypatch.setattr(validator._deploy_health, "evaluate_deployment", lambda *args: {
        "health": {"http_status": 200}, "deployment_operational": True,
        "failures": [], "customer_intelligence_state": "fresh",
        "customer_intelligence_healthy": True, "liveness": {"alive": True},
    })

    result, code = validator.run_validation(
        "201.0", expected_deploy_sha=APPROVED_SHA, strict_customer_readiness=True
    )
    assert code == 0
    assert result["overall"] == "GATEWAY_READINESS_PASSED_NOT_WORLDWIDE_RELEASE"
    assert result["gateway_readiness"]["deployed_source_parity_passed"] is True
    assert result["worldwide_customer_release_certified"] is False
    assert result["gateway_readiness"]["paid_entitlement_certified"] is False
