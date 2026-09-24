#!/usr/bin/env python3
"""
tests/test_deployment_health_contract.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- release-gate health contract drift guard.

INCIDENT (2026-09-24): after PR #488 the Worker truthfully answers
/api/health 503 while intelligence is stale. post-deploy-validation.yml
GATE A (and post_deploy_validator.py GATE A) still required /api/health
== 200 as an *availability* probe, so a live, healthy Worker deploy
(/api/health/live 200) failed validation because the feed was stale.

Contract pinned here (scripts/deployment_health_contract.py):
  * Worker availability = /api/health/live (200, alive, sentinel-apex, version).
  * /api/health is evaluated as a structured contract: 200 ok/fresh, or a
    VALID SENTINEL 503 (degraded / unhealthy with a contract reason).
    Generic/HTML/malformed 503s, contradictions and exposed secret/config
    fields fail deployment.
  * Deployment "operational" never implies customer-healthy: the release
    freshness gate (STAGE 5.9.10, public_feed_freshness_gate.py) keeps
    failing until the feed is genuinely fresh.

Scenario letters follow the P0 remediation brief (A-M). Every PASS scenario
is paired with a negative control that must FAIL.
"""
import copy
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import deployment_health_contract as dhc  # noqa: E402
import public_feed_freshness_gate as gate  # noqa: E402

NOW = datetime(2026, 9, 24, 6, 0, 0, tzinfo=timezone.utc)
INCIDENT_GENERATED_AT = "2026-08-26T09:55:27Z"  # production feed on 2026-09-24 before recovery
VERSION = "200.0"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


FRESH_AT = _iso(NOW - timedelta(minutes=10))

LIVE_OK = (200, {"status": "alive", "service": "sentinel-apex", "version": VERSION,
                 "generated_at": "2026-09-24T06:00:00.000Z"}, None)


def _health(status, reason, intel_status, generated_at, count=49):
    """Body exactly as workers/intel-gateway/src/index.js builds the PUBLIC view."""
    body = {
        "status": status, "service": "sentinel-apex", "version": VERSION,
        "advisory_count": count, "critical_count": 13, "kev_confirmed": 4,
        "last_sync": generated_at, "feed_index": f"live:{count}_items", "platform_reachable": True,
        "intelligence_available": count > 0,
        "intelligence": {"status": intel_status, "generated_at": generated_at,
                         "age_seconds": 600, "max_age_seconds": 21600, "advisory_count": count},
        "checks": {"gateway": "ok", "worker_runtime": "ok",
                   "intelligence_available": "ok" if count else "empty",
                   "intelligence_freshness": intel_status, "publication_integrity": "ok",
                   "feed_index": f"live:{count}_items"},
        "generated_at": "2026-09-24T06:00:00.000Z",
    }
    if reason:
        body["reason"] = reason
    return body


HEALTH_FRESH = (200, _health("ok", None, "fresh", FRESH_AT), None)
HEALTH_STALE = (503, _health("degraded", "intelligence_stale", "stale", INCIDENT_GENERATED_AT), None)
_unavail = _health("unhealthy", "feed_unavailable", "unavailable", None, count=0)
_unavail["checks"].update(intelligence_available="unavailable", intelligence_freshness="unknown",
                          publication_integrity="unknown")
HEALTH_UNAVAILABLE = (503, _unavail, None)


def deploy(live, health):
    return dhc.evaluate_deployment(live, health, now=NOW)


def feed_body(generated_at, n=49):
    return {"generated_at": generated_at, "count": n, "items": [{"id": f"intel--{i}"} for i in range(n)]}


# ── A: live 200 + health 200 fresh -> PASS ──────────────────────────────────

def test_A_live_and_fresh_health_pass():
    r = deploy(LIVE_OK, HEALTH_FRESH)
    assert r["deployment_verdict"] == "PASS", r["failures"]
    assert r["customer_intelligence_state"] == "healthy"
    assert r["customer_intelligence_healthy"] is True
    assert r["release_freshness_certifiable"] is True


# ── B: live 200 + valid stale 503 -> deploy PASS, release FAIL ──────────────

def test_B_valid_stale_503_is_operational_but_not_releasable():
    r = deploy(LIVE_OK, HEALTH_STALE)
    assert r["deployment_verdict"] == "PASS", r["failures"]
    assert r["customer_intelligence_state"] == "degraded"
    assert r["customer_intelligence_healthy"] is False
    assert r["release_freshness_certifiable"] is False
    # and the release gate over the same production state still fails
    rel = gate.evaluate(200, feed_body(INCIDENT_GENERATED_AT), None, *HEALTH_STALE, now=NOW)
    assert rel["verdict"] == "FAIL"


# ── C: live 200 + valid unavailable 503 -> operational, release blocked ─────

@pytest.mark.parametrize("reason,intel_status", [
    ("feed_unavailable", "unavailable"), ("invalid_feed_structure", "invalid"),
    ("no_intelligence_items", "fresh"), ("publication_count_mismatch", "fresh"),
    ("generated_at_in_future", "future_timestamp"), ("generated_at_missing", "missing_timestamp"),
    ("generated_at_invalid", "invalid_timestamp"),
])
def test_C_valid_unhealthy_503_is_operational_release_blocked(reason, intel_status):
    body = _health("unhealthy", reason, intel_status, FRESH_AT if intel_status == "fresh" else None)
    r = deploy(LIVE_OK, (503, body, None))
    assert r["deployment_verdict"] == "PASS", r["failures"]
    assert r["customer_intelligence_state"] == "unhealthy"
    assert r["release_freshness_certifiable"] is False


# ── D/E/F: liveness failures ────────────────────────────────────────────────

@pytest.mark.parametrize("live", [
    pytest.param((404, {"error": "not found"}, None), id="D-live-404"),
    pytest.param((404, dict(LIVE_OK[1]), None), id="D-live-404-alive-body"),
    pytest.param((500, {"error": "Internal"}, None), id="E-live-500"),
    pytest.param((500, dict(LIVE_OK[1]), None), id="E-live-500-alive-body"),
    pytest.param((200, None, "invalid JSON: Expecting value"), id="F-live-malformed"),
    pytest.param((200, {"status": "ok", "service": "sentinel-apex", "version": VERSION}, None), id="F-live-wrong-status"),
    pytest.param((200, {"status": "alive", "service": "other", "version": VERSION}, None), id="F-live-wrong-service"),
    pytest.param((200, {"status": "alive", "service": "sentinel-apex"}, None), id="F-live-no-version"),
    pytest.param((None, None, "URLError: timed out"), id="F-live-unreachable"),
])
@pytest.mark.parametrize("health", [HEALTH_FRESH, HEALTH_STALE], ids=["fresh", "stale"])
def test_DEF_liveness_failure_fails_deployment(live, health):
    r = deploy(live, health)
    assert r["deployment_verdict"] == "FAIL"
    assert r["liveness"]["alive"] is False


# ── G/H: generic 503s are NOT a valid degraded state ────────────────────────

@pytest.mark.parametrize("health", [
    pytest.param((503, None, "invalid JSON: Expecting value: line 1 column 1"), id="G-cloudflare-html-503"),
    pytest.param((503, None, "empty body"), id="G-empty-503"),
    pytest.param((503, {"error": "Service Unavailable"}, None), id="G-generic-json-503"),
    pytest.param((503, None, "invalid JSON: Unterminated string"), id="H-malformed-json-503"),
    pytest.param((503, ["degraded"], None), id="H-json-array-503"),
    pytest.param((500, {"error": "Worker threw exception"}, None), id="uncaught-exception-500"),
    pytest.param((502, None, "invalid JSON"), id="gateway-502"),
    pytest.param((None, None, "ConnectionResetError"), id="unreachable"),
])
def test_GH_generic_or_malformed_health_fails(health):
    r = deploy(LIVE_OK, health)
    assert r["deployment_verdict"] == "FAIL"
    assert r["customer_intelligence_state"] == "invalid"


def test_G_real_cloudflare_error_page_bytes_fail_through_fetch_parser(monkeypatch):
    html = b"<!DOCTYPE html><html><head><title>Error 503 | intel.cyberdudebivash.com | Cloudflare</title>"

    class _Resp:
        status = 503

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return html
    monkeypatch.setattr(dhc.urllib.request, "urlopen", lambda req, timeout: _Resp())
    status, body, err = dhc.fetch_json("https://x/api/health", 1)
    assert (status, body) == (503, None) and "invalid JSON" in err
    assert deploy(LIVE_OK, (status, body, err))["deployment_verdict"] == "FAIL"


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda b: b.update(service="other-service"), id="wrong-service"),
    pytest.param(lambda b: b.pop("service"), id="no-service"),
    pytest.param(lambda b: b.update(status="error"), id="non-contract-status"),
    pytest.param(lambda b: b.pop("intelligence"), id="no-intelligence-object"),
    pytest.param(lambda b: b.pop("checks"), id="no-checks-object"),
    pytest.param(lambda b: b["checks"].update(worker_runtime="error"), id="worker-runtime-not-ok"),
    pytest.param(lambda b: b.pop("reason"), id="degraded-without-reason"),
    pytest.param(lambda b: b.update(reason="something_else"), id="degraded-unknown-reason"),
    pytest.param(lambda b: b.update(version="199.0"), id="stale-worker-version"),
])
def test_invalid_structured_503_fails(mutate):
    body = copy.deepcopy(HEALTH_STALE[1])
    mutate(body)
    assert deploy(LIVE_OK, (503, body, None))["deployment_verdict"] == "FAIL"


def test_unhealthy_with_unknown_or_mismatched_reason_fails():
    assert deploy(LIVE_OK, (503, _health("unhealthy", "boom", "unavailable", None), None))["deployment_verdict"] == "FAIL"
    assert deploy(LIVE_OK, (503, _health("unhealthy", "feed_unavailable", "fresh", FRESH_AT), None))["deployment_verdict"] == "FAIL"


# ── I: 200 but body stale/degraded -> contradiction ─────────────────────────

@pytest.mark.parametrize("body", [
    pytest.param(_health("degraded", "intelligence_stale", "stale", INCIDENT_GENERATED_AT), id="200-degraded"),
    pytest.param(_health("unhealthy", "feed_unavailable", "unavailable", None, count=0), id="200-unhealthy"),
    pytest.param(_health("ok", None, "stale", INCIDENT_GENERATED_AT), id="200-ok-intel-stale"),
    pytest.param(_health("ok", None, "fresh", INCIDENT_GENERATED_AT), id="200-ok-but-generated_at-stale"),
    pytest.param(_health("ok", "intelligence_stale", "fresh", FRESH_AT), id="200-ok-with-reason"),
    pytest.param(_health("ok", None, "fresh", FRESH_AT, count=0), id="200-ok-no-items"),
])
def test_I_200_with_non_fresh_body_is_contradiction(body):
    r = deploy(LIVE_OK, (200, body, None))
    assert r["deployment_verdict"] == "FAIL"
    assert r["customer_intelligence_healthy"] is False


# ── J: 503 but body ok/fresh -> contradiction ───────────────────────────────

@pytest.mark.parametrize("body", [
    pytest.param(_health("ok", None, "fresh", FRESH_AT), id="503-ok"),
    pytest.param(_health("degraded", "intelligence_stale", "fresh", FRESH_AT), id="503-degraded-intel-fresh"),
    pytest.param(_health("degraded", "intelligence_stale", "stale", FRESH_AT), id="503-degraded-generated_at-fresh"),
])
def test_J_503_with_fresh_body_is_contradiction(body):
    assert deploy(LIVE_OK, (503, body, None))["deployment_verdict"] == "FAIL"


# ── K: sensitive/config exposure -> FAIL ────────────────────────────────────

@pytest.mark.parametrize("mutate", [
    pytest.param(lambda b: b["checks"].update(jwt_configured=True), id="jwt_configured"),
    pytest.param(lambda b: b["checks"].update(r2_intel="ok"), id="r2_intel"),
    pytest.param(lambda b: b["checks"].update(kv_rate_limit="ok"), id="kv_rate_limit"),
    pytest.param(lambda b: b["checks"].update(razorpay_configured=True), id="razorpay_configured"),
    pytest.param(lambda b: b.update(security={"auth": "JWT_HS256+KV"}), id="security-block"),
    pytest.param(lambda b: b.update(data_freshness={"status": "FRESH"}), id="operator-only-field"),
    pytest.param(lambda b: b.update(account_id="abc"), id="account-id"),
    pytest.param(lambda b: b["intelligence"].update(bucket="sentinel-apex-data"), id="nested-bucket"),
    pytest.param(lambda b: b["checks"].update(admin_configured=True), id="admin_configured"),
])
@pytest.mark.parametrize("base", [HEALTH_FRESH, HEALTH_STALE], ids=["fresh", "stale"])
def test_K_public_health_exposing_sensitive_fields_fails(mutate, base):
    status, body, _ = base
    body = copy.deepcopy(body)
    mutate(body)
    r = deploy(LIVE_OK, (status, body, None))
    assert r["deployment_verdict"] == "FAIL"
    assert any("exposes" in f for f in r["failures"])


# ── L/M: release freshness gate is NOT weakened ─────────────────────────────

def test_L_release_freshness_gate_fails_on_stale_production_state():
    # The exact production state captured on 2026-09-24 before recovery:
    # feed generated_at 2026-08-26, /api/health 503 degraded.
    rel = gate.evaluate(200, feed_body(INCIDENT_GENERATED_AT), None, *HEALTH_STALE, now=NOW)
    assert rel["verdict"] == "FAIL"
    assert any("stale" in f for f in rel["failures"])
    # ...while the deployment gate over that SAME state is operational.
    assert deploy(LIVE_OK, HEALTH_STALE)["deployment_verdict"] == "PASS"


def test_M_release_freshness_gate_passes_on_valid_fresh_fixture():
    rel = gate.evaluate(200, feed_body(FRESH_AT), None, *HEALTH_FRESH, now=NOW)
    assert rel["verdict"] == "PASS", rel["failures"]


def test_release_gate_still_rejects_unavailable_and_lying_health():
    assert gate.evaluate(200, feed_body(FRESH_AT, n=0), None, *HEALTH_UNAVAILABLE, now=NOW)["verdict"] == "FAIL"
    lying = (200, _health("ok", None, "fresh", FRESH_AT), None)
    assert gate.evaluate(200, feed_body(INCIDENT_GENERATED_AT), None, *lying, now=NOW)["verdict"] == "FAIL"


# ── Negative controls: the OLD gate logic is provably wrong ─────────────────

def _old_gate_a(health_status):
    """Pre-fix post-deploy-validation.yml GATE A: /api/health must be 200."""
    return "PASS" if health_status == 200 else "FAIL"


def test_negative_control_old_gate_rejected_healthy_stale_deploy():
    # the defect: old logic FAILS a live Worker because intel is stale ...
    assert _old_gate_a(HEALTH_STALE[0]) == "FAIL"
    # ... and would PASS an invalid "200 but stale" lie that the new gate rejects.
    assert _old_gate_a(200) == "PASS"
    assert deploy(LIVE_OK, (200, HEALTH_STALE[1], None))["deployment_verdict"] == "FAIL"


def test_negative_control_valid_fixtures_are_actually_valid():
    """Guards the FAIL scenarios above from passing vacuously: each mutated
    fixture's unmutated base passes."""
    for h in (HEALTH_FRESH, HEALTH_STALE, HEALTH_UNAVAILABLE):
        r = deploy(LIVE_OK, h)
        assert r["deployment_verdict"] == "PASS", (h[1]["status"], r["failures"])


# ── Parity with the Worker's own public-field test ──────────────────────────

def _js_set(src, name):
    m = re.search(rf"const {name} = new Set\(\[(.*?)\]\);", src, re.S)
    assert m, name
    return frozenset(re.findall(r'"([^"]+)"', m.group(1)))


def test_allowlist_parity_with_worker_test():
    src = (REPO / "workers/intel-gateway/src/__tests__/health-freshness-contract.test.js").read_text(encoding="utf-8")
    assert _js_set(src, "PUBLIC_TOP_LEVEL") == dhc.PUBLIC_TOP_LEVEL
    assert _js_set(src, "PUBLIC_CHECKS") == dhc.PUBLIC_CHECKS
    js_forbidden = re.search(r"const FORBIDDEN = /(.*?)/i;", src).group(1)
    assert js_forbidden == dhc.FORBIDDEN_KEY_RE.pattern


def test_reason_set_parity_with_worker_contract():
    src = (REPO / "workers/intel-gateway/src/freshness-contract.js").read_text(encoding="utf-8")
    js_reasons = set(re.findall(r'base\("unhealthy", "([a-z_]+)"', src))
    js_reasons |= set(re.findall(r'\]: "([a-z_]+)"', src))
    assert js_reasons == set(dhc.REASON_TO_INTEL_STATUS) | {dhc.DEGRADED_REASON}


# ── End-to-end against the REAL Worker route (node) ─────────────────────────

_NODE_HARNESS = r"""
import worker from "./workers/intel-gateway/src/index.js";
const kv = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); },
  delete: async (k) => { m.delete(k); }, list: async () => ({ keys: [], list_complete: true }) }; };
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
const iso = (s) => new Date(Date.now() - s * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const feeds = {
  fresh: { generated_at: iso(600), count: 1, items: [{ id: "intel--live", severity: "HIGH" }] },
  stale: { generated_at: "2026-08-26T09:55:27Z", count: 1, items: [{ id: "intel--live", severity: "HIGH" }] },
  unavailable: null,
  empty: { generated_at: iso(600), count: 0, items: [] },
};
const out = {};
for (const [name, feed] of Object.entries(feeds)) {
  const env = { INTEL_R2: { get: async (k) => (k === "api/v1/intel/latest.json" && feed ? { text: async () => JSON.stringify(feed) } : null) },
    RATE_LIMIT_KV: kv(), API_KEYS_KV: kv(), SECURITY_HUB_KV: kv(), ANALYTICS_KV: kv(), REVENUE_CRM_KV: kv(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test" };
  const ctx = { waitUntil: () => {} };
  const call = async (p) => { const r = await worker.fetch(new Request("https://intel.cyberdudebivash.com" + p), env, ctx);
    return [r.status, await r.json()]; };
  out[name] = { live: await call("/api/health/live"), health: await call("/api/health") };
}
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed (the gateway node suite pins the Worker side)")
def test_real_worker_responses_satisfy_the_deployment_contract():
    proc = subprocess.run(["node", "--input-type=module", "-e", _NODE_HARNESS], cwd=REPO,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    line = [ln for ln in proc.stdout.splitlines() if ln.startswith("{\"fresh\"")][-1]
    res = json.loads(line)
    expect = {"fresh": ("healthy", True), "stale": ("degraded", False),
              "unavailable": ("unhealthy", False), "empty": ("unhealthy", False)}
    for name, (state, healthy) in expect.items():
        live, health = res[name]["live"], res[name]["health"]
        r = dhc.evaluate_deployment((live[0], live[1], None), (health[0], health[1], None))
        assert r["deployment_verdict"] == "PASS", (name, r["failures"])
        assert (r["customer_intelligence_state"], r["customer_intelligence_healthy"]) == (state, healthy), name


# ── Workflow wiring: the drift cannot come back ─────────────────────────────

def _step(wf_text, name):
    i = wf_text.index(f'- name: "{name}')
    j = wf_text.find("\n      - name:", i + 1)
    return wf_text[i: j if j != -1 else len(wf_text)]


def test_post_deploy_gate_a_uses_liveness_and_structured_contract():
    wf = (REPO / ".github/workflows/post-deploy-validation.yml").read_text(encoding="utf-8")
    a = _step(wf, "GATE A")
    loop = a[a.index("Public endpoints (must be HTTP 200)"):a.index("Auth-protected endpoints")]
    assert "/api/health\"" not in loop, "/api/health must never be back in the 200-only availability loop"
    assert "scripts/deployment_health_contract.py" in a
    assert "continue-on-error" not in a and "|| true" not in a.split("deployment_health_contract.py")[1].split("\n")[0]
    for ep in ("/api/v1/intel/latest.json", "/api/v1/intel/top10.json", "/api/feed.json"):
        assert ep in loop


def test_jwt_gate_and_stage_5_9_10_unweakened():
    wf = (REPO / ".github/workflows/post-deploy-validation.yml").read_text(encoding="utf-8")
    d = _step(wf, "GATE D")
    assert "secrets.ADMIN_SECRET" in d and 'if [ -z "${ADMIN_SECRET}" ]' in d and "exit 1" in d
    assert "continue-on-error" not in d
    sb = (REPO / ".github/workflows/sentinel-blogger.yml").read_text(encoding="utf-8")
    s = _step(sb, "STAGE 5.9.10")
    assert "python3 scripts/public_feed_freshness_gate.py" in s
    assert "continue-on-error" not in s and "|| true" not in s


def test_python_validator_gate_a_uses_contract():
    src = (REPO / "scripts/post_deploy_validator.py").read_text(encoding="utf-8")
    ep_block = src[src.index("endpoints = {"):src.index("}", src.index("endpoints = {"))]
    assert "/api/health" not in ep_block
    assert "_deploy_health.evaluate_deployment(" in src
    assert '"A", "B", "E"' in src, "GATE A must remain a hard gate"


# ── Phase 5: every deployment/readiness consumer uses the right contract ────

def _fake_fetch(live, health):
    def f(url, timeout, headers=None):
        return live if url.split("?")[0].endswith("/api/health/live") else health
    return f


def _freeze_freshness_clock(monkeypatch):
    """HEALTH_FRESH is 10 minutes before the fixture clock (2026-09-24 06:00Z).
    Canary and rollback evaluators that omit `now=` use the wall clock, so
    this fixture becomes STALE six hours later and the release gate goes red
    for a reason that is not a product regression."""
    import public_freshness_contract as contract

    class Frozen(contract.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(contract, "datetime", Frozen)


@pytest.mark.parametrize("health,expect", [
    (HEALTH_FRESH, True), (HEALTH_STALE, True), (HEALTH_UNAVAILABLE, True),
    ((503, None, "invalid JSON: <!DOCTYPE html>"), False),
    ((200, HEALTH_STALE[1], None), False),
])
def test_deployment_canary_a_uses_contract(monkeypatch, health, expect):
    import deployment_canary as dc
    _freeze_freshness_clock(monkeypatch)
    monkeypatch.setattr(dc._deploy_health, "fetch_json", _fake_fetch(LIVE_OK, health))
    r = dc.canary_a_health("https://x", 5, now=NOW)
    assert r["pass"] is expect, r
    if expect:
        assert r["intelligence_state"] in ("healthy", "degraded", "unhealthy")


def test_deployment_canary_a_fails_when_worker_not_live(monkeypatch):
    import deployment_canary as dc
    monkeypatch.setattr(dc._deploy_health, "fetch_json", _fake_fetch((404, {"error": "nf"}, None), HEALTH_STALE))
    assert dc.canary_a_health("https://x", 5, now=NOW)["pass"] is False


def test_rollback_fingerprint_keeps_version_while_stale(monkeypatch):
    import rollback_authority as ra
    monkeypatch.setattr(dhc, "fetch_json", _fake_fetch(LIVE_OK, HEALTH_STALE))
    r = ra.probe_worker_version()
    assert (r["ok"], r["version"], r["status"], r["intelligence_state"]) == (True, VERSION, "degraded", "degraded")
    monkeypatch.setattr(dhc, "fetch_json", _fake_fetch((500, None, "x"), HEALTH_STALE))
    assert ra.probe_worker_version()["ok"] is False


def test_canary_and_feed_contract_validators_delegate_health():
    import canary_contract_validator as ccv
    import feed_contract_validator as fcv
    ep = [e for e in ccv.CANARY_ENDPOINTS if e["path"] == "/api/health"][0]
    assert ep.get("health_contract") is True
    assert fcv.CONTRACTS["/api/health"].get("health_contract") is True
    assert "unhealthy" in fcv.CONTRACTS["/api/health"]["envelope_values"]["status:oneof"]


def test_feed_contract_live_health_accepts_valid_503_rejects_html(monkeypatch, tmp_path):
    import feed_contract_validator as fcv
    for health, hard in ((HEALTH_STALE, False), ((503, None, "invalid JSON"), True)):
        monkeypatch.setattr(fcv._deploy_health, "fetch_json", _fake_fetch(LIVE_OK, health))
        v = fcv.FeedContractValidator("https://x", 5, True, tmp_path)
        v._check_live_health_contract("/api/health", fcv.CONTRACTS["/api/health"])
        assert bool(v.report.hard_fails) is hard, (health, v.report.hard_fails)


@pytest.mark.parametrize("wf,needle", [
    ("master-deployment-orchestrator.yml", "scripts/deployment_health_contract.py"),
    ("environment-promotion.yml", "scripts/deployment_health_contract.py"),
    ("enterprise-rollback-governance.yml", "scripts/post_rollback_canary.py"),
])
def test_deploy_readiness_workflows_use_liveness_contract(wf, needle):
    src = (REPO / ".github/workflows" / wf).read_text(encoding="utf-8")
    assert needle in src
    assert not re.search(r"curl -sf[^\n]*/api/health\"", src), f"{wf}: 200-only /api/health probe is back"


def test_status_page_shows_degraded_not_unreachable_for_sentinel_503():
    src = (REPO / "status.html").read_text(encoding="utf-8")
    assert "r.status !== 503" in src and "b.service === 'sentinel-apex'" in src
    assert "DEGRADED" in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
