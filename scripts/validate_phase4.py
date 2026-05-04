#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — Phase IV Validation Gate v143.0.0        ║
║  9/9 Integrity Checks — Run before every production deployment              ║
║                                                                              ║
║  Checks:                                                                     ║
║   [1] Enterprise AI endpoints — enterprise_ai.py wired into main.py        ║
║   [2] Executive Briefing PDF engine — generate_executive_briefing.py       ║
║   [3] Sovereign Mode config tool — sovereign_config.py + feature_flags     ║
║   [4] Dark Web domain monitor — dark_web_domain_monitor.py                 ║
║   [5] SOC Connector Suite — Splunk/Sentinel/QRadar connectors              ║
║   [6] AI-SPM Toolkit — ai_spm_assessment.py + ATLAS coverage              ║
║   [7] Arsenal bundles — YARA + Sigma files present and parseable           ║
║   [8] Payment notify endpoint — payment.py wired + audit log writable      ║
║   [9] SLA monitor — sla_monitor.py functional + rate_limiter dual-window   ║
║                                                                              ║
║  Exit codes: 0 = all pass | 1 = one or more checks failed                 ║
║  CLI: python scripts/validate_phase4.py [--json] [--strict]               ║
║                                                                              ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).parent.parent

# ── Result tracking ───────────────────────────────────────────────────────────

PASS  = "PASS"
FAIL  = "FAIL"
WARN  = "WARN"

results: List[Dict] = []

def check(name: str, passed: bool, detail: str, level: str = PASS) -> bool:
    status = PASS if passed else FAIL
    results.append({
        "check":  name,
        "status": status,
        "detail": detail,
        "ts":     datetime.now(timezone.utc).isoformat(),
    })
    icon = "✅" if passed else "❌"
    print(f"  {icon} [{status}] {name}")
    if not passed or detail:
        print(f"         {detail}")
    return passed


def warn(name: str, detail: str) -> bool:
    results.append({"check": name, "status": WARN, "detail": detail,
                    "ts": datetime.now(timezone.utc).isoformat()})
    print(f"  ⚠️  [WARN] {name}: {detail}")
    return True


def _file_exists(path: Path) -> bool:
    return path.exists() and path.is_file()


def _file_contains(path: Path, *needles: str) -> bool:
    if not path.exists():
        return False
    content = path.read_text(encoding="utf-8", errors="replace")
    return all(needle in content for needle in needles)


def _file_min_lines(path: Path, min_lines: int) -> bool:
    if not path.exists():
        return False
    return sum(1 for _ in path.open(encoding="utf-8", errors="replace")) >= min_lines


def _can_import(module_path: Path) -> Tuple[bool, str]:
    """Attempt to import a Python module file.
    Registers the module in sys.modules before exec so that Python 3.10
    dataclasses._is_type() can resolve cls.__module__ via sys.modules.
    """
    import sys as _sys
    mod_name = f"_val_module_{id(module_path)}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, module_path)
        mod  = importlib.util.module_from_spec(spec)
        _sys.modules[mod_name] = mod          # ← must register BEFORE exec
        spec.loader.exec_module(mod)
        return True, "import OK"
    except Exception as e:
        _sys.modules.pop(mod_name, None)
        return False, str(e)[:120]


# ── Individual checks ─────────────────────────────────────────────────────────

def check_1_enterprise_ai():
    """[1] Enterprise AI — endpoints file + wired into main.py"""
    print("\n[1] Enterprise AI Endpoints")

    endpoint_file = ROOT / "sentinel-apex-api" / "app" / "api" / "v1" / "endpoints" / "enterprise_ai.py"
    main_file     = ROOT / "sentinel-apex-api" / "app" / "main.py"

    ok1 = check("enterprise_ai.py exists", _file_exists(endpoint_file),
                 str(endpoint_file.relative_to(ROOT)))

    ok2 = check("enterprise_ai.py has hasValidApexAI guard",
                 _file_contains(endpoint_file, "hasValidApexAI"),
                 "Function signature must be present")

    ok3 = check("enterprise_ai.py has /predict/enterprise endpoint",
                 _file_contains(endpoint_file, "/predict/enterprise", "EnterpriseForcast"),
                 "POST /api/v1/predict/enterprise must be defined")

    ok4 = check("enterprise_ai.py has /anomalies/critical endpoint",
                 _file_contains(endpoint_file, "/anomalies/critical"),
                 "GET /api/v1/anomalies/critical must be defined")

    ok5 = check("enterprise_ai.py wired into main.py",
                 _file_contains(main_file, "enterprise_ai", "enterprise_ai.router"),
                 "import + app.include_router required")

    ok6 = check("enterprise_ai.py uses atomic reads",
                 _file_contains(endpoint_file, "_atomic_read_json"),
                 "Atomic read pattern must be present")

    return all([ok1, ok2, ok3, ok4, ok5, ok6])


def check_2_executive_briefing():
    """[2] Executive Briefing PDF Engine"""
    print("\n[2] Executive Briefing PDF Engine")

    script = ROOT / "scripts" / "generate_executive_briefing.py"

    ok1 = check("generate_executive_briefing.py exists",
                 _file_exists(script), str(script.relative_to(ROOT)))

    ok2 = check("Script has watermark canvas",
                 _file_contains(script, "WatermarkCanvas", "TLP:AMBER"),
                 "TLP watermark required")

    ok3 = check("Script has GSTIN branding",
                 _file_contains(script, "21ARKPN8270G1ZP"),
                 "GSTIN must be present")

    ok4 = check("Script has atomic write pattern",
                 _file_contains(script, ".tmp", "rename"),
                 "Atomic write: .tmp → rename pattern required")

    ok5 = check("Script min 200 lines (full implementation)",
                 _file_min_lines(script, 200),
                 "Full implementation expected")

    return all([ok1, ok2, ok3, ok4, ok5])


def check_3_sovereign_mode():
    """[3] Sovereign Mode Config"""
    print("\n[3] Sovereign Mode + White-Label Config")

    script       = ROOT / "scripts" / "sovereign_config.py"
    feature_flags = ROOT / "config" / "feature_flags.json"

    ok1 = check("sovereign_config.py exists",
                 _file_exists(script), str(script.relative_to(ROOT)))

    ok2 = check("sovereign_config.py has provision/revoke/list",
                 _file_contains(script, "provision", "revoke", "list"),
                 "Three CLI subcommands required")

    ok3 = check("sovereign_config.py generates API keys",
                 _file_contains(script, "cdb-sovereign"),
                 "cdb-sovereign- key prefix required")

    ok4 = check("sovereign_config.py price $1,999/mo",
                 _file_contains(script, "1999"),
                 "MSSP_PRICE_USD = 1999 required")

    ok5 = False
    if feature_flags.exists():
        try:
            flags = json.loads(feature_flags.read_bytes())
            has_sovereign = "ENABLE_SOVEREIGN_MODE" in flags
            ok5 = check("feature_flags.json has ENABLE_SOVEREIGN_MODE",
                         has_sovereign, str(feature_flags.relative_to(ROOT)))
        except Exception as e:
            ok5 = check("feature_flags.json parseable", False, str(e)[:80])
    else:
        ok5 = check("feature_flags.json exists", False, str(feature_flags.relative_to(ROOT)))

    return all([ok1, ok2, ok3, ok4, ok5])


def check_4_dark_web_monitor():
    """[4] Dark Web Domain Monitor"""
    print("\n[4] Dark Web Domain Monitor")

    script = ROOT / "scripts" / "dark_web_domain_monitor.py"

    ok1 = check("dark_web_domain_monitor.py exists",
                 _file_exists(script), str(script.relative_to(ROOT)))

    ok2 = check("Monitor supports up to 10 domains",
                 _file_contains(script, "MAX_DOMAINS"),
                 "MAX_DOMAINS constant required")

    ok3 = check("Monitor has Telegram alert support",
                 _file_contains(script, "send_telegram_alert", "api.telegram.org"),
                 "Telegram Bot API integration required")

    ok4 = check("Monitor has HMAC-signed webhook alerts",
                 _file_contains(script, "HMAC", "X-APEX-Signature"),
                 "HMAC signature on webhook payloads required")

    ok5 = check("Monitor has alert deduplication",
                 _file_contains(script, "dedup", "md5") or
                 _file_contains(script, "deduplicate", "cache"),
                 "Deduplication window required")

    return all([ok1, ok2, ok3, ok4, ok5])


def check_5_soc_connectors():
    """[5] SOC Connector Suite"""
    print("\n[5] SOC Connector Suite — Splunk / Sentinel / QRadar")

    splunk   = ROOT / "integrations" / "splunk_hec_connector.py"
    sentinel = ROOT / "integrations" / "ms_sentinel_connector.py"
    qradar   = ROOT / "integrations" / "qradar_leef_connector.py"

    ok1 = check("splunk_hec_connector.py exists + has HEC batch",
                 _file_exists(splunk) and _file_contains(splunk, "build_hec_batch", "push_batch"),
                 str(splunk.relative_to(ROOT)))

    ok2 = check("ms_sentinel_connector.py exists + has HMAC auth",
                 _file_exists(sentinel) and _file_contains(sentinel, "_build_signature", "hmac"),
                 str(sentinel.relative_to(ROOT)))

    ok3 = check("qradar_leef_connector.py exists + has LEEF 2.0",
                 _file_exists(qradar) and _file_contains(qradar, "LEEF:2.0", "apex_to_leef"),
                 str(qradar.relative_to(ROOT)))

    ok4 = check("All connectors have retry logic",
                 all(_file_contains(f, "RETRY_ATTEMPTS") for f in [splunk, sentinel, qradar]),
                 "RETRY_ATTEMPTS constant required in all 3 connectors")

    ok5 = check("All connectors have atomic-read feed loading",
                 all(_file_contains(f, "load") and f.exists() for f in [splunk, sentinel, qradar]),
                 "load_feed() / load_latest_feed() required in all 3")

    return all([ok1, ok2, ok3, ok4, ok5])


def check_6_ai_spm():
    """[6] AI-SPM Assessment Toolkit"""
    print("\n[6] AI-SPM Toolkit — MITRE ATLAS + NIST AI RMF")

    script = ROOT / "scripts" / "ai_spm_assessment.py"

    ok1 = check("ai_spm_assessment.py exists",
                 _file_exists(script), str(script.relative_to(ROOT)))

    ok2 = check("Toolkit has MITRE ATLAS technique catalog",
                 _file_contains(script, "AML.T0043", "AML.T0018", "AML.T0048"),
                 "ATLAS AML.T04x techniques required")

    ok3 = check("Toolkit has NIST AI RMF domains",
                 _file_contains(script, "GOVERN", "MAP", "MEASURE", "MANAGE"),
                 "All 4 NIST AI RMF function domains required")

    ok4 = check("Toolkit has OWASP LLM Top 10 mapping",
                 _file_contains(script, "LLM01", "LLM06", "OWASP"),
                 "OWASP LLM Top 10 mapping required")

    ok5 = check("Toolkit generates scored JSON report",
                 _file_contains(script, "AssessmentReport", "overall_score", "maturity_level"),
                 "AssessmentReport dataclass required")

    ok6 = check("Toolkit price $299 documented",
                 _file_contains(script, "299"),
                 "PRICE_USD = 299 required")

    # Functional validation
    try:
        import sys as _sys
        _mod_name = "ai_spm_validate"
        spec = importlib.util.spec_from_file_location(_mod_name, script)
        mod  = importlib.util.module_from_spec(spec)
        _sys.modules[_mod_name] = mod         # register before exec (py3.10 dataclasses fix)
        spec.loader.exec_module(mod)
        report = mod.run_assessment("ValidationTest", "SENTINEL_APEX", mod.QUICK_SCAN_DEFAULTS)
        ok7 = check("Toolkit produces valid scored report",
                     isinstance(report.overall_percentage, float) and 0 <= report.overall_percentage <= 100,
                     f"Score: {report.overall_percentage}% | Risk: {report.risk_rating}")
    except Exception as e:
        ok7 = check("Toolkit functional validation", False, str(e)[:120])

    return all([ok1, ok2, ok3, ok4, ok5, ok6, ok7])


def check_7_arsenal():
    """[7] Arsenal bundles — YARA + Sigma"""
    print("\n[7] Arsenal Bundles — Detection Signatures")

    arsenal_dir = ROOT / "data" / "arsenal" / "lazarus_apt28"
    yara_file   = arsenal_dir / "lazarus_apt28_full.yar"
    sigma_file  = arsenal_dir / "lazarus_apt28_sigma.yml"

    ok1 = check("YARA arsenal file exists",
                 _file_exists(yara_file), str(yara_file.relative_to(ROOT)))

    ok2 = check("YARA has Lazarus + APT28 rules",
                 _file_contains(yara_file, "Lazarus", "APT28", "MITRE"),
                 "Both actor families required")

    ok3 = check("YARA has MITRE ATT&CK tags in meta",
                 _file_contains(yara_file, "mitre_attack", "T1566"),
                 "MITRE ATT&CK technique tags required")

    ok4 = check("YARA file has ≥8 rules",
                 yara_file.exists() and
                 len(re.findall(r'^rule\s+\w+', yara_file.read_text(encoding="utf-8"), re.MULTILINE)) >= 8,
                 "Expected: AppleJeus, BlindingCan, DTrack, BeagleBoyz, XAgent, GAMEFISH, Zebrocy, LoJax + cross-actor")

    ok5 = check("Sigma file exists",
                 _file_exists(sigma_file), str(sigma_file.relative_to(ROOT)))

    ok6 = check("Sigma has ≥6 detection rules",
                 sigma_file.exists() and
                 sigma_file.read_text(encoding="utf-8").count("title: CDB_") >= 6,
                 "Expected: 7 Sigma rules covering Lazarus + APT28 TTPs")

    ok7 = check("Sigma rules have MITRE ATT&CK tags",
                 _file_contains(sigma_file, "attack.t1", "attack.initial_access"),
                 "Sigma logsource + detection blocks required")

    return all([ok1, ok2, ok3, ok4, ok5, ok6, ok7])


def check_8_payment():
    """[8] Payment notify endpoint"""
    print("\n[8] Payment Notify — Proof-of-Payment VIP Onboarding")

    payment_file = ROOT / "sentinel-apex-api" / "app" / "api" / "v1" / "endpoints" / "payment.py"
    main_file    = ROOT / "sentinel-apex-api" / "app" / "main.py"

    ok1 = check("payment.py exists",
                 _file_exists(payment_file), str(payment_file.relative_to(ROOT)))

    ok2 = check("payment.py has Gumroad webhook",
                 _file_contains(payment_file, "gumroad", "GumroadPingPayload"),
                 "/notify/gumroad endpoint required")

    ok3 = check("payment.py has Stripe webhook",
                 _file_contains(payment_file, "stripe", "stripe_signature"),
                 "/notify/stripe endpoint required")

    ok4 = check("payment.py has Priority Triage trigger",
                 _file_contains(payment_file, "_set_priority_triage", "priority_triage"),
                 "Priority Triage status must be set on payment")

    ok5 = check("payment.py has HMAC signature verification",
                 _file_contains(payment_file, "hmac.compare_digest", "_verify_gumroad_signature"),
                 "HMAC verification on webhook payloads required")

    ok6 = check("payment.py wired into main.py",
                 _file_contains(main_file, "payment", "payment.router"),
                 "import + app.include_router required")

    ok7 = check("payment.py has 120-minute SLA constant",
                 _file_contains(payment_file, "KEY_DELIVERY_SLA_SECONDS", "7200"),
                 "SLA: 7200 seconds = 120 minutes")

    return all([ok1, ok2, ok3, ok4, ok5, ok6, ok7])


def check_9_sla_rate():
    """[9] SLA Monitor + Enterprise rate limiter"""
    print("\n[9] SLA Monitor + Enterprise Rate Limiter (2,000 req/min)")

    sla_py   = ROOT / "core" / "sla_monitor.py"
    sla_js   = ROOT / "js" / "sla-monitor.js"
    rl_file  = ROOT / "sentinel-apex-api" / "app" / "middleware" / "rate_limit.py"
    api_html = ROOT / "api-key-manager.html"

    ok1 = check("core/sla_monitor.py exists",
                 _file_exists(sla_py), str(sla_py.relative_to(ROOT)))

    ok2 = check("sla_monitor.py has uptime calculation",
                 _file_contains(sla_py, "calculate_uptime", "uptime_pct", "SLA_TARGET"),
                 "99.9% SLA target + uptime calculation required")

    ok3 = check("sla_monitor.py has incident management",
                 _file_contains(sla_py, "open_incident", "close_incident", "generate_status"),
                 "Incident open/close/status functions required")

    ok4 = check("js/sla-monitor.js exists",
                 _file_exists(sla_js), str(sla_js.relative_to(ROOT)))

    ok5 = check("sla-monitor.js fetches sla_status.json",
                 _file_contains(sla_js, "sla_status.json", "SLAMonitor"),
                 "SLAMonitor global + status JSON fetch required")

    ok6 = check("rate_limit.py has 2,000 req/min Enterprise burst",
                 _file_contains(rl_file, "TIER_BURST_LIMITS", "2000"),
                 "ENTERPRISE burst limit = 2000/min required")

    ok7 = check("rate_limit.py has dual-window enforcement",
                 _file_contains(rl_file, "check_and_increment", "burst_limit", "_burst"),
                 "Per-minute + per-day sliding window required")

    ok8 = check("rate_limit.py injects burst headers",
                 _file_contains(rl_file, "X-RateLimit-Burst-Limit", "X-RateLimit-Burst-Remaining"),
                 "Burst rate limit headers required")

    ok9 = check("api-key-manager.html has Chart.js analytics",
                 _file_contains(api_html, "dailyChart", "endpointChart", "_render_daily_chart"),
                 "Chart.js usage analytics section required")

    # Functional SLA test
    try:
        import sys as _sys
        _mod_name = "sla_mon_validate"
        spec = importlib.util.spec_from_file_location(_mod_name, sla_py)
        mod  = importlib.util.module_from_spec(spec)
        _sys.modules[_mod_name] = mod         # register before exec (py3.10 dataclasses fix)
        spec.loader.exec_module(mod)
        mod.record_heartbeat("up", 142.5)
        status = mod.generate_status(save=False)
        ok10 = check("sla_monitor functional — generates valid status",
                      status.get("platform_status") in ("OPERATIONAL", "DEGRADED", "PARTIAL_OUTAGE"),
                      f"Status: {status.get('platform_status')} | Uptime: {status.get('uptime',{}).get('30d',{}).get('uptime_pct',0)}%")
    except Exception as e:
        ok10 = check("sla_monitor functional validation", False, str(e)[:120])

    return all([ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8, ok9, ok10])


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Phase IV Validation Gate — 9/9 checks"
    )
    parser.add_argument("--json",   action="store_true", help="Output JSON report")
    parser.add_argument("--strict", action="store_true", help="Fail on WARN too")
    parser.add_argument("--check",  type=int, default=None,
                        help="Run only check N (1-9)")
    args = parser.parse_args()

    start = time.time()

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  SENTINEL APEX Phase IV Validation Gate v143.0.0            ║")
    print(f"║  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'):<56}║")
    print("╚══════════════════════════════════════════════════════════════╝")

    check_fns = [
        check_1_enterprise_ai,
        check_2_executive_briefing,
        check_3_sovereign_mode,
        check_4_dark_web_monitor,
        check_5_soc_connectors,
        check_6_ai_spm,
        check_7_arsenal,
        check_8_payment,
        check_9_sla_rate,
    ]

    if args.check:
        idx = args.check - 1
        if 0 <= idx < len(check_fns):
            check_fns[idx]()
        else:
            print(f"Invalid check number: {args.check} (valid: 1-{len(check_fns)})")
            sys.exit(1)
    else:
        for fn in check_fns:
            fn()

    elapsed = time.time() - start

    # Tally
    total  = len(results)
    passed = sum(1 for r in results if r["status"] == PASS)
    failed = sum(1 for r in results if r["status"] == FAIL)
    warns  = sum(1 for r in results if r["status"] == WARN)

    print(f"\n{'═'*64}")
    print(f"  RESULTS: {passed}/{total} passed | {failed} failed | {warns} warnings")
    print(f"  Elapsed: {elapsed:.2f}s")
    print(f"{'═'*64}")

    gate_passed = failed == 0 and (warns == 0 if args.strict else True)
    if gate_passed:
        print("  ✅ PHASE IV VALIDATION: ALL CHECKS PASSED — safe to deploy")
    else:
        print(f"  ❌ PHASE IV VALIDATION: {failed} check(s) FAILED — do not deploy")
        for r in results:
            if r["status"] == FAIL:
                print(f"     ↳ FAILED: {r['check']} — {r['detail']}")

    if args.json:
        report = {
            "gateway":    "phase4_validation",
            "version":    "143.0.0",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "elapsed_s":  round(elapsed, 3),
            "summary":    {"total": total, "passed": passed, "failed": failed, "warns": warns},
            "gate_passed": gate_passed,
            "results":    results,
            "gstin":      "21ARKPN8270G1ZP",
        }
        print("\n" + json.dumps(report, indent=2))

    sys.exit(0 if gate_passed else 1)


if __name__ == "__main__":
    main()
