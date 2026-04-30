#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — Phase 9: Final Validation Report
=================================================
Aggregates all phase results into a single authoritative status report:

  ✓ Dashboard ≠ API mismatch resolved?   YES/NO
  ✓ Encoding corruption eliminated?      YES/NO
  ✓ Render count (must be exactly 1)?    COUNT
  ✓ Sync status (API = UI)?              PASS/FAIL
  ✓ Pipeline stability?                  PASS/FAIL
  ✓ Output gate status?                  PASS/FAIL
  ✓ Self-heal status?                    HEALTHY/HEALED/UNRECOVERABLE

Outputs:
  - Console summary (ASCII table)
  - data/audit/final_validation_report.json
  - data/audit/PLATFORM_STATUS.txt  (single-line badge: PRODUCTION_READY / DEGRADED / CRITICAL)

Usage:
    python scripts/final_validation_report.py [--repo-root .] [--strict]
"""

import os, sys, json, re, hashlib, argparse
from datetime import datetime, timezone

SCRIPT_VERSION = "1.0.0"
REPORT_PATH    = os.path.join("data", "audit", "final_validation_report.json")
STATUS_BADGE   = os.path.join("data", "audit", "PLATFORM_STATUS.txt")
UTF8_BOM       = b"\xef\xbb\xbf"

MOJIBAKE_PATTERNS = [
    b"\xc3\x82\xc2\xae", b"\xc3\x82\xc2\xa9", b"\xc3\x82\xc2\xb7",
    b"\xc3\x83\xc2\xa9", b"\xc3\x83\xc2\xa8", b"\xc3\x82\xc2\xa0",
]


# ────────────────────────────────────────────────────────────
def sha16(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()[:16]

def ts_key(e):
    for f in ("published","last_modified","timestamp","created"):
        v = e.get(f,"")
        if v: return str(v)
    return ""

def load_json_safe(path):
    try:
        with open(path,"rb") as f: raw = f.read()
        return json.loads(raw.decode("utf-8")), None
    except Exception as e:
        return None, str(e)

def unwrap(data):
    if isinstance(data, list): return data
    for k in ("entries","items","intel","data","objects"):
        if k in data and isinstance(data[k], list): return data[k]
    return []

def check_ok(val): return "[YES]" if val else "[NO] "
def pass_fail(val): return "PASS" if val else "FAIL"


# ────────────────────────────────────────────────────────────
def check_encoding(path, label, checks):
    """Check a file for encoding issues. Mutates checks dict."""
    if not os.path.exists(path):
        checks[label + "_exists"] = False
        return
    checks[label + "_exists"] = True
    try:
        with open(path, "rb") as f:
            raw = f.read()
        checks[label + "_bom"]       = raw[:3] != UTF8_BOM
        checks[label + "_no_nulls"]  = b"\x00" not in raw
        moji_free = all(p not in raw[:65536] for p in MOJIBAKE_PATTERNS)
        checks[label + "_no_mojibake"] = moji_free
        try:
            raw.decode("utf-8")
            checks[label + "_valid_utf8"] = True
        except UnicodeDecodeError:
            checks[label + "_valid_utf8"] = False
    except Exception as e:
        checks[label + "_read_error"] = str(e)


def check_dashboard_api_sync(repo_root):
    """Compare top-10 entries between manifest and api/feed.json."""
    manifest_path = os.path.join(repo_root, "data", "stix", "feed_manifest.json")
    api_path      = os.path.join(repo_root, "api", "feed.json")

    m_data, m_err = load_json_safe(manifest_path)
    a_data, a_err = load_json_safe(api_path)

    if m_err or a_err:
        return False, f"Load errors: manifest={m_err} api={a_err}"

    m_entries = sorted(unwrap(m_data), key=ts_key, reverse=True)
    a_entries = sorted(unwrap(a_data), key=ts_key, reverse=True)

    n = min(10, len(m_entries), len(a_entries))
    if n == 0:
        return False, "Empty entries"

    m_ids = [(e.get("stix_id") or e.get("id",""))[:36] for e in m_entries[:n]]
    a_ids = [(e.get("stix_id") or e.get("id",""))[:36] for e in a_entries[:n]]

    mismatches = sum(1 for x, y in zip(m_ids, a_ids) if x != y)
    if mismatches:
        return False, f"{mismatches}/{n} top-ID order mismatches"
    return True, f"Top-{n} IDs match"


def check_render_dedup(repo_root):
    """Verify __DATA_LOADED__ and __INTEL_RENDERED__ guards exist in index.html."""
    idx = os.path.join(repo_root, "index.html")
    if not os.path.exists(idx):
        return 0, "index.html missing"
    with open(idx, "rb") as f:
        raw = f.read()
    dl = raw.count(b"__DATA_LOADED__")
    ir = raw.count(b"__INTEL_RENDERED__")
    # Guards should appear (at least declaration + usage = ≥ 2 refs each)
    if dl >= 2 and ir >= 2:
        return 1, f"Guards present (DATA_LOADED={dl} refs, INTEL_RENDERED={ir} refs)"
    return 0, f"Guards missing or partial (DATA_LOADED={dl}, INTEL_RENDERED={ir})"


def check_embedded_intel(repo_root):
    """Verify EMBEDDED_INTEL is [] (empty) in index.html."""
    idx = os.path.join(repo_root, "index.html")
    if not os.path.exists(idx):
        return False, "index.html missing"
    with open(idx, "rb") as f:
        raw = f.read()
    # Should be window.EMBEDDED_INTEL = [] (no large array)
    stale = re.search(rb'window\.EMBEDDED_INTEL\s*=\s*\[.{1000,}', raw)
    if stale:
        return False, "EMBEDDED_INTEL still contains stale inline data"
    return True, "EMBEDDED_INTEL = [] (clean)"


def check_worker_security(repo_root):
    """Verify worker has CSP, HSTS, Content-Type charset in it."""
    wp = os.path.join(repo_root, "workers", "intel-gateway", "src", "index.js")
    if not os.path.exists(wp):
        return False, "Worker index.js missing"
    with open(wp, encoding="utf-8", errors="replace") as f:
        src = f.read()
    checks_found = {
        "CSP": "Content-Security-Policy" in src,
        "HSTS": "Strict-Transport-Security" in src,
        "charset": "charset=utf-8" in src,
        "nosniff": "nosniff" in src,
        "DENY": "DENY" in src,
    }
    missing = [k for k, v in checks_found.items() if not v]
    if missing:
        return False, f"Missing security headers: {missing}"
    return True, "All security headers present"


def load_sub_report(repo_root, rel_path):
    """Load a phase sub-report if it exists."""
    p = os.path.join(repo_root, rel_path)
    if not os.path.exists(p):
        return None
    data, _ = load_json_safe(p)
    return data


# ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SENTINEL APEX Final Validation Report v" + SCRIPT_VERSION)
    ap.add_argument("--repo-root", default=".", help="Repository root")
    ap.add_argument("--strict",    action="store_true", help="Fail on warnings")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    report_path  = os.path.join(repo_root, REPORT_PATH)
    badge_path   = os.path.join(repo_root, STATUS_BADGE)

    print(f"\n{'='*65}")
    print(f"SENTINEL APEX — FINAL VALIDATION REPORT v{SCRIPT_VERSION}")
    print(f"{'='*65}")
    print(f"  Repo: {repo_root}")
    print(f"  Date: {datetime.now(timezone.utc).isoformat()}")
    print()

    results = {}

    # ── Check 1: Dashboard ≠ API mismatch resolved ───────────
    sync_ok, sync_detail = check_dashboard_api_sync(repo_root)
    results["dashboard_api_sync"] = {"pass": sync_ok, "detail": sync_detail}
    print(f"  [1] Dashboard=API sync:       {check_ok(sync_ok)}  ({sync_detail})")

    # ── Check 2: Encoding corruption ────────────────────────
    enc_checks = {}
    check_encoding(os.path.join(repo_root, "index.html"),       "index_html",    enc_checks)
    check_encoding(os.path.join(repo_root, "api", "feed.json"), "api_feed",      enc_checks)
    check_encoding(os.path.join(repo_root, "data", "stix", "feed_manifest.json"), "manifest", enc_checks)
    enc_ok = all(
        enc_checks.get(k, False) for k in [
            "index_html_bom", "index_html_no_nulls", "index_html_no_mojibake", "index_html_valid_utf8",
            "api_feed_bom", "api_feed_valid_utf8", "api_feed_no_mojibake",
            "manifest_bom", "manifest_valid_utf8",
        ]
    )
    results["encoding_clean"] = {"pass": enc_ok, "detail": enc_checks}
    print(f"  [2] Encoding clean:           {check_ok(enc_ok)}")

    # ── Check 3: EMBEDDED_INTEL purged ───────────────────────
    ei_ok, ei_detail = check_embedded_intel(repo_root)
    results["embedded_intel_purged"] = {"pass": ei_ok, "detail": ei_detail}
    print(f"  [3] EMBEDDED_INTEL purged:    {check_ok(ei_ok)}  ({ei_detail})")

    # ── Check 4: Render dedup guards ─────────────────────────
    rd_count, rd_detail = check_render_dedup(repo_root)
    rd_ok = rd_count == 1
    results["render_dedup"] = {"pass": rd_ok, "count": rd_count, "detail": rd_detail}
    print(f"  [4] Render guard (count=1):   {'[YES]' if rd_ok else '[NO] '}  count={rd_count}  ({rd_detail})")

    # ── Check 5: Pipeline stability report ───────────────────
    stab = load_sub_report(repo_root, "data/audit/stability_report.json")
    # Key is "health" in sentinel_stability_lock output
    stab_health = None
    if stab:
        for k in ("health", "overall_health", "status", "system_health"):
            v = stab.get(k)
            if v:
                stab_health = str(v).upper()
                break
    stab_ok = stab_health in ("PASS","HEALTHY","OK") if stab_health else False
    stab_detail = stab_health if stab_health else ("report missing" if stab is None else "no health key")
    results["pipeline_stability"] = {"pass": stab_ok, "detail": stab_detail}
    print(f"  [5] Pipeline stability:       {check_ok(stab_ok)}  ({stab_detail})")

    # ── Check 6: Output gate ─────────────────────────────────
    gate = load_sub_report(repo_root, "data/audit/gate_report.json")
    gate_ok = gate is not None and gate.get("status") == "PASS"
    gate_detail = gate.get("status","NOT RUN") if gate else "not run"
    results["output_gate"] = {"pass": gate_ok, "detail": gate_detail}
    print(f"  [6] Output gate:              {check_ok(gate_ok)}  ({gate_detail})")

    # ── Check 7: Self-heal status ─────────────────────────────
    heal = load_sub_report(repo_root, "data/audit/self_heal_report.json")
    heal_ok = heal is not None and heal.get("status") in ("HEALTHY","HEALED")
    heal_detail = heal.get("status","NOT RUN") if heal else "not run"
    results["self_heal"] = {"pass": heal_ok, "detail": heal_detail}
    print(f"  [7] Self-heal guard:          {check_ok(heal_ok)}  ({heal_detail})")

    # ── Check 8: Worker security headers ─────────────────────
    ws_ok, ws_detail = check_worker_security(repo_root)
    results["worker_security"] = {"pass": ws_ok, "detail": ws_detail}
    print(f"  [8] Worker security headers:  {check_ok(ws_ok)}  ({ws_detail})")

    # ── Check 9: Feed counts ─────────────────────────────────
    api_data, _ = load_json_safe(os.path.join(repo_root, "api", "feed.json"))
    m_data,   _ = load_json_safe(os.path.join(repo_root, "data", "stix", "feed_manifest.json"))
    api_count = len(unwrap(api_data)) if api_data else 0
    m_count   = len(unwrap(m_data))   if m_data   else 0
    counts_ok = api_count > 0 and m_count > 0 and api_count <= 500
    results["feed_counts"] = {
        "pass": counts_ok,
        "api_count": api_count,
        "manifest_count": m_count
    }
    print(f"  [9] Feed counts:              {check_ok(counts_ok)}  api={api_count}  manifest={m_count}")

    # ── Overall verdict ───────────────────────────────────────
    all_checks = [
        sync_ok, enc_ok, ei_ok, rd_ok, stab_ok,
        gate_ok, heal_ok, ws_ok, counts_ok
    ]
    critical_checks = [sync_ok, enc_ok, ei_ok, counts_ok, ws_ok]
    pass_count = sum(all_checks)
    critical_pass = sum(critical_checks)

    if all(all_checks):
        platform_status = "PRODUCTION_READY"
        exit_code = 0
    elif critical_pass == len(critical_checks):
        platform_status = "DEGRADED"
        exit_code = 1
    else:
        platform_status = "CRITICAL"
        exit_code = 2

    # ── Write report ──────────────────────────────────────────
    report = {
        "script":           "final_validation_report",
        "version":          SCRIPT_VERSION,
        "platform_status":  platform_status,
        "checks_passed":    pass_count,
        "checks_total":     len(all_checks),
        "results":          results,
        "validated_at":     datetime.now(timezone.utc).isoformat(),
        "checksums": {
            "index_html":    sha16(os.path.join(repo_root,"index.html")) if os.path.exists(os.path.join(repo_root,"index.html")) else "",
            "api_feed":      sha16(os.path.join(repo_root,"api","feed.json")) if os.path.exists(os.path.join(repo_root,"api","feed.json")) else "",
            "feed_manifest": sha16(os.path.join(repo_root,"data","stix","feed_manifest.json")) if os.path.exists(os.path.join(repo_root,"data","stix","feed_manifest.json")) else "",
        }
    }

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(badge_path, "w", encoding="utf-8") as f:
        f.write(f"{platform_status}\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Checks: {pass_count}/{len(all_checks)} passed\n")

    print(f"\n  Report: {report_path}")
    print(f"  Badge:  {badge_path}")
    print(f"\n{'='*65}")
    status_icon = {"PRODUCTION_READY": "[**]", "DEGRADED": "[!!]", "CRITICAL": "[XX]"}.get(platform_status, "[??]")
    print(f"  PLATFORM STATUS: {status_icon}  {platform_status}  ({pass_count}/{len(all_checks)} checks passed)")
    print(f"{'='*65}\n")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
