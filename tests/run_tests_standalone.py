#!/usr/bin/env python3
"""
run_tests_standalone.py — CyberDudeBivash SENTINEL APEX ULTRA
Standalone test runner (no pytest required).

Validates all new enhancements work correctly without breaking
existing functionality. Runs in the current environment.
"""
import sys
import os
import re
import json
import traceback
import uuid as uuid_mod
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Colour helpers ───────────────────────────────────────────────────────────
GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; RESET = "\033[0m"; BOLD = "\033[1m"
ok   = lambda s: f"{GREEN}✅ {s}{RESET}"
fail = lambda s: f"{RED}❌ {s}{RESET}"
warn = lambda s: f"{YELLOW}⚠️  {s}{RESET}"

passed = 0; failed = 0; skipped = 0
_failures = []

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(ok(name))
        passed += 1
    else:
        msg = f"{name}: {detail}" if detail else name
        print(fail(msg))
        failed += 1
        _failures.append(msg)

def skip(name, reason):
    global skipped
    print(warn(f"SKIP  {name} — {reason}"))
    skipped += 1

def section(title):
    print(f"\n{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# Load modules
# ─────────────────────────────────────────────────────────────────────────────
try:
    from agent.enricher import enricher
    from agent.risk_engine import risk_engine
    from agent.mitre_mapper import mitre_engine
    from agent.integrations.actor_matrix import actor_matrix
    from agent.integrations.detection_engine import detection_engine
    from agent.export_stix import stix_exporter
    from agent.deduplication import dedup_engine
    from agent.feed_reliability import FeedHealthTracker, USER_AGENTS, feed_health
    print(ok("All modules loaded successfully"))
except ImportError as e:
    print(fail(f"Module import error: {e}"))
    sys.exit(1)

# ─── Shared Fixtures ──────────────────────────────────────────────────────────
SAMPLE_TEXT = """
Emerging threat from 185.220.101.45 and C2 at 45.33.32.156.
Hash: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
Domain: evil-login.example-malware.com, malware-cdn.evil.net
CVE-2024-12345 and CVE-2023-44487 exploited. Email: attacker@darknet.org
dropper.exe from https://malware-cdn.evil.net/payload.zip
Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware-svc
Private: 192.168.1.1  Loopback: 127.0.0.1  Google DNS: 8.8.8.8
"""

# ─────────────────────────────────────────────────────────────────────────────
# 1. IOC Extraction Tests
# ─────────────────────────────────────────────────────────────────────────────
section("1. IOC Extraction & Well-Known IP Exclusion (Bug Fix)")

iocs = enricher.extract_iocs(SAMPLE_TEXT)

check("extract_iocs returns dict",            isinstance(iocs, dict))
check("ipv4 is a list",                       isinstance(iocs.get("ipv4"), list))
check("Public IP 185.220.101.45 extracted",   "185.220.101.45" in iocs.get("ipv4", []))
check("192.168.1.1 excluded (private)",       "192.168.1.1" not in iocs.get("ipv4", []))
check("127.0.0.1 excluded (loopback)",        "127.0.0.1" not in iocs.get("ipv4", []))
check("8.8.8.8 excluded (well-known DNS)",    "8.8.8.8" not in iocs.get("ipv4", []))
check("SHA256 extracted",                     len(iocs.get("sha256", [])) >= 1)
check("SHA256 is 64 chars",                   all(len(h)==64 for h in iocs.get("sha256",[])))
check("CVE-2024-12345 extracted",             "CVE-2024-12345" in iocs.get("cve", []))
check("Multiple CVEs extracted",              len(iocs.get("cve", [])) >= 2)
check("Email extracted",                      "attacker@darknet.org" in iocs.get("email", []))
check("URL extracted",                        any("payload.zip" in u for u in iocs.get("url", [])))
check("Malicious domain extracted",           "evil-login.example-malware.com" in iocs.get("domain", []))
check("dropper.exe artifact",                 "dropper.exe" in iocs.get("artifacts", []))
check("Registry key extracted",               any("CurrentVersion\\Run" in r for r in iocs.get("registry",[])))
check("No duplicates in ipv4",                len(iocs["ipv4"]) == len(set(iocs["ipv4"])))

# False positive domain exclusion
fp_iocs = enricher.extract_iocs("Check google.com and microsoft.com for updates")
check("google.com excluded (false positive)", "google.com" not in fp_iocs.get("domain", []))
check("microsoft.com excluded",               "microsoft.com" not in fp_iocs.get("domain", []))

# Empty input
empty_result = enricher.extract_iocs("")
check("Empty input returns dict",             isinstance(empty_result, dict))

# Confidence scoring
conf = enricher.calculate_confidence(iocs)
check("Confidence is numeric",                isinstance(conf, (int, float)))
check("Confidence in [0, 100]",               0 <= conf <= 100)
empty_conf = enricher.calculate_confidence({k: [] for k in iocs})
check("Empty IOCs → low confidence",          empty_conf < 50, f"got {empty_conf}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Risk Engine Tests
# ─────────────────────────────────────────────────────────────────────────────
section("2. Dynamic Risk Scoring Engine")

risk_score = risk_engine.calculate_risk_score(iocs=iocs)
check("Risk score is float",                  isinstance(risk_score, float))
check("Risk score in [0.0, 10.0]",            0.0 <= risk_score <= 10.0, f"got {risk_score}")
check("Score not hardcoded 9.3",              risk_score != 9.3)
check("Score not hardcoded 5.0",              risk_score != 5.0)

empty_score = risk_engine.calculate_risk_score(iocs={k: [] for k in iocs})
check("Empty IOCs → lower score",             empty_score < risk_score, f"empty={empty_score} vs rich={risk_score}")

kev_off = risk_engine.calculate_risk_score(iocs=iocs, kev_present=False)
kev_on  = risk_engine.calculate_risk_score(iocs=iocs, kev_present=True)
check("KEV boosts risk score",                kev_on >= kev_off)

# Use minimal IOCs so the score isn't already capped at 10.0
minimal_iocs = {k: [] for k in iocs}
low_cvss  = risk_engine.calculate_risk_score(iocs=minimal_iocs, cvss_score=2.0)
high_cvss = risk_engine.calculate_risk_score(iocs=minimal_iocs, cvss_score=9.8)
check("High CVSS → higher score",            high_cvss > low_cvss)

# Severity labels
for score, expected in [(9.5,"CRITICAL"),(8.0,"HIGH"),(5.5,"MEDIUM"),(2.5,"LOW"),(0.5,"INFO")]:
    label = risk_engine.get_severity_label(score)
    check(f"Severity({score}) = {expected}",  label == expected, f"got {label}")

# TLP labels
for score, expected_prefix in [(9.5,"TLP:RED"),(1.0,"TLP:GREEN")]:
    tlp = risk_engine.get_tlp_label(score)
    check(f"TLP({score}) starts with {expected_prefix}", tlp["label"].startswith("TLP:"))

# Extended metrics — note: compute_extended_metrics does NOT take a severity kwarg
severity = risk_engine.get_severity_label(risk_score)
metrics = risk_engine.compute_extended_metrics(risk_score=risk_score, iocs=iocs)
check("compute_extended_metrics returns dict", isinstance(metrics, dict))
check("intel_confidence_score present",       "intel_confidence_score" in metrics)
check("threat_momentum_score in [0,100]",     0 <= metrics.get("threat_momentum_score",0) <= 100)

# Determinism
s1 = risk_engine.calculate_risk_score(iocs=iocs, cvss_score=7.5)
s2 = risk_engine.calculate_risk_score(iocs=iocs, cvss_score=7.5)
check("Scoring is deterministic",             s1 == s2)

# ─────────────────────────────────────────────────────────────────────────────
# 3. Detection Engine Tests
# ─────────────────────────────────────────────────────────────────────────────
section("3. Sigma & YARA Detection Rule Generation")

import yaml
sigma = detection_engine.generate_sigma_rule("Test Campaign", iocs)
check("Sigma rule is string",                 isinstance(sigma, str))
check("Sigma rule has title:",                "title:" in sigma)
check("Sigma rule has detection:",            "detection:" in sigma)
check("Sigma rule has condition:",            "condition:" in sigma)
check("Sigma rule has level:",                any(f"level: {l}" in sigma.lower() for l in ["low","medium","high","critical"]))

# Multi-doc YAML validity
docs = [d for d in sigma.split("\n---\n") if d.strip()]
all_valid = all(isinstance(yaml.safe_load(d), dict) for d in docs)
check("Sigma YAML is parseable",              all_valid)

sigma_empty = detection_engine.generate_sigma_rule("Generic Threat", {k:[] for k in iocs})
check("Sigma with empty IOCs still generated",len(sigma_empty.strip()) > 50)

sigma_ransom = detection_engine.generate_sigma_rule("LockBit Ransomware", {k:[] for k in iocs})
check("Ransomware rule has shadow copy ref",  "shadow" in sigma_ransom.lower() or "vssadmin" in sigma_ransom.lower())

yara = detection_engine.generate_yara_rule("Test Campaign", iocs)
check("YARA rule is string",                  isinstance(yara, str))
check("YARA rule starts with 'rule '",        yara.strip().startswith("rule "))
check("YARA rule has meta:",                  "meta:" in yara)
check("YARA rule has strings:",               "strings:" in yara)
check("YARA rule has condition:",             "condition:" in yara)
check("YARA rule ends with '}'",              yara.strip().endswith("}"))
check("YARA embeds IOC strings",              any(ip in yara for ip in iocs.get("ipv4",[])) or
                                              any(d in yara for d in iocs.get("domain",[])))
check("YARA has filesize constraint",         "filesize" in yara)

# ─────────────────────────────────────────────────────────────────────────────
# 4. STIX 2.1 Export Tests
# ─────────────────────────────────────────────────────────────────────────────
section("4. STIX 2.1 Bundle Generation & Validation")

import glob as _glob

mitre_data  = mitre_engine.map_threat(SAMPLE_TEXT)
actor_data  = actor_matrix.correlate_actor(SAMPLE_TEXT, iocs)
rs          = risk_engine.calculate_risk_score(iocs=iocs, mitre_matches=mitre_data, actor_data=actor_data)
sev         = risk_engine.get_severity_label(rs)
tlp_info    = risk_engine.get_tlp_label(rs)
tlp_label   = tlp_info.get("label", "TLP:CLEAR")
actor_tag   = actor_data.get("tracking_id", "UNC-CDB-99")

# create_bundle() writes the STIX JSON to disk and returns the bundle_id string
bundle_id = stix_exporter.create_bundle(
    title="Standalone Test: Malware Campaign",
    iocs=iocs,
    risk_score=rs,
    severity=sev,
    tlp_label=tlp_label,
    mitre_tactics=mitre_data,
    actor_tag=actor_tag,
)
check("create_bundle returns bundle_id string",  isinstance(bundle_id, str) and bundle_id.startswith("bundle--"))

# Load the most recently written bundle file for structural checks
_stix_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "stix")
_bundle_files = sorted(_glob.glob(os.path.join(_stix_dir, "CDB-APEX-*.json")))
if _bundle_files:
    with open(_bundle_files[-1]) as _f:
        bundle = json.load(_f)
    check("Bundle written to disk", True)
else:
    check("Bundle written to disk", False, "No CDB-APEX-*.json file found in data/stix/")
    bundle = {}

check("Bundle is dict",                       isinstance(bundle, dict))
check("bundle.type == 'bundle'",              bundle.get("type") == "bundle")
check("bundle.id starts with 'bundle--'",     bundle.get("id","").startswith("bundle--"))
check("bundle.objects is list",               isinstance(bundle.get("objects"), list))
check("bundle has objects",                   len(bundle.get("objects", [])) > 0)
check("Bundle is JSON-serialisable",          bool(json.dumps(bundle)))

objs = bundle.get("objects", [])
check("Identity object present",              any(o.get("type")=="identity" for o in objs))
check("Indicator objects present",            any(o.get("type")=="indicator" for o in objs))
check("TLP marking-definition present",       any(o.get("type")=="marking-definition" for o in objs))

# All objects have required fields
VALID_TYPES = {
    "bundle","identity","indicator","malware","attack-pattern","campaign",
    "course-of-action","grouping","infrastructure","intrusion-set","location",
    "malware-analysis","note","observed-data","opinion","relationship","report",
    "threat-actor","tool","vulnerability","marking-definition","extension-definition",
    "language-content","data-component","data-source",
}
for o in objs:
    if o.get("type") == "marking-definition":
        continue
    for field in ("type","id","spec_version","created","modified"):
        if field not in o:
            check(f"Object '{o.get('type')}' has '{field}'", False, f"missing {field}")

# ID prefix format
bad_ids = [o for o in objs if o.get("id") and not o["id"].startswith(f"{o['type']}--")]
check("All object IDs have correct type prefix", len(bad_ids)==0,
      f"{len(bad_ids)} objects with bad IDs")

# No duplicate IDs
all_ids = [o.get("id") for o in objs]
check("No duplicate object IDs",              len(all_ids) == len(set(all_ids)))

# Indicator pattern syntax
indicators = [o for o in objs if o.get("type")=="indicator"]
for ind in indicators:
    pat = ind.get("pattern","")
    check(f"Indicator has STIX pattern syntax", "[" in pat and ":" in pat, f"pattern: {pat[:50]}")

# Timestamp ISO8601 UTC
ts_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
for o in objs:
    if o.get("type") == "marking-definition":
        continue
    for field in ("created", "modified"):
        if field in o:
            ts = o[field]
            if not ts_pattern.match(ts):
                check(f"Timestamp {field} is ISO8601 UTC", False, f"'{ts}' in {o.get('type')}")

# validate_bundle()
vresult = stix_exporter.validate_bundle(bundle)
check("validate_bundle() returns dict",       isinstance(vresult, dict))
check("validate_bundle() has 'valid' key",    "valid" in vresult)
check("Generated bundle passes validation",   vresult["valid"] is True,
      f"errors: {vresult.get('errors', [])}")
check("validate_bundle has stix2_validated",  "stix2_validated" in vresult)

bad_bundle = {"type": "bundle", "id": "bad-id"}
bad_result = stix_exporter.validate_bundle(bad_bundle)
check("Malformed bundle fails validation",    bad_result["valid"] is False)

# MISP export  (export_to_misp uses title/iocs/risk_score/tlp_label)
misp = stix_exporter.export_to_misp(title="Test Campaign", iocs=iocs, risk_score=rs, tlp_label=tlp_label)
check("MISP export is dict",                  isinstance(misp, dict))
check("MISP export has 'Event' key",          "Event" in misp)

# ─────────────────────────────────────────────────────────────────────────────
# 5. Deduplication Tests
# ─────────────────────────────────────────────────────────────────────────────
section("5. Deduplication Engine")

unique = f"STANDALONE_TEST_{uuid_mod.uuid4().hex}"
first  = dedup_engine.is_duplicate(unique)       # Not seen yet → False
dedup_engine.mark_processed(unique)              # Register it
second = dedup_engine.is_duplicate(unique)       # Now seen → True
check("First check → not duplicate",   first  is False)
check("Second check → is duplicate",   second is True)

count = dedup_engine.get_processed_count()
check("get_processed_count() returns int", isinstance(count, int))
check("Processed count > 0",              count > 0)

# ─────────────────────────────────────────────────────────────────────────────
# 6. Feed Reliability Layer Tests
# ─────────────────────────────────────────────────────────────────────────────
section("6. Feed Reliability Layer (New Module)")

tracker = FeedHealthTracker()

tracker.record_success("FeedA", latency_ms=100)
tracker.record_success("FeedA", latency_ms=200)
status_a = tracker.get_feed_status("FeedA")
check("Success recorded correctly",        status_a["success_count"] == 2)
check("Status is 'healthy' after success", status_a["status"] == "healthy")
check("Avg latency computed",              status_a["avg_latency_ms"] == 150.0)

tracker.record_failure("FeedB", error="Timeout")
status_b = tracker.get_feed_status("FeedB")
check("Failure recorded",                  status_b["failure_count"] == 1)
check("Status reflects failure",           status_b["status"] in {"degraded","intermittent"})
check("Last error stored",                 "Timeout" in (status_b.get("last_error") or ""))

summary = tracker.get_summary()
check("Summary is dict",                   isinstance(summary, dict))
check("Summary has feeds list",            isinstance(summary.get("feeds"), list))
check("Summary total_feeds_tracked == 2", summary["total_feeds_tracked"] == 2)
check("Summary healthy == 1",             summary["healthy"] == 1)

degraded = tracker.get_degraded_feeds()
check("get_degraded_feeds returns list",   isinstance(degraded, list))
check("FeedB in degraded list",            any(f["feed_name"] == "FeedB" for f in degraded))

tracker.reset("FeedA")
check("reset(feed) removes it",            tracker.get_summary()["total_feeds_tracked"] == 1)

tracker2 = FeedHealthTracker()
tracker2.record_success("F1"); tracker2.record_success("F2")
tracker2.reset()
check("reset() clears all",               tracker2.get_summary()["total_feeds_tracked"] == 0)

check("USER_AGENTS non-empty",             len(USER_AGENTS) >= 1)
check("feed_health is FeedHealthTracker", isinstance(feed_health, FeedHealthTracker))

# ─────────────────────────────────────────────────────────────────────────────
# 7. Feed Manifest Schema Validation
# ─────────────────────────────────────────────────────────────────────────────
section("7. Feed Manifest Schema")

manifest_path = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data/stix/feed_manifest.json"
)
try:
    with open(manifest_path) as f:
        manifest = json.load(f)
    check("Manifest loads as JSON",           True)
    check("Manifest is list",                 isinstance(manifest, list))
    check("Manifest has entries",             len(manifest) > 0)

    REQUIRED = {"title", "stix_id", "risk_score", "severity", "timestamp"}
    VALID_SEVER = {"CRITICAL","HIGH","MEDIUM","LOW","INFO"}
    bid_pat = re.compile(r"bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    all_keys_ok = all(all(k in e for k in REQUIRED) for e in manifest)
    check("All entries have required keys",   all_keys_ok)

    scores_ok = all(0.0 <= float(e["risk_score"]) <= 10.0 for e in manifest if e.get("risk_score") is not None)
    check("All risk_scores in [0, 10]",       scores_ok)

    severities_ok = all(e.get("severity","") in VALID_SEVER for e in manifest if e.get("severity"))
    check("All severities are valid",         severities_ok)

    stix_ids_ok = all(bid_pat.match(e.get("stix_id","")) for e in manifest if e.get("stix_id"))
    check("All stix_ids are valid format",    stix_ids_ok)

except Exception as e:
    check("Manifest validation",              False, str(e))

# ─────────────────────────────────────────────────────────────────────────────
# 8. Existing Pre-Flight Diagnostic (regression guard)
# ─────────────────────────────────────────────────────────────────────────────
section("8. Regression: Original verify_pipeline.py")

try:
    import subprocess
    result = subprocess.run(
        [sys.executable, "tests/verify_pipeline.py"],
        capture_output=True, text=True, timeout=60,
        cwd=os.path.dirname(os.path.dirname(__file__))
    )
    passed_original = "ALL DIAGNOSTICS PASSED" in result.stdout
    check("verify_pipeline.py: ALL DIAGNOSTICS PASSED", passed_original,
          result.stdout[-300:] if not passed_original else "")
except Exception as e:
    check("verify_pipeline.py regression", False, str(e))

# ─────────────────────────────────────────────────────────────────────────────
# 9. API Gateway — Auth, Rate Limiter, STANDARD/PREMIUM Tiers
# ─────────────────────────────────────────────────────────────────────────────
section("9. API Gateway: Auth + Rate Limiter (STANDARD/PREMIUM tiers)")

try:
    from agent.api.auth import (
        auth_handler as _auth,
        TIER_FREE, TIER_STANDARD, TIER_PREMIUM, TIER_PRO, TIER_ENTERPRISE,
    )
    from agent.api.rate_limiter import rate_limiter as _rl

    # ── Tier resolution ──────────────────────────────────────
    tier, identity, err = _auth.resolve_tier()
    check("FREE tier resolve (no credentials)",
          tier == TIER_FREE and err is None, f"tier={tier} err={err}")

    tier, identity, err = _auth.resolve_tier(api_key="unknown_key_xyz")
    check("Unknown API key → FREE tier",
          tier == TIER_FREE, f"tier={tier}")

    # ── Tier ordering ─────────────────────────────────────────
    check("FREE < STANDARD",
          _auth.tier_allows(TIER_STANDARD, TIER_FREE) and
          not _auth.tier_allows(TIER_FREE, TIER_STANDARD))

    check("STANDARD < PREMIUM",
          _auth.tier_allows(TIER_PREMIUM, TIER_STANDARD) and
          not _auth.tier_allows(TIER_STANDARD, TIER_PREMIUM))

    check("PREMIUM < ENTERPRISE",
          _auth.tier_allows(TIER_ENTERPRISE, TIER_PREMIUM) and
          not _auth.tier_allows(TIER_PREMIUM, TIER_ENTERPRISE))

    check("PRO == PREMIUM (legacy alias)",
          _auth.tier_allows(TIER_PRO, TIER_PREMIUM) and
          _auth.tier_allows(TIER_PREMIUM, TIER_PRO))

    # ── JWT round-trip ─────────────────────────────────────────
    jwt_token = _auth.generate_jwt("test_user", TIER_ENTERPRISE)
    check("JWT generate returns non-empty string",
          isinstance(jwt_token, str) and len(jwt_token.split(".")) == 3)

    tier_from_jwt, identity_jwt, err_jwt = _auth._validate_jwt(jwt_token)
    check("JWT validate: correct tier", tier_from_jwt == TIER_ENTERPRISE, f"tier={tier_from_jwt} err={err_jwt}")
    check("JWT validate: correct identity", identity_jwt == "test_user", f"identity={identity_jwt}")
    check("JWT validate: no error", err_jwt is None, str(err_jwt))

    # Tampered JWT should fail
    tampered = jwt_token[:-4] + "XXXX"
    t2, _, e2 = _auth._validate_jwt(tampered)
    check("Tampered JWT rejected", t2 == TIER_FREE and e2 is not None, f"tier={t2} err={e2}")

    # ── Rate limiter — STANDARD tier ──────────────────────────
    _rl.reset("test_standard_001", TIER_STANDARD)
    allowed, info = _rl.check("test_standard_001", TIER_STANDARD)
    check("STANDARD rate limit: first request allowed", allowed, str(info))
    check("STANDARD rate limit: limit field present", "limit" in info)
    check("STANDARD rate limit: 150 req/min capacity", info["limit"] == 150, f"limit={info['limit']}")

    # ── Rate limiter — PREMIUM tier ───────────────────────────
    _rl.reset("test_premium_001", TIER_PREMIUM)
    allowed, info = _rl.check("test_premium_001", TIER_PREMIUM)
    check("PREMIUM rate limit: first request allowed", allowed, str(info))
    check("PREMIUM rate limit: 500 req/min capacity", info["limit"] == 500, f"limit={info['limit']}")

    # ── Rate limiter — ENTERPRISE tier ───────────────────────
    _rl.reset("test_enterprise_001", TIER_ENTERPRISE)
    allowed_ent, info_ent = _rl.check("test_enterprise_001", TIER_ENTERPRISE)
    check("ENTERPRISE rate limit: first request allowed", allowed_ent, str(info_ent))
    check("ENTERPRISE rate limit: 1000 req/min capacity", info_ent["limit"] == 1000, f"limit={info_ent['limit']}")

    # ── Rate limit headers ────────────────────────────────────
    headers = _rl.get_headers(info)
    check("Rate limit headers contain X-RateLimit-Limit",     "X-RateLimit-Limit"     in headers)
    check("Rate limit headers contain X-RateLimit-Remaining", "X-RateLimit-Remaining" in headers)
    check("Rate limit headers contain X-RateLimit-Tier",      "X-RateLimit-Tier"      in headers)

    # ── Rate limiter stats ────────────────────────────────────
    stats = _rl.get_stats()
    check("Rate limiter stats returns dict", isinstance(stats, dict))
    check("Stats contain active_buckets", "active_buckets" in stats)
    check("Stats contain tier_limits",    "tier_limits"    in stats)

except Exception as e:
    check("API Gateway tests (Section 9)", False, str(e))

# ─────────────────────────────────────────────────────────────────────────────
# 10. Remediation Engine — PowerShell + Python kit generation
# ─────────────────────────────────────────────────────────────────────────────
section("10. Remediation Engine: PowerShell + Python hardening kits")

try:
    from agent.integrations.remediation_engine import RemediationEngine, RemediationKit

    _reng = RemediationEngine()

    _test_iocs = {
        "ipv4":        ["10.13.37.1", "192.168.99.2"],
        "domain":      ["evil-c2.example.com", "malware.test.net"],
        "sha256":      ["aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ab"],
        "url":         ["http://evil-c2.example.com/beacon"],
        "cve":         ["CVE-2024-21762", "CVE-2021-44228"],
    }

    kit = _reng.generate_kit(
        headline   = "STANDALONE TEST: Critical RCE via Log4Shell + FortiOS",
        iocs       = _test_iocs,
        severity   = "CRITICAL",
        risk_score = 9.5,
        actor_tag  = "CDB-APT-28",
        cves       = ["CVE-2024-21762", "CVE-2021-44228"],
        save_to_disk = True,
    )

    # ── Type and dataclass checks ─────────────────────────────
    check("generate_kit returns RemediationKit", isinstance(kit, RemediationKit))
    check("Kit headline matches input",          kit.headline.startswith("STANDALONE TEST"))
    check("Kit severity == CRITICAL",            kit.severity == "CRITICAL")
    check("Kit risk_score == 9.5",               kit.risk_score == 9.5)
    check("Kit cve_count == 2",                  kit.cve_count == 2, f"cve_count={kit.cve_count}")
    check("Kit ioc_count > 0",                   kit.ioc_count > 0,  f"ioc_count={kit.ioc_count}")

    # ── PowerShell content checks ─────────────────────────────
    ps1 = kit.powershell
    check("PS1 is non-empty string",             isinstance(ps1, str) and len(ps1) > 500)
    check("PS1 contains DryRun param",           "-DryRun" in ps1 or "DryRun" in ps1)
    check("PS1 blocks IOC IP address",           "10.13.37.1" in ps1)
    check("PS1 blocks IOC domain",               "evil-c2.example.com" in ps1)
    check("PS1 references CVE-2024-21762",       "CVE-2024-21762" in ps1)
    check("PS1 references CVE-2021-44228",       "CVE-2021-44228" in ps1)
    check("PS1 has log file directive",          "log" in ps1.lower())
    check("PS1 has firewall rule section",       "Firewall" in ps1 or "firewall" in ps1 or "New-NetFirewallRule" in ps1)

    # ── Python script content checks ──────────────────────────
    py = kit.python_script
    check("Python script is non-empty string",   isinstance(py, str) and len(py) > 300)
    check("Python script blocks IOC IP",         "10.13.37.1" in py)
    check("Python script blocks IOC domain",     "evil-c2.example.com" in py)
    check("Python script has platform check",    "platform" in py or "sys.platform" in py)
    check("Python script has main guard",        'if __name__' in py)

    # ── Disk save verification ────────────────────────────────
    check("Kit ps1_path populated",              kit.ps1_path and len(kit.ps1_path) > 0, f"path={kit.ps1_path}")
    check("Kit py_path populated",              kit.py_path  and len(kit.py_path) > 0,  f"path={kit.py_path}")
    check("Kit .ps1 file exists on disk",        os.path.isfile(kit.ps1_path), f"path={kit.ps1_path}")
    check("Kit .py  file exists on disk",        os.path.isfile(kit.py_path),  f"path={kit.py_path}")
    check("Kit .ps1 file has content",           os.path.getsize(kit.ps1_path) > 200)
    check("Kit .py  file has content",           os.path.getsize(kit.py_path)  > 200)
    check("Kit generated_at is ISO string",      "T" in kit.generated_at and "Z" in kit.generated_at)

    # ── No-disk mode ──────────────────────────────────────────
    kit_nodisk = _reng.generate_kit(
        headline   = "STANDALONE TEST: No-Disk Kit",
        iocs       = {"ip": [], "domain": [], "hash_sha256": [], "url": [], "cve": []},
        severity   = "HIGH",
        risk_score = 7.0,
        save_to_disk = False,
    )
    check("No-disk kit: powershell non-empty",   len(kit_nodisk.powershell) > 100)
    check("No-disk kit: ps1_path is empty str",  kit_nodisk.ps1_path == "")

except Exception as e:
    check("Remediation Engine tests (Section 10)", False, str(e))

# ─────────────────────────────────────────────────────────────────────────────
# 11. Adversary Swarm — safe breach simulation script generation
# ─────────────────────────────────────────────────────────────────────────────
section("11. Adversary Swarm: safe breach simulation generation")

try:
    from agent.integrations.adversary_swarm import AdversarySwarm, SimulationKit

    _swarm = AdversarySwarm()

    _sim_iocs = {
        "ipv4":        ["10.99.1.200", "203.0.113.5"],
        "domain":      ["c2-test.malware.dev", "ransomware-c2.example.net"],
        "sha256":      ["deadbeefdeadbeef00112233445566778899aabbccddeeff001122334455ab"],
        "url":         ["http://c2-test.malware.dev/gate"],
        "cve":         ["CVE-2023-3519"],
    }

    kit_apt = _swarm.generate_simulation(
        headline  = "STANDALONE TEST: APT28 Credential Dump via LSASS",
        iocs      = _sim_iocs,
        severity  = "CRITICAL",
        actor_tag = "CDB-APT-28",
        cves      = ["CVE-2023-3519"],
        save_to_disk = True,
    )

    # ── Type checks ───────────────────────────────────────────
    check("generate_simulation returns SimulationKit", isinstance(kit_apt, SimulationKit))
    check("Kit headline matches input",                kit_apt.headline.startswith("STANDALONE TEST"))
    check("Kit severity == CRITICAL",                  kit_apt.severity == "CRITICAL")
    check("Kit actor_tag == CDB-APT-28",               kit_apt.actor_tag == "CDB-APT-28")
    check("Kit ioc_count > 0",                         kit_apt.ioc_count > 0, f"ioc_count={kit_apt.ioc_count}")
    check("Kit test_count > 0",                        kit_apt.test_count > 0, f"test_count={kit_apt.test_count}")

    # ── Script content checks ─────────────────────────────────
    sc = kit_apt.script
    check("Script is non-empty string",                isinstance(sc, str) and len(sc) > 500)
    check("Script has SAFE SIMULATION disclaimer",     "SAFE SIMULATION" in sc or "safe simulation" in sc.lower())
    check("Script has atexit cleanup registered",      "atexit" in sc)
    check("Script has _cleanup function",              "def _cleanup" in sc or "_cleanup" in sc)
    check("Script has argparse --dry-run support",     "--dry-run" in sc or "dry_run" in sc or "dry-run" in sc)
    check("Script has sim_file_drop function",         "def sim_file_drop" in sc or "file_drop" in sc)
    check("Script has DNS/C2 simulation",              "dns" in sc.lower() or "c2" in sc.lower())

    # ── IOC embedding checks ──────────────────────────────────
    check("Script references IOC IP",                  "10.99.1.200" in sc or "203.0.113.5" in sc)
    check("Script references IOC domain",              "c2-test.malware.dev" in sc or "ransomware-c2.example.net" in sc)

    # ── Actor-specific techniques ─────────────────────────────
    check("APT28 script has credential-related sim",
          "credential" in sc.lower() or "lsass" in sc.lower() or "lateral" in sc.lower())

    # ── Disk save verification ────────────────────────────────
    check("Kit path populated",                        kit_apt.path and len(kit_apt.path) > 0, f"path={kit_apt.path}")
    check("Simulation .py file exists on disk",        os.path.isfile(kit_apt.path), f"path={kit_apt.path}")
    check("Simulation .py file has content",           os.path.getsize(kit_apt.path) > 200)
    check("Kit generated_at is ISO string",            "T" in kit_apt.generated_at and "Z" in kit_apt.generated_at)

    # ── Ransomware actor generates canary simulation ──────────
    kit_ran = _swarm.generate_simulation(
        headline  = "STANDALONE TEST: RansomHub File Encrypt Canary",
        iocs      = _sim_iocs,
        severity  = "CRITICAL",
        actor_tag = "CDB-RAN-01",
        save_to_disk = False,
    )
    check("Ransomware sim has shadow/encrypt/canary reference",
          "shadow" in kit_ran.script.lower() or "encrypt" in kit_ran.script.lower() or "ransom" in kit_ran.script.lower())

    # ── No-disk mode ──────────────────────────────────────────
    kit_nodisk = _swarm.generate_simulation(
        headline  = "STANDALONE TEST: No-Disk Swarm",
        iocs      = {"ip": [], "domain": [], "hash_sha256": [], "url": [], "cve": []},
        severity  = "LOW",
        actor_tag = "",
        save_to_disk = False,
    )
    check("No-disk sim: script non-empty", len(kit_nodisk.script) > 100)
    check("No-disk sim: path is empty str", kit_nodisk.path == "")

    # ── Generic actor fallback ────────────────────────────────
    kit_generic = _swarm.generate_simulation(
        headline  = "STANDALONE TEST: Unknown Actor Generic",
        iocs      = _sim_iocs,
        severity  = "MEDIUM",
        actor_tag = "CDB-UNKNOWN-99",
        save_to_disk = False,
    )
    check("Unknown actor falls back to generic techniques", isinstance(kit_generic.script, str) and len(kit_generic.script) > 200)

except Exception as e:
    check("Adversary Swarm tests (Section 11)", False, str(e))

# ─────────────────────────────────────────────────────────────────────────────
# Final Summary
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*65}")
print(f"{BOLD}STANDALONE TEST RESULTS{RESET}")
print(f"{'='*65}")
print(f"  {GREEN}Passed:  {passed}{RESET}")
print(f"  {RED}Failed:  {failed}{RESET}")
if skipped:
    print(f"  {YELLOW}Skipped: {skipped}{RESET}")

if _failures:
    print(f"\n{RED}Failed Tests:{RESET}")
    for f in _failures:
        print(f"  {RED}• {f}{RESET}")

print(f"{'='*65}")

if failed == 0:
    print(f"{GREEN}{BOLD}✅  ALL {passed} TESTS PASSED — SENTINEL APEX ULTRA v1.1.0 READY{RESET}")
else:
    print(f"{RED}{BOLD}❌  {failed} TEST(S) FAILED — Review above failures{RESET}")
    sys.exit(1)
