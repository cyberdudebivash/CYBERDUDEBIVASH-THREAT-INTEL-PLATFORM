#!/usr/bin/env python3
"""
test_ioc_engine_p0_fix.py — P0 Fix Validation Test Suite
CYBERDUDEBIVASH® SENTINEL APEX
================================================
Tests for ALL four root-cause fixes applied 2026-06-06.

Run: python3 test_ioc_engine_p0_fix.py

All tests must PASS before clean_feed.py is run.
Zero failures tolerated — production is live.

Test structure:
  PASS = value/text correctly extracted or accepted
  FAIL = value/text correctly rejected (false positive eliminated)

Each test case documents the evidence basis for the rule.
"""
from __future__ import annotations
import sys, json, traceback
sys.path.insert(0, '.')

from agent.ioc_engine import (
    extract_iocs,
    enforce_ioc_integrity,
    _is_valid_extracted_domain,
    _extract_domains,
    _FILE_EXT_BLOCKLIST,
)

PASS = 0
FAIL = 0
ERRORS = []

def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✓  {name}")
    else:
        FAIL += 1
        ERRORS.append(name)
        print(f"  ✗  FAIL: {name}  [{detail}]")


# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 — _FILE_EXT_BLOCKLIST additions
# Evidence: store.ts in 33/44 items, app.asar, exe.config, ntds.dit, rc.local
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 1: File Extension Blocklist ===")

# TypeScript — THE original P0 trigger
check("store.ts REJECTED", not _is_valid_extracted_domain("store.ts"),
      "store.ts was in 33/44 feed items — must be blocked")
check("index.ts REJECTED", not _is_valid_extracted_domain("index.ts"))
check("app.ts REJECTED",   not _is_valid_extracted_domain("app.ts"))
check("main.ts REJECTED",  not _is_valid_extracted_domain("main.ts"))
check("utils.ts REJECTED", not _is_valid_extracted_domain("utils.ts"))

# React / JSX
check("component.tsx REJECTED", not _is_valid_extracted_domain("component.tsx"))
check("app.jsx REJECTED",       not _is_valid_extracted_domain("app.jsx"))
check("page.jsx REJECTED",      not _is_valid_extracted_domain("page.jsx"))

# Modern JS modules
check("module.mjs REJECTED", not _is_valid_extracted_domain("module.mjs"))
check("bundle.cjs REJECTED",  not _is_valid_extracted_domain("bundle.cjs"))

# Other languages
check("main.go REJECTED",    not _is_valid_extracted_domain("main.go"))
check("lib.rs REJECTED",     not _is_valid_extracted_domain("lib.rs"))
check("Program.cs REJECTED", not _is_valid_extracted_domain("Program.cs"))
check("Main.kt REJECTED",    not _is_valid_extracted_domain("Main.kt"))
check("App.swift REJECTED",  not _is_valid_extracted_domain("App.swift"))
check("app.vue REJECTED",    not _is_valid_extracted_domain("app.vue"))
check("App.dart REJECTED",   not _is_valid_extracted_domain("App.dart"))

# Package / system files — proven evidence
check("app.asar REJECTED",             not _is_valid_extracted_domain("app.asar"),
      "app.asar seen in live feed")
check("xprotect-150.dmg REJECTED",     not _is_valid_extracted_domain("xprotect-150.dmg"),
      "xprotect-remediator-150.dmg seen in live feed")
check("ntds.dit REJECTED",             not _is_valid_extracted_domain("ntds.dit"),
      "ntds.dit (AD DB) seen in live feed")
check("app.config REJECTED",           not _is_valid_extracted_domain("app.config"),
      "exe.config, web.config seen in live feed")
check("rc.local REJECTED",             not _is_valid_extracted_domain("rc.local"),
      "rc.local, vsphere.local seen in live feed")
check("vsphere.local REJECTED",        not _is_valid_extracted_domain("vsphere.local"))
check("overview.jsp REJECTED",         not _is_valid_extracted_domain("overview.jsp"),
      "overview.jsp seen in live feed")
check("aws.ds REJECTED",               not _is_valid_extracted_domain("aws.ds"),
      ".ds is macOS data store extension, not IANA ccTLD")
check("server.pem REJECTED",           not _is_valid_extracted_domain("server.pem"))
check("cert.key REJECTED",             not _is_valid_extracted_domain("cert.key"))

# Regression: legitimate domains that MUST NOT be blocked
check("malware.evil.ru ACCEPTED",         _is_valid_extracted_domain("malware.evil.ru"))
check("c2.domain.com ACCEPTED",           _is_valid_extracted_domain("c2.domain.com"))
check("phish.azurewebsites.net ACCEPTED", _is_valid_extracted_domain("phish.azurewebsites.net"))
check("baxe.pics ACCEPTED",               _is_valid_extracted_domain("baxe.pics"),
      ".pics is a real gTLD — must not be blocked")
check("payload.delivery ACCEPTED",        _is_valid_extracted_domain("payload.delivery"),
      ".delivery is a real gTLD")
check("evil.kr ACCEPTED",                 _is_valid_extracted_domain("evil.kr"),
      ".kr (South Korea) is real ccTLD")
check("e.gg ACCEPTED",                    _is_valid_extracted_domain("e.gg"),
      ".gg (Guernsey) is real ccTLD — single letter prefix with 2 labels is ok")
check("m.io ACCEPTED",                    _is_valid_extracted_domain("m.io"),
      ".io (British Indian Ocean) — real ccTLD")
check("zanity.net ACCEPTED",              _is_valid_extracted_domain("zanity.net"))
check("strangled.net ACCEPTED",           _is_valid_extracted_domain("strangled.net"))
check("mega.nz ACCEPTED",                 _is_valid_extracted_domain("mega.nz"),
      ".nz (New Zealand) is real ccTLD")


# ─────────────────────────────────────────────────────────────────────────────
# FIX 2 — _MITRE_TAG_PREFIX_RE expanded
# Evidence: 26 code-namespace false positives proven in live feed
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 2: Code Namespace Prefix Filter ===")

# Proven false positives from live feed
check("event.target REJECTED",                       not _is_valid_extracted_domain("event.target"),
      "event.target seen in live feed")
check("os.popen REJECTED",                           not _is_valid_extracted_domain("os.popen"),
      "os.popen seen in live feed")
check("system.security.cryptography REJECTED",       not _is_valid_extracted_domain("system.security.cryptography.protectdata"),
      "system.security.cryptography.protectdata seen in live feed")
check("resource.department REJECTED",                not _is_valid_extracted_domain("resource.department"),
      "resource.department seen in live feed")
check("principal.process REJECTED",                  not _is_valid_extracted_domain("principal.process"))
check("target.process REJECTED",                     not _is_valid_extracted_domain("target.process"))
check("user.authentication REJECTED",                not _is_valid_extracted_domain("user.authentication"))
check("device.feature.nat.ice.enabled REJECTED",     not _is_valid_extracted_domain("device.feature.nat.ice.enabled"))
check("method.invoke REJECTED",                      not _is_valid_extracted_domain("method.invoke"))
check("cert.incident REJECTED",                      not _is_valid_extracted_domain("cert.incident"))
check("http.title REJECTED",                         not _is_valid_extracted_domain("http.title"))
check("graph.org REJECTED",                          not _is_valid_extracted_domain("graph.org"),
      "graph.org (Telegra.ph) is metadata, not C2")
check("isolation.tools REJECTED",                    not _is_valid_extracted_domain("isolation.tools"))
check("support.apple REJECTED",                      not _is_valid_extracted_domain("support.apple"))
check("victim.user REJECTED",                        not _is_valid_extracted_domain("victim.user"))
check("video.mds REJECTED",                          not _is_valid_extracted_domain("video.mds"))
check("vscode.download.prss.microsoft REJECTED",     not _is_valid_extracted_domain("vscode.download.prss.microsoft"))
check("load.auraria REJECTED",                       not _is_valid_extracted_domain("load.auraria"))
check("additional.fields REJECTED",                  not _is_valid_extracted_domain("additional.fields"))
check("com.vmware.sso REJECTED",                     not _is_valid_extracted_domain("com.vmware.sso"))
check("extensions.webextensions.uuids REJECTED",     not _is_valid_extracted_domain("extensions.webextensions.uuids"))
check("hipreport.esp REJECTED",                      not _is_valid_extracted_domain("hipreport.esp"))
check("getconfig.esp REJECTED",                      not _is_valid_extracted_domain("getconfig.esp"))
check("login.esp REJECTED",                          not _is_valid_extracted_domain("login.esp"))
check("the.phpextension REJECTED",                   not _is_valid_extracted_domain("the.phpextension"))
check("the.hosting REJECTED",                        not _is_valid_extracted_domain("the.hosting"))
check("io.hugo REJECTED",                            not _is_valid_extracted_domain("io.hugo"))
check("api.ipify.org REJECTED",                      not _is_valid_extracted_domain("api.ipify.org"),
      "api.ipify.org is utility IP lookup, not C2")

# Regression: legitimate threat domains that MUST still pass
check("c2.redteam.tools ACCEPTED",                   _is_valid_extracted_domain("c2.redteam.tools"),
      "tools can be a real gTLD")
check("phishing.target.com ACCEPTED",                _is_valid_extracted_domain("phishing.target.com"),
      "target.com is a real domain — only reject 'target.X' prefix pattern")
check("attack-tools.io ACCEPTED",                    _is_valid_extracted_domain("attack-tools.io"))
check("evilservice.ru ACCEPTED",                     _is_valid_extracted_domain("evilservice.ru"))


# ─────────────────────────────────────────────────────────────────────────────
# FIX 3 — Single-letter variable chain guard
# Evidence: e.target.closest, w.location.href seen in live feed
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 3: Single-Letter Variable Chain Guard ===")

check("e.target.closest REJECTED",  not _is_valid_extracted_domain("e.target.closest"),
      "JavaScript variable.property.method chain — not a domain")
check("w.location.href REJECTED",   not _is_valid_extracted_domain("w.location.href"),
      "JavaScript window.location.href chain — not a domain")

# Single-letter 2-label domains MUST still pass (they're real ccTLDs / real domains)
check("e.gg ACCEPTED (2-label)",    _is_valid_extracted_domain("e.gg"))
check("m.io ACCEPTED (2-label)",    _is_valid_extracted_domain("m.io"))
check("c.kr ACCEPTED (2-label)",    _is_valid_extracted_domain("c.kr"))
check("a.io ACCEPTED (2-label)",    _is_valid_extracted_domain("a.io"))


# ─────────────────────────────────────────────────────────────────────────────
# FIX 4 — Stale merge propagation prevention
# Evidence: existing_iocs_by_type contamination persists across runs
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 4: Merge Path Contamination Prevention ===")

# Simulate: a contaminated existing_iocs_by_type dict passed to extract_iocs
contaminated_existing = {
    "domain": ["store.ts", "event.target", "e.target.closest", "rc.local",
               "os.popen", "system.security.cryptography.protectdata",
               "malware.evil.ru",      # LEGITIMATE — must survive merge
               "c2.phishing.com",      # LEGITIMATE — must survive merge
               ],
    "url": ["https://malicious-c2.com/payload"],
    "ipv4": ["198.51.100.42"],  # TEST-NET — but not RFC1918, should pass
}

result = extract_iocs("", existing_iocs_by_type=contaminated_existing)
retained_domains = result.iocs_by_type.get("domain", [])
retained_flat = result.flat_iocs

check("store.ts NOT in merged result",
      "store.ts" not in retained_domains,
      f"Got: {retained_domains}")
check("event.target NOT in merged result",
      "event.target" not in retained_domains)
check("e.target.closest NOT in merged result",
      "e.target.closest" not in retained_domains)
check("rc.local NOT in merged result",
      "rc.local" not in retained_domains)
check("os.popen NOT in merged result",
      "os.popen" not in retained_domains)
check("malware.evil.ru SURVIVES merge",
      "malware.evil.ru" in retained_domains,
      f"Legitimate IOC was dropped. Got: {retained_domains}")
check("c2.phishing.com SURVIVES merge",
      "c2.phishing.com" in retained_domains,
      f"Legitimate IOC was dropped. Got: {retained_domains}")
check("Legitimate URL survives merge",
      "https://malicious-c2.com/payload" in result.iocs_by_type.get("url", []))

# enforce_ioc_integrity must not re-inject contamination
contaminated_entry = {
    "id": "test-001",
    "title": "CVE-2026-TEST benign description",
    "description": "",
    "summary": "",
    "summary_ai": "",
    "iocs": ["store.ts", "event.target", "malware.evil.ru"],
    "ioc_count": 3,
    "iocs_by_type": {"domain": ["store.ts", "event.target", "malware.evil.ru"]},
    "ioc_confidence": 89.0,
    "ioc_threat_level": "CRITICAL",
}
cleaned = enforce_ioc_integrity(contaminated_entry)
clean_domains = cleaned.get("iocs_by_type", {}).get("domain", [])
check("enforce_ioc_integrity removes store.ts from iocs_by_type",
      "store.ts" not in clean_domains,
      f"Got: {clean_domains}")
check("enforce_ioc_integrity removes event.target from iocs_by_type",
      "event.target" not in clean_domains)


# ─────────────────────────────────────────────────────────────────────────────
# FIX 5 — vulners.com source URL blocked
# Evidence: vulners.com source_url appeared as URL IOC in live feed
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 5: Source URL Blocklist (vulners.com) ===")

vuln_text = (
    "CVE-2026-12345 A vulnerability in X. "
    "https://vulners.com/cvelist/CVE-2026-12345?utm_source=rss "
    "https://nvd.nist.gov/vuln/detail/CVE-2026-12345 "
    "https://malicious-c2.ru/payload.php "  # This IS a real C2 URL — must be kept
)
r = extract_iocs(vuln_text)
urls = r.iocs_by_type.get("url", [])
check("vulners.com URL NOT extracted as IOC",
      not any("vulners.com" in u for u in urls),
      f"Got URLs: {urls}")
check("nvd.nist.gov URL NOT extracted as IOC",
      not any("nvd.nist.gov" in u for u in urls))
check("malicious-c2.ru URL IS extracted as IOC",
      any("malicious-c2.ru" in u for u in urls),
      f"Legitimate C2 URL was dropped. Got: {urls}")


# ─────────────────────────────────────────────────────────────────────────────
# END-TO-END: Feed item simulation
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== END-TO-END: CVE Feed Item Simulation ===")

# Simulate a CVE item that previously produced store.ts contamination
cve_text = (
    "CVE-2026-10879 DBI versions before 1.648 for Perl have a heap overflow. "
    "Affected component: store.ts in web applications. "
    "Reference: https://vulners.com/cvelist/CVE-2026-10879?utm_source=rss "
    "See also: https://nvd.nist.gov/vuln/detail/CVE-2026-10879"
)
r2 = extract_iocs(cve_text)
check("store.ts NOT in CVE item domains",
      "store.ts" not in r2.iocs_by_type.get("domain", []),
      f"Got domains: {r2.iocs_by_type.get('domain', [])}")
check("CVE-2026-10879 IS extracted",
      "CVE-2026-10879" in r2.iocs_by_type.get("cve", []))
check("vulners.com NOT in CVE item URLs",
      not any("vulners.com" in u for u in r2.iocs_by_type.get("url", [])))
check("No CRITICAL inflation from single code-file reference",
      r2.threat_level in ("NONE", "LOW", "MEDIUM"),
      f"Got threat_level={r2.threat_level} with ioc_confidence={r2.ioc_confidence}")

# Simulate a real malware item — legitimate IOCs must all pass
malware_text = (
    "Emotet campaign distributes malware via phishing. "
    "C2 infrastructure: 185.220.101.45 evil-payload.ru "
    "SHA256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 "
    "Download URL: https://malware-c2.xyz/stager/payload.bin "
    "Email actor: threat@evil-domain.biz"
)
r3 = extract_iocs(malware_text)
check("Real IPv4 C2 extracted",    "185.220.101.45" in r3.iocs_by_type.get("ipv4", []))
check("Real domain C2 extracted",  "evil-payload.ru" in r3.iocs_by_type.get("domain", []))
check("Real SHA256 extracted",
      any(len(h) == 64 for h in r3.iocs_by_type.get("sha256", [])))
check("Real C2 URL extracted",
      any("malware-c2.xyz" in u for u in r3.iocs_by_type.get("url", [])))
check("Confidence > 0 for real malware IOCs",  r3.ioc_confidence > 0)
check("Threat level not NONE for real malware", r3.threat_level != "NONE")


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT CHECK
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== INVARIANT: ioc_count == len(flat_iocs) ===")
for text in [cve_text, malware_text, "", "hello world no IOCs here"]:
    r = extract_iocs(text)
    check(f"ioc_count invariant for text[:40]='{text[:40]}'",
          r.ioc_count == len(r.flat_iocs),
          f"ioc_count={r.ioc_count} len(flat)={len(r.flat_iocs)}")


# ─────────────────────────────────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  TOTAL:  {PASS + FAIL} tests")
print(f"  PASS:   {PASS}")
print(f"  FAIL:   {FAIL}")
print(f"{'='*60}")

if FAIL > 0:
    print("\nFAILED TESTS:")
    for e in ERRORS:
        print(f"  ✗ {e}")
    print("\n⛔ DO NOT RUN clean_feed.py — fix all failures first.")
    sys.exit(1)
else:
    print("\n✅ ALL TESTS PASS — safe to run clean_feed.py")
    sys.exit(0)
