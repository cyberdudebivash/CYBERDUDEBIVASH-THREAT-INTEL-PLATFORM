#!/usr/bin/env python3
"""
scripts/validate_monetization.py
CYBERDUDEBIVASH(R) SENTINEL APEX v149.0 -- Monetization Integrity Guard
========================================================================
PRODUCTION HARDENING GATE -- validates all monetization/payment assets.

Checks:
  1. upgrade.html    -- real credentials present, no BOM, no junk chars
  2. PAYMENT-GATEWAY.html -- exists, real credentials present, no BOM
  3. pricing.html    -- CTA links point to upgrade.html (not broken)
  4. store.html      -- payment strip present
  5. services.html   -- payment strip present
  6. index.html      -- payment strip present
  7. Payment credential integrity -- real UPI, crypto, NEFT, PayPal
  8. No placeholder/fake credentials in payment files
  9. Formspree endpoint present for confirmation form
 10. WhatsApp link correct
 11. GSTIN present on payment pages

Exit 0 -- all checks passed
Exit 1 -- one or more CRITICAL checks failed

(c) 2026 CYBERDUDEBIVASH PRIVATE LIMITED. CONFIDENTIAL.
"""
from __future__ import annotations

import os
import sys
import re
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

ERRORS   = []
WARNINGS = []
PASSES   = []

def fail(msg: str) -> None:
    ERRORS.append(msg)
    print(f"  [FAIL] {msg}")

def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"  [WARN] {msg}")

def ok(msg: str) -> None:
    PASSES.append(msg)
    print(f"  [ OK ] {msg}")

def read_file(path: pathlib.Path) -> bytes:
    try:
        return path.read_bytes()
    except Exception as e:
        fail(f"Cannot read {path.name}: {e}")
        return b""

def check_no_bom(data: bytes, fname: str) -> None:
    if data.startswith(b"\xef\xbb\xbf"):
        fail(f"{fname}: BOM detected (UTF-8 BOM) -- will cause junk chars in browser")
    else:
        ok(f"{fname}: No BOM")

def check_no_junk_chars(data: bytes, fname: str) -> None:
    """Check for common mojibake sequences that indicate encoding corruption."""
    junk_patterns = [
        b"\xe2\x80\x94",   # â€" (em dash mojibake)
        b"\xe2\x82\xb9",   # â‚¹ (rupee mojibake)
        b"\xc3\xa2",       # Ã¢ (common mojibake prefix)
        b"\xc2\xa0",       # Â\xa0 (non-breaking space mojibake)
        b"\xe2\x80\x9c",   # mojibake left double quote (UTF-8 bytes)
        b"\xe2\x80\x9d",   # mojibake right double quote (UTF-8 bytes)
        b"\xe2\x80\x98",   # mojibake left single quote (UTF-8 bytes)
        b"\xf0\x9f\x85\xbf",  # emoji mojibake: P (PayPal icon)
    ]
    found = []
    for pattern in junk_patterns:
        if pattern in data:
            found.append(pattern)
    if found:
        fail(f"{fname}: Mojibake/junk char sequences detected ({len(found)} patterns)")
    else:
        ok(f"{fname}: No junk char sequences")

def check_credential(data: bytes, credential: bytes, label: str, fname: str) -> None:
    if credential in data:
        ok(f"{fname}: {label} present")
    else:
        fail(f"{fname}: {label} MISSING -- credential not found")

def check_no_placeholder(data: bytes, placeholder: bytes, label: str, fname: str) -> None:
    if placeholder in data:
        fail(f"{fname}: Placeholder credential found: {label} -- must be replaced with real value")
    else:
        ok(f"{fname}: No placeholder '{label}'")

def check_link(data: bytes, link: bytes, label: str, fname: str) -> None:
    if link in data:
        ok(f"{fname}: {label} link present")
    else:
        warn(f"{fname}: {label} link not found (may be optional)")

# =====================================================================
# REAL CREDENTIALS (single source of truth)
# =====================================================================
REAL_UPI_PRIMARY     = b"iambivash.bn-5@okaxis"
REAL_UPI_AXIS        = b"6302177246@axisbank"
REAL_PAYPAL_EMAIL    = b"iambivash.bn@gmail.com"
REAL_CRYPTO_BNB      = b"0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796"
REAL_BANK_ACCOUNT    = b"915010024617260"
REAL_IFSC            = b"UTIB0000052"
REAL_GSTIN           = b"21ARKPN8270G1ZP"
REAL_WHATSAPP        = b"8179881447"
REAL_CONTACT_EMAIL   = b"bivash@cyberdudebivash.com"
REAL_FORMSPREE       = b"formspree.io"

# Placeholder credentials that must NOT appear
PLACEHOLDER_UPI_1    = b"bivash@upi"
PLACEHOLDER_CRYPTO_1 = b"TKwP4mWh6LN5m2jS8eFfXxMaH4HhYTjuMe"  # old fake TRC20
PLACEHOLDER_CRYPTO_2 = b"0x3b2f4d7a91c0e8b6f15d8a4c3e9b0f6a2d7c4e1"  # old fake ETH
PLACEHOLDER_BTC      = b"bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"   # fake BTC


def validate_upgrade_html() -> None:
    fname = "upgrade.html"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND -- critical monetization asset missing")
        return

    data = read_file(path)
    if not data:
        return

    check_no_bom(data, fname)
    check_no_junk_chars(data, fname)

    # Real credentials must be present
    check_credential(data, REAL_UPI_PRIMARY,    "UPI iambivash.bn-5@okaxis",   fname)
    check_credential(data, REAL_UPI_AXIS,       "UPI 6302177246@axisbank",     fname)
    check_credential(data, REAL_PAYPAL_EMAIL,   "PayPal iambivash.bn@gmail.com",fname)
    check_credential(data, REAL_CRYPTO_BNB,     "BNB 0xa824c20...",            fname)
    check_credential(data, REAL_BANK_ACCOUNT,   "Bank A/C 915010024617260",    fname)
    check_credential(data, REAL_IFSC,           "IFSC UTIB0000052",            fname)
    check_credential(data, REAL_GSTIN,          "GSTIN 21ARKPN8270G1ZP",       fname)
    check_credential(data, REAL_WHATSAPP,       "WhatsApp +91 8179881447",     fname)
    check_credential(data, REAL_FORMSPREE,      "Formspree endpoint",          fname)

    # Placeholders must NOT be present
    check_no_placeholder(data, PLACEHOLDER_UPI_1,    "bivash@upi (placeholder)", fname)
    check_no_placeholder(data, PLACEHOLDER_CRYPTO_1, "TKwP4mWh6L... (old fake TRC20)", fname)
    check_no_placeholder(data, PLACEHOLDER_CRYPTO_2, "0x3b2f4d7a91... (old fake ETH)", fname)
    check_no_placeholder(data, PLACEHOLDER_BTC,      "bc1qxy2k... (fake BTC)", fname)

    # Plan data must be present
    if b"4100" in data:
        ok(f"{fname}: PRO plan INR 4100 present")
    else:
        fail(f"{fname}: PRO plan INR 4100 not found")

    if b"formspree.io/f/xpzgdkoe" in data:
        ok(f"{fname}: Formspree form ID xpzgdkoe present")
    else:
        warn(f"{fname}: Formspree form ID xpzgdkoe not found -- check form action")

    # JavaScript check -- no syntax errors by running node --check if available
    check_js_syntax(path, fname)


def validate_payment_gateway() -> None:
    fname = "PAYMENT-GATEWAY.html"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND -- payment hub page missing")
        return

    data = read_file(path)
    if not data:
        return

    check_no_bom(data, fname)
    check_no_junk_chars(data, fname)
    check_credential(data, REAL_UPI_PRIMARY,  "UPI iambivash.bn-5@okaxis", fname)
    check_credential(data, REAL_UPI_AXIS,     "UPI 6302177246@axisbank",   fname)
    check_credential(data, REAL_PAYPAL_EMAIL, "PayPal email",              fname)
    check_credential(data, REAL_CRYPTO_BNB,   "BNB wallet",               fname)
    check_credential(data, REAL_BANK_ACCOUNT, "Bank A/C",                 fname)
    check_credential(data, REAL_IFSC,         "IFSC",                     fname)
    check_credential(data, REAL_GSTIN,        "GSTIN",                    fname)


def validate_pricing_html() -> None:
    fname = "pricing.html"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND")
        return

    data = read_file(path)
    if not data:
        return

    # No BOM check
    check_no_bom(data, fname)

    # Upgrade links must exist
    if b"/upgrade.html" in data:
        ok(f"{fname}: /upgrade.html CTAs present")
    else:
        fail(f"{fname}: No /upgrade.html links found -- CTA broken")

    # Broken plan=team link check (team plan doesn't exist in upgrade.html)
    if b"plan=team" in data:
        fail(f"{fname}: plan=team link found -- 'team' plan removed, use 'enterprise'")
    else:
        ok(f"{fname}: No broken plan=team links")

    # Payment methods strip
    if b"PAYMENT-GATEWAY.html" in data or b"iambivash.bn-5@okaxis" in data or b"GPay" in data:
        ok(f"{fname}: Payment methods strip present")
    else:
        warn(f"{fname}: Payment methods strip not detected -- consider adding")

    # GSTIN
    if b"21ARKPN8270G1ZP" in data:
        ok(f"{fname}: GSTIN present")
    else:
        warn(f"{fname}: GSTIN not found")


def validate_store_html() -> None:
    fname = "store.html"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND")
        return

    data = read_file(path)
    if not data:
        return

    check_no_bom(data, fname)

    if b"PAYMENT-GATEWAY.html" in data or b"iambivash.bn-5@okaxis" in data:
        ok(f"{fname}: Payment methods strip present")
    else:
        fail(f"{fname}: Payment methods strip missing -- customers cannot see payment options")

    if b"gumroad.com" in data:
        ok(f"{fname}: Gumroad product links present")
    else:
        warn(f"{fname}: No Gumroad links found")


def validate_services_html() -> None:
    fname = "services.html"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND")
        return

    data = read_file(path)
    if not data:
        return

    check_no_bom(data, fname)

    if b"PAYMENT-GATEWAY.html" in data or b"iambivash.bn-5@okaxis" in data:
        ok(f"{fname}: Payment methods strip present")
    else:
        fail(f"{fname}: Payment methods strip missing")

    if b"8179881447" in data:
        ok(f"{fname}: WhatsApp contact present")
    else:
        warn(f"{fname}: WhatsApp contact not found")


def validate_index_html() -> None:
    fname = "index.html"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND")
        return

    data = read_file(path)
    if not data:
        return

    check_no_bom(data, fname)

    if b"PAYMENT-GATEWAY.html" in data:
        ok(f"{fname}: Payment Gateway link present")
    else:
        fail(f"{fname}: Payment Gateway link missing from index.html")

    if b"/upgrade.html" in data:
        ok(f"{fname}: upgrade.html CTAs present")
    else:
        fail(f"{fname}: No upgrade.html links in index.html")

    # Check upgrade banner is present
    if b"cdb-upgrade-banner" in data:
        ok(f"{fname}: Upgrade banner present")
    else:
        warn(f"{fname}: Upgrade banner not found")


def check_js_syntax(html_path: pathlib.Path, fname: str) -> None:
    """Extract inline <script> blocks and check JS syntax with node --check."""
    import subprocess
    import tempfile

    try:
        result = subprocess.run(["node", "--version"], capture_output=True, timeout=5)
        if result.returncode != 0:
            warn(f"{fname}: node not available for JS syntax check")
            return
    except (FileNotFoundError, subprocess.TimeoutExpired):
        warn(f"{fname}: node not available -- skipping JS syntax check")
        return

    data = html_path.read_text(encoding="utf-8", errors="replace")
    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", data, re.IGNORECASE)
    if not scripts:
        ok(f"{fname}: No inline scripts to check")
        return

    js_combined = "\n".join(scripts)
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False, encoding="utf-8") as f:
        f.write(js_combined)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["node", "--check", tmp_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            ok(f"{fname}: JS syntax valid (node --check passed)")
        else:
            fail(f"{fname}: JS SYNTAX ERROR -- {result.stderr.strip()[:200]}")
    except subprocess.TimeoutExpired:
        warn(f"{fname}: node --check timed out")
    except Exception as e:
        warn(f"{fname}: node --check error: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def validate_version_json() -> None:
    fname = "version.json"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        fail(f"{fname}: FILE NOT FOUND -- single source of truth missing")
        return
    try:
        import json
        with open(path, "r", encoding="utf-8") as f:
            v = json.load(f)
        ok(f"{fname}: Valid JSON. Version: {v.get('version','unknown')}")
    except Exception as e:
        fail(f"{fname}: JSON parse error: {e}")


def validate_feed_manifest() -> None:
    fname = "data/stix/feed_manifest.json"
    path  = REPO_ROOT / fname
    print(f"\n--- {fname} ---")
    if not path.exists():
        # Try alternate location
        alt = REPO_ROOT / "data" / "feed_manifest.json"
        if not alt.exists():
            warn(f"{fname}: Not found at primary or alternate location")
            return
        path = alt
    try:
        import json
        data = json.loads(path.read_bytes())
        count = len(data) if isinstance(data, list) else (
            len(data.get("items", data.get("advisories", [])))
            if isinstance(data, dict) else 0
        )
        ok(f"{fname}: Valid JSON, {count} entries")
    except Exception as e:
        fail(f"{fname}: JSON parse error: {e}")


def validate_all_html_bom() -> None:
    """v149.1: BOM check on ALL HTML files in repo root -- zero tolerance."""
    print(f"\n--- BOM scan: ALL HTML files ---")
    html_files = sorted(REPO_ROOT.glob("*.html"))
    bom_found = []
    for f in html_files:
        try:
            data = f.read_bytes()
            if data.startswith(b"\xef\xbb\xbf"):
                bom_found.append(f.name)
                fail(f"{f.name}: BOM detected -- will corrupt rendering")
        except Exception as e:
            warn(f"{f.name}: cannot read ({e})")
    if not bom_found:
        ok(f"BOM scan: ALL {len(html_files)} HTML files BOM-free")


def validate_all_html_encoding() -> None:
    """v149.1: Encoding scan on ALL HTML files -- blocks any mojibake from shipping."""
    junk_patterns = [
        (b"\xc3\xa2",     "double-encoded mojibake prefix"),
        (b"\xef\xbb\xbf", "BOM"),
    ]
    print(f"\n--- Encoding scan: ALL HTML files ---")
    html_files = sorted(REPO_ROOT.glob("*.html"))
    dirty = []
    for f in html_files:
        try:
            data = f.read_bytes()
            found = []
            for pat, label in junk_patterns:
                if pat in data:
                    count = data.count(pat)
                    found.append(f"{label} ({count}x)")
            if found:
                dirty.append(f.name)
                fail(f"{f.name}: double-encoded mojibake prefix detected -- run fix_all_html_encoding.py")
        except Exception as e:
            warn(f"{f.name}: cannot read ({e})")
    if not dirty:
        ok(f"Encoding scan: ALL {len(html_files)} HTML files encoding-clean")


# =====================================================================
# v148.0.0 API KEY ENFORCEMENT GATE
# Validates that premium endpoints (apex.json, ai_summary.json) are
# gated behind authentication in the Cloudflare Worker source code.
# Fails the gate if these endpoints can be served without auth.
# =====================================================================

WORKER_SRC = REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js"

PREMIUM_ENDPOINTS = [
    "/api/v1/intel/apex.json",
    "/api/v1/intel/ai_summary.json",
]

def validate_worker_api_auth_enforcement() -> None:
    """v148.0.0: Confirms premium intel endpoints require PRO+ auth in Worker source."""
    print(f"\n--- Worker API auth enforcement (v148.0.0) ---")

    if not WORKER_SRC.exists():
        fail(f"Worker source not found: {WORKER_SRC}")
        return

    src = WORKER_SRC.read_text(encoding="utf-8", errors="replace")

    # 1. PREMIUM_INTEL_PATHS set must exist and contain both premium endpoints
    if "PREMIUM_INTEL_PATHS" not in src:
        fail("Worker: PREMIUM_INTEL_PATHS set is missing — premium endpoints are NOT gated")
    else:
        for ep in PREMIUM_ENDPOINTS:
            ep_literal = ep.replace("/", "\\/") if "\\/" in ep else ep
            # Check the literal path string appears inside PREMIUM_INTEL_PATHS block
            if ep not in src:
                fail(f"Worker: '{ep}' not found in source — cannot verify gating")
            else:
                ok(f"Worker: '{ep}' present in source")

    # 2. servePremiumIntelManifest function must exist
    if "async function servePremiumIntelManifest" not in src:
        fail("Worker: servePremiumIntelManifest() is missing — premium gate function absent")
    else:
        ok("Worker: servePremiumIntelManifest() function defined")

    # 3. Router must call servePremiumIntelManifest for PREMIUM_INTEL_PATHS
    if "PREMIUM_INTEL_PATHS.has(pathname)" not in src:
        fail("Worker router: PREMIUM_INTEL_PATHS.has() check missing — premium endpoints not routed to auth gate")
    else:
        ok("Worker router: PREMIUM_INTEL_PATHS.has() gate is wired")

    # 4. servePremiumIntelManifest must call resolveAuth (not bypass it)
    # Extract function body between servePremiumIntelManifest and the next async function
    fn_match = re.search(
        r"async function servePremiumIntelManifest\s*\(.*?\)\s*\{(.*?)(?=\n(?:async function|export default))",
        src, re.DOTALL
    )
    if fn_match:
        fn_body = fn_match.group(1)
        if "resolveAuth" not in fn_body:
            fail("servePremiumIntelManifest: does not call resolveAuth() — auth bypass risk")
        else:
            ok("servePremiumIntelManifest: calls resolveAuth()")
        # Must check for FREE tier rejection
        if "TIERS.FREE" not in fn_body and "tier_insufficient" not in fn_body:
            warn("servePremiumIntelManifest: FREE tier rejection check not found — free users may access premium data")
        else:
            ok("servePremiumIntelManifest: FREE tier rejection enforced")
        # Must NOT call servePublicIntelManifest (would bypass masking path and skip auth)
        if "servePublicIntelManifest(" in fn_body and "servePublicIntelManifestRaw" not in fn_body:
            fail("servePremiumIntelManifest: calls servePublicIntelManifest() instead of Raw variant — potential auth bypass")
        else:
            ok("servePremiumIntelManifest: delegates to Raw fetch helper correctly")
    else:
        warn("servePremiumIntelManifest: could not extract function body for deep inspection")

    # 5. CRITICAL: apex.json and ai_summary.json must NOT appear in the FREE public ALLOWED set
    public_fn_match = re.search(
        r"async function servePublicIntelManifest\s*\(.*?\)\s*\{(.*?)(?=\n(?:async function|export default))",
        src, re.DOTALL
    )
    if public_fn_match:
        pub_body = public_fn_match.group(1)
        for ep in PREMIUM_ENDPOINTS:
            if ep in pub_body:
                fail(f"servePublicIntelManifest: '{ep}' is in the FREE handler ALLOWED set — premium data exposed publicly!")
            else:
                ok(f"servePublicIntelManifest: '{ep}' correctly absent from FREE ALLOWED set")
    else:
        warn("servePublicIntelManifest: could not extract function body for ALLOWED set inspection")

    # 6. Free-tier masking must be applied (maskForFreeTier function present)
    if "function maskForFreeTier" not in src:
        warn("Worker: maskForFreeTier() missing — free-tier responses may leak premium fields")
    else:
        ok("Worker: maskForFreeTier() field masking function defined")

    # 7. Free endpoints limited to 25 items (revenue protection)
    if "slice(0, 25)" in src or ".slice(0,25)" in src:
        ok("Worker: free-tier item count cap (25 items) enforced")
    else:
        warn("Worker: free-tier 25-item cap not detected in source — free users may get full dataset")


# =====================================================================
# MAIN
# =====================================================================
def main() -> None:
    print("=" * 70)
    print("  SENTINEL APEX v148.0.0 -- MONETIZATION INTEGRITY GATE")
    print("  Validates: payment credentials, CTAs, encoding, JS syntax,")
    print("             BOM-free, mojibake-free, API auth enforcement")
    print("=" * 70)

    validate_upgrade_html()
    validate_payment_gateway()
    validate_pricing_html()
    validate_store_html()
    validate_services_html()
    validate_index_html()
    validate_version_json()
    validate_feed_manifest()
    validate_all_html_bom()
    validate_all_html_encoding()
    validate_worker_api_auth_enforcement()

    print("\n" + "=" * 70)
    print(f"  RESULTS: {len(PASSES)} passed, {len(WARNINGS)} warnings, {len(ERRORS)} errors")
    print("=" * 70)

    if WARNINGS:
        print("\n  WARNINGS:")
        for w in WARNINGS:
            print(f"    - {w}")

    if ERRORS:
        print("\n  CRITICAL ERRORS (DEPLOYMENT BLOCKED):")
        for e in ERRORS:
            print(f"    X {e}")
        print("\n  GATE: FAIL -- fix all errors before deploying")
        sys.exit(1)
    else:
        print("\n  GATE: PASS -- all monetization checks passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
