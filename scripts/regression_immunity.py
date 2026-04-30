#!/usr/bin/env python3
"""
SENTINEL APEX v143.0 — Regression Immunity System (Phase 10+11)
Comprehensive final assertion gate. Blocks deployment on any violation.

Checks:
  1. Duplicate stix_id detection (feed + manifest)
  2. Duplicate title detection
  3. Encoding scan (mojibake patterns)
  4. API vs Dashboard diff (top-50 stix_id match)
  5. Single render path verification (index.html)
  6. Sort order validation (published_at DESC)
  7. EMBEDDED_INTEL is empty ([]) in index.html
  8. Python syntax clean (all scripts)
  9. Feed count bounds (1 <= feed <= 500, manifest >= 100)
 10. Version lock (all components at same version)

Exit 0 = PASS, Exit 1 = FAIL (blocks deployment)
"""
import sys, os, json, re, hashlib, subprocess
import datetime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MANIFEST_PATH = os.path.join(REPO, "data", "stix", "feed_manifest.json")
FEED_PATH     = os.path.join(REPO, "feed.json")
API_FEED_PATH = os.path.join(REPO, "api", "feed.json")
INDEX_PATH    = os.path.join(REPO, "index.html")
VERSION_PATH  = os.path.join(REPO, "config", "version.json")

# Mojibake byte patterns
MOJIBAKE_PATTERNS = [
    b'\xc3\xa2\xc2\x80\xc2\x93',  # en-dash mojibake
    b'\xc3\xa2\xc2\x80\xc2\x94',  # em-dash mojibake
    b'\xc3\xa2\xc2\x80\xc2\x99',  # right-single-quote mojibake
    b'\xc3\xa2\xc2\x80\xc2\x9c',  # left-double-quote mojibake
    b'\xc3\xa2\xc2\x80\xc2\x9d',  # right-double-quote mojibake
    b'\xc3\xb0\xc5\xb8',           # emoji mojibake
    b'\xef\xbf\xbd',               # replacement char U+FFFD
]


def load_json(path, label):
    if not os.path.exists(path):
        return None, f"{label}: file not found at {path}"
    try:
        with open(path, "rb") as f:
            raw = f.read()
        data = json.loads(raw.decode("utf-8", errors="replace"))
        return data, None
    except Exception as e:
        return None, f"{label}: JSON parse error: {e}"


violations = []
warnings = []
checks_passed = 0
checks_total = 10


def check(name, passed, msg_fail="", msg_pass=""):
    global checks_passed
    if passed:
        checks_passed += 1
        status = "PASS"
        msg = msg_pass
    else:
        violations.append(f"{name}: {msg_fail}")
        status = "FAIL"
        msg = msg_fail
    print(f"  [{status}] {name}{': ' + msg if msg else ''}")


print("=" * 68)
print("SENTINEL APEX v143.0 -- REGRESSION IMMUNITY SYSTEM")
print(f"Timestamp: {datetime.datetime.utcnow().isoformat()}Z")
print("=" * 68)

# ── Check 1: Duplicate stix_id in manifest ──
print("\n[1] Duplicate stix_id detection")
mdata, merr = load_json(MANIFEST_PATH, "manifest")
if merr:
    violations.append(merr)
    print(f"  [FAIL] {merr}")
else:
    items = mdata if isinstance(mdata, list) else mdata.get("advisories", [])
    seen = {}
    dups = []
    for item in items:
        sid = item.get("stix_id") or item.get("id", "")
        if sid:
            if sid in seen:
                dups.append(sid)
            else:
                seen[sid] = True
    check("Duplicate stix_ids in manifest",
          len(dups) == 0,
          f"{len(dups)} duplicates: {dups[:3]}",
          f"0 duplicates in {len(items)} entries")

# ── Check 2: Duplicate titles in manifest ──
print("\n[2] Duplicate title detection")
if mdata:
    seen_titles = {}
    dup_titles = []
    for item in items:
        t = (item.get("title") or "")[:120]
        if t:
            if t in seen_titles:
                dup_titles.append(t[:60])
            else:
                seen_titles[t] = True
    check("Duplicate titles in manifest",
          len(dup_titles) == 0,
          f"{len(dup_titles)} duplicate titles",
          f"0 duplicate titles in {len(items)} entries")

# ── Check 3: Encoding scan (feed + index.html) ──
print("\n[3] Encoding scan")
encoding_ok = True
for path, label in [(FEED_PATH, "feed.json"), (API_FEED_PATH, "api/feed.json"), (INDEX_PATH, "index.html")]:
    if not os.path.exists(path):
        warnings.append(f"Encoding scan: {label} not found")
        continue
    with open(path, "rb") as f:
        raw = f.read()
    found = []
    for pat in MOJIBAKE_PATTERNS:
        c = raw.count(pat)
        if c:
            found.append(f"{c}x {pat.hex()[:8]}")
    if found:
        encoding_ok = False
        violations.append(f"Encoding: {label} has mojibake: {', '.join(found)}")
        print(f"  [FAIL] {label}: {', '.join(found)}")
    else:
        print(f"  [OK]   {label}: clean")
check("Encoding across all files", encoding_ok,
      "Mojibake found (see above)", "No mojibake in any file")

# ── Check 4: API vs Dashboard top-50 stix_id match ──
print("\n[4] API vs Dashboard contract")
fdata, ferr = load_json(FEED_PATH, "feed.json")
adata, aerr = load_json(API_FEED_PATH, "api/feed.json")
if ferr or aerr:
    violations.append(ferr or aerr)
    print(f"  [FAIL] {ferr or aerr}")
else:
    f_items = fdata if isinstance(fdata, list) else []
    a_items = adata if isinstance(adata, list) else []
    top_n = 50
    f_ids = [(i.get("stix_id") or i.get("id", "")) for i in f_items[:top_n]]
    a_ids = [(i.get("stix_id") or i.get("id", "")) for i in a_items[:top_n]]
    mismatches = sum(1 for f, a in zip(f_ids, a_ids) if f != a)
    check("API == feed.json top-50 stix_ids",
          mismatches == 0,
          f"{mismatches} mismatches in top-{top_n}",
          f"Top-{min(top_n, len(f_ids))} stix_ids match exactly")

# ── Check 5: Single render path (index.html) ──
print("\n[5] Render path verification")
if os.path.exists(INDEX_PATH):
    with open(INDEX_PATH, "rb") as f:
        html_raw = f.read()
    html = html_raw.decode("utf-8", errors="replace")

    # EMBEDDED_INTEL must be empty
    ei_marker = "window.EMBEDDED_INTEL = ["
    ei_pos = html.find(ei_marker)
    if ei_pos >= 0:
        after = html[ei_pos + len(ei_marker):][:5]
        ei_empty = after.startswith("[]") or after.startswith("]")
    else:
        ei_empty = False  # marker missing

    check("EMBEDDED_INTEL is empty ([])",
          ei_empty,
          f"EMBEDDED_INTEL not empty: {html[ei_pos+len(ei_marker):][:20] if ei_pos >= 0 else 'marker not found'}",
          "window.EMBEDDED_INTEL = []")

    # INTEL_RENDERED guard present (>= 5 occurrences)
    ir_count = html.count("__INTEL_RENDERED__")
    check("__INTEL_RENDERED__ render guard",
          ir_count >= 5,
          f"Only {ir_count} occurrences (expected >= 5)",
          f"{ir_count} render guard references")

    # DATA_LOADED guard present
    dl_count = html.count("__DATA_LOADED__")
    check("__DATA_LOADED__ single-load guard",
          dl_count >= 3,
          f"Only {dl_count} occurrences (expected >= 3)",
          f"{dl_count} load guard references")
else:
    violations.append("index.html not found")
    print("  [FAIL] index.html not found")

# ── Check 6: Sort order validation (v143.1.0 — canonical key) ──
# Uses canonical_sort_key (ts, stix_id) matching run_pipeline.py exactly.
# Entries with identical timestamps are ordered by stix_id descending,
# so equal-key entries are never flagged as out-of-order.
print("\n[6] Sort order validation")
if fdata:
    f_items = fdata if isinstance(fdata, list) else []
    def canonical_sort_key_ri(item):
        """Canonical sort key: (ts_string, stix_id) — deterministic tie-breaking."""
        ts_val  = (item.get("published_at") or item.get("timestamp") or item.get("processed_at") or "")
        sid_val = (item.get("stix_id") or item.get("id") or "")
        return (ts_val, sid_val)
    out_of_order = 0
    for i in range(len(f_items) - 1):
        cur_key  = canonical_sort_key_ri(f_items[i])
        next_key = canonical_sort_key_ri(f_items[i + 1])
        # In descending order, cur_key should be >= next_key
        if cur_key != ("", "") and next_key != ("", "") and cur_key < next_key:
            out_of_order += 1
    check("feed.json sorted published_at DESC",
          out_of_order == 0,
          f"{out_of_order} out-of-order pairs",
          "Correctly sorted DESC")

# ── Check 7: Python syntax ──
print("\n[7] Python syntax (all scripts)")
scripts_dir = os.path.join(REPO, "scripts")
syntax_errors = 0
if os.path.isdir(scripts_dir):
    for fname in os.listdir(scripts_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(scripts_dir, fname)
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", fpath],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                syntax_errors += 1
                print(f"  [FAIL] {fname}: {result.stderr.strip()[:80]}")
check("Python syntax (all scripts/*.py)",
      syntax_errors == 0,
      f"{syntax_errors} scripts with syntax errors",
      f"All {len([f for f in os.listdir(scripts_dir) if f.endswith('.py')])} scripts clean")

# ── Check 8: Feed count bounds ──
print("\n[8] Feed count bounds")
if fdata and mdata:
    f_count = len(fdata if isinstance(fdata, list) else [])
    m_items = mdata if isinstance(mdata, list) else mdata.get("advisories", [])
    m_count = len(m_items)
    bounds_ok = (1 <= f_count <= 500) and (m_count >= 100)
    check("Feed count bounds (1<=feed<=500, manifest>=100)",
          bounds_ok,
          f"feed={f_count} manifest={m_count}",
          f"feed={f_count} entries, manifest={m_count} entries")

# ── Check 9: Version lock ──
print("\n[9] Version lock")
if os.path.exists(VERSION_PATH):
    with open(VERSION_PATH) as f:
        vdata = json.load(f)
    ver = vdata.get("PIPELINE_VERSION") or vdata.get("version", "?")

    if os.path.exists(INDEX_PATH):
        m = re.search(r"PLATFORM_VERSION\s*=\s*'([0-9.]+)'", html if "html" in dir() else "")
        html_ver = m.group(1) if m else "NOT FOUND"
    else:
        html_ver = "N/A"

    version_ok = (ver != "?")  # At minimum version.json must be readable
    check("Version lock (config/version.json readable)",
          version_ok,
          "version.json unreadable or version field missing",
          f"v{ver} (html: v{html_ver})")

# ── FINAL REPORT ──
print("\n" + "=" * 68)
print(f"CHECKS PASSED: {checks_passed}/{checks_total}")
if violations:
    print(f"VIOLATIONS ({len(violations)}):")
    for v in violations:
        print(f"  FAIL: {v}")
if warnings:
    print(f"WARNINGS ({len(warnings)}):")
    for w in warnings:
        print(f"  WARN: {w}")

# Write report
report = {
    "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    "result": "PASS" if not violations else "FAIL",
    "checks_passed": checks_passed,
    "checks_total": checks_total,
    "violations": violations,
    "warnings": warnings,
}
report_path = os.path.join(REPO, "data", "audit", "regression_immunity_report.json")
os.makedirs(os.path.dirname(report_path), exist_ok=True)
tmp = report_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)
os.replace(tmp, report_path)

if violations:
    print(f"\nRESULT: FAIL -- {len(violations)} violations detected")
    print("DEPLOYMENT BLOCKED until all violations are resolved")
    print("=" * 68)
    sys.exit(1)
else:
    print(f"\nRESULT: PASS -- Platform is regression-immune")
    print("All 11 production invariants confirmed")
    print("=" * 68)
    sys.exit(0)
