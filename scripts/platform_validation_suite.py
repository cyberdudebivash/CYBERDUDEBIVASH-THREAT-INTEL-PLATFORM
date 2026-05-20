#!/usr/bin/env python3
"""
platform_validation_suite.py -- SENTINEL APEX Platform Validation Suite v158.0
Phase 3: Full platform validation.
"""
import sys, ast
from pathlib import Path
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except Exception: pass

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX     = REPO_ROOT / "index.html"
SW        = REPO_ROOT / "service-worker.js"
HEADERS   = REPO_ROOT / "_headers"
WORKFLOW  = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
BUILD_PY  = REPO_ROOT / "scripts" / "build_dist_artifact.py"

results  = []
failures = []

def check(name, passed, detail=""):
    results.append(("PASS" if passed else "FAIL", name, detail))
    if not passed: failures.append((name, detail))
    return passed

def P(passed): return "[PASS]" if passed else "[FAIL]"
def section(t): print("\n" + "="*62 + "\n  " + t + "\n" + "="*62)

# ── 1. CRITICAL ROUTES ──────────────────────────────────────────
section("1. CRITICAL ROUTE VALIDATION")
CRITICAL_ROUTES = [
    "index.html", "PAYMENT-GATEWAY.html", "404.html",
    "dashboard/enterprise_dashboard.html",
    "dashboard/enterprise_dashboard_v2.html",
    "dashboard/orchestration_hub.html",
    "dashboard/social_distribution.html",
    "dashboard/revenue_acceleration.html",
    "dashboard/revenue_dashboard.html",
    "dashboard/web3_dashboard.html",
    "dashboard/analyst_dashboard.html",
    "dashboard/agents_control_panel.html",
    "dashboard/threat_graph_dashboard.html",
]
for route in CRITICAL_ROUTES:
    p = REPO_ROOT / route
    ok = p.exists() and p.stat().st_size > 500
    detail = str(p.stat().st_size) + " bytes" if ok else "MISSING"
    check("/" + route, ok, detail)
    print("  " + P(ok) + " /" + route + (" (" + detail + ")" if ok else " <- " + detail))

# ── 2. BUILD PIPELINE VALIDATION ────────────────────────────────
section("2. BUILD PIPELINE VALIDATION")
src_build = BUILD_PY.read_text(encoding='utf-8') if BUILD_PY.exists() else ""

check("build_dist_artifact.py exists", BUILD_PY.exists())
print("  " + P(BUILD_PY.exists()) + " build_dist_artifact.py exists")

# Python 3.14-safe: use .value not .s
def ast_const_value(node):
    if isinstance(node, ast.Constant): return node.value
    return None  # legacy ast.Str/Num not needed in Python 3.x

try:
    tree = ast.parse(src_build)
    pg_in_set = False
    dash_in_dirs = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == 'HTML_EXCLUDE_PREFIXES':
                    members = [ast_const_value(e) for e in node.value.elts]
                    pg_in_set = 'PAYMENT-GATEWAY' in members
                if isinstance(t, ast.Name) and t.id == 'INCLUDE_DIRS':
                    vals = [ast_const_value(e) for e in node.value.elts]
                    dash_in_dirs = 'dashboard' in vals
    c = check("PAYMENT-GATEWAY NOT in HTML_EXCLUDE_PREFIXES", not pg_in_set)
    print("  " + P(c) + " PAYMENT-GATEWAY NOT in HTML_EXCLUDE_PREFIXES")
    c = check("dashboard IN INCLUDE_DIRS", dash_in_dirs)
    print("  " + P(c) + " dashboard in INCLUDE_DIRS")
except Exception as e:
    check("AST parse of build_dist_artifact.py", False, str(e))
    print("  [FAIL] AST parse error: " + str(e))

for label, needle in [
    ("Step 5.1 dashboard validator", "DASHBOARD ROUTE VALIDATOR"),
    ("Step 5.2 payment gateway validator", "PAYMENT GATEWAY VALIDATOR"),
]:
    found = needle in src_build
    check(label, found)
    print("  " + P(found) + " " + label)

try:
    ast.parse(src_build)
    check("build_dist syntax valid", True)
    print("  [PASS] build_dist_artifact.py syntax valid")
except SyntaxError as e:
    check("build_dist syntax valid", False, str(e))
    print("  [FAIL] build_dist_artifact.py syntax: " + str(e))

# ── 3. INDEX.HTML STRUCTURAL VALIDATION ─────────────────────────
section("3. INDEX.HTML STRUCTURAL VALIDATION")
src = INDEX.read_text(encoding='utf-8') if INDEX.exists() else ""
lines = src.count('\n')

struct_checks = [
    ("V173 renderer block START",        'CDB-RENDERER-ENGINE-V173-START' in src),
    ("V173 renderer block END",          'CDB-RENDERER-ENGINE-V173-END' in src),
    ("GVOS version 173",                 "173.0.0" in src),
    ("SOC tab system",                   'id="cdb-tab-bar"' in src),
    ("Threat grid",                      'id="threat-grid"' in src),
    ("Enterprise intel command center",  'id="enterprise-intel-command"' in src),
    ("EICC threat ticker",               'eicc-ticker-inner' in src),
    ("EICC metrics row",                 'eicc-metrics-row' in src),
    ("EICC AI predictions",              'eicc-ai-predictions' in src),
    ("EICC warfare heatmap",             'eicc-heatmap' in src),
    ("EICC SOC status",                  'eicc-soc-status' in src),
    ("EICC feed preview",                'eicc-feed-preview' in src),
    ("EICC data engine script",          'eiccEngine' in src),
    ("PAYMENT-GATEWAY CTA link",         '/PAYMENT-GATEWAY.html' in src),
    ("premium-intel-products section",   'id="premium-intel-products"' in src),
    ("No duplicate premium section",     src.count('id="premium-intel-products"') == 1),
    ("No duplicate EICC section",        src.count('id="enterprise-intel-command"') == 1),
    ("Dashboard nav links",              'enterprise_dashboard.html' in src),
    ("Pricing section",                  'id="pricing"' in src),
    ("Contact section",                  'id="contact"' in src),
    ("Subscribe section",                'id="subscribe"' in src),
    ("Script tags balanced",             src.count('<script') == src.count('</script>')),
    ("Style tags balanced",              src.count('<style') == src.count('</style>')),
    ("Charset UTF-8",                    'charset="UTF-8"' in src),
    ("Viewport meta",                    'name="viewport"' in src),
    ("Service worker registration",      'serviceWorker' in src or 'service-worker.js' in src),
    ("MITRE heatmap present",            'mitre' in src.lower()),
    ("File > 1MB",                       INDEX.stat().st_size > 1_000_000),
    ("Line count > 18000",               lines > 18000),
    ("EICC before premium (ordering)",   src.index('enterprise-intel-command') < src.index('premium-intel-products')),
    ("V173 panel display governance",    'display:block!important' in src or 'display:block !important' in src),
    ("V173 panel flex-basis governance", 'flex-basis:100%!important' in src or 'flex-basis:100% !important' in src),
]
for name, passed in struct_checks:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 4. PAYMENT GATEWAY VALIDATION ───────────────────────────────
section("4. PAYMENT GATEWAY VALIDATION")
pg = REPO_ROOT / "PAYMENT-GATEWAY.html"
pg_src = pg.read_text(encoding='utf-8') if pg.exists() else ""
for name, passed in [
    ("PAYMENT-GATEWAY.html exists",      pg.exists()),
    ("File > 500 lines",                 pg_src.count('\n') > 500),
    ("Valid DOCTYPE",                    '<!DOCTYPE html>' in pg_src),
    ("Pricing tiers present",            'plan-grid' in pg_src or 'plan-tile' in pg_src),
    ("Payment methods present",          'UPI' in pg_src or 'PayPal' in pg_src),
    ("noindex meta",                     'noindex' in pg_src),
    ("Script tags balanced",             pg_src.count('<script') == pg_src.count('</script>')),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 5. 404.HTML VALIDATION ───────────────────────────────────────
section("5. 404.HTML VALIDATION")
pg404 = REPO_ROOT / "404.html"
src404 = pg404.read_text(encoding='utf-8') if pg404.exists() else ""
for name, passed in [
    ("404.html exists",                  pg404.exists()),
    ("Valid DOCTYPE",                    '<!DOCTYPE html>' in src404),
    ("Has link back to /",               'href="/"' in src404),
    ("Has PAYMENT-GATEWAY link",         'PAYMENT-GATEWAY.html' in src404),
    ("Has 404 in title/content",         '404' in src404),
    ("Script tags balanced",             src404.count('<script') == src404.count('</script>')),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 6. SERVICE WORKER ────────────────────────────────────────────
section("6. SERVICE WORKER & CACHE VALIDATION")
sw_src = SW.read_text(encoding='utf-8') if SW.exists() else ""
for name, passed in [
    ("service-worker.js exists",         SW.exists()),
    ("V173 cache version",               'sentinel-apex-v173' in sw_src),
    ("Cache purge/delete logic",         'delete' in sw_src),
    ("Fetch handler",                    'fetch' in sw_src),
    ("Activate handler",                 'activate' in sw_src),
    ("Install handler",                  'install' in sw_src),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 7. _HEADERS ──────────────────────────────────────────────────
section("7. _HEADERS CACHE CONTROL")
hdr_src = HEADERS.read_text(encoding='utf-8') if HEADERS.exists() else ""
for name, passed in [
    ("_headers file exists",             HEADERS.exists()),
    ("Cache-Control headers",            'Cache-Control' in hdr_src),
    ("JS assets coverage",               '/js/' in hdr_src),
    ("no-cache directive",               'no-cache' in hdr_src or 'no-store' in hdr_src),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 8. DEPLOYMENT WORKFLOW ───────────────────────────────────────
section("8. DEPLOYMENT WORKFLOW VALIDATION")
wf_src = WORKFLOW.read_text(encoding='utf-8') if WORKFLOW.exists() else ""
for name, passed in [
    ("sentinel-blogger.yml exists",      WORKFLOW.exists()),
    ("build_dist_artifact.py in CI",     'build_dist_artifact.py' in wf_src),
    ("JamesIves deploy action",          'JamesIves/github-pages-deploy-action' in wf_src),
    ("Deploys from dist/",               'folder: dist' in wf_src),
    ("gh-pages branch target",           'gh-pages' in wf_src),
    ("clean: false",                     'clean: false' in wf_src),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 9. DASHBOARD FILE INTEGRITY ──────────────────────────────────
section("9. DASHBOARD FILE INTEGRITY")
dashboard_dir = REPO_ROOT / "dashboard"
c = check("dashboard/ exists", dashboard_dir.exists())
print("  " + P(c) + " dashboard/ directory")
if dashboard_dir.exists():
    dash_files = sorted(dashboard_dir.glob("*.html"))
    print("    " + str(len(dash_files)) + " HTML files found")
    for df in dash_files:
        ok2 = df.stat().st_size > 500
        check("dashboard/" + df.name, ok2)
        print("  " + P(ok2) + " " + df.name + " (" + str(df.stat().st_size) + " bytes)")

# ── 10. API ENDPOINTS ─────────────────────────────────────────────
section("10. API ENDPOINT VALIDATION")
for ep, required in [
    ("api/ai/tracker.json", True),
    ("api/ai/predictions.json", False),  # Optional — EICC uses tracker.json
    ("feed.json", True),
    ("latest.json", True),
    ("feed_manifest.json", True),
    ("manifest.json", True),
]:
    p = REPO_ROOT / ep
    ok2 = p.exists()
    detail = str(p.stat().st_size) + " bytes" if ok2 else ("MISSING (optional)" if not required else "MISSING")
    if required:
        check("/" + ep, ok2, detail)
    print("  " + P(ok2) + " /" + ep + " " + detail + ("" if required else " [optional]"))

# ── 11. MOBILE / RESPONSIVE ───────────────────────────────────────
section("11. MOBILE & RESPONSIVE VALIDATION")
for name, passed in [
    ("Viewport meta tag",                '<meta name="viewport"' in src),
    ("CSS media queries",                '@media' in src),
    ("EICC mobile override",             'max-width:768px' in src),
    ("CSS auto-fit grid",                'auto-fit' in src),
    ("CSS minmax() layout",              'minmax(' in src),
    ("Flexbox",                          'display:flex' in src),
    ("CSS Grid",                         'display:grid' in src),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 12. GPU / RENDER STABILITY ────────────────────────────────────
section("12. GPU & RENDER STABILITY (V173)")
comp_path = REPO_ROOT / "js" / "engines" / "compositor-governance-engine.js"
comp_src  = comp_path.read_text(encoding='utf-8') if comp_path.exists() else ""
for name, passed in [
    ("V173 IIFE cdbV173()",              'function cdbV173' in src),
    ("applySize() present",              'applySize' in src),
    ("startViewportWatchdog()",          'startViewportWatchdog' in src),
    ("injectCriticalCSS()",              'injectCriticalCSS' in src),
    ("panel display:block governance",   'display:block!important' in src or 'display:block !important' in src),
    ("panel flex-basis:100% governance", 'flex-basis:100%!important' in src or 'flex-basis:100% !important' in src),
    ("compositor engine exists",         comp_path.exists()),
    ("promote() neutralized",            'promote' in comp_src and ('no-op' in comp_src.lower() or 'neutralized' in comp_src.lower() or 'no op' in comp_src.lower())),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── 13. BROWSER COMPATIBILITY ─────────────────────────────────────
section("13. BROWSER COMPATIBILITY")
for name, passed in [
    ("requestIdleCallback + setTimeout fallback", 'requestIdleCallback' in src and 'setTimeout' in src),
    ("CSS variables var(--)",            'var(--' in src),
    ("Canvas 2D getContext",             'getContext' in src),
    ("requestAnimationFrame",            'requestAnimationFrame' in src),
    ("No IE filter hacks",               'filter: progid' not in src),
    ("fetch() API",                      'fetch(' in src),
]:
    check(name, passed)
    print("  " + P(passed) + " " + name)

# ── FINAL SUMMARY ─────────────────────────────────────────────────
total        = len(results)
passed_count = sum(1 for r in results if r[0]=='PASS')
fail_count   = len(failures)

print("\n" + "="*62)
print("  PLATFORM VALIDATION SUITE -- FINAL REPORT v158.0")
print("="*62)
print("  Total checks : " + str(total))
print("  Passed       : " + str(passed_count))
print("  Failed       : " + str(fail_count))
print("  Score        : " + str(100 * passed_count // total) + "%")
print("  Timestamp    : " + datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))

if failures:
    print("\n  FAILURES (" + str(fail_count) + "):")
    for name, detail in failures:
        print("    [FAIL] " + name + (" -> " + detail if detail else ""))
    print("")
    sys.exit(1)
else:
    print("\n  ALL " + str(total) + " CHECKS PASSED -- platform validated")
    sys.exit(0)
