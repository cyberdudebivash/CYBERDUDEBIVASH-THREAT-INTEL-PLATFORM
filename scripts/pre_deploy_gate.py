#!/usr/bin/env python3
"""
pre_deploy_gate.py -- SENTINEL APEX Pre-Deploy Gate v158.0
Runs BEFORE every deployment. Hard-fails if any P0 condition is violated.
Called from sentinel-blogger.yml before build_dist_artifact.py.

Exit codes:
  0 = gate passed, safe to deploy
  1 = gate FAILED, deployment BLOCKED

Usage: python scripts/pre_deploy_gate.py
"""
import sys, ast
from pathlib import Path
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except Exception: pass

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_PY  = REPO_ROOT / "scripts" / "build_dist_artifact.py"
INDEX     = REPO_ROOT / "index.html"
SW        = REPO_ROOT / "service-worker.js"

failures = []

def gate(name, passed, fix=""):
    if not passed:
        failures.append((name, fix))
        print("[GATE FAIL] " + name)
        if fix: print("   FIX: " + fix)
    else:
        print("[GATE PASS] " + name)
    return passed

print("=" * 62)
print("  SENTINEL APEX PRE-DEPLOY GATE v158.0")
print("  " + datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
print("=" * 62)

# ── GATE 1: PAYMENT-GATEWAY.html must exist ──────────────────────
gate("PAYMENT-GATEWAY.html exists in repo",
     (REPO_ROOT / "PAYMENT-GATEWAY.html").exists(),
     "Restore PAYMENT-GATEWAY.html to repo root before deploying")

# ── GATE 2: PAYMENT-GATEWAY not excluded from dist ───────────────
src_build = BUILD_PY.read_text(encoding='utf-8') if BUILD_PY.exists() else ""
try:
    tree = ast.parse(src_build)
    pg_excluded = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == 'HTML_EXCLUDE_PREFIXES':
                    members = [n.value for n in node.value.elts if isinstance(n, ast.Constant)]
                    pg_excluded = 'PAYMENT-GATEWAY' in members
    gate("PAYMENT-GATEWAY NOT in HTML_EXCLUDE_PREFIXES",
         not pg_excluded,
         "Remove 'PAYMENT-GATEWAY' from HTML_EXCLUDE_PREFIXES in build_dist_artifact.py")
except Exception as e:
    gate("PAYMENT-GATEWAY exclusion check", False, "AST parse failed: " + str(e))

# ── GATE 3: dashboard in INCLUDE_DIRS ────────────────────────────
try:
    dash_present = False
    for node in ast.walk(ast.parse(src_build)):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == 'INCLUDE_DIRS':
                    vals = [n.value for n in node.value.elts if isinstance(n, ast.Constant)]
                    dash_present = 'dashboard' in vals
    gate("dashboard in INCLUDE_DIRS",
         dash_present,
         "Add 'dashboard' to INCLUDE_DIRS in build_dist_artifact.py")
except Exception as e:
    gate("dashboard in INCLUDE_DIRS", False, "AST parse failed: " + str(e))

# ── GATE 4: build_dist_artifact.py syntax valid ───────────────────
try:
    ast.parse(src_build)
    gate("build_dist_artifact.py syntax valid", True)
except SyntaxError as e:
    gate("build_dist_artifact.py syntax valid", False, "Fix syntax error: " + str(e))

# ── GATE 5: index.html exists and is non-trivial ─────────────────
gate("index.html exists and > 1MB",
     INDEX.exists() and INDEX.stat().st_size > 1_000_000,
     "index.html is missing or truncated")

# ── GATE 6: 404.html exists ──────────────────────────────────────
gate("404.html exists",
     (REPO_ROOT / "404.html").exists(),
     "Restore 404.html to repo root")

# ── GATE 7: Service worker V173 cache version ─────────────────────
sw_src = SW.read_text(encoding='utf-8') if SW.exists() else ""
gate("Service worker has V173 cache version",
     'sentinel-apex-v173' in sw_src,
     "Update CACHE_VERSION in service-worker.js to sentinel-apex-v173-live")

# ── GATE 8: V173 renderer intact ─────────────────────────────────
src = INDEX.read_text(encoding='utf-8') if INDEX.exists() else ""
gate("V173 renderer block intact",
     'CDB-RENDERER-ENGINE-V173-START' in src and 'CDB-RENDERER-ENGINE-V173-END' in src,
     "V173 renderer block has been removed from index.html")

# ── GATE 9: Script/style tags balanced in index.html ─────────────
gate("index.html script tags balanced",
     src.count('<script') == src.count('</script>'),
     "Unbalanced <script> tags in index.html — syntax error")

gate("index.html style tags balanced",
     src.count('<style') == src.count('</style>'),
     "Unbalanced <style> tags in index.html — syntax error")

# ── GATE 10: All dashboard files exist ───────────────────────────
REQUIRED_DASHBOARD = [
    "dashboard/enterprise_dashboard.html",
    "dashboard/enterprise_dashboard_v2.html",
    "dashboard/orchestration_hub.html",
]
for route in REQUIRED_DASHBOARD:
    gate("Exists: " + route,
         (REPO_ROOT / route).exists(),
         "Restore " + route + " before deploying")

# ── GATE 11: Deployment validators present ────────────────────────
gate("Step 5.1 dashboard validator in build script",
     "DASHBOARD ROUTE VALIDATOR" in src_build,
     "Restore Step 5.1 validator in build_dist_artifact.py")

gate("Step 5.2 payment gateway validator in build script",
     "PAYMENT GATEWAY VALIDATOR" in src_build,
     "Restore Step 5.2 validator in build_dist_artifact.py")

# ── SUMMARY ───────────────────────────────────────────────────────
total = 13 + len(REQUIRED_DASHBOARD) - 3  # adjust count
print("")
print("=" * 62)
if failures:
    print("  PRE-DEPLOY GATE: BLOCKED (" + str(len(failures)) + " failures)")
    print("=" * 62)
    for name, fix in failures:
        print("  [BLOCKED] " + name)
        if fix: print("    -> " + fix)
    print("")
    print("  Deployment is BLOCKED until all gate failures are resolved.")
    sys.exit(1)
else:
    print("  PRE-DEPLOY GATE: PASSED -- safe to deploy")
    print("=" * 62)
    sys.exit(0)
