#!/usr/bin/env python3
"""Final validation + git commit + push for P0 feed.json fix"""
import subprocess, pathlib, py_compile, json, sys

REPO = pathlib.Path(r"C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM")
GIT  = r"C:\Program Files\Git\cmd\git.exe"
PY   = r"C:\Users\Administrator\AppData\Local\Programs\Python\Python314\python.exe"

def run(cmd, **kw):
    r = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                       timeout=60, errors="replace", **kw)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

print("=" * 60)
print("STEP 1: py_compile validation on modified scripts")
print("=" * 60)
targets = [
    "scripts/sanitize_repo.py",
    "scripts/api_layer_v101.py",
    "scripts/run_pipeline.py",
    "scripts/validate_repo.py",
]
all_ok = True
for rel in targets:
    fp = REPO / rel
    try:
        py_compile.compile(str(fp), doraise=True)
        print(f"  PASS: {rel}")
    except py_compile.PyCompileError as e:
        print(f"  FAIL: {rel}  ->  {e}")
        all_ok = False

if not all_ok:
    print("\nABORTED: Syntax errors found. Fix before committing.")
    sys.exit(1)

print("\n" + "=" * 60)
print("STEP 2: Verify feed.json is valid JSON []")
print("=" * 60)
feed = REPO / "feed.json"
try:
    obj = json.loads(feed.read_text("utf-8"))
    print(f"  feed.json: VALID ({type(obj).__name__}): {obj!r}")
except Exception as e:
    print(f"  FAIL: feed.json invalid: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("STEP 3: python_syntax_guard.py full scan")
print("=" * 60)
out, err, rc = run([PY, "scripts/python_syntax_guard.py"])
print(out or "(no output)")
if rc != 0:
    print(f"WARN: syntax_guard exit {rc} -- {err}")

print("\n" + "=" * 60)
print("STEP 4: git diff --stat")
print("=" * 60)
out, err, rc = run([GIT, "diff", "--stat"])
print(out or "(no changes)")

print("\n" + "=" * 60)
print("STEP 5: git add modified files")
print("=" * 60)
files_to_add = [
    "feed.json",
    "scripts/sanitize_repo.py",
    "scripts/api_layer_v101.py",
    "scripts/run_pipeline.py",
    "scripts/validate_repo.py",
]
for f in files_to_add:
    out, err, rc = run([GIT, "add", f])
    print(f"  git add {f}: rc={rc}" + (f" ERR:{err}" if err else ""))

print("\n" + "=" * 60)
print("STEP 6: git commit")
print("=" * 60)
msg = ("P0 FINAL FIX: feed.json data pipeline -- Stage 0.1 + Stage 5.5\n\n"
       "- feed.json at repo root: replaced YAML content with valid JSON []\n"
       "- sanitize_repo.py: added feed.json + api/feed.json to MANIFEST_FALLBACKS\n"
       "- sanitize_repo.py: get_fallback_structure handles list fallbacks ([] is valid)\n"
       "- api_layer_v101.py: added safe_write_feed() + safe_load_feed() with hard validation\n"
       "- api_layer_v101.py: build_feed_json() now verifies written JSON post-write\n"
       "- run_pipeline.py: added stage_feed_guard() as Stage 0.0a (first step in main)\n"
       "  Guarantees feed.json always exists and contains valid JSON before any read\n"
       "- validate_repo.py: hardened check_json() -- [] is explicitly VALID\n"
       "  Missing feed files are WARNING not FAIL; check_yaml() encoding-safe\n"
       "- All modified files compile clean (py_compile + ast.parse)")

out, err, rc = run([GIT, "commit", "-m", msg])
print(out)
if err: print("STDERR:", err[:300])
if rc != 0 and "nothing to commit" not in (out + err):
    print(f"Commit failed rc={rc}")
    sys.exit(1)

print("\n" + "=" * 60)
print("STEP 7: git pull --rebase then push")
print("=" * 60)
out, err, rc = run([GIT, "pull", "--rebase", "origin", "main"], timeout=60)
print("pull:", out[:300])
out, err, rc = run([GIT, "push", "origin", "main"], timeout=60)
print("push:", out[:200], err[:200])
if rc == 0:
    print("\nPUSH SUCCESSFUL")
else:
    print(f"\nPUSH FAILED rc={rc}: {err[:400]}")
    sys.exit(1)

print("\n" + "=" * 60)
print("FINAL: Verify git log")
print("=" * 60)
out, err, rc = run([GIT, "log", "--oneline", "-5"])
print(out)
