import subprocess, json, pathlib, os, sys

REPO = r"C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
GIT  = r"C:\Program Files\Git\cmd\git.exe"
OUT  = REPO + r"\diag_out.txt"

buf = []
def p(*a): line=" ".join(str(x) for x in a); buf.append(line); print(line)

def run(cmd):
    try:
        r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception as e:
        return f"ERR:{e}"

p("=== GIT LOG ===")
p(run([GIT, "log", "--oneline", "-8"]))

p("\n=== feed.json tracked in local git? ===")
p(repr(run([GIT, "ls-files", "feed.json"])))

p("\n=== feed.json on origin/main (remote)? ===")
remote_feed = run([GIT, "show", "origin/main:feed.json"])
p(repr(remote_feed[:300]) if remote_feed else "NOT FOUND ON REMOTE")

p("\n=== All feed.json files locally ===")
for fp in pathlib.Path(REPO).rglob("feed.json"):
    try:
        sz = fp.stat().st_size
        head = fp.read_bytes()[:120]
        p(f"  {fp.relative_to(REPO)}  [{sz}B]  {head!r}")
    except Exception as e:
        p(f"  ERR: {e}")

p("\n=== Critical JSON files ===")
for rel in ["data/stix/feed_manifest.json","data/feed_manifest.json","data/publish_queue.json","api/feed.json"]:
    fp = pathlib.Path(REPO) / rel
    if not fp.exists():
        p(f"  MISSING: {rel}")
        continue
    try:
        obj = json.loads(fp.read_text("utf-8"))
        p(f"  OK ({type(obj).__name__}, sz={fp.stat().st_size}): {rel}")
    except Exception as e:
        p(f"  INVALID {rel}: {e}")

p("\n=== check_encoding simulation (YAML/shell for non-ASCII) ===")
SKIP = {".git","node_modules","__pycache__",".venv","venv","dist","build"}
dirty = []
for dirpath, dirnames, filenames in os.walk(REPO):
    dirnames[:] = [d for d in dirnames if d not in SKIP]
    for fname in filenames:
        fp2 = pathlib.Path(dirpath) / fname
        if fp2.suffix.lower() not in {".yml",".yaml",".sh",".bash"}:
            continue
        try:
            data = fp2.read_bytes()
        except:
            continue
        if data.startswith(b"\xef\xbb\xbf"):
            dirty.append(f"{fp2.relative_to(REPO)} [BOM]"); continue
        try:
            data.decode("ascii")
        except UnicodeDecodeError:
            dirty.append(f"{fp2.relative_to(REPO)} [non-ASCII]")
if dirty:
    p(f"  FAIL: {len(dirty)} files: {dirty[:8]}")
else:
    p("  PASS: all YAML/shell files clean")

pathlib.Path(OUT).write_text("\n".join(buf), encoding="utf-8")
p(f"\n[SAVED] {OUT}")
