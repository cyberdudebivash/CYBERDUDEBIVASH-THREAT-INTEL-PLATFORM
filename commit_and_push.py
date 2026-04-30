#!/usr/bin/env python3
"""
GOD MODE commit + push + trigger GHA workflow_dispatch.
Run from repo root.
"""
import subprocess
import sys
import os
import json
import urllib.request
import urllib.error

REPO = r"C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
COMMIT_MSG = "P0 GOD MODE FIX v141.8.0: tuple-unpack fix + structural guard - dashboard 2-advisory corruption ELIMINATED permanently"
GH_REPO = "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
WORKFLOW_FILE = "sentinel-blogger.yml"
BRANCH = "main"

def run(cmd, **kwargs):
    print(f"[CMD] {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, **kwargs)
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.stderr.strip():
        print(r.stderr.strip())
    return r

def get_github_token():
    # Try git credential store
    r = run(["git", "config", "--get", "http.extraheader"])
    if "AUTHORIZATION" in r.stdout:
        # parse Bearer token
        import re
        m = re.search(r'Bearer\s+([A-Za-z0-9_\-]+)', r.stdout)
        if m:
            return m.group(1)

    # Try from git config
    r2 = run(["git", "remote", "get-url", "origin"])
    url = r2.stdout.strip()
    if "@" in url:
        # https://TOKEN@github.com/...
        import re
        m = re.search(r'https://([^@]+)@github', url)
        if m:
            return m.group(1)

    # env var fallback
    return os.environ.get("GITHUB_TOKEN", "")

def main():
    os.chdir(REPO)

    # 1. Verify staged files
    r = run(["git", "diff", "--cached", "--name-only"])
    staged = r.stdout.strip()
    print(f"\n[STAGED] {staged}")
    if not staged:
        print("[INFO] Nothing staged — checking working tree...")
        run(["git", "add", "scripts/run_pipeline.py", "scripts/validate_repo.py"])
        r2 = run(["git", "diff", "--cached", "--name-only"])
        if not r2.stdout.strip():
            print("[WARN] Nothing to commit. Files may already be committed.")
        staged = r2.stdout.strip()

    # 2. Commit
    print("\n[COMMIT] ...")
    r = run(["git", "commit", "-m", COMMIT_MSG])
    if r.returncode not in (0, 1):
        print(f"[ERROR] Commit failed: {r.stderr}")
        sys.exit(1)
    if "nothing to commit" in r.stdout.lower():
        print("[INFO] Already committed.")
    else:
        print("[OK] Committed.")

    # 3. Pull rebase (GHA commits data back during runs)
    print("\n[PULL REBASE] ...")
    run(["git", "pull", "--rebase", "origin", BRANCH])

    # 4. Push
    print("\n[PUSH] ...")
    r = run(["git", "push", "origin", BRANCH])
    if r.returncode != 0:
        print(f"[ERROR] Push failed: {r.stderr}")
        sys.exit(1)
    print("[OK] Pushed to origin/main.")

    # 5. Trigger workflow_dispatch via GitHub API
    token = get_github_token()
    if not token:
        print("[WARN] No GitHub token found — workflow_dispatch skipped. "
              "Manually trigger at: https://github.com/" + GH_REPO + "/actions")
        return

    url = f"https://api.github.com/repos/{GH_REPO}/actions/workflows/{WORKFLOW_FILE}/dispatches"
    payload = json.dumps({"ref": BRANCH}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    print(f"\n[TRIGGER] POST {url}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
        print(f"[OK] workflow_dispatch HTTP {status} — pipeline is queued!")
        print(f"     Monitor at: https://github.com/{GH_REPO}/actions")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[WARN] workflow_dispatch failed HTTP {e.code}: {body}")
        print("       Trigger manually at: https://github.com/" + GH_REPO + "/actions")

    # 6. Show log
    print("\n[GIT LOG - last 3]")
    run(["git", "log", "--oneline", "-3"])
    print("\n[DONE] All steps complete.")

if __name__ == "__main__":
    main()
