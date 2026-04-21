import subprocess, pathlib

REPO = r"C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
GIT  = r"C:\Program Files\Git\cmd\git.exe"

def git(*args):
    r = subprocess.run([GIT] + list(args), cwd=REPO,
                       capture_output=True, timeout=90)
    out = r.stdout.decode("utf-8", "replace").strip() if r.stdout else ""
    err = r.stderr.decode("utf-8", "replace").strip() if r.stderr else ""
    return out, err, r.returncode

print("--- pull --rebase ---")
out, err, rc = git("pull", "--rebase", "origin", "main")
print(out[:400]); print(err[:200]); print(f"rc={rc}")

print("\n--- push ---")
out, err, rc = git("push", "origin", "main")
print(out[:400]); print(err[:400]); print(f"rc={rc}")

print("\n--- git log ---")
out, _, _ = git("log", "--oneline", "-6")
print(out)
