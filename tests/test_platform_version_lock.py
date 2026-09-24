"""The release identity is one version. VERSION is the authority."""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_version_governance_check_is_clean():
    proc = subprocess.run(
        [sys.executable, "scripts/version_governance.py", "--check"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
