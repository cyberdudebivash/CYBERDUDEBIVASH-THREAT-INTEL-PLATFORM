"""Regression: manifest reconciliation must not abort publication under Windows cp1252 pipes.

The production eligibility generator spawns the reconciler with captured stdout.
Printing U+2705 with a legacy non-UTF-8 subprocess stream previously raised
UnicodeEncodeError *after* a successful reconciliation, causing the parent
manifest generator to refuse publication. Simulate that encoding on every OS.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("scenario", ["already_reconciled", "sync_missing_item"])
def test_reconciler_success_logs_are_cp1252_safe(tmp_path: Path, scenario: str):
    item = {
        "id": "intel--synthetic-encoding-control",
        "stix_id": "intel--synthetic-encoding-control",
        "title": "Synthetic public advisory",
        "tlp": "TLP:CLEAR",
        "iocs": [],
        "ioc_count": 0,
    }
    feed = tmp_path / "feed.json"
    manifest = tmp_path / "manifest.json"
    feed.write_text(json.dumps([item]), encoding="utf-8")
    manifest.write_text(json.dumps([item] if scenario == "already_reconciled" else []),
                        encoding="utf-8")

    script = ("from pathlib import Path; from scripts.manifest_reconciler import reconcile; "
              "import sys; result=reconcile(feed_path=Path(sys.argv[1]), "
              "manifest_path=Path(sys.argv[2])); "
              "assert result['status']==sys.argv[3], result")
    expected_status = "clean" if scenario == "already_reconciled" else "synced"
    env = dict(os.environ, PYTHONIOENCODING="cp1252:strict", PYTHONUTF8="0")
    result = subprocess.run([sys.executable, "-c", script,
                             str(feed), str(manifest), expected_status],
                            cwd=ROOT, env=env, capture_output=True, text=True,
                            encoding="cp1252", errors="strict", timeout=20, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[RECONCILER] [OK]" in result.stdout
    assert all(ord(char) < 128 for char in result.stdout)
    saved = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(saved) == 1 and saved[0]["id"] == item["id"]
