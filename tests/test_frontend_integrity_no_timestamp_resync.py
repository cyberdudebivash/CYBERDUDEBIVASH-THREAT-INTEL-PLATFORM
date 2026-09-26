"""
frontend_integrity.py generate rewrites the registry only when a checksum
changes.

PR #538 (2026-09-26): frontend-integrity-sync pushed resync commit 9fa9dac
that changed only generated_at and checkout-time last_modified values.
GitHub held that bot commit's six workflow runs for approval and closed them
as failed when the PR merged (no job executed).
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import frontend_integrity as fi  # noqa: E402


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    (tmp_path / "a.html").write_text("<html>a</html>")
    (tmp_path / "b.js").write_text("console.log(1)")
    monkeypatch.setattr(fi, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(fi, "PROTECTED_ASSETS", ["a.html", "b.js"])
    monkeypatch.setattr(fi, "REGISTRY_PATH", tmp_path / "config" / "frontend_checksums.json")
    return tmp_path


def _generate():
    fi.cmd_generate(None)
    return fi.REGISTRY_PATH.read_text(encoding="utf-8")


def test_unchanged_checksums_leave_the_file_byte_identical(sandbox):
    first = _generate()
    import os, time
    os.utime(sandbox / "a.html", (time.time() + 60, time.time() + 60))  # new checkout mtime
    assert _generate() == first


def test_content_change_rewrites(sandbox):
    first = json.loads(_generate())
    (sandbox / "a.html").write_text("<html>changed</html>")
    second = json.loads(_generate())
    assert second["assets"]["a.html"]["sha256"] != first["assets"]["a.html"]["sha256"]


def test_missing_or_corrupt_registry_is_written(sandbox):
    assert json.loads(_generate())["assets"].keys() == {"a.html", "b.js"}
    fi.REGISTRY_PATH.write_text("{broken")
    assert json.loads(_generate())["protected_count"] == 2


def test_asset_list_change_rewrites(sandbox, monkeypatch):
    _generate()
    (sandbox / "c.css").write_text("x{}")
    monkeypatch.setattr(fi, "PROTECTED_ASSETS", ["a.html", "b.js", "c.css"])
    assert "c.css" in json.loads(_generate())["assets"]


def test_repo_registry_is_left_alone_when_assets_unchanged():
    before = (REPO / "config" / "frontend_checksums.json").read_bytes()
    fi.cmd_generate(None)
    assert (REPO / "config" / "frontend_checksums.json").read_bytes() == before
