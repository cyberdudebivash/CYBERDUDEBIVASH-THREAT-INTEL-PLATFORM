"""Version consistency tests"""
import pytest
import json
import re
from pathlib import Path

def test_version_file_exists():
    """VERSION file must exist"""
    assert Path("VERSION").exists()

def test_version_format():
    """VERSION must be semantic versioning"""
    version = Path("VERSION").read_text().strip()
    assert re.match(r"^\d+\.\d+\.\d+$", version)

def test_version_consistency():
    """All version sources must match"""
    version_file = Path("VERSION").read_text().strip()
    
    # Check core/version.py
    from core.version import VERSION
    assert VERSION == version_file, f"core/version.py ({VERSION}) != VERSION ({version_file})"

def test_index_html_version():
    """index.html must have current version"""
    version = Path("VERSION").read_text().strip()
    major_minor = ".".join(version.split(".")[:2])
    
    index_content = Path("index.html").read_text()
    assert f"v{major_minor}" in index_content, f"v{major_minor} not found in index.html"

def test_no_credentials_committed():
    """Real credentials must not be in repo"""
    creds_path = Path("credentials/credentials.json")
    if creds_path.exists():
        content = json.loads(creds_path.read_text())
        if "installed" in content:
            client_id = content["installed"].get("client_id", "")
            assert "YOUR_" in client_id or len(client_id) < 20, \
                "Real credentials detected in credentials.json!"
