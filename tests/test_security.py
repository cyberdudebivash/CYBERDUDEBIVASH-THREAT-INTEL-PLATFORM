"""Security hygiene tests"""
import pytest
from pathlib import Path
import re

SENSITIVE_PATTERNS = [
    r"api_key\s*=\s*['\"][^'\"]{20,}['\"]",
    r"secret\s*=\s*['\"][^'\"]{20,}['\"]",
    r"password\s*=\s*['\"][^'\"]{8,}['\"]",
]

def test_no_hardcoded_secrets():
    """No hardcoded secrets in Python files"""
    for py_file in Path(".").rglob("*.py"):
        if "__pycache__" in str(py_file) or "test" in str(py_file).lower():
            continue
        content = py_file.read_text()
        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            # Filter out obvious placeholders
            real_matches = [m for m in matches if "your_" not in m.lower() and "xxx" not in m.lower()]
            assert not real_matches, f"Possible secret in {py_file}"

def test_gitignore_has_credentials():
    """.gitignore must exclude credentials"""
    gitignore = Path(".gitignore").read_text()
    assert "credentials/" in gitignore
    assert ".env" in gitignore
    assert "*.pem" in gitignore
