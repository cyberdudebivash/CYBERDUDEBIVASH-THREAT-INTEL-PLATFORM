"""
conftest.py — CyberDudeBivash SENTINEL APEX ULTRA
Pytest shared fixtures and configuration for the full test suite.
"""
import os
import sys
import json
import pytest

# Ensure project root is on the path so agent.* imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Shared Sample Data ────────────────────────────────────────────────────────

SAMPLE_THREAT_TEXT = """
Emerging threat detected from 185.220.101.45 and C2 server at 45.33.32.156.
Malware hash: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
Phishing domain: evil-login.example-malware.com
Registry persistence: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware-svc
CVE-2024-12345 exploited in the wild.  CVE-2023-44487 also observed.
Contact attacker@darknet.org
Payload: dropper.exe downloaded from https://malware-cdn.evil.net/payload.zip
Private IP 192.168.1.1 should be excluded.
Loopback 127.0.0.1 should also be excluded.
"""

SAMPLE_RANSOMWARE_TEXT = """
LockBit 3.0 variant detected.  Ransomware encrypted files and deleted shadow copies.
vssadmin delete shadows used to destroy backups.
C2: 203.0.113.99  Ransom note found: YOUR_FILES_HAVE_BEEN_ENCRYPTED.txt
"""

SAMPLE_NATION_STATE_TEXT = """
APT41 nation-state actor exploiting supply chain vulnerability in widely-used library.
CVE-2024-99999 active exploitation confirmed by CISA KEV catalogue.
"""


@pytest.fixture
def sample_text():
    return SAMPLE_THREAT_TEXT


@pytest.fixture
def ransomware_text():
    return SAMPLE_RANSOMWARE_TEXT


@pytest.fixture
def sample_iocs():
    """Pre-built IOC dict matching SAMPLE_THREAT_TEXT extraction."""
    return {
        "ipv4": ["185.220.101.45", "45.33.32.156"],
        "domain": ["evil-login.example-malware.com", "malware-cdn.evil.net", "darknet.org"],
        "url": ["https://malware-cdn.evil.net/payload.zip"],
        "sha256": ["a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"],
        "md5": [],
        "sha1": [],
        "email": ["attacker@darknet.org"],
        "cve": ["CVE-2024-12345", "CVE-2023-44487"],
        "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware-svc"],
        "artifacts": ["dropper.exe"],
    }


@pytest.fixture
def empty_iocs():
    return {
        "ipv4": [], "domain": [], "url": [], "sha256": [],
        "md5": [], "sha1": [], "email": [], "cve": [], "registry": [], "artifacts": [],
    }


@pytest.fixture
def minimal_stix_bundle():
    """A minimal valid STIX 2.1 bundle for schema testing."""
    return {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789abc",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "identity",
                "id": "identity--12345678-1234-1234-1234-123456789abc",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
                "name": "CyberDudeBivash GOC",
                "identity_class": "organization",
            }
        ],
    }
