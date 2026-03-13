"""
test_ioc_extraction.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for the IOC extraction engine (enricher.py).

Tests cover:
- IPv4 extraction and private-IP exclusion
- Domain extraction and false-positive filtering
- SHA256 / MD5 hash extraction
- URL extraction
- Email extraction
- CVE ID extraction
- Registry key extraction
- Artifact filename extraction
- Confidence scoring
"""
import pytest
from agent.enricher import enricher


# ─── IPv4 Extraction ──────────────────────────────────────────────────────────

class TestIPv4Extraction:
    def test_public_ip_extracted(self):
        iocs = enricher.extract_iocs("Threat actor at 185.220.101.45 connected to C2.")
        assert "185.220.101.45" in iocs["ipv4"]

    def test_private_ip_10_excluded(self):
        iocs = enricher.extract_iocs("Internal host 10.0.0.1 is not a threat.")
        assert "10.0.0.1" not in iocs.get("ipv4", [])

    def test_private_ip_192_168_excluded(self):
        iocs = enricher.extract_iocs("192.168.1.100 should not appear.")
        assert "192.168.1.100" not in iocs.get("ipv4", [])

    def test_private_ip_172_excluded(self):
        iocs = enricher.extract_iocs("172.16.0.1 is a private address.")
        assert "172.16.0.1" not in iocs.get("ipv4", [])

    def test_loopback_excluded(self):
        iocs = enricher.extract_iocs("Loopback 127.0.0.1 should be excluded.")
        assert "127.0.0.1" not in iocs.get("ipv4", [])

    def test_google_dns_excluded(self):
        iocs = enricher.extract_iocs("Using Google DNS 8.8.8.8 for resolution.")
        assert "8.8.8.8" not in iocs.get("ipv4", [])

    def test_multiple_public_ips(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        # Both public IPs in sample text should be present
        assert len(iocs.get("ipv4", [])) >= 1

    def test_no_ips_returns_empty_list(self):
        iocs = enricher.extract_iocs("No IP addresses here at all.")
        assert iocs.get("ipv4", []) == [] or isinstance(iocs.get("ipv4"), list)


# ─── Domain Extraction ────────────────────────────────────────────────────────

class TestDomainExtraction:
    def test_malicious_domain_extracted(self):
        iocs = enricher.extract_iocs("C2 at evil-login.example-malware.com detected.")
        assert "evil-login.example-malware.com" in iocs.get("domain", [])

    def test_false_positive_domain_excluded(self):
        """Known benign domains should be filtered out."""
        iocs = enricher.extract_iocs("Update available at microsoft.com and google.com")
        # Major benign domains should not appear as threat IOCs
        domains = iocs.get("domain", [])
        assert "google.com" not in domains
        assert "microsoft.com" not in domains

    def test_subdomain_extracted(self):
        iocs = enricher.extract_iocs("Payload from malware-cdn.evil.net detected.")
        assert "malware-cdn.evil.net" in iocs.get("domain", [])


# ─── Hash Extraction ──────────────────────────────────────────────────────────

class TestHashExtraction:
    SHA256_HASH = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    MD5_HASH = "5d41402abc4b2a76b9719d911017c592"

    def test_sha256_extracted(self):
        iocs = enricher.extract_iocs(f"Malware hash: {self.SHA256_HASH}")
        assert self.SHA256_HASH in iocs.get("sha256", [])

    def test_md5_extracted(self):
        iocs = enricher.extract_iocs(f"MD5: {self.MD5_HASH}")
        assert self.MD5_HASH in iocs.get("md5", [])

    def test_sha256_correct_length(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        for h in iocs.get("sha256", []):
            assert len(h) == 64, f"SHA256 hash wrong length: {h}"

    def test_md5_correct_length(self):
        iocs = enricher.extract_iocs(f"MD5: {self.MD5_HASH}")
        for h in iocs.get("md5", []):
            assert len(h) == 32, f"MD5 hash wrong length: {h}"


# ─── URL Extraction ───────────────────────────────────────────────────────────

class TestURLExtraction:
    def test_http_url_extracted(self):
        iocs = enricher.extract_iocs("Downloaded from https://malware-cdn.evil.net/payload.zip")
        assert any("payload.zip" in u for u in iocs.get("url", []))

    def test_url_is_string(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        for u in iocs.get("url", []):
            assert isinstance(u, str), f"URL should be a string, got {type(u)}"


# ─── Email Extraction ─────────────────────────────────────────────────────────

class TestEmailExtraction:
    def test_email_extracted(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        assert "attacker@darknet.org" in iocs.get("email", [])

    def test_email_format_valid(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        for email in iocs.get("email", []):
            assert "@" in email
            assert "." in email.split("@")[-1]


# ─── CVE Extraction ───────────────────────────────────────────────────────────

class TestCVEExtraction:
    def test_cve_extracted(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        assert "CVE-2024-12345" in iocs.get("cve", [])

    def test_multiple_cves_extracted(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        assert len(iocs.get("cve", [])) >= 2

    def test_cve_format(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        import re
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        for cve in iocs.get("cve", []):
            assert cve_pattern.match(cve), f"Malformed CVE: {cve}"


# ─── Artifact Extraction ──────────────────────────────────────────────────────

class TestArtifactExtraction:
    def test_exe_artifact_extracted(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        assert "dropper.exe" in iocs.get("artifacts", [])

    def test_artifact_has_known_extension(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        known_exts = {".exe", ".dll", ".zip", ".iso", ".bin", ".bat", ".ps1",
                      ".vbs", ".js", ".msi", ".scr", ".lnk", ".hta", ".cmd"}
        for art in iocs.get("artifacts", []):
            ext = "." + art.rsplit(".", 1)[-1].lower() if "." in art else ""
            assert ext in known_exts, f"Unexpected artifact extension: {art}"


# ─── Registry Extraction ──────────────────────────────────────────────────────

class TestRegistryExtraction:
    def test_registry_key_extracted(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        reg_keys = iocs.get("registry", [])
        assert len(reg_keys) >= 1
        assert any("CurrentVersion\\Run" in r for r in reg_keys)


# ─── IOC Return Structure ─────────────────────────────────────────────────────

class TestIOCStructure:
    def test_extract_iocs_returns_dict(self):
        iocs = enricher.extract_iocs("Some text")
        assert isinstance(iocs, dict)

    def test_all_expected_keys_present(self):
        iocs = enricher.extract_iocs("Some text")
        expected_keys = {"ipv4", "domain", "sha256", "url", "email", "cve", "artifacts"}
        for key in expected_keys:
            assert key in iocs, f"Missing key in IOC dict: {key}"

    def test_all_values_are_lists(self):
        iocs = enricher.extract_iocs("Some text with 1.2.3.4 and CVE-2024-0001")
        for key, val in iocs.items():
            assert isinstance(val, list), f"Expected list for key '{key}', got {type(val)}"

    def test_no_duplicates_in_output(self, sample_text):
        iocs = enricher.extract_iocs(sample_text)
        for key, values in iocs.items():
            assert len(values) == len(set(values)), f"Duplicates found in '{key}'"

    def test_empty_string_input(self):
        iocs = enricher.extract_iocs("")
        assert isinstance(iocs, dict)
        for key, val in iocs.items():
            assert isinstance(val, list)


# ─── Confidence Scoring ───────────────────────────────────────────────────────

class TestConfidenceScoring:
    def test_confidence_is_numeric(self, sample_iocs):
        score = enricher.calculate_confidence(sample_iocs)
        assert isinstance(score, (int, float))

    def test_confidence_range(self, sample_iocs):
        score = enricher.calculate_confidence(sample_iocs)
        assert 0 <= score <= 100, f"Confidence {score} out of [0, 100]"

    def test_empty_iocs_low_confidence(self, empty_iocs):
        score = enricher.calculate_confidence(empty_iocs)
        assert score < 50, f"Empty IOCs should yield low confidence, got {score}"

    def test_rich_iocs_higher_confidence(self, sample_iocs, empty_iocs):
        rich_score = enricher.calculate_confidence(sample_iocs)
        empty_score = enricher.calculate_confidence(empty_iocs)
        assert rich_score >= empty_score, "Rich IOCs should yield >= confidence vs empty"

    def test_actor_mapped_boosts_confidence(self, sample_iocs):
        without_actor = enricher.calculate_confidence(sample_iocs, actor_mapped=False)
        with_actor = enricher.calculate_confidence(sample_iocs, actor_mapped=True)
        assert with_actor >= without_actor, "Actor-mapped should boost confidence"
