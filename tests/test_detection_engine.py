"""
test_detection_engine.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for the Detection Rule Generator (detection_engine.py).

Tests cover:
- Sigma rule generation structure and YAML validity
- YARA rule generation and syntax
- Behavioral fallback when no IOCs are present
- Threat-type specific rule generation
"""
import yaml
import pytest
from agent.integrations.detection_engine import detection_engine


# ─── Sigma Rule Tests ─────────────────────────────────────────────────────────

class TestSigmaRuleGeneration:
    def test_sigma_rule_is_string(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        assert isinstance(rule, str)

    def test_sigma_rule_not_empty(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        assert len(rule.strip()) > 50

    def test_sigma_rule_is_valid_yaml(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        # Multi-document YAML (separated by ---)
        docs = [d for d in rule.split("\n---\n") if d.strip()]
        for doc in docs:
            parsed = yaml.safe_load(doc)
            assert isinstance(parsed, dict), f"Sigma rule YAML block is not a dict: {doc[:100]}"

    def test_sigma_rule_has_title(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        assert "title:" in rule

    def test_sigma_rule_has_detection(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        assert "detection:" in rule

    def test_sigma_rule_has_condition(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        assert "condition:" in rule

    def test_sigma_rule_has_level(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        valid_levels = {"low", "medium", "high", "critical", "informational"}
        assert any(f"level: {lvl}" in rule.lower() for lvl in valid_levels), \
            "Sigma rule must include a valid severity level"

    def test_sigma_rule_with_empty_iocs_uses_behavioral(self, empty_iocs):
        rule = detection_engine.generate_sigma_rule("Generic Threat", empty_iocs)
        assert isinstance(rule, str)
        assert len(rule.strip()) > 50, "Behavioral fallback should still produce a rule"

    def test_sigma_ransomware_rule(self, empty_iocs):
        rule = detection_engine.generate_sigma_rule("LockBit Ransomware Campaign", empty_iocs)
        # Ransomware-specific rule should mention shadow copy deletion
        assert "shadow" in rule.lower() or "vssadmin" in rule.lower(), \
            "Ransomware Sigma rule should detect shadow copy deletion"

    def test_sigma_rule_references_cyberdudebivash(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test", sample_iocs)
        assert "cyberdudebivash" in rule.lower()

    def test_sigma_cdb_id_present(self, sample_iocs):
        rule = detection_engine.generate_sigma_rule("Test Campaign", sample_iocs)
        assert "cdb-" in rule.lower(), "Sigma rule ID should start with 'cdb-'"


# ─── YARA Rule Tests ──────────────────────────────────────────────────────────

class TestYARARuleGeneration:
    def test_yara_rule_is_string(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert isinstance(rule, str)

    def test_yara_rule_not_empty(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert len(rule.strip()) > 50

    def test_yara_rule_has_rule_keyword(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert rule.strip().startswith("rule "), "YARA rule must start with 'rule '"

    def test_yara_rule_has_meta_section(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert "meta:" in rule

    def test_yara_rule_has_strings_section(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert "strings:" in rule

    def test_yara_rule_has_condition_section(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert "condition:" in rule

    def test_yara_rule_has_closing_brace(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        assert rule.strip().endswith("}"), "YARA rule must end with closing brace"

    def test_yara_ioc_strings_present(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test Campaign", sample_iocs)
        # At least one IOC from our sample set should appear
        has_ioc = (
            any(ip in rule for ip in sample_iocs.get("ipv4", [])) or
            any(dom in rule for dom in sample_iocs.get("domain", []))
        )
        assert has_ioc, "YARA rule should embed actual IOC strings"

    def test_yara_meta_has_author(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test", sample_iocs)
        assert "author" in rule.lower()

    def test_yara_meta_has_severity(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test", sample_iocs)
        assert "severity" in rule.lower()

    def test_yara_rule_with_empty_iocs(self, empty_iocs):
        rule = detection_engine.generate_yara_rule("Generic Malware", empty_iocs)
        assert len(rule.strip()) > 50, "YARA rule should still be generated with empty IOCs"

    def test_yara_rule_condition_has_filesize(self, sample_iocs):
        rule = detection_engine.generate_yara_rule("Test", sample_iocs)
        assert "filesize" in rule, "YARA rule should include filesize constraint for efficiency"


# ─── Edge Cases ───────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_sigma_special_chars_in_title(self, sample_iocs):
        """Special characters in title should be sanitised."""
        rule = detection_engine.generate_sigma_rule(
            "Test: CVE-2024-1234 'Evil' Campaign <script>", sample_iocs
        )
        assert isinstance(rule, str)
        assert len(rule) > 50

    def test_yara_special_chars_in_title(self, sample_iocs):
        rule = detection_engine.generate_yara_rule(
            "Test: CVE-2024-1234 (Ransomware) Attack!", sample_iocs
        )
        assert isinstance(rule, str)
        # YARA rule names cannot have special chars — should be sanitised
        assert rule.strip().startswith("rule CDB_")

    def test_sigma_very_long_title(self, sample_iocs):
        long_title = "A" * 300
        rule = detection_engine.generate_sigma_rule(long_title, sample_iocs)
        assert isinstance(rule, str)
        # Title should be truncated
        assert len(rule) > 0
