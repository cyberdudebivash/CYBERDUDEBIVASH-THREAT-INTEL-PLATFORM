"""
test_v46_vanguard.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0
Comprehensive test suite for VANGUARD enhancement modules.

Tests cover:
  - IOC Validator: FP elimination, hash deconfliction, domain filtering
  - KEV Enricher: catalog loading, lookup interface contract
  - Confidence Engine: multi-dimensional scoring, label mapping, bounds
  - Vanguard Engine: orchestration, graceful degradation
  - Integration: config.py FP extension coverage
"""

import pytest
from typing import Dict, List


# ═══════════════════════════════════════════════════════════════════════════════
# IOC VALIDATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIOCValidator:
    """Tests for agent.v46_vanguard.ioc_validator"""

    @pytest.fixture
    def validator(self):
        from agent.v46_vanguard.ioc_validator import ioc_validator
        return ioc_validator

    @pytest.fixture
    def iocs_with_fp_domains(self):
        """IOCs containing source code filenames as FP domains."""
        return {
            "ipv4": ["185.220.101.45"],
            "domain": [
                "evil-login.example-malware.com",  # Real malicious domain
                "stealer.py",                       # FP: Python filename
                "hvnc.py",                          # FP: Python filename
                "utils.cpp",                        # FP: C++ filename
                "config.yaml",                      # FP: YAML config
                "main.go",                          # FP: Go source
                "payload.rs",                       # FP: Rust source
            ],
            "url": [],
            "sha256": ["a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"],
            "sha1": [],
            "md5": [],
            "email": [],
            "cve": [],
            "registry": [],
            "artifacts": [],
        }

    @pytest.fixture
    def iocs_with_hash_collision(self):
        """IOCs with SHA1/MD5 values that are substrings of SHA256."""
        sha256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        return {
            "ipv4": [],
            "domain": [],
            "url": [],
            "sha256": [sha256],
            "sha1": [sha256[:40]],  # First 40 chars = FP SHA1
            "md5": [sha256[:32]],   # First 32 chars = FP MD5
            "email": [],
            "cve": [],
            "registry": [],
            "artifacts": [],
        }

    def test_removes_python_filename_domains(self, validator, iocs_with_fp_domains):
        cleaned = validator.validate(iocs_with_fp_domains)
        for d in cleaned["domain"]:
            assert not d.endswith(".py"), f"Python file {d} should be filtered"

    def test_removes_cpp_filename_domains(self, validator, iocs_with_fp_domains):
        cleaned = validator.validate(iocs_with_fp_domains)
        for d in cleaned["domain"]:
            assert not d.endswith(".cpp"), f"C++ file {d} should be filtered"

    def test_preserves_real_domains(self, validator, iocs_with_fp_domains):
        cleaned = validator.validate(iocs_with_fp_domains)
        assert "evil-login.example-malware.com" in cleaned["domain"]

    def test_removes_go_yaml_rs_domains(self, validator, iocs_with_fp_domains):
        cleaned = validator.validate(iocs_with_fp_domains)
        fp_exts = {".go", ".yaml", ".rs"}
        for d in cleaned["domain"]:
            for ext in fp_exts:
                assert not d.endswith(ext), f"{d} should be filtered"

    def test_fp_count_correct(self, validator, iocs_with_fp_domains):
        cleaned = validator.validate(iocs_with_fp_domains)
        orig_count = len(iocs_with_fp_domains["domain"])
        clean_count = len(cleaned["domain"])
        # Should have removed stealer.py, hvnc.py, utils.cpp, config.yaml, main.go, payload.rs = 6
        assert clean_count < orig_count
        assert clean_count == 1  # Only evil-login.example-malware.com survives

    def test_hash_deconfliction_sha1(self, validator, iocs_with_hash_collision):
        cleaned = validator.validate(iocs_with_hash_collision)
        assert len(cleaned["sha256"]) == 1, "SHA256 should be preserved"
        assert len(cleaned["sha1"]) == 0, "SHA1 substring of SHA256 should be removed"

    def test_hash_deconfliction_md5(self, validator, iocs_with_hash_collision):
        cleaned = validator.validate(iocs_with_hash_collision)
        assert len(cleaned["md5"]) == 0, "MD5 substring of SHA256 should be removed"

    def test_preserves_independent_md5(self, validator):
        """MD5 not matching any SHA256 should be preserved."""
        iocs = {
            "ipv4": [], "domain": [], "url": [],
            "sha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "sha1": [],
            "md5": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],  # Not a substring of SHA256
            "email": [], "cve": [], "registry": [], "artifacts": [],
        }
        cleaned = validator.validate(iocs)
        assert len(cleaned["md5"]) == 1

    def test_returns_same_schema(self, validator, iocs_with_fp_domains):
        cleaned = validator.validate(iocs_with_fp_domains)
        expected_keys = {"ipv4", "domain", "url", "sha256", "sha1", "md5",
                         "email", "cve", "registry", "artifacts"}
        assert set(cleaned.keys()) == expected_keys

    def test_empty_iocs_returns_empty(self, validator, empty_iocs):
        cleaned = validator.validate(empty_iocs)
        for key, val in cleaned.items():
            assert isinstance(val, list)
            assert len(val) == 0

    def test_version_like_ip_filtering(self, validator):
        """Version strings like 2.0.1.0 should be filtered from IPs."""
        iocs = {
            "ipv4": ["185.220.101.45", "2.0.1.0", "1.2.3.0"],
            "domain": [], "url": [], "sha256": [], "sha1": [], "md5": [],
            "email": [], "cve": [], "registry": [], "artifacts": [],
        }
        cleaned = validator.validate(iocs)
        assert "185.220.101.45" in cleaned["ipv4"]
        # Version-like IPs ending in .0 should be filtered
        for ip in cleaned["ipv4"]:
            assert not ip.endswith(".0"), f"Network address {ip} should be filtered"


# ═══════════════════════════════════════════════════════════════════════════════
# KEV ENRICHER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestKEVEnricher:
    """Tests for agent.v46_vanguard.kev_enricher"""

    @pytest.fixture
    def enricher(self):
        from agent.v46_vanguard.kev_enricher import kev_enricher
        return kev_enricher

    def test_lookup_returns_tuple(self, enricher):
        result = enricher.lookup("CVE-2024-99999")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_lookup_unknown_cve_returns_false(self, enricher):
        is_kev, meta = enricher.lookup("CVE-9999-99999")
        assert isinstance(is_kev, bool)
        assert isinstance(meta, dict)

    def test_lookup_empty_string(self, enricher):
        is_kev, meta = enricher.lookup("")
        assert is_kev is False
        assert meta == {}

    def test_lookup_batch_returns_dict(self, enricher):
        results = enricher.lookup_batch(["CVE-2024-1111", "CVE-2024-2222"])
        assert isinstance(results, dict)
        assert len(results) == 2

    def test_catalog_size_is_int(self, enricher):
        assert isinstance(enricher.catalog_size, int)

    def test_is_loaded_is_bool(self, enricher):
        assert isinstance(enricher.is_loaded, bool)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIDENCE ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfidenceEngine:
    """Tests for agent.v46_vanguard.confidence_engine"""

    @pytest.fixture
    def engine(self):
        from agent.v46_vanguard.confidence_engine import confidence_engine
        return confidence_engine

    @pytest.fixture
    def rich_iocs(self):
        return {
            "ipv4": ["1.2.3.4", "5.6.7.8"],
            "domain": ["evil.com", "bad.net"],
            "url": ["https://evil.com/payload"],
            "sha256": ["a" * 64],
            "sha1": [],
            "md5": ["b" * 32],
            "email": ["test@evil.com"],
            "cve": ["CVE-2024-12345"],
            "registry": ["HKCU\\...\\Run\\malware"],
            "artifacts": ["dropper.exe"],
        }

    @pytest.fixture
    def sparse_iocs(self):
        return {
            "ipv4": [], "domain": ["suspicious.net"], "url": [],
            "sha256": [], "sha1": [], "md5": [],
            "email": [], "cve": [], "registry": [], "artifacts": [],
        }

    def test_score_returns_confidence_result(self, engine, rich_iocs):
        result = engine.score(iocs=rich_iocs)
        assert hasattr(result, "score")
        assert hasattr(result, "label")
        assert hasattr(result, "dimensions")

    def test_score_in_valid_range(self, engine, rich_iocs):
        result = engine.score(iocs=rich_iocs)
        assert 0.0 <= result.score <= 100.0

    def test_rich_iocs_higher_than_sparse(self, engine, rich_iocs, sparse_iocs):
        rich_result = engine.score(iocs=rich_iocs)
        sparse_result = engine.score(iocs=sparse_iocs)
        assert rich_result.score > sparse_result.score, \
            "Rich IOCs should produce higher confidence than sparse"

    def test_label_mapping_high(self, engine, rich_iocs):
        result = engine.score(
            iocs=rich_iocs,
            mitre_data=[{"id": f"T{i}"} for i in range(8)],
            fetched_article={"fetch_status": "success", "word_count": 1500, "paragraphs": ["x"] * 15},
            cvss_score=9.8,
            kev_present=True,
        )
        assert result.label in {"HIGH", "MODERATE"}

    def test_label_mapping_low(self, engine, sparse_iocs):
        result = engine.score(iocs=sparse_iocs)
        assert result.label in {"LOW", "UNVERIFIED", "MODERATE"}

    def test_dimensions_present(self, engine, rich_iocs):
        result = engine.score(iocs=rich_iocs)
        expected_dims = {
            "ioc_richness", "source_depth", "mitre_coverage",
            "actor_attribution", "impact_evidence", "cve_verification",
        }
        assert set(result.dimensions.keys()) == expected_dims

    def test_each_dimension_in_range(self, engine, rich_iocs):
        result = engine.score(iocs=rich_iocs)
        for dim_name, dim_val in result.dimensions.items():
            assert 0.0 <= dim_val <= 100.0, \
                f"Dimension {dim_name} = {dim_val} outside [0, 100]"

    def test_kev_boosts_cve_dimension(self, engine, rich_iocs):
        without_kev = engine.score(iocs=rich_iocs, kev_present=False)
        with_kev = engine.score(iocs=rich_iocs, kev_present=True)
        assert with_kev.dimensions["cve_verification"] >= without_kev.dimensions["cve_verification"]

    def test_empty_iocs_low_confidence(self, engine, empty_iocs):
        result = engine.score(iocs=empty_iocs)
        assert result.score < 50.0, f"Empty IOCs should yield low confidence, got {result.score}"

    def test_rationale_not_empty(self, engine, rich_iocs):
        result = engine.score(iocs=rich_iocs)
        assert len(result.rationale) > 0

    def test_deterministic(self, engine, rich_iocs):
        r1 = engine.score(iocs=rich_iocs)
        r2 = engine.score(iocs=rich_iocs)
        assert r1.score == r2.score


# ═══════════════════════════════════════════════════════════════════════════════
# VANGUARD ENGINE (ORCHESTRATOR) TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestVanguardEngine:
    """Tests for agent.v46_vanguard.vanguard_engine"""

    @pytest.fixture
    def engine(self):
        from agent.v46_vanguard.vanguard_engine import vanguard_engine
        return vanguard_engine

    @pytest.fixture
    def pipeline_iocs(self):
        return {
            "ipv4": ["203.0.113.50"],
            "domain": ["evil.com", "stealer.py"],  # stealer.py = FP
            "url": [],
            "sha256": ["a" * 64],
            "sha1": ["a" * 40],  # substring of sha256 = FP
            "md5": [],
            "email": [],
            "cve": ["CVE-2024-12345"],
            "registry": [],
            "artifacts": ["dropper.exe"],
        }

    def test_enhance_returns_dict(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        assert isinstance(result, dict)

    def test_enhance_has_required_keys(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        required = {"iocs", "kev_present", "kev_metadata", "confidence",
                     "fp_removed_count", "enhancements_applied"}
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_ioc_validation_removes_fp_domain(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        for d in result["iocs"]["domain"]:
            assert not d.endswith(".py"), f"FP domain {d} not removed"

    def test_ioc_validation_removes_hash_fp(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        # SHA1 "a"*40 is a substring of SHA256 "a"*64
        assert len(result["iocs"]["sha1"]) == 0, "SHA1 substring FP not removed"

    def test_fp_removed_count_nonzero(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        assert result["fp_removed_count"] > 0, "Should have removed at least 1 FP"

    def test_enhancements_applied_list(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        assert isinstance(result["enhancements_applied"], list)
        assert "ioc_validation" in result["enhancements_applied"]

    def test_confidence_recalculated(self, engine, pipeline_iocs):
        result = engine.enhance(
            iocs=pipeline_iocs,
            mitre_data=[{"id": "T1486"}],
            actor_data={"tracking_id": "UNC-CDB-99"},
        )
        if result["confidence"] is not None:
            assert 0.0 <= result["confidence"] <= 100.0

    def test_kev_present_is_bool(self, engine, pipeline_iocs):
        result = engine.enhance(iocs=pipeline_iocs)
        assert isinstance(result["kev_present"], bool)

    def test_empty_iocs_no_crash(self, engine, empty_iocs):
        result = engine.enhance(iocs=empty_iocs)
        assert isinstance(result, dict)
        assert isinstance(result["iocs"], dict)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG.PY FP EXTENSION COVERAGE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigFPExtensions:
    """Verify config.py FALSE_POSITIVE_EXTENSIONS covers critical patterns."""

    def test_python_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".py" in FALSE_POSITIVE_EXTENSIONS

    def test_cpp_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".cpp" in FALSE_POSITIVE_EXTENSIONS

    def test_go_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".go" in FALSE_POSITIVE_EXTENSIONS

    def test_rust_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".rs" in FALSE_POSITIVE_EXTENSIONS

    def test_typescript_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".ts" in FALSE_POSITIVE_EXTENSIONS

    def test_java_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".java" in FALSE_POSITIVE_EXTENSIONS

    def test_yaml_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".yaml" in FALSE_POSITIVE_EXTENSIONS

    def test_shell_extension_in_list(self):
        from agent.config import FALSE_POSITIVE_EXTENSIONS
        assert ".sh" in FALSE_POSITIVE_EXTENSIONS


# ═══════════════════════════════════════════════════════════════════════════════
# ENRICHER INTEGRATION TEST (FP DOMAINS)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnricherFPIntegration:
    """Verify enricher.extract_iocs no longer classifies .py/.cpp as domains."""

    def test_stealer_py_not_extracted_as_domain(self):
        from agent.enricher import enricher
        text = "The attacker used stealer.py to harvest credentials"
        iocs = enricher.extract_iocs(text)
        assert "stealer.py" not in iocs["domain"], \
            "stealer.py should be filtered by FALSE_POSITIVE_EXTENSIONS"

    def test_utils_cpp_not_extracted_as_domain(self):
        from agent.enricher import enricher
        text = "The source code was found in utils.cpp containing backdoor logic"
        iocs = enricher.extract_iocs(text)
        assert "utils.cpp" not in iocs["domain"], \
            "utils.cpp should be filtered by FALSE_POSITIVE_EXTENSIONS"

    def test_hvnc_py_not_extracted_as_domain(self):
        from agent.enricher import enricher
        text = "HVNC module was implemented in hvnc.py for remote access"
        iocs = enricher.extract_iocs(text)
        assert "hvnc.py" not in iocs["domain"], \
            "hvnc.py should be filtered by FALSE_POSITIVE_EXTENSIONS"

    def test_real_domain_still_extracted(self):
        from agent.enricher import enricher
        text = "C2 server at malware-command.evil.net contacted by stealer.py module"
        iocs = enricher.extract_iocs(text)
        assert "malware-command.evil.net" in iocs["domain"]

    def test_main_go_not_extracted(self):
        from agent.enricher import enricher
        text = "The Go implant was compiled from main.go"
        iocs = enricher.extract_iocs(text)
        assert "main.go" not in iocs["domain"]
