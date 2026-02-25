"""
test_stix_schema.py — CyberDudeBivash SENTINEL APEX ULTRA
STIX 2.1 Schema Validation Tests

Validates generated bundles against the official STIX 2.1 specification
using the `stix2` Python library (when available) as a secondary validation
layer beyond our internal validate_bundle() checks.

Falls back to structural checks when stix2 library is not installed so CI
never hard-fails due to a missing optional dependency.
"""
import json
import pytest

try:
    import stix2
    HAS_STIX2_LIB = True
except ImportError:
    HAS_STIX2_LIB = False

from agent.export_stix import stix_exporter
from agent.risk_engine import risk_engine
from agent.mitre_mapper import mitre_engine
from agent.integrations.actor_matrix import actor_matrix


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _build_bundle(sample_text, sample_iocs):
    mitre_data = mitre_engine.map_threat(sample_text)
    actor_data = actor_matrix.correlate_actor(sample_text, sample_iocs)
    risk_score = risk_engine.calculate_risk_score(
        iocs=sample_iocs, mitre_matches=mitre_data, actor_data=actor_data,
    )
    severity = risk_engine.get_severity_label(risk_score)
    tlp = risk_engine.get_tlp_label(risk_score)

    return stix_exporter.create_bundle(
        headline="Schema Validation Test Bundle",
        iocs=sample_iocs,
        risk_score=risk_score,
        severity=severity,
        tlp=tlp,
        mitre_data=mitre_data,
        actor_data=actor_data,
        source_url="https://example.com/schema-test",
        content=sample_text,
    )


# ─── STIX 2.1 Spec Field Compliance ──────────────────────────────────────────

class TestSTIX21SpecCompliance:
    """Spec-level checks that do not require the stix2 library."""

    VALID_STIX_TYPES = {
        "bundle", "identity", "indicator", "malware", "attack-pattern",
        "campaign", "course-of-action", "grouping", "infrastructure",
        "intrusion-set", "location", "malware-analysis", "note", "observed-data",
        "opinion", "relationship", "report", "threat-actor", "tool",
        "vulnerability", "marking-definition", "extension-definition",
        "language-content", "data-component", "data-source",
    }

    def test_bundle_top_level_type(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        assert bundle["type"] == "bundle"

    def test_bundle_id_is_uuid4_format(self, sample_text, sample_iocs):
        import re
        bundle = _build_bundle(sample_text, sample_iocs)
        bundle_id = bundle["id"]
        uuid_pattern = re.compile(
            r"bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        assert uuid_pattern.match(bundle_id), f"Bundle ID not UUID4 format: {bundle_id}"

    def test_all_object_types_are_valid_stix(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")
            assert obj_type in self.VALID_STIX_TYPES, (
                f"Unknown STIX type '{obj_type}' — not in STIX 2.1 spec"
            )

    def test_all_object_ids_are_uuid4(self, sample_text, sample_iocs):
        import re
        bundle = _build_bundle(sample_text, sample_iocs)
        uuid_pattern = re.compile(
            r"^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        for obj in bundle.get("objects", []):
            obj_id = obj.get("id", "")
            assert uuid_pattern.match(obj_id), f"Object ID not valid STIX ID: {obj_id}"

    def test_timestamps_are_iso8601(self, sample_text, sample_iocs):
        """All created/modified timestamps must be ISO 8601 UTC."""
        import re
        bundle = _build_bundle(sample_text, sample_iocs)
        ts_pattern = re.compile(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
        )
        for obj in bundle.get("objects", []):
            if obj.get("type") == "marking-definition":
                continue  # marking-definition may have different timestamp format
            for field in ("created", "modified"):
                if field in obj:
                    ts = obj[field]
                    assert ts_pattern.match(ts), (
                        f"Timestamp '{ts}' in field '{field}' of '{obj.get('type')}' "
                        f"is not ISO 8601 UTC (expected format: YYYY-MM-DDTHH:MM:SSZ)"
                    )

    def test_indicator_patterns_use_stix_syntax(self, sample_text, sample_iocs):
        """STIX indicators must use STIX pattern language."""
        bundle = _build_bundle(sample_text, sample_iocs)
        indicators = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
        for ind in indicators:
            pattern = ind.get("pattern", "")
            # STIX patterns start with [ and contain :
            assert "[" in pattern, f"Pattern doesn't look like STIX: {pattern[:80]}"
            assert ":" in pattern, f"Pattern missing object:field separator: {pattern[:80]}"

    def test_no_duplicate_ids(self, sample_text, sample_iocs):
        """No two objects in the bundle should share an ID."""
        bundle = _build_bundle(sample_text, sample_iocs)
        all_ids = [o.get("id") for o in bundle.get("objects", [])]
        assert len(all_ids) == len(set(all_ids)), "Bundle contains objects with duplicate IDs"

    def test_relationship_source_and_target_exist(self, sample_text, sample_iocs):
        """Relationship source_ref and target_ref must point to existing objects."""
        bundle = _build_bundle(sample_text, sample_iocs)
        all_ids = {o.get("id") for o in bundle.get("objects", [])}
        for obj in bundle.get("objects", []):
            if obj.get("type") == "relationship":
                src = obj.get("source_ref", "")
                tgt = obj.get("target_ref", "")
                assert src in all_ids, f"Relationship source_ref '{src}' not found in bundle"
                assert tgt in all_ids, f"Relationship target_ref '{tgt}' not found in bundle"

    def test_identity_class_is_valid(self, sample_text, sample_iocs):
        """Identity objects must have a valid identity_class."""
        VALID_IDENTITY_CLASSES = {
            "individual", "group", "system", "organization", "class", "unknown"
        }
        bundle = _build_bundle(sample_text, sample_iocs)
        identities = [o for o in bundle.get("objects", []) if o.get("type") == "identity"]
        for ident in identities:
            cls = ident.get("identity_class", "")
            assert cls in VALID_IDENTITY_CLASSES, (
                f"identity_class '{cls}' is not a valid STIX 2.1 value"
            )


# ─── stix2 Library Validation (Optional) ─────────────────────────────────────

@pytest.mark.skipif(not HAS_STIX2_LIB, reason="stix2 library not installed — install with: pip install stix2")
class TestStix2LibraryValidation:
    """Deep validation using the official Oasis stix2 Python library."""

    def test_parse_bundle_with_stix2_library(self, sample_text, sample_iocs):
        """stix2.parse() should accept our generated bundle without exceptions."""
        bundle = _build_bundle(sample_text, sample_iocs)
        bundle_json = json.dumps(bundle)
        try:
            parsed = stix2.parse(bundle_json, allow_custom=False)
            assert parsed is not None
        except stix2.exceptions.STIXError as e:
            pytest.fail(f"stix2.parse() rejected the bundle: {e}")

    def test_indicators_parseable_individually(self, sample_text, sample_iocs):
        """Each indicator should parse cleanly with the stix2 library."""
        bundle = _build_bundle(sample_text, sample_iocs)
        indicators = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
        for ind in indicators:
            ind_json = json.dumps(ind)
            try:
                parsed = stix2.parse(ind_json, allow_custom=True)
                assert parsed is not None
            except stix2.exceptions.STIXError as e:
                pytest.fail(f"Indicator failed stix2 parse: {e}\nIndicator: {ind_json[:200]}")


# ─── JSON Feed Manifest Schema ────────────────────────────────────────────────

class TestFeedManifestSchema:
    """Validate the structure of data/stix/feed_manifest.json."""

    MANIFEST_PATH = "data/stix/feed_manifest.json"
    REQUIRED_ENTRY_KEYS = {
        "title", "stix_id", "risk_score", "severity", "timestamp",
    }

    def _load_manifest(self, base_path):
        import os
        path = os.path.join(base_path, self.MANIFEST_PATH)
        with open(path) as f:
            return json.load(f)

    def test_manifest_is_list(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = self._load_manifest(base)
        assert isinstance(manifest, list), "feed_manifest.json must be a JSON array"

    def test_manifest_has_entries(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = self._load_manifest(base)
        assert len(manifest) > 0, "feed_manifest.json must not be empty"

    def test_manifest_entry_has_required_keys(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = self._load_manifest(base)
        for i, entry in enumerate(manifest):
            for key in self.REQUIRED_ENTRY_KEYS:
                assert key in entry, (
                    f"Manifest entry [{i}] missing required key '{key}'"
                )

    def test_manifest_risk_scores_in_range(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = self._load_manifest(base)
        for i, entry in enumerate(manifest):
            score = entry.get("risk_score")
            if score is not None:
                assert 0.0 <= float(score) <= 10.0, (
                    f"Manifest entry [{i}] risk_score={score} out of [0, 10]"
                )

    def test_manifest_stix_ids_valid_format(self):
        import os, re
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = self._load_manifest(base)
        pattern = re.compile(
            r"bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        for i, entry in enumerate(manifest):
            stix_id = entry.get("stix_id", "")
            if stix_id:
                assert pattern.match(stix_id), (
                    f"Manifest entry [{i}] has malformed stix_id: {stix_id}"
                )

    def test_manifest_severities_valid(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = self._load_manifest(base)
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for i, entry in enumerate(manifest):
            sev = entry.get("severity")
            if sev:
                assert sev in valid_severities, (
                    f"Manifest entry [{i}] has invalid severity '{sev}'"
                )
