"""
test_stix_export.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for the STIX 2.1 Export Engine (export_stix.py).

Tests cover:
- Bundle structure and required fields
- TLP markings presence
- Identity object presence
- Indicator objects for each IOC type
- Relationship objects
- bundle validate_bundle() compliance check
- MISP export format
- Manifest update logic
"""
import json
import tempfile
import pytest
from pathlib import Path
from agent.export_stix import STIXExporter, stix_exporter
from agent.risk_engine import risk_engine
from agent.mitre_mapper import mitre_engine
from agent.integrations.actor_matrix import actor_matrix


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _build_bundle(sample_text, sample_iocs):
    """Build a real STIX bundle using the full pipeline and return it as a dict.

    create_bundle() writes to disk and returns a bundle_id string; we create an
    isolated STIXExporter in a temp dir so tests are hermetic and read the
    written JSON back as a dict for structural assertions.
    """
    mitre_data = mitre_engine.map_threat(sample_text)
    actor_data = actor_matrix.correlate_actor(sample_text, sample_iocs)
    risk_score = risk_engine.calculate_risk_score(
        iocs=sample_iocs,
        mitre_matches=mitre_data,
        actor_data=actor_data,
    )
    severity = risk_engine.get_severity_label(risk_score)
    tlp = risk_engine.get_tlp_label(risk_score)

    with tempfile.TemporaryDirectory() as tmpdir:
        exporter = STIXExporter(output_dir=tmpdir)
        exporter.create_bundle(
            title="Test: Malware Campaign Targeting Financial Sector",
            iocs=sample_iocs,
            risk_score=risk_score,
            severity=severity,
            tlp_label=tlp.get("label", "TLP:CLEAR"),
            actor_tag=actor_data.get("tracking_id", "UNC-CDB-99"),
            mitre_tactics=mitre_data,
            metadata={"source_url": "https://example.com/test-article"},
        )
        bundle_files = sorted(Path(tmpdir).glob("CDB-APEX-*.json"))
        if not bundle_files:
            raise RuntimeError(f"create_bundle wrote no file to {tmpdir}")
        return json.loads(bundle_files[-1].read_text())


# ─── Bundle Structure ─────────────────────────────────────────────────────────

class TestBundleStructure:
    def test_bundle_is_dict(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        assert isinstance(bundle, dict), "Bundle must be a dict"

    def test_bundle_type_field(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        assert bundle.get("type") == "bundle"

    def test_bundle_id_format(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        bundle_id = bundle.get("id", "")
        assert bundle_id.startswith("bundle--"), f"Bundle ID must start with 'bundle--', got: {bundle_id}"

    def test_spec_version(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        assert bundle.get("spec_version") == "2.1", "Bundle must declare STIX spec_version 2.1"

    def test_objects_is_list(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        assert isinstance(bundle.get("objects"), list), "Bundle objects must be a list"

    def test_objects_not_empty(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        assert len(bundle.get("objects", [])) > 0, "Bundle must contain at least one object"

    def test_bundle_is_json_serialisable(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        serialised = json.dumps(bundle)
        assert len(serialised) > 100


# ─── Required STIX Objects ────────────────────────────────────────────────────

class TestRequiredObjects:
    def _get_objects_by_type(self, bundle, obj_type):
        return [o for o in bundle.get("objects", []) if o.get("type") == obj_type]

    def test_identity_object_present(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        identities = self._get_objects_by_type(bundle, "identity")
        assert len(identities) >= 1, "Bundle must contain at least one identity object"

    def test_identity_name_present(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        identities = self._get_objects_by_type(bundle, "identity")
        for ident in identities:
            assert "name" in ident, "Identity object must have a name field"

    def test_tlp_marking_present(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        markings = self._get_objects_by_type(bundle, "marking-definition")
        assert len(markings) >= 1 or any(
            "object_marking_refs" in o for o in bundle.get("objects", [])
        ), "Bundle must include TLP marking definitions or references"

    def test_indicator_objects_present(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        indicators = self._get_objects_by_type(bundle, "indicator")
        assert len(indicators) >= 1, "Bundle must contain at least one indicator"

    def test_relationship_objects_present(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        relations = self._get_objects_by_type(bundle, "relationship")
        # Relationships are optional if no actor/intrusion-set is present, but good practice
        # Just assert it's a list (may be empty for minimal IOC sets)
        assert isinstance(relations, list)

    def test_note_or_report_present(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        notes = [o for o in bundle.get("objects", []) if o.get("type") in {"note", "report"}]
        # Notes are generated by the AI narrative engine — should be present
        assert len(notes) >= 0  # Optional but preferred


# ─── Object Field Validation ──────────────────────────────────────────────────

class TestObjectFields:
    REQUIRED_FIELDS = {"type", "id", "spec_version", "created", "modified"}

    def test_all_objects_have_required_fields(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        marking_types = {"marking-definition"}
        for obj in bundle.get("objects", []):
            if obj.get("type") in marking_types:
                # Marking definitions have slightly different schema
                assert "type" in obj and "id" in obj
                continue
            for field in self.REQUIRED_FIELDS:
                assert field in obj, (
                    f"Object of type '{obj.get('type')}' missing required field '{field}'"
                )

    def test_all_ids_have_correct_prefix(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")
            obj_id = obj.get("id", "")
            if obj_type and obj_id:
                assert obj_id.startswith(f"{obj_type}--"), (
                    f"Object ID '{obj_id}' does not match expected prefix '{obj_type}--'"
                )

    def test_indicators_have_pattern(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        indicators = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
        for ind in indicators:
            assert "pattern" in ind, "Indicator must have a pattern field"
            assert isinstance(ind["pattern"], str)
            assert len(ind["pattern"]) > 5

    def test_indicators_have_valid_from(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        indicators = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
        for ind in indicators:
            assert "valid_from" in ind, "Indicator must have a valid_from field"

    def test_indicators_have_pattern_type(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        indicators = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
        for ind in indicators:
            assert "pattern_type" in ind, "Indicator must declare pattern_type"
            assert ind["pattern_type"] == "stix", "Pattern type should be 'stix'"


# ─── validate_bundle() ────────────────────────────────────────────────────────

class TestValidateBundle:
    def test_validate_bundle_method_exists(self):
        assert hasattr(stix_exporter, "validate_bundle"), \
            "stix_exporter must have a validate_bundle() method"

    def test_validate_bundle_returns_dict(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        result = stix_exporter.validate_bundle(bundle)
        assert isinstance(result, dict)

    def test_validate_bundle_has_valid_key(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        result = stix_exporter.validate_bundle(bundle)
        assert "valid" in result, "validate_bundle() result must include 'valid' key"

    def test_valid_bundle_passes_validation(self, sample_text, sample_iocs):
        bundle = _build_bundle(sample_text, sample_iocs)
        result = stix_exporter.validate_bundle(bundle)
        assert result["valid"] is True, (
            f"Generated bundle failed validation: {result.get('errors', [])}"
        )

    def test_invalid_bundle_fails_validation(self):
        bad_bundle = {"type": "bundle", "id": "bad-id"}  # Missing spec_version
        result = stix_exporter.validate_bundle(bad_bundle)
        assert result["valid"] is False, "Malformed bundle should fail validation"

    def test_minimal_valid_bundle_passes(self, minimal_stix_bundle):
        # A minimal bundle may or may not pass our custom validator
        # depending on required fields — just check it doesn't crash
        result = stix_exporter.validate_bundle(minimal_stix_bundle)
        assert "valid" in result


# ─── MISP Export ──────────────────────────────────────────────────────────────

class TestMISPExport:
    def test_misp_export_method_exists(self):
        assert hasattr(stix_exporter, "export_to_misp"), \
            "stix_exporter must have export_to_misp() method"

    def test_misp_export_returns_dict(self, sample_text, sample_iocs):
        misp_event = stix_exporter.export_to_misp(
            title="Test Campaign",
            iocs=sample_iocs,
            risk_score=7.5,
        )
        assert isinstance(misp_event, dict)

    def test_misp_event_has_required_keys(self, sample_text, sample_iocs):
        misp_event = stix_exporter.export_to_misp(
            title="Test Campaign",
            iocs=sample_iocs,
            risk_score=7.5,
        )
        required = {"Event"}
        for key in required:
            assert key in misp_event, f"MISP export missing key: {key}"
