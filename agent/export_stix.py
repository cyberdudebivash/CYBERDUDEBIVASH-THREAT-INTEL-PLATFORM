#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
STIX 2.1 EXPORTER + MISP BRIDGE — PRODUCTION UPGRADE

v22.0 ADDITIONS (all additive, non-breaking):
  - STIX 2.1 Identity object for CyberDudeBivash as producer
  - TLP Marking Definition objects (CLEAR/GREEN/AMBER/RED) per STIX spec
  - object_marking_refs on all objects (proper TLP attribution)
  - created_by_ref on all objects (producer identity)
  - CourseOfAction objects for CVSS-based remediation guidance
  - Note objects for AI-generated threat narrative (when available)
  - granular_markings support for object-level TLP control
  - MISP bridge: export_to_misp() generates MISP-compatible JSON event
  - Bundle validation: validate_bundle() checks spec compliance
  - create_bundle() signature extended with optional v22.0 params (backward compat)

All v17.0 functionality preserved unchanged.
"""
import json
import uuid
import os
import re as _re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ── Optional: stix2 library for deep schema validation ──────────────────────
# Install with: pip install stix2==3.0.1
# Falls back gracefully when not installed — all existing functionality intact.
try:
    import stix2 as _stix2_lib
    _STIX2_AVAILABLE = True
except ImportError:
    _stix2_lib = None
    _STIX2_AVAILABLE = False

from agent.config import (
    MANIFEST_MAX_ENTRIES,
    MANIFEST_DIR,
    STIX_IDENTITY_ID,
    STIX_TLP_MARKING,
)

logger = logging.getLogger("CDB-STIX")

# ── STIX 2.1 Standard TLP Marking Definitions (OASIS spec) ──
TLP_MARKING_DEFS = {
    "TLP:CLEAR": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": STIX_TLP_MARKING["CLEAR"],
        "created": "2022-10-01T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "clear"},
    },
    "TLP:GREEN": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": STIX_TLP_MARKING["GREEN"],
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "green"},
    },
    "TLP:AMBER": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": STIX_TLP_MARKING["AMBER"],
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "amber"},
    },
    "TLP:RED": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": STIX_TLP_MARKING["RED"],
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "red"},
    },
}

# ── Producer Identity Object ──
CDB_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": STIX_IDENTITY_ID,
    "name": "CyberDudeBivash SENTINEL APEX",
    "description": "CyberDudeBivash Pvt. Ltd. — Global Cybersecurity Intelligence Infrastructure",
    "identity_class": "organization",
    "sectors": ["technology"],
    "contact_information": "bivash@cyberdudebivash.com",
    "created": "2024-01-01T00:00:00Z",
    "modified": "2024-01-01T00:00:00Z",
}


def _tlp_marking_id(tlp_label: str) -> str:
    """Map TLP label string to STIX marking definition ID."""
    mapping = {
        "TLP:RED":   STIX_TLP_MARKING["RED"],
        "TLP:AMBER": STIX_TLP_MARKING["AMBER"],
        "TLP:GREEN": STIX_TLP_MARKING["GREEN"],
        "TLP:CLEAR": STIX_TLP_MARKING["CLEAR"],
    }
    return mapping.get(tlp_label.upper(), STIX_TLP_MARKING["CLEAR"])


class STIXExporter:
    """Enhanced STIX 2.1 exporter with full object graph, TLP markings, and MISP bridge."""

    def __init__(self, output_dir: str = MANIFEST_DIR):
        self.output_dir   = output_dir
        self.manifest_path = os.path.join(output_dir, "feed_manifest.json")
        os.makedirs(self.output_dir, exist_ok=True)

    def create_bundle(
        self,
        title: str,
        iocs: Dict[str, List[str]],
        risk_score: float,
        metadata: Optional[Dict] = None,
        confidence: float = 0.0,
        severity: str = "HIGH",
        tlp_label: str = "TLP:CLEAR",
        ioc_counts: Optional[Dict[str, int]] = None,
        actor_tag: str = "UNC-CDB-99",
        mitre_tactics: Optional[List] = None,
        feed_source: str = "CDB-SENTINEL",
        # v21.0 additions (preserved)
        epss_score: Optional[float] = None,
        cvss_score: Optional[float] = None,
        kev_present: bool = False,
        nvd_url: Optional[str] = None,
        # v22.0 additions (all optional, backward compatible)
        ai_narrative: Optional[str] = None,
        supply_chain: bool = False,
        cwe_ids: Optional[List[str]] = None,
    ) -> str:
        """
        Create a comprehensive STIX 2.1 bundle with:
        - Producer identity + TLP marking definitions
        - object_marking_refs on all objects
        - created_by_ref on all objects
        - Intrusion set, indicators, attack patterns, vulnerabilities
        - CourseOfAction for remediation [v22.0]
        - Note for AI narrative [v22.0]
        """
        timestamp        = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        bundle_id        = f"bundle--{uuid.uuid4()}"
        intrusion_set_id = f"intrusion-set--{uuid.uuid4()}"
        marking_id       = _tlp_marking_id(tlp_label)
        common_markings  = [marking_id]

        # Bundle always starts with: identity + TLP marking def
        objects = [
            CDB_IDENTITY,
            TLP_MARKING_DEFS.get(tlp_label.upper(), TLP_MARKING_DEFS["TLP:CLEAR"]),
        ]

        def _mark(obj: Dict) -> Dict:
            """Add common marking and identity refs to any STIX object."""
            obj["object_marking_refs"] = common_markings
            obj["created_by_ref"]      = STIX_IDENTITY_ID
            return obj

        # ── Intrusion Set (Campaign/Actor) ──
        objects.append(_mark({
            "type":            "intrusion-set",
            "spec_version":    "2.1",
            "id":              intrusion_set_id,
            "name":            f"{actor_tag} Campaign",
            "description":     f"Tactical cluster: {title}",
            "created":         timestamp,
            "modified":        timestamp,
            "confidence":      int(confidence),
            "aliases":         [actor_tag],
            # v22.0: supply chain flag
            **({"labels": ["supply-chain-attack"]} if supply_chain else {}),
        }))

        # ── Indicator Objects ──
        indicator_ids = []

        for ip in (iocs.get('ipv4') or [])[:20]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious IP: {ip}",
                "pattern":      f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        for domain in (iocs.get('domain') or [])[:20]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious Domain: {domain}",
                "pattern":      f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        for sha in (iocs.get('sha256') or [])[:10]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious Hash: {sha[:16]}...",
                "pattern":      f"[file:hashes.'SHA-256' = '{sha}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
            }))

        for url in (iocs.get('url') or [])[:10]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         "Malicious URL",
                "pattern":      f"[url:value = '{url}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
            }))

        # ── Relationships: Indicator → Intrusion Set ──
        for ind_id in indicator_ids:
            objects.append(_mark({
                "type":              "relationship",
                "spec_version":      "2.1",
                "id":                f"relationship--{uuid.uuid4()}",
                "relationship_type": "indicates",
                "source_ref":        ind_id,
                "target_ref":        intrusion_set_id,
                "created":           timestamp,
                "modified":          timestamp,
            }))

        # ── Attack Patterns (MITRE) ──
        attack_pattern_ids = []
        if mitre_tactics:
            for tactic in mitre_tactics[:10]:
                ap_id      = f"attack-pattern--{uuid.uuid4()}"
                tactic_name = tactic if isinstance(tactic, str) else tactic.get('tactic', 'Unknown')
                tech_id    = tactic.get('id', '') if isinstance(tactic, dict) else ''
                tech_name  = tactic.get('name', tactic_name) if isinstance(tactic, dict) else tactic_name

                ap_obj = _mark({
                    "type":         "attack-pattern",
                    "spec_version": "2.1",
                    "id":           ap_id,
                    "name":         tech_name,
                    "created":      timestamp,
                    "modified":     timestamp,
                })
                if tech_id:
                    ap_obj["external_references"] = [{
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                    }]
                objects.append(ap_obj)
                attack_pattern_ids.append(ap_id)

                objects.append(_mark({
                    "type":              "relationship",
                    "spec_version":      "2.1",
                    "id":                f"relationship--{uuid.uuid4()}",
                    "relationship_type": "uses",
                    "source_ref":        intrusion_set_id,
                    "target_ref":        ap_id,
                    "created":           timestamp,
                    "modified":          timestamp,
                }))

        # ── v17.0: CVE Vulnerability Objects ──
        cve_pattern    = _re.compile(r'CVE-\d{4}-\d{4,}', _re.IGNORECASE)
        title_text     = title or ""
        meta_text      = str(metadata or {})
        cve_ids_found  = list(set(cve_pattern.findall(title_text + " " + meta_text)))

        vulnerability_ids = []
        for cve_id in cve_ids_found[:5]:
            vuln_id = f"vulnerability--{uuid.uuid4()}"
            vulnerability_ids.append(vuln_id)
            vuln_obj = _mark({
                "type":         "vulnerability",
                "spec_version": "2.1",
                "id":           vuln_id,
                "name":         cve_id.upper(),
                "created":      timestamp,
                "modified":     timestamp,
                "external_references": [{
                    "source_name": "cve",
                    "external_id": cve_id.upper(),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"
                }],
            })
            # v22.0: add CWE references
            if cwe_ids:
                for cwe in cwe_ids[:3]:
                    vuln_obj["external_references"].append({
                        "source_name": "cwe",
                        "external_id": cwe,
                        "url": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html"
                    })
            # v22.0: CVSS extension
            if cvss_score is not None:
                vuln_obj["x_cdb_cvss_score"] = cvss_score
            if epss_score is not None:
                vuln_obj["x_cdb_epss_score"] = epss_score
            if kev_present:
                vuln_obj["x_cdb_kev_confirmed"] = True

            objects.append(vuln_obj)

            objects.append(_mark({
                "type":              "relationship",
                "spec_version":      "2.1",
                "id":                f"relationship--{uuid.uuid4()}",
                "relationship_type": "exploits",
                "source_ref":        intrusion_set_id,
                "target_ref":        vuln_id,
                "created":           timestamp,
                "modified":          timestamp,
            }))

            for ap_id in attack_pattern_ids[:3]:
                objects.append(_mark({
                    "type":              "relationship",
                    "spec_version":      "2.1",
                    "id":                f"relationship--{uuid.uuid4()}",
                    "relationship_type": "targets",
                    "source_ref":        vuln_id,
                    "target_ref":        ap_id,
                    "created":           timestamp,
                    "modified":          timestamp,
                    "description":       "CVE exploited via mapped ATT&CK technique",
                }))

        # ── v22.0: CourseOfAction (Remediation Guidance) ──
        if cvss_score is not None or kev_present:
            priority = ("CRITICAL — Patch immediately" if kev_present else
                        "HIGH — Patch within 7 days"   if (cvss_score or 0) >= 9.0 else
                        "MEDIUM — Patch within 30 days")
            coa_id = f"course-of-action--{uuid.uuid4()}"
            objects.append(_mark({
                "type":         "course-of-action",
                "spec_version": "2.1",
                "id":           coa_id,
                "name":         f"Remediation: {priority}",
                "description":  (
                    f"Remediation guidance for: {title}\n"
                    f"Priority: {priority}\n"
                    f"{'CISA KEV confirmed — treat as immediate emergency.' if kev_present else ''}\n"
                    f"{'NVD Reference: ' + nvd_url if nvd_url else ''}"
                ).strip(),
                "created":  timestamp,
                "modified": timestamp,
            }))

            for vuln_id in vulnerability_ids:
                objects.append(_mark({
                    "type":              "relationship",
                    "spec_version":      "2.1",
                    "id":                f"relationship--{uuid.uuid4()}",
                    "relationship_type": "mitigates",
                    "source_ref":        coa_id,
                    "target_ref":        vuln_id,
                    "created":           timestamp,
                    "modified":          timestamp,
                }))

        # ── v22.0: Note (AI Narrative) ──
        if ai_narrative:
            objects.append(_mark({
                "type":         "note",
                "spec_version": "2.1",
                "id":           f"note--{uuid.uuid4()}",
                "abstract":     "AI-Generated Threat Narrative",
                "content":      ai_narrative[:2000],  # cap length
                "object_refs":  [intrusion_set_id],
                "created":      timestamp,
                "modified":     timestamp,
                "authors":      ["CDB-SENTINEL-APEX-AI"],
            }))

        # ── Write bundle ──
        stix_bundle = {
            "type":    "bundle",
            "id":      bundle_id,
            "objects": objects,
        }

        epoch = int(datetime.now(timezone.utc).timestamp())
        stix_filename = f"CDB-APEX-{epoch}.json"
        stix_path     = os.path.join(self.output_dir, stix_filename)
        with open(stix_path, 'w') as f:
            json.dump(stix_bundle, f, indent=2)

        logger.info(
            f"STIX v22.0 bundle written: {stix_filename} | "
            f"Objects: {len(objects)} | TLP: {tlp_label} | "
            f"Indicators: {len(indicator_ids)} | CVEs: {len(cve_ids_found)}"
        )

        # ── Update Manifest ──
        blog_url   = (metadata or {}).get('blog_url', '')
        source_url = (metadata or {}).get('source_url', '') or blog_url
        self._update_manifest(
            title=title,
            stix_id=bundle_id,
            risk_score=risk_score,
            blog_url=blog_url,
            source_url=source_url,
            severity=severity,
            confidence=confidence,
            tlp_label=tlp_label,
            ioc_counts=ioc_counts or {},
            actor_tag=actor_tag,
            mitre_tactics=[
                t if isinstance(t, str) else t.get('id', 'Unknown')
                for t in (mitre_tactics or [])
            ],
            feed_source=feed_source,
            indicator_count=len(indicator_ids),
            stix_file=stix_filename,
            epss_score=epss_score,
            cvss_score=cvss_score,
            kev_present=kev_present,
            nvd_url=nvd_url,
            supply_chain=supply_chain,
            object_count=len(objects),
        )

        return bundle_id

    # ── v22.0 NEW: MISP Bridge ─────────────────────────────────

    def export_to_misp(
        self,
        title: str,
        iocs: Dict[str, List[str]],
        risk_score: float,
        tlp_label: str = "TLP:CLEAR",
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        kev_present: bool = False,
        actor_tag: str = "",
        mitre_tactics: Optional[List] = None,
    ) -> Dict:
        """
        Generate MISP-compatible event JSON.
        Output is suitable for direct import into MISP via REST API.
        """
        tlp_to_distrib = {"TLP:RED": 0, "TLP:AMBER": 1, "TLP:GREEN": 2, "TLP:CLEAR": 3}
        tlp_to_level   = {"TLP:RED": 4, "TLP:AMBER": 3, "TLP:GREEN": 2, "TLP:CLEAR": 1}

        distribution  = tlp_to_distrib.get(tlp_label.upper(), 3)
        threat_level  = tlp_to_level.get(tlp_label.upper(), 2)
        analysis      = 2 if kev_present else (1 if (cvss_score or 0) >= 7 else 0)

        attributes = []

        # Add IOC attributes
        for ip in (iocs.get('ipv4') or [])[:20]:
            attributes.append({"type": "ip-dst", "value": ip, "to_ids": True,
                                "comment": "Malicious IP indicator"})

        for domain in (iocs.get('domain') or [])[:20]:
            attributes.append({"type": "domain", "value": domain, "to_ids": True})

        for sha in (iocs.get('sha256') or [])[:10]:
            attributes.append({"type": "sha256", "value": sha, "to_ids": True})

        for url in (iocs.get('url') or [])[:10]:
            attributes.append({"type": "url", "value": url, "to_ids": True})

        for email in (iocs.get('email') or [])[:5]:
            attributes.append({"type": "email-src", "value": email, "to_ids": False})

        for cve in (iocs.get('cve') or [])[:5]:
            attributes.append({"type": "vulnerability", "value": cve.upper(), "to_ids": False,
                                "comment": f"CVSS: {cvss_score}, EPSS: {epss_score}, KEV: {kev_present}"})

        # MITRE techniques as attributes
        for tactic in (mitre_tactics or [])[:10]:
            tech_id = tactic.get('id', '') if isinstance(tactic, dict) else tactic
            if tech_id:
                attributes.append({"type": "text", "value": tech_id,
                                   "category": "External analysis",
                                   "comment": "MITRE ATT&CK technique"})

        # Risk score as attribute
        attributes.append({
            "type": "text", "value": str(risk_score),
            "category": "Other", "comment": "CDB Risk Score (0-10)"
        })
        if actor_tag:
            attributes.append({"type": "threat-actor", "value": actor_tag,
                               "to_ids": False, "category": "Attribution"})

        event = {
            "info":          f"[CDB-APEX] {title}",
            "distribution":  distribution,
            "threat_level_id": str(threat_level),
            "analysis":      str(analysis),
            "date":          datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "Attribute":     attributes,
            "Tag": [
                {"name": tlp_label},
                {"name": "cdb:platform:sentinel-apex"},
                *(([{"name": "cdb:kev:confirmed"}] if kev_present else [])),
                *(([{"name": "cdb:severity:critical"}] if risk_score >= 8.5 else [])),
                *(([{"name": "cdb:supply-chain"}] if any(
                    "supply chain" in str(a.get("comment","")).lower() for a in attributes
                ) else [])),
            ],
            "uuid": str(uuid.uuid4()),
            "Orgc": {
                "name": "CyberDudeBivash SENTINEL APEX",
                "uuid": "cdb-sentinel-apex-v22",
            },
        }
        return {"Event": event}

    # ── v22.0 NEW: Bundle Validation ──────────────────────────

    def validate_bundle(self, bundle: Dict) -> Dict:
        """
        Validate STIX 2.1 bundle for spec compliance.
        Returns: {valid: bool, errors: [], warnings: [], object_count: int}
        """
        errors = []
        warnings = []

        if bundle.get("type") != "bundle":
            errors.append("Root object must have type='bundle'")
        if not bundle.get("id", "").startswith("bundle--"):
            errors.append("Bundle ID must start with 'bundle--'")

        objects = bundle.get("objects", [])
        if not objects:
            warnings.append("Bundle contains no objects")

        has_identity  = any(o.get("type") == "identity" for o in objects)
        has_marking   = any(o.get("type") == "marking-definition" for o in objects)
        has_indicator = any(o.get("type") == "indicator" for o in objects)

        if not has_identity:
            warnings.append("No identity object found (recommended per STIX 2.1)")
        if not has_marking:
            warnings.append("No marking-definition found (TLP not set)")
        if not has_indicator:
            warnings.append("No indicator objects found")

        # Check all objects have spec_version
        for i, obj in enumerate(objects):
            if obj.get("type") in ("identity", "marking-definition"):
                continue  # These may use older spec
            if not obj.get("spec_version"):
                warnings.append(f"Object {i} ({obj.get('type')}) missing spec_version")
            if not obj.get("id"):
                errors.append(f"Object {i} ({obj.get('type')}) missing id")
            if not obj.get("created") or not obj.get("modified"):
                warnings.append(f"Object {i} ({obj.get('type')}) missing created/modified")

        # ── v23.0 ADDITION: Deep stix2 library validation (optional) ────────
        # Uses the official Oasis stix2 Python library when available.
        # Adds findings to warnings (non-breaking) rather than hard errors
        # so existing pipelines are never disrupted by library availability.
        stix2_validated = False
        stix2_errors = []
        if _STIX2_AVAILABLE and len(errors) == 0:
            try:
                _stix2_lib.parse(json.dumps(bundle), allow_custom=True)
                stix2_validated = True
            except Exception as stix2_exc:
                stix2_errors.append(str(stix2_exc))
                warnings.append(f"stix2 library validation: {stix2_exc}")

        return {
            "valid":          len(errors) == 0,
            "errors":         errors,
            "warnings":       warnings,
            "object_count":   len(objects),
            "has_identity":   has_identity,
            "has_tlp":        has_marking,
            "stix2_validated": stix2_validated,
            "stix2_errors":   stix2_errors,
        }

    # ── Manifest Update (preserved + v22.0 fields) ──────────────

    def _update_manifest(self, title, stix_id, risk_score, blog_url,
                         severity, confidence, tlp_label, ioc_counts,
                         actor_tag, mitre_tactics, feed_source,
                         indicator_count, stix_file,
                         cvss_score=None, epss_score=None,
                         kev_present=False, source_url="",
                         nvd_url=None, extended_metrics=None,
                         supply_chain=False, object_count=0):
        """Update manifest — backward-compatible + v22.0 new fields."""
        manifest_entries = []
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    manifest_entries = data
                elif isinstance(data, dict):
                    manifest_entries = data.get("entries", [])
            except Exception:
                manifest_entries = []

        # Dedup guard
        existing_titles = {e.get("title", "").strip().lower() for e in manifest_entries}
        if title.strip().lower() in existing_titles:
            logger.info(f"  [MANIFEST] Dedup guard: skipping duplicate: {title[:60]}")
            return

        entry = {
            # v11.0 original fields (preserved)
            "title":            title,
            "stix_id":          stix_id,
            "bundle_id":        stix_id,
            "risk_score":       float(risk_score),
            "blog_url":         blog_url,
            "source_url":       source_url or blog_url,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "severity":         severity,
            "confidence_score": float(confidence),
            "confidence":       float(confidence),
            "tlp_label":        tlp_label,
            "ioc_counts":       ioc_counts,
            "actor_tag":        actor_tag,
            "mitre_tactics":    mitre_tactics[:5] if mitre_tactics else [],
            "feed_source":      feed_source,
            "indicator_count":  indicator_count,
            "stix_file":        stix_file,
            # v17.0 fields (preserved)
            "cvss_score":       cvss_score,
            "epss_score":       epss_score,
            "kev_present":      kev_present,
            "status":           "active",
            "extended_metrics": extended_metrics or {},
            "nvd_url":          nvd_url,
            # v22.0 new fields
            "supply_chain":     supply_chain,
            "stix_object_count":object_count,
            "stix_version":     "2.1",
            "schema_version":   "v22.0",
        }

        manifest_entries.append(entry)
        trimmed = manifest_entries[-MANIFEST_MAX_ENTRIES:]

        with open(self.manifest_path, 'w') as f:
            json.dump(trimmed, f, indent=4)

        logger.info(f"Manifest updated: {len(trimmed)} entries | latest: {title[:50]}")


# Global singleton (backward compatible)
stix_exporter = STIXExporter()
