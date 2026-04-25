#!/usr/bin/env python3
"""
export_stix.py - CyberDudeBivash v23.1 (SENTINEL APEX ULTRA)
STIX 2.1 EXPORTER + MISP BRIDGE - PRODUCTION UPGRADE

v23.1 ADDITIONS (all additive, non-breaking):
  - STIX Indicator objects for SHA-1, MD5, malware artifacts, registry keys
    Fixes: "STIX Indicators: 0" for advisories with only artifact/hash IOCs
    Root cause: export loop only handled ipv4/domain/sha256/url types

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

# -- Optional: stix2 library for deep schema validation ----------------------
# Install with: pip install stix2==3.0.1
# Falls back gracefully when not installed - all existing functionality intact.
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

# -- STIX 2.1 Standard TLP Marking Definitions (OASIS spec) --
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

# -- Producer Identity Object --
CDB_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": STIX_IDENTITY_ID,
    "name": "CyberDudeBivash SENTINEL APEX",
    "description": "CyberDudeBivash Pvt. Ltd. - Global Cybersecurity Intelligence Infrastructure",
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
        # v23.0 additions — APEX AI enrichment (fully optional, zero regression)
        apex_data: Optional[Dict] = None,
        # v134.0: IOC engine outputs (passed from pipeline item)
        ioc_confidence: float = 0.0,
        ioc_threat_level: str = "NONE",
        ioc_extraction_meta: Optional[Dict] = None,
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

        # ── Hoist title_text / meta_text early (v134.0 crash fix) ────────────
        # These are used in CVE-from-iocs dedup block (below) AND in the
        # v17.0 CVE scan block further down. Initialize here so neither block
        # raises UnboundLocalError regardless of execution order.
        cve_pattern    = _re.compile(r'CVE-\d{4}-\d{4,}', _re.IGNORECASE)
        title_text     = (title or "").strip()
        meta_text      = str(metadata or {})

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

        # -- Intrusion Set (Campaign/Actor) --
        _intrusion_set_obj = {
            "type":            "intrusion-set",
            "spec_version":    "2.1",
            "id":              intrusion_set_id,
            "name":            f"{actor_tag} Campaign",
            "description":     title,   # v134.0: real title as description (was: "Tactical cluster: {title}")
            "created":         timestamp,
            "modified":        timestamp,
            "confidence":      int(confidence),
            "aliases":         [actor_tag],
            # v22.0: supply chain flag
            **({"labels": ["supply-chain-attack"]} if supply_chain else {}),
        }
        # v23.0: APEX AI Extension — injected only when apex_data present (backward compat)
        if apex_data and isinstance(apex_data, dict):
            try:
                _apex_ext = {
                    "predictive_score":   float(apex_data.get("composite_score", 0.0)),
                    "campaign_id":        str(apex_data.get("campaign_id", "")),
                    "campaign_confidence": float(apex_data.get("priority_score", 0.0)),
                    "threat_category":    str(apex_data.get("threat_category", "UNKNOWN")),
                    "behavioral_tags":    list(apex_data.get("behavioral_tags", [])),
                    "ai_summary":         str(apex_data.get("ai_summary", ""))[:500],
                    "risk_factors":       list(apex_data.get("risk_factors", [])),
                    "soc_priority":       str(apex_data.get("priority", "P4")),
                    "threat_level":       str(apex_data.get("threat_level", "UNKNOWN")),
                    "recommended_action": str(apex_data.get("recommended_action", ""))[:200],
                }
                _intrusion_set_obj["extensions"] = {
                    "x-cdb-apex-1": _apex_ext
                }
            except Exception:
                pass  # Never block STIX generation on apex error
        objects.append(_mark(_intrusion_set_obj))

        # -- Indicator Objects --
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

        # v23.1 FIX: SHA-1 hash indicators (was missing → "STIX Indicators: 0" for
        # advisories whose only IOCs were SHA1/MD5/artifacts/registry keys)
        for sha1 in (iocs.get('sha1') or [])[:10]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious Hash (SHA-1): {sha1[:16]}...",
                "pattern":      f"[file:hashes.'SHA-1' = '{sha1}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        # v23.1 FIX: MD5 hash indicators
        for md5 in (iocs.get('md5') or [])[:10]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious Hash (MD5): {md5}",
                "pattern":      f"[file:hashes.MD5 = '{md5}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        # v23.1 FIX: Malware artifact indicators (filenames: .exe, .dll, .lnk, etc.)
        for artifact in (iocs.get('artifacts') or [])[:10]:
            # Sanitize artifact name for STIX pattern (escape single quotes)
            safe_artifact = artifact.replace("'", "\\'")
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious Artifact: {artifact}",
                "pattern":      f"[file:name = '{safe_artifact}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        # v23.1 FIX: Windows registry key persistence indicators
        for reg_key in (iocs.get('registry') or iocs.get('registry_key') or [])[:10]:
            safe_reg = reg_key.replace("'", "\\'").replace("\\", "\\\\")
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Registry Persistence: {reg_key[:60]}",
                "pattern":      f"[windows-registry-key:key = '{safe_reg}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity", "compromised"],
                "confidence":   int(confidence),
            }))

        # v134.0: Email address indicators (phishing/spearphishing attribution)
        for email_addr in (iocs.get('email') or iocs.get('emails') or [])[:10]:
            safe_email = email_addr.replace("'", "\\'")
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Threat Actor Email: {email_addr}",
                "pattern":      f"[email-message:from_ref.value = '{safe_email}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity", "attribution"],
                "confidence":   int(confidence),
            }))

        # v134.0: File path indicators (malware drop locations)
        for fpath in (iocs.get('file_path') or [])[:10]:
            safe_path = fpath.replace("'", "\\'")
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious File Path: {fpath[:80]}",
                "pattern":      f"[file:parent_directory_ref.path = '{safe_path}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        # v134.0: Mutex name indicators (process injection / RAT persistence)
        for mutex_name in (iocs.get('mutex') or [])[:5]:
            safe_mutex = mutex_name.replace("'", "\\'")
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append(_mark({
                "type":         "indicator",
                "spec_version": "2.1",
                "id":           ind_id,
                "name":         f"Malicious Mutex: {mutex_name[:60]}",
                "pattern":      f"[process:opened_connections[*].dst_port > 0 AND process:name = '{safe_mutex}']",
                "pattern_type": "stix",
                "valid_from":   timestamp,
                "created":      timestamp,
                "modified":     timestamp,
                "indicator_types": ["malicious-activity"],
                "confidence":   int(confidence),
            }))

        # v134.0: Malware family → STIX Malware objects (linked to intrusion-set)
        malware_ids = []
        for mw_family in (iocs.get('malware_family') or [])[:5]:
            mw_id = f"malware--{uuid.uuid4()}"
            malware_ids.append(mw_id)
            objects.append(_mark({
                "type":              "malware",
                "spec_version":      "2.1",
                "id":                mw_id,
                "name":              mw_family,
                "malware_types":     ["trojan", "ransomware", "backdoor"],
                "is_family":         True,
                "created":           timestamp,
                "modified":          timestamp,
                "confidence":        int(confidence),
            }))
            objects.append(_mark({
                "type":              "relationship",
                "spec_version":      "2.1",
                "id":                f"relationship--{uuid.uuid4()}",
                "relationship_type": "uses",
                "source_ref":        intrusion_set_id,
                "target_ref":        mw_id,
                "created":           timestamp,
                "modified":          timestamp,
            }))

        # v134.0: Threat actor references → STIX Threat Actor objects
        ta_ids = []
        for ta_name in (iocs.get('threat_actor') or [])[:3]:
            ta_id = f"threat-actor--{uuid.uuid4()}"
            ta_ids.append(ta_id)
            objects.append(_mark({
                "type":              "threat-actor",
                "spec_version":      "2.1",
                "id":                ta_id,
                "name":              ta_name,
                "threat_actor_types":["nation-state", "crime-syndicate"],
                "sophistication":    "advanced",
                "resource_level":    "government",
                "created":           timestamp,
                "modified":          timestamp,
            }))
            objects.append(_mark({
                "type":              "relationship",
                "spec_version":      "2.1",
                "id":                f"relationship--{uuid.uuid4()}",
                "relationship_type": "attributed-to",
                "source_ref":        intrusion_set_id,
                "target_ref":        ta_id,
                "created":           timestamp,
                "modified":          timestamp,
            }))

        # v134.0: CVE IOCs → STIX Vulnerability objects (from iocs dict, not just title)
        cve_from_iocs = (iocs.get('cve') or iocs.get('cves') or [])[:5]
        for cve_ioc in cve_from_iocs:
            cve_upper = cve_ioc.upper()
            # Only add if not already found in title/metadata text scan below
            if cve_upper not in [c.upper() for c in _re.compile(r'CVE-\d{4}-\d{4,}', _re.IGNORECASE).findall(title_text + " " + meta_text)]:
                vuln_id = f"vulnerability--{uuid.uuid4()}"
                vuln_obj = _mark({
                    "type":         "vulnerability",
                    "spec_version": "2.1",
                    "id":           vuln_id,
                    "name":         cve_upper,
                    "created":      timestamp,
                    "modified":     timestamp,
                    "external_references": [{
                        "source_name": "cve",
                        "external_id": cve_upper,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_upper}"
                    }],
                })
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

        # -- Relationships: Indicator -> Intrusion Set --
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

        # -- Attack Patterns (MITRE) --
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

        # -- v17.0: CVE Vulnerability Objects --
        # NOTE: cve_pattern, title_text, meta_text already initialized at top of create_bundle()
        # Re-assignment here is safe and idempotent (values identical, no UnboundLocalError).
        title_text     = title_text or (title or "")
        meta_text      = meta_text or str(metadata or {})
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

        # -- v22.0: CourseOfAction (Remediation Guidance) --
        if cvss_score is not None or kev_present:
            priority = ("CRITICAL - Patch immediately" if kev_present else
                        "HIGH - Patch within 7 days"   if (cvss_score or 0) >= 9.0 else
                        "MEDIUM - Patch within 30 days")
            coa_id = f"course-of-action--{uuid.uuid4()}"
            objects.append(_mark({
                "type":         "course-of-action",
                "spec_version": "2.1",
                "id":           coa_id,
                "name":         f"Remediation: {priority}",
                "description":  (
                    f"Remediation guidance for: {title}\n"
                    f"Priority: {priority}\n"
                    f"{'CISA KEV confirmed - treat as immediate emergency.' if kev_present else ''}\n"
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

        # -- v22.0: Note (AI Narrative) --
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

        # -- Write bundle --
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
            f"STIX v23.1 bundle written: {stix_filename} | "
            f"Objects: {len(objects)} | TLP: {tlp_label} | "
            f"Indicators: {len(indicator_ids)} | CVEs: {len(cve_ids_found)}"
        )

        # -- Update Manifest --
        # v134.0: blog_url completely removed — source_url preserved for reference only.
        # v134.0 P0 FIX: report_url MUST always be an internal /reports/ path.
        # It must NEVER be set to source_url (external article).
        # _update_manifest constructs /reports/YYYY/MM/{intel_id}.html when report_url="".
        source_url = (metadata or {}).get('source_url', '') or (metadata or {}).get('blog_url', '')
        report_url = ""  # v134.0: always empty → _update_manifest constructs internal path

        # v134.0 P0 FIX: Run IOC engine to compute correct ioc_confidence and flat iocs list.
        # Previously ioc_confidence was always 0 because it defaulted to 0.0 at call site,
        # and no computation happened before passing it to create_bundle.
        # Also: ioc_counts was a dict of {type: int} but never included the actual IOC values
        # in the manifest entry — causing ioc_count > 0 with iocs = [].
        _ioc_engine_result = None
        try:
            from agent.ioc_engine import extract_iocs as _extract_iocs_engine
            _title_text_for_ioc = (title or "")
            _meta_text_for_ioc  = str(metadata or {})
            _ioc_engine_result = _extract_iocs_engine(
                _title_text_for_ioc + " " + _meta_text_for_ioc,
                existing_iocs_by_type=iocs or {},
            )
            # Use engine-computed values (always more accurate than caller-provided defaults)
            _effective_ioc_confidence  = _ioc_engine_result.ioc_confidence
            _effective_ioc_threat_level = _ioc_engine_result.threat_level
            _effective_flat_iocs       = _ioc_engine_result.flat_iocs
            _effective_iocs_by_type    = _ioc_engine_result.iocs_by_type
        except Exception as _ioc_e:
            logger.warning("IOC engine failed (using caller values): %s", _ioc_e)
            # Fallback: build flat list from the structured iocs dict
            _effective_flat_iocs = []
            _seen_flat = set()
            for _ioc_type, _ioc_vals in (iocs or {}).items():
                for _v in (_ioc_vals or []):
                    if _v and str(_v).strip() not in _seen_flat:
                        _effective_flat_iocs.append(str(_v).strip())
                        _seen_flat.add(str(_v).strip())
            _effective_ioc_confidence   = ioc_confidence if ioc_confidence > 0 else (
                max(len(_effective_flat_iocs) * 2.0, 0.0)
            )
            _effective_ioc_threat_level = ioc_threat_level if ioc_threat_level != "NONE" else (
                "LOW" if _effective_flat_iocs else "NONE"
            )
            _effective_iocs_by_type     = iocs or {}

        # Integrity guard: ioc_count MUST equal len(flat_iocs)
        _effective_ioc_count = len(_effective_flat_iocs)

        # v134.0: STIX bundle URL — construct from stix_file (filename → CDN URL)
        # This ensures API layer always has a non-null stix_bundle_url when a bundle exists.
        _stix_bundle_url = ""
        if stix_filename:
            _cdn_base = os.environ.get(
                "STIX_CDN_BASE",
                "https://intel.cyberdudebivash.com/data/stix"
            )
            _stix_bundle_url = f"{_cdn_base}/{stix_filename}"

        self._update_manifest(
            title=title,
            stix_id=bundle_id,
            risk_score=risk_score,
            blog_url='',          # legacy param kept for signature compat — always empty now
            source_url=source_url,
            report_url=report_url,
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
            stix_bundle_url=_stix_bundle_url,  # v134.0: full URL, never null when bundle exists
            epss_score=epss_score,
            cvss_score=cvss_score,
            kev_present=kev_present,
            nvd_url=nvd_url,
            supply_chain=supply_chain,
            object_count=len(objects),
            apex_data=apex_data,         # v23.0: pass through to manifest
            # v134.0: IOC engine-computed values (always consistent)
            ioc_confidence=_effective_ioc_confidence,
            ioc_threat_level=_effective_ioc_threat_level,
            ioc_extraction_meta=ioc_extraction_meta or {},
            # v134.0 P0 FIX: actual IOC flat list (guarantees ioc_count == len(iocs))
            iocs_flat=_effective_flat_iocs,
            iocs_by_type=_effective_iocs_by_type,
        )

        return bundle_id

    # -- v22.0 NEW: MISP Bridge ---------------------------------

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

    # -- v22.0 NEW: Bundle Validation --------------------------

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

        has_identity    = any(o.get("type") == "identity" for o in objects)
        has_marking     = any(o.get("type") == "marking-definition" for o in objects)
        has_indicator   = any(o.get("type") == "indicator" for o in objects)
        has_malware     = any(o.get("type") == "malware" for o in objects)
        has_threat_act  = any(o.get("type") == "threat-actor" for o in objects)
        has_vuln        = any(o.get("type") == "vulnerability" for o in objects)
        has_intrusion   = any(o.get("type") == "intrusion-set" for o in objects)
        indicator_count = sum(1 for o in objects if o.get("type") == "indicator")

        if not has_identity:
            warnings.append("No identity object found (recommended per STIX 2.1)")
        if not has_marking:
            warnings.append("No marking-definition found (TLP not set)")

        # v134.0 ENFORCEMENT: Bundles for valid threats MUST contain indicators.
        # If intrusion-set is present but 0 indicators → this is a quality failure.
        if has_intrusion and not has_indicator and not has_malware and not has_vuln:
            errors.append(
                "ENFORCEMENT VIOLATION: Intrusion-set present but ZERO indicator/malware/vulnerability "
                "objects found. Pipeline quality gate: HIGH/CRITICAL threats require ≥1 IOC indicator. "
                "Check NormalizeStage IOC extraction and ScoreStage fallback enrichment."
            )
        elif not has_indicator:
            warnings.append(
                f"No indicator objects found. Bundle has: "
                f"malware={has_malware}, vulnerability={has_vuln}, threat-actor={has_threat_act}. "
                "For STIX consumers, indicator objects are required for automated detection rules."
            )

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

        # -- v23.0 ADDITION: Deep stix2 library validation (optional) --------
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

    # -- Manifest Update (preserved + v22.0 fields) --------------


    # ── FIX-05: threat_type classification (v140.0) ──────────────────────────
    # Replaces the Worker's "General" fallback with real category at write-time.
    # This ensures every manifest entry carries a meaningful threat_type that
    # survives through api/feed.json without the Worker needing to guess.
    @staticmethod
    def _classify_threat_type(title: str, tags=None) -> str:
        t = (title or "").lower()
        tg = " ".join(tags or []).lower()
        combined = t + " " + tg
        rules = [
            (["ransomware","ransom","lockbit","blackcat","clop","akira","revil","ryuk"],  "Ransomware"),
            (["apt","advanced persistent","nation.state","lazarus","volt typhoon","fancy bear",
              "cozy bear","turla","equation group","kimsuky","sandworm"],                 "APT"),
            (["cve-","vulnerability","rce","remote code","exploit","patch","zero.day","0day",
              "buffer overflow","privilege escalation","heap spray","use.after.free"],    "Vulnerability"),
            (["supply chain","solarwinds","xz utils","polyfill","npm package",
              "pypi","dependency","open source compromise"],                              "Supply Chain"),
            (["phishing","spear.phish","credential harvest","business email","bec"],      "Phishing"),
            (["malware","trojan","backdoor","rat ","stealer","infostealer","keylogger",
              "botnet","loader","dropper","wiper","rootkit"],                             "Malware"),
            (["data breach","data leak","exfiltrat","stolen data","dump","database exposed"], "Data Breach"),
            (["ddos","denial of service","botnet flood","amplification attack"],         "DDoS"),
            (["cryptojack","cryptominer","mining","coin miner"],                         "Cryptojacking"),
            (["ics","scada","industrial","ot security","operational technology"],        "ICS/OT"),
            (["cloud","aws","azure","gcp","s3 bucket","misconfigured","kubernetes"],     "Cloud Security"),
            (["mobile","android","ios","iphone","app store","apk"],                      "Mobile"),
        ]
        for keywords, threat_type in rules:
            for kw in keywords:
                if kw in combined:
                    return threat_type
        return "Threat Intel"

    def _update_manifest(self, title, stix_id, risk_score, blog_url,
                         severity, confidence, tlp_label, ioc_counts,
                         actor_tag, mitre_tactics, feed_source,
                         indicator_count, stix_file,
                         cvss_score=None, epss_score=None,
                         kev_present=False, source_url="",
                         report_url="",
                         nvd_url=None, extended_metrics=None,
                         supply_chain=False, object_count=0,
                         # v23.0: APEX enrichment (optional, backward compat)
                         apex_data=None,
                         # v134.0: IOC engine outputs
                         ioc_confidence=0.0, ioc_threat_level="NONE",
                         ioc_extraction_meta=None,
                         # v134.0 P0 FIX: actual IOC data (ioc_count == len(iocs) guaranteed)
                         iocs_flat=None, iocs_by_type=None,
                         stix_bundle_url=""):
        """Update manifest - backward-compatible + v134.0 IOC integrity fields."""
        manifest_entries = []
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    manifest_entries = data
                elif isinstance(data, dict):
                    # v134.0 FIX: bootstrap writes "advisories" key, not "entries".
                    # Using data.get("entries",[]) returned [] when manifest was a dict,
                    # causing sentinel_blogger to overwrite the full manifest with a
                    # single-entry list on each call. All previous enriched entries lost.
                    for _key in ("advisories", "entries", "reports", "items"):
                        _v = data.get(_key)
                        if isinstance(_v, list):
                            manifest_entries = _v
                            break
            except Exception:
                manifest_entries = []

        # Brand/identity filter — block company identity objects from intel feed
        _BRAND_KEYWORDS = [
            "CYBERDUDEBIVASH® PRIVATE LIMITED",
            "OFFICIAL WORKPLACE",
            "GST & PAN VERIFIED",
            "GLOBAL CYBERSECURITY AUTHORITY",
        ]
        if any(kw in title for kw in _BRAND_KEYWORDS):
            logger.info(f"  [MANIFEST] Brand filter: skipping identity entry: {title[:60]}")
            return

        # Dedup guard
        existing_titles = {e.get("title", "").strip().lower() for e in manifest_entries}
        if title.strip().lower() in existing_titles:
            logger.info(f"  [MANIFEST] Dedup guard: skipping duplicate: {title[:60]}")
            return

        # v134.0 SCHEMA CONTRACT: every entry MUST carry id + report_url.
        # id: prefer STIX identifier when it starts with "intel--", else derive.
        import hashlib as _hashlib
        _ts_now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        _intel_id = stix_id if (isinstance(stix_id, str) and stix_id.startswith("intel--")) else (
            "intel--" + _hashlib.sha1(f"{title}::{_ts_now}".encode("utf-8")).hexdigest()[:24]
        )
        # report_url: always /reports/YYYY/MM/<id>.html (relative); physical HTML
        # is produced by scripts/report_generator.py (inline) or generate_intel_reports.py.
        # v134.0: reject ANY external URL — not just blogspot. If the URL starts with
        # "http" and is not on cyberdudebivash.com, it is external and must be replaced.
        _report_url = (report_url or "").strip()
        _is_external = (
            _report_url.startswith("http") and "cyberdudebivash" not in _report_url
        )
        if not _report_url or "blogspot" in _report_url.lower() or _is_external:
            _yyyy = _ts_now[:4]; _mm = _ts_now[5:7]
            _report_url = f"/reports/{_yyyy}/{_mm}/{_intel_id}.html"
        # source_url: never a blogspot URL
        _source_url = (source_url or "").strip()
        if _source_url and "blogspot" in _source_url.lower():
            _source_url = ""
        # tags: from labels/mitre if provided in kwargs; default to mitre_tactics copy
        _tags = list(mitre_tactics)[:8] if mitre_tactics else []
        # FIX-05: classify threat_type at write-time — prevents Worker "General" fallback
        _threat_type = self._classify_threat_type(title, _tags)

        # v134.0 P0 FIX — INLINE REPORT GENERATION (HARD FAIL)
        # Root cause of previous failure: 'metadata' and '_effective_flat_iocs'
        # were referenced but are NOT in scope inside _update_manifest() —
        # they belong to create_bundle(). Fixed by using only _update_manifest()
        # parameters: iocs_flat, mitre_tactics, feed_source, etc.
        #
        # Architecture: this block generates the physical HTML dossier BEFORE
        # the manifest entry is written. If generation fails for ANY reason,
        # RuntimeError is raised and the pipeline STOPS. There is NO silent
        # failure, NO fallback continuation, NO partial publish.
        #
        # Every advisory MUST have a valid HTML report file on disk. Non-negotiable.
        import sys as _rg_sys, os as _rg_os
        _rg_scripts_dir = _rg_os.path.normpath(
            _rg_os.path.join(_rg_os.path.dirname(__file__), "..", "scripts")
        )
        if _rg_scripts_dir not in _rg_sys.path:
            _rg_sys.path.insert(0, _rg_scripts_dir)

        try:
            from report_generator import generate_report as _gen_report
        except ImportError as _rg_imp_err:
            raise RuntimeError(
                f"P0: cannot import report_generator for entry '{_intel_id}': "
                f"{_rg_imp_err!r}. "
                "Ensure scripts/report_generator.py is present and syntax-clean. "
                "Pipeline stopped — every advisory MUST have a valid HTML report."
            ) from _rg_imp_err

        # Build entry preview using ONLY parameters available in _update_manifest().
        # 'metadata' and '_effective_flat_iocs' are NOT in scope here —
        # use 'iocs_flat' (the parameter name) and construct description inline.
        _rg_iocs = iocs_flat if isinstance(iocs_flat, list) else []
        _rg_ttp_count = len(mitre_tactics) if mitre_tactics else 0
        _rg_description = (
            f"{title} "
            f"[{len(_rg_iocs)} IOC(s) | {_rg_ttp_count} TTP(s) | Source: {feed_source or 'SENTINEL-APEX'}]"
        )

        _report_entry_for_gen = {
            "id":                  _intel_id,
            "stix_id":             _intel_id,
            "title":               title,
            "severity":            severity,
            "risk_score":          float(risk_score),
            "description":         _rg_description,
            "tlp":                 (tlp_label or "TLP:CLEAR").upper(),
            "actor_tag":           actor_tag or "UNC",
            "mitre_tactics":       list(mitre_tactics[:5]) if mitre_tactics else [],
            "confidence":          float(confidence),
            "confidence_score":    float(confidence),
            "feed_source":         feed_source or "SENTINEL-APEX",
            "source":              feed_source or "SENTINEL-APEX",
            "threat_type":         _threat_type,
            "source_url":          _source_url,
            "iocs":                _rg_iocs,
            "ioc_count":           len(_rg_iocs),
            "stix_bundle_url":     stix_bundle_url or "",
            "stix_bundle":         stix_bundle_url or stix_file or "",
            "stix_file":           stix_file or "",
            "processed_at":        _ts_now,
            "timestamp":           _ts_now,
            "internal_report_url": _report_url,
            "report_url":          _report_url,
            "cvss_score":          cvss_score,
            "epss_score":          epss_score,
            "kev_present":         kev_present,
        }

        try:
            _rg_ok, _rg_result = _gen_report(
                _report_entry_for_gen,
                stix_file or None,
            )
        except Exception as _rg_call_err:
            raise RuntimeError(
                f"P0: report_generator.generate_report() raised exception for "
                f"'{_intel_id}': {_rg_call_err!r}. "
                "Pipeline stopped — fix report_generator.py."
            ) from _rg_call_err

        # HARD FAIL: generation function reported failure
        if not _rg_ok:
            raise RuntimeError(
                f"P0: report generation returned failure for entry '{_intel_id}': "
                f"{_rg_result}. "
                "Pipeline stopped — every advisory MUST have a valid HTML report."
            )

        # HARD FAIL: verify physical file existence
        _rg_file_path = _rg_result
        if not _rg_os.path.exists(_rg_file_path):
            raise RuntimeError(
                f"P0: report file does not exist after generation: '{_rg_file_path}'. "
                f"Entry: '{_intel_id}'. Pipeline stopped."
            )

        # HARD FAIL: verify non-empty file
        _rg_file_size = _rg_os.path.getsize(_rg_file_path)
        if _rg_file_size < 500:
            raise RuntimeError(
                f"P0: report file is too small ({_rg_file_size} bytes) — likely "
                f"truncated or corrupted: '{_rg_file_path}'. "
                f"Entry: '{_intel_id}'. Pipeline stopped."
            )

        # HARD FAIL: verify valid HTML structure
        try:
            with open(_rg_file_path, "r", encoding="utf-8", errors="replace") as _rg_f:
                _rg_head = _rg_f.read(512)
        except Exception as _rg_read_err:
            raise RuntimeError(
                f"P0: cannot read report file '{_rg_file_path}': {_rg_read_err!r}. "
                f"Entry: '{_intel_id}'. Pipeline stopped."
            ) from _rg_read_err

        _rg_head_lower = _rg_head.lower()
        if "<!doctype html" not in _rg_head_lower and "<html" not in _rg_head_lower:
            raise RuntimeError(
                f"P0: report file '{_rg_file_path}' does not start with valid HTML "
                f"(got: {_rg_head[:80]!r}). "
                f"Entry: '{_intel_id}'. Pipeline stopped — file may be JSON or corrupted."
            )

        logger.info(
            "[REPORT] ✔ Generated and verified: %s (%d bytes) → %s",
            _intel_id, _rg_file_size, _rg_file_path
        )

        entry = {
            # v134.0 SCHEMA CONTRACT (required)
            "id":               _intel_id,
            "stix_id":          _intel_id,
            "bundle_id":        stix_id or _intel_id,
            "title":            title,
            # v134.0.0 FRESHNESS FIX: processed_at = pipeline generation time (UTC-now).
            # This is ALWAYS the current run timestamp — independent of the RSS article's
            # publication date. Use as primary sort key so newly generated intel ALWAYS
            # ranks above older items regardless of their source published_at date.
            "processed_at":     _ts_now,
            "timestamp":        _ts_now,
            "risk_score":       float(risk_score),
            "severity":         severity,
            "report_url":       _report_url,
            "source_url":       _source_url,
            "tlp":              (tlp_label or "TLP:CLEAR").upper(),
            "tags":             _tags,
            # v134.0 enrichment (preserved when populated)
            "generated_at":     _ts_now,
            "confidence_score": float(confidence),
            "confidence":       float(confidence),
            "tlp_label":        tlp_label,
            "ioc_counts":       ioc_counts,
            "actor_tag":        actor_tag,
            "mitre_tactics":    mitre_tactics[:5] if mitre_tactics else [],
            "ttps":             mitre_tactics[:5] if mitre_tactics else [],
            "feed_source":      feed_source,
            "source":           feed_source or "SENTINEL-APEX",
            "threat_type":      _threat_type,
            "indicator_count":  indicator_count,
            "stix_file":        stix_file,
            "cvss_score":       cvss_score,
            "epss_score":       epss_score,
            "kev_present":      kev_present,
            "status":           "active",
            "extended_metrics": extended_metrics or {},
            "nvd_url":          nvd_url,
            "supply_chain":     supply_chain,
            "stix_object_count":object_count,
            "stix_version":     "2.1",
            "schema_version":   "v134.0",
            # v134.0: always published — Blogger permanently disabled
            "published":        True,
            # v134.0: validation_status is set to 'valid' here because the
            # HTML dossier at _rg_file_path has already passed the 4 HARD-FAIL
            # checks above (exists, size > 500 bytes, starts with HTML sig).
            # scripts/update_validation_status.py performs an additional
            # post-pipeline sweep as a safety net.
            "validation_status": "valid",
            "validated_at":     _ts_now,
            # v134.0 P0 FIX: actual IOC flat list — ioc_count ALWAYS == len(iocs)
            # iocs_flat is the authoritative flat list computed by the IOC engine.
            # ioc_count is derived from it (never from ioc_counts dict which was
            # the source of the count > 0 / empty list desync bug).
            "iocs":              iocs_flat if isinstance(iocs_flat, list) else [],
            "iocs_by_type":      iocs_by_type if isinstance(iocs_by_type, dict) else {},
            "ioc_count":         len(iocs_flat) if isinstance(iocs_flat, list) else (
                                     sum(ioc_counts.values()) if ioc_counts else 0
                                 ),
            "ioc_confidence":    round(float(ioc_confidence or 0.0), 2),
            "ioc_threat_level":  ioc_threat_level or "NONE",
            "ioc_extraction_meta": ioc_extraction_meta or {},
            # v134.0: STIX bundle URL (never null when stix_file is set)
            "stix_bundle_url":   stix_bundle_url or "",
            # v134.0 P0 FIX: internal_report_url — always the canonical internal
            # HTML dossier path. Dashboard MUST use this over report_url or
            # source_url. report_url is also forced to the same internal path so
            # both fields are consistent.
            "internal_report_url": _report_url,
            # v134.0: stix_bundle mirrors stix_bundle_url for API consumers that
            # check the shorter field name.
            "stix_bundle":       stix_bundle_url or stix_file or "",
        }
        # v134.0: legacy blog_url field never emitted
        entry.pop("blog_url", None)

        # v23.0: Inject compact APEX field (optional — zero regression on absence)
        if apex_data and isinstance(apex_data, dict):
            try:
                entry["apex"] = {
                    "predictive_score": round(float(apex_data.get("composite_score", 0.0)), 2),
                    "campaign_id":      str(apex_data.get("campaign_id", "")),
                    "threat_category":  str(apex_data.get("threat_category", "UNKNOWN")),
                    "confidence":       round(float(apex_data.get("priority_score", 0.0)), 2),
                    "priority":         str(apex_data.get("priority", "P4")),
                    "threat_level":     str(apex_data.get("threat_level", "UNKNOWN")),
                    "behavioral_tags":  list(apex_data.get("behavioral_tags", []))[:5],
                    "ai_summary":       str(apex_data.get("ai_summary", ""))[:300],
                    "recommended_action": str(apex_data.get("recommended_action", ""))[:150],
                }
            except Exception:
                pass  # Never block manifest write on apex error

        # v134.0 P0 PIPELINE FAILSAFE: internal_report_url MUST be set before
        # this entry enters the manifest. Hard fail prevents silent regression
        # where the dashboard would fall back to external source links.
        if not entry.get("internal_report_url"):
            raise RuntimeError(
                f"P0: missing internal_report_url for entry '{entry.get('id', '?')}'. "
                "Pipeline must produce a /reports/... path before writing manifest."
            )
        # P0 REGRESSION GUARD: report_url must never be an external URL that is
        # not the cyberdudebivash domain.
        _ru_check = entry.get("report_url", "")
        if _ru_check.startswith("http") and "cyberdudebivash" not in _ru_check:
            raise RuntimeError(
                f"P0 REGRESSION: external report_url detected for "
                f"'{entry.get('id', '?')}': {_ru_check!r}. "
                "Set report_url to internal path (/reports/...)."
            )

        manifest_entries.append(entry)

        # v75.0 FIX: Sort BEFORE trim. Original bug used [-500:] on an
        # unsorted list, silently evicting the newest entries. The correct
        # order is: deduplicate -> sort DESC -> slice [:500].
        #
        # v134.0.0 FRESHNESS FIX: processed_at is PRIMARY sort key.
        # processed_at = pipeline generation time (always UTC-now when entry is created).
        # This ensures newly generated intel ALWAYS appears at the top, regardless of
        # source article's published_at date (which may be days/weeks old).
        def _ts_sort_key(e):
            for f in ("processed_at", "timestamp", "generated_at", "published", "published_date"):
                v = e.get(f)
                if v and isinstance(v, str) and len(v) >= 10:
                    return v
            return "1970-01-01T00:00:00+00:00"

        manifest_entries.sort(key=_ts_sort_key, reverse=True)
        trimmed = manifest_entries[:MANIFEST_MAX_ENTRIES]

        # v75.1 ATOMIC WRITE: write to temp file then os.replace() - POSIX-atomic.
        # Eliminates corruption risk if process is killed during write.
        # Previously: plain json.dump() could leave partial JSON on disk.
        _tmp_path = self.manifest_path + ".tmp"
        try:
            with open(_tmp_path, 'w', encoding='utf-8') as f:
                json.dump(trimmed, f, indent=4, ensure_ascii=False, default=str)
            os.replace(_tmp_path, self.manifest_path)
        except Exception as _e:
            # Clean up temp on failure - never leave .tmp on disk
            try:
                if os.path.exists(_tmp_path):
                    os.remove(_tmp_path)
            except Exception:
                pass
            raise _e

        logger.info(f"Manifest updated: {len(trimmed)} entries | latest: {title[:50]}")


# Global singleton (backward compatible)
stix_exporter = STIXExporter()
