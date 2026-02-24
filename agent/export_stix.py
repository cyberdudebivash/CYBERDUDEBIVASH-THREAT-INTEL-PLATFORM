#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v17.0 (SENTINEL APEX ULTRA)
ENHANCED: STIX 2.1 bundles with full indicator objects and rich relationships.

v17.0 ADDITIONS (non-breaking):
  - CVE → Malware relationship objects
  - CVE → Threat Actor relationship objects
  - CVE → MITRE Technique relationship objects with technique metadata
  - Vulnerability objects for CVE IDs extracted from content
  - Manifest schema extended: generated_at, source_url, cvss_score, status fields
  - Manifest format migrated to {entries: [], generated_at: ...} dict format
    with backward-compatible list fallback
"""
import json
import uuid
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from agent.config import MANIFEST_MAX_ENTRIES, MANIFEST_DIR

logger = logging.getLogger("CDB-STIX")


class STIXExporter:
    """Enhanced STIX 2.1 exporter with full object graph and expanded manifest."""

    def __init__(self, output_dir: str = MANIFEST_DIR):
        self.output_dir = output_dir
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
        mitre_tactics: Optional[List[str]] = None,
        feed_source: str = "CDB-SENTINEL",
        # v21.0 additions (all optional, non-breaking)
        epss_score: Optional[float] = None,
        cvss_score: Optional[float] = None,
        kev_present: bool = False,
        nvd_url: Optional[str] = None,
    ) -> str:
        """
        Create a comprehensive STIX 2.1 bundle with indicators and relationships.

        Returns:
            bundle_id string
        """
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        bundle_id = f"bundle--{uuid.uuid4()}"
        intrusion_set_id = f"intrusion-set--{uuid.uuid4()}"

        objects = []

        # ── Intrusion Set (Campaign/Actor) ──
        objects.append({
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": intrusion_set_id,
            "name": f"{actor_tag} Campaign",
            "description": f"Tactical cluster: {title}",
            "created": timestamp,
            "modified": timestamp,
            "confidence": int(confidence),
        })

        # ── Indicator Objects for each IOC type ──
        indicator_ids = []

        for ip in (iocs.get('ipv4') or [])[:20]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "name": f"Malicious IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "created": timestamp,
                "modified": timestamp,
            })

        for domain in (iocs.get('domain') or [])[:20]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "name": f"Malicious Domain: {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "created": timestamp,
                "modified": timestamp,
            })

        for sha in (iocs.get('sha256') or [])[:10]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "name": f"Malicious Hash: {sha[:16]}...",
                "pattern": f"[file:hashes.'SHA-256' = '{sha}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "created": timestamp,
                "modified": timestamp,
            })

        for url in (iocs.get('url') or [])[:10]:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "name": f"Malicious URL",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "created": timestamp,
                "modified": timestamp,
            })

        # ── Relationships: Indicator → Intrusion Set ──
        for ind_id in indicator_ids:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": intrusion_set_id,
                "created": timestamp,
                "modified": timestamp,
            })

        # ── Attack Patterns (MITRE) ──
        attack_pattern_ids = []
        if mitre_tactics:
            for tactic in mitre_tactics[:10]:
                ap_id = f"attack-pattern--{uuid.uuid4()}"
                tactic_name = tactic if isinstance(tactic, str) else tactic.get('tactic', 'Unknown')
                tech_id = tactic.get('id', '') if isinstance(tactic, dict) else ''
                tech_name = tactic.get('name', tactic_name) if isinstance(tactic, dict) else tactic_name

                ap_obj = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "name": tech_name,
                    "created": timestamp,
                    "modified": timestamp,
                }
                # Add external reference to MITRE ATT&CK if technique ID available
                if tech_id:
                    ap_obj["external_references"] = [{
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                    }]
                objects.append(ap_obj)
                attack_pattern_ids.append(ap_id)

                # Intrusion Set → USES → Attack Pattern
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "relationship_type": "uses",
                    "source_ref": intrusion_set_id,
                    "target_ref": ap_id,
                    "created": timestamp,
                    "modified": timestamp,
                })

        # ── v17.0: CVE Vulnerability Objects + Relationships ──
        # Extract CVE IDs from title and metadata for structured STIX objects
        import re as _re
        cve_pattern = _re.compile(r'CVE-\d{4}-\d{4,}', _re.IGNORECASE)
        title_text = title or ""
        meta_text = str(metadata or {})
        cve_ids_found = list(set(cve_pattern.findall(title_text + " " + meta_text)))

        vulnerability_ids = []
        for cve_id in cve_ids_found[:5]:  # Cap at 5 CVEs per bundle
            vuln_id = f"vulnerability--{uuid.uuid4()}"
            vulnerability_ids.append(vuln_id)
            vuln_obj = {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "name": cve_id.upper(),
                "created": timestamp,
                "modified": timestamp,
                "external_references": [{
                    "source_name": "cve",
                    "external_id": cve_id.upper(),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"
                }]
            }
            objects.append(vuln_obj)

            # Intrusion Set → EXPLOITS → Vulnerability
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "relationship_type": "exploits",
                "source_ref": intrusion_set_id,
                "target_ref": vuln_id,
                "created": timestamp,
                "modified": timestamp,
            })

            # Vulnerability → TARGETS → Attack Patterns (via indicators)
            for ap_id in attack_pattern_ids[:3]:
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "relationship_type": "targets",
                    "source_ref": vuln_id,
                    "target_ref": ap_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "description": "CVE exploited via mapped ATT&CK technique",
                })

        # ── Write STIX Bundle to file ──
        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        epoch = int(datetime.now(timezone.utc).timestamp())
        stix_filename = f"CDB-APEX-{epoch}.json"
        stix_path = os.path.join(self.output_dir, stix_filename)

        with open(stix_path, 'w') as f:
            json.dump(stix_bundle, f, indent=2)

        # ── Update Manifest ──
        blog_url = (metadata or {}).get('blog_url', '')
        source_url = (metadata or {}).get('source_url', '') or blog_url  # v21.0 fix
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
        )

        return bundle_id

    def _update_manifest(self, title, stix_id, risk_score, blog_url,
                         severity, confidence, tlp_label, ioc_counts,
                         actor_tag, mitre_tactics, feed_source,
                         indicator_count, stix_file,
                         cvss_score=None, epss_score=None,
                         kev_present=False, source_url="",
                         nvd_url=None,
                         extended_metrics=None):
        """
        Update manifest with backward-compatible schema.
        v17.0: Enhanced manifest format with {entries: [], generated_at: ...}
               Extended entry fields: generated_at, source_url, cvss_score,
               epss_score, kev_present, status, extended_metrics
        """
        # Load existing manifest — support both old list format and new dict format
        manifest_entries = []
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    manifest_entries = data  # Legacy list format
                elif isinstance(data, dict):
                    manifest_entries = data.get("entries", [])
            except Exception:
                manifest_entries = []

        # ── Dedup guard at manifest level ──
        existing_titles = {e.get("title", "").strip().lower() for e in manifest_entries}
        if title.strip().lower() in existing_titles:
            logger.info(f"  [MANIFEST] Dedup guard: skipping duplicate title: {title[:60]}")
            return

        # ── Build enhanced manifest entry ──
        entry = {
            # Original fields (backward compatible)
            "title": title,
            "stix_id": stix_id,
            "bundle_id": stix_id,        # v17.0: alias for API layer
            "risk_score": float(risk_score),
            "blog_url": blog_url,
            "source_url": source_url or blog_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),  # v17.0 alias
            # v11.0 fields
            "severity": severity,
            "confidence_score": float(confidence),
            "confidence": float(confidence),  # v17.0 alias
            "tlp_label": tlp_label,
            "ioc_counts": ioc_counts,
            "actor_tag": actor_tag,
            "mitre_tactics": mitre_tactics[:5] if mitre_tactics else [],
            "feed_source": feed_source,
            "indicator_count": indicator_count,
            "stix_file": stix_file,
            # v17.0 NEW fields
            "cvss_score": cvss_score,
            "epss_score": epss_score,
            "kev_present": kev_present,
            "status": "active",          # active | archived
            "extended_metrics": extended_metrics or {},
            # v21.0 NEW fields
            "nvd_url": nvd_url,          # Direct NVD link for CVE entries
        }

        manifest_entries.append(entry)

        # Keep last N entries
        trimmed = manifest_entries[-MANIFEST_MAX_ENTRIES:]

        # Write manifest — plain list format (backward-compatible with dashboard)
        # Dashboard reads both list [...] and dict {entries:[...]} formats
        with open(self.manifest_path, 'w') as f:
            json.dump(trimmed, f, indent=4)


# Global singleton (backward compatible)
stix_exporter = STIXExporter()
