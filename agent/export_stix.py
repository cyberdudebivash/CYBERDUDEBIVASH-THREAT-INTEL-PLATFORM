#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
UPGRADED: Proper STIX 2.1 bundles with indicator objects, relationships,
attack-pattern references, expanded manifest schema.
"""
import json
import uuid
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from agent.config import MANIFEST_MAX_ENTRIES, MANIFEST_DIR


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
        if mitre_tactics:
            for tactic in mitre_tactics[:10]:
                ap_id = f"attack-pattern--{uuid.uuid4()}"
                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "name": tactic if isinstance(tactic, str) else tactic.get('tactic', 'Unknown'),
                    "created": timestamp,
                    "modified": timestamp,
                })
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
        self._update_manifest(
            title=title,
            stix_id=bundle_id,
            risk_score=risk_score,
            blog_url=blog_url,
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
        )

        return bundle_id

    def _update_manifest(self, title, stix_id, risk_score, blog_url,
                         severity, confidence, tlp_label, ioc_counts,
                         actor_tag, mitre_tactics, feed_source,
                         indicator_count, stix_file):
        """Update expanded manifest with backward-compatible schema."""
        manifest = []
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r') as f:
                    data = json.load(f)
                    manifest = data if isinstance(data, list) else []
            except Exception:
                manifest = []

        # ── Expanded Manifest Entry ──
        manifest.append({
            # Original fields (backward compatible)
            "title": title,
            "stix_id": stix_id,
            "risk_score": float(risk_score),
            "blog_url": blog_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            # NEW fields
            "severity": severity,
            "confidence_score": float(confidence),
            "tlp_label": tlp_label,
            "ioc_counts": ioc_counts,
            "actor_tag": actor_tag,
            "mitre_tactics": mitre_tactics[:5] if mitre_tactics else [],
            "feed_source": feed_source,
            "indicator_count": indicator_count,
            "stix_file": stix_file,
        })

        # Keep last N entries (upgraded from 10 → configurable)
        with open(self.manifest_path, 'w') as f:
            json.dump(manifest[-MANIFEST_MAX_ENTRIES:], f, indent=4)


# Global singleton (backward compatible)
stix_exporter = STIXExporter()
