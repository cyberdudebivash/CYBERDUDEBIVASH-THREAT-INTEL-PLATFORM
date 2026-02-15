#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v7.1
Beast Mode: Geospatial + MITRE ATT&CK Tactic Aggregation.
"""
import os
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

class STIXExporter:
    def __init__(self):
        self.output_dir = "data/stix"
        self.manifest_path = "data/stix/feed_manifest.json"

    def _ensure_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def update_manifest(self):
        """Aggregates Geo-IP and MITRE Tactics for the Command Center UI."""
        self._ensure_dir()
        stix_files = [f for f in os.listdir(self.output_dir) 
                      if f.endswith(".json") and f != "feed_manifest.json"]
        
        country_stats = Counter()
        active_tactics = set()
        
        for file in stix_files[:50]: # Scan recent 50 nodes for real-time heatmap
            try:
                with open(os.path.join(self.output_dir, file), 'r') as f:
                    data = json.load(f)
                    for obj in data.get('objects', []):
                        # Extract Country Codes
                        if obj.get('type') == 'location':
                            country_stats[obj.get('country')] += 1
                        
                        # Extract MITRE Tactics from Indicator references
                        if obj.get('type') == 'indicator' and 'external_references' in obj:
                            for ref in obj['external_references']:
                                if ref.get('source_name') == 'mitre-attack':
                                    tactic = ref.get('description', '').split(':')[-1].strip()
                                    if tactic: active_tactics.add(tactic)
            except Exception:
                continue

        manifest = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_nodes": len(stix_files),
            "top_countries": dict(country_stats.most_common(10)),
            "active_tactics": list(active_tactics),
            "files": sorted(stix_files, reverse=True)
        }
        
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)
        print(f"✓ v7.1 Manifest Updated: {len(stix_files)} nodes | {len(active_tactics)} Tactics Mapped.")

    def create_bundle(self, title: str, iocs: Dict[str, List[str]], risk_score: float, enriched_data: dict, mitre_data: list = None) -> str:
        """Generates STIX 2.1 bundles with full Metadata Enrichment."""
        self._ensure_dir()
        bundle_id = f"bundle--{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        objects = []
        
        # Identity Object
        identity_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity", "spec_version": "2.1", "id": identity_id,
            "name": "CyberDudeBivash Sentinel APEX", "identity_class": "organization"
        })

        # Process IOCs
        for ioc_type, values in iocs.items():
            for val in values:
                loc_id = None
                if enriched_data and val in enriched_data:
                    geo = enriched_data[val]
                    if geo.get('country_code'):
                        loc_id = f"location--{uuid.uuid4()}"
                        objects.append({
                            "type": "location", "spec_version": "2.1", "id": loc_id,
                            "country": geo['country_code']
                        })

                # Indicator with MITRE mapping
                external_refs = []
                if mitre_data:
                    for tech in mitre_data:
                        external_refs.append({
                            "source_name": "mitre-attack",
                            "external_id": tech['id'],
                            "description": f"Tactic: {tech['tactic']}"
                        })

                objects.append({
                    "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
                    "created": timestamp, "modified": timestamp, "name": f"Node: {val}",
                    "pattern": f"[{ioc_type}:value = '{val}']", "pattern_type": "stix",
                    "valid_from": timestamp, "created_by_ref": identity_id,
                    "where_sighted_refs": [loc_id] if loc_id else [],
                    "external_references": external_refs
                })

        bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
        filename = f"CDB-APEX-{int(datetime.now().timestamp())}.json"
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump(bundle, f, indent=4)
        
        self.update_manifest()
        return json.dumps(bundle)

stix_exporter = STIXExporter()
