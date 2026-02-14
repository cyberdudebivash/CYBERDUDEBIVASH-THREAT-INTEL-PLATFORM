#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v6.0
Geospatial Intelligence: STIX 2.1 Generation with Country-Code Mapping.
"""
import os
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

class STIXExporter:
    def __init__(self):
        self.namespace = "cyberdudebivash-sentinel"
        self.output_dir = "data/stix"
        self.manifest_path = "data/stix/feed_manifest.json"

    def _ensure_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def update_manifest(self):
        """Aggregates threat data and geospatial stats for the Global Watch Map."""
        self._ensure_dir()
        stix_files = [f for f in os.listdir(self.output_dir) 
                      if f.endswith(".json") and f != "feed_manifest.json"]
        
        country_stats = Counter()
        
        # Extract Geo-stats from existing nodes for the Map
        for file in stix_files[:50]: # Scan recent 50 for performance
            try:
                with open(os.path.join(self.output_dir, file), 'r') as f:
                    data = json.load(f)
                    for obj in data.get('objects', []):
                        if obj.get('type') == 'location':
                            country_code = obj.get('country')
                            if country_code:
                                country_stats[country_code] += 1
            except Exception:
                continue

        manifest = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_nodes": len(stix_files),
            "top_countries": dict(country_stats.most_common(10)),
            "files": sorted(stix_files, reverse=True)
        }
        
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)
        print(f"✓ v6.0 Manifest Updated: {len(stix_files)} nodes | Map Data Synced.")

    def create_bundle(self, title: str, iocs: Dict[str, List[str]], risk_score: float, enriched_data: dict = None) -> str:
        """Generates STIX 2.1 bundles with Location objects for map attribution."""
        self._ensure_dir()
        bundle_id = f"bundle--{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        objects = []
        identity_id = f"identity--{uuid.uuid4()}"
        
        # 1. Identity
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "name": "CyberDudeBivash Sentinel APEX",
            "identity_class": "organization",
            "created": timestamp,
            "modified": timestamp
        })

        # 2. Location & Indicators
        for ioc_type, values in iocs.items():
            for val in values:
                # Add Location Object if Geo-data exists
                loc_id = None
                if enriched_data and val in enriched_data:
                    geo = enriched_data[val]
                    if geo.get('country_code'):
                        loc_id = f"location--{uuid.uuid4()}"
                        objects.append({
                            "type": "location",
                            "spec_version": "2.1",
                            "id": loc_id,
                            "country": geo['country_code'],
                            "description": f"Origin: {geo.get('location', 'Unknown')}"
                        })

                # Indicator logic
                indicator_id = f"indicator--{uuid.uuid4()}"
                pattern = f"[{ioc_type}:value = '{val}']"
                if ioc_type == "ipv4": pattern = f"[ipv4-addr:value = '{val}']"

                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": f"Node: {val}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                    "created_by_ref": identity_id,
                    "where_sighted_refs": [loc_id] if loc_id else []
                })

        # 3. Finalize Bundle
        bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
        filename = f"CDB-APEX-{int(datetime.now().timestamp())}.json"
        
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump(bundle, f, indent=4)
        
        self.update_manifest()
        return json.dumps(bundle, indent=4)

stix_exporter = STIXExporter()
