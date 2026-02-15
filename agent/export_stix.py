#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v7.4.1
Enhanced Manifest Engine: Robust Risk Extraction & Dependency Fix.
"""
import os
import json
import re
import time  # CRITICAL FIX: Resolved NameError
from datetime import datetime, timezone

class STIXExporter:
    def __init__(self):
        self.output_dir = "data/stix"
        self.manifest_path = "data/stix/feed_manifest.json"

    def _ensure_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def update_manifest(self):
        """Aggregates TLP & Risk with regex resilience."""
        self._ensure_dir()
        stix_files = [f for f in os.listdir(self.output_dir) 
                      if f.endswith(".json") and f != "feed_manifest.json"]
        file_metadata = []

        for file in sorted(stix_files, reverse=True)[:100]:
            try:
                with open(os.path.join(self.output_dir, file), 'r') as f:
                    data = json.load(f)
                    risk = 5.0
                    file_tactics = []

                    for obj in data.get('objects', []):
                        if obj.get('type') == 'indicator':
                            desc = obj.get('description', '')
                            # Safe Extraction using Regex to prevent ValueError
                            risk_match = re.search(r"Risk:\s*([\d.]+)", desc)
                            if risk_match:
                                try:
                                    risk = float(risk_match.group(1))
                                except ValueError:
                                    risk = 5.0
                            
                            if 'external_references' in obj:
                                for ref in obj['external_references']:
                                    if ref.get('source_name') == 'mitre-attack':
                                        t = ref.get('description', '').split(':')[-1].strip()
                                        if t: file_tactics.append(t)

                    file_metadata.append({
                        "name": file,
                        "risk_score": risk,
                        "tlp": "AMBER" if risk >= 7.0 else "CLEAR",
                        "tactics": sorted(list(set(file_tactics))),
                        "pdf": file.replace(".json", ".pdf") if risk >= 7.0 else None
                    })
            except Exception:
                continue

        manifest = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_nodes": len(stix_files),
            "files": file_metadata 
        }
        
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)

    def create_bundle(self, title, iocs, risk_score, enriched_data, mitre_data=None):
        """Generates STIX 2.1 bundles with standardized Risk format."""
        self._ensure_dir()
        bundle_id = f"bundle--{time.time()}"  # time.time() is now safe
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        objects = []
        
        for ioc_type, values in iocs.items():
            for val in values:
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{os.urandom(8).hex()}",
                    "created": timestamp,
                    "description": f"Risk: {float(risk_score)}/10",
                    "pattern": f"[{ioc_type}:value = '{val}']",
                    "pattern_type": "stix"
                })

        filename = f"CDB-APEX-{int(time.time())}.json"
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump({"type": "bundle", "id": bundle_id, "objects": objects}, f)
        self.update_manifest()

stix_exporter = STIXExporter()
