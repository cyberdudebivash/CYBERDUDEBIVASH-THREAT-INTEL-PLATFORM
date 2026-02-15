#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v7.4.1
Final Production Version: Robust Risk Extraction & Time Synchronization.
"""
import os, json, re, time # Verified Imports
from datetime import datetime, timezone

class STIXExporter:
    def __init__(self):
        self.output_dir = "data/stix"
        self.manifest_path = "data/stix/feed_manifest.json"

    def update_manifest(self):
        """Aggregates TLP & Risk with regex resilience."""
        stix_files = [f for f in os.listdir(self.output_dir) if f.endswith(".json") and f != "feed_manifest.json"]
        file_metadata = []
        for file in sorted(stix_files, reverse=True)[:100]:
            try:
                with open(os.path.join(self.output_dir, file), 'r') as f:
                    data = json.load(f)
                    risk = 5.0
                    for obj in data.get('objects', []):
                        if obj.get('type') == 'indicator':
                            match = re.search(r"Risk:\s*([\d.]+)", obj.get('description', ''))
                            if match: risk = float(match.group(1))
                    file_metadata.append({"name": file, "risk_score": risk, "tlp": "AMBER" if risk >= 7.0 else "CLEAR"})
            except: continue
        with open(self.manifest_path, "w") as f:
            json.dump({"last_updated": datetime.now(timezone.utc).isoformat(), "files": file_metadata}, f, indent=4)

    def create_bundle(self, title, iocs, risk_score, enriched_data, mitre_data=None):
        """Standardized STIX generation."""
        os.makedirs(self.output_dir, exist_ok=True)
        objects = []
        for ioc_type, values in iocs.items():
            for val in values:
                objects.append({
                    "type": "indicator", "spec_version": "2.1",
                    "id": f"indicator--{os.urandom(8).hex()}",
                    "description": f"Risk: {float(risk_score)}/10",
                    "pattern": f"[{ioc_type}:value = '{val}']", "pattern_type": "stix"
                })
        filename = f"CDB-APEX-{int(time.time())}.json"
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump({"type": "bundle", "id": f"bundle--{time.time()}", "objects": objects}, f)
        self.update_manifest()

stix_exporter = STIXExporter()
