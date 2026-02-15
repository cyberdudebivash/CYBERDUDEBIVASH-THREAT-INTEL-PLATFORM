#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v7.4
Enhanced Manifest Engine: TLP & Risk Aggregation for Dashboard UI.
"""
import os
import json
from datetime import datetime, timezone

class STIXExporter:
    def __init__(self):
        self.output_dir = "data/stix"
        self.manifest_path = "data/stix/feed_manifest.json"

    def _ensure_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def update_manifest(self):
        """Aggregates TLP, Risk, and Tactics for the Command Center UI."""
        self._ensure_dir()
        stix_files = [f for f in os.listdir(self.output_dir) 
                      if f.endswith(".json") and f != "feed_manifest.json"]
        
        active_tactics = set()
        file_metadata = []

        for file in sorted(stix_files, reverse=True)[:100]:
            try:
                with open(os.path.join(self.output_dir, file), 'r') as f:
                    data = json.load(f)
                    risk = 5.0
                    file_tactics = []

                    for obj in data.get('objects', []):
                        if obj.get('type') == 'indicator':
                            # Parse Risk from description generated in sentinel_blogger.py
                            desc = obj.get('description', '')
                            if "Risk:" in desc:
                                try: risk = float(desc.split("Risk:")[1].split("/")[0])
                                except: pass
                            
                            if 'external_references' in obj:
                                for ref in obj['external_references']:
                                    if ref.get('source_name') == 'mitre-attack':
                                        t = ref.get('description', '').split(':')[-1].strip()
                                        if t: 
                                            file_tactics.append(t)
                                            active_tactics.add(t)

                    file_metadata.append({
                        "name": file,
                        "risk_score": risk,
                        "tlp": "AMBER" if risk >= 7.0 else "CLEAR",
                        "tactics": sorted(list(set(file_tactics))),
                        "pdf": file.replace(".json", ".pdf") if risk >= 7.0 else None
                    })
            except: continue

        manifest = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_nodes": len(stix_files),
            "active_tactics": sorted(list(active_tactics)),
            "files": file_metadata 
        }
        
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)
        print(f"✓ v7.4 Manifest Updated: {len(file_metadata)} Enhanced Nodes.")

    def create_bundle(self, title, iocs, risk_score, enriched_data, mitre_data=None):
        """Generates STIX 2.1 bundles with Risk metadata."""
        self._ensure_dir()
        bundle_id = f"bundle--{datetime.now().timestamp()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        objects = []
        
        for ioc_type, values in iocs.items():
            for val in values:
                external_refs = []
                if mitre_data:
                    for tech in mitre_data:
                        external_refs.append({
                            "source_name": "mitre-attack",
                            "external_id": tech['id'],
                            "description": f"Tactic: {tech['tactic']}"
                        })

                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{val}",
                    "created": timestamp,
                    "description": f"Triage by Sentinel APEX. Risk: {risk_score}/10",
                    "pattern": f"[{ioc_type}:value = '{val}']",
                    "pattern_type": "stix",
                    "external_references": external_refs
                })

        bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
        filename = f"CDB-APEX-{int(datetime.now().timestamp())}.json"
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump(bundle, f, indent=4)
        self.update_manifest()

stix_exporter = STIXExporter()
