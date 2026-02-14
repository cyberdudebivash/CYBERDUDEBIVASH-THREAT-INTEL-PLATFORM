#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v2.0
Enterprise Feed Orchestration: STIX 2.1 Generation with Manifest Discovery.
"""
import os
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List

class STIXExporter:
    def __init__(self):
        self.namespace = "cyberdudebivash-sentinel"
        self.output_dir = "data/stix"
        self.manifest_path = "data/stix/feed_manifest.json"

    def _ensure_dir(self):
        """Ensures the forensic directory exists."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def update_manifest(self):
        """Generates a discovery registry for the landing page to fetch nodes."""
        self._ensure_dir()
        # Scan for all JSON files except the manifest itself
        stix_files = [f for f in os.listdir(self.output_dir) 
                      if f.endswith(".json") and f != "feed_manifest.json"]
        
        manifest = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_nodes": len(stix_files),
            "namespace": self.namespace,
            "files": sorted(stix_files, reverse=True) # Newest first
        }
        
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)
        print(f"✓ Manifest Updated: {len(stix_files)} nodes indexed.")

    def create_bundle(self, title: str, iocs: Dict[str, List[str]], risk_score: float) -> str:
        """Generates a machine-readable STIX 2.1 JSON bundle and saves it."""
        self._ensure_dir()
        bundle_id = f"bundle--{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        objects = []
        
        # 1. Identity Object (The Creator)
        identity_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "name": "CyberDudeBivash Sentinel APEX",
            "identity_class": "organization",
            "created": timestamp,
            "modified": timestamp
        })

        # 2. Indicator Objects
        for ioc_type, values in iocs.items():
            for val in values:
                # Standard STIX 2.1 Patterning
                if ioc_type == "ipv4":
                    pattern = f"[ipv4-addr:value = '{val}']"
                elif ioc_type == "url":
                    pattern = f"[url:value = '{val}']"
                elif "sha" in ioc_type or "md5" in ioc_type:
                    pattern = f"[file:hashes.'{ioc_type.upper()}' = '{val}']"
                else:
                    pattern = f"[{ioc_type}:value = '{val}']"

                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "name": f"Extracted {ioc_type} from {title}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                    "confidence": int(risk_score * 10),
                    "created_by_ref": identity_id
                })

        # 3. Report Object (The Container)
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": title,
            "description": f"Automated threat triage report with risk score {risk_score}",
            "published": timestamp,
            "object_refs": [obj["id"] for obj in objects],
            "created_by_ref": identity_id
        })

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
        
        # Save unique file
        filename = f"CDB-APEX-{int(datetime.now().timestamp())}.json"
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump(bundle, f, indent=4)
        
        # Update the registry for the landing page
        self.update_manifest()
        
        return json.dumps(bundle, indent=4)

# Global Instance
stix_exporter = STIXExporter()
