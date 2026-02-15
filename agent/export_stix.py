#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v10.1 (APEX ELITE)
Standard: STIX 2.1 Final Production Logic for GOC Interoperability.
"""
import json
import uuid
import logging
from datetime import datetime

logger = logging.getLogger("CDB-STIX")

class STIXExporter:
    def __init__(self, output_dir="data/stix"):
        self.output_dir = output_dir
        self.manifest_path = f"{output_dir}/feed_manifest.json"

    def create_bundle(self, title, iocs, risk_score, metadata):
        """
        Serializes forensic data into STIX 2.1 SDOs (Shared Data Objects).
        """
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        bundle_id = f"bundle--{uuid.uuid4()}"
        
        # 1. Create the primary Intrusion Set (UNC-CDB-99)
        intrusion_set = {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": f"intrusion-set--{uuid.uuid4()}",
            "name": "UNC-CDB-99 (Lumma Cluster)",
            "created": timestamp,
            "modified": timestamp,
            "description": "High-fidelity cluster weaponizing Google Groups for credential exfiltration.",
            "confidence": 98
        }

        # 2. Map Indicators to STIX Observables
        objects = [intrusion_set]
        
        # Mapping Google Groups to URL Indicators
        for group in iocs.get('google_groups', []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "indicator_types": ["malicious-activity"],
                "pattern": f"[url:value = '{group}']",
                "pattern_type": "stix",
                "valid_from": timestamp
            })

        # Mapping Registry Keys to Windows Registry Patterns
        for reg in iocs.get('registry_keys', []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "pattern": f"[windows-registry-key:key = '{reg.replace('\\', '\\\\')}']",
                "pattern_type": "stix",
                "valid_from": timestamp
            })

        # 3. Finalize Bundle and Update GOC Manifest
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

        # Save individual STIX file
        stix_filename = f"{self.output_dir}/stix_{int(datetime.utcnow().timestamp())}.json"
        with open(stix_filename, 'w') as f:
            json.dump(bundle, f, indent=4)

        # Update the live manifest for the Sentinel Apex Dashboard
        self._update_manifest(title, bundle_id, risk_score, metadata.get('blog_url'))
        return bundle_id

    def _update_manifest(self, title, stix_id, risk_score, blog_url):
        """Synchronizes the dashboard feed manifest."""
        manifest = []
        try:
            with open(self.manifest_path, 'r') as f:
                manifest = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        manifest.append({
            "title": title,
            "stix_id": stix_id,
            "risk_score": risk_score,
            "blog_url": blog_url,
            "timestamp": datetime.utcnow().isoformat()
        })

        # Keep manifest optimized for landing page performance (Last 10 nodes)
        with open(self.manifest_path, 'w') as f:
            json.dump(manifest[-10:], f, indent=4)

stix_exporter = STIXExporter()
