#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v10.1 (APEX ELITE)
FINAL PRODUCTION FIX: Resolves AttributeError 'dict' has no attribute 'append'
"""
import json
import uuid
import logging
import os
from datetime import datetime

# Institutional Branding for GOC Logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-STIX] %(message)s")
logger = logging.getLogger("CDB-STIX")

class STIXExporter:
    def __init__(self, output_dir="data/stix"):
        self.output_dir = output_dir
        self.manifest_path = os.path.join(output_dir, "feed_manifest.json")
        # Ensure forensic directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def create_bundle(self, title, iocs, risk_score, metadata):
        """Serializes forensic data into STIX 2.1 SDOs."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        bundle_id = f"bundle--{uuid.uuid4()}"
        
        # 1. Intrusion Set Mapping (UNC-CDB-99)
        objects = [{
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": f"intrusion-set--{uuid.uuid4()}",
            "name": "UNC-CDB-99 (Lumma Cluster)",
            "created": timestamp,
            "modified": timestamp,
            "description": "Cluster weaponizing Google Groups infrastructure.",
            "confidence": 98
        }]

        # 2. Forensic Indicator Mapping
        for group in iocs.get('google_groups', []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "pattern": f"[url:value = '{group}']",
                "pattern_type": "stix",
                "valid_from": timestamp
            })

        # 3. Finalize Bundle
        bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
        stix_filename = os.path.join(self.output_dir, f"stix_{int(datetime.utcnow().timestamp())}.json")
        
        with open(stix_filename, 'w') as f:
            json.dump(bundle, f, indent=4)

        # 4. CRITICAL FIX: Synchronize GOC Manifest
        self._update_manifest(title, bundle_id, risk_score, metadata.get('blog_url'))
        return bundle_id

    def _update_manifest(self, title, stix_id, risk_score, blog_url):
        """
        Logic-hardened manifest updater. 
        Resolves AttributeError by enforcing list-type validation.
        """
        manifest = []
        
        # Attempt to load existing manifest
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r') as f:
                    data = json.load(f)
                    # CRITICAL FIX: Verify data type before appending
                    if isinstance(data, list):
                        manifest = data
                    else:
                        logger.warning("Manifest was dictionary. Re-initializing as list.")
                        manifest = []
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Manifest corruption detected: {e}. Resetting.")
                manifest = []

        # Secure Append
        new_entry = {
            "title": title,
            "stix_id": stix_id,
            "risk_score": float(risk_score),
            "blog_url": blog_url,
            "timestamp": datetime.utcnow().isoformat()
        }
        manifest.append(new_entry)

        # Keep manifest optimized for Dashboard performance (Last 10 nodes)
        with open(self.manifest_path, 'w') as f:
            json.dump(manifest[-10:], f, indent=4)
        logger.info(f"✓ GOC Manifest Synchronized: {title}")

stix_exporter = STIXExporter()
