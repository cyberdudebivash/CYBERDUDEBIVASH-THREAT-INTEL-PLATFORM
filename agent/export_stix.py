import json
import uuid
import os
from datetime import datetime

class STIXExporter:
    def __init__(self, output_dir="data/stix"):
        self.output_dir = output_dir
        self.manifest_path = os.path.join(output_dir, "feed_manifest.json")
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)

    def create_bundle(self, title, iocs, risk_score, metadata):
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        bundle_id = f"bundle--{uuid.uuid4()}"
        
        # Institutional Intrusion Set Mapping
        objects = [{
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": f"intrusion-set--{uuid.uuid4()}",
            "name": "UNC-CDB-99 (Lumma Cluster)",
            "description": "Tactical cluster weaponizing CSP infrastructure.",
            "created": timestamp, "modified": timestamp
        }]

        # Final Fix: Sync Manifest with list-validation
        self._update_manifest(title, bundle_id, risk_score, metadata.get('blog_url'))
        return bundle_id

    def _update_manifest(self, title, stix_id, risk_score, blog_url):
        manifest = []
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r') as f:
                    data = json.load(f)
                    manifest = data if isinstance(data, list) else [] # Fix for AttributeError
            except: manifest = []

        manifest.append({
            "title": title, "stix_id": stix_id, "risk_score": float(risk_score),
            "blog_url": blog_url, "timestamp": datetime.utcnow().isoformat()
        })

        with open(self.manifest_path, 'w') as f:
            json.dump(manifest[-10:], f, indent=4)

stix_exporter = STIXExporter()
