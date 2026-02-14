#!/usr/bin/env python3
"""
export_stix.py — CyberDudeBivash v1.0
Intelligence Portability: Generating STIX 2.1 Standardized Threat Data.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List

class STIXExporter:
    def __init__(self):
        self.namespace = "cyberdudebivash-sentinel"

    def create_bundle(self, title: str, iocs: Dict[str, List[str]], risk_score: float) -> str:
        """Generates a machine-readable STIX 2.1 JSON bundle."""
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
                pattern = f"[{ioc_type}:value = '{val}']"
                if ioc_type == "ipv4":
                    pattern = f"[ipv4-addr:value = '{val}']"
                elif "sha" in ioc_type or "md5" in ioc_type:
                    pattern = f"[file:hashes.'{ioc_type.upper()}' = '{val}']"

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
        
        return json.dumps(bundle, indent=4)

# Global Instance
stix_exporter = STIXExporter()
