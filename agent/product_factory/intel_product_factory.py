#!/usr/bin/env python3
"""
intel_product_factory.py — CYBERDUDEBIVASH® SENTINEL APEX v45.0
CENTRAL ASSEMBLY LINE ORCHESTRATOR
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

import logging
from agent.product_factory.detection_pack_builder import DETECTION_BUILDER
from agent.product_factory.ioc_bundle_builder import IOC_BUILDER
from agent.product_factory.soc_playbook_generator import PLAYBOOK_GEN
from agent.revenue_engine import REVENUE_CORE

class IntelProductFactory:
    def __init__(self):
        self.authority = "CYBERDUDEBIVASH OFFICIAL AUTHORITY"

    def run_assembly_line(self):
        """Orchestrates the creation of all sellable assets."""
        print("🏭 v45.0 PRODUCT FACTORY: STARTING ASSEMBLY LINE...")
        
        # 1. Build Detection Packs
        det_result = DETECTION_BUILDER.build_pack(tier="enterprise")
        
        # 2. Build IOC Bundles
        ioc_result = IOC_BUILDER.generate_bundle(format="json")
        
        # 3. Generate Sample Playbook
        pb_path = PLAYBOOK_GEN.generate_for_threat("Ransomware", "Lazarus-Variant")

        print(f"✅ Assembly Complete: {det_result['product_id']} created.")
        
        # Log event for Revenue Analytics
        # Metadata will be consumed by Premium API to serve latest downloads
        return {
            "detections": det_result,
            "iocs": ioc_result,
            "playbooks": pb_path
        }

if __name__ == "__main__":
    factory = IntelProductFactory()
    factory.run_assembly_line()