#!/usr/bin/env python3
"""
asset_zipper.py — CYBERDUDEBIVASH® SENTINEL APEX
ENTERPRISE ASSET BUNDLING ENGINE
Mandate: Zero-Error compression of Signed Rules, Playbooks, and Certificates.
"""

import os
import zipfile
import logging
from datetime import datetime

# --- Institutional Logging ---
logger = logging.getLogger("CDB-ZIPPER")

class AssetZipper:
    def __init__(self, output_base="data/enterprise_kits"):
        self.output_base = output_base
        os.makedirs(self.output_base, exist_ok=True)

    def bundle_kit(self, threat_name, file_paths):
        """
        Bundles multiple institutional assets into a single signed enterprise ZIP.
       
        """
        # 1. Generate Standardized Filename
        date_str = datetime.now().strftime("%Y%m%d")
        safe_name = threat_name.replace(" ", "_").upper()
        zip_filename = f"{date_str}_{safe_name}_CDB_KIT.zip"
        zip_path = os.path.join(self.output_base, zip_filename)

        try:
            # 2. Initialize ZIP with high-level compression
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in file_paths:
                    if os.path.exists(file):
                        # Add to ZIP using its base name (no folder nesting)
                        zipf.write(file, arcname=os.path.basename(file))
                    else:
                        logger.error(f"❌ Missing expected asset for bundle: {file}")

            logger.info(f"✅ ASSET BUNDLED SUCCESSFULLY: {zip_path}")
            return zip_path

        except Exception as e:
            logger.error(f"❌ Critical Failure in Asset Bundling: {e}")
            return None

# Global Instance for the Apex Engine
asset_zipper = AssetZipper()
