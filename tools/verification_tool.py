#!/usr/bin/env python3
"""
================================================================================
TOOL:       CYBERDUDEBIVASH® SENTINEL VERIFIER
VERSION:    v1.0 (Enterprise Edition)
AUTHORITY:  CYBERDUDEBIVASH PVT LTD
PURPOSE:    Cryptographic Integrity & Authenticity Verification
COPYRIGHT:  © 2026 CYBERDUDEBIVASH PVT LTD. ALL RIGHTS RESERVED.
================================================================================
"""

import sys
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# --- Institutional Logging ---
logging.basicConfig(level=logging.INFO, format="[CDB-VERIFIER] %(message)s")
logger = logging.getLogger("CDB-VERIFIER")

class SentinelVerifier:
    def __init__(self, public_key_path="cdb_public_key.pem"):
        self.public_key_path = public_key_path

    def verify_asset(self, content_path: str, signature_hex: str) -> bool:
        """
        Verifies the authenticity of a technical asset using the CDB Public Key.
        Returns True if the asset is genuine and untampered.
        """
        try:
            # 1. Load the Authority Public Key
            with open(self.public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            # 2. Read the Asset Content
            with open(content_path, "rb") as f:
                asset_content = f.read()

            # 3. Convert Hex Signature to Bytes
            signature = bytes.fromhex(signature_hex)

            # 4. Cryptographic Validation (RSA-2048 + SHA256 + PSS)
            public_key.verify(
                signature,
                asset_content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info("✅ VERIFICATION SUCCESS: Asset is authentic and untampered.")
            return True

        except Exception as e:
            logger.error(f"❌ VERIFICATION FAILED: {e}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verification_tool.py <path_to_file> <hex_signature>")
        sys.exit(1)

    verifier = SentinelVerifier()
    verifier.verify_asset(sys.argv[1], sys.argv[2])
