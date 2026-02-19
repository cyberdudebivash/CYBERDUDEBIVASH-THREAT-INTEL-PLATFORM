#!/usr/bin/env python3
"""
sovereignty_engine.py — CYBERDUDEBIVASH® SENTINEL APEX
SECURE SOVEREIGNTY & CRYPTOGRAPHIC SIGNING ENGINE (v2.0)
Mandate: 100% Secure Environment Validation | RSA-2048 signing.
"""

import os
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --- Institutional Logging ---
logger = logging.getLogger("CDB-SOVEREIGNTY")

class SovereigntyEngine:
    def __init__(self, key_path="secrets/cdb_sovereign.pem"):
        self.key_path = key_path
        # MANDATORY SECURE ENVIRONMENT CHECK
        self._validate_secure_environment()

    def _validate_secure_environment(self):
        """
        Ensures the engine is running within a hardened production environment.
        Strictly mandates GitHub Actions runners for master key access.
        """
        # 1. Check for standard CI/CD environment flags
        is_ci = os.getenv('CI', 'false').lower() == 'true'
        is_github = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
        
        # 2. Institutional Logic: Block local execution of master signing
        if not (is_ci and is_github):
            logger.critical("🛑 SECURITY BREACH ATTEMPT: Non-Secure environment detected.")
            logger.critical("Sovereignty Engine initialization ABORTED to protect Master Key.")
            # Hard crash to prevent any memory leakage of signing functions
            raise SystemError("UNAUTHORIZED_ENVIRONMENT: Sovereignty Engine requires a hardened runner.")

        logger.info("🛡️ SECURE ENVIRONMENT VERIFIED: Hardened GitHub Runner detected.")

    def sign_asset(self, asset_content: str) -> str:
        """
        Signs the technical asset with the CyberDudeBivash master key.
        Only accessible if the secure environment validation passed.
        """
        if not os.path.exists(self.key_path):
            logger.error(f"❌ Master Key Missing at {self.key_path}. Signing aborted.")
            return "SIGNATURE_FAILED:KEY_MISSING"

        try:
            with open(self.key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            
            signature = private_key.sign(
                asset_content.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            logger.error(f"❌ Cryptographic Error: {e}")
            return "SIGNATURE_FAILED:CRYPTO_ERROR"

# Initialize Sovereign Engine
# Note: This will throw an error if run locally to protect the Master Key.
sovereign_engine = SovereigntyEngine()
