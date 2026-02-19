import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

class SovereigntyEngine:
    """
    CYBERDUDEBIVASH® SOVEREIGNTY ENGINE
    Mandate: Cryptographic Proof of Ownership for all Technical Assets.
    """
    def __init__(self, key_path="secrets/cdb_sovereign.pem"):
        self.key_path = key_path
        self._ensure_keys()

    def _ensure_keys(self):
        """Generates the master sovereign key if not present."""
        if not os.path.exists(self.key_path):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(self.key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

    def sign_asset(self, asset_content: str) -> str:
        """Signs the technical asset with the CyberDudeBivash master key."""
        with open(self.key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        
        signature = private_key.sign(
            asset_content.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature.hex()

# Master Sovereignty Instance
sovereign_engine = SovereigntyEngine()
