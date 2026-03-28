"""
CYBERDUDEBIVASH® SENTINEL APEX
QUANTUM-SAFE SECURITY PREPARATION ENGINE v1.0
Crypto agility framework, PQC readiness assessment, migration roadmap.
"""
import re, logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-QUANTUM")

# NIST PQC Standardized Algorithms (FIPS 203/204/205 - 2024)
PQC_ALGORITHMS = {
    "ML-KEM":     {"type": "KEM",       "standard": "FIPS 203", "status": "STANDARDIZED", "security_level": 3},
    "ML-DSA":     {"type": "Signature", "standard": "FIPS 204", "status": "STANDARDIZED", "security_level": 3},
    "SLH-DSA":    {"type": "Signature", "standard": "FIPS 205", "status": "STANDARDIZED", "security_level": 3},
    "FN-DSA":     {"type": "Signature", "standard": "FIPS 206", "status": "DRAFT",        "security_level": 3},
}

VULNERABLE_ALGORITHMS = {
    "RSA":        {"quantum_vulnerable": True,  "grover_speedup": False, "shor_vulnerable": True},
    "ECDSA":      {"quantum_vulnerable": True,  "grover_speedup": False, "shor_vulnerable": True},
    "ECDH":       {"quantum_vulnerable": True,  "grover_speedup": False, "shor_vulnerable": True},
    "DH":         {"quantum_vulnerable": True,  "grover_speedup": False, "shor_vulnerable": True},
    "DSA":        {"quantum_vulnerable": True,  "grover_speedup": False, "shor_vulnerable": True},
    "AES-128":    {"quantum_vulnerable": False, "grover_speedup": True,  "note": "Upgrade to AES-256"},
    "AES-256":    {"quantum_vulnerable": False, "grover_speedup": False, "note": "Quantum-safe"},
    "SHA-256":    {"quantum_vulnerable": False, "grover_speedup": True,  "note": "Use SHA-384 or SHA-512"},
    "SHA-384":    {"quantum_vulnerable": False, "grover_speedup": False, "note": "Quantum-safe"},
    "SHA-512":    {"quantum_vulnerable": False, "grover_speedup": False, "note": "Quantum-safe"},
}


MIGRATION_ROADMAP = [
    {"phase": 1, "timeline": "0-6 months",  "action": "Inventory all cryptographic assets",
     "priority": "CRITICAL", "effort": "LOW"},
    {"phase": 2, "timeline": "3-9 months",  "action": "Prioritize TLS/PKI infrastructure for migration",
     "priority": "CRITICAL", "effort": "HIGH"},
    {"phase": 3, "timeline": "6-18 months", "action": "Deploy hybrid PQC+classical certificates",
     "priority": "HIGH", "effort": "HIGH"},
    {"phase": 4, "timeline": "12-24 months","action": "Migrate code signing to ML-DSA",
     "priority": "HIGH", "effort": "MEDIUM"},
    {"phase": 5, "timeline": "18-36 months","action": "Full PQC migration for all systems",
     "priority": "MEDIUM", "effort": "VERY HIGH"},
]


class QuantumReadinessEngine:
    """
    Assesses quantum readiness and generates PQC migration roadmaps.
    Detects quantum-vulnerable cryptography in advisory text.
    """

    def __init__(self):
        self.assessments_done = 0

    def assess_advisory(self, advisory: Dict) -> Dict:
        """Detect quantum-vulnerable crypto references in advisory."""
        text = f"{advisory.get('title','')} {advisory.get('summary','')}".lower()
        vuln_algos_found = []
        safe_algos_found = []

        for algo, props in VULNERABLE_ALGORITHMS.items():
            if algo.lower() in text:
                if props["quantum_vulnerable"] or props.get("grover_speedup"):
                    vuln_algos_found.append({
                        "algorithm": algo,
                        "quantum_vulnerable": props["quantum_vulnerable"],
                        "grover_speedup": props.get("grover_speedup", False),
                        "note": props.get("note", ""),
                    })
                else:
                    safe_algos_found.append(algo)

        is_crypto_relevant = len(vuln_algos_found) > 0
        self.assessments_done += 1

        return {
            "advisory_id":           advisory.get("stix_id", ""),
            "is_crypto_relevant":    is_crypto_relevant,
            "vulnerable_algorithms": vuln_algos_found,
            "safe_algorithms":       safe_algos_found,
            "quantum_risk_level":    "HIGH" if vuln_algos_found else "LOW",
            "pqc_action_required":   is_crypto_relevant,
            "recommended_pqc": [
                {"replace": a["algorithm"], "with": "ML-KEM" if "RSA" in a["algorithm"] or "DH" in a["algorithm"]
                 else "ML-DSA", "standard": "FIPS 203/204"}
                for a in vuln_algos_found
            ],
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

    def generate_pqc_roadmap(self) -> Dict:
        """Generate organization-wide PQC migration roadmap."""
        return {
            "roadmap_version": "1.0",
            "nist_pqc_standards": PQC_ALGORITHMS,
            "vulnerable_algorithms_catalog": VULNERABLE_ALGORITHMS,
            "migration_phases": MIGRATION_ROADMAP,
            "immediate_actions": [
                "Begin cryptographic asset inventory",
                "Subscribe to NIST PQC migration guidance",
                "Test ML-KEM in non-production TLS environments",
                "Evaluate PQC-capable HSM vendors",
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_stats(self) -> Dict:
        return {"assessments_done": self.assessments_done, "engine": "QuantumReadinessEngine v1.0"}
