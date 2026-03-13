"""
IOC Export Module (STIX 2.1 + MISP)
FINAL • PRODUCTION • INTERFACE-HARDENED

This module guarantees stable IOC export functions
expected by all orchestrators.
"""

from datetime import datetime, timezone
from typing import List, Dict
import json
import os


# =================================================
# UTILS
# =================================================

EXPORT_DIR = "exports"
os.makedirs(EXPORT_DIR, exist_ok=True)


def _utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


# =================================================
# STIX EXPORT
# =================================================

def _build_stix_bundle(cves: List[Dict], malware_items: List[Dict]) -> Dict:
    objects = []

    for cve in cves:
        if not cve.get("id"):
            continue
        objects.append({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{cve['id'].lower()}",
            "name": cve["id"],
            "description": cve.get("description", ""),
        })

    for malware in malware_items:
        objects.append({
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{malware.get('family','unknown').lower()}",
            "name": malware.get("family", "Unknown"),
            "is_family": True,
        })

    return {
        "type": "bundle",
        "id": f"bundle--cdb-{_utc_date()}",
        "objects": objects,
    }


def export_stix_bundle(
    cves: List[Dict],
    malware_items: List[Dict],
) -> str:
    """
    PRIMARY PUBLIC API
    Export IOC data as a STIX 2.1 bundle.
    """

    try:
        bundle = _build_stix_bundle(cves, malware_items)
        path = os.path.join(
            EXPORT_DIR, f"cdb_iocs_{_utc_date()}.stix.json"
        )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

        print(f"📦 STIX exported → {path}")
        return path

    except Exception as exc:
        print(f"⚠️ STIX export failed: {exc}")
        return ""


# =================================================
# MISP EXPORT
# =================================================

def export_misp_event(
    cves: List[Dict],
    malware_items: List[Dict],
) -> str:
    """
    PRIMARY PUBLIC API
    Export IOC data in a MISP-compatible structure.
    """

    try:
        event = {
            "info": "CyberDudeBivash Daily Threat Intelligence",
            "date": _utc_date(),
            "attributes": [],
        }

        for cve in cves:
            if cve.get("id"):
                event["attributes"].append({
                    "type": "vulnerability",
                    "value": cve["id"],
                })

        for malware in malware_items:
            if malware.get("family"):
                event["attributes"].append({
                    "type": "malware-family",
                    "value": malware["family"],
                })

        path = os.path.join(
            EXPORT_DIR, f"cdb_iocs_{_utc_date()}.misp.json"
        )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2)

        print(f"📦 MISP exported → {path}")
        return path

    except Exception as exc:
        print(f"⚠️ MISP export failed: {exc}")
        return ""


# =================================================
# BACKWARD-COMPATIBILITY ALIASES
# =================================================
# These prevent future import breakage
# =================================================

def export_stix(cves: List[Dict], malware_items: List[Dict]) -> str:
    return export_stix_bundle(cves, malware_items)


def export_misp(cves: List[Dict], malware_items: List[Dict]) -> str:
    return export_misp_event(cves, malware_items)
