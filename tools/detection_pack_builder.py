"""
CyberDudeBivash Sentinel APEX
Detection Pack Builder Engine
Production v1.0
"""

import os
import json
import zipfile
from datetime import datetime
from pathlib import Path

MANIFEST_PATH = Path("data/stix/feed_manifest.json")
OUTPUT_DIR = Path("data/premium_packs")


# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def load_manifest():
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError("Manifest not found.")
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def already_built(stix_id: str):
    return (OUTPUT_DIR / f"{stix_id}.zip").exists()


# ─────────────────────────────────────────────
# Detection Artifact Generators
# ─────────────────────────────────────────────

def generate_ioc_csv(item, pack_dir: Path):
    file_path = pack_dir / "ioc_feed.csv"

    with file_path.open("w", encoding="utf-8") as f:
        f.write("indicator_type,value\n")

        indicators = item.get("indicators", [])
        for ioc in indicators:
            f.write(f"{ioc.get('type','unknown')},{ioc.get('value','')}\n")

        # fallback for count-based manifests
        if not indicators and item.get("ioc_counts"):
            for key, count in item["ioc_counts"].items():
                f.write(f"{key},{count}\n")


def generate_sigma_rule(item, pack_dir: Path):
    content = f"""title: {item.get('title')}
id: {item.get('stix_id')}
status: experimental
description: Detection rule generated from Sentinel APEX intelligence
author: CyberDudeBivash Sentinel APEX
date: {datetime.utcnow().date()}
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
falsepositives:
  - Unknown
level: high
"""

    (pack_dir / "detection_sigma.yml").write_text(content, encoding="utf-8")


def generate_kql_rule(item, pack_dir: Path):
    content = f"""// Sentinel APEX KQL Detection
// Threat: {item.get('title')}

SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 1
"""

    (pack_dir / "detection_kql.txt").write_text(content, encoding="utf-8")


def generate_spl_rule(item, pack_dir: Path):
    content = f"""# Splunk SPL Detection
# Threat: {item.get('title')}

index=security EventCode=1
| stats count by host, user
"""

    (pack_dir / "detection_spl.txt").write_text(content, encoding="utf-8")


def generate_metadata(item, pack_dir: Path):
    metadata = {
        "title": item.get("title"),
        "stix_id": item.get("stix_id"),
        "risk_score": item.get("risk_score"),
        "confidence_score": item.get("confidence_score"),
        "generated_utc": datetime.utcnow().isoformat(),
        "source": "CyberDudeBivash Sentinel APEX"
    }

    with (pack_dir / "metadata.json").open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def generate_readme(item, pack_dir: Path):
    content = f"""
CyberDudeBivash Sentinel APEX Detection Pack

Threat Title: {item.get('title')}
STIX ID: {item.get('stix_id')}
Risk Score: {item.get('risk_score')}/10
Confidence: {item.get('confidence_score', 'N/A')}%

Generated: {datetime.utcnow().isoformat()} UTC

Includes:
• IOC CSV Feed
• Sigma Detection Rule
• Microsoft Sentinel KQL Query
• Splunk SPL Query
• Metadata JSON

License: Enterprise Defensive Use Only
"""

    (pack_dir / "README.txt").write_text(content, encoding="utf-8")


# ─────────────────────────────────────────────
# Pack Builder
# ─────────────────────────────────────────────

def zip_pack(stix_id: str, pack_dir: Path):
    zip_path = OUTPUT_DIR / f"{stix_id}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for file in pack_dir.iterdir():
            z.write(file, file.name)

    return zip_path


def build_latest_pack():
    ensure_directory(OUTPUT_DIR)

    manifest = load_manifest()
    if not manifest:
        print("Manifest empty.")
        return

    latest = manifest[-1]
    stix_id = latest.get("stix_id")

    if not stix_id:
        raise ValueError("Missing STIX ID.")

    if already_built(stix_id):
        print("Detection pack already exists. Skipping.")
        return

    pack_dir = OUTPUT_DIR / stix_id
    ensure_directory(pack_dir)

    generate_ioc_csv(latest, pack_dir)
    generate_sigma_rule(latest, pack_dir)
    generate_kql_rule(latest, pack_dir)
    generate_spl_rule(latest, pack_dir)
    generate_metadata(latest, pack_dir)
    generate_readme(latest, pack_dir)

    zip_path = zip_pack(stix_id, pack_dir)

    print(f"Detection pack generated: {zip_path}")


if __name__ == "__main__":
    build_latest_pack()
