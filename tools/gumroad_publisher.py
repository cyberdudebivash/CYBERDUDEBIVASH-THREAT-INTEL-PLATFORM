"""
CyberDudeBivash Sentinel APEX
Gumroad Auto Publisher Engine
Production v1.0
"""

import os
import json
import requests
from pathlib import Path

GUMROAD_TOKEN = os.environ.get("GUMROAD_ACCESS_TOKEN")

MANIFEST_PATH = Path("data/stix/feed_manifest.json")
PACK_DIR = Path("data/premium_packs")

GUMROAD_API = "https://api.gumroad.com/v2/products"


# ─────────────────────────────────────────────

def load_manifest():
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_manifest(data):
    with MANIFEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def determine_price(score):
    if score >= 9:
        return 4900
    elif score >= 7:
        return 2900
    return 1900


def publish_latest():
    if not GUMROAD_TOKEN:
        raise RuntimeError("Missing GUMROAD_ACCESS_TOKEN")

    manifest = load_manifest()
    if not manifest:
        print("Manifest empty.")
        return

    latest = manifest[-1]

    if latest.get("gumroad_url"):
        print("Already published.")
        return

    stix_id = latest.get("stix_id")
    zip_path = PACK_DIR / f"{stix_id}.zip"

    if not zip_path.exists():
        print("Detection pack missing.")
        return

    price = determine_price(latest.get("risk_score", 5))

    with zip_path.open("rb") as f:
        files = {"file": (zip_path.name, f)}

        payload = {
            "access_token": GUMROAD_TOKEN,
            "name": f"Sentinel APEX Detection Pack – {latest.get('title')}",
            "price": price,
            "description": f"""
CyberDudeBivash Sentinel APEX Detection Pack

Threat: {latest.get('title')}
Risk Score: {latest.get('risk_score')}/10

Includes:
• IOC Feed
• Sigma Detection
• Microsoft Sentinel KQL
• Splunk SPL
• SOC Guide

Generated automatically from Sentinel APEX.
""",
            "published": True
        }

        response = requests.post(GUMROAD_API, data=payload, files=files)

        if response.status_code != 200:
            raise RuntimeError(response.text)

        product_data = response.json()
        product_url = product_data["product"]["short_url"]

        latest["gumroad_url"] = product_url
        save_manifest(manifest)

        print(f"Published successfully: {product_url}")


if __name__ == "__main__":
    publish_latest()
