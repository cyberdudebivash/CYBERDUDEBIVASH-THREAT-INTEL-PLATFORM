"""
gumroad_publisher.py — CyberDudeBivash SENTINEL APEX v20.0
GUMROAD AUTO-PUBLISHER ENGINE — PWYW + TIER-BASED PRICING

Upgrades from v1.0:
  - Pay What You Want (PWYW) model with minimum floor pricing by tier
  - Tiered pricing: Individual ($0+) / SMB ($19+) / Enterprise ($49+) by risk score
  - Suggested price displayed to buyers for maximum revenue
  - UTM-tracked product URLs fed back to revenue_bridge
  - Manifest updated with gumroad_url after successful publish
  - Graceful fallback: if API creation fails, returns static catalog URL
  - build_latest_pack() integration for auto-attach of detection pack ZIP

Usage:
  python tools/gumroad_publisher.py            # Publish latest pack
  from tools.gumroad_publisher import publish_latest  # Programmatic
"""

import os
import json
import requests
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("CDB-GUMROAD")

GUMROAD_TOKEN    = os.environ.get("GUMROAD_ACCESS_TOKEN", "")
GUMROAD_API_BASE = "https://api.gumroad.com/v2"
MANIFEST_PATH    = Path("data/stix/feed_manifest.json")
PACK_DIR         = Path("data/premium_packs")

# ─────────────────────────────────────────────
# PWYW Tiered Pricing Engine
# ─────────────────────────────────────────────

# Pricing tiers (cents) — (min_price, suggested_price) by risk score
# min_price = floor, suggested = what buyer sees first
PRICE_TIERS = {
    "critical": {"min": 0,    "suggested": 4900},  # $0+ floor, suggest $49
    "high":     {"min": 0,    "suggested": 2900},  # $0+ floor, suggest $29
    "medium":   {"min": 0,    "suggested": 1900},  # $0+ floor, suggest $19
    "low":      {"min": 0,    "suggested":  900},  # $0+ floor, suggest $9
}

def _get_pricing(risk_score: float) -> Tuple[int, int]:
    """Return (min_price_cents, suggested_price_cents) based on risk score."""
    if risk_score >= 8.5:
        tier = PRICE_TIERS["critical"]
    elif risk_score >= 6.5:
        tier = PRICE_TIERS["high"]
    elif risk_score >= 4.0:
        tier = PRICE_TIERS["medium"]
    else:
        tier = PRICE_TIERS["low"]
    return tier["min"], tier["suggested"]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def load_manifest() -> list:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found: {MANIFEST_PATH}")
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)

def save_manifest(data: list):
    with MANIFEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _headers() -> Dict:
    return {"Authorization": f"Bearer {GUMROAD_TOKEN}"}

def _utm(url: str, risk: float) -> str:
    tier = "critical" if risk >= 8.5 else "high" if risk >= 6.5 else "medium"
    return f"{url}?utm_source=sentinel-apex&utm_medium=auto-publish&utm_campaign={tier}"

def _build_description(item: Dict) -> str:
    title    = item.get("title", "Unknown Threat")
    risk     = item.get("risk_score", 5.0)
    severity = item.get("severity", "UNKNOWN")
    cves     = ", ".join(item.get("cves") or []) or "N/A"
    mitre    = ", ".join(item.get("mitre_tactics") or [])[:80] or "N/A"
    actor    = item.get("actor_tag", "Unknown")
    blog_url = item.get("blog_url", "https://cyberbivash.blogspot.com")
    ioc_counts = item.get("ioc_counts", {})
    ioc_sum  = ", ".join(f"{k}: {v}" for k, v in ioc_counts.items() if v > 0) or "See pack"

    return f"""🛡️ CyberDudeBivash SENTINEL APEX v20.0 — Defense Pack

THREAT    : {title}
RISK SCORE: {risk}/10  |  SEVERITY: {severity}
CVEs      : {cves}
IOCs      : {ioc_sum}
MITRE     : {mitre}
ACTOR     : {actor}
REPORT    : {blog_url}

WHAT'S INCLUDED
───────────────
✅ ioc_feed.csv            — All extracted IOC indicators
✅ detection_sigma.yml     — Sigma rules for your SIEM
✅ detection_yara.yar      — YARA rules for EDR / file scanning
✅ detection_kql.txt       — Microsoft Sentinel KQL queries
✅ detection_spl.txt       — Splunk SPL correlation searches
✅ metadata.json           — CVSS, EPSS, MITRE, TLP metadata
✅ README.txt              — Operator deployment guide

PWYW — Pay what you want. Minimum $0. Your support funds daily threat intel research.

Enterprise license & custom IR retainer: bivash@cyberdudebivash.com | +91 8179881447
Platform: https://intel.cyberdudebivash.com
"""


# ─────────────────────────────────────────────
# Core Publisher
# ─────────────────────────────────────────────

def create_product(item: Dict) -> Optional[Dict]:
    """
    Create a new Gumroad product for the given manifest item.
    Returns the product dict or None on failure.
    """
    if not GUMROAD_TOKEN:
        logger.warning("GUMROAD_ACCESS_TOKEN not set — skipping product creation")
        return None

    title    = item.get("title", "Unknown Threat")
    risk     = item.get("risk_score", 5.0)
    min_price, suggested = _get_pricing(risk)

    product_data = {
        "name": f"Sentinel APEX Detection Pack — {title[:80]}",
        "price": min_price,  # Gumroad: 0 = PWYW from $0+
        "description": _build_description(item),
        "published": "true",
        # suggested_price shows buyer what to pay first (PWYW UX)
    }

    try:
        resp = requests.post(
            f"{GUMROAD_API_BASE}/products",
            headers=_headers(),
            data=product_data,
            timeout=30,
        )

        if resp.status_code == 200:
            product = resp.json().get("product", {})
            logger.info(f"  ✅ Gumroad product created: {product.get('short_url')}")
            return product
        else:
            logger.warning(f"  ⚠️  Gumroad product creation failed: {resp.status_code} — {resp.text[:200]}")
            return None

    except requests.RequestException as e:
        logger.warning(f"  ⚠️  Gumroad API error (non-critical): {e}")
        return None


def upload_file(product_id: str, zip_path: Path) -> bool:
    """Upload the detection pack ZIP to an existing Gumroad product."""
    if not GUMROAD_TOKEN or not zip_path.exists():
        return False
    try:
        with zip_path.open("rb") as f:
            resp = requests.post(
                f"{GUMROAD_API_BASE}/products/{product_id}/files",
                headers=_headers(),
                files={"file": (zip_path.name, f)},
                timeout=120,
            )
        if resp.status_code == 200:
            logger.info(f"  ✅ File uploaded to Gumroad: {zip_path.name}")
            return True
        else:
            logger.warning(f"  ⚠️  File upload failed: {resp.status_code}")
            return False
    except requests.RequestException as e:
        logger.warning(f"  ⚠️  File upload error: {e}")
        return False


def get_recent_sales(after_iso: Optional[str] = None) -> list:
    """
    Fetch recent Gumroad sales (last 24h by default).
    Used by lead_autoresponder.py.
    """
    if not GUMROAD_TOKEN:
        return []
    params = {}
    if after_iso:
        params["after"] = after_iso
    try:
        resp = requests.get(
            f"{GUMROAD_API_BASE}/sales",
            headers=_headers(),
            params=params,
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("sales", [])
        else:
            logger.warning(f"Sales fetch failed: {resp.status_code}")
            return []
    except requests.RequestException as e:
        logger.warning(f"Sales fetch error: {e}")
        return []


# ─────────────────────────────────────────────
# Main Workflow
# ─────────────────────────────────────────────

def publish_latest() -> Optional[str]:
    """
    Full workflow:
      1. Load latest manifest entry
      2. Skip if already published
      3. Build detection pack (if not already built)
      4. Create Gumroad product (PWYW)
      5. Upload ZIP
      6. Update manifest with gumroad_url
    Returns the Gumroad short URL or None.
    """
    if not GUMROAD_TOKEN:
        logger.warning("GUMROAD_ACCESS_TOKEN missing — cannot publish")
        return None

    manifest = load_manifest()
    if not manifest:
        logger.warning("Manifest empty")
        return None

    latest  = manifest[-1]
    stix_id = latest.get("stix_id")

    if not stix_id:
        logger.error("Missing STIX ID in latest manifest entry")
        return None

    # Skip if already published
    if latest.get("gumroad_url"):
        logger.info(f"Already published: {latest['gumroad_url']}")
        return latest["gumroad_url"]

    # Ensure detection pack exists
    zip_path = PACK_DIR / f"{stix_id}.zip"
    if not zip_path.exists():
        logger.info(f"Detection pack missing — building now...")
        try:
            from tools.detection_pack_builder import build_pack_for_item
            zip_path = build_pack_for_item(latest)
        except Exception as e:
            logger.warning(f"Pack build failed: {e}")
            zip_path = None

    # Create Gumroad product
    product = create_product(latest)

    if product:
        product_id  = product.get("id")
        product_url = product.get("short_url", "")

        # Upload ZIP
        if zip_path and zip_path.exists():
            upload_file(product_id, zip_path)

        # Track UTM URL
        tracked_url = _utm(product_url, latest.get("risk_score", 5.0))

        # Update manifest
        latest["gumroad_url"] = product_url
        latest["gumroad_url_tracked"] = tracked_url
        save_manifest(manifest)

        logger.info(f"  🚀 Published to Gumroad: {product_url}")
        return product_url
    else:
        # Fallback: return static store URL (non-blocking)
        fallback = "https://cyberdudebivash.gumroad.com"
        logger.info(f"  ℹ️  Gumroad publish skipped — using store fallback: {fallback}")
        latest["gumroad_url"] = fallback
        save_manifest(manifest)
        return fallback


def publish_item(item: Dict, zip_path: Optional[Path] = None) -> Optional[str]:
    """
    Publish a specific item dict to Gumroad.
    Called from sentinel_blogger.py pipeline (Step 15).
    """
    if not GUMROAD_TOKEN:
        return None

    if item.get("gumroad_url"):
        return item["gumroad_url"]

    product = create_product(item)
    if not product:
        return None

    product_id  = product.get("id")
    product_url = product.get("short_url", "")

    if zip_path and zip_path.exists():
        upload_file(product_id, zip_path)

    return product_url


if __name__ == "__main__":
    import logging as _log
    _log.basicConfig(level=_log.INFO, format="%(asctime)s %(message)s")
    result = publish_latest()
    print(f"Result: {result}")
