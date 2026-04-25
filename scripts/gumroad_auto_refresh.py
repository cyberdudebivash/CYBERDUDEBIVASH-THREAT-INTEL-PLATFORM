#!/usr/bin/env python3
"""
scripts/gumroad_auto_refresh.py
CYBERDUDEBIVASH(R) SENTINEL APEX v141.0.0 -- Gumroad Auto Product Refresh
==========================================================================
AUTOMATED REVENUE ENGINE: Reads live feed -> generates detection rule pack
descriptions from today's top CVEs/threats -> calls Gumroad API to update
product descriptions with fresh threat coverage -> drives organic discovery
and conversion.

Runs via GitHub Actions cron (daily 08:30 UTC, after telegram_revenue_bot).

Revenue flows driven:
  1. Detection Pack listings auto-updated with LIVE threat coverage
  2. Fresh CVE names in product descriptions -> SEO/discoverability boost
  3. Active Sigma + YARA + KQL rule counts shown -> purchase confidence
  4. Urgency signals (KEV, P1) embedded in product copy -> conversion rate

Environment variables:
  GUMROAD_ACCESS_TOKEN   -- OAuth token from Gumroad account settings
  FEED_PATH              -- Path to feed.json (default: feed.json)
  GUMROAD_DRY_RUN        -- Set to "true" to log without API calls

Gumroad API v2 endpoints:
  GET  /v2/products              -- list all products
  PUT  /v2/products/:permalink   -- update description
  GET  /v2/sales                 -- fetch recent sales (metrics)

(c) 2026 CYBERDUDEBIVASH Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GUMROAD] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.gumroad_refresh")

# ── Constants ─────────────────────────────────────────────────────────────────
PLATFORM_URL   = "https://intel.cyberdudebivash.com"
STORE_URL      = f"{PLATFORM_URL}/store.html"
API_DOCS_URL   = f"{PLATFORM_URL}/api-docs.html"
GUMROAD_BASE   = "https://api.gumroad.com/v2"
GUMROAD_STORE  = "https://cyberdudebivash.gumroad.com"
MAX_DESC_CHARS = 3000  # Gumroad description limit

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}

# Detection pack product keywords to match against Gumroad product names
DETECTION_PACK_KEYWORDS = [
    "detection", "pack", "sigma", "yara", "kql", "rule", "hunt",
    "threat", "intel", "bundle", "soc", "siem",
]


# ── Gumroad API Layer ─────────────────────────────────────────────────────────
def gm_request(token: str, method: str, path: str,
               data: dict | None = None) -> dict:
    """Gumroad API v2 request. Returns parsed JSON dict."""
    url = f"{GUMROAD_BASE}{path}"
    body: bytes | None = None
    if data is not None:
        # Gumroad uses form-encoded PUT bodies
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")[:400]
        log.error("Gumroad %s %s HTTP %d: %s", method, path, e.code, err_body)
        return {"success": False, "error": f"HTTP {e.code}: {err_body}"}
    except Exception as e:
        log.error("Gumroad %s %s error: %s", method, path, e)
        return {"success": False, "error": str(e)}


def list_products(token: str) -> list[dict]:
    """Return all Gumroad products for this account."""
    resp = gm_request(token, "GET", "/products")
    if not resp.get("success"):
        log.warning("list_products failed: %s", resp.get("message", resp.get("error")))
        return []
    return resp.get("products", [])


def update_product_description(token: str, product_id: str,
                                description: str, dry_run: bool = False) -> bool:
    """Update a single product's description. Returns success bool."""
    if dry_run:
        log.info("[DRY RUN] Would update product %s (%d chars)", product_id, len(description))
        return True
    resp = gm_request(token, "PUT", f"/products/{product_id}", {
        "description": description,
    })
    ok = bool(resp.get("success"))
    if ok:
        log.info("Updated product %s OK", product_id)
    else:
        log.warning("Update product %s FAILED: %s", product_id,
                    resp.get("message", resp.get("error")))
    return ok


def fetch_recent_sales(token: str) -> dict[str, int]:
    """Returns {product_id: sale_count} for recent sales (metrics only)."""
    resp = gm_request(token, "GET", "/sales")
    if not resp.get("success"):
        return {}
    sales = resp.get("sales", [])
    counts: dict[str, int] = {}
    for s in sales:
        pid = s.get("product_id") or s.get("permalink", "")
        if pid:
            counts[pid] = counts.get(pid, 0) + 1
    return counts


# ── Feed Analysis ─────────────────────────────────────────────────────────────
def load_feed(feed_path: str = "feed.json") -> list[dict]:
    for candidate in (feed_path, "api/feed.json", "feed.json"):
        p = Path(candidate)
        if p.exists():
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("items", data.get("data", []))
    log.error("No feed.json found at %s or api/feed.json", feed_path)
    return []


def top_threats(feed: list[dict], n: int = 10) -> list[dict]:
    return sorted(feed, key=lambda x: float(x.get("risk_score", 0)), reverse=True)[:n]


def critical_kev(feed: list[dict]) -> list[dict]:
    return [i for i in feed
            if i.get("severity", "").upper() == "CRITICAL" and i.get("kev_present")]


def collect_ttp_stats(feed: list[dict]) -> dict[str, int]:
    freq: dict[str, int] = {}
    for item in feed:
        for t in item.get("ttps", []):
            if isinstance(t, str) and t.startswith("T"):
                freq[t] = freq.get(t, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: -x[1])[:10])


def collect_rule_stats(feed: list[dict]) -> dict[str, int]:
    """Count how many advisories have each rule type."""
    stats: dict[str, int] = {}
    rule_types = ("sigma", "yara", "kql", "spl", "eql")
    for item in feed:
        rules = item.get("detection_rules", {})
        if not isinstance(rules, dict):
            continue
        for rt in rule_types:
            if rules.get(rt) or rules.get(rt + "_rule") or rules.get(rt + "_rules"):
                stats[rt] = stats.get(rt, 0) + 1
    return stats


# ── Description Builder ───────────────────────────────────────────────────────
def is_detection_pack(product: dict) -> bool:
    """Heuristic: match products that are detection/threat rule packs."""
    name = (product.get("name") or "").lower()
    desc = (product.get("description") or "").lower()
    combined = name + " " + desc
    return any(kw in combined for kw in DETECTION_PACK_KEYWORDS)


def build_detection_pack_description(feed: list[dict], product: dict) -> str:
    """Generate a fresh, threat-driven product description for a detection pack."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%d %b %Y")
    threats = top_threats(feed, n=7)
    kevs = critical_kev(feed)[:3]
    total = len(feed)
    critical_count = sum(1 for i in feed if i.get("severity", "").upper() == "CRITICAL")
    kev_count = sum(1 for i in feed if i.get("kev_present"))
    rule_stats = collect_rule_stats(feed)
    ttp_stats = collect_ttp_stats(feed)
    product_name = product.get("name", "Detection Pack")

    sigma_n  = rule_stats.get("sigma", 0)
    yara_n   = rule_stats.get("yara", 0)
    kql_n    = rule_stats.get("kql", 0)
    spl_n    = rule_stats.get("spl", 0)
    top_ttps = list(ttp_stats.keys())[:5]

    lines = [
        f"## {product_name}",
        f"**Last updated: {date_str} — Live threat data refreshed daily by SENTINEL APEX**\n",
        "---\n",
        "### What's Inside",
        (
            f"This pack covers **{total} advisories** sourced and enriched today, "
            f"including **{critical_count} Critical** severity threats and "
            f"**{kev_count} CISA KEV** entries with confirmed active exploitation.\n"
        ),
        "**Detection rule coverage:**",
    ]

    if sigma_n:
        lines.append(f"- **Sigma** rules: {sigma_n} advisories covered (SIEM-agnostic)")
    if yara_n:
        lines.append(f"- **YARA** rules: {yara_n} advisories covered (malware/IOC hunting)")
    if kql_n:
        lines.append(f"- **KQL** rules: {kql_n} advisories covered (Microsoft Sentinel / Defender)")
    if spl_n:
        lines.append(f"- **SPL** rules: {spl_n} advisories covered (Splunk ES)")
    if not any([sigma_n, yara_n, kql_n, spl_n]):
        lines.append("- Full Sigma, YARA, KQL, and SPL rule sets included per advisory")

    lines += [
        "",
        "**MITRE ATT&CK coverage** (most active techniques today):",
    ]
    for ttp in top_ttps:
        lines.append(f"  `{ttp}`  (×{ttp_stats[ttp]} advisories)")

    lines += [
        "",
        "---\n",
        "### Today's Top Threats\n",
    ]

    for i, t in enumerate(threats[:7]):
        sev   = t.get("severity", "UNKNOWN").upper()
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        title = t.get("title", "Unknown Threat")[:65]
        risk  = t.get("risk_score", 0)
        kev   = " ⚡KEV" if t.get("kev_present") else ""
        iocs  = t.get("ioc_count", 0)
        lines.append(f"{emoji} **#{i+1}** {title} — Risk {risk}/10{kev} | {iocs} IOCs")

    if kevs:
        lines += [
            "",
            "---\n",
            "### ⚡ Active Exploitation (CISA KEV)\n",
        ]
        for item in kevs:
            title = item.get("title", "")[:70]
            cvss  = item.get("cvss_score") or "N/A"
            lines.append(f"🔴 **{title}** — CVSS {cvss}")

    lines += [
        "",
        "---\n",
        "### Who This Is For",
        (
            "- **SOC Analysts** deploying immediate detection rules to SIEM/EDR\n"
            "- **Threat Hunters** building hunt hypotheses from ATT&CK TTPs\n"
            "- **Security Engineers** updating detection engineering backlogs\n"
            "- **MSSPs** enriching client detection libraries at scale\n"
        ),
        "---\n",
        "### Delivery",
        (
            "Instant download upon purchase. All rules are production-ready, "
            "field-validated, and tested against MITRE ATT&CK v15 technique mapping. "
            "Free updates included — pack is refreshed every 24 hours."
        ),
        "",
        "---\n",
        f"_Powered by CYBERDUDEBIVASH® SENTINEL APEX v141.0.0 — {PLATFORM_URL}_",
        f"_Live dashboard: {PLATFORM_URL} | API: {API_DOCS_URL}_",
    ]

    description = "\n".join(lines)
    # Enforce Gumroad's character limit
    if len(description) > MAX_DESC_CHARS:
        description = description[:MAX_DESC_CHARS - 3] + "..."
    return description


def build_generic_description(feed: list[dict], product: dict) -> str:
    """Minimal refresh for non-detection-pack products: inject live stats only."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%d %b %Y")
    total = len(feed)
    critical_count = sum(1 for i in feed if i.get("severity", "").upper() == "CRITICAL")
    kev_count = sum(1 for i in feed if i.get("kev_present"))
    existing_desc = (product.get("description") or "").strip()

    stat_block = (
        f"\n\n---\n"
        f"**Live Coverage (as of {date_str}):** "
        f"{total} advisories | {critical_count} Critical | {kev_count} CISA KEV active\n"
        f"_Powered by CYBERDUDEBIVASH® SENTINEL APEX — {PLATFORM_URL}_"
    )

    # Append stat block; strip any previously appended one to avoid duplication
    if "---\n**Live Coverage" in existing_desc:
        existing_desc = existing_desc[:existing_desc.index("---\n**Live Coverage")].rstrip()

    full_desc = existing_desc + stat_block
    if len(full_desc) > MAX_DESC_CHARS:
        full_desc = full_desc[:MAX_DESC_CHARS - 3] + "..."
    return full_desc


# ── Main Orchestration ────────────────────────────────────────────────────────
def main() -> int:
    token     = os.environ.get("GUMROAD_ACCESS_TOKEN", "").strip()
    feed_path = os.environ.get("FEED_PATH", "feed.json")
    dry_run   = os.environ.get("GUMROAD_DRY_RUN", "").lower() in ("true", "1", "yes")

    if not token:
        log.info("GUMROAD_ACCESS_TOKEN not set — skipping product refresh (non-fatal).")
        return 0

    log.info("Loading feed from %s ...", feed_path)
    feed = load_feed(feed_path)
    if not feed:
        log.error("Empty feed — cannot refresh product descriptions.")
        return 1

    log.info("Feed loaded: %d advisories | dry_run=%s", len(feed), dry_run)

    # Fetch all Gumroad products
    log.info("Fetching Gumroad product catalog ...")
    products = list_products(token)
    if not products:
        log.warning("No products found on Gumroad account. Check token permissions.")
        return 0

    log.info("Found %d Gumroad products", len(products))

    # Fetch recent sales for logging/metrics (non-fatal)
    try:
        sales_counts = fetch_recent_sales(token)
        total_recent = sum(sales_counts.values())
        log.info("Recent sales across all products: %d", total_recent)
    except Exception as e:
        log.warning("Sales fetch skipped: %s", e)
        sales_counts = {}

    updated = 0
    skipped = 0
    failed  = 0

    for product in products:
        pid    = product.get("id") or product.get("permalink") or ""
        pname  = product.get("name", "Unnamed")
        listed = product.get("published", False)

        if not pid:
            log.warning("Product with no ID/permalink — skipping: %s", pname)
            skipped += 1
            continue

        if not listed:
            log.info("Skipping unlisted product: %s", pname)
            skipped += 1
            continue

        log.info("Processing product: %s [%s]", pname, pid)

        if is_detection_pack(product):
            new_desc = build_detection_pack_description(feed, product)
            log.info("  -> Detection pack — full threat-driven description (%d chars)", len(new_desc))
        else:
            new_desc = build_generic_description(feed, product)
            log.info("  -> Generic product — live stats injected (%d chars)", len(new_desc))

        ok = update_product_description(token, pid, new_desc, dry_run=dry_run)
        if ok:
            updated += 1
        else:
            failed += 1

    log.info(
        "Gumroad refresh complete: %d updated | %d skipped | %d failed",
        updated, skipped, failed,
    )

    # Non-zero exit only if ALL updates failed and at least one was attempted
    if failed > 0 and updated == 0 and (updated + failed) > 0:
        log.warning("All product updates failed — check GUMROAD_ACCESS_TOKEN permissions.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
