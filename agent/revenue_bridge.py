#!/usr/bin/env python3
"""
revenue_bridge.py — CYBERDUDEBIVASH® SENTINEL APEX v18.0
REVENUE ORCHESTRATION BRIDGE

Connects the threat intel pipeline to ALL monetization modules in one call:
  1. Injects contextual Gumroad CTAs into published blog posts
  2. Dispatches executive briefing emails to subscribers
  3. Records revenue metrics (clicks tracked via UTM, emails sent)

Called from process_entry() in sentinel_blogger.py AFTER Blogger publish.
Non-blocking — ALL errors are caught and logged, never crash the pipeline.
Zero breaking changes to existing code.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("CDB-REVENUE")

# Category keyword maps for threat classification
_CATEGORY_KEYWORDS = {
    "vulnerability":     ["cve-", "vulnerability", "zero-day", "0-day", "exploit", "patch", "rce", "privilege escalation"],
    "ransomware":        ["ransomware", "ransom", "lockbit", "blackcat", "cl0p", "conti", "encrypt"],
    "malware_campaign":  ["malware", "stealer", "trojan", "rat", "backdoor", "botnet", "infostealer", "loader"],
    "mobile_malware":    ["android", "mobile malware", "apk", "ios malware", "banking trojan", "sms trojan"],
    "data_breach":       ["breach", "leak", "exposed", "stolen data", "customer records", "data dump"],
    "apt":               ["apt", "nation-state", "state-sponsored", "apt28", "apt29", "apt41", "lazarus", "volt typhoon"],
    "supply_chain":      ["supply chain", "software supply", "build system", "dependency", "package poisoning"],
    "phishing":          ["phishing", "spear-phishing", "credential harvest", "fake login", "social engineering"],
    "browser_extension": ["browser extension", "chrome extension", "malicious extension", "browser plugin"],
    "cloud_attack":      ["cloud attack", "aws", "azure", "gcp", "s3 bucket", "cloud misconfiguration"],
    "ddos":              ["ddos", "denial of service", "botnet attack", "volumetric"],
}


def detect_threat_category(headline: str, content: str) -> str:
    """Classify threat category from headline + content for contextual CTA mapping."""
    text = f"{headline} {content}".lower()
    scores = {}
    for category, keywords in _CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[category] = score
    if scores:
        return max(scores, key=scores.get)
    return "default"


def activate_revenue_pipeline(
    report_html: str,
    headline: str,
    risk_score: float,
    live_blog_url: str,
    content: str = "",
    product_url: str = "",
) -> str:
    """
    Main revenue activation function. Call this AFTER a post is published to Blogger.

    Args:
        report_html:   The HTML content that was published
        headline:      Threat title
        risk_score:    CDB Risk Index score (0-10)
        live_blog_url: The live Blogger URL of the published post
        content:       Enriched content (for category detection)
        product_url:   Explicit Gumroad URL override (optional)

    Returns:
        report_html with CTAs injected (for reference — Blogger post already published)
    """
    enriched_html = report_html

    # ── Step 1: Detect threat category ──────────────────────────────────
    try:
        threat_category = detect_threat_category(headline, content)
        logger.info(f"  💰 Revenue: Threat category detected → {threat_category}")
    except Exception as e:
        threat_category = "default"
        logger.warning(f"  ⚠️  Revenue: Category detection failed (non-critical): {e}")

    # ── Step 2: Inject CTAs into report HTML (for reference/logging) ────
    try:
        from agent.upsell_injector import upsell_engine
        enriched_html = upsell_engine.inject_premium_cta(
            report_html=report_html,
            product_url=product_url,
            risk_score=risk_score,
            threat_category=threat_category,
        )
        logger.info(f"  ✅ Revenue: Dual CTA injected (category={threat_category}, score={risk_score})")
    except Exception as e:
        logger.warning(f"  ⚠️  Revenue: CTA injection failed (non-critical): {e}")

    # ── Step 3: Email executive briefing to subscribers ─────────────────
    # Only trigger for High+ severity (score >= 6.5) to avoid subscriber fatigue
    if risk_score >= 6.5:
        try:
            from agent.email_dispatcher import send_executive_briefing
            send_executive_briefing(
                title=headline,
                score=risk_score,
                content_html=enriched_html,
                url=live_blog_url,
            )
            logger.info(f"  📧 Revenue: Executive briefing dispatched (score={risk_score})")
        except ImportError:
            logger.debug("  Email dispatcher not available — skipping")
        except Exception as e:
            logger.warning(f"  ⚠️  Revenue: Email dispatch failed (non-critical): {e}")
    else:
        logger.info(f"  📧 Revenue: Email skipped (score {risk_score} < 6.5 threshold)")

    # ── Step 4: Log revenue event ────────────────────────────────────────
    try:
        _log_revenue_event(headline, risk_score, threat_category, live_blog_url)
    except Exception as e:
        logger.debug(f"Revenue event log failed (non-critical): {e}")

    return enriched_html


def _log_revenue_event(headline: str, score: float, category: str, url: str):
    """Append revenue event to data/revenue_log.json for tracking."""
    import json, time
    from pathlib import Path

    log_path = Path("data/revenue_log.json")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    existing = []
    if log_path.exists():
        try:
            with open(log_path) as f:
                existing = json.load(f)
        except Exception:
            existing = []

    existing.append({
        "ts": int(time.time()),
        "headline": headline[:100],
        "risk_score": score,
        "category": category,
        "url": url,
        "cta_triggered": score >= 7.0,
        "email_triggered": score >= 6.5,
    })

    # Keep last 200 events
    if len(existing) > 200:
        existing = existing[-200:]

    with open(log_path, 'w') as f:
        json.dump(existing, f, indent=2)
