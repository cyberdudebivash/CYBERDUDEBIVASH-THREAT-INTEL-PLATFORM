#!/usr/bin/env python3
"""
SENTINEL APEX v185.0 — Tiered Intelligence Feed Generator [GOD-MODE]
=====================================================================
PURPOSE — REVENUE PRODUCT ACTIVATION:
  Transforms the certified premium baseline into four discrete customer product
  tiers, each priced and positioned for a different buyer segment. Every pipeline
  run refreshes all tiers atomically from api/feed.baseline.json.

PRODUCT TIERS GENERATED:
  api/feed.gold.json      — ENTERPRISE PLAN  ($999/mo)  GOLD tier only (richness >= 5.0)
  api/feed.silver.json    — PROFESSIONAL PLAN ($499/mo)  GOLD + SILVER  (richness >= 3.0)
  api/feed.standard.json  — STANDARD PLAN    ($199/mo)  All certified items
  api/feed.trial.json     — TRIAL / FREEMIUM (FREE→CTA) Top 10 by richness, fields redacted
  api/feed.executive.json — EXECUTIVE BRIEF  ($299/mo)  CRITICAL+HIGH summary view

CUSTOMER ACTIVATION VALUE:
  - Separate endpoints allow per-tier API key gating at the CDN/Worker layer
  - Trial feed drives conversion: preview quality, CTA to upgrade in every item
  - Executive brief serves CISO/VP dashboards with a lean payload
  - Detection pack companion feed (separate script) rounds out the enterprise suite

USAGE:
  python3 scripts/generate_tiered_feeds.py
  BASELINE_PATH=api/feed.baseline.json DRY_RUN=true python3 scripts/generate_tiered_feeds.py
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO          = Path(__file__).resolve().parent.parent
BASELINE_PATH = Path(os.environ.get("BASELINE_PATH", str(REPO / "api" / "feed.baseline.json")))
API_DIR       = REPO / "api"
DRY_RUN       = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
PLATFORM_BASE = "https://intel.cyberdudebivash.com"
VERSION       = "185.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("tiered_feeds")


def _safe_float(val: object, default: float = 0.0) -> float:
    try:
        return float(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _tier_value(t: str) -> int:
    return {"GOLD": 3, "SILVER": 2, "STANDARD": 1}.get(t, 0)


def _redact_for_trial(item: Dict, rank: int) -> Dict:
    """Return a trial-safe version of an item with premium fields redacted + upgrade CTA."""
    sev  = item.get("severity", "HIGH")
    risk = _safe_float(item.get("risk_score"))
    return {
        "id":               item.get("id", ""),
        "title":            item.get("title", ""),
        "severity":         sev,
        "risk_score":       round(risk, 2),
        "published_at":     item.get("published_at", ""),
        "tlp":              item.get("tlp", "TLP:GREEN"),
        "premium_tier":     item.get("premium_tier", "STANDARD"),
        "_trial_rank":      rank,
        "_trial_notice":    (
            "This is a TRIAL preview. Upgrade to access: full exec_summary, "
            "IOCs, CVSS/EPSS data, Sigma/KQL detection rules, actor attribution, "
            "APEX AI enrichment, and STIX 2.1 export. "
            f"Subscribe at {PLATFORM_BASE}/pricing"
        ),
        "source_url":       item.get("source_url", ""),
        "blog_url":         item.get("blog_url", ""),
        "_upgrade_url":     f"{PLATFORM_BASE}/pricing",
        "_generated_at":    datetime.now(timezone.utc).isoformat(),
    }


def _executive_view(item: Dict) -> Optional[Dict]:
    """Lean executive brief view: only items CRITICAL/HIGH with exec_summary."""
    sev = str(item.get("severity") or "").upper()
    if sev not in ("CRITICAL", "HIGH"):
        return None
    exec_s = str(item.get("exec_summary") or "").strip()
    if not exec_s:
        return None
    return {
        "id":               item.get("id", ""),
        "title":            item.get("title", ""),
        "severity":         sev,
        "risk_score":       round(_safe_float(item.get("risk_score")), 2),
        "cvss_score":       item.get("cvss_score"),
        "epss_score":       item.get("epss_score"),
        "kev":              item.get("kev"),
        "nvd_status":       item.get("nvd_status"),
        "exec_summary":     exec_s,
        "published_at":     item.get("published_at", ""),
        "tlp":              item.get("tlp", "TLP:GREEN"),
        "source_url":       item.get("source_url", ""),
        "blog_url":         item.get("blog_url", ""),
        "premium_tier":     item.get("premium_tier", "STANDARD"),
        "_intelligence_richness": item.get("_intelligence_richness"),
        "_generated_at":    datetime.now(timezone.utc).isoformat(),
    }


def _wrap(items: List[Dict], tier: str, description: str, count_total: int) -> Dict:
    """Wrap a list of items in a product envelope with metadata."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "_meta": {
            "product":          f"SENTINEL APEX — {tier}",
            "description":      description,
            "version":          VERSION,
            "generated_at":     now,
            "item_count":       len(items),
            "baseline_total":   count_total,
            "tier":             tier,
            "platform":         PLATFORM_BASE,
            "upgrade_url":      f"{PLATFORM_BASE}/pricing",
            "docs_url":         f"{PLATFORM_BASE}/docs/api",
            "stix_export_url":  f"{PLATFORM_BASE}/api/stix/bundle.json",
            "tlp_policy":       "Handle per TLP classification of individual items",
        },
        "items": items,
    }


def _atomic_write(path: Path, data: Any) -> bool:
    tmp = path.with_suffix(".tmp_tier")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        return True
    except Exception as exc:
        log.error("Write failed %s: %s", path, exc)
        tmp.unlink(missing_ok=True)
        return False


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — Tiered Feed Generator v%s [GOD-MODE]", VERSION)
    log.info("Baseline : %s", BASELINE_PATH)
    log.info("DryRun   : %s", DRY_RUN)
    log.info("=" * 60)

    if not BASELINE_PATH.exists():
        log.error("Baseline not found: %s", BASELINE_PATH)
        return 1

    try:
        baseline: List[Dict] = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to parse baseline: %s", exc)
        return 1

    if not isinstance(baseline, list):
        log.error("Baseline must be a list of items")
        return 1

    total = len(baseline)
    log.info("Loaded baseline: %d certified items", total)

    # ── GOLD tier: richness >= 5.0 ───────────────────────────────────────────────
    gold_items = [i for i in baseline if i.get("premium_tier") == "GOLD"]
    gold_items.sort(key=lambda x: -_safe_float(x.get("_intelligence_richness")))
    log.info("GOLD tier: %d items", len(gold_items))

    # ── SILVER tier: GOLD + SILVER (richness >= 3.0) ─────────────────────────────
    silver_items = [i for i in baseline if i.get("premium_tier") in ("GOLD", "SILVER")]
    silver_items.sort(key=lambda x: -_safe_float(x.get("_intelligence_richness")))
    log.info("PROFESSIONAL (GOLD+SILVER) tier: %d items", len(silver_items))

    # ── STANDARD tier: all certified items ───────────────────────────────────────
    standard_items = list(baseline)
    log.info("STANDARD tier: %d items", len(standard_items))

    # ── TRIAL: top 10 by richness, fields redacted + upgrade CTA ─────────────────
    sorted_all = sorted(baseline, key=lambda x: -_safe_float(x.get("_intelligence_richness")))
    trial_items = [_redact_for_trial(item, rank + 1) for rank, item in enumerate(sorted_all[:10])]
    log.info("TRIAL tier: %d items (redacted preview)", len(trial_items))

    # ── EXECUTIVE brief: CRITICAL+HIGH with exec_summary ─────────────────────────
    exec_items_raw = [_executive_view(i) for i in baseline]
    exec_items = [e for e in exec_items_raw if e is not None]
    exec_items.sort(key=lambda x: -_safe_float(x.get("risk_score")))
    log.info("EXECUTIVE brief: %d items (CRITICAL+HIGH only)", len(exec_items))

    # ── Write products ────────────────────────────────────────────────────────────
    products = [
        (API_DIR / "feed.gold.json",      gold_items,     "ENTERPRISE",    "Gold-tier verified threat intelligence — all premium enrichments included"),
        (API_DIR / "feed.silver.json",     silver_items,   "PROFESSIONAL",  "Professional threat intelligence — GOLD + SILVER certified items"),
        (API_DIR / "feed.standard.json",   standard_items, "STANDARD",      "Full certified intelligence feed — all 176 quality-gated items"),
        (API_DIR / "feed.trial.json",      trial_items,    "TRIAL",         "Trial preview — top 10 intelligence items (redacted). Upgrade for full access."),
        (API_DIR / "feed.executive.json",  exec_items,     "EXECUTIVE",     "Executive intelligence brief — CRITICAL + HIGH severity items only"),
    ]

    written = 0
    for path, items, tier, desc in products:
        wrapped = _wrap(items, tier, desc, total)
        if DRY_RUN:
            log.info("[DRY RUN] Would write %s (%d items)", path.name, len(items))
            written += 1
        else:
            if _atomic_write(path, wrapped):
                log.info("Written: %s (%d items)", path.name, len(items))
                written += 1
            else:
                log.error("FAILED: %s", path.name)

    # ── Product manifest ──────────────────────────────────────────────────────────
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version":      VERSION,
        "platform":     PLATFORM_BASE,
        "products": [
            {
                "tier":      "ENTERPRISE",
                "plan":      "Enterprise Plan",
                "price_usd_monthly": 999,
                "endpoint":  f"{PLATFORM_BASE}/api/feed.gold.json",
                "file":      "api/feed.gold.json",
                "items":     len(gold_items),
                "features":  ["GOLD tier only", "CVSS/EPSS data", "KEV flags", "IOCs", "Sigma/KQL rules", "APEX AI", "exec_summary", "STIX 2.1"],
            },
            {
                "tier":      "PROFESSIONAL",
                "plan":      "Professional Plan",
                "price_usd_monthly": 499,
                "endpoint":  f"{PLATFORM_BASE}/api/feed.silver.json",
                "file":      "api/feed.silver.json",
                "items":     len(silver_items),
                "features":  ["GOLD + SILVER tiers", "CVSS/EPSS data", "KEV flags", "IOCs", "Sigma/KQL rules", "exec_summary"],
            },
            {
                "tier":      "STANDARD",
                "plan":      "Standard Plan",
                "price_usd_monthly": 199,
                "endpoint":  f"{PLATFORM_BASE}/api/feed.standard.json",
                "file":      "api/feed.standard.json",
                "items":     len(standard_items),
                "features":  ["All certified items", "CVSS data", "exec_summary", "severity scoring"],
            },
            {
                "tier":      "EXECUTIVE",
                "plan":      "Executive Brief",
                "price_usd_monthly": 299,
                "endpoint":  f"{PLATFORM_BASE}/api/feed.executive.json",
                "file":      "api/feed.executive.json",
                "items":     len(exec_items),
                "features":  ["CRITICAL+HIGH only", "exec_summary", "CVSS/EPSS", "KEV", "lean payload"],
            },
            {
                "tier":      "TRIAL",
                "plan":      "Free Trial",
                "price_usd_monthly": 0,
                "endpoint":  f"{PLATFORM_BASE}/api/feed.trial.json",
                "file":      "api/feed.trial.json",
                "items":     len(trial_items),
                "features":  ["Top 10 preview", "upgrade CTA", "conversion funnel"],
            },
        ],
    }

    manifest_path = REPO / "data" / "product_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if not DRY_RUN:
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Product manifest: %s", manifest_path)

    log.info("=" * 60)
    log.info("TIERED FEEDS COMPLETE — %d/%d products written", written, len(products))
    log.info("  ENTERPRISE:    %d items  ($999/mo)", len(gold_items))
    log.info("  PROFESSIONAL:  %d items  ($499/mo)", len(silver_items))
    log.info("  STANDARD:      %d items  ($199/mo)", len(standard_items))
    log.info("  EXECUTIVE:     %d items  ($299/mo)", len(exec_items))
    log.info("  TRIAL:         %d items  (FREE → conversion)", len(trial_items))
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
