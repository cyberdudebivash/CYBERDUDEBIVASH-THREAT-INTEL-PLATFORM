#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — SEO Blog Generator v1.0
=========================================================
Generates high-value, SEO-optimised cybersecurity blog posts daily from
live manifest data. Auto-wires internal links back to the platform.

OUTPUTS:
  - data/growth/seo_posts/YYYY-MM-DD-<slug>.md
  - data/growth/seo_index.json (post catalogue)

SEO STRATEGY:
  - Target: "CVE-XXXX-XXXXX analysis", "critical vulnerability 2026",
    "ransomware threat intelligence", "CISA KEV exploit", etc.
  - Every post links to: intel.cyberdudebivash.com + pricing page
  - Schema.org Article markup in frontmatter
  - MITRE ATT&CK technique cross-links

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations
import json, logging, os, re, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SEO-BLOG] %(message)s")
logger = logging.getLogger("SEO-BLOG")

BASE_DIR      = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
OUTPUT_DIR    = BASE_DIR / "data" / "growth" / "seo_posts"
INDEX_PATH    = BASE_DIR / "data" / "growth" / "seo_index.json"

PLATFORM_URL  = "https://intel.cyberdudebivash.com"
PRICING_URL   = "https://intel.cyberdudebivash.com/landing/pricing.html"
DASH_URL      = "https://intel.cyberdudebivash.com/landing/dashboard.html"
API_DOCS_URL  = "https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/docs"
TELEGRAM_URL  = "https://t.me/cyberdudebivashSentinelApex"
BRAND         = "CYBERDUDEBIVASH® Sentinel APEX"
MAX_POSTS_PER_RUN = int(os.environ.get("SEO_MAX_POSTS", "3"))

# ── Keyword / Category mapping for SEO targeting ──────────────────────────────
SEO_CATEGORY_MAP = {
    "ransomware":       ["ransomware attack 2026", "ransomware threat intelligence", "ransomware IOC detection"],
    "supply_chain":     ["supply chain attack 2026", "software supply chain compromise", "SolarWinds style attack"],
    "kev":              ["CISA KEV exploit 2026", "known exploited vulnerability", "actively exploited CVE"],
    "critical_rce":     ["remote code execution vulnerability", "RCE exploit 2026", "critical RCE CVE"],
    "apt":              ["APT threat actor 2026", "nation-state attack", "advanced persistent threat"],
    "vulnerability":    ["CVE analysis 2026", "critical vulnerability assessment", "CVSS 9 vulnerability"],
    "malware":          ["malware analysis 2026", "threat intelligence malware", "IOC malware detection"],
}

MITRE_DESCRIPTIONS = {
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1566": "Phishing",
    "T1133": "External Remote Services",
    "T1105": "Ingress Tool Transfer",
}


def _slug(title: str) -> str:
    """Generate URL-safe slug from title."""
    s = re.sub(r"[^a-z0-9\s-]", "", title.lower())
    s = re.sub(r"\s+", "-", s.strip())
    return s[:80]


def _sev_label(score: float, sev: str) -> str:
    if sev == "CRITICAL" or score >= 9.0: return "CRITICAL"
    if sev == "HIGH"     or score >= 7.0: return "HIGH"
    if sev == "MEDIUM"   or score >= 4.0: return "MEDIUM"
    return "LOW"


def _detect_category(entry: Dict) -> str:
    """Classify entry into SEO category."""
    title = (entry.get("title") or "").lower()
    apex  = entry.get("apex") or {}
    cat   = (apex.get("threat_category") or "").lower()

    if "ransom" in title or "ransom" in cat: return "ransomware"
    if entry.get("kev_present"):             return "kev"
    if "supply chain" in title:              return "supply_chain"
    if "apt" in title or "nation-state" in title: return "apt"
    if "rce" in title or "remote code" in title:  return "critical_rce"
    if "malware" in title or "trojan" in title or "stealer" in title: return "malware"
    return "vulnerability"


def _extract_cve(title: str) -> Optional[str]:
    m = re.search(r"CVE-\d{4}-\d+", title, re.IGNORECASE)
    return m.group(0).upper() if m else None


def _pick_candidates(manifest: List[Dict], already_posted: set) -> List[Dict]:
    """Select high-value, unposted entries for blog generation."""
    scored = []
    for e in manifest:
        stix_id = e.get("stix_id","")
        if stix_id in already_posted: continue
        score = float(e.get("risk_score", 0))
        is_kev = bool(e.get("kev_present"))
        has_cve = bool(_extract_cve(e.get("title","")))
        has_blog = bool(e.get("blog_url"))
        apex_p1 = (e.get("apex") or {}).get("priority") == "P1"
        priority = score + (2 if is_kev else 0) + (1 if apex_p1 else 0) + (1 if has_cve else 0) + (1 if has_blog else 0)
        scored.append((priority, e))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:MAX_POSTS_PER_RUN * 3]]  # over-select, then filter

def _generate_post(entry: Dict) -> str:
    """Generate a full SEO-optimised Markdown blog post from a manifest entry."""
    title   = entry.get("title", "Critical Cybersecurity Advisory")
    score   = float(entry.get("risk_score", 0))
    sev     = _sev_label(score, entry.get("severity",""))
    cve_id  = _extract_cve(title)
    cat     = _detect_category(entry)
    apex    = entry.get("apex") or {}
    tactics = (entry.get("mitre_tactics") or [])[:4]
    blog_url= entry.get("blog_url","")
    source  = entry.get("source_url","") or entry.get("feed_source","")
    cvss    = entry.get("cvss_score")
    epss    = entry.get("epss_score")
    kev     = entry.get("kev_present", False)
    ts      = entry.get("timestamp","")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    apex_action = apex.get("recommended_action","")
    apex_summary= apex.get("ai_summary","")
    campaign_id = apex.get("campaign_id","")

    seo_kws  = SEO_CATEGORY_MAP.get(cat, SEO_CATEGORY_MAP["vulnerability"])
    keywords = ", ".join(seo_kws + (([f"{cve_id} analysis", f"{cve_id} exploit"] if cve_id else [])))

    # Build MITRE tactics section
    mitre_lines = "\n".join(
        f"- **[{t}](https://attack.mitre.org/techniques/{t.replace('.','/').rstrip('/')}/)**"
        f" — {MITRE_DESCRIPTIONS.get(t, 'Adversarial Technique')}"
        for t in tactics if t
    ) or "- No specific MITRE techniques mapped"

    # IOC counts
    ioc_counts = entry.get("ioc_counts") or {}
    ioc_lines = "\n".join(
        f"- **{v}** {k.upper()} indicators"
        for k, v in ioc_counts.items() if isinstance(v, int) and v > 0
    ) or "- IOC data available via API (Pro tier)"

    # Risk metrics block
    metrics = []
    if cvss is not None: metrics.append(f"| **CVSS Score** | `{cvss}` |")
    if epss is not None: metrics.append(f"| **EPSS** | `{epss}%` exploitation probability |")
    if kev:              metrics.append(f"| **CISA KEV** | ✅ Actively Exploited |")
    metrics.append(f"| **APEX AI Priority** | `{apex.get('priority','P?')}` — SLA {apex.get('threat_level','UNKNOWN')} |")
    if campaign_id:      metrics.append(f"| **Campaign ID** | `{campaign_id}` |")
    metrics_table = "\n".join(metrics)

    # Recommended action
    action_block = f"""
## Recommended Immediate Actions

{apex_action or 'Review the full advisory and apply patches immediately.'}

1. **Identify exposure** — Check all systems running the affected software
2. **Apply patches** — Prioritise this over routine maintenance cycles
3. **Monitor IOCs** — Feed provided indicators into your SIEM/EDR immediately
4. **Tune detection rules** — Use MITRE ATT&CK techniques above to update detection logic
""".strip()

    # CTA block
    cta_block = f"""
---

## 🔍 Monitor This Threat in Real Time

This advisory is actively tracked by **{BRAND}** — an AI-powered threat intelligence platform
that delivers APEX AI enrichment, P1 alerts, and automated SOC response for threats like this one.

### Free Access (No Sign-Up Required)

```bash
curl {API_DOCS_URL.replace('/docs','')}/api/v1/intel/latest
```

### Full Intelligence Access

| Plan | Price | IOC Access | APEX AI | Alerts |
|------|-------|-----------|---------|--------|
| Free | $0 | Limited | ✗ | ✗ |
| Pro  | $49/mo | ✅ Full | ✅ | ✅ Telegram |
| Enterprise | $499/mo | ✅ Bulk | ✅ | ✅ Webhook |

👉 **[View Live Threat Dashboard]({PLATFORM_URL})** · **[Get API Access]({PRICING_URL})** · **[Join Telegram]({TELEGRAM_URL})**

---
*Powered by {BRAND} — Real-time AI threat intelligence for cybersecurity professionals.*
*Data sourced from CISA, NVD, CVEfeed, and 10+ threat intel sources. Updated every 6 hours.*
""".strip()

    # Full post
    slug = _slug(title)
    headline = f"{sev} Severity: {title}" if cve_id else f"Threat Advisory: {title}"

    post = f"""---
title: "{headline}"
date: "{ts}"
slug: "{ts}-{slug}"
description: "APEX AI threat analysis of {title}. Risk score {score}/10. {('CVSS ' + str(cvss) + '. ') if cvss else ''}{('CISA KEV confirmed. ') if kev else ''}IOCs, MITRE ATT&CK, and remediation guidance."
keywords: "{keywords}"
category: "threat-intelligence"
severity: "{sev}"
risk_score: {score}
cve_id: "{cve_id or ''}"
kev_confirmed: {str(kev).lower()}
platform_url: "{PLATFORM_URL}"
schema_type: "Article"
author: "CYBERDUDEBIVASH Sentinel APEX AI"
---

# {headline}

> **⚠️ {sev} SEVERITY** · Risk Score: **{score}/10** · Published: {ts}
> {f'CISA KEV Confirmed — Actively Exploited ⚡' if kev else f'APEX AI Priority: {apex.get("priority","P?")}'} · [Live Intelligence Feed]({PLATFORM_URL})

## Overview

{apex_summary or f'A {sev.lower()}-severity advisory has been identified affecting the above component. Security teams should evaluate exposure and apply mitigations immediately.'}

This advisory has been enriched by the **APEX AI engine** with predictive risk scoring, campaign attribution, and automated SOC response recommendations.

## Risk Metrics

| Metric | Value |
|--------|-------|
| **Risk Score** | `{score}/10` ({sev}) |
{metrics_table}

## MITRE ATT&CK Techniques

{mitre_lines}

## IOC Summary

{ioc_lines}

{action_block}

{f'## Full Report' + chr(10) + f'[Read the complete premium advisory on the Sentinel APEX blog]({blog_url})' if blog_url else ''}

{cta_block}
"""
    return post.strip()

def run_seo_blog_generator() -> Dict:
    """Main entry: load manifest, pick candidates, generate posts, write files."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not MANIFEST_PATH.exists():
        logger.warning("[SEO-BLOG] Manifest not found — skipping")
        return {"generated": 0, "status": "NO_MANIFEST"}

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Load existing SEO index to avoid duplicates
    already_posted: set = set()
    seo_index: List[Dict] = []
    if INDEX_PATH.exists():
        try:
            with open(INDEX_PATH, "r", encoding="utf-8") as f:
                seo_index = json.load(f)
            already_posted = {e.get("stix_id","") for e in seo_index}
        except Exception:
            seo_index = []

    candidates = _pick_candidates(manifest, already_posted)
    generated  = 0
    today      = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for entry in candidates:
        if generated >= MAX_POSTS_PER_RUN:
            break
        try:
            stix_id = entry.get("stix_id","")
            title   = entry.get("title","")[:80]
            slug    = _slug(title)
            filename= f"{today}-{slug}.md"
            out_path= OUTPUT_DIR / filename

            if out_path.exists():
                logger.debug(f"[SEO-BLOG] Skip existing: {filename}")
                continue

            post_md = _generate_post(entry)
            out_path.write_bytes(post_md.encode("utf-8"))

            # Update index
            seo_index.insert(0, {
                "stix_id":   stix_id,
                "title":     title,
                "slug":      slug,
                "date":      today,
                "filename":  filename,
                "risk_score": entry.get("risk_score", 0),
                "severity":  entry.get("severity",""),
                "category":  _detect_category(entry),
                "cve_id":    _extract_cve(title) or "",
                "kev":       bool(entry.get("kev_present")),
                "url":       f"{PLATFORM_URL}/growth/posts/{filename.replace('.md','')}/",
            })
            already_posted.add(stix_id)
            generated += 1
            logger.info(f"[SEO-BLOG] Generated: {filename}")

        except Exception as e:
            logger.warning(f"[SEO-BLOG] Failed post for {entry.get('title','?')[:40]}: {e}")

    # Keep last 500 entries in index
    seo_index = seo_index[:500]
    tmp = str(INDEX_PATH) + ".tmp"
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, "wb") as f:
        f.write(json.dumps(seo_index, indent=2, ensure_ascii=False).encode("utf-8"))
    os.replace(tmp, INDEX_PATH)

    logger.info(f"[SEO-BLOG] Complete: {generated} posts generated")
    return {"generated": generated, "total_indexed": len(seo_index), "status": "OK"}


if __name__ == "__main__":
    result = run_seo_blog_generator()
    print(json.dumps(result, indent=2))
    sys.exit(0)
