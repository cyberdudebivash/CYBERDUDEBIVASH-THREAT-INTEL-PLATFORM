#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — SEO DOMINATION ENGINE v1.0
==========================================
Phase 6: Global Authority Content Pipeline

WHAT IT DOES:
  For every intel report in api/feed.json:
  1. Generates SEO-optimized <head> meta block (title, description, keywords,
     canonical, OG, Twitter Card, JSON-LD structured data)
  2. Injects meta block into every report HTML in reports/
  3. Generates sitemap.xml covering all reports + static pages
  4. Generates robots.txt with crawl budget directives
  5. Generates data/seo/keyword_clusters.json — keyword → article mapping
     for content gap analysis

KEYWORD STRATEGY:
  Primary:  "<CVE-ID> exploit analysis", "<threat actor> IOC", "<malware> indicators"
  Secondary: "STIX threat intel", "cybersecurity threat report", "MITRE ATT&CK <technique>"
  Long-tail: "how to detect <malware> with SIEM", "<CVE> patch <vendor>"

SITEMAP PRIORITY LOGIC:
  risk_score >= 9   → priority 1.0, changefreq daily
  risk_score >= 7   → priority 0.8, changefreq weekly
  risk_score >= 5   → priority 0.6, changefreq monthly
  else              → priority 0.4, changefreq monthly

OUTPUT:
  sitemap.xml                         → repo root (served at /sitemap.xml)
  robots.txt                          → repo root
  data/seo/keyword_clusters.json      → keyword intelligence map
  data/seo/seo_report.json            → injection stats + coverage

USAGE:
  python3 scripts/seo_domination.py
  python3 scripts/seo_domination.py --dry-run        (no file writes)
  python3 scripts/seo_domination.py --sitemap-only   (skip HTML injection)
"""

import json
import re
import sys
import os
import hashlib
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [seo-domination] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("seo-domination")

REPO = Path(__file__).parent.parent.resolve()

# ─── PLATFORM CONFIG ────────────────────────────────────────────────────────
PLATFORM = {
    "name":        "CYBERDUDEBIVASH SENTINEL APEX",
    "short":       "Sentinel APEX",
    "domain":      "https://intel.cyberdudebivash.com",
    "author":      "CYBERDUDEBIVASH",
    "twitter":     "@cyberdudebivash",
    "logo":        "https://intel.cyberdudebivash.com/logo.png",
    "tagline":     "World-Class AI-Powered Cybersecurity Threat Intelligence",
    "description": (
        "Real-time AI-powered cybersecurity threat intelligence. "
        "STIX 2.1 feeds, CVE analysis, IOC extraction, MITRE ATT&CK mapping, "
        "and enterprise threat hunting — free and enterprise tiers available."
    ),
}

# ─── STATIC PAGES (always in sitemap) ────────────────────────────────────────
STATIC_PAGES = [
    {"url": "/",                   "priority": "1.0", "changefreq": "daily"},
    {"url": "/pricing.html",       "priority": "0.9", "changefreq": "weekly"},
    {"url": "/enterprise.html",    "priority": "0.9", "changefreq": "weekly"},
    {"url": "/observability.html", "priority": "0.7", "changefreq": "weekly"},
    {"url": "/status.html",        "priority": "0.6", "changefreq": "daily"},
    {"url": "/onboarding.html",    "priority": "0.7", "changefreq": "monthly"},
    {"url": "/trust-center.html",  "priority": "0.7", "changefreq": "monthly"},
    {"url": "/upgrade.html",       "priority": "0.8", "changefreq": "weekly"},
]

# ─── MITRE TACTIC → KEYWORD EXPANSION ────────────────────────────────────────
TACTIC_KEYWORDS = {
    "initial-access":       ["initial access attack", "phishing detection", "exploit entry point"],
    "execution":            ["malware execution", "code execution exploit", "threat execution"],
    "persistence":          ["persistence mechanism", "backdoor detection", "APT persistence"],
    "privilege-escalation": ["privilege escalation", "CVE local privilege", "kernel exploit"],
    "defense-evasion":      ["defense evasion", "AV bypass", "EDR evasion technique"],
    "credential-access":    ["credential theft", "password dumping", "LSASS attack"],
    "discovery":            ["network discovery", "reconnaissance attack", "threat actor discovery"],
    "lateral-movement":     ["lateral movement", "network pivot", "SMB exploit"],
    "collection":           ["data collection", "exfiltration staging", "threat actor IOC"],
    "command-and-control":  ["C2 infrastructure", "command and control", "botnet C2 IOC"],
    "exfiltration":         ["data exfiltration", "data breach IOC", "sensitive data theft"],
    "impact":               ["ransomware attack", "destructive malware", "cyber impact"],
}


def load_feed() -> list:
    feed_path = REPO / "api" / "feed.json"
    if not feed_path.exists():
        log.error("api/feed.json not found")
        sys.exit(1)
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("advisories", data.get("items", []))


def slug_to_report_path(stix_id: str) -> Path | None:
    """Find a report HTML file from its stix_id."""
    sid = stix_id.replace("indicator--", "").replace("report--", "")
    for y in ["2026", "2025", "2024"]:
        for m in ["01","02","03","04","05","06","07","08","09","10","11","12"]:
            p = REPO / "reports" / y / m / f"intel--{sid}.html"
            if p.exists():
                return p
    # Fallback: glob search
    matches = list((REPO / "reports").rglob(f"intel--{sid}.html"))
    return matches[0] if matches else None


def build_keywords(item: dict) -> list[str]:
    """Generate keyword list for an intel item."""
    kws = []

    # CVE keywords
    cves = item.get("cves", []) or []
    for cve in cves[:5]:
        kws.extend([
            cve,
            f"{cve} exploit",
            f"{cve} vulnerability",
            f"{cve} patch",
            f"{cve} analysis",
            f"{cve} proof of concept",
        ])

    # Threat actor
    actor = item.get("threat_actor", "") or ""
    if actor and actor not in ("unknown", "Unknown", "N/A"):
        kws.extend([
            actor,
            f"{actor} IOC",
            f"{actor} TTPs",
            f"{actor} threat intelligence",
        ])

    # Malware family
    malware = item.get("malware_family", "") or item.get("malware", "") or ""
    if malware and malware not in ("unknown", "Unknown", "N/A"):
        kws.extend([
            malware,
            f"{malware} indicators",
            f"{malware} detection",
            f"how to detect {malware}",
        ])

    # MITRE tactics — field can be list[str] OR list[dict] depending on pipeline version
    tactics = item.get("mitre_tactics", []) or item.get("tactics", []) or []
    for tactic in tactics[:3]:
        if isinstance(tactic, dict):
            # Extract name from dict: {"name": "...", "phase_name": "..."} or {"tactic": "..."}
            tactic_str = (
                tactic.get("name") or tactic.get("phase_name") or
                tactic.get("tactic") or tactic.get("id") or ""
            )
        elif isinstance(tactic, str):
            tactic_str = tactic
        else:
            continue
        if not tactic_str:
            continue
        tactic_key = tactic_str.lower().replace(" ", "-")
        kws.extend(TACTIC_KEYWORDS.get(tactic_key, [tactic_str]))

    # Category
    category = item.get("category", "") or ""
    if category:
        kws.extend([
            category,
            f"{category} threat intelligence",
            f"{category} cybersecurity",
        ])

    # Generic platform keywords always included
    kws.extend([
        "STIX 2.1 threat intelligence",
        "MITRE ATT&CK",
        "IOC indicators of compromise",
        "cybersecurity threat intel",
        "enterprise threat hunting",
        "SENTINEL APEX",
    ])

    # Deduplicate while preserving order
    seen = set()
    out = []
    for kw in kws:
        kw_clean = kw.strip()
        if kw_clean and kw_clean.lower() not in seen:
            seen.add(kw_clean.lower())
            out.append(kw_clean)

    return out[:25]  # cap at 25 keywords per page


def build_meta_block(item: dict, report_url: str) -> str:
    """Generate full SEO <head> meta block for an intel report."""
    title_raw = item.get("title", "Threat Intelligence Report")
    # Truncate title to 60 chars for SEO
    seo_title = title_raw[:57] + "..." if len(title_raw) > 60 else title_raw
    full_title = f"{seo_title} | {PLATFORM['short']}"

    # Meta description: 150-160 chars
    desc_parts = []
    cves = item.get("cves", [])
    if cves:
        desc_parts.append(f"CVEs: {', '.join(cves[:3])}")
    risk = item.get("risk_score", 0)
    if risk:
        desc_parts.append(f"Risk: {risk}/10")
    summary = item.get("summary", item.get("description", ""))
    base_desc = f"{PLATFORM['short']} threat report. {'. '.join(desc_parts)}. {summary}"
    meta_desc = base_desc[:157] + "..." if len(base_desc) > 160 else base_desc

    keywords = build_keywords(item)
    keywords_str = ", ".join(keywords[:15])

    published = item.get("published_at", item.get("created", datetime.now(timezone.utc).isoformat()))
    modified  = item.get("updated_at", published)

    stix_id = item.get("stix_id", item.get("id", ""))
    iocs = item.get("iocs", [])
    ioc_count = len(iocs) if iocs else item.get("ioc_count", 0)

    # JSON-LD structured data (Article schema)
    json_ld = {
        "@context": "https://schema.org",
        "@type": "TechArticle",
        "headline": seo_title,
        "description": meta_desc,
        "url": report_url,
        "datePublished": published,
        "dateModified": modified,
        "author": {
            "@type": "Organization",
            "name": PLATFORM["author"],
            "url": PLATFORM["domain"],
        },
        "publisher": {
            "@type": "Organization",
            "name": PLATFORM["name"],
            "url": PLATFORM["domain"],
            "logo": {
                "@type": "ImageObject",
                "url": PLATFORM["logo"],
            },
        },
        "keywords": keywords_str,
        "about": {
            "@type": "Thing",
            "name": "Cybersecurity Threat Intelligence",
        },
        "mainEntityOfPage": {
            "@type": "WebPage",
            "@id": report_url,
        },
    }
    if item.get("cves"):
        json_ld["mentions"] = [
            {"@type": "SoftwareApplication", "name": cve}
            for cve in item["cves"][:5]
        ]

    json_ld_str = json.dumps(json_ld, indent=2, ensure_ascii=False)

    # Risk badge label
    risk_label = "CRITICAL" if risk >= 9 else "HIGH" if risk >= 7 else "MEDIUM" if risk >= 5 else "LOW"

    meta_block = f"""  <!-- SEO DOMINATION ENGINE v1.0 — SENTINEL APEX Phase 6 -->
  <title>{full_title}</title>
  <meta name="description" content="{meta_desc}">
  <meta name="keywords" content="{keywords_str}">
  <meta name="author" content="{PLATFORM['author']}">
  <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">
  <link rel="canonical" href="{report_url}">

  <!-- Open Graph (LinkedIn, Facebook) -->
  <meta property="og:type" content="article">
  <meta property="og:title" content="{full_title}">
  <meta property="og:description" content="{meta_desc}">
  <meta property="og:url" content="{report_url}">
  <meta property="og:site_name" content="{PLATFORM['name']}">
  <meta property="og:image" content="{PLATFORM['domain']}/logo.png">
  <meta property="article:published_time" content="{published}">
  <meta property="article:modified_time" content="{modified}">
  <meta property="article:section" content="Cybersecurity Threat Intelligence">
  <meta property="article:tag" content="{keywords[0] if keywords else 'threat intelligence'}">

  <!-- Twitter / X Card -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:site" content="{PLATFORM['twitter']}">
  <meta name="twitter:creator" content="{PLATFORM['twitter']}">
  <meta name="twitter:title" content="{full_title}">
  <meta name="twitter:description" content="{meta_desc}">
  <meta name="twitter:image" content="{PLATFORM['domain']}/logo.png">
  <meta name="twitter:label1" content="Risk Level">
  <meta name="twitter:data1" content="{risk_label} ({risk}/10)">
  <meta name="twitter:label2" content="IOC Count">
  <meta name="twitter:data2" content="{ioc_count} indicators">

  <!-- JSON-LD Structured Data -->
  <script type="application/ld+json">
{json_ld_str}
  </script>
  <!-- /SEO DOMINATION ENGINE -->"""

    return meta_block


def inject_meta_into_report(report_path: Path, meta_block: str, dry_run: bool = False) -> bool:
    """Inject SEO meta block into a report HTML. Returns True if changed."""
    try:
        content = report_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        log.warning(f"Could not read {report_path}: {e}")
        return False

    # Remove existing SEO block if present (idempotent)
    seo_pattern = re.compile(
        r'\s*<!-- SEO DOMINATION ENGINE.*?<!-- /SEO DOMINATION ENGINE -->',
        re.DOTALL
    )
    content = seo_pattern.sub("", content)

    # Find injection point: after <head> or before first <meta>/<title>
    inject_after = re.search(r'<head[^>]*>', content, re.IGNORECASE)
    if not inject_after:
        log.debug(f"No <head> tag found in {report_path.name} — skipping")
        return False

    pos = inject_after.end()
    new_content = content[:pos] + "\n" + meta_block + "\n" + content[pos:]

    if not dry_run:
        report_path.write_text(new_content, encoding="utf-8")
    return True


def sitemap_priority(risk: int | float) -> tuple[str, str]:
    """Return (priority, changefreq) based on risk score."""
    r = float(risk or 0)
    if r >= 9:
        return "1.0", "daily"
    elif r >= 7:
        return "0.8", "weekly"
    elif r >= 5:
        return "0.6", "monthly"
    else:
        return "0.4", "monthly"


def generate_sitemap(items: list, dry_run: bool = False) -> str:
    """Generate sitemap.xml covering all reports + static pages."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"')
    lines.append('        xmlns:news="http://www.google.com/schemas/sitemap-news/0.9">')

    # Static pages
    for page in STATIC_PAGES:
        lines.append("  <url>")
        lines.append(f"    <loc>{PLATFORM['domain']}{page['url']}</loc>")
        lines.append(f"    <lastmod>{now}</lastmod>")
        lines.append(f"    <changefreq>{page['changefreq']}</changefreq>")
        lines.append(f"    <priority>{page['priority']}</priority>")
        lines.append("  </url>")

    # Intel reports
    for item in items:
        stix_id = item.get("stix_id", item.get("id", ""))
        if not stix_id:
            continue
        sid = stix_id.replace("indicator--", "").replace("report--", "")
        report_url_path = item.get("report_url", "")
        if not report_url_path:
            # Derive from stix_id
            pub = item.get("published_at", now)
            try:
                pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                report_url_path = f"/reports/{pub_dt.year}/{pub_dt.month:02d}/intel--{sid}.html"
            except Exception:
                continue

        full_url = f"{PLATFORM['domain']}{report_url_path}"
        pub_date = (item.get("published_at", now) or now)[:10]
        risk = item.get("risk_score", 5)
        priority, changefreq = sitemap_priority(risk)
        title = item.get("title", "")[:100]

        lines.append("  <url>")
        lines.append(f"    <loc>{full_url}</loc>")
        lines.append(f"    <lastmod>{pub_date}</lastmod>")
        lines.append(f"    <changefreq>{changefreq}</changefreq>")
        lines.append(f"    <priority>{priority}</priority>")
        if title:
            lines.append(f"    <!-- {title[:80].replace('--', '-')} -->")
        lines.append("  </url>")

    lines.append("</urlset>")
    sitemap_xml = "\n".join(lines)

    if not dry_run:
        out = REPO / "sitemap.xml"
        out.write_text(sitemap_xml, encoding="utf-8")
        log.info(f"sitemap.xml written: {len(items) + len(STATIC_PAGES)} URLs")

    return sitemap_xml


def generate_robots(dry_run: bool = False) -> str:
    """Generate robots.txt with crawl budget optimization."""
    content = f"""# robots.txt — {PLATFORM['name']}
# Generated by SEO Domination Engine v1.0
# Platform: {PLATFORM['domain']}

User-agent: *
Allow: /

# High-value crawl targets — prioritize these
Allow: /reports/
Allow: /blog/
Allow: /api/feed.json
Allow: /pricing.html
Allow: /enterprise.html

# Exclude pipeline/CI artifacts
Disallow: /data/cache/
Disallow: /data/stix/
Disallow: /data/audit/
Disallow: /data/telemetry/
Disallow: /data/governance/
Disallow: /data/publish_queue.json
Disallow: /.github/
Disallow: /scripts/

# Sitemap
Sitemap: {PLATFORM['domain']}/sitemap.xml
Sitemap: {PLATFORM['domain']}/blog/sitemap.xml

# Crawl-delay (be polite to bots)
Crawl-delay: 1
"""
    if not dry_run:
        out = REPO / "robots.txt"
        out.write_text(content, encoding="utf-8")
        log.info("robots.txt written")
    return content


def build_keyword_clusters(items: list, dry_run: bool = False) -> dict:
    """Build keyword → article mapping for content gap analysis."""
    clusters: dict[str, list] = defaultdict(list)

    for item in items:
        kws = build_keywords(item)
        stix_id = item.get("stix_id", item.get("id", ""))
        title   = item.get("title", "")
        risk    = item.get("risk_score", 0)
        pub     = (item.get("published_at", "") or "")[:10]
        url     = item.get("report_url", "")

        for kw in kws:
            clusters[kw].append({
                "stix_id": stix_id,
                "title":   title,
                "risk":    risk,
                "pub":     pub,
                "url":     url,
            })

    # Sort each cluster by risk descending
    for kw in clusters:
        clusters[kw] = sorted(clusters[kw], key=lambda x: x["risk"], reverse=True)

    # Top keywords by article count
    top_keywords = sorted(clusters.keys(), key=lambda k: len(clusters[k]), reverse=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_keywords": len(clusters),
        "total_items": len(items),
        "top_30_keywords": [
            {
                "keyword": kw,
                "article_count": len(clusters[kw]),
                "top_article": clusters[kw][0]["title"] if clusters[kw] else "",
            }
            for kw in top_keywords[:30]
        ],
        "clusters": {kw: clusters[kw] for kw in top_keywords},
    }

    if not dry_run:
        out_dir = REPO / "data" / "seo"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "keyword_clusters.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info(f"keyword_clusters.json written: {len(clusters)} unique keywords")

    return report


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX SEO Domination Engine")
    parser.add_argument("--dry-run",       action="store_true", help="Run without writing files")
    parser.add_argument("--sitemap-only",  action="store_true", help="Only generate sitemap/robots")
    parser.add_argument("--reports-only",  action="store_true", help="Only inject meta into reports")
    parser.add_argument("--limit",         type=int, default=0,  help="Limit report injection to N items")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("SENTINEL APEX — SEO DOMINATION ENGINE v1.0")
    log.info(f"Mode: {'DRY-RUN' if args.dry_run else 'LIVE'} | Domain: {PLATFORM['domain']}")
    log.info("=" * 70)

    items = load_feed()
    log.info(f"Loaded {len(items)} intel items from api/feed.json")

    injected = 0
    skipped  = 0
    missing  = 0
    errors   = 0

    # ── 1. Generate sitemap + robots ────────────────────────────────────────
    if not args.reports_only:
        generate_sitemap(items, dry_run=args.dry_run)
        generate_robots(dry_run=args.dry_run)
        build_keyword_clusters(items, dry_run=args.dry_run)

    # ── 2. Inject SEO meta into every HTML report ───────────────────────────
    if not args.sitemap_only:
        targets = items[:args.limit] if args.limit else items
        log.info(f"Injecting SEO meta into {len(targets)} reports...")

        for i, item in enumerate(targets):
            stix_id = item.get("stix_id", item.get("id", ""))
            if not stix_id:
                skipped += 1
                continue

            report_path = slug_to_report_path(stix_id)
            if not report_path:
                missing += 1
                if missing <= 5:
                    log.debug(f"Report not found for {stix_id}")
                continue

            sid = stix_id.replace("indicator--", "").replace("report--", "")
            pub = item.get("published_at", "")
            try:
                pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                report_url = f"{PLATFORM['domain']}/reports/{pub_dt.year}/{pub_dt.month:02d}/intel--{sid}.html"
            except Exception:
                # v166.3-FIX: fallback must include year/month (bare /reports/intel--xxx.html → 404)
                from datetime import datetime as _dt
                _now = _dt.utcnow()
                report_url = f"{PLATFORM['domain']}/reports/{_now.year}/{_now.month:02d}/intel--{sid}.html"

            try:
                meta = build_meta_block(item, report_url)
                changed = inject_meta_into_report(report_path, meta, dry_run=args.dry_run)
                if changed:
                    injected += 1
                else:
                    skipped += 1
            except Exception as e:
                log.warning(f"Error injecting {stix_id}: {e}")
                errors += 1

            if (i + 1) % 500 == 0:
                log.info(f"  Progress: {i+1}/{len(targets)} | injected={injected} missing={missing}")

    # ── 3. Write SEO report ─────────────────────────────────────────────────
    seo_report = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "dry_run":        args.dry_run,
        "total_items":    len(items),
        "injected":       injected,
        "skipped":        skipped,
        "missing_report": missing,
        "errors":         errors,
        "sitemap_urls":   len(items) + len(STATIC_PAGES),
        "coverage_pct":   round(injected / max(len(items), 1) * 100, 1),
        "platform":       PLATFORM["domain"],
    }

    if not args.dry_run:
        out_dir = REPO / "data" / "seo"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "seo_report.json").write_text(
            json.dumps(seo_report, indent=2), encoding="utf-8"
        )

    log.info("=" * 70)
    log.info("SEO DOMINATION ENGINE -- COMPLETE")
    log.info(f"  Items processed : {len(items)}")
    log.info(f"  Meta injected   : {injected}")
    log.info(f"  Reports missing : {missing}")
    log.info(f"  Coverage        : {seo_report['coverage_pct']}%")
    log.info(f"  Sitemap URLs    : {seo_report['sitemap_urls']}")
    log.info(f"  Errors          : {errors}")
    log.info("=" * 70)

    if errors > 10:
        log.error(f"Too many errors ({errors}) -- check logs")
        sys.exit(1)

    log.info("SEO DOMINATION: COMPLETE -- organic traffic engine online")


if __name__ == "__main__":
    main()
