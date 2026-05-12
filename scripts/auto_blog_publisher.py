#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — AUTO BLOG PUBLISHER v1.0
=========================================
Phase 6: Global Authority Content Pipeline

WHAT IT DOES:
  Converts top threat intel items from api/feed.json into fully SEO-optimized
  blog posts published to blog/ directory on GitHub Pages.

BLOG POST STRUCTURE (per article):
  - H1: SEO-optimized headline
  - Executive Summary (2-3 sentences, risk context)
  - CVE Details table (CVSS, vendor, affected systems)
  - IOC Table (type, value, confidence)
  - MITRE ATT&CK Tactics + Techniques
  - Threat Actor Attribution
  - Detection Recommendations (SIEM queries, YARA hints)
  - Remediation Steps (numbered, actionable)
  - CTA → pricing.html enterprise upgrade
  - JSON-LD Article schema
  - Full meta SEO head block

SELECTION CRITERIA:
  - risk_score >= 7 (HIGH or CRITICAL)
  - Has at least 1 CVE or IOC
  - Not already published (checks blog/index.json)

OUTPUT:
  blog/<YYYY>/<MM>/<slug>.html        → individual blog post
  blog/index.json                     → blog index (title, url, pub, risk)
  blog/index.html                     → blog listing page (auto-generated)
  blog/sitemap.xml                    → blog sitemap
  blog/feed.xml                       → RSS feed

USAGE:
  python3 scripts/auto_blog_publisher.py                  (publish top 10 new)
  python3 scripts/auto_blog_publisher.py --limit 20       (publish top 20)
  python3 scripts/auto_blog_publisher.py --risk-min 9     (CRITICAL only)
  python3 scripts/auto_blog_publisher.py --dry-run        (no writes)
  python3 scripts/auto_blog_publisher.py --rebuild-index  (refresh listing page)
"""

import json
import re
import sys
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import quote

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [blog-publisher] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("blog-publisher")

REPO = Path(__file__).parent.parent.resolve()
BLOG_DIR = REPO / "blog"

PLATFORM = {
    "name":    "CYBERDUDEBIVASH SENTINEL APEX",
    "short":   "Sentinel APEX",
    "domain":  "https://intel.cyberdudebivash.com",
    "author":  "CYBERDUDEBIVASH",
    "twitter": "@cyberdudebivash",
    "tagline": "World-Class AI-Powered Cybersecurity Threat Intelligence",
}

RISK_LABELS = {10: "CRITICAL", 9: "CRITICAL", 8: "HIGH", 7: "HIGH",
               6: "MEDIUM",    5: "MEDIUM",   4: "LOW",  3: "LOW",  0: "INFO"}

RISK_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#30d158",
    "INFO":     "#636366",
}


def load_feed() -> list:
    for path in ["api/feed.json", "feed.json"]:
        fp = REPO / path
        if fp.exists():
            data = json.loads(fp.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else data.get("advisories", [])
    log.error("No feed file found")
    sys.exit(1)


def load_blog_index() -> dict:
    idx_path = BLOG_DIR / "index.json"
    if idx_path.exists():
        try:
            return json.loads(idx_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"posts": [], "generated_at": ""}


def save_blog_index(index: dict, dry_run: bool = False):
    if dry_run:
        return
    BLOG_DIR.mkdir(parents=True, exist_ok=True)
    index["generated_at"] = datetime.now(timezone.utc).isoformat()
    # Sort by published desc
    index["posts"] = sorted(index["posts"], key=lambda p: p.get("published", ""), reverse=True)
    (BLOG_DIR / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def make_slug(item: dict) -> str:
    """Generate URL-friendly slug from item title."""
    title = item.get("title", item.get("stix_id", "threat-intel"))
    # Extract CVE if present
    cves = item.get("cves", [])
    prefix = cves[0].lower().replace("-", "") + "-" if cves else ""
    slug = re.sub(r'[^a-z0-9]+', '-', title.lower())
    slug = re.sub(r'-+', '-', slug).strip('-')
    full_slug = f"{prefix}{slug}"[:80]
    return full_slug


def risk_label(risk: int | float) -> str:
    r = int(risk or 0)
    return RISK_LABELS.get(r, RISK_LABELS.get(0))


def format_ioc_table(iocs: list) -> str:
    if not iocs:
        return "<p><em>No IOCs extracted for this report.</em></p>"
    rows = ""
    for ioc in iocs[:30]:
        if isinstance(ioc, dict):
            itype = ioc.get("type", "unknown")
            value = ioc.get("value", ioc.get("indicator", ""))
            conf  = ioc.get("confidence", "medium")
        elif isinstance(ioc, str):
            itype, value, conf = "indicator", ioc, "medium"
        else:
            continue
        conf_badge = f'<span class="badge badge-{conf.lower()}">{conf.upper()}</span>'
        value_escaped = value.replace("<", "&lt;").replace(">", "&gt;")[:80]
        rows += f"      <tr><td><code>{itype}</code></td><td><code>{value_escaped}</code></td><td>{conf_badge}</td></tr>\n"
    return f"""    <div class="table-wrap">
      <table class="ioc-table">
        <thead><tr><th>Type</th><th>Indicator</th><th>Confidence</th></tr></thead>
        <tbody>
{rows}        </tbody>
      </table>
    </div>"""


def _normalize_mitre_entry(entry) -> str:
    """Safely extract a string label from a str or dict MITRE entry.
    Returns empty string for None / unrecognized types (never "None" as string)."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return (
            entry.get("name") or entry.get("phase_name") or
            entry.get("tactic") or entry.get("technique") or
            entry.get("external_id") or entry.get("id") or ""
        )
    return ""  # None, int, or other unexpected types → empty string (filtered by caller)


def format_mitre_tactics(tactics: list, techniques: list) -> str:
    if not tactics and not techniques:
        return "<p><em>MITRE ATT&CK mapping not available for this item.</em></p>"
    tags = ""
    for t in (tactics or [])[:8]:
        label = _normalize_mitre_entry(t)
        if label:
            tags += f'<span class="mitre-tag tactic">{label}</span>\n        '
    for t in (techniques or [])[:10]:
        label = _normalize_mitre_entry(t)
        if label:
            tags += f'<span class="mitre-tag technique">{label}</span>\n        '
    return f'<div class="mitre-tags">\n        {tags}\n      </div>'


def format_cve_table(cves: list, item: dict) -> str:
    if not cves:
        return "<p><em>No CVEs associated with this report.</em></p>"
    cvss = item.get("cvss_score", item.get("cvss", "N/A"))
    vendor = item.get("vendor", item.get("affected_vendor", "Unknown"))
    rows = ""
    for cve in cves[:10]:
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        rows += f"""        <tr>
          <td><a href="{nvd_url}" target="_blank" rel="noopener">{cve}</a></td>
          <td>{cvss}</td>
          <td>{vendor}</td>
        </tr>\n"""
    return f"""    <div class="table-wrap">
      <table class="cve-table">
        <thead><tr><th>CVE ID</th><th>CVSS</th><th>Vendor</th></tr></thead>
        <tbody>
{rows}        </tbody>
      </table>
    </div>"""


def build_blog_post(item: dict, slug: str, pub_year: int, pub_month: int) -> str:
    """Generate complete HTML blog post for an intel item."""
    title  = item.get("title", "Threat Intelligence Report")
    risk   = item.get("risk_score", 5)
    rlabel = risk_label(risk)
    rcolor = RISK_COLORS.get(rlabel, "#636366")
    summary = item.get("summary", item.get("description", "No summary available."))
    cves    = item.get("cves", []) or []
    iocs    = item.get("iocs", []) or []
    ioc_cnt = len(iocs) if iocs else item.get("ioc_count", 0)
    tactics    = [_normalize_mitre_entry(t) for t in (item.get("mitre_tactics", item.get("tactics", [])) or []) if _normalize_mitre_entry(t)]
    techniques = [_normalize_mitre_entry(t) for t in (item.get("mitre_techniques", item.get("techniques", [])) or []) if _normalize_mitre_entry(t)]
    actor   = item.get("threat_actor", "") or "Unknown"
    malware = item.get("malware_family", item.get("malware", "")) or "N/A"
    category = item.get("category", "Threat Intelligence")
    stix_id = item.get("stix_id", item.get("id", ""))
    published = (item.get("published_at", "") or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    source_url = item.get("source_url", item.get("url", ""))

    post_url = f"{PLATFORM['domain']}/blog/{pub_year}/{pub_month:02d}/{slug}.html"
    report_url = item.get("report_url", "")
    full_report_url = f"{PLATFORM['domain']}{report_url}" if report_url else ""

    # SEO title (60 chars max)
    seo_title_short = title[:57] + "..." if len(title) > 60 else title
    meta_title = f"{seo_title_short} | {PLATFORM['short']} Threat Intel"

    # Meta description
    cve_str = f"CVEs: {', '.join(cves[:3])}. " if cves else ""
    meta_desc = f"{rlabel} severity threat. {cve_str}{summary[:120]}... Full IOC list, MITRE ATT&CK mapping & detection rules."
    meta_desc = meta_desc[:160]

    # Keywords
    kws = []
    for cve in cves[:3]:
        kws.extend([cve, f"{cve} exploit", f"{cve} vulnerability"])
    if actor not in ("Unknown", "N/A", ""):
        kws.extend([actor, f"{actor} IOC", f"{actor} threat intel"])
    if malware not in ("N/A", "", "Unknown"):
        kws.extend([malware, f"{malware} detection", f"detect {malware}"])
    kws.extend(["cybersecurity threat intelligence", "IOC", "STIX 2.1", "MITRE ATT&CK", "SENTINEL APEX"])
    keywords_str = ", ".join(kws[:20])

    # Detection recommendations
    siem_hints = []
    for ioc in (iocs or [])[:3]:
        if isinstance(ioc, dict):
            v = ioc.get("value", "")
            t = ioc.get("type", "")
        else:
            v, t = str(ioc), "indicator"
        if v:
            siem_hints.append(f'<li><code>{v}</code> — search in proxy/DNS/firewall logs</li>')
    if cves:
        for cve in cves[:2]:
            siem_hints.append(f'<li>Search SIEM for exploit attempts targeting <strong>{cve}</strong></li>')
    if not siem_hints:
        siem_hints = ["<li>Baseline your environment against provided IOCs</li>",
                      "<li>Enable enhanced logging on potentially affected systems</li>"]

    # Remediation
    remed = []
    if cves:
        remed.append(f"Apply vendor patches for {', '.join(cves[:3])} immediately")
    remed.extend([
        "Block all provided IOCs at the perimeter (firewall, proxy, DNS sinkhole)",
        "Hunt for the IOC indicators across SIEM logs for the past 90 days",
        f"Review systems matching the threat actor profile: {actor}",
        "Enable endpoint detection rules for associated MITRE techniques",
        "Notify SOC team and escalate to incident response if IOCs detected",
    ])

    json_ld = json.dumps({
        "@context": "https://schema.org",
        "@type": "TechArticle",
        "headline": meta_title,
        "description": meta_desc,
        "url": post_url,
        "datePublished": published,
        "author": {"@type": "Organization", "name": PLATFORM["author"], "url": PLATFORM["domain"]},
        "publisher": {"@type": "Organization", "name": PLATFORM["name"], "url": PLATFORM["domain"]},
        "keywords": keywords_str,
        "about": {"@type": "Thing", "name": "Cybersecurity Threat Intelligence"},
    }, indent=2)

    remed_items = "".join(f"    <li>{r}</li>\n" for r in remed)
    siem_items  = "".join(f"      {h}\n" for h in siem_hints[:5])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{meta_title}</title>
  <meta name="description" content="{meta_desc}">
  <meta name="keywords" content="{keywords_str}">
  <meta name="author" content="{PLATFORM['author']}">
  <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
  <link rel="canonical" href="{post_url}">
  <meta property="og:type" content="article">
  <meta property="og:title" content="{meta_title}">
  <meta property="og:description" content="{meta_desc}">
  <meta property="og:url" content="{post_url}">
  <meta property="og:site_name" content="{PLATFORM['name']}">
  <meta property="og:image" content="{PLATFORM['domain']}/logo.png">
  <meta property="article:published_time" content="{published}">
  <meta property="article:section" content="Cybersecurity Threat Intelligence">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:site" content="{PLATFORM['twitter']}">
  <meta name="twitter:title" content="{meta_title}">
  <meta name="twitter:description" content="{meta_desc}">
  <meta name="twitter:image" content="{PLATFORM['domain']}/logo.png">
  <script type="application/ld+json">
{json_ld}
  </script>
  <style>
    :root {{
      --bg: #0a0a0f; --surface: #12121a; --border: #1e1e2e;
      --text: #e2e2f0; --muted: #8888aa; --accent: #00d4ff;
      --red: #ff2d55; --orange: #ff6b35; --yellow: #ffd60a;
      --green: #30d158; --font: 'Inter', system-ui, sans-serif;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: var(--font); line-height: 1.7; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }}
    header .logo {{ font-size: 1.1rem; font-weight: 700; color: var(--accent); }}
    header nav a {{ margin-left: 1.5rem; color: var(--muted); font-size: 0.9rem; }}
    .container {{ max-width: 860px; margin: 0 auto; padding: 2rem 1.5rem; }}
    .risk-badge {{ display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.3rem 0.9rem; border-radius: 999px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.05em; background: {rcolor}22; color: {rcolor}; border: 1px solid {rcolor}55; margin-bottom: 1rem; }}
    h1 {{ font-size: clamp(1.4rem, 4vw, 2rem); font-weight: 800; line-height: 1.25; margin-bottom: 1rem; }}
    .meta-row {{ display: flex; flex-wrap: wrap; gap: 1rem; color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }}
    .meta-row span {{ display: flex; align-items: center; gap: 0.3rem; }}
    h2 {{ font-size: 1.2rem; font-weight: 700; color: var(--accent); margin: 2rem 0 0.75rem; padding-left: 0.75rem; border-left: 3px solid var(--accent); }}
    p {{ margin-bottom: 1rem; color: #c8c8e0; }}
    .table-wrap {{ overflow-x: auto; margin: 1rem 0; border-radius: 8px; border: 1px solid var(--border); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: var(--surface); color: var(--muted); font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
    td {{ padding: 0.65rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    code {{ background: #1e1e2e; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.82em; color: var(--accent); word-break: break-all; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.72rem; font-weight: 700; }}
    .badge-high, .badge-HIGH {{ background: #ff6b3522; color: var(--orange); }}
    .badge-medium, .badge-MEDIUM {{ background: #ffd60a22; color: var(--yellow); }}
    .badge-low, .badge-LOW {{ background: #30d15822; color: var(--green); }}
    .badge-critical, .badge-CRITICAL {{ background: #ff2d5522; color: var(--red); }}
    .mitre-tags {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.75rem 0; }}
    .mitre-tag {{ padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }}
    .mitre-tag.tactic {{ background: #0066ff22; color: #4da6ff; border: 1px solid #0066ff44; }}
    .mitre-tag.technique {{ background: #9900ff22; color: #cc88ff; border: 1px solid #9900ff44; }}
    ol, ul {{ padding-left: 1.5rem; margin-bottom: 1rem; color: #c8c8e0; }}
    li {{ margin-bottom: 0.4rem; }}
    .cta-box {{ background: linear-gradient(135deg, #00d4ff11, #9900ff11); border: 1px solid #00d4ff33; border-radius: 12px; padding: 2rem; text-align: center; margin: 2.5rem 0; }}
    .cta-box h3 {{ color: var(--accent); font-size: 1.1rem; margin-bottom: 0.5rem; }}
    .cta-box p {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 1rem; }}
    .cta-btn {{ display: inline-block; background: linear-gradient(135deg, #00d4ff, #9900ff); color: #fff; font-weight: 700; padding: 0.75rem 2rem; border-radius: 8px; font-size: 0.95rem; transition: opacity 0.2s; }}
    .cta-btn:hover {{ opacity: 0.85; text-decoration: none; }}
    .breadcrumb {{ font-size: 0.82rem; color: var(--muted); margin-bottom: 1.5rem; }}
    .breadcrumb a {{ color: var(--muted); }}
    .source-link {{ font-size: 0.8rem; color: var(--muted); }}
    footer {{ background: var(--surface); border-top: 1px solid var(--border); padding: 2rem; text-align: center; color: var(--muted); font-size: 0.82rem; margin-top: 3rem; }}
  </style>
</head>
<body>
<header>
  <a class="logo" href="{PLATFORM['domain']}">⚡ {PLATFORM['short']}</a>
  <nav>
    <a href="{PLATFORM['domain']}">Dashboard</a>
    <a href="{PLATFORM['domain']}/blog/">Blog</a>
    <a href="{PLATFORM['domain']}/pricing.html">Pricing</a>
    <a href="{PLATFORM['domain']}/enterprise.html">Enterprise</a>
  </nav>
</header>

<div class="container">
  <div class="breadcrumb">
    <a href="{PLATFORM['domain']}">Home</a> /
    <a href="{PLATFORM['domain']}/blog/">Threat Intel Blog</a> /
    <span>{category}</span>
  </div>

  <div class="risk-badge">⚠ {rlabel} — Risk {risk}/10</div>
  <h1>{title}</h1>

  <div class="meta-row">
    <span>📅 {published}</span>
    <span>🏷 {category}</span>
    <span>🎯 {actor}</span>
    <span>🦠 {malware}</span>
    <span>🔍 {ioc_cnt} IOCs</span>
    {f'<span>🔗 <a href="{source_url}" target="_blank" rel="noopener" class="source-link">Source</a></span>' if source_url else ''}
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <p>{summary}</p>
  <p>This is a <strong>{rlabel}</strong> severity threat with a risk score of <strong>{risk}/10</strong>.
  {f"Associated CVEs: <strong>{', '.join(cves)}</strong>. " if cves else ""}
  {f"Threat actor: <strong>{actor}</strong>. " if actor not in ("Unknown","N/A","") else ""}
  {f"Malware family: <strong>{malware}</strong>." if malware not in ("N/A","","Unknown") else ""}</p>

  <!-- CVE Details -->
  <h2>CVE Details</h2>
{format_cve_table(cves, item)}

  <!-- Indicators of Compromise -->
  <h2>Indicators of Compromise (IOCs)</h2>
{format_ioc_table(iocs)}

  <!-- MITRE ATT&CK -->
  <h2>MITRE ATT&CK Coverage</h2>
{format_mitre_tactics(tactics, techniques)}

  <!-- Detection Recommendations -->
  <h2>Detection Recommendations</h2>
  <p>Search your SIEM, proxy logs, DNS logs, and endpoint telemetry for the following indicators:</p>
  <ul>
{siem_items}  </ul>

  <!-- Remediation -->
  <h2>Remediation Steps</h2>
  <ol>
{remed_items}  </ol>

  {f'<p><a href="{full_report_url}">→ View full automated threat report</a></p>' if full_report_url else ''}

  <!-- CTA Box -->
  <div class="cta-box">
    <h3>🛡 Get Real-Time Enterprise Threat Intelligence</h3>
    <p>Full STIX 2.1 feed · TAXII 2.1 · SIEM integrations · YARA rules · 24/7 AI monitoring</p>
    <a class="cta-btn" href="{PLATFORM['domain']}/pricing.html?plan=enterprise&source=blog">
      Start Enterprise Trial — Free 30 Days
    </a>
  </div>

</div><!-- /container -->

<footer>
  <p>© {published[:4]} {PLATFORM['name']} · <a href="{PLATFORM['domain']}">intel.cyberdudebivash.com</a></p>
  <p style="margin-top:0.5rem;">
    <a href="{PLATFORM['domain']}/blog/">Blog</a> ·
    <a href="{PLATFORM['domain']}/pricing.html">Pricing</a> ·
    <a href="{PLATFORM['domain']}/enterprise.html">Enterprise</a> ·
    <a href="{PLATFORM['domain']}/trust-center.html">Trust Center</a>
  </p>
  <p style="margin-top:0.5rem; font-size:0.75rem;">
    TLP:CLEAR · STIX ID: <code>{stix_id}</code>
  </p>
</footer>
</body>
</html>"""
    return html


def build_blog_index_page(index: dict) -> str:
    """Generate the blog listing page at blog/index.html."""
    posts = index.get("posts", [])
    post_cards = ""
    for post in posts[:50]:
        risk = post.get("risk_score", 0)
        rlabel = risk_label(risk)
        rcolor = RISK_COLORS.get(rlabel, "#636366")
        title = post.get("title", "Threat Report")[:80]
        pub   = post.get("published", "")[:10]
        url   = post.get("url", "#")
        cves  = post.get("cves", [])
        cve_str = f' · {", ".join(cves[:2])}' if cves else ""
        actor = post.get("actor", "")
        actor_str = f' · {actor}' if actor and actor not in ("Unknown","N/A","") else ""
        post_cards += f"""
    <article class="post-card" onclick="location.href='{url}'">
      <div class="post-risk" style="color:{rcolor};">{rlabel} {risk}/10</div>
      <h2><a href="{url}">{title}</a></h2>
      <div class="post-meta">{pub}{cve_str}{actor_str}</div>
    </article>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cybersecurity Threat Intelligence Blog | SENTINEL APEX</title>
  <meta name="description" content="Real-time AI-powered cybersecurity threat intelligence blog. CVE analysis, IOC reports, MITRE ATT&CK mapping, threat actor profiles. Updated daily.">
  <meta name="keywords" content="cybersecurity threat intelligence, CVE analysis, IOC, STIX 2.1, MITRE ATT&CK, threat hunting, SENTINEL APEX">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="{PLATFORM['domain']}/blog/">
  <meta property="og:title" content="Cybersecurity Threat Intelligence Blog | SENTINEL APEX">
  <meta property="og:type" content="website">
  <meta property="og:url" content="{PLATFORM['domain']}/blog/">
  <meta property="og:site_name" content="{PLATFORM['name']}">
  <script type="application/ld+json">{{
    "@context":"https://schema.org","@type":"Blog",
    "name":"SENTINEL APEX Threat Intelligence Blog",
    "url":"{PLATFORM['domain']}/blog/",
    "publisher":{{"@type":"Organization","name":"{PLATFORM['name']}","url":"{PLATFORM['domain']}"}}
  }}</script>
  <style>
    :root {{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--text:#e2e2f0;--muted:#8888aa;--accent:#00d4ff;--font:'Inter',system-ui,sans-serif;}}
    *{{box-sizing:border-box;margin:0;padding:0;}}
    body{{background:var(--bg);color:var(--text);font-family:var(--font);}}
    a{{color:var(--accent);text-decoration:none;}}
    header{{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center;}}
    .logo{{font-size:1.1rem;font-weight:700;color:var(--accent);}}
    nav a{{margin-left:1.5rem;color:var(--muted);font-size:0.9rem;}}
    .hero{{padding:3rem 2rem;text-align:center;border-bottom:1px solid var(--border);}}
    .hero h1{{font-size:clamp(1.5rem,4vw,2.2rem);font-weight:800;margin-bottom:0.75rem;}}
    .hero p{{color:var(--muted);max-width:600px;margin:0 auto;}}
    .posts{{max-width:860px;margin:2rem auto;padding:0 1.5rem;display:grid;gap:1rem;}}
    .post-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem 1.5rem;cursor:pointer;transition:border-color 0.2s,transform 0.2s;}}
    .post-card:hover{{border-color:var(--accent);transform:translateY(-2px);}}
    .post-risk{{font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.4rem;}}
    .post-card h2{{font-size:1rem;font-weight:600;margin-bottom:0.35rem;line-height:1.4;}}
    .post-card h2 a{{color:var(--text);}}
    .post-meta{{font-size:0.8rem;color:var(--muted);}}
    footer{{background:var(--surface);border-top:1px solid var(--border);padding:2rem;text-align:center;color:var(--muted);font-size:0.82rem;margin-top:3rem;}}
  </style>
</head>
<body>
<header>
  <a class="logo" href="{PLATFORM['domain']}">⚡ Sentinel APEX</a>
  <nav>
    <a href="{PLATFORM['domain']}">Dashboard</a>
    <a href="{PLATFORM['domain']}/pricing.html">Pricing</a>
    <a href="{PLATFORM['domain']}/enterprise.html">Enterprise</a>
  </nav>
</header>
<div class="hero">
  <h1>🛡 Cybersecurity Threat Intelligence Blog</h1>
  <p>AI-powered daily threat reports · CVE analysis · IOC feeds · MITRE ATT&CK mapping</p>
  <p style="margin-top:0.5rem;font-size:0.85rem;color:var(--muted);">{len(posts)} reports published · Updated daily</p>
</div>
<div class="posts">
{post_cards}
</div>
<footer>
  <p>© {datetime.now().year} {PLATFORM['name']} · <a href="{PLATFORM['domain']}">intel.cyberdudebivash.com</a></p>
  <p style="margin-top:0.5rem;">
    <a href="{PLATFORM['domain']}/sitemap.xml">Sitemap</a> ·
    <a href="{PLATFORM['domain']}/blog/feed.xml">RSS Feed</a> ·
    <a href="{PLATFORM['domain']}/pricing.html">Pricing</a>
  </p>
</footer>
</body>
</html>"""


def build_rss_feed(index: dict) -> str:
    """Generate RSS feed for the blog."""
    posts = index.get("posts", [])[:20]
    items_xml = ""
    for post in posts:
        title   = post.get("title", "Threat Report").replace("&", "&amp;").replace("<","&lt;").replace(">","&gt;")
        url     = post.get("url", "")
        pub     = post.get("published", "")[:10]
        summary = post.get("summary", "")[:200].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        cves    = ", ".join(post.get("cves", []))
        items_xml += f"""  <item>
    <title>{title}</title>
    <link>{url}</link>
    <guid isPermaLink="true">{url}</guid>
    <pubDate>{pub}</pubDate>
    <description>{summary} CVEs: {cves}</description>
    <category>Cybersecurity Threat Intelligence</category>
  </item>\n"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>{PLATFORM['name']} — Threat Intelligence Blog</title>
  <link>{PLATFORM['domain']}/blog/</link>
  <description>AI-powered cybersecurity threat intelligence. Daily CVE analysis, IOC feeds, MITRE ATT&CK mapping.</description>
  <language>en-us</language>
  <lastBuildDate>{datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")}</lastBuildDate>
  <atom:link href="{PLATFORM['domain']}/blog/feed.xml" rel="self" type="application/rss+xml"/>
  <managingEditor>{PLATFORM['author']}</managingEditor>
  <image>
    <url>{PLATFORM['domain']}/logo.png</url>
    <title>{PLATFORM['short']}</title>
    <link>{PLATFORM['domain']}/blog/</link>
  </image>
{items_xml}</channel>
</rss>"""


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Auto Blog Publisher")
    parser.add_argument("--dry-run",       action="store_true")
    parser.add_argument("--limit",         type=int, default=10, help="Max posts to publish per run (default: 10)")
    parser.add_argument("--risk-min",      type=int, default=7,  help="Minimum risk score (default: 7)")
    parser.add_argument("--rebuild-index", action="store_true",  help="Rebuild index.html from index.json only")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("SENTINEL APEX — AUTO BLOG PUBLISHER v1.0")
    log.info(f"Mode: {'DRY-RUN' if args.dry_run else 'LIVE'} | Risk min: {args.risk_min} | Limit: {args.limit}")
    log.info("=" * 70)

    items = load_feed()
    index = load_blog_index()
    published_ids = {p["stix_id"] for p in index.get("posts", [])}

    if args.rebuild_index:
        log.info("Rebuilding blog index page from existing index.json...")
        if not args.dry_run:
            BLOG_DIR.mkdir(parents=True, exist_ok=True)
            (BLOG_DIR / "index.html").write_text(build_blog_index_page(index), encoding="utf-8")
            (BLOG_DIR / "feed.xml").write_text(build_rss_feed(index), encoding="utf-8")
            log.info("Blog index.html and feed.xml rebuilt.")
        return

    # Filter candidates
    candidates = [
        item for item in items
        if item.get("risk_score", 0) >= args.risk_min
        and item.get("stix_id", item.get("id", "")) not in published_ids
        and (item.get("cves") or item.get("iocs") or item.get("ioc_count", 0) > 0)
    ]
    candidates.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    targets = candidates[:args.limit]

    log.info(f"Feed: {len(items)} items | Eligible new: {len(candidates)} | Publishing: {len(targets)}")

    published = 0
    for item in targets:
        stix_id = item.get("stix_id", item.get("id", ""))
        slug    = make_slug(item)
        pub_raw = item.get("published_at", "") or datetime.now(timezone.utc).isoformat()
        try:
            pub_dt = datetime.fromisoformat(pub_raw.replace("Z", "+00:00"))
        except Exception:
            pub_dt = datetime.now(timezone.utc)

        pub_year  = pub_dt.year
        pub_month = pub_dt.month

        post_html = build_blog_post(item, slug, pub_year, pub_month)
        post_url  = f"{PLATFORM['domain']}/blog/{pub_year}/{pub_month:02d}/{slug}.html"

        if not args.dry_run:
            out_dir = BLOG_DIR / str(pub_year) / f"{pub_month:02d}"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{slug}.html"
            out_path.write_text(post_html, encoding="utf-8")

        # Add to index
        index["posts"].append({
            "stix_id":    stix_id,
            "title":      item.get("title", ""),
            "slug":       slug,
            "url":        post_url,
            "published":  pub_dt.strftime("%Y-%m-%d"),
            "risk_score": item.get("risk_score", 0),
            "ioc_count":  ioc_cnt,
            "cves":       item.get("cves", [])[:3],
            "actor":      item.get("threat_actor", ""),
            "summary":    (item.get("summary", "") or "")[:200],
        })
        published += 1
        log.info(f"  ✔ Published: {slug} (risk={item.get('risk_score',0)}, stix={stix_id[:20]}...)")

    if not args.dry_run and published > 0:
        save_blog_index(index, dry_run=False)
        BLOG_DIR.mkdir(parents=True, exist_ok=True)
        (BLOG_DIR / "index.html").write_text(build_blog_index_page(index), encoding="utf-8")
        (BLOG_DIR / "feed.xml").write_text(build_rss_feed(index), encoding="utf-8")
        log.info(f"Blog index.html + feed.xml updated. Total posts: {len(index['posts'])}")

    log.info("=" * 70)
    log.info(f"AUTO BLOG PUBLISHER COMPLETE -- Published: {published} new posts")
    log.info("=" * 70)


if __name__ == "__main__":
    main()
