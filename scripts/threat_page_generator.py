"""
threat_page_generator.py — SENTINEL APEX v74.3.1
Enhanced SEO + Monetization Edition
=====================================================================
Generates individual threat report pages from the manifest.
v74.3.1 Enhancements:
  - JSON-LD structured data (Article + FAQPage schema for Google Rich Results)
  - Enhanced Open Graph + Twitter Card meta tags
  - Enrichment data display (threat_type, exploit_probability, MITRE, OpenClaw)
  - Gumroad product CTAs with UTM tracking
  - Internal linking (related threats by threat_type)
  - Professional SOC-grade visual design matching dashboard
  - AdSense integration preserved
  - Sitemap with lastmod dates + priority scoring
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from html import escape

MANIFEST_PATH = "data/stix/feed_manifest.json"
OUTPUT_DIR = "threat"
BASE_URL = "https://intel.cyberdudebivash.com"
BLOG_URL = "https://blog.cyberdudebivash.com"
GUMROAD_URL = "https://cyberdudebivash.gumroad.com"
COMPANY = "CyberDudeBivash Pvt. Ltd."

os.makedirs(OUTPUT_DIR, exist_ok=True)


def slugify(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'\s+', '-', text)
    return text[:80]


def safe(entry, key, default="N/A"):
    return entry.get(key) or default


def severity_color(risk):
    try:
        r = float(risk)
    except (TypeError, ValueError):
        return "#6B7C93"
    if r >= 9:
        return "#FF4444"
    elif r >= 7:
        return "#FF8C00"
    elif r >= 4:
        return "#FFB800"
    return "#00C9A7"


def severity_label(risk):
    try:
        r = float(risk)
    except (TypeError, ValueError):
        return "INFO"
    if r >= 9:
        return "CRITICAL"
    elif r >= 7:
        return "HIGH"
    elif r >= 4:
        return "MEDIUM"
    return "LOW"


def find_related(entry, all_entries, max_related=5):
    """Find related threats by threat_type + actor_tag."""
    tt = entry.get("threat_type", "General")
    actor = entry.get("actor_tag", "")
    stix_id = entry.get("stix_id", "")
    related = []
    for e in all_entries:
        if e.get("stix_id") == stix_id:
            continue
        if e.get("threat_type") == tt or (actor and actor != "UNC-CDB-99" and e.get("actor_tag") == actor):
            related.append(e)
        if len(related) >= max_related:
            break
    return related


def generate_html(entry, all_entries):
    title = safe(entry, "title")
    title_escaped = escape(title)
    risk = safe(entry, "risk_score", "0")
    blog_url = safe(entry, "blog_url", "#")
    stix_id = safe(entry, "stix_id", "unknown")
    timestamp = safe(entry, "timestamp", "")[:19]
    tt = safe(entry, "threat_type", "General")
    ep = safe(entry, "exploit_probability", "Unknown")
    actor = safe(entry, "actor_tag", "Unknown")
    mitre = entry.get("mitre_tactics", [])
    kev = entry.get("kev_present", False)
    cvss = entry.get("cvss_score")
    epss = entry.get("epss_score")
    confidence = entry.get("confidence", 0)
    oc = entry.get("openclaw", {})
    alert = entry.get("alert", {})
    campaign = entry.get("campaign", {})
    correlation = entry.get("correlation", {})

    slug = slugify(title)
    filename = f"{slug}.html"
    page_url = f"{BASE_URL}/threat/{filename}"
    sev = severity_label(risk)
    sev_color = severity_color(risk)
    date_published = timestamp[:10] if timestamp else datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # CVE extraction for FAQ schema
    cves = re.findall(r'CVE-\d{4}-\d{4,}', title, re.IGNORECASE)
    cve_display = ", ".join(cves) if cves else ""

    # Related threats
    related = find_related(entry, all_entries)
    related_html = ""
    for r in related:
        r_slug = slugify(safe(r, "title"))
        r_sev = severity_label(safe(r, "risk_score", "0"))
        r_color = severity_color(safe(r, "risk_score", "0"))
        related_html += f'<a href="/threat/{r_slug}.html" style="display:block;padding:12px 16px;background:rgba(0,255,198,0.04);border-radius:8px;border:1px solid rgba(0,255,198,0.1);margin-bottom:8px;text-decoration:none;color:#C9D1D9;transition:border-color 0.2s;"><span style="color:{r_color};font-weight:700;font-size:11px;letter-spacing:1px;">{r_sev}</span> {escape(safe(r,"title"))[:70]}</a>\n'

    # MITRE display
    mitre_chips = ""
    for t in mitre[:6]:
        mitre_chips += f'<span style="display:inline-block;padding:3px 10px;background:rgba(88,166,255,0.12);border:1px solid rgba(88,166,255,0.25);border-radius:4px;font-size:12px;color:#58A6FF;margin:3px;font-family:monospace;">{escape(str(t))}</span>'

    # OpenClaw patterns
    oc_patterns = ""
    if oc and oc.get("patterns"):
        for p in oc["patterns"][:4]:
            oc_patterns += f'<span style="display:inline-block;padding:3px 10px;background:rgba(255,140,0,0.1);border:1px solid rgba(255,140,0,0.25);border-radius:4px;font-size:12px;color:#FF8C00;margin:3px;">{escape(str(p))}</span>'

    # JSON-LD structured data (Article schema for Google)
    json_ld_article = json.dumps({
        "@context": "https://schema.org",
        "@type": "TechArticle",
        "headline": title_escaped[:110],
        "description": f"Threat intelligence analysis of {title_escaped[:80]}. Risk score: {risk}/10. Classification: {tt}.",
        "author": {"@type": "Organization", "name": COMPANY, "url": "https://cyberdudebivash.com"},
        "publisher": {"@type": "Organization", "name": COMPANY, "logo": {"@type": "ImageObject", "url": f"{BASE_URL}/assets/logo.png"}},
        "datePublished": date_published,
        "dateModified": date_published,
        "url": page_url,
        "mainEntityOfPage": page_url,
        "articleSection": "Threat Intelligence",
        "keywords": f"cybersecurity, {tt}, threat intelligence" + (f", {cve_display}" if cve_display else ""),
    }, ensure_ascii=False)

    # FAQ schema (helps with Google rich results)
    faq_items = [
        {"@type": "Question", "name": f"What is the risk level of {title_escaped[:60]}?", "acceptedAnswer": {"@type": "Answer", "text": f"This threat has a risk score of {risk}/10 ({sev}). Exploit probability is {ep}."}},
        {"@type": "Question", "name": f"How should organizations respond to this threat?", "acceptedAnswer": {"@type": "Answer", "text": "Organizations should apply patches, monitor IOCs, deploy EDR/XDR solutions, and restrict network privileges. See the full report for specific mitigation steps."}},
    ]
    if cves:
        faq_items.append({"@type": "Question", "name": f"What is {cves[0]}?", "acceptedAnswer": {"@type": "Answer", "text": f"{cves[0]} is a vulnerability tracked in this advisory with a risk score of {risk}/10. It is classified as {tt} with exploit probability: {ep}."}})

    json_ld_faq = json.dumps({"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": faq_items}, ensure_ascii=False)

    # KEV badge
    kev_badge = '<span style="display:inline-block;padding:4px 12px;background:rgba(255,68,68,0.15);border:1px solid #FF4444;border-radius:4px;color:#FF4444;font-size:12px;font-weight:700;letter-spacing:1px;">CISA KEV</span>' if kev else ""

    # Campaign badge
    camp_badge = ""
    if campaign:
        camp_badge = f'<span style="display:inline-block;padding:4px 12px;background:rgba(168,85,247,0.12);border:1px solid rgba(168,85,247,0.4);border-radius:4px;color:#A855F7;font-size:12px;margin-left:6px;">{escape(campaign.get("name","")[:40])}</span>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title_escaped} | CYBERDUDEBIVASH Threat Intelligence</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="{title_escaped[:140]}. Risk: {risk}/10 ({sev}). Type: {tt}. Exploit probability: {ep}. Full analysis by CyberDudeBivash SENTINEL APEX.">
<meta name="keywords" content="cybersecurity, threat intelligence, {tt}, {escape(actor)}, {''.join(cves)}, MITRE ATT&CK, SOC, STIX">
<meta name="author" content="{COMPANY}">
<meta name="robots" content="index, follow">
<link rel="canonical" href="{page_url}">
<meta property="og:title" content="{title_escaped[:70]}">
<meta property="og:description" content="Risk {risk}/10 ({sev}). {tt} threat intelligence report by CyberDudeBivash SENTINEL APEX.">
<meta property="og:type" content="article">
<meta property="og:url" content="{page_url}">
<meta property="og:site_name" content="CyberDudeBivash SENTINEL APEX">
<meta name="twitter:card" content="summary">
<meta name="twitter:site" content="@cyberbivash">
<meta name="twitter:title" content="{title_escaped[:70]}">
<meta name="twitter:description" content="Risk {risk}/10 — {tt} threat analysis by SENTINEL APEX">
<script type="application/ld+json">{json_ld_article}</script>
<script type="application/ld+json">{json_ld_faq}</script>
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Space Grotesk',system-ui,sans-serif;background:#060a10;color:#C9D1D9;line-height:1.7}}
a{{color:#00FFC6;text-decoration:none}}
a:hover{{text-decoration:underline}}
.wrap{{max-width:880px;margin:0 auto;padding:20px}}
.topbar{{background:rgba(0,255,198,0.06);border-bottom:1px solid rgba(0,255,198,0.15);padding:10px 20px;font-size:13px;letter-spacing:2px;color:#6B7C93;display:flex;justify-content:space-between;align-items:center}}
.topbar a{{color:#00FFC6;font-weight:600}}
.hero{{padding:40px 0 30px;border-bottom:1px solid rgba(255,255,255,0.06)}}
.hero h1{{font-size:clamp(22px,3vw,32px);color:#E6EDF3;font-weight:700;line-height:1.3;margin-bottom:16px}}
.sev-badge{{display:inline-block;padding:5px 16px;border-radius:6px;font-size:13px;font-weight:700;letter-spacing:1.5px;color:#fff;background:{sev_color}}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:24px 0}}
.metric{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:10px;padding:16px;text-align:center}}
.metric-val{{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace}}
.metric-label{{font-size:11px;color:#6B7C93;letter-spacing:1px;margin-top:4px}}
.card{{background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:24px;margin:20px 0}}
.card h2{{font-size:16px;color:#E6EDF3;margin-bottom:14px;letter-spacing:1px}}
.cta-box{{background:linear-gradient(135deg,rgba(0,255,198,0.08),rgba(88,166,255,0.08));border:1px solid rgba(0,255,198,0.2);border-radius:12px;padding:28px;text-align:center;margin:30px 0}}
.cta-box h3{{font-size:18px;color:#E6EDF3;margin-bottom:10px}}
.cta-btn{{display:inline-block;padding:12px 32px;background:#00FFC6;color:#060a10;font-weight:700;border-radius:8px;font-size:14px;letter-spacing:1px;margin-top:12px;transition:transform 0.2s}}
.cta-btn:hover{{transform:translateY(-2px);text-decoration:none}}
.footer{{padding:40px 0;border-top:1px solid rgba(255,255,255,0.06);text-align:center;font-size:13px;color:#6B7C93;margin-top:40px}}
@media(max-width:600px){{.metrics{{grid-template-columns:1fr 1fr}}.wrap{{padding:12px}}}}
</style>
</head>
<body>
<div class="topbar">
<span>CYBERDUDEBIVASH SENTINEL APEX</span>
<a href="{BASE_URL}/">&larr; DASHBOARD</a>
</div>
<div class="wrap">
<div class="hero">
<span class="sev-badge">{sev}</span> {kev_badge} {camp_badge}
<h1>{title_escaped}</h1>
<p style="color:#6B7C93;font-size:14px;">Published {date_published} &middot; STIX ID: <code style="font-size:12px;color:#58A6FF;">{escape(stix_id)[:40]}</code></p>
</div>

<div class="metrics">
<div class="metric"><div class="metric-val" style="color:{sev_color}">{risk}</div><div class="metric-label">RISK SCORE</div></div>
<div class="metric"><div class="metric-val">{escape(str(tt))}</div><div class="metric-label">THREAT TYPE</div></div>
<div class="metric"><div class="metric-val">{escape(str(ep))}</div><div class="metric-label">EXPLOIT PROB</div></div>
<div class="metric"><div class="metric-val">{escape(str(actor)[:15])}</div><div class="metric-label">ACTOR</div></div>
</div>

{"<div class='card'><h2>CVSS / EPSS</h2><p>CVSS: <strong>" + str(cvss) + "</strong> &middot; EPSS: <strong>" + str(epss) + "</strong></p></div>" if cvss else ""}

<div class="card">
<h2>MITRE ATT&CK TECHNIQUES</h2>
{mitre_chips if mitre_chips else '<p style="color:#6B7C93;">No MITRE techniques mapped</p>'}
</div>

{"<div class='card'><h2>OPENCLAW BEHAVIORAL ANALYSIS</h2><p>Intelligence Score: <strong>" + str(oc.get('score',0)) + "/100</strong> &middot; Anomaly: <strong>" + str(oc.get('anomaly',False)) + "</strong> &middot; Velocity: <strong>" + str(oc.get('velocity','stable')) + "</strong></p><div style='margin-top:10px;'>" + oc_patterns + "</div></div>" if oc else ""}

<div class="card">
<h2>THREAT OVERVIEW</h2>
<p>This advisory covers <strong>{title_escaped[:100]}</strong>, a <strong>{escape(str(tt))}</strong> threat with a risk score of <strong>{risk}/10</strong>. {"This vulnerability is tracked in the <strong>CISA Known Exploited Vulnerabilities</strong> catalog, confirming active exploitation in the wild." if kev else "Organizations should assess exposure and apply recommended mitigations."}</p>
</div>

<div class="card">
<h2>RECOMMENDED ACTIONS</h2>
<ul style="padding-left:20px;line-height:2.2;">
<li>Apply vendor patches and security updates immediately</li>
<li>Monitor the IOCs associated with this threat using your SIEM/SOAR</li>
<li>Review MITRE ATT&CK techniques above for detection rule creation</li>
<li>Deploy EDR/XDR coverage for the affected attack surface</li>
{"<li><strong>CISA KEV:</strong> This is a mandatory remediation item per BOD 22-01</li>" if kev else ""}
</ul>
</div>

{"<div class='card'><h2>FULL INTELLIGENCE REPORT</h2><p>Read the complete analyst report with IOCs, STIX bundles, and detection rules:</p><p style='margin-top:12px;'><a href='" + escape(blog_url) + "' target='_blank' rel='noopener' style='color:#00FFC6;font-weight:600;'>View Full Report on CyberDudeBivash Blog &rarr;</a></p></div>" if blog_url != "#" else ""}

<div class="cta-box">
<h3>Get Premium Threat Intelligence</h3>
<p style="color:#9FB3C8;font-size:14px;">Access STIX bundles, detection rules (Sigma, YARA, Suricata), IOC feeds, and API access.</p>
<a href="{GUMROAD_URL}/?utm_source=threat-page&utm_medium={slug[:30]}&utm_campaign=cta" class="cta-btn" target="_blank" rel="noopener">VIEW PRODUCTS</a>
</div>

<ins class="adsbygoogle" style="display:block" data-ad-format="auto" data-full-width-responsive="true"></ins>
<script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>

{"<div class='card'><h2>RELATED THREATS</h2>" + related_html + "</div>" if related_html else ""}

<div class="footer">
<p>&copy; 2026 {COMPANY} &middot; <a href="{BASE_URL}/">SENTINEL APEX Dashboard</a> &middot; <a href="{BASE_URL}/threat/">SOC 3.0</a> &middot; <a href="{GUMROAD_URL}" target="_blank">Products</a></p>
</div>
</div>
</body>
</html>"""
    return filename, html, slug, date_published


def generate_sitemap(entries_data):
    """Enhanced sitemap with lastmod, priority, and changefreq."""
    with open("sitemap.xml", "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        # Main pages
        f.write(f'<url><loc>{BASE_URL}/</loc><changefreq>hourly</changefreq><priority>1.0</priority></url>\n')
        f.write(f'<url><loc>{BASE_URL}/threat/</loc><changefreq>hourly</changefreq><priority>0.9</priority></url>\n')
        f.write(f'<url><loc>{BASE_URL}/api/</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n')
        # Threat pages
        for slug, date, risk in entries_data:
            try:
                r = float(risk)
            except (TypeError, ValueError):
                r = 5.0
            priority = "0.8" if r >= 9 else "0.6" if r >= 7 else "0.5"
            f.write(f'<url><loc>{BASE_URL}/threat/{slug}.html</loc><lastmod>{date}</lastmod><changefreq>weekly</changefreq><priority>{priority}</priority></url>\n')
        f.write('</urlset>')
    print(f"[+] Sitemap generated: {len(entries_data) + 3} URLs")


def main():
    if not os.path.exists(MANIFEST_PATH):
        print("[!] Manifest not found, skipping...")
        return

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries_data = []
    generated = 0

    for entry in data:
        try:
            filename, html, slug, date = generate_html(entry, data)
            path = os.path.join(OUTPUT_DIR, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            entries_data.append((slug, date, entry.get("risk_score", 5)))
            generated += 1
        except Exception as e:
            print(f"[WARN] Skipping entry: {e}")
            continue

    generate_sitemap(entries_data)
    print(f"[+] Generated {generated} threat pages (SEO + monetization enhanced)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}")
