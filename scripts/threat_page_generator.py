import json
import os
import re
from datetime import datetime
from pathlib import Path

MANIFEST_PATH = "data/stix/feed_manifest.json"
OUTPUT_DIR = "threat"
BASE_URL = "https://intel.cyberdudebivash.com"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------
# UTILITIES
# ---------------------------

def slugify(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'\s+', '-', text)
    return text[:80]

def safe_get(entry, key, default="N/A"):
    return entry.get(key) or default

# ---------------------------
# HTML TEMPLATE (ENTERPRISE)
# ---------------------------

def generate_html(entry, all_entries):
    title = safe_get(entry, "title")
    risk = safe_get(entry, "risk_score")
    blog_url = safe_get(entry, "blog_url", "#")
    stix_id = safe_get(entry, "stix_id", "unknown")

    slug = slugify(title)
    filename = f"{slug}.html"

    # Internal linking (last 3 threats)
    related_links = ""
    for e in all_entries[:3]:
        rel_title = safe_get(e, "title")
        rel_slug = slugify(rel_title)
        related_links += f'<li><a href="/threat/{rel_slug}.html">{rel_title}</a></li>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} | CYBERDUDEBIVASH Threat Intelligence</title>

<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="{title} threat analysis, mitigation, and intelligence report.">
<meta name="keywords" content="cybersecurity, threat intelligence, {title}, CVE, malware">

<link rel="canonical" href="{BASE_URL}/threat/{slug}.html">

<!-- Open Graph -->
<meta property="og:title" content="{title}">
<meta property="og:description" content="Threat intelligence report on {title}">
<meta property="og:type" content="article">

<!-- AdSense -->
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>

<style>
body {{
    font-family: system-ui;
    background: #0b0f1a;
    color: #e6edf3;
    margin: 0;
}}
.container {{
    max-width: 900px;
    margin: auto;
    padding: 20px;
}}
h1 {{ color: #58a6ff; }}
.card {{
    background: #111827;
    padding: 20px;
    border-radius: 12px;
}}
.section {{ margin-top: 30px; }}
a {{ color: #58a6ff; }}
</style>
</head>

<body>
<div class="container">

<h1>{title}</h1>

<div class="card">
<p><strong>Risk Score:</strong> {risk}/10</p>
<p><strong>STIX ID:</strong> {stix_id}</p>
<p><strong>Published:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</p>
</div>

<div class="section">
<h2>Threat Overview</h2>
<p>This report provides a detailed analysis of {title}, including attack vectors, exploitation methods, and defensive strategies.</p>
</div>

<div class="section">
<h2>Technical Analysis</h2>
<p>Attackers may exploit vulnerabilities, misconfigurations, or zero-day conditions to gain unauthorized access and execute malicious operations.</p>
</div>

<div class="section">
<h2>Impact Assessment</h2>
<p>Potential impact includes data exfiltration, lateral movement, persistence, and full system compromise.</p>
</div>

<div class="section">
<h2>Mitigation Strategies</h2>
<ul>
<li>Apply latest patches</li>
<li>Monitor indicators of compromise</li>
<li>Deploy EDR/XDR solutions</li>
<li>Restrict privileges</li>
</ul>
</div>

<!-- Ad Block -->
<div class="section">
<ins class="adsbygoogle"
     style="display:block"
     data-ad-client="ca-pub-XXXXXXXXXXXX"
     data-ad-slot="1234567890"
     data-ad-format="auto"></ins>
<script>
(adsbygoogle = window.adsbygoogle || []).push({{}});
</script>
</div>

<div class="section">
<h2>Full Report</h2>
<p><a href="{blog_url}" target="_blank">Read Full Intelligence Report</a></p>
</div>

<div class="section">
<h2>Related Threats</h2>
<ul>
{related_links}
</ul>
</div>

</div>
</body>
</html>
"""
    return filename, html, slug

# ---------------------------
# SITEMAP GENERATOR
# ---------------------------

def generate_sitemap(slugs):
    sitemap_path = "sitemap.xml"
    with open(sitemap_path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        for slug in slugs:
            f.write(f"<url><loc>{BASE_URL}/threat/{slug}.html</loc></url>\n")
        f.write("</urlset>")
    print("[+] Sitemap generated")

# ---------------------------
# MAIN
# ---------------------------

def main():
    if not os.path.exists(MANIFEST_PATH):
        print("[!] Manifest not found, skipping...")
        return

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    slugs = []

    for entry in data:
        filename, html, slug = generate_html(entry, data)
        path = os.path.join(OUTPUT_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        slugs.append(slug)

    generate_sitemap(slugs)

    print(f"[+] Generated {len(data)} threat pages")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}")