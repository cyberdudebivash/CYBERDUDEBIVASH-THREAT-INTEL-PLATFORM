#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — SOCIAL AMPLIFIER v1.0
=======================================
Phase 6: Global Authority Content Pipeline

WHAT IT DOES:
  For each newly published blog post, generates platform-optimized social
  copy for LinkedIn, Twitter/X, and Telegram — ready to post or auto-push
  via API.

OUTPUT PER POST:
  LinkedIn post  — 1200–1500 chars, authority tone, 3 hashtags, CTA link
  Twitter/X post — ≤280 chars, hook + CVE + risk + link
  Telegram post  — HTML-formatted, full context, Sentinel brand voice
  Mastodon post  — 500 chars, fediverse-friendly

OUTPUT FILES:
  data/social_queue/<YYYYMMDD>/<slug>_linkedin.txt   → paste into LinkedIn
  data/social_queue/<YYYYMMDD>/<slug>_twitter.txt    → paste into Twitter/X
  data/social_queue/<YYYYMMDD>/<slug>_telegram.html  → Telegram HTML-formatted
  data/social_queue/queue.json                        → API-ready queue

LINKEDIN VOICE:
  Professional authority — CISO / threat researcher persona
  Leads with the threat hook, provides business context, ends with CTA
  Hashtags: #CyberSecurity #ThreatIntelligence #<CVE/ThreatActor>

TWITTER/X VOICE:
  High-impact hook in first 50 chars
  Format: 🚨 [RISK LABEL]: [CVE/Title] — [1-line impact] — [link] #hashtag

TELEGRAM VOICE:
  Full HTML format matching @cyberdudebivashSentinelApex channel style
  Includes: risk badge, summary, IOC count, MITRE tactics, CTA button link

USAGE:
  python3 scripts/social_amplifier.py                         (process all new posts)
  python3 scripts/social_amplifier.py --limit 5               (cap at 5)
  python3 scripts/social_amplifier.py --platforms linkedin,twitter  (specific platforms)
  python3 scripts/social_amplifier.py --dry-run               (print only)
"""

import json
import re
import sys
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [social-amplifier] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("social-amplifier")

REPO     = Path(__file__).parent.parent.resolve()
BLOG_DIR = REPO / "blog"
QUEUE_DIR = REPO / "data" / "social_queue"

PLATFORM = {
    "name":    "CYBERDUDEBIVASH SENTINEL APEX",
    "short":   "Sentinel APEX",
    "domain":  "https://intel.cyberdudebivash.com",
    "twitter": "@cyberdudebivash",
    "linkedin": "cyberdudebivash",
    "telegram": "@cyberdudebivashSentinelApex",
    "hashtags_base": ["#CyberSecurity", "#ThreatIntelligence", "#SENTINELAPEX"],
}

RISK_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

RISK_LABELS = {10: "CRITICAL", 9: "CRITICAL", 8: "HIGH", 7: "HIGH",
               6: "MEDIUM", 5: "MEDIUM", 4: "LOW", 3: "LOW", 0: "INFO"}


def rlabel(risk):
    return RISK_LABELS.get(int(risk or 0), "INFO")


def load_blog_index() -> list:
    idx = BLOG_DIR / "index.json"
    if not idx.exists():
        return []
    data = json.loads(idx.read_text(encoding="utf-8"))
    return data.get("posts", [])


def load_social_queue() -> dict:
    qf = QUEUE_DIR / "queue.json"
    if qf.exists():
        try:
            return json.loads(qf.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"processed": [], "pending": []}


def save_social_queue(queue: dict, dry_run: bool = False):
    if dry_run:
        return
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    queue["updated_at"] = datetime.now(timezone.utc).isoformat()
    (QUEUE_DIR / "queue.json").write_text(
        json.dumps(queue, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def extract_hashtags(post: dict) -> list[str]:
    tags = list(PLATFORM["hashtags_base"])
    cves = post.get("cves", [])
    actor = post.get("actor", "")

    if cves:
        cve = cves[0].replace("-", "").upper()
        tags.append(f"#{cve}")

    if actor and actor not in ("Unknown", "N/A", ""):
        actor_tag = re.sub(r'[^a-zA-Z0-9]', '', actor)
        if actor_tag:
            tags.append(f"#{actor_tag}")

    tags.append("#STIX21")
    tags.append("#SOC")
    return tags[:6]


# ─── LINKEDIN POST GENERATOR ────────────────────────────────────────────────
def generate_linkedin(post: dict) -> str:
    title   = post.get("title", "Threat Intelligence Report")
    risk    = post.get("risk_score", 7)
    rl      = rlabel(risk)
    emoji   = RISK_EMOJIS.get(rl, "⚠")
    cves    = post.get("cves", [])
    actor   = post.get("actor", "") or "Unknown threat actor"
    summary = post.get("summary", "") or "New threat intelligence report available."
    url     = post.get("url", PLATFORM["domain"])
    pub     = post.get("published", "")[:10]
    hashtags = extract_hashtags(post)
    cve_str = " | ".join(cves[:3]) if cves else "No CVE — behavioral threat"
    hashtag_str = " ".join(hashtags)

    # Open with hook
    if risk >= 9:
        hook = f"🚨 CRITICAL THREAT ALERT: {title[:60]}"
    elif risk >= 7:
        hook = f"{emoji} HIGH SEVERITY: {title[:60]}"
    else:
        hook = f"{emoji} Threat Advisory: {title[:60]}"

    # Business context
    biz = (
        "Cybersecurity teams relying on signature-based detection alone will miss this. "
        "The indicators below require behavioral analysis + SIEM correlation to detect."
    ) if risk >= 8 else (
        "Teams should review their detection coverage against the provided MITRE ATT&CK techniques "
        "and validate IOC blocks at the perimeter."
    )

    linkedin = f"""{hook}

{summary[:300]}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 INTEL SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔹 Risk Score:    {risk}/10 ({rl})
🔹 CVEs:          {cve_str}
🔹 Threat Actor:  {actor}
🔹 Published:     {pub}
🔹 IOCs:          {post.get('ioc_count', 'see report')} indicators

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 SO WHAT?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{biz}

Our AI engine has automatically extracted all IOCs, generated MITRE ATT&CK mappings,
and produced STIX 2.1 bundles — available now on SENTINEL APEX.

🔗 Full Report: {url}

👉 Get enterprise-grade threat intel with SIEM integration, TAXII 2.1,
and YARA rule generation: {PLATFORM['domain']}/pricing.html?plan=enterprise&source=li

{hashtag_str}

---
Powered by CYBERDUDEBIVASH SENTINEL APEX | AI-First Cybersecurity Threat Intelligence
{PLATFORM['domain']}"""

    return linkedin.strip()


# ─── TWITTER/X POST GENERATOR ────────────────────────────────────────────────
def generate_twitter(post: dict) -> str:
    risk  = post.get("risk_score", 7)
    rl    = rlabel(risk)
    emoji = RISK_EMOJIS.get(rl, "⚠")
    cves  = post.get("cves", [])
    title = post.get("title", "Threat Report")
    url   = post.get("url", PLATFORM["domain"])
    tags  = extract_hashtags(post)[:3]
    tag_str = " ".join(tags)

    # Target: ≤280 chars
    cve_part = f" {cves[0]}" if cves else ""
    title_short = title[:50] + ("…" if len(title) > 50 else "")
    actor = post.get("actor", "")
    actor_part = f" | {actor}" if actor and actor not in ("Unknown","N/A","") else ""

    tweet = f"{emoji} {rl}{cve_part}: {title_short}{actor_part} — Full IOC list + MITRE ATT&CK → {url} {tag_str}"

    # Ensure ≤280
    if len(tweet) > 280:
        tweet = f"{emoji} {rl}{cve_part}: {title_short} → {url} {tag_str}"
    if len(tweet) > 280:
        tweet = f"{emoji} {rl}{cve_part}: {title_short[:40]}… → {url} {' '.join(tags[:2])}"

    return tweet


# ─── TELEGRAM POST GENERATOR ────────────────────────────────────────────────
def generate_telegram(post: dict) -> str:
    risk    = post.get("risk_score", 7)
    rl      = rlabel(risk)
    emoji   = RISK_EMOJIS.get(rl, "⚠")
    cves    = post.get("cves", [])
    title   = post.get("title", "Threat Report")
    summary = (post.get("summary", "") or "")[:300]
    url     = post.get("url", PLATFORM["domain"])
    actor   = post.get("actor", "") or "Unknown"
    pub     = post.get("published", "")[:10]
    ioc_cnt = post.get("ioc_count", 0)

    cve_str = " | ".join(f"<code>{c}</code>" for c in cves[:3]) if cves else "<i>No CVE</i>"

    tg = f"""<b>{emoji} [{rl}] {title}</b>

{summary}

<b>━━━ SENTINEL APEX INTEL ━━━</b>
🔺 Risk Score: <b>{risk}/10 ({rl})</b>
🧬 CVEs: {cve_str}
🎯 Actor: <b>{actor}</b>
🔍 IOCs: <b>{ioc_cnt}</b>
📅 Date: {pub}

<b>🔗 Full Report + IOCs:</b>
{url}

<b>⚡ Enterprise Feed:</b>
{PLATFORM['domain']}/pricing.html?plan=enterprise&amp;source=tg

<i>CYBERDUDEBIVASH SENTINEL APEX — AI-Powered Threat Intelligence</i>
<i>TLP:CLEAR | STIX 2.1</i>"""

    return tg


# ─── MASTODON POST GENERATOR ─────────────────────────────────────────────────
def generate_mastodon(post: dict) -> str:
    risk  = post.get("risk_score", 7)
    rl    = rlabel(risk)
    emoji = RISK_EMOJIS.get(rl, "⚠")
    cves  = post.get("cves", [])
    title = post.get("title", "Threat Report")
    url   = post.get("url", PLATFORM["domain"])
    cve_part = f" | {cves[0]}" if cves else ""
    title_short = title[:60] + ("…" if len(title) > 60 else "")

    toot = (
        f"{emoji} {rl}{cve_part}: {title_short}\n\n"
        f"Full IOC list, MITRE ATT&CK mapping & detection rules:\n{url}\n\n"
        "#CyberSecurity #ThreatIntelligence #STIX #MITRE #SOC #InfoSec"
    )
    return toot[:500]


def process_post(post: dict, platforms: list, today_dir: Path, dry_run: bool = False) -> dict:
    """Generate and write all social copy for one post."""
    slug = post.get("slug", post.get("stix_id", "post"))
    result = {"slug": slug, "title": post.get("title",""), "files": {}}

    generators = {
        "linkedin":  generate_linkedin,
        "twitter":   generate_twitter,
        "telegram":  generate_telegram,
        "mastodon":  generate_mastodon,
    }
    exts = {
        "linkedin": "_linkedin.txt",
        "twitter":  "_twitter.txt",
        "telegram": "_telegram.html",
        "mastodon": "_mastodon.txt",
    }

    for platform in platforms:
        if platform not in generators:
            continue
        content = generators[platform](post)
        fname   = f"{slug[:50]}{exts[platform]}"
        fpath   = today_dir / fname

        if dry_run:
            log.info(f"\n  [{platform.upper()}]\n{content[:200]}...\n")
        else:
            today_dir.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")
            result["files"][platform] = str(fpath.relative_to(REPO))

    return result


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Social Amplifier")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--limit",     type=int, default=10)
    parser.add_argument("--platforms", type=str, default="linkedin,twitter,telegram,mastodon",
                        help="Comma-separated: linkedin,twitter,telegram,mastodon")
    parser.add_argument("--risk-min",  type=int, default=7)
    args = parser.parse_args()

    platforms = [p.strip() for p in args.platforms.split(",")]

    log.info("=" * 70)
    log.info("SENTINEL APEX — SOCIAL AMPLIFIER v1.0")
    log.info(f"Mode: {'DRY-RUN' if args.dry_run else 'LIVE'} | Platforms: {', '.join(platforms)}")
    log.info("=" * 70)

    posts = load_blog_index()
    queue = load_social_queue()
    processed_slugs = set(queue.get("processed", []))

    # Filter: not already processed + meets risk min
    candidates = [
        p for p in posts
        if p.get("slug", p.get("stix_id","")) not in processed_slugs
        and p.get("risk_score", 0) >= args.risk_min
    ]
    targets = candidates[:args.limit]
    log.info(f"Blog posts: {len(posts)} | New eligible: {len(candidates)} | Processing: {len(targets)}")

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    today_dir = QUEUE_DIR / today
    generated = 0

    for post in targets:
        result = process_post(post, platforms, today_dir, dry_run=args.dry_run)
        slug = post.get("slug", post.get("stix_id", ""))
        if not args.dry_run:
            queue["processed"].append(slug)
            queue["pending"].append({
                "slug":      slug,
                "title":     post.get("title",""),
                "risk":      post.get("risk_score", 0),
                "url":       post.get("url",""),
                "files":     result.get("files", {}),
                "queued_at": datetime.now(timezone.utc).isoformat(),
                "status":    "ready",
            })
        generated += 1
        log.info(f"  ✔ Amplified: {slug[:50]} ({', '.join(platforms)})")

    if not args.dry_run:
        save_social_queue(queue, dry_run=False)

    log.info("=" * 70)
    log.info(f"SOCIAL AMPLIFIER COMPLETE — Generated: {generated} post sets")
    log.info(f"  Queue dir: data/social_queue/{today}/")
    log.info(f"  Platforms: {', '.join(platforms)}")
    log.info("=" * 70)

    # Print daily posting schedule hint
    if generated > 0 and not args.dry_run:
        log.info("\nPOSTING SCHEDULE (suggested):")
        log.info("  LinkedIn → post between 08:00-09:00 or 17:00-18:00 local time")
        log.info("  Twitter/X → post at 09:00, 13:00, 17:00 (3x/day max)")
        log.info("  Telegram → post immediately (24/7 audience)")
        log.info("  Files ready in: data/social_queue/" + today + "/")


if __name__ == "__main__":
    main()
