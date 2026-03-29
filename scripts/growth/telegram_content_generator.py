#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Telegram Content Generator v1.0
=================================================================
Generates and publishes daily threat intelligence posts to Telegram.
Multiple post types: threat roundup, single CVE spotlight, APEX digest.

POST TYPES:
  1. daily_roundup   — Top 5 threats summary (runs daily)
  2. cve_spotlight   — Deep-dive on single high-impact CVE
  3. apex_digest     — APEX AI intelligence summary
  4. weekly_recap    — Sunday weekly wrap-up

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations
import json, logging, os, re, sys, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("TG-CONTENT")

BASE_DIR      = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
TG_STATE_PATH = BASE_DIR / "data" / "growth" / "telegram_state.json"

BOT_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID     = os.environ.get("TELEGRAM_CHAT_ID", "")
API_URL     = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

PLATFORM_URL = "https://intel.cyberdudebivash.com"
PRICING_URL  = "https://intel.cyberdudebivash.com/landing/pricing.html"
DASH_URL     = "https://intel.cyberdudebivash.com/landing/dashboard.html"


def _load_state() -> Dict:
    try:
        if TG_STATE_PATH.exists():
            with open(TG_STATE_PATH, encoding="utf-8") as f:
                return json.load(f)
    except Exception: pass
    return {"last_roundup": "", "last_spotlight": "", "posted_stix_ids": []}


def _save_state(state: Dict) -> None:
    try:
        TG_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(TG_STATE_PATH) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(state, indent=2).encode("utf-8"))
        os.replace(tmp, TG_STATE_PATH)
    except Exception as e:
        logger.warning(f"[TG-CONTENT] State save failed: {e}")


def _send(message: str) -> bool:
    """Send message to Telegram. Returns True on success."""
    if not BOT_TOKEN or not CHAT_ID:
        logger.info(f"[TG-CONTENT] Telegram not configured — would post:\n{message[:200]}...")
        return False
    try:
        import requests
        resp = requests.post(API_URL, json={
            "chat_id": CHAT_ID, "text": message,
            "parse_mode": "Markdown", "disable_web_page_preview": False,
        }, timeout=12)
        if resp.status_code == 200:
            logger.info("[TG-CONTENT] Message sent successfully")
            return True
        elif resp.status_code == 429:
            retry = resp.json().get("parameters", {}).get("retry_after", 10)
            logger.warning(f"[TG-CONTENT] Rate limited, retry in {retry}s")
            time.sleep(min(retry, 15))
            return False
        else:
            logger.warning(f"[TG-CONTENT] Send failed HTTP {resp.status_code}")
            return False
    except Exception as e:
        logger.warning(f"[TG-CONTENT] Send error: {e}")
        return False

def _build_daily_roundup(manifest: List[Dict]) -> str:
    """Generate daily top-5 threat roundup post."""
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    # Sort by risk score desc, pick top 5
    top5 = sorted(manifest, key=lambda x: float(x.get("risk_score", 0)), reverse=True)[:5]

    lines = [
        f"📊 *SENTINEL APEX — Daily Threat Roundup*",
        f"_{today} | Powered by CYBERDUDEBIVASH® Sentinel APEX_",
        f"",
        f"🔴 *Top 5 Critical Threats Today:*",
        f"",
    ]
    for i, e in enumerate(top5, 1):
        title = (e.get("title") or "")[:70]
        score = float(e.get("risk_score", 0))
        sev   = e.get("severity","")
        kev   = "⚡ KEV" if e.get("kev_present") else ""
        apex  = (e.get("apex") or {}).get("priority","")
        prio  = f"[{apex}]" if apex else ""
        icon  = "🔴" if score >= 9 else "🟠" if score >= 7 else "🟡"
        lines.append(f"{i}. {icon} *{title}*")
        lines.append(f"   Risk: `{score:.1f}/10` | {sev} {prio} {kev}".strip())
        lines.append("")

    # Stats
    crit_count = sum(1 for e in manifest if float(e.get("risk_score",0)) >= 9)
    kev_count  = sum(1 for e in manifest if e.get("kev_present"))
    lines.extend([
        f"📈 *Platform Stats:*",
        f"• {len(manifest)} total advisories tracked",
        f"• {crit_count} CRITICAL threats (score ≥9.0)",
        f"• {kev_count} CISA KEV confirmed exploits",
        f"",
        f"🔗 [Live Dashboard]({PLATFORM_URL}) | [Get API Access]({PRICING_URL})",
        f"📱 [Join Telegram Channel]({PLATFORM_URL.replace('intel.','t.me/cyberdudebivash')}SentinelApex)",
        f"",
        f"💡 *Free API — no signup:*",
        f"`curl {PLATFORM_URL.replace('https://intel.','https://cyberdudebivash-threat-intel-platform-production.up.railway.app')}/api/v1/intel/latest`",
        f"",
        f"_Pro plan ($49/mo) → full IOC + APEX AI + Telegram alerts_",
        f"_→ {PRICING_URL}_",
    ])
    return "\n".join(lines)


def _build_cve_spotlight(entry: Dict) -> str:
    """Generate single CVE spotlight post with full APEX context."""
    import re as _re
    title    = entry.get("title","")[:120]
    score    = float(entry.get("risk_score",0))
    sev      = entry.get("severity","")
    cvss     = entry.get("cvss_score")
    epss     = entry.get("epss_score")
    kev      = entry.get("kev_present",False)
    blog_url = entry.get("blog_url","")
    apex     = entry.get("apex") or {}
    cve_m    = _re.search(r"CVE-\d{4}-\d+", title)
    cve_id   = cve_m.group(0) if cve_m else "Advisory"
    action   = (apex.get("recommended_action") or "Apply patches immediately")[:120]
    summary  = (apex.get("ai_summary") or "")[:300]
    tags     = (apex.get("behavioral_tags") or [])[:3]
    camp_id  = apex.get("campaign_id","")

    icon = "🔴" if score >= 9 else "🟠" if score >= 7 else "🟡"
    kev_line = f"⚡ *CISA KEV CONFIRMED — Actively Exploited*\n" if kev else ""

    lines = [
        f"{icon} *CVE SPOTLIGHT: {cve_id}*",
        f"",
        kev_line,
        f"*{title}*",
        f"",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"🎯 *Risk Score:* `{score:.1f}/10` | *Severity:* {sev}",
    ]
    if cvss  is not None: lines.append(f"📊 *CVSS:* `{cvss}` | *EPSS:* `{epss}%`" if epss else f"📊 *CVSS:* `{cvss}`")
    if camp_id: lines.append(f"🗺 *Campaign:* `{camp_id}`")
    if tags:    lines.append(f"🏷 {' | '.join(f'`{t}`' for t in tags)}")
    lines.extend([
        f"",
        f"⚡ *APEX Action:* {action}",
    ])
    if summary:
        lines.extend([f"", f"🤖 *AI Analysis:* _{summary}_"])
    lines.extend([
        f"",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"📋 [Full Advisory + IOCs]({blog_url or PLATFORM_URL})",
        f"🌐 [Live Dashboard — 500+ Advisories]({PLATFORM_URL})",
        f"🔑 [Get Pro API $49/mo — Full APEX AI]({PRICING_URL})",
        f"📡 [Join Telegram](https://t.me/cyberdudebivashSentinelApex)",
        f"",
        f"_Free: `curl .../api/v1/intel/latest` — no signup_",
        f"_CYBERDUDEBIVASH® Sentinel APEX — AI-Powered Threat Intelligence_",
    ])
    return "\n".join(line for line in lines if line is not None)


def _build_apex_digest(manifest: List[Dict]) -> str:
    """Weekly APEX AI intelligence digest."""
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    p1 = [e for e in manifest if (e.get("apex") or {}).get("priority") == "P1"]
    kev_list = [e for e in manifest if e.get("kev_present")]
    categories: Dict[str, int] = {}
    for e in manifest:
        cat = (e.get("apex") or {}).get("threat_category","UNKNOWN")
        categories[cat] = categories.get(cat,0) + 1
    top_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]

    lines = [
        f"⬡ *APEX AI INTELLIGENCE DIGEST*",
        f"_{today} | 12-Engine AI Analysis_",
        f"",
        f"📊 *Threat Landscape Overview:*",
        f"• `{len(manifest)}` total advisories in database",
        f"• `{len(p1)}` P1 CRITICAL (immediate action required)",
        f"• `{len(kev_list)}` CISA KEV confirmed exploits",
        f"",
        f"🗂 *Top Threat Categories (APEX AI):*",
    ]
    for cat, count in top_cats:
        cat_label = cat.replace("_"," ").title()
        lines.append(f"• {cat_label}: `{count}` advisories")
    lines.extend([
        f"",
        f"🤖 *What APEX AI Does:*",
        f"• Predictive risk scoring (12 AI engines)",
        f"• Campaign tracking & attribution",
        f"• Behavioral tag classification",
        f"• Auto-generates firewall blocks & SOC tickets",
        f"",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"🌐 [Live Dashboard]({PLATFORM_URL})",
        f"🔑 [Pro API — $49/mo]({PRICING_URL})",
        f"📖 Free tier: no signup required",
        f"",
        f"_Join 1,000+ security professionals monitoring threats daily_",
    ])
    return "\n".join(lines)

def run_telegram_content(post_type: str = "daily_roundup") -> Dict:
    """Generate and publish Telegram content. post_type: daily_roundup | cve_spotlight | apex_digest"""
    if not MANIFEST_PATH.exists():
        return {"status": "NO_MANIFEST", "sent": False}

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    state = _load_state()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dow   = datetime.now(timezone.utc).weekday()  # 0=Mon, 6=Sun

    message = ""
    if post_type == "daily_roundup":
        if state.get("last_roundup") == today:
            logger.info("[TG-CONTENT] Roundup already posted today")
            return {"status": "ALREADY_POSTED", "sent": False}
        message = _build_daily_roundup(manifest)
        state["last_roundup"] = today

    elif post_type == "cve_spotlight":
        posted = set(state.get("posted_stix_ids", []))
        # Pick highest-risk unposted entry with CVE ID
        import re as _re
        candidates = [
            e for e in sorted(manifest, key=lambda x: float(x.get("risk_score",0)), reverse=True)
            if _re.search(r"CVE-\d{4}-\d+", e.get("title",""))
            and e.get("stix_id","") not in posted
        ]
        if not candidates:
            logger.info("[TG-CONTENT] No new CVE candidates for spotlight")
            return {"status": "NO_CANDIDATES", "sent": False}
        entry = candidates[0]
        message = _build_cve_spotlight(entry)
        state.setdefault("posted_stix_ids", []).insert(0, entry.get("stix_id",""))
        state["posted_stix_ids"] = state["posted_stix_ids"][:200]  # cap

    elif post_type == "apex_digest":
        message = _build_apex_digest(manifest)

    else:
        return {"status": f"UNKNOWN_TYPE:{post_type}", "sent": False}

    if not message:
        return {"status": "EMPTY_MESSAGE", "sent": False}

    sent = _send(message)
    _save_state(state)
    logger.info(f"[TG-CONTENT] {post_type} | sent={sent} | chars={len(message)}")
    return {"status": "OK", "sent": sent, "type": post_type, "chars": len(message)}


if __name__ == "__main__":
    post_type = sys.argv[1] if len(sys.argv) > 1 else "daily_roundup"
    result = run_telegram_content(post_type)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("status") in ("OK","ALREADY_POSTED","NO_CANDIDATES") else 1)
