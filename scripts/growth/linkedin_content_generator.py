#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — LinkedIn Content Generator v1.0
=================================================================
Generates high-authority LinkedIn posts from live threat intel data.
Positions Bivash as a cybersecurity thought leader while driving
traffic to the platform.

POST FORMATS:
  1. threat_insight    — "5 things you need to know about [CVE]"
  2. platform_launch   — Product update / feature announcement
  3. industry_insight  — Broader threat landscape commentary
  4. stats_post        — Data-driven stats post (high engagement)

LINKEDIN API:
  Requires: LINKEDIN_ACCESS_TOKEN + LINKEDIN_AUTHOR_URN env vars
  Falls back to file output if not configured.

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations
import json, logging, os, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("LI-CONTENT")

BASE_DIR      = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
LI_OUTPUT_DIR = BASE_DIR / "data" / "growth" / "linkedin_posts"
LI_STATE_PATH = BASE_DIR / "data" / "growth" / "linkedin_state.json"

LI_TOKEN    = os.environ.get("LINKEDIN_ACCESS_TOKEN", "")
LI_AUTHOR   = os.environ.get("LINKEDIN_AUTHOR_URN", "")
LI_API_URL  = "https://api.linkedin.com/v2/ugcPosts"

PLATFORM_URL = "https://intel.cyberdudebivash.com"
PRICING_URL  = "https://intel.cyberdudebivash.com/landing/pricing.html"

HASHTAGS_BASE = "#CyberSecurity #ThreatIntelligence #SOC #CISO #InfoSec"


def _load_li_state() -> Dict:
    try:
        if LI_STATE_PATH.exists():
            with open(LI_STATE_PATH, encoding="utf-8") as f: return json.load(f)
    except Exception: pass
    return {"last_post_date": "", "posted_count": 0}


def _save_li_state(state: Dict) -> None:
    try:
        LI_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(LI_STATE_PATH) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(state, indent=2).encode("utf-8"))
        os.replace(tmp, LI_STATE_PATH)
    except Exception: pass


def _post_to_linkedin(text: str) -> bool:
    """Post to LinkedIn via UGC Posts API. Returns True on success."""
    if not LI_TOKEN or not LI_AUTHOR:
        logger.info("[LI-CONTENT] LinkedIn not configured — saving to file")
        return False
    try:
        import requests
        payload = {
            "author": LI_AUTHOR,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": text},
                    "shareMediaCategory": "NONE",
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
        }
        resp = requests.post(LI_API_URL, json=payload, headers={
            "Authorization": f"Bearer {LI_TOKEN}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0",
        }, timeout=12)
        if resp.status_code in (200, 201):
            logger.info("[LI-CONTENT] Posted successfully to LinkedIn")
            return True
        logger.warning(f"[LI-CONTENT] LinkedIn API HTTP {resp.status_code}: {resp.text[:100]}")
        return False
    except Exception as e:
        logger.warning(f"[LI-CONTENT] LinkedIn post error: {e}")
        return False

def _build_threat_insight(entry: Dict) -> str:
    title = entry.get("title","")[:100]
    score = float(entry.get("risk_score",0))
    cvss  = entry.get("cvss_score")
    kev   = entry.get("kev_present",False)
    cve_m = re.search(r"CVE-\d{4}-\d+", title)
    cve   = cve_m.group(0) if cve_m else "This vulnerability"
    apex  = entry.get("apex") or {}
    action= (apex.get("recommended_action") or "patch immediately")[:80]
    sev   = entry.get("severity","")

    return f"""🔴 {sev} SEVERITY: {title}

Here's what every security team needs to know right now:

1/ Risk score: {score:.1f}/10{f" | CVSS: {cvss}" if cvss else ""}
{"2/ ⚡ CISA KEV CONFIRMED — This is actively exploited in the wild" if kev else f"2/ APEX AI classified this as priority {apex.get('priority','P?')}"}
3/ MITRE ATT&CK techniques mapped for detection
4/ IOC indicators ready for SIEM ingestion
5/ Recommended action: {action}

We've been tracking {cve} since it hit our pipeline. Here's the real-time intelligence:
→ {PLATFORM_URL}

---

Most SOC teams will read about this in their vendor newsletter 48 hours from now.

Our platform delivered this intelligence in real-time with full IOC context, APEX AI enrichment, and automated response playbooks.

Free API access available — no signup required.
→ {PRICING_URL}

{HASHTAGS_BASE} #CVE #VulnerabilityManagement #ThreatHunting"""


def _build_stats_post(manifest: List[Dict]) -> str:
    crit  = sum(1 for e in manifest if float(e.get("risk_score",0)) >= 9)
    kev   = sum(1 for e in manifest if e.get("kev_present"))
    total = len(manifest)
    p1    = sum(1 for e in manifest if (e.get("apex") or {}).get("priority") == "P1")
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")

    return f"""📊 Cybersecurity Threat Intelligence Stats — {today}

I track 500+ CVEs and threat advisories through our AI-powered platform. Here's what the data looks like right now:

▸ {total} total advisories in our database
▸ {crit} scored 9.0+/10 (CRITICAL severity)
▸ {kev} confirmed by CISA as actively exploited
▸ {p1} classified P1 by our APEX AI engine
▸ Updated automatically every 6 hours

The most alarming trend: organisations are still patching CVEs weeks after they appear in CISA KEV.

Our platform fires Telegram alerts the moment a P1 threat enters the feed. 15-minute SLA for incident response.

For security teams using spreadsheets to track CVEs in 2026 — there's a better way.

Free tier: instant API access, no credit card.
→ {PRICING_URL}

What's your current CVE tracking workflow? Drop it below 👇

{HASHTAGS_BASE} #CISA #KEV #CVSS #ZeroDay #ThreatIntelligence"""


def _build_platform_post() -> str:
    return f"""🚀 We just shipped something significant for SOC teams.

CYBERDUDEBIVASH® Sentinel APEX — our AI-powered threat intelligence platform — now includes:

✅ 12-engine APEX AI enrichment on every advisory
✅ Real-time P1 alerts via Telegram (< 15 min SLA)
✅ Automated firewall block + SOC ticket generation
✅ STIX 2.1 export with x-cdb-apex-1 custom extension
✅ Campaign tracking with deterministic IDs
✅ Free tier — no signup, no card

The intelligence gap between enterprise security teams and everyone else is widening.

We built this because SOC analysts deserved better than stale RSS feeds and manual triage.

Free API:
curl {PLATFORM_URL.replace('https://','').replace('intel.','')} → instant threat feed

Pro access ($49/mo) → full APEX AI, IOC details, Telegram alerts.

Link in comments 👇

#CyberSecurity #ThreatIntelligence #SOC #SIEM #SOAR #AI #Cybersecurity2026"""


def run_linkedin_content(post_type: str = "threat_insight") -> Dict:
    """Generate and optionally publish LinkedIn post."""
    LI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    manifest: List[Dict] = []
    if MANIFEST_PATH.exists():
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            manifest = json.load(f)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state = _load_li_state()
    if state.get("last_post_date") == today and post_type != "force":
        logger.info("[LI-CONTENT] Already posted today")
        return {"status": "ALREADY_POSTED", "posted": False}

    text = ""
    if post_type == "threat_insight" and manifest:
        # Pick highest-risk entry
        entry = sorted(manifest, key=lambda x: float(x.get("risk_score",0)), reverse=True)[0]
        text = _build_threat_insight(entry)
    elif post_type == "stats_post":
        text = _build_stats_post(manifest)
    elif post_type == "platform_post":
        text = _build_platform_post()
    else:
        entry = sorted(manifest, key=lambda x: float(x.get("risk_score",0)), reverse=True)[0]
        text = _build_threat_insight(entry)

    if not text:
        return {"status": "EMPTY", "posted": False}

    # Save to file always
    out_path = LI_OUTPUT_DIR / f"{today}-{post_type}.txt"
    out_path.write_bytes(text.encode("utf-8"))
    logger.info(f"[LI-CONTENT] Saved: {out_path.name}")

    # Try posting
    posted = _post_to_linkedin(text)
    state["last_post_date"] = today
    state["posted_count"]   = state.get("posted_count", 0) + (1 if posted else 0)
    _save_li_state(state)

    return {"status": "OK", "posted": posted, "type": post_type,
            "chars": len(text), "file": str(out_path.name)}


if __name__ == "__main__":
    post_type = sys.argv[1] if len(sys.argv) > 1 else "threat_insight"
    result = run_linkedin_content(post_type)
    print(json.dumps(result, indent=2))
    sys.exit(0)
