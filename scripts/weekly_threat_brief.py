#!/usr/bin/env python3
"""
scripts/weekly_threat_brief.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Weekly Threat Brief Generator v1.0.0
========================================================================
REVENUE MECHANISM:
  Delivers a polished weekly threat intelligence brief to subscribers.
  This is the primary recurring value that justifies the monthly fee.
  Sent every Monday at 08:00 IST via Telegram + published at /weekly-brief.html

WHAT THIS GENERATES:
  1. Top 10 threats of the week (by risk_score + kev)
  2. CISA KEV additions this week
  3. Active ransomware groups observed
  4. Detection roundup (Sigma rules count)
  5. Threat landscape summary
  6. Published as: /api/v1/intel/weekly_brief.json + /weekly-brief.html

USAGE:
  python3 scripts/weekly_threat_brief.py
  python3 scripts/weekly_threat_brief.py --send-telegram
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BRIEF] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("BRIEF")

REPO_ROOT       = Path(__file__).resolve().parent.parent
FEED_PATH       = REPO_ROOT / "api" / "feed.json"
MANIFEST_PATH   = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
BRIEF_JSON_PATH = REPO_ROOT / "api" / "v1" / "intel" / "weekly_brief.json"
BRIEF_HTML_PATH = REPO_ROOT / "weekly-brief.html"
TELEGRAM_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT   = os.environ.get("TELEGRAM_CHAT_ID", "")
SEND_TELEGRAM   = "--send-telegram" in sys.argv
PLATFORM_URL    = "https://intel.cyberdudebivash.com"


def _load_feed() -> List[Dict]:
    """Load the live feed, try manifest first for richer data."""
    for path in (MANIFEST_PATH, FEED_PATH):
        try:
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    raw = json.load(f)
                items = raw if isinstance(raw, list) else raw.get("advisories", raw.get("items", []))
                if items:
                    log.info("Loaded %d items from %s", len(items), path.name)
                    return items
        except Exception as e:
            log.warning("Failed to load %s: %s", path, e)
    return []


def _is_this_week(item: dict) -> bool:
    """Return True if item was published/updated this week."""
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    for field in ("published_at", "published", "updated_at"):
        ts = item.get(field)
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                return dt >= week_ago
            except Exception:
                pass
    return False


def _get_week_range() -> tuple:
    now = datetime.now(timezone.utc)
    week_start = now - timedelta(days=7)
    return week_start.strftime("%d %b %Y"), now.strftime("%d %b %Y")


def _build_brief(items: List[Dict]) -> Dict:
    """Build the weekly brief data structure."""
    week_start, week_end = _get_week_range()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    week_num = datetime.now(timezone.utc).isocalendar()[1]
    year     = datetime.now(timezone.utc).year

    # Filter this week's items
    this_week = [it for it in items if _is_this_week(it)]
    all_items = this_week or items  # fallback to all if no recent items

    # Sort by risk score descending
    all_sorted = sorted(all_items, key=lambda x: float(x.get("risk_score") or 0), reverse=True)

    # Top 10 threats
    top10 = all_sorted[:10]

    # KEV additions this week
    kev_items = [it for it in all_items if it.get("kev") or it.get("cisa_kev")]

    # Critical items
    critical_items = [it for it in all_items if str(it.get("severity", "")).upper() == "CRITICAL"]

    # Ransomware activity
    ransomware_items = [it for it in all_items
                        if "ransomware" in str(it.get("threat_type", "")).lower()
                        or "ransomware" in str(it.get("title", "")).lower()]

    # Phishing activity
    phishing_items = [it for it in all_items
                      if "phish" in str(it.get("title", "")).lower()
                      or "phish" in str(it.get("threat_type", "")).lower()]

    # Active threat actors
    actors = set()
    for it in all_items:
        actor = it.get("actor") or it.get("actor_attribution") or it.get("threat_actor") or ""
        if actor and "UNATTR" not in str(actor).upper():
            actors.add(str(actor)[:50])

    # Detection rule count
    sigma_count  = sum(1 for it in all_items if it.get("sigma_rule"))
    kql_count    = sum(1 for it in all_items if it.get("kql_query"))
    stix_bundles = sum(1 for it in all_items if it.get("stix_id"))

    # Severity breakdown
    severity_counts: Dict[str, int] = {}
    for it in all_items:
        sev = str(it.get("severity", "UNKNOWN")).upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    brief = {
        "_schema": "sentinel-apex-weekly-brief-v1",
        "week": f"Week {week_num} {year}",
        "period": f"{week_start} — {week_end}",
        "generated_at": now_str,
        "platform": PLATFORM_URL,
        "stats": {
            "total_advisories": len(all_items),
            "critical_count": len(critical_items),
            "kev_additions": len(kev_items),
            "ransomware_events": len(ransomware_items),
            "phishing_events": len(phishing_items),
            "sigma_rules_available": sigma_count,
            "kql_queries_available": kql_count,
            "stix_bundles": stix_bundles,
            "severity_breakdown": severity_counts,
        },
        "top_threats": [
            {
                "rank": i + 1,
                "title": it.get("title", "Unknown"),
                "severity": it.get("severity", "UNKNOWN"),
                "risk_score": float(it.get("risk_score") or 0),
                "cve_id": it.get("cve_id") or it.get("title", ""),
                "threat_type": it.get("threat_type", ""),
                "kev": bool(it.get("kev") or it.get("cisa_kev")),
                "report_url": f"{PLATFORM_URL}{it.get('report_url') or it.get('internal_report_url') or ''}",
                "sigma_available": bool(it.get("sigma_rule")),
                "actor": it.get("actor") or it.get("threat_actor") or "Unknown",
            }
            for i, it in enumerate(top10)
        ],
        "kev_additions": [
            {
                "cve_id": it.get("cve_id") or it.get("title", ""),
                "title": it.get("title", ""),
                "risk_score": float(it.get("risk_score") or 0),
                "report_url": f"{PLATFORM_URL}{it.get('report_url') or ''}",
            }
            for it in kev_items[:5]
        ],
        "active_threat_actors": sorted(list(actors))[:10],
        "ransomware_activity": [
            {"title": it.get("title", ""), "actor": it.get("actor", "Unknown"),
             "risk_score": float(it.get("risk_score") or 0)}
            for it in ransomware_items[:5]
        ],
        "upgrade_cta": {
            "message": "Get full detection rules (Sigma, KQL, Suricata), IOC feeds, STIX bundles and AI threat analysis.",
            "url": f"{PLATFORM_URL}/upgrade.html",
            "plans": ["PRO — ₹4,100/month", "ENTERPRISE — ₹15,000/month", "MSSP — Custom Pricing"],
        },
    }
    return brief


def _render_html(brief: Dict) -> str:
    """Render the weekly brief as a production-quality HTML page."""
    stats   = brief.get("stats", {})
    top10   = brief.get("top_threats", [])
    kev     = brief.get("kev_additions", [])
    actors  = brief.get("active_threat_actors", [])
    period  = brief.get("period", "")
    week    = brief.get("week", "")
    gen     = brief.get("generated_at", "")

    # Build top 10 rows
    rows = ""
    for t in top10:
        sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(
            str(t["severity"]).upper(), "#6b7280")
        kev_badge = '<span style="background:#ef4444;color:#fff;font-size:10px;padding:2px 6px;border-radius:4px;margin-left:6px;">CISA KEV</span>' if t.get("kev") else ""
        sigma_badge = '<span style="background:#7c3aed;color:#fff;font-size:10px;padding:2px 6px;border-radius:4px;margin-left:6px;">SIGMA</span>' if t.get("sigma_available") else ""
        rows += f"""
        <tr>
          <td style="padding:10px 8px;border-bottom:1px solid #1e293b;color:#64748b;font-size:12px;">{t['rank']}</td>
          <td style="padding:10px 8px;border-bottom:1px solid #1e293b;">
            <a href="{t['report_url']}" style="color:#38bdf8;text-decoration:none;font-size:13px;">{t['title'][:90]}</a>
            {kev_badge}{sigma_badge}
          </td>
          <td style="padding:10px 8px;border-bottom:1px solid #1e293b;">
            <span style="color:{sev_color};font-size:12px;font-weight:700;">{t['severity']}</span>
          </td>
          <td style="padding:10px 8px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:12px;">{t['risk_score']:.1f}</td>
          <td style="padding:10px 8px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:12px;">{str(t['actor'])[:30]}</td>
        </tr>"""

    kev_items_html = ""
    for k in kev:
        kev_items_html += f'<li style="margin-bottom:8px;"><a href="{k["report_url"]}" style="color:#38bdf8;">{k["title"]}</a> — Risk {k["risk_score"]:.1f}</li>'
    if not kev_items_html:
        kev_items_html = "<li style='color:#64748b;'>No new KEV additions this week.</li>"

    actors_html = " | ".join(f'<span style="background:#1e293b;padding:3px 8px;border-radius:4px;font-size:12px;">{a}</span>' for a in actors) or "<span style='color:#64748b;'>No attributed actors this period</span>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>CYBERDUDEBIVASH® SENTINEL APEX — {week} Threat Intelligence Brief</title>
<meta name="description" content="Weekly threat intelligence brief from SENTINEL APEX. Top threats, CISA KEV, detection rules. {period}."/>
<meta property="og:title" content="SENTINEL APEX — {week} Threat Intelligence Brief"/>
<meta property="og:description" content="{stats.get('critical_count',0)} CRITICAL advisories · {stats.get('kev_additions',0)} CISA KEV · {stats.get('sigma_rules_available',0)} detection rules. {period}."/>
<meta property="og:url" content="{PLATFORM_URL}/weekly-brief.html"/>
<link rel="canonical" href="{PLATFORM_URL}/weekly-brief.html"/>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#0f172a;color:#e2e8f0;font-family:'Inter',-apple-system,sans-serif;line-height:1.6;}}
.container{{max-width:960px;margin:0 auto;padding:40px 20px;}}
.header{{text-align:center;padding:40px 0 30px;border-bottom:1px solid #1e293b;margin-bottom:32px;}}
.header h1{{font-size:28px;font-weight:800;color:#38bdf8;letter-spacing:-0.5px;}}
.header .sub{{color:#64748b;font-size:14px;margin-top:8px;}}
.badge{{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;}}
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:32px;}}
.stat-card{{background:#1e293b;border-radius:12px;padding:20px;text-align:center;}}
.stat-num{{font-size:32px;font-weight:800;color:#38bdf8;}}
.stat-label{{font-size:12px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:1px;}}
.section{{background:#1e293b;border-radius:12px;padding:24px;margin-bottom:24px;}}
.section-title{{font-size:16px;font-weight:700;color:#f8fafc;margin-bottom:16px;letter-spacing:0.5px;text-transform:uppercase;}}
table{{width:100%;border-collapse:collapse;}}
th{{text-align:left;padding:10px 8px;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #334155;}}
.cta{{background:linear-gradient(135deg,#1e3a8a,#312e81);border-radius:12px;padding:32px;text-align:center;margin-top:32px;}}
.cta h3{{font-size:22px;font-weight:800;color:#f8fafc;margin-bottom:12px;}}
.cta p{{color:#94a3b8;margin-bottom:24px;}}
.btn{{display:inline-block;background:#38bdf8;color:#0f172a;padding:14px 32px;border-radius:8px;font-weight:700;text-decoration:none;font-size:15px;}}
footer{{text-align:center;padding:32px 0;color:#334155;font-size:12px;border-top:1px solid #1e293b;margin-top:40px;}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">CYBERDUDEBIVASH® SENTINEL APEX</div>
    <h1>🛡️ {week} — Threat Intelligence Brief</h1>
    <div class="sub">{period} · Generated {gen[:10]} · <a href="{PLATFORM_URL}" style="color:#38bdf8;">intel.cyberdudebivash.com</a></div>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-num">{stats.get('total_advisories',0)}</div><div class="stat-label">Advisories</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#ef4444;">{stats.get('critical_count',0)}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#f97316;">{stats.get('kev_additions',0)}</div><div class="stat-label">CISA KEV</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#7c3aed;">{stats.get('sigma_rules_available',0)}</div><div class="stat-label">Sigma Rules</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#22c55e;">{stats.get('ransomware_events',0)}</div><div class="stat-label">Ransomware</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#f59e0b;">{stats.get('phishing_events',0)}</div><div class="stat-label">Phishing</div></div>
  </div>

  <div class="section">
    <div class="section-title">🔴 Top 10 Threats This Week</div>
    <table>
      <thead><tr><th>#</th><th>Advisory</th><th>Severity</th><th>Risk</th><th>Actor</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-title">⚠️ CISA Known Exploited Vulnerabilities (KEV)</div>
    <ul style="list-style:none;padding:0;">{kev_items_html}</ul>
  </div>

  <div class="section">
    <div class="section-title">🎭 Active Threat Actors Observed</div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;">{actors_html}</div>
  </div>

  <div class="section">
    <div class="section-title">🛡️ Detection Coverage This Week</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;text-align:center;">
      <div><div style="font-size:24px;font-weight:800;color:#7c3aed;">{stats.get('sigma_rules_available',0)}</div><div style="color:#64748b;font-size:12px;">Sigma Rules</div></div>
      <div><div style="font-size:24px;font-weight:800;color:#38bdf8;">{stats.get('kql_queries_available',0)}</div><div style="color:#64748b;font-size:12px;">KQL Queries</div></div>
      <div><div style="font-size:24px;font-weight:800;color:#22c55e;">{stats.get('stix_bundles',0)}</div><div style="color:#64748b;font-size:12px;">STIX 2.1 Bundles</div></div>
    </div>
    <div style="margin-top:16px;padding:16px;background:#0f172a;border-radius:8px;border-left:3px solid #7c3aed;">
      <span style="font-size:12px;color:#94a3b8;">⚡ PRO subscribers get all Sigma rules, KQL queries, Suricata signatures and YARA rules for instant SIEM deployment.</span>
      <a href="{PLATFORM_URL}/upgrade.html" style="color:#7c3aed;margin-left:8px;font-size:12px;font-weight:700;">Upgrade →</a>
    </div>
  </div>

  <div class="cta">
    <h3>Get Full Intelligence Access</h3>
    <p>PRO subscribers receive: actor attribution, detection rules, IOC feeds, STIX bundles, AI analysis, and priority email delivery every Monday morning.</p>
    <a href="{PLATFORM_URL}/upgrade.html" class="btn">Upgrade to PRO — ₹4,100/month</a>
  </div>

  <footer>
    <p>CYBERDUDEBIVASH PRIVATE LIMITED · GSTIN: 21ARKPN8270G1ZP · Odisha, India</p>
    <p style="margin-top:8px;"><a href="{PLATFORM_URL}" style="color:#334155;">intel.cyberdudebivash.com</a> · <a href="mailto:bivash@cyberdudebivash.com" style="color:#334155;">bivash@cyberdudebivash.com</a></p>
  </footer>
</div>
</body>
</html>"""


def _send_telegram(brief: Dict) -> None:
    """Send weekly brief summary to Telegram channel."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        log.warning("Telegram not configured — skipping notification")
        return
    stats = brief.get("stats", {})
    top3  = brief.get("top_threats", [])[:3]
    top3_text = "\n".join(
        f"  {i+1}. {t['title'][:60]}... [{t['severity']}]"
        for i, t in enumerate(top3)
    )
    kev_count = stats.get("kev_additions", 0)
    kev_alert = f"🚨 {kev_count} NEW CISA KEV ADDITIONS\n\n" if kev_count else ""

    msg = (
        f"🛡️ SENTINEL APEX — {brief.get('week','Weekly')} Threat Brief\n"
        f"📅 {brief.get('period','')}\n\n"
        f"{kev_alert}"
        f"📊 Stats:\n"
        f"  • {stats.get('total_advisories',0)} advisories processed\n"
        f"  • {stats.get('critical_count',0)} CRITICAL threats\n"
        f"  • {stats.get('sigma_rules_available',0)} Sigma rules available\n\n"
        f"🔴 Top Threats:\n{top3_text}\n\n"
        f"📖 Full brief: {PLATFORM_URL}/weekly-brief.html\n"
        f"🔑 Get detection rules: {PLATFORM_URL}/upgrade.html"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": TELEGRAM_CHAT, "text": msg, "parse_mode": "HTML"}).encode()
    try:
        req = urllib.request.Request(url, data=payload,
                                      headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            log.info("[TELEGRAM] Sent successfully: %d", resp.status)
    except Exception as e:
        log.warning("[TELEGRAM] Failed: %s", e)


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    content = json.dumps(data, indent=2, ensure_ascii=False) if isinstance(data, (dict, list)) else str(data)
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def main():
    log.info("=" * 60)
    log.info("WEEKLY THREAT BRIEF GENERATOR v1.0.0")
    log.info("=" * 60)

    items = _load_feed()
    if not items:
        log.error("No feed data available — cannot generate brief")
        return

    brief = _build_brief(items)
    html  = _render_html(brief)

    _atomic_write(BRIEF_JSON_PATH, brief)
    log.info("[WRITE] Brief JSON: %s", BRIEF_JSON_PATH)

    BRIEF_HTML_PATH.write_text(html, encoding="utf-8")
    log.info("[WRITE] Brief HTML: %s", BRIEF_HTML_PATH)

    if SEND_TELEGRAM:
        _send_telegram(brief)

    log.info("BRIEF COMPLETE: %d advisories | %d critical | %d KEV",
             brief["stats"]["total_advisories"],
             brief["stats"]["critical_count"],
             brief["stats"]["kev_additions"])
    print(f"[DONE] Brief generated for {brief['week']} — {brief['period']}")


if __name__ == "__main__":
    main()
