#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
PRODUCTION ORCHESTRATOR: Multi-feed fusion, dynamic risk scoring,
deduplication, enhanced STIX, MITRE mapping, actor attribution,
TLP classification, confidence scoring, rate-limit protection.

CRITICAL: All existing functionality preserved. Only evolved.
"""
import os
import time
import logging
import feedparser
from typing import List, Dict, Optional

from agent.enricher import enricher
from agent.export_stix import stix_exporter
from agent.blogger_auth import get_blogger_service
from agent.risk_engine import risk_engine
from agent.deduplication import dedup_engine
from agent.mitre_mapper import mitre_engine
from agent.integrations.actor_matrix import actor_matrix
from agent.integrations.detection_engine import detection_engine
from agent.config import (
    BLOG_ID as CONFIG_BLOG_ID,
    CDB_RSS_FEED,
    RSS_FEEDS,
    MAX_ENTRIES_PER_FEED,
    RATE_LIMIT_DELAY,
    BRAND,
)

# ═══════════════════════════════════════════════════════════
# INSTITUTIONAL LOGGING
# ═══════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-SENTINEL] %(message)s"
)
logger = logging.getLogger("CDB-SENTINEL")

BLOG_ID = os.getenv('BLOG_ID') or CONFIG_BLOG_ID


# ═══════════════════════════════════════════════════════════
# REPORT GENERATOR (EVOLVED)
# ═══════════════════════════════════════════════════════════
def generate_elite_report(
    headline: str,
    iocs: Dict,
    risk_score: float,
    severity: str,
    tlp: Dict,
    confidence: float,
    mitre_data: List[Dict],
    actor_data: Optional[Dict] = None,
    sigma_rule: str = "",
    yara_rule: str = "",
) -> str:
    """
    Generates the UPGRADED 6-Pillar Elite HTML tactical report.
    EVOLVED: Dynamic content, skips empty sections, real MITRE mapping,
    severity-aware styling, TLP classification, Sigma/YARA rules.
    """
    tracking_id = (actor_data or {}).get('tracking_id', 'UNC-CDB-99')
    actor_profile = (actor_data or {}).get('profile', {})
    tlp_color = tlp.get('color', '#00d4aa')
    tlp_label = tlp.get('label', 'TLP:CLEAR')

    # Severity color mapping
    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#d97706", "LOW": "#16a34a", "INFO": "#3b82f6"
    }
    sev_color = sev_colors.get(severity, "#00d4aa")

    # ── Build IOC Section (skip empty categories) ──
    ioc_items = []
    ioc_labels = {
        'ipv4': '🌐 Public IPs', 'domain': '🔗 Domains/URIs',
        'url': '🌍 Malicious URLs', 'sha256': '🔑 SHA256 Hashes',
        'sha1': '🔑 SHA1 Hashes', 'md5': '🔑 MD5 Hashes',
        'email': '📧 Threat Actor Emails', 'cve': '⚠️ CVEs Referenced',
        'registry': '🗝️ Registry Keys', 'artifacts': '📦 Malicious Artifacts',
    }
    for key, label in ioc_labels.items():
        values = iocs.get(key, [])
        if values:
            ioc_items.append(
                f'<li style="margin-bottom:8px;">'
                f'<strong>{label}:</strong> '
                f'<code style="font-family:monospace;color:#00d4aa;font-size:12px;">'
                f'{", ".join(values[:10])}'
                f'{"..." if len(values) > 10 else ""}'
                f'</code></li>'
            )

    ioc_html = "".join(ioc_items) if ioc_items else \
        '<li style="color:#666;">Intelligence sweep returned no actionable indicators for this campaign.</li>'

    # ── Build MITRE Section (dynamic, not hardcoded) ──
    mitre_rows = ""
    if mitre_data:
        for tech in mitre_data:
            mitre_rows += (
                f'<tr><td style="padding:6px 12px;border-bottom:1px solid #111;color:#aaa;">'
                f'{tech.get("tactic", "Unknown")}</td>'
                f'<td style="padding:6px 12px;border-bottom:1px solid #111;color:#00d4aa;">'
                f'{tech.get("id", "N/A")}</td></tr>'
            )
    else:
        mitre_rows = ('<tr><td colspan="2" style="padding:10px;color:#666;">'
                      'No specific ATT&CK techniques mapped for this campaign.</td></tr>')

    # ── Build Detection Section ──
    detection_html = ""
    if sigma_rule:
        detection_html += f'''
        <div style="margin-top:15px;">
            <b style="color:#666;font-size:10px;text-transform:uppercase;letter-spacing:1px;">
                Sigma Rule (Auto-Generated)</b>
            <pre style="background:#000;color:#00ff00;padding:18px;border:1px solid #1a1a1a;
                        font-size:11px;margin:8px 0;overflow-x:auto;border-radius:4px;">{sigma_rule}</pre>
        </div>'''
    if yara_rule:
        detection_html += f'''
        <div style="margin-top:15px;">
            <b style="color:#666;font-size:10px;text-transform:uppercase;letter-spacing:1px;">
                YARA Rule (Auto-Generated)</b>
            <pre style="background:#000;color:#00ff00;padding:18px;border:1px solid #1a1a1a;
                        font-size:11px;margin:8px 0;overflow-x:auto;border-radius:4px;">{yara_rule}</pre>
        </div>'''

    report = f"""
    <div style="font-family:'Segoe UI',Arial,sans-serif;color:#dcdcdc;background:#020202;
                max-width:950px;margin:auto;border:1px solid #1a1a1a;">

        <!-- TLP + Classification Header -->
        <div style="background:{tlp_color};color:#000;padding:12px;text-align:center;
                    font-weight:900;letter-spacing:4px;font-size:10px;">
            {tlp_label} // CDB-GOC STRATEGIC ADVISORY // {BRAND['version']} APEX ULTRA
        </div>

        <div style="padding:40px 50px;">

            <!-- Risk Badge Strip -->
            <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:25px;">
                <span style="background:{sev_color};color:#fff;padding:4px 12px;border-radius:100px;
                             font-size:10px;font-weight:800;letter-spacing:1px;">{severity}</span>
                <span style="background:#111;color:#00d4aa;padding:4px 12px;border-radius:100px;
                             font-size:10px;font-weight:700;border:1px solid #1a1a1a;">
                    RISK: {risk_score}/10</span>
                <span style="background:#111;color:#3b82f6;padding:4px 12px;border-radius:100px;
                             font-size:10px;font-weight:700;border:1px solid #1a1a1a;">
                    CONFIDENCE: {confidence}%</span>
                <span style="background:#111;color:#8b5cf6;padding:4px 12px;border-radius:100px;
                             font-size:10px;font-weight:700;border:1px solid #1a1a1a;">
                    ACTOR: {tracking_id}</span>
            </div>

            <p style="color:#00d4aa;font-weight:bold;margin:0;font-size:11px;letter-spacing:2px;">
                CDB SENTINEL // AI-POWERED THREAT INTELLIGENCE</p>
            <h1 style="color:#fff;font-size:32px;margin-top:10px;letter-spacing:-1.5px;line-height:1.2;">
                {headline}</h1>

            <!-- 1. EXECUTIVE SUMMARY -->
            <h2 style="color:#fff;border-bottom:1px solid #222;padding-bottom:8px;margin-top:40px;
                        font-size:16px;">1. EXECUTIVE INTELLIGENCE SNAPSHOT</h2>
            <div style="background:#080808;border-left:4px solid {sev_color};padding:20px;margin:15px 0;">
                <p style="line-height:1.8;font-size:14px;color:#bbb;">
                    CDB GOC Node {BRAND['node_id']} has identified a <b>{severity}</b>-severity campaign
                    associated with <b>{tracking_id}</b>
                    ({actor_profile.get('origin', 'Under Investigation')}).
                    Dynamic risk assessment: <b>{risk_score}/10</b>.
                    IOC confidence: <b>{confidence}%</b>.
                    This advisory requires immediate security team review.
                </p>
            </div>

            <!-- 2. FORENSIC INDICATORS -->
            <h2 style="color:#fff;border-bottom:1px solid #222;padding-bottom:8px;margin-top:40px;
                        font-size:16px;">2. FORENSIC INDICATORS (IOCs)</h2>
            <ul style="background:#080808;padding:20px 20px 20px 35px;list-style:none;
                       border:1px solid #111;border-radius:4px;margin:15px 0;">
                {ioc_html}
            </ul>

            <!-- 3. MITRE ATT&CK MAPPING -->
            <h2 style="color:#fff;border-bottom:1px solid #222;padding-bottom:8px;margin-top:40px;
                        font-size:16px;">3. MITRE ATT&CK® MAPPING</h2>
            <table style="width:100%;border-collapse:collapse;background:#080808;
                          border:1px solid #111;margin:15px 0;">
                <tr style="border-bottom:1px solid #222;">
                    <th style="padding:10px 12px;text-align:left;color:#666;font-size:10px;
                               text-transform:uppercase;letter-spacing:1px;">Tactic</th>
                    <th style="padding:10px 12px;text-align:left;color:#666;font-size:10px;
                               text-transform:uppercase;letter-spacing:1px;">Technique ID</th>
                </tr>
                {mitre_rows}
            </table>

            <!-- 4. DETECTION ENGINEERING -->
            <h2 style="color:#fff;border-bottom:1px solid #222;padding-bottom:8px;margin-top:40px;
                        font-size:16px;">4. DETECTION ENGINEERING (AUTO-GENERATED)</h2>
            {detection_html if detection_html else
             '<p style="color:#666;font-size:13px;margin:15px 0;">No IOC-specific detection rules generated for this sweep.</p>'}

            <!-- 5. REMEDIATION -->
            <h2 style="color:#fff;border-bottom:1px solid #222;padding-bottom:8px;margin-top:40px;
                        font-size:16px;">5. REMEDIATION & ACTION PLAN</h2>
            <div style="background:#080808;padding:20px;border:1px solid #111;margin:15px 0;
                        line-height:2;font-size:13px;color:#aaa;">
                <b style="color:#dc2626;">⚡ Immediate (24h):</b> Block identified IOCs in firewall/proxy/SIEM.
                Deploy auto-generated Sigma rules.<br>
                <b style="color:#ea580c;">🔶 Short-term (7d):</b> Enforce MFA on all exposed services.
                Review conditional access policies.<br>
                <b style="color:#d97706;">📋 Strategic (30d):</b> Conduct purple team exercise against
                mapped ATT&CK techniques. Update incident response playbook.
            </div>

            <!-- Footer -->
            <div style="margin-top:60px;border-top:1px solid #1a1a1a;padding-top:25px;
                        text-align:center;font-size:9px;color:#333;letter-spacing:4px;">
                © 2026 {BRAND['legal']} // {BRAND['node_id']} // {BRAND['city']}, {BRAND['country']}
            </div>
        </div>
    </div>
    """
    return report


# ═══════════════════════════════════════════════════════════
# MULTI-FEED INGESTION ENGINE
# ═══════════════════════════════════════════════════════════
def fetch_feed_entries(feed_url: str, max_entries: int = 1) -> List[Dict]:
    """Fetch and normalize entries from a single RSS feed."""
    try:
        feed = feedparser.parse(feed_url)
        entries = []
        for entry in feed.entries[:max_entries]:
            content = ""
            if hasattr(entry, 'description'):
                content = entry.description
            elif hasattr(entry, 'summary'):
                content = entry.summary
            elif hasattr(entry, 'content') and entry.content:
                content = entry.content[0].get('value', '')

            entries.append({
                'title': entry.get('title', 'Untitled Advisory'),
                'content': content,
                'link': entry.get('link', ''),
                'source': feed_url,
                'published': entry.get('published', ''),
            })
        return entries
    except Exception as e:
        logger.warning(f"Feed fetch failed for {feed_url}: {e}")
        return []


# ═══════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════
def main():
    logger.info("=" * 65)
    logger.info("APEX v11.0 — GOC AUTHORITY ACTIVATED (ULTRA ENGINE)")
    logger.info("=" * 65)

    # ── Initialize Blogger Service ──
    try:
        service = get_blogger_service()
    except Exception as e:
        logger.error(f"Blogger authentication failed: {e}")
        return

    published_count = 0

    # ═══════════════════════════════════════════════════════
    # PHASE 1: Process Primary CDB Feed (backward compatible)
    # ═══════════════════════════════════════════════════════
    logger.info("─── PHASE 1: Primary CDB Intelligence Feed ───")
    primary_entries = fetch_feed_entries(CDB_RSS_FEED, max_entries=1)

    for entry in primary_entries:
        result = process_entry(entry, service, feed_source="CDB-NEWS")
        if result:
            published_count += 1
        time.sleep(RATE_LIMIT_DELAY)

    # ═══════════════════════════════════════════════════════
    # PHASE 2: Multi-Feed Fusion (NEW)
    # ═══════════════════════════════════════════════════════
    logger.info("─── PHASE 2: Multi-Feed Intelligence Fusion ───")
    for feed_url in RSS_FEEDS:
        entries = fetch_feed_entries(feed_url, max_entries=MAX_ENTRIES_PER_FEED)
        logger.info(f"Feed [{feed_url[:50]}...]: {len(entries)} entries")

        for entry in entries:
            # Rate limit protection
            time.sleep(RATE_LIMIT_DELAY)

            # Deduplication check
            if dedup_engine.is_duplicate(entry['title'], entry.get('link', '')):
                logger.info(f"⏭ SKIP (duplicate): {entry['title'][:60]}")
                continue

            result = process_entry(entry, service, feed_source=feed_url[:30])
            if result:
                published_count += 1

    logger.info("=" * 65)
    logger.info(f"APEX v11.0 COMPLETE — Published {published_count} advisories")
    logger.info("=" * 65)


def process_entry(entry: Dict, service, feed_source: str = "EXTERNAL") -> bool:
    """
    Process a single intelligence entry through the full pipeline.
    Returns True if successfully published.
    """
    headline = entry['title']
    content = entry.get('content', '')

    logger.info(f"Analyzing Dossier: {headline[:80]}")

    # ── 1. IOC Extraction (Enhanced) ──
    extracted_iocs = enricher.extract_iocs(content)
    ioc_counts = enricher.get_ioc_counts(extracted_iocs)

    # ── 2. MITRE ATT&CK Mapping (Dynamic) ──
    full_corpus = f"{headline} {content}"
    mitre_data = mitre_engine.map_threat(full_corpus)

    # ── 3. Actor Attribution ──
    actor_data = actor_matrix.correlate_actor(full_corpus, extracted_iocs)
    actor_mapped = actor_data.get('tracking_id', '').startswith('CDB-')

    # ── 4. Dynamic Risk Scoring (replaces hardcoded 9.3) ──
    risk_score = risk_engine.calculate_risk_score(
        iocs=extracted_iocs,
        mitre_matches=mitre_data,
        actor_data=actor_data,
    )
    severity = risk_engine.get_severity_label(risk_score)
    tlp = risk_engine.get_tlp_label(risk_score)

    # ── 5. Confidence Scoring ──
    confidence = enricher.calculate_confidence(extracted_iocs, actor_mapped)

    # ── 6. Detection Engineering (Auto-Generated) ──
    sigma_rule = detection_engine.generate_sigma_rule(headline, extracted_iocs)
    yara_rule = detection_engine.generate_yara_rule(headline, extracted_iocs)

    # ── 7. Generate Elite Report ──
    report_html = generate_elite_report(
        headline=headline,
        iocs=extracted_iocs,
        risk_score=risk_score,
        severity=severity,
        tlp=tlp,
        confidence=confidence,
        mitre_data=mitre_data,
        actor_data=actor_data,
        sigma_rule=sigma_rule,
        yara_rule=yara_rule,
    )

    # ── 8. Publish to Blogger ──
    try:
        post_body = {
            "kind": "blogger#post",
            "title": headline,
            "content": report_html,
            "labels": [
                "Threat Intelligence", "CyberDudeBivash",
                severity, tlp.get('label', 'TLP:CLEAR'),
                feed_source,
            ],
        }

        response = service.posts().insert(blogId=BLOG_ID, body=post_body).execute()
        live_blog_url = response.get('url', '')
        logger.info(f"✓ GOC ELITE ADVISORY LIVE: {live_blog_url}")

        # ── 9. STIX Bundle + Manifest Sync ──
        stix_exporter.create_bundle(
            title=headline,
            iocs=extracted_iocs,
            risk_score=risk_score,
            metadata={"blog_url": live_blog_url},
            confidence=confidence,
            severity=severity,
            tlp_label=tlp.get('label', 'TLP:CLEAR'),
            ioc_counts=ioc_counts,
            actor_tag=actor_data.get('tracking_id', 'UNC-CDB-99'),
            mitre_tactics=mitre_data,
            feed_source=feed_source,
        )

        # ── 10. Mark as Processed (Dedup) ──
        dedup_engine.mark_processed(headline, entry.get('link', ''))

        return True

    except Exception as e:
        logger.error(f"APEX PUBLISH FAILURE: {e}")
        return False


if __name__ == "__main__":
    main()
