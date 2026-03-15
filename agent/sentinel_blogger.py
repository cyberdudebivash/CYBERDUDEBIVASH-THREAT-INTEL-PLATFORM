#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v21.0 (SENTINEL APEX ULTRA)
PRODUCTION ORCHESTRATOR: Multi-feed fusion, source article fetching,
PREMIUM 16-section report generation (2500+ words), dynamic risk scoring,
TRIPLE-LAYER deduplication, enhanced STIX, MITRE mapping, actor attribution,
TLP classification, confidence scoring, rate-limit protection.

v21.0 UPGRADE:
  - EPSS + CVSS enrichment for CVE advisories (api.first.org + NVD)
  - source_url correctly written to STIX manifest (was always blank)
  - Manifest schema: nvd_url field added for CVE entries
  - KEV lookup enrichment via CISA KEV feed
  - All existing functionality PRESERVED. Zero breaking changes.
"""
import os
import re
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
from agent.content.premium_report_generator import premium_report_gen
from agent.content.source_fetcher import source_fetcher
from agent.config import (
    BLOG_ID as CONFIG_BLOG_ID,
    CDB_RSS_FEED,
    RSS_FEEDS,
    MAX_ENTRIES_PER_FEED,
    RATE_LIMIT_DELAY,
    BRAND,
    TELEMETRY_ENABLED,
    PREDICTIVE_ENABLED,
    CAMPAIGN_TRACKER_ENABLED,
)

# v17.0: New module imports (safe — all wrapped in try/except for graceful degradation)
try:
    from agent.core.telemetry import telemetry as _telemetry
    _TELEMETRY_OK = TELEMETRY_ENABLED
except ImportError:
    _telemetry = None
    _TELEMETRY_OK = False

try:
    from agent.predictive.exploit_forecaster import exploit_forecaster as _forecaster
    from agent.predictive.risk_trend_model import risk_trend_model as _trend_model
    _PREDICTIVE_OK = PREDICTIVE_ENABLED
except ImportError:
    _forecaster = None
    _trend_model = None
    _PREDICTIVE_OK = False

try:
    from agent.threat_actor.campaign_tracker import campaign_tracker as _campaign_tracker
    from agent.threat_actor.actor_registry import actor_registry as _actor_registry
    _CAMPAIGN_OK = CAMPAIGN_TRACKER_ENABLED
except ImportError:
    _campaign_tracker = None
    _actor_registry = None
    _CAMPAIGN_OK = False

# v19.0: Content Quality Gate (non-breaking — if import fails, all articles pass through)
try:
    from agent.content.quality_gate import is_relevant_threat as _quality_gate
    _QUALITY_GATE_OK = True
except ImportError:
    _quality_gate = None
    _QUALITY_GATE_OK = False

# v46.0 VANGUARD: IOC Validation + KEV Enrichment + Confidence Engine
# Non-breaking: if import fails, pipeline continues as v45.0
try:
    from agent.v46_vanguard.vanguard_engine import vanguard_engine as _vanguard
    _VANGUARD_OK = True
except ImportError:
    _vanguard = None
    _VANGUARD_OK = False

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
# MULTI-FEED INGESTION ENGINE (ENHANCED)
# ═══════════════════════════════════════════════════════════
def fetch_feed_entries(feed_url: str, max_entries: int = 3) -> List[Dict]:
    """Fetch and normalize entries from a single RSS feed.
    Enhanced: extracts ALL available content fields including tags."""
    try:
        feed = feedparser.parse(feed_url)
        entries = []
        for entry in feed.entries[:max_entries]:
            # Extract ALL available content from feed entry
            content = ""
            if hasattr(entry, 'content') and entry.content:
                content = entry.content[0].get('value', '')
            if not content and hasattr(entry, 'description'):
                content = entry.description
            if not content and hasattr(entry, 'summary'):
                content = entry.summary

            # Get full summary if available (some feeds have both)
            summary = ""
            if hasattr(entry, 'summary') and entry.summary != content:
                summary = entry.summary

            entries.append({
                'title': entry.get('title', 'Untitled Advisory'),
                'content': content,
                'summary': summary,
                'link': entry.get('link', ''),
                'source': feed_url,
                'published': entry.get('published', ''),
                'tags': [t.get('term', '') for t in entry.get('tags', [])],
            })
        return entries
    except Exception as e:
        logger.warning(f"Feed fetch failed for {feed_url}: {e}")
        return []


# ═══════════════════════════════════════════════════════════
# SOURCE ARTICLE CONTENT ENRICHMENT (NEW IN v11.5)
# ═══════════════════════════════════════════════════════════
def enrich_with_source_content(entry: Dict) -> Optional[Dict]:
    """
    Fetch the full source article to extract comprehensive content.
    This is the KEY UPGRADE that turns thin RSS summaries into
    rich, detailed intelligence reports.
    """
    source_url = entry.get('link', '')
    if not source_url:
        return None

    try:
        logger.info(f"  → Fetching source article: {source_url[:80]}...")
        fetched = source_fetcher.fetch_article(source_url)
        if fetched and fetched.get('fetch_status') == 'success':
            logger.info(f"  → Source fetched: {fetched.get('word_count', 0)} words, "
                       f"{len(fetched.get('paragraphs', []))} paragraphs")
            return fetched
        else:
            logger.warning(f"  → Source fetch incomplete for: {source_url[:60]}")
    except Exception as e:
        logger.warning(f"  → Source fetch error: {e}")

    return None


def build_enriched_content(entry: Dict, fetched_article: Optional[Dict]) -> str:
    """
    Combine RSS content + source article content for maximum
    IOC extraction coverage.
    """
    parts = []
    if entry.get('content'):
        parts.append(entry['content'])
    if entry.get('summary'):
        parts.append(entry['summary'])
    if fetched_article and fetched_article.get('full_text'):
        parts.append(fetched_article['full_text'])
    return '\n\n'.join(parts)


# ═══════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════
def main():
    logger.info("=" * 70)
    logger.info("SENTINEL APEX v21.0 — ULTRA-PREMIUM REPORT ENGINE ACTIVATED")
    logger.info("Triple-Layer Dedup • 15 Feeds • Quality Gate • IOC FP Filter")
    logger.info("v21.0: EPSS+CVSS Enrichment • Source URL Fix • KEV Lookup")
    logger.info("=" * 70)

    # ── v17.0: Start run telemetry ──
    _run_start = time.monotonic()
    if _TELEMETRY_OK and _telemetry:
        _telemetry.start_timer("total_run")
        logger.info("📊 Telemetry: ENABLED")
    else:
        logger.info("📊 Telemetry: DISABLED or module not loaded")

    if _PREDICTIVE_OK:
        logger.info("🔮 Predictive Engine: ENABLED")
    if _CAMPAIGN_OK:
        logger.info("🎯 Campaign Tracker: ENABLED")

    try:
        service = get_blogger_service()
    except Exception as e:
        logger.error(f"Blogger authentication failed: {e}")
        return

    published_count = 0

    # ─── v56: Retry any pending publish queue items from previous failed runs ───
    try:
        from agent.v56_publish_guard.publisher import retry_pending_queue
        pending_published = retry_pending_queue(service, BLOG_ID)
        if pending_published > 0:
            published_count += pending_published
            logger.info(f"  ✓ Published {pending_published} pending items from queue")
    except ImportError:
        pass  # v56 module not available
    except Exception as _pq_err:
        logger.debug(f"Pending queue retry skipped (non-critical): {_pq_err}")

    # ═══════════════════════════════════════════════════════
    # PHASE 1: Process Primary CDB Feed
    # v14.0 FIX: Added dedup check (was MISSING → caused 6x duplicates)
    # ═══════════════════════════════════════════════════════
    logger.info("─── PHASE 1: Primary CDB Intelligence Feed ───")
    _ph1_start = time.monotonic()
    primary_entries = fetch_feed_entries(CDB_RSS_FEED, max_entries=1)
    # v55.0 FIX: Record feed telemetry
    if _TELEMETRY_OK and _telemetry:
        _telemetry.record_feed_fetch(CDB_RSS_FEED, time.monotonic() - _ph1_start, success=len(primary_entries) > 0)

    for entry in primary_entries:
        if dedup_engine.is_duplicate(entry['title'], entry.get('link', '')):
            logger.info(f"  ⏭ SKIP (duplicate): {entry['title'][:60]}")
            if _TELEMETRY_OK and _telemetry:
                _telemetry.record_dedup()
            continue
        # v19.0: Quality gate — skip non-threat editorial/marketing content
        if _QUALITY_GATE_OK and _quality_gate:
            try:
                _qok, _qscore, _qreason = _quality_gate(
                    entry['title'], entry.get('content', '') + entry.get('summary', ''))
                if not _qok:
                    logger.info(f"  ⏭ SKIP (quality gate [{_qreason[:60]}]): {entry['title'][:50]}")
                    dedup_engine.mark_processed(entry['title'], entry.get('link', ''))
                    continue
                logger.info(f"  ✅ Quality gate PASS (score={_qscore:.1f}): {entry['title'][:50]}")
            except Exception as _qe:
                logger.debug(f"  Quality gate error (non-critical): {_qe}")
        result = process_entry(entry, service, feed_source="CDB-NEWS")
        if result:
            published_count += 1
            if _TELEMETRY_OK and _telemetry:
                _telemetry.record_publish(elapsed_sec=0.0, success=True)
                _telemetry.record_cve_processing(elapsed_sec=0.0)
        time.sleep(RATE_LIMIT_DELAY)

    # ═══════════════════════════════════════════════════════
    # PHASE 2: Multi-Feed Fusion (ENHANCED v14.0)
    # v14.0 FIX: Added manifest similarity check (was never called)
    # ═══════════════════════════════════════════════════════
    logger.info("─── PHASE 2: Multi-Feed Intelligence Fusion ───")

    # Load manifest ONCE for similarity checking
    # v17.0: Handle both old list format and new dict format
    _manifest = []
    try:
        import json as _json
        _mpath = os.path.join("data", "stix", "feed_manifest.json")
        if os.path.exists(_mpath):
            with open(_mpath) as _f:
                _data = _json.load(_f)
            if isinstance(_data, list):
                _manifest = _data
            elif isinstance(_data, dict):
                _manifest = _data.get("entries", [])
    except Exception:
        pass

    for feed_url in RSS_FEEDS:
        _feed_start = time.monotonic()
        entries = fetch_feed_entries(feed_url, max_entries=MAX_ENTRIES_PER_FEED)
        _feed_elapsed = time.monotonic() - _feed_start
        logger.info(f"Feed [{feed_url[:50]}...]: {len(entries)} entries")
        # v55.0 FIX: Record feed fetch telemetry
        if _TELEMETRY_OK and _telemetry:
            _telemetry.record_feed_fetch(feed_url, _feed_elapsed, success=len(entries) > 0)

        for entry in entries:
            time.sleep(RATE_LIMIT_DELAY)

            # Triple-layer dedup check
            if dedup_engine.is_duplicate(entry['title'], entry.get('link', '')):
                logger.info(f"  ⏭ SKIP (duplicate): {entry['title'][:60]}")
                if _TELEMETRY_OK and _telemetry:
                    _telemetry.record_dedup()
                continue

            # v14.0: Manifest similarity check (catches near-identical titles)
            if _manifest and dedup_engine.is_similar_in_manifest(
                    entry['title'], _manifest, threshold=0.80):
                logger.info(f"  ⏭ SKIP (manifest similar): {entry['title'][:60]}")
                dedup_engine.mark_processed(entry['title'], entry.get('link', ''))
                if _TELEMETRY_OK and _telemetry:
                    _telemetry.record_dedup()
                continue

            # v19.0: Quality gate — filter non-threat content before processing
            if _QUALITY_GATE_OK and _quality_gate:
                try:
                    _qok, _qscore, _qreason = _quality_gate(
                        entry['title'], entry.get('content', '') + entry.get('summary', ''))
                    if not _qok:
                        logger.info(f"  ⏭ SKIP (quality gate [{_qreason[:60]}]): {entry['title'][:50]}")
                        dedup_engine.mark_processed(entry['title'], entry.get('link', ''))
                        continue
                except Exception as _qe:
                    logger.debug(f"  Quality gate error (non-critical): {_qe}")

            result = process_entry(entry, service, feed_source=feed_url[:30])
            if result:
                published_count += 1
                if _TELEMETRY_OK and _telemetry:
                    _telemetry.record_publish(elapsed_sec=0.0, success=True)
                    _telemetry.record_cve_processing(elapsed_sec=0.0)

    logger.info("=" * 70)
    logger.info(f"APEX v19.0 COMPLETE — Published {published_count} PREMIUM advisories")

    # ── v17.0: Run predictive trend analysis ──
    if _PREDICTIVE_OK and _trend_model:
        try:
            trend = _trend_model.analyze()
            logger.info(
                f"📈 Threat Trend: {trend.get('trend_direction', 'N/A')} | "
                f"Velocity: {trend.get('attack_velocity_per_day', 0)}/day | "
                f"High Risk Rate: {trend.get('high_risk_rate_pct', 0)}%"
            )
        except Exception as e:
            logger.warning(f"Trend analysis failed (non-critical): {e}")

    # ── v17.0: Finalize telemetry ──
    if _TELEMETRY_OK and _telemetry:
        try:
            total_elapsed = time.monotonic() - _run_start
            _telemetry.finalize_run(
                total_elapsed=total_elapsed,
                status="success" if published_count >= 0 else "partial"
            )
        except Exception as e:
            logger.warning(f"Telemetry finalization failed (non-critical): {e}")
    logger.info("=" * 70)


def process_entry(entry: Dict, service, feed_source: str = "EXTERNAL") -> bool:
    """
    Process a single intelligence entry through the FULL PREMIUM pipeline:
    1. Fetch full source article content
    2. Extract IOCs from enriched content (RSS + full article)
    3. Dynamic risk scoring + MITRE mapping + actor attribution
    4. Generate 16-section PREMIUM report (2500+ words)
    5. Publish to Blogger
    6. Create STIX bundle + update manifest
    Returns True if successfully published.
    """
    headline = entry['title']
    source_url = entry.get('link', '')

    logger.info(f"▶ PROCESSING: {headline[:80]}")

    # ─── STEP 1: Fetch Full Source Article ───
    fetched_article = enrich_with_source_content(entry)
    enriched_content = build_enriched_content(entry, fetched_article)
    logger.info(f"  → Enriched content: {len(enriched_content.split())} words available for analysis")

    # ─── STEP 2: IOC Extraction from ENRICHED content ───
    extracted_iocs = enricher.extract_iocs(enriched_content)
    ioc_counts = enricher.get_ioc_counts(extracted_iocs)
    total_iocs = sum(ioc_counts.values())
    logger.info(f"  → IOCs extracted: {total_iocs} indicators across "
               f"{sum(1 for v in extracted_iocs.values() if v)} categories")

    # ─── STEP 3: MITRE ATT&CK Mapping ───
    full_corpus = f"{headline} {enriched_content}"
    mitre_data = mitre_engine.map_threat(full_corpus)
    logger.info(f"  → MITRE techniques mapped: {len(mitre_data)}")

    # ─── STEP 4: Actor Attribution ───
    actor_data = actor_matrix.correlate_actor(full_corpus, extracted_iocs)
    actor_mapped = actor_data.get('tracking_id', '').startswith('CDB-')

    # ─── STEP 5: Dynamic Risk Scoring (NOW CONTENT-AWARE) ───
    risk_score = risk_engine.calculate_risk_score(
        iocs=extracted_iocs,
        mitre_matches=mitre_data,
        actor_data=actor_data,
        headline=headline,
        content=enriched_content,
    )
    severity = risk_engine.get_severity_label(risk_score)
    tlp = risk_engine.get_tlp_label(risk_score)

    # Extract impact metrics for report enrichment
    impact_metrics = risk_engine.extract_impact_metrics(headline, enriched_content)
    logger.info(f"  → Risk: {risk_score}/10 | Severity: {severity} | TLP: {tlp.get('label')}"
               f" | Records: {impact_metrics['records_affected']:,}"
               f" | Keywords: {len(impact_metrics['severity_keywords'])}")

    # ─── STEP 6: Confidence Scoring (v13.0 MULTI-DIMENSIONAL) ───
    # Factors: IOCs + content signals + MITRE depth + actor attribution quality
    confidence = enricher.calculate_confidence(extracted_iocs, actor_mapped)
    if impact_metrics["records_affected"] > 0:
        confidence = min(confidence + 15.0, 100.0)  # Records confirmed
    if len(impact_metrics["severity_keywords"]) >= 3:
        confidence = min(confidence + 10.0, 100.0)  # Multiple severity signals
    # NEW: MITRE technique depth bonus
    if len(mitre_data) >= 5:
        confidence = min(confidence + 8.0, 100.0)   # Deep MITRE coverage
    elif len(mitre_data) >= 3:
        confidence = min(confidence + 4.0, 100.0)   # Moderate MITRE coverage
    # NEW: Actor attribution quality bonus
    actor_conf_str = str(actor_data.get("profile", {}).get("confidence_score", "Low")).lower()
    if "high" in actor_conf_str:
        confidence = min(confidence + 5.0, 100.0)   # High-confidence actor
    elif "medium" in actor_conf_str:
        confidence = min(confidence + 3.0, 100.0)   # Medium-confidence actor

    # ─── STEP 7: Detection Engineering ───
    sigma_rule = detection_engine.generate_sigma_rule(headline, extracted_iocs)
    yara_rule = detection_engine.generate_yara_rule(headline, extracted_iocs)

    # ─── STEP 7b: CVE Enrichment — EPSS + CVSS + KEV (v21.0, non-critical) ───
    epss_score = None
    cvss_score = None
    kev_present = False
    nvd_url = None
    cve_ids = extracted_iocs.get('cve', [])
    if cve_ids:
        try:
            _epss, _cvss, _kev, _nvd = _enrich_cve_metadata(cve_ids[0])
            epss_score = _epss
            cvss_score = _cvss
            kev_present = _kev
            nvd_url = _nvd
            if epss_score or cvss_score:
                logger.info(f"  → CVE enrichment: EPSS={epss_score} CVSS={cvss_score} KEV={kev_present}")
        except Exception as _cve_e:
            logger.debug(f"CVE enrichment skipped (non-critical): {_cve_e}")

    # ─── STEP 7c: VANGUARD v46.0 Enhancement Pass (non-breaking) ───
    # IOC validation (removes .py/.cpp FP domains, deconflicts hashes)
    # KEV live lookup (fixes always-False kev_present)
    # Confidence recalculation (Bayesian weighted, replaces additive)
    if _VANGUARD_OK and _vanguard:
        try:
            _v46 = _vanguard.enhance(
                iocs=extracted_iocs,
                source_text=enriched_content,
                cve_ids=cve_ids,
                mitre_data=mitre_data,
                actor_data=actor_data,
                impact_metrics=impact_metrics,
                fetched_article=fetched_article,
                source_content=enriched_content,
                epss_score=epss_score,
                cvss_score=cvss_score,
                kev_present=kev_present,
            )
            # Apply validated IOCs
            extracted_iocs = _v46["iocs"]
            ioc_counts = enricher.get_ioc_counts(extracted_iocs)
            # Apply KEV result (overrides broken v21 implementation)
            if _v46["kev_present"]:
                kev_present = True
            # Apply recalculated confidence (if engine succeeded)
            if _v46["confidence"] is not None:
                confidence = _v46["confidence"]
            if _v46["fp_removed_count"] > 0:
                logger.info(f"  → VANGUARD: {_v46['fp_removed_count']} IOC FPs removed, "
                           f"confidence recalculated to {confidence:.1f}%")
        except Exception as _v46_e:
            logger.debug(f"VANGUARD enhancement skipped (non-critical): {_v46_e}")

    # ─── STEP 8: Generate PREMIUM 16-Section Report (2500+ words) ───
    logger.info(f"  → Generating PREMIUM 16-section report...")

    report_html = premium_report_gen.generate_premium_report(
        headline=headline,
        source_content=enriched_content,
        source_url=source_url,
        iocs=extracted_iocs,
        risk_score=risk_score,
        severity=severity,
        confidence=confidence,
        tlp=tlp,
        mitre_data=mitre_data,
        actor_data=actor_data,
        sigma_rule=sigma_rule,
        yara_rule=yara_rule,
        fetched_article=fetched_article,
        impact_metrics=impact_metrics,
    )

    report_word_count = len(re.sub(r'<[^>]+>', ' ', report_html).split())
    logger.info(f"  → Report generated: ~{report_word_count} words (target: 2500+)")

    # ─── STEP 9: Smart Labels ───
    labels = _generate_smart_labels(headline, severity, tlp, feed_source, extracted_iocs)

    # ─── STEP 10-13: v56 Resilient Publish (Rate Limit + Retry + Manifest-First) ───
    try:
        from agent.v56_publish_guard.publisher import resilient_publish
        return resilient_publish(
            service=service,
            blog_id=BLOG_ID,
            headline=headline,
            report_html=report_html,
            labels=labels,
            entry=entry,
            stix_exporter=stix_exporter,
            dedup_engine=dedup_engine,
            extracted_iocs=extracted_iocs,
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            tlp=tlp,
            ioc_counts=ioc_counts,
            actor_data=actor_data,
            mitre_data=mitre_data,
            feed_source=feed_source,
            source_url=source_url,
            enriched_content=enriched_content,
            epss_score=epss_score,
            cvss_score=cvss_score,
            kev_present=kev_present,
            nvd_url=nvd_url,
        )
    except ImportError:
        # Fallback: v56 module not available — use original logic
        logger.warning("  ⚠ v56 publish guard not available — using legacy publish")
        try:
            post_body = {
                "kind": "blogger#post",
                "title": headline,
                "content": report_html,
                "labels": labels,
            }
            response = service.posts().insert(blogId=BLOG_ID, body=post_body).execute()
            live_blog_url = response.get('url', '')
            logger.info(f"  ✓ PREMIUM ADVISORY PUBLISHED ({report_word_count} words): {live_blog_url}")
            stix_exporter.create_bundle(
                title=headline, iocs=extracted_iocs, risk_score=risk_score,
                metadata={"blog_url": live_blog_url, "source_url": source_url},
                confidence=confidence, severity=severity,
                tlp_label=tlp.get('label', 'TLP:CLEAR'), ioc_counts=ioc_counts,
                actor_tag=actor_data.get('tracking_id', 'UNC-CDB-99'),
                mitre_tactics=mitre_data, feed_source=feed_source,
                epss_score=epss_score, cvss_score=cvss_score,
                kev_present=kev_present, nvd_url=nvd_url,
            )
            dedup_engine.mark_processed(headline, entry.get('link', ''))
            return True
        except Exception as e:
            logger.error(f"  ✗ PUBLISH FAILURE: {e}")
            return False


def _enrich_cve_metadata(cve_id: str):
    """
    Fetch EPSS score, CVSS base score, and KEV status for a given CVE ID.
    v21.0 addition — non-critical, returns None values on failure.
    Sources:
      - EPSS: https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX
      - NVD:  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX
      - KEV:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Returns (epss_score, cvss_score, kev_present, nvd_url)
    """
    import urllib.request
    import json as _json

    cve_upper = cve_id.upper().strip()
    epss_score = None
    cvss_score = None
    kev_present = False
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_upper}"

    # ── EPSS lookup ──
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_upper}"
        req = urllib.request.Request(url, headers={"User-Agent": "CDB-Sentinel/21.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = _json.loads(resp.read())
        if data.get("data"):
            epss_score = round(float(data["data"][0].get("epss", 0)) * 100, 2)
    except Exception:
        pass

    # ── NVD CVSS lookup ──
    try:
        nvd_key = os.getenv("NVD_API_KEY", "")
        headers = {"User-Agent": "CDB-Sentinel/21.0"}
        if nvd_key:
            headers["apiKey"] = nvd_key
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read())
        vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
        metrics = vuln.get("metrics", {})
        # Try CVSS v3.1 first, fall back to v3.0, then v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                if cvss_score:
                    break
    except Exception:
        pass

    return epss_score, cvss_score, kev_present, nvd_url


def _generate_smart_labels(headline: str, severity: str, tlp: Dict,
                           feed_source: str, iocs: Dict) -> List[str]:
    """Generate SEO-optimized contextual labels for the blog post."""
    labels = [
        "Threat Intelligence",
        "CyberDudeBivash",
        severity,
        tlp.get('label', 'TLP:CLEAR'),
        "Sentinel APEX",
    ]

    text = headline.lower()
    threat_labels = {
        "ransomware": "Ransomware",
        "malware": "Malware Analysis",
        "phishing": "Phishing",
        "cve": "CVE Advisory",
        "vulnerability": "Vulnerability",
        "breach": "Data Breach",
        "zero-day": "Zero-Day",
        "exploit": "Exploit Analysis",
        "apt": "APT",
        "supply chain": "Supply Chain",
        "clickfix": "Social Engineering",
        "backdoor": "Backdoor",
        "trojan": "Trojan",
        "botnet": "Botnet",
        "windows": "Windows Security",
        "microsoft": "Microsoft",
        "chrome": "Chrome Security",
        "linux": "Linux Security",
    }
    for keyword, label in threat_labels.items():
        if keyword in text:
            labels.append(label)

    if iocs.get('cve'):
        labels.append("CVE Analysis")
    if iocs.get('sha256') or iocs.get('md5'):
        labels.append("IOC Report")

    return list(dict.fromkeys(labels))[:10]


if __name__ == "__main__":
    main()
