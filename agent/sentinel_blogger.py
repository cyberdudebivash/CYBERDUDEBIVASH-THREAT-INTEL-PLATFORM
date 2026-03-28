#!/usr/bin/env python3
"""
sentinel_blogger.py - CyberDudeBivash v21.0 (SENTINEL APEX ULTRA)
Path: agent/sentinel_blogger.py (PRODUCTION PIPELINE - authoritative)

PRODUCTION ORCHESTRATOR: Multi-feed fusion, source article fetching,
PREMIUM 16-section report generation (2500+ words), dynamic risk scoring,
TRIPLE-LAYER deduplication, enhanced STIX, MITRE mapping, actor attribution,
TLP classification, confidence scoring, rate-limit protection.

VERSION HISTORY:
  v11.5  Source article fetching added
  v13.0  Multi-dimensional confidence scoring
  v14.0  Manifest similarity dedup check added
  v17.0  Telemetry + predictive engine + campaign tracker
  v19.0  Content quality gate
  v21.0  EPSS + CVSS enrichment, source_url fix, KEV lookup, NVD schema
  v23.0  Content-aware risk scoring (fixes keyword inflation from AI sections)
  v46.0  VANGUARD IOC validation engine
  v55.0  Feed telemetry recording
  v55.2  Phase 1 manifest similarity check (was missing - caused CDB re-publishes)
  v56.0  Resilient publish guard (rate-limit retry + pending queue)
  v75.1  Trusted-source quality gate bypass via URL
  v75.5  CVSS-aware score cap + NVD recalculation after fetch
  v75.6  Smart labels rebuilt after NVD score update
  v76.2  CVSS passed to TLP classifier for RED qualification
  v77.1  FIX: kev_present initialised before use in process_entry (was NameError)
         FIX: _confirmed_actor guard uses local kev_present not dir() hack
"""
import os
import re
import sys
import time
import json
import logging
import urllib.request
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
from agent.telegram_alerts import send_threat_alert, send_pipeline_summary
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

# -- Optional module imports - all wrapped, degrade gracefully --------------

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

try:
    from agent.content.quality_gate import is_relevant_threat as _quality_gate
    _QUALITY_GATE_OK = True
except ImportError:
    _quality_gate = None
    _QUALITY_GATE_OK = False

try:
    from agent.v46_vanguard.vanguard_engine import vanguard_engine as _vanguard
    _VANGUARD_OK = True
except ImportError:
    _vanguard = None
    _VANGUARD_OK = False

# -- Logging ----------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-ENRICHER] %(message)s"
)
logger = logging.getLogger("CDB-ENRICHER")

BLOG_ID = os.getenv("BLOG_ID") or CONFIG_BLOG_ID


# ==============================================================================
# FEED INGESTION ENGINE
# ==============================================================================

def fetch_feed_entries(feed_url: str, max_entries: int = 3) -> List[Dict]:
    """Fetch and normalise entries from a single RSS/Atom feed."""
    try:
        feed = feedparser.parse(feed_url)
        entries = []
        for entry in feed.entries[:max_entries]:
            content = ""
            if hasattr(entry, "content") and entry.content:
                content = entry.content[0].get("value", "")
            if not content and hasattr(entry, "description"):
                content = entry.description
            if not content and hasattr(entry, "summary"):
                content = entry.summary

            summary = ""
            if hasattr(entry, "summary") and entry.summary != content:
                summary = entry.summary

            entries.append({
                "title":     entry.get("title", "Untitled Advisory"),
                "content":   content,
                "summary":   summary,
                "link":      entry.get("link", ""),
                "source":    feed_url,
                "published": entry.get("published", ""),
                "tags":      [t.get("term", "") for t in entry.get("tags", [])],
            })
        return entries
    except Exception as e:
        logger.warning(f"Feed fetch failed for {feed_url}: {e}")
        return []


# ==============================================================================
# SOURCE ARTICLE ENRICHMENT
# ==============================================================================

def enrich_with_source_content(entry: Dict) -> Optional[Dict]:
    """Fetch the full source article for deeper IOC extraction."""
    source_url = entry.get("link", "")
    if not source_url:
        return None
    try:
        logger.info(f"  -> Fetching source article: {source_url[:80]}...")
        fetched = source_fetcher.fetch_article(source_url)
        if fetched and fetched.get("fetch_status") == "success":
            logger.info(
                f"  -> Source fetched: {fetched.get('word_count', 0)} words, "
                f"{len(fetched.get('paragraphs', []))} paragraphs"
            )
            return fetched
        logger.warning(f"  -> Source fetch incomplete for: {source_url[:60]}")
    except Exception as e:
        logger.warning(f"  -> Source fetch error: {e}")
    return None


def build_enriched_content(entry: Dict, fetched_article: Optional[Dict]) -> str:
    """Combine RSS + full source article text."""
    parts = []
    if entry.get("content"):
        parts.append(entry["content"])
    if entry.get("summary"):
        parts.append(entry["summary"])
    if fetched_article and fetched_article.get("full_text"):
        parts.append(fetched_article["full_text"])
    return "\n\n".join(parts)


# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================

def main():
    logger.info("=" * 70)
    logger.info("SENTINEL APEX v21.0 - ULTRA-PREMIUM REPORT ENGINE ACTIVATED")
    logger.info("Triple-Layer Dedup * 15 Feeds * Quality Gate * IOC FP Filter")
    logger.info("v21.0: EPSS+CVSS Enrichment * Source URL Fix * KEV Lookup")
    logger.info("=" * 70)

    _run_start = time.monotonic()

    if _TELEMETRY_OK and _telemetry:
        _telemetry.start_timer("total_run")
        logger.info("[STATS] Telemetry: ENABLED")
    else:
        logger.info("[STATS] Telemetry: DISABLED or module not loaded")

    if _PREDICTIVE_OK:
        logger.info("? Predictive Engine: ENABLED")
    if _CAMPAIGN_OK:
        logger.info("? Campaign Tracker: ENABLED")

    try:
        service = get_blogger_service()
    except Exception as e:
        logger.error(f"Blogger authentication failed: {e}")
        return

    published_count = 0

    # -- v56.1: STRICT SYNC MODE — retry pending queue FIRST ----------------
    # TASK 3: Queue items are PRIORITIZED over new advisories.
    # TASK 4: Mandatory logging: QUEUE SIZE, RETRY SUCCESS, DEFERRED TO NEXT RUN
    _queue_size_before = 0
    try:
        from agent.v56_publish_guard.publisher import retry_pending_queue, _load_queue
        _queue_before = _load_queue()
        _queue_size_before = len(_queue_before)
        if _queue_size_before > 0:
            logger.info(f"  [QUEUE SIZE] {_queue_size_before} items pending before run")
        pending_published = retry_pending_queue(service, BLOG_ID)
        if pending_published > 0:
            published_count += pending_published
            logger.info(f"  [OK] Published {pending_published} pending items from queue")
    except ImportError:
        pass
    except Exception as _pq_err:
        logger.debug(f"Pending queue retry skipped (non-critical): {_pq_err}")

    # -- Load manifest once for similarity checking -------------------------
    def _load_manifest(path: str) -> List[Dict]:
        try:
            if os.path.exists(path):
                with open(path) as _f:
                    _data = json.load(_f)
                if isinstance(_data, list):
                    return _data
                elif isinstance(_data, dict):
                    return _data.get("entries", [])
        except Exception:
            pass
        return []

    _manifest_path = os.path.join("data", "stix", "feed_manifest.json")
    _manifest = _load_manifest(_manifest_path)

    # -- PHASE 1: Primary CDB Feed ------------------------------------------
    logger.info("--- PHASE 1: Primary CDB Intelligence Feed ---")
    _ph1_start = time.monotonic()
    primary_entries = fetch_feed_entries(CDB_RSS_FEED, max_entries=1)
    if _TELEMETRY_OK and _telemetry:
        _telemetry.record_feed_fetch(
            CDB_RSS_FEED, time.monotonic() - _ph1_start,
            success=len(primary_entries) > 0
        )

    for entry in primary_entries:
        if dedup_engine.is_duplicate(entry["title"], entry.get("link", "")):
            logger.info(f"  ? SKIP (duplicate): {entry['title'][:60]}")
            if _TELEMETRY_OK and _telemetry:
                _telemetry.record_dedup()
            continue

        if _manifest and dedup_engine.is_similar_in_manifest(
                entry["title"], _manifest, threshold=0.80):
            logger.info(f"  ? SKIP (manifest similar): {entry['title'][:60]}")
            dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
            if _TELEMETRY_OK and _telemetry:
                _telemetry.record_dedup()
            continue

        if _QUALITY_GATE_OK and _quality_gate:
            try:
                _qok, _qscore, _qreason = _quality_gate(
                    entry["title"],
                    entry.get("content", "") + entry.get("summary", ""),
                    source_url=entry.get("link", ""),
                )
                if not _qok:
                    logger.info(
                        f"  ? SKIP (quality gate [{_qreason[:60]}]): {entry['title'][:50]}"
                    )
                    dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                    continue
                logger.info(f"  ? Quality gate PASS (score={_qscore:.1f}): {entry['title'][:50]}")
            except Exception as _qe:
                logger.debug(f"  Quality gate error (non-critical): {_qe}")

        # v77.2 PIPELINE CRASH GUARD: wrap process_entry so a single article
        # error (NameError, AttributeError, timeout etc.) never kills the
        # whole pipeline. Crash on one entry = log + continue to next entry.
        try:
            result = process_entry(entry, service, feed_source="CDB-NEWS")
        except Exception as _pe:
            logger.error(f"  [CRASH-GUARD] process_entry failed for '{entry['title'][:60]}': {_pe}")
            result = False
        if result:
            published_count += 1
            if _TELEMETRY_OK and _telemetry:
                _telemetry.record_publish(elapsed_sec=0.0, success=True)
                _telemetry.record_cve_processing(elapsed_sec=0.0)
        time.sleep(RATE_LIMIT_DELAY)

    # -- PHASE 2: Multi-Feed Fusion -----------------------------------------
    logger.info("--- PHASE 2: Multi-Feed Intelligence Fusion ---")

    for feed_url in RSS_FEEDS:
        _feed_start = time.monotonic()
        entries = fetch_feed_entries(feed_url, max_entries=MAX_ENTRIES_PER_FEED)
        _feed_elapsed = time.monotonic() - _feed_start
        logger.info(f"Feed [{feed_url[:50]}...]: {len(entries)} entries")
        if _TELEMETRY_OK and _telemetry:
            _telemetry.record_feed_fetch(feed_url, _feed_elapsed, success=len(entries) > 0)

        for entry in entries:
            time.sleep(RATE_LIMIT_DELAY)

            if dedup_engine.is_duplicate(entry["title"], entry.get("link", "")):
                logger.info(f"  ? SKIP (duplicate): {entry['title'][:60]}")
                if _TELEMETRY_OK and _telemetry:
                    _telemetry.record_dedup()
                continue

            if _manifest and dedup_engine.is_similar_in_manifest(
                    entry["title"], _manifest, threshold=0.80):
                logger.info(f"  ? SKIP (manifest similar): {entry['title'][:60]}")
                dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                if _TELEMETRY_OK and _telemetry:
                    _telemetry.record_dedup()
                continue

            if _QUALITY_GATE_OK and _quality_gate:
                try:
                    _qok, _qscore, _qreason = _quality_gate(
                        entry["title"],
                        entry.get("content", "") + entry.get("summary", ""),
                        source_url=entry.get("link", ""),
                    )
                    if not _qok:
                        logger.info(
                            f"  ? SKIP (quality gate [{_qreason[:60]}]): {entry['title'][:50]}"
                        )
                        dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                        continue
                except Exception as _qe:
                    logger.debug(f"  Quality gate error (non-critical): {_qe}")

            # v77.2 PIPELINE CRASH GUARD: same as Phase 1 — one bad article
            # must never crash the entire run and block all remaining entries.
            try:
                result = process_entry(entry, service, feed_source=feed_url[:30])
            except Exception as _pe:
                logger.error(f"  [CRASH-GUARD] process_entry failed for '{entry['title'][:60]}': {_pe}")
                result = False
            if result:
                published_count += 1
                if _TELEMETRY_OK and _telemetry:
                    _telemetry.record_publish(elapsed_sec=0.0, success=True)
                    _telemetry.record_cve_processing(elapsed_sec=0.0)

    logger.info("=" * 70)
    logger.info(f"APEX v21.0 COMPLETE - Published {published_count} PREMIUM advisories")

    # [R-07] Telegram pipeline summary — fires once per run, non-blocking
    try:
        _critical_count = sum(
            1 for e in _telemetry._run_data.get("entries", [])
            if e.get("risk_score", 0) >= 9.0
        ) if (_TELEMETRY_OK and _telemetry and hasattr(_telemetry, "_run_data")) else 0
        send_pipeline_summary(
            published=published_count,
            failed=0,
            critical=_critical_count,
            run_ts=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        )
    except Exception:
        pass  # Never crash pipeline on Telegram failure

    # -- Predictive trend analysis ------------------------------------------
    if _PREDICTIVE_OK and _trend_model:
        try:
            trend = _trend_model.analyze()
            logger.info(
                f"? Risk Trend: {trend.get('trend_direction', 'N/A')} | "
                f"Velocity: {trend.get('attack_velocity_per_day', 0)}/day | "
                f"High Risk Rate: {trend.get('high_risk_rate_pct', 0)}%"
            )
        except Exception as e:
            logger.warning(f"Trend analysis failed (non-critical): {e}")

    # -- Finalise telemetry -------------------------------------------------
    if _TELEMETRY_OK and _telemetry:
        try:
            total_elapsed = time.monotonic() - _run_start
            _telemetry.finalize_run(
                total_elapsed=total_elapsed,
                status="success" if published_count >= 0 else "partial",
            )
        except Exception as e:
            logger.warning(f"Telemetry finalization failed (non-critical): {e}")
    logger.info("=" * 70)


# ==============================================================================
# ENTRY PROCESSOR
# ==============================================================================

def process_entry(entry: Dict, service, feed_source: str = "EXTERNAL") -> bool:
    """
    Full 13-step premium pipeline for a single intelligence entry.
    Returns True if published successfully.

    Steps:
      1  Fetch full source article
      2  IOC extraction from enriched content
      3  MITRE ATT&CK mapping
      4  Actor attribution
      5  Dynamic risk scoring (source-only, avoids AI-inflation)
      6  Confidence scoring (multi-dimensional)
      7  Detection engineering (Sigma + YARA)
      7b CVE enrichment (EPSS + CVSS + KEV via NVD/FIRST/CISA)
      7c VANGUARD IOC validation pass
      8  16-section premium report generation (2500+ words)
      9  Smart SEO labels
      10 Resilient publish (rate-limit retry + pending queue)
    """
    headline   = entry["title"]
    source_url = entry.get("link", "")

    logger.info(f"? PROCESSING: {headline[:80]}")

    # -- STEP 1: Source article ---------------------------------------------
    fetched_article  = enrich_with_source_content(entry)
    enriched_content = build_enriched_content(entry, fetched_article)
    logger.info(f"  -> Enriched content: {len(enriched_content.split())} words available for analysis")

    # -- STEP 2: IOC extraction ---------------------------------------------
    extracted_iocs = enricher.extract_iocs(enriched_content)
    ioc_counts     = enricher.get_ioc_counts(extracted_iocs)
    total_iocs     = sum(ioc_counts.values())
    logger.info(
        f"  -> IOCs extracted: {total_iocs} indicators across "
        f"{sum(1 for v in extracted_iocs.values() if v)} categories"
    )

    # -- STEP 3: MITRE ATT&CK mapping --------------------------------------
    full_corpus = f"{headline} {enriched_content}"
    mitre_data  = mitre_engine.map_threat(full_corpus)
    logger.info(f"  -> MITRE techniques mapped: {len(mitre_data)}")

    # -- STEP 4: Actor attribution ------------------------------------------
    actor_data  = actor_matrix.correlate_actor(full_corpus, extracted_iocs)
    actor_mapped = actor_data.get("tracking_id", "").startswith("CDB-")

    # -- STEP 5: Dynamic risk scoring --------------------------------------
    # v23.0 FIX: score ONLY from source text, not AI-generated report sections.
    # AI sections contain inflated keywords -> self-fulfilling CRITICAL scores.
    _source_for_scoring = (
        (fetched_article or {}).get("full_text", "")
        or entry.get("content", "")
        or entry.get("summary", "")
        or enriched_content[:2000]
    )
    _source_word_count = len(_source_for_scoring.split())

    # v77.1 FIX: initialise kev_present here so it is always defined,
    # even before the CVE enrichment step (STEP 7b) sets its real value.
    # Previously this was set in STEP 7b but referenced in STEP 5 via
    # `kev_present if 'kev_present' in dir() else False` - an unsafe hack.
    kev_present = False
    epss_score  = None
    cvss_score  = None
    nvd_url     = None

    risk_score = risk_engine.calculate_risk_score(
        iocs=extracted_iocs,
        mitre_matches=mitre_data,
        actor_data=actor_data,
        headline=headline,
        content=_source_for_scoring,
    )

    # v75.5 FIX: CVSS-aware score cap - never cap real HIGH/CRITICAL CVEs.
    _cve_only = bool(extracted_iocs.get("cve")) and not any([
        extracted_iocs.get("sha256"),
        extracted_iocs.get("ipv4"),
        extracted_iocs.get("domain"),
    ])
    _cvss_in_title = None
    try:
        _m = re.search(r"CVSS[: ]+(\d+\.?\d*)", enriched_content[:500] + headline)
        _cvss_in_title = float(_m.group(1)) if _m else None
    except Exception:
        pass
    _cap_exempt = _cvss_in_title and _cvss_in_title >= 7.0
    if _source_word_count < 50 and _cve_only and risk_score > 6.4 and not _cap_exempt:
        _original_score = risk_score
        risk_score = min(risk_score, 6.4)
        logger.info(
            f"  -> v75.5 score cap: {_original_score:.1f}->{risk_score:.1f} "
            f"(no source, CVE-only, CVSS<7)"
        )

    severity = risk_engine.get_severity_label(risk_score)
    _confirmed_actor = bool(actor_data and not actor_data.get("tracking_id", "").startswith("UNC-"))

    tlp = risk_engine.get_tlp_label(
        risk_score,
        iocs=extracted_iocs,
        kev_present=kev_present,        # v77.1: uses local variable, not dir() hack
        confirmed_actor=_confirmed_actor,
        cvss_score=None,                # Real CVSS not yet fetched - re-evaluated after NVD
    )

    impact_metrics = risk_engine.extract_impact_metrics(headline, enriched_content)
    logger.info(
        f"  -> Risk: {risk_score}/10 | Severity: {severity} | TLP: {tlp.get('label')} "
        f"| Records: {impact_metrics['records_affected']:,} "
        f"| Keywords: {len(impact_metrics['severity_keywords'])}"
    )

    # -- STEP 6: Confidence scoring -----------------------------------------
    confidence = enricher.calculate_confidence(extracted_iocs, actor_mapped)
    if impact_metrics["records_affected"] > 0:
        confidence = min(confidence + 15.0, 100.0)
    if len(impact_metrics["severity_keywords"]) >= 3:
        confidence = min(confidence + 10.0, 100.0)
    if len(mitre_data) >= 5:
        confidence = min(confidence + 8.0, 100.0)
    elif len(mitre_data) >= 3:
        confidence = min(confidence + 4.0, 100.0)
    actor_conf_str = str(actor_data.get("profile", {}).get("confidence_score", "Low")).lower()
    if "high" in actor_conf_str:
        confidence = min(confidence + 5.0, 100.0)
    elif "medium" in actor_conf_str:
        confidence = min(confidence + 3.0, 100.0)

    # -- STEP 7: Detection engineering -------------------------------------
    sigma_rule = detection_engine.generate_sigma_rule(headline, extracted_iocs)
    yara_rule  = detection_engine.generate_yara_rule(headline, extracted_iocs)

    # -- STEP 7b: CVE enrichment - EPSS + CVSS + KEV -----------------------
    cve_ids = extracted_iocs.get("cve", [])
    if cve_ids:
        try:
            _epss, _cvss, _kev, _nvd = _enrich_cve_metadata(cve_ids[0])
            epss_score  = _epss
            cvss_score  = _cvss
            kev_present = _kev
            nvd_url     = _nvd
            if epss_score or cvss_score:
                logger.info(
                    f"  -> CVE enrichment: EPSS={epss_score} CVSS={cvss_score} KEV={kev_present}"
                )
                # v75.5 FIX: Recalculate risk with real NVD data
                _nvd_score = risk_engine.recalculate_with_nvd(
                    base_score=risk_score,
                    cvss_score=cvss_score,
                    epss_score=epss_score,
                    kev_present=kev_present,
                )
                if _nvd_score != risk_score:
                    risk_score = _nvd_score
                    severity   = risk_engine.get_severity_label(risk_score)
                    tlp        = risk_engine.get_tlp_label(
                        risk_score,
                        iocs=extracted_iocs,
                        kev_present=kev_present,
                        confirmed_actor=_confirmed_actor,
                        cvss_score=cvss_score,   # v76.2: enables TLP:RED for CVSS 9+
                    )
                    logger.info(
                        f"  -> NVD-updated: Risk={risk_score}/10 "
                        f"| Severity={severity} | TLP={tlp.get('label')}"
                    )
                    # v75.6: Rebuild labels with updated severity
                    labels = _generate_smart_labels(
                        headline, severity, tlp, feed_source, extracted_iocs
                    )
        except Exception as _cve_e:
            logger.debug(f"CVE enrichment skipped (non-critical): {_cve_e}")

    # -- STEP 7c: VANGUARD IOC validation ----------------------------------
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
            extracted_iocs = _v46["iocs"]
            ioc_counts     = enricher.get_ioc_counts(extracted_iocs)
            if _v46["kev_present"]:
                kev_present = True
            if _v46["confidence"] is not None:
                confidence = _v46["confidence"]
            if _v46["fp_removed_count"] > 0:
                logger.info(
                    f"  -> VANGUARD: {_v46['fp_removed_count']} IOC FPs removed, "
                    f"confidence recalculated to {confidence:.1f}%"
                )
        except Exception as _v46_e:
            logger.debug(f"VANGUARD enhancement skipped (non-critical): {_v46_e}")

    # -- STEP 8: Premium report generation ---------------------------------
    logger.info("  -> Generating PREMIUM 16-section report...")
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
    report_word_count = len(re.sub(r"<[^>]+>", " ", report_html).split())
    logger.info(f"  -> Report generated: ~{report_word_count} words (target: 2500+)")

    # -- STEP 8b: Report Quality Gate (v77.2) --------------------------------
    # Validates the generated HTML before publishing to Blogger.
    # Catches: junk chars surviving into final HTML, Brotli garbage, empty reports,
    # suspiciously short reports, and structural integrity issues.
    JUNK_CHARS_SET = set('`][|~;{}\\^@#&*!?><')
    _html_text_only = re.sub(r"<[^>]+>", " ", report_html)
    _junk_in_report = sum(1 for c in _html_text_only[:3000] if c in JUNK_CHARS_SET)
    _junk_ratio = _junk_in_report / max(len(_html_text_only[:3000]), 1)
    _quality_failures = []

    if report_word_count < 300:
        _quality_failures.append(f"report too short ({report_word_count} words, min=300)")
    if _junk_ratio > 0.08:
        _quality_failures.append(f"junk char ratio too high ({_junk_ratio:.2%}, max=8%)")
    if '&#' in report_html:
        # Count numeric HTML entities — sign of unescaped non-ASCII leaking through
        _entity_count = len(re.findall(r'&#\d+;', report_html))
        if _entity_count > 5:
            _quality_failures.append(f"{_entity_count} raw &#NNN; entities in HTML (junk chars)")
    if '<h2' not in report_html:
        _quality_failures.append("missing section headers (structural failure)")

    if _quality_failures:
        logger.error(
            f"  [QUALITY-GATE] Report BLOCKED for '{headline[:60]}': "
            f"{'; '.join(_quality_failures)}"
        )
        # Save to pending queue as failed — will retry on next run with clean content
        try:
            from agent.v56_publish_guard.publisher import save_to_pending_queue
            save_to_pending_queue(headline, {"title": headline, "content": report_html, "labels": []})
        except Exception:
            pass
        return False  # Skip publishing this report

    logger.info(f"  [QUALITY-GATE] Report PASSED ({report_word_count} words, junk={_junk_ratio:.2%})")

    # -- STEP 9: Smart labels -----------------------------------------------
    labels = _generate_smart_labels(headline, severity, tlp, feed_source, extracted_iocs)

    # -- STEP 10: Resilient publish -----------------------------------------
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
        # Fallback: v56 module unavailable
        logger.warning("  [!] v56 publish guard not available - using legacy publish")
        try:
            post_body = {
                "kind":    "blogger#post",
                "title":   headline,
                "content": report_html,
                "labels":  labels,
            }
            response      = service.posts().insert(blogId=BLOG_ID, body=post_body).execute()
            live_blog_url = response.get("url", "")
            logger.info(
                f"  [OK] PREMIUM ADVISORY PUBLISHED ({report_word_count} words): {live_blog_url}"
            )
            stix_exporter.create_bundle(
                title=headline,
                iocs=extracted_iocs,
                risk_score=risk_score,
                metadata={"blog_url": live_blog_url, "source_url": source_url},
                confidence=confidence,
                severity=severity,
                tlp_label=tlp.get("label", "TLP:CLEAR"),
                ioc_counts=ioc_counts,
                actor_tag=actor_data.get("tracking_id", "UNC-CDB-99"),
                mitre_tactics=mitre_data,
                feed_source=feed_source,
                epss_score=epss_score,
                cvss_score=cvss_score,
                kev_present=kev_present,
                nvd_url=nvd_url,
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            # [R-07] Telegram alert — non-blocking, fires on HIGH/CRITICAL only
            send_threat_alert(
                title=headline, risk=risk_score, url=live_blog_url,
                cves=[c for c in re.findall(r'CVE-\d{4}-\d+', enriched_content or "")[:3]],
                ioc_count=sum(ioc_counts.values()) if isinstance(ioc_counts, dict) else 0,
                feed_source=feed_source,
            )
            return True
        except Exception as e:
            logger.error(f"  [X] PUBLISH FAILURE: {e}")
            return False


# ==============================================================================
# CVE METADATA ENRICHMENT
# ==============================================================================

def _enrich_cve_metadata(cve_id: str):
    """
    Fetch EPSS, CVSS base score, and KEV status for a CVE.
    Non-critical - returns (None, None, False, nvd_url) on any failure.
    Sources:
      EPSS  -> https://api.first.org/data/v1/epss
      CVSS  -> https://services.nvd.nist.gov/rest/json/cves/2.0
      KEV   -> CISA Known Exploited Vulnerabilities (via VANGUARD or v48 hardener)
    """
    cve_upper  = cve_id.upper().strip()
    epss_score = None
    cvss_score = None
    kev_present = False
    nvd_url    = f"https://nvd.nist.gov/vuln/detail/{cve_upper}"

    # EPSS lookup
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_upper}"
        req = urllib.request.Request(url, headers={"User-Agent": "CDB-Sentinel/21.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        if data.get("data"):
            epss_score = round(float(data["data"][0].get("epss", 0)) * 100, 2)
    except Exception:
        pass

    # NVD CVSS lookup
    try:
        nvd_key = os.getenv("NVD_API_KEY", "")
        headers = {"User-Agent": "CDB-Sentinel/21.0"}
        if nvd_key:
            headers["apiKey"] = nvd_key
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        vuln    = data.get("vulnerabilities", [{}])[0].get("cve", {})
        metrics = vuln.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                if cvss_score:
                    break
    except Exception:
        pass

    return epss_score, cvss_score, kev_present, nvd_url


# ==============================================================================
# SMART LABEL GENERATION
# ==============================================================================

def _generate_smart_labels(
    headline: str, severity: str, tlp: Dict,
    feed_source: str, iocs: Dict
) -> List[str]:
    """Generate SEO-optimised contextual Blogger labels."""
    labels = [
        "Threat Intelligence",
        "CyberDudeBivash",
        severity,
        tlp.get("label", "TLP:CLEAR"),
        "Sentinel APEX",
    ]
    text = headline.lower()
    threat_map = {
        "ransomware":    "Ransomware",
        "malware":       "Malware Analysis",
        "phishing":      "Phishing",
        "cve":           "CVE Advisory",
        "vulnerability": "Vulnerability",
        "breach":        "Data Breach",
        "zero-day":      "Zero-Day",
        "exploit":       "Exploit Analysis",
        "apt":           "APT",
        "supply chain":  "Supply Chain",
        "clickfix":      "Social Engineering",
        "backdoor":      "Backdoor",
        "trojan":        "Trojan",
        "botnet":        "Botnet",
        "windows":       "Windows Security",
        "microsoft":     "Microsoft",
        "chrome":        "Chrome Security",
        "linux":         "Linux Security",
    }
    for keyword, label in threat_map.items():
        if keyword in text:
            labels.append(label)
    if iocs.get("cve"):
        labels.append("CVE Analysis")
    if iocs.get("sha256") or iocs.get("md5"):
        labels.append("IOC Report")
    return list(dict.fromkeys(labels))[:10]


if __name__ == "__main__":
    main()
