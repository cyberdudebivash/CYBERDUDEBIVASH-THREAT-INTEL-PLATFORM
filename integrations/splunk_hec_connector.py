#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — Splunk HEC Connector v143.0.0                            ║
║  Phase IV Asset 5 — 30-Second SOC Integration                             ║
║                                                                            ║
║  Pushes SENTINEL APEX threat advisories to Splunk via HTTP Event           ║
║  Collector (HEC). Production-hardened: retry, batching, auth,              ║
║  TLS verification, and structured JSON for CIM compliance.                 ║
║                                                                            ║
║  Quick Start (30 seconds):                                                 ║
║    export SPLUNK_HEC_URL="https://splunk.acme.com:8088"                   ║
║    export SPLUNK_HEC_TOKEN="<your-hec-token>"                             ║
║    python integrations/splunk_hec_connector.py --test                     ║
║    python integrations/splunk_hec_connector.py --push-latest              ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SPLUNK-HEC")

# ── Config ────────────────────────────────────────────────────────────────────
SPLUNK_HEC_URL    = os.getenv("SPLUNK_HEC_URL", "").rstrip("/")
SPLUNK_HEC_TOKEN  = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX      = os.getenv("SPLUNK_INDEX", "cyberdudebivash_threats")
SPLUNK_SOURCETYPE = "cyberdudebivash:sentinel_apex:threat"
SPLUNK_SOURCE     = "sentinel-apex-v143.0.0"
SPLUNK_HOST       = "intel.cyberdudebivash.com"

BATCH_SIZE        = 50        # events per HEC batch request
RETRY_ATTEMPTS    = 3
RETRY_BACKOFF_SEC = 2
REQUEST_TIMEOUT   = 15

ROOT         = Path(__file__).parent.parent
DATA_DIR     = ROOT / "data"
FEED_SOURCES = [
    DATA_DIR / "apex_v2_manifest.json",
    DATA_DIR / "apex_enriched_manifest.json",
    DATA_DIR / "feed_manifest.json",
    ROOT / "feed.json",
]


# ── Normalization: APEX → Splunk CIM ─────────────────────────────────────────

def apex_to_splunk_event(item: Dict) -> Dict:
    """
    Convert APEX threat advisory to Splunk CIM-compliant JSON event.
    Maps to CIM Threat Intelligence data model fields.
    """
    apex_ai = item.get("apex_ai") or item.get("apex") or {}
    now_epoch = int(time.time())
    item_ts = item.get("timestamp") or item.get("published_at") or ""
    try:
        item_epoch = int(
            datetime.fromisoformat(
                item_ts.replace("Z", "+00:00")
            ).timestamp()
        ) if item_ts else now_epoch
    except Exception:
        item_epoch = now_epoch

    # CIM Threat Intelligence fields
    cim_event = {
        # ── Identity ──────────────────────────────────────────────────────
        "src":               "sentinel-apex-v143.0.0",
        "vendor_product":    "CYBERDUDEBIVASH SENTINEL APEX",
        "threat_collection": "cyberdudebivash_apex",
        "threat_collection_version": "143.0.0",

        # ── Threat ID ─────────────────────────────────────────────────────
        "threat_id":         item.get("id") or item.get("stix_id") or "",
        "stix_id":           item.get("stix_id") or "",

        # ── Severity / Risk ───────────────────────────────────────────────
        "severity":          item.get("severity", "UNKNOWN"),
        "risk_score":        item.get("risk_score", 0),
        "cvss_score":        item.get("cvss_score"),
        "epss_score":        item.get("epss_score"),
        "kev_present":       item.get("kev_present", False),

        # ── Threat Content ────────────────────────────────────────────────
        "threat_name":       item.get("title", "")[:512],
        "description":       item.get("description", "")[:1024],
        "threat_type":       item.get("threat_type", "THREAT-INTEL"),
        "tlp":               item.get("tlp", "TLP:GREEN"),
        "source":            item.get("source", ""),
        "source_url":        item.get("source_url", ""),

        # ── Actor ─────────────────────────────────────────────────────────
        "actor":             item.get("actor_tag") or apex_ai.get("actor_fingerprint") or "",
        "campaign_id":       apex_ai.get("campaign_id") or "",

        # ── MITRE ATT&CK ──────────────────────────────────────────────────
        "mitre_techniques":  [
            t if isinstance(t, str) else t.get("technique_id", "")
            for t in (item.get("ttps") or item.get("mitre_tactics") or [])
        ],
        "ttp_count":         item.get("ttp_count", 0),

        # ── IOC Summary ───────────────────────────────────────────────────
        "ioc_count":         item.get("ioc_count", 0),
        "ioc_threat_level":  item.get("ioc_threat_level", "NONE"),

        # ── APEX AI Enrichment ────────────────────────────────────────────
        "apex_soc_priority":     apex_ai.get("soc_priority", ""),
        "apex_threat_level":     apex_ai.get("threat_level", ""),
        "apex_predictive_risk":  apex_ai.get("predictive_risk", 0),
        "apex_ai_confidence":    apex_ai.get("ai_confidence", 0),
        "apex_kill_chain":       apex_ai.get("kill_chain_primary") or "",

        # ── Timestamps ────────────────────────────────────────────────────
        "event_time":        item_epoch,
        "processed_at":      item.get("processed_at", ""),
        "ingest_time":       now_epoch,

        # ── Platform Meta ─────────────────────────────────────────────────
        "platform":          "SENTINEL-APEX/143.0.0",
        "gstin":             "21ARKPN8270G1ZP",
        "portal_url":        "https://intel.cyberdudebivash.com",
    }
    return cim_event


def build_hec_batch(items: List[Dict]) -> bytes:
    """Build Splunk HEC batch payload — newline-delimited JSON events."""
    lines = []
    for item in items:
        event_data = apex_to_splunk_event(item)
        hec_wrapper = {
            "time":       event_data["event_time"],
            "host":       SPLUNK_HOST,
            "source":     SPLUNK_SOURCE,
            "sourcetype": SPLUNK_SOURCETYPE,
            "index":      SPLUNK_INDEX,
            "event":      event_data,
        }
        lines.append(json.dumps(hec_wrapper, separators=(",", ":")))
    return ("\n".join(lines)).encode("utf-8")


# ── HTTP Push ─────────────────────────────────────────────────────────────────

def _build_ssl_context(verify_tls: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def push_batch(
    payload: bytes,
    hec_url: str,
    hec_token: str,
    verify_tls: bool = True,
) -> Dict:
    """
    Push a single batch to Splunk HEC.
    Returns {"success": bool, "status_code": int, "response": str}.
    """
    url     = f"{hec_url.rstrip('/')}/services/collector/event"
    headers = {
        "Authorization":  f"Splunk {hec_token}",
        "Content-Type":   "application/json; charset=utf-8",
        "X-Splunk-Request-Channel": "sentinel-apex",
    }

    for attempt in range(RETRY_ATTEMPTS):
        try:
            req = urllib.request.Request(
                url, data=payload, headers=headers, method="POST"
            )
            ctx = _build_ssl_context(verify_tls)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT,
                                        context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if resp.status in (200, 201):
                    logger.info(f"HEC batch pushed (attempt {attempt+1}): "
                                f"{resp.status} | {len(payload)} bytes")
                    return {"success": True, "status_code": resp.status,
                            "response": body}
                else:
                    logger.warning(f"HEC non-200: {resp.status} | {body[:200]}")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            logger.error(f"HEC HTTPError {e.code} (attempt {attempt+1}): {body[:200]}")
            if e.code in (400, 401, 403):
                return {"success": False, "status_code": e.code, "response": body}
        except Exception as ex:
            logger.error(f"HEC push error (attempt {attempt+1}): {ex}")

        if attempt < RETRY_ATTEMPTS - 1:
            time.sleep(RETRY_BACKOFF_SEC ** (attempt + 1))

    return {"success": False, "status_code": 0, "response": "Max retries exceeded"}


def test_connectivity(hec_url: str, hec_token: str) -> Dict:
    """Send a test event to verify HEC connectivity."""
    test_item = {
        "id": "test-sentinel-apex-001",
        "title": "SENTINEL APEX HEC Connectivity Test",
        "severity": "INFO",
        "risk_score": 0,
        "source": "sentinel_apex_test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    payload = build_hec_batch([test_item])
    result  = push_batch(payload, hec_url, hec_token)
    result["test_event_sent"] = True
    result["hec_url"]         = hec_url
    return result


# ── Main Push Pipeline ────────────────────────────────────────────────────────

def load_latest_feed() -> List[Dict]:
    for src in FEED_SOURCES:
        if src.exists():
            try:
                raw = json.loads(src.read_bytes())
                items = raw if isinstance(raw, list) else \
                        raw.get("items") or raw.get("advisories") or []
                if items:
                    logger.info(f"Feed loaded: {src.name} ({len(items)} items)")
                    return items
            except Exception as e:
                logger.warning(f"Feed load failed {src.name}: {e}")
    return []


def push_feed(
    hec_url: Optional[str] = None,
    hec_token: Optional[str] = None,
    severity_filter: Optional[str] = None,
    limit: int = 500,
    verify_tls: bool = True,
) -> Dict:
    """
    Push APEX threat feed to Splunk HEC.
    Returns summary of push operation.
    """
    url   = hec_url or SPLUNK_HEC_URL
    token = hec_token or SPLUNK_HEC_TOKEN

    if not url or not token:
        return {
            "success": False,
            "error": "SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set",
            "setup_guide": "https://intel.cyberdudebivash.com/soc-integrations.html"
        }

    items = load_latest_feed()
    if severity_filter:
        items = [i for i in items
                 if str(i.get("severity", "")).upper() == severity_filter.upper()]
    items = items[:limit]

    if not items:
        return {"success": True, "pushed": 0, "batches": 0,
                "warning": "No items to push"}

    batches_pushed = 0
    events_pushed  = 0
    errors         = []

    for i in range(0, len(items), BATCH_SIZE):
        batch   = items[i:i + BATCH_SIZE]
        payload = build_hec_batch(batch)
        result  = push_batch(payload, url, token, verify_tls)
        if result["success"]:
            batches_pushed += 1
            events_pushed  += len(batch)
        else:
            errors.append({"batch_start": i, "error": result.get("response", "")[:200]})

    summary = {
        "success":        len(errors) == 0,
        "pushed":         events_pushed,
        "batches":        batches_pushed,
        "errors":         len(errors),
        "error_details":  errors[:5],
        "index":          SPLUNK_INDEX,
        "sourcetype":     SPLUNK_SOURCETYPE,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }
    logger.info(f"Splunk push: {events_pushed} events | {batches_pushed} batches | "
                f"{len(errors)} errors")
    return summary


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX → Splunk HEC Push Connector"
    )
    parser.add_argument("--test",         action="store_true", help="Test HEC connectivity")
    parser.add_argument("--push-latest",  action="store_true", help="Push latest feed")
    parser.add_argument("--severity",     default=None,
                        help="Filter severity (CRITICAL/HIGH/MEDIUM/LOW)")
    parser.add_argument("--limit",        type=int, default=500)
    parser.add_argument("--no-tls-verify", action="store_true")
    parser.add_argument("--hec-url",      default=None)
    parser.add_argument("--hec-token",    default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s | %(levelname)s | %(message)s")

    url   = args.hec_url   or SPLUNK_HEC_URL
    token = args.hec_token or SPLUNK_HEC_TOKEN

    if args.test:
        result = test_connectivity(url, token)
        print(json.dumps(result, indent=2))
    elif args.push_latest:
        result = push_feed(url, token, args.severity, args.limit, not args.no_tls_verify)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
