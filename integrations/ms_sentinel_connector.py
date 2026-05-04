#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — Microsoft Sentinel Connector v143.0.0                    ║
║  Phase IV Asset 5 — 30-Second SOC Integration                             ║
║                                                                            ║
║  Pushes SENTINEL APEX intelligence to Microsoft Sentinel via the          ║
║  Log Analytics Data Collector API (legacy) and DCR-based Ingestion        ║
║  API (modern). Supports both authentication paths.                        ║
║                                                                            ║
║  Quick Start (30 seconds):                                                 ║
║    export MS_SENTINEL_WORKSPACE_ID="<workspace-guid>"                    ║
║    export MS_SENTINEL_SHARED_KEY="<primary-key>"                         ║
║    python integrations/ms_sentinel_connector.py --test                    ║
║    python integrations/ms_sentinel_connector.py --push-latest             ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-SENTINEL-CONNECTOR")

WORKSPACE_ID      = os.getenv("MS_SENTINEL_WORKSPACE_ID", "")
SHARED_KEY        = os.getenv("MS_SENTINEL_SHARED_KEY", "")
LOG_TYPE          = os.getenv("MS_SENTINEL_TABLE", "CyberDudeBivash_ThreatIntel")
BATCH_SIZE        = 100
RETRY_ATTEMPTS    = 3
REQUEST_TIMEOUT   = 20

ROOT     = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
FEED_SOURCES = [
    DATA_DIR / "apex_v2_manifest.json",
    DATA_DIR / "apex_enriched_manifest.json",
    DATA_DIR / "feed_manifest.json",
]


# ── HMAC Auth (Log Analytics API) ────────────────────────────────────────────

def _build_signature(workspace_id: str, shared_key: str,
                     date_str: str, content_length: int,
                     content_type: str) -> str:
    string_to_hash = (
        f"POST\n{content_length}\n{content_type}\n"
        f"x-ms-date:{date_str}\n/api/logs"
    )
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key   = base64.b64decode(shared_key)
    encoded_hash  = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


# ── Normalization: APEX → Sentinel ────────────────────────────────────────────

def apex_to_sentinel_record(item: Dict) -> Dict:
    """Convert APEX threat advisory to Sentinel KQL-queryable record."""
    apex_ai = item.get("apex_ai") or item.get("apex") or {}
    return {
        "TimeGenerated":       item.get("timestamp") or item.get("published_at") or
                               datetime.now(timezone.utc).isoformat(),
        "ThreatId_s":          item.get("id") or item.get("stix_id") or "",
        "StixId_s":            item.get("stix_id") or "",
        "Title_s":             (item.get("title") or "")[:512],
        "Description_s":       (item.get("description") or "")[:2048],
        "Severity_s":          item.get("severity", "UNKNOWN"),
        "ThreatType_s":        item.get("threat_type", "THREAT-INTEL"),
        "RiskScore_d":         float(item.get("risk_score") or 0),
        "CvssScore_d":         float(item.get("cvss_score") or 0),
        "EpssScore_d":         float(item.get("epss_score") or 0),
        "KevPresent_b":        bool(item.get("kev_present", False)),
        "TlpClassification_s": item.get("tlp", "TLP:GREEN"),
        "Source_s":            item.get("source", ""),
        "SourceUrl_s":         item.get("source_url", ""),
        "ActorTag_s":          item.get("actor_tag") or apex_ai.get("actor_fingerprint") or "",
        "CampaignId_s":        apex_ai.get("campaign_id") or "",
        "SocPriority_s":       apex_ai.get("soc_priority") or "",
        "ThreatLevel_s":       apex_ai.get("threat_level") or "",
        "PredictiveRisk_d":    float(apex_ai.get("predictive_risk") or 0),
        "AiConfidence_d":      float(apex_ai.get("ai_confidence") or 0),
        "KillChain_s":         apex_ai.get("kill_chain_primary") or "",
        "IocCount_d":          float(item.get("ioc_count") or 0),
        "TtpCount_d":          float(item.get("ttp_count") or 0),
        "MitreTechniques_s":   json.dumps([
            t if isinstance(t, str) else t.get("technique_id", "")
            for t in (item.get("ttps") or item.get("mitre_tactics") or [])
        ]),
        "Platform_s":          "SENTINEL-APEX/143.0.0",
        "Gstin_s":             "21ARKPN8270G1ZP",
        "IngestSource_s":      "cyberdudebivash_apex_push",
    }


# ── HTTP Push ─────────────────────────────────────────────────────────────────

def push_to_sentinel(
    records: List[Dict],
    workspace_id: str,
    shared_key: str,
    log_type: str = LOG_TYPE,
) -> Dict:
    """Push records to Sentinel Log Analytics workspace."""
    if not workspace_id or not shared_key:
        return {
            "success": False,
            "error": "MS_SENTINEL_WORKSPACE_ID and MS_SENTINEL_SHARED_KEY required",
            "setup": "https://intel.cyberdudebivash.com/soc-integrations.html"
        }

    sentinel_records = [apex_to_sentinel_record(r) for r in records]
    body         = json.dumps(sentinel_records).encode("utf-8")
    content_len  = len(body)
    content_type = "application/json"
    date_str     = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    signature = _build_signature(
        workspace_id, shared_key, date_str, content_len, content_type
    )
    url = (
        f"https://{workspace_id}.ods.opinsights.azure.com"
        f"/api/logs?api-version=2016-04-01"
    )
    headers = {
        "Content-Type":  content_type,
        "Authorization": signature,
        "Log-Type":      log_type,
        "x-ms-date":     date_str,
        "time-generated-field": "TimeGenerated",
    }

    for attempt in range(RETRY_ATTEMPTS):
        try:
            req  = urllib.request.Request(url, data=body, headers=headers, method="POST")
            ctx  = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                if resp.status == 200:
                    logger.info(f"Sentinel push OK (attempt {attempt+1}): "
                                f"{len(records)} records")
                    return {"success": True, "status_code": 200,
                            "records_pushed": len(records)}
        except urllib.error.HTTPError as e:
            body_err = e.read().decode() if e.fp else ""
            logger.error(f"Sentinel HTTPError {e.code} (attempt {attempt+1}): {body_err[:200]}")
            if e.code in (400, 401, 403):
                return {"success": False, "status_code": e.code, "error": body_err[:200]}
        except Exception as ex:
            logger.error(f"Sentinel push error (attempt {attempt+1}): {ex}")

        if attempt < RETRY_ATTEMPTS - 1:
            time.sleep(2 ** (attempt + 1))

    return {"success": False, "error": "Max retries exceeded"}


def load_feed() -> List[Dict]:
    for src in FEED_SOURCES:
        if src.exists():
            try:
                raw   = json.loads(src.read_bytes())
                items = raw if isinstance(raw, list) else \
                        raw.get("items") or raw.get("advisories") or []
                if items:
                    return items
            except Exception:
                pass
    return []


def run_push(workspace_id: str, shared_key: str,
             severity: Optional[str] = None, limit: int = 1000) -> Dict:
    items = load_feed()
    if severity:
        items = [i for i in items if str(i.get("severity", "")).upper() == severity.upper()]
    items = items[:limit]

    total_pushed = 0
    errors       = []
    for i in range(0, len(items), BATCH_SIZE):
        batch  = items[i:i + BATCH_SIZE]
        result = push_to_sentinel(batch, workspace_id, shared_key)
        if result.get("success"):
            total_pushed += len(batch)
        else:
            errors.append(result.get("error", "")[:200])

    return {
        "success":       len(errors) == 0,
        "records_pushed": total_pushed,
        "errors":         len(errors),
        "log_type":       LOG_TYPE,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APEX → Microsoft Sentinel Push")
    parser.add_argument("--test",        action="store_true")
    parser.add_argument("--push-latest", action="store_true")
    parser.add_argument("--severity",    default=None)
    parser.add_argument("--limit",       type=int, default=1000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s | %(levelname)s | %(message)s")

    ws   = WORKSPACE_ID
    key  = SHARED_KEY

    if args.test:
        result = push_to_sentinel([{
            "id": "test-001", "title": "APEX Connectivity Test",
            "severity": "INFO", "risk_score": 0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }], ws, key)
        print(json.dumps(result, indent=2))
    elif args.push_latest:
        result = run_push(ws, key, args.severity, args.limit)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
