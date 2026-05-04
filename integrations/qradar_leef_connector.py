#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — IBM QRadar LEEF Connector v143.0.0                       ║
║  Phase IV Asset 5 — 30-Second SOC Integration                             ║
║                                                                            ║
║  Pushes SENTINEL APEX threat intelligence to IBM QRadar via:              ║
║    • LEEF 2.0 syslog format (UDP/TCP)                                     ║
║    • QRadar REST API (Reference Tables / Offense Enrichment)              ║
║                                                                            ║
║  Quick Start (30 seconds):                                                 ║
║    export QRADAR_HOST="qradar.acme.com"                                   ║
║    export QRADAR_API_TOKEN="<sec-token>"                                  ║
║    python integrations/qradar_leef_connector.py --test                    ║
║    python integrations/qradar_leef_connector.py --push-latest             ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-QRADAR-LEEF")

QRADAR_HOST      = os.getenv("QRADAR_HOST", "")
QRADAR_API_TOKEN = os.getenv("QRADAR_API_TOKEN", "")
QRADAR_SYSLOG_PORT = int(os.getenv("QRADAR_SYSLOG_PORT", "514"))
QRADAR_API_PORT  = int(os.getenv("QRADAR_API_PORT", "443"))
QRADAR_VERIFY_SSL = os.getenv("QRADAR_VERIFY_SSL", "true").lower() == "true"

LEEF_VERSION    = "LEEF:2.0"
LEEF_VENDOR     = "CyberDudeBivash"
LEEF_PRODUCT    = "SentinelAPEX"
LEEF_VER        = "143.0.0"

BATCH_SIZE      = 50
RETRY_ATTEMPTS  = 3

ROOT     = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
FEED_SOURCES = [
    DATA_DIR / "apex_v2_manifest.json",
    DATA_DIR / "apex_enriched_manifest.json",
    DATA_DIR / "feed_manifest.json",
]


# ── LEEF 2.0 Formatter ───────────────────────────────────────────────────────

def _leef_escape(value: str) -> str:
    """Escape special chars for LEEF key=value pairs."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|") \
                     .replace("\t", " ").replace("\n", " ").replace("\r", "")


def apex_to_leef(item: Dict) -> str:
    """
    Convert APEX threat advisory to LEEF 2.0 syslog string.
    Format: LEEF:2.0|Vendor|Product|Version|EventID\tkey=value\t...
    """
    apex_ai = item.get("apex_ai") or {}
    sev_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}
    sev     = str(item.get("severity", "INFO")).upper()
    sev_num = sev_map.get(sev, 1)

    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    event_id = _leef_escape(item.get("id") or item.get("stix_id") or "APEX-UNKNOWN")

    header = f"{LEEF_VERSION}|{LEEF_VENDOR}|{LEEF_PRODUCT}|{LEEF_VER}|{event_id}"

    attrs = {
        "devTime":       datetime.now(timezone.utc).isoformat(),
        "sev":           sev_num,
        "cat":           _leef_escape(item.get("threat_type", "THREAT-INTEL")),
        "severity":      _leef_escape(sev),
        "msg":           _leef_escape((item.get("title") or "")[:256]),
        "description":   _leef_escape((item.get("description") or "")[:512]),
        "src":           "intel.cyberdudebivash.com",
        "threatId":      _leef_escape(event_id),
        "riskScore":     item.get("risk_score", 0),
        "cvssScore":     item.get("cvss_score") or 0,
        "epssScore":     item.get("epss_score") or 0,
        "kevPresent":    int(bool(item.get("kev_present", False))),
        "tlp":           _leef_escape(item.get("tlp", "TLP:GREEN")),
        "actor":         _leef_escape(
            item.get("actor_tag") or apex_ai.get("actor_fingerprint") or "UNKNOWN"
        ),
        "campaignId":    _leef_escape(apex_ai.get("campaign_id") or ""),
        "socPriority":   _leef_escape(apex_ai.get("soc_priority") or ""),
        "predictRisk":   apex_ai.get("predictive_risk") or 0,
        "iocCount":      item.get("ioc_count", 0),
        "ttpCount":      item.get("ttp_count", 0),
        "source":        _leef_escape(item.get("source") or ""),
        "sourceUrl":     _leef_escape(item.get("source_url") or ""),
        "platform":      "SENTINEL-APEX/143.0.0",
        "gstin":         "21ARKPN8270G1ZP",
    }

    attr_str = "\t".join(f"{k}={v}" for k, v in attrs.items())
    syslog_pri = "<14>"   # facility=1 (user), severity=6 (info)
    return f"{syslog_pri}{ts} sentinel-apex {header}\t{attr_str}"


# ── Syslog Push (UDP/TCP) ─────────────────────────────────────────────────────

def push_syslog_udp(leef_messages: List[str], host: str, port: int = 514) -> Dict:
    """Push LEEF messages via UDP syslog."""
    if not host:
        return {"success": False, "error": "QRADAR_HOST not configured"}
    sent = 0
    errors = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for msg in leef_messages:
            try:
                sock.sendto(msg.encode("utf-8"), (host, port))
                sent += 1
            except Exception as e:
                errors.append(str(e)[:100])
    return {"success": len(errors) == 0, "sent": sent, "errors": errors[:5], "proto": "udp"}


def push_syslog_tcp(leef_messages: List[str], host: str, port: int = 514,
                    use_tls: bool = False) -> Dict:
    """Push LEEF messages via TCP syslog (optionally TLS-wrapped)."""
    if not host:
        return {"success": False, "error": "QRADAR_HOST not configured"}
    sent   = 0
    errors = []
    try:
        raw_sock = socket.create_connection((host, port), timeout=15)
        if use_tls:
            ctx  = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        with sock:
            for msg in leef_messages:
                try:
                    sock.sendall((msg + "\n").encode("utf-8"))
                    sent += 1
                except Exception as e:
                    errors.append(str(e)[:100])
    except Exception as e:
        return {"success": False, "error": str(e), "proto": "tcp"}
    return {"success": len(errors) == 0, "sent": sent, "errors": errors[:5],
            "proto": "tcp+tls" if use_tls else "tcp"}


# ── QRadar REST API push (Reference Data) ────────────────────────────────────

def push_via_qradar_api(
    items: List[Dict],
    host: str,
    api_token: str,
    reference_table: str = "APEX_ThreatIntel",
) -> Dict:
    """
    Push IOC / threat data to QRadar Reference Tables via REST API.
    Enriches QRadar offenses with APEX intelligence.
    """
    if not host or not api_token:
        return {"success": False, "error": "QRADAR_HOST and QRADAR_API_TOKEN required"}

    url = f"https://{host}/api/reference_data/tables/{reference_table}"
    # Build bulk payload
    bulk_data = {}
    for item in items:
        threat_id = item.get("id") or item.get("stix_id") or ""
        if not threat_id:
            continue
        bulk_data[threat_id] = {
            "title":       (item.get("title") or "")[:255],
            "severity":    item.get("severity", "UNKNOWN"),
            "risk_score":  str(item.get("risk_score") or 0),
            "actor":       item.get("actor_tag") or "UNKNOWN",
            "source":      item.get("source") or "",
            "platform":    "SENTINEL-APEX/143.0.0",
        }

    payload = json.dumps({"data": bulk_data}).encode("utf-8")
    headers = {
        "SEC":             api_token,
        "Content-Type":    "application/json",
        "Accept":          "application/json",
        "Version":         "17.0",
        "X-APEX-Platform": "SENTINEL-APEX/143.0.0",
    }

    ctx = ssl.create_default_context()
    if not QRADAR_VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    for attempt in range(RETRY_ATTEMPTS):
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if resp.status in (200, 201, 204):
                    return {"success": True, "records": len(bulk_data), "table": reference_table}
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            logger.error(f"QRadar API error {e.code}: {body[:200]}")
            if e.code in (400, 401, 403):
                return {"success": False, "status_code": e.code, "error": body[:200]}
        except Exception as ex:
            logger.error(f"QRadar API error (attempt {attempt+1}): {ex}")
        if attempt < RETRY_ATTEMPTS - 1:
            time.sleep(2 ** (attempt + 1))

    return {"success": False, "error": "Max retries exceeded"}


# ── Main Pipeline ─────────────────────────────────────────────────────────────

def load_feed() -> List[Dict]:
    for src in FEED_SOURCES:
        if src.exists():
            try:
                raw = json.loads(src.read_bytes())
                items = raw if isinstance(raw, list) else \
                        raw.get("items") or raw.get("advisories") or []
                if items:
                    return items
            except Exception:
                pass
    return []


def run_push(host: str, api_token: str, use_syslog: bool = True,
             severity: Optional[str] = None, limit: int = 500) -> Dict:
    items = load_feed()
    if severity:
        items = [i for i in items if str(i.get("severity", "")).upper() == severity.upper()]
    items = items[:limit]

    results: Dict = {"total": len(items)}

    if use_syslog:
        leef_messages = [apex_to_leef(i) for i in items]
        syslog_result = push_syslog_udp(leef_messages, host, QRADAR_SYSLOG_PORT)
        results["syslog"] = syslog_result

    if api_token:
        api_result = push_via_qradar_api(items, host, api_token)
        results["api"] = api_result

    results["timestamp"] = datetime.now(timezone.utc).isoformat()
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APEX → IBM QRadar Push Connector")
    parser.add_argument("--test",        action="store_true")
    parser.add_argument("--push-latest", action="store_true")
    parser.add_argument("--syslog-only", action="store_true")
    parser.add_argument("--api-only",    action="store_true")
    parser.add_argument("--severity",    default=None)
    parser.add_argument("--limit",       type=int, default=500)
    parser.add_argument("--host",        default=None)
    parser.add_argument("--token",       default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s | %(levelname)s | %(message)s")

    host  = args.host  or QRADAR_HOST
    token = args.token or QRADAR_API_TOKEN

    if args.test:
        test_item = [{"id": "apex-test-001", "title": "QRadar Connectivity Test",
                      "severity": "INFO", "risk_score": 0}]
        result = push_via_qradar_api(test_item, host, token)
        print(json.dumps(result, indent=2))
    elif args.push_latest:
        result = run_push(
            host, token,
            use_syslog=not args.api_only,
            severity=args.severity,
            limit=args.limit
        )
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
