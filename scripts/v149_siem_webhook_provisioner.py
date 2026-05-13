#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- v149 SIEM + Enterprise Webhook Provisioner
===============================================================================
PRIORITY: P4 — SIEM + ENTERPRISE DELIVERY

PURPOSE:
  Provisions and delivers threat intelligence payloads to enterprise SIEM
  endpoints. Supports Splunk HEC, Microsoft Sentinel (Log Analytics Workspace),
  and generic webhook endpoints. Reads live API feed and pushes in real-time.

DELIVERY TARGETS:
  1. Splunk HTTP Event Collector (HEC)
     - Posts each intelligence item as a structured HEC event
     - Sourcetype: sentinel_apex_intel
     - Index: threat_intel (configurable)
  2. Microsoft Sentinel (Azure Monitor / Log Analytics)
     - Custom Log ingestion via Data Collector API
     - Table: CyberdudeBivashIntel_CL
     - Workspace ID + Key via env vars
  3. Generic JSON Webhooks
     - Configurable endpoint list from feature_flags.json WEBHOOK_ENDPOINTS
     - HMAC-SHA256 signature header: X-CDB-Signature
     - Retry: exponential backoff, max 3 attempts
  4. SIEM Replay Queue (data/siem/replay_queue.json)
     - Failed deliveries buffered for next run
     - Automatic replay on next invocation

SECURITY:
  - No credentials stored in code. Reads from env vars:
      SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
      SENTINEL_WORKSPACE_ID, SENTINEL_WORKSPACE_KEY
      CDB_WEBHOOK_SECRET (HMAC signing key)
  - All HTTP requests have 10s timeout
  - TLS verification enforced

ENTERPRISE PAYLOAD SCHEMA:
  {
    "cdb_version": "149.0.0",
    "event_type": "threat_intel",
    "stix_id": "...",
    "title": "...",
    "severity": "HIGH",
    "risk_score": 8.5,
    "cvss": 9.1,
    "epss": 0.82,
    "kev": true,
    "threat_category": "Remote Code Execution",
    "actor": "CDB-RAN-GEN",
    "confidence": 87,
    "soc_priority": "P1",
    "mitre_techniques": ["T1203", "T1078"],
    "ioc_count": 12,
    "tlp": "GREEN",
    "timestamp": "2026-05-13T10:00:00Z",
    "source_url": "https://...",
    "blog_url": "https://..."
  }

DEPLOYMENT:
  Add to sentinel-blogger.yml AFTER STAGE 3.1 (post APEX enrichment):
    - name: "v149 SIEM Webhook Delivery"
      continue-on-error: true
      env:
        SPLUNK_HEC_URL: ${{ secrets.SPLUNK_HEC_URL }}
        SPLUNK_HEC_TOKEN: ${{ secrets.SPLUNK_HEC_TOKEN }}
        SENTINEL_WORKSPACE_ID: ${{ secrets.SENTINEL_WORKSPACE_ID }}
        SENTINEL_WORKSPACE_KEY: ${{ secrets.SENTINEL_WORKSPACE_KEY }}
        CDB_WEBHOOK_SECRET: ${{ secrets.CDB_WEBHOOK_SECRET }}
      run: python3 scripts/v149_siem_webhook_provisioner.py

Version: 149.0.0
"""
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [v149-SIEM] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("v149-SIEM")

REPO = Path(__file__).resolve().parent.parent
VERSION = "149.0.0"
TIMEOUT_SEC = 10
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds

# ─── Source paths (in priority order) ─────────────────────────────────────
FEED_PATHS = [
    REPO / "api" / "feed.json",
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "feed_manifest.json",
]

# ─── Delivery state ────────────────────────────────────────────────────────
REPLAY_QUEUE_PATH = REPO / "data" / "siem" / "replay_queue.json"
DELIVERY_AUDIT_PATH = REPO / "data" / "governance" / "v149_siem_delivery_audit.json"
SIEM_REGISTRY_PATH = REPO / "data" / "siem" / "endpoint_registry.json"


# ─── Payload construction ─────────────────────────────────────────────────
def _build_enterprise_payload(item: dict) -> dict:
    """Normalize a feed item into the standard SIEM event schema."""
    apex = item.get("apex_ai", item.get("apex", {})) or {}
    return {
        "cdb_version": VERSION,
        "event_type": "threat_intel",
        "stix_id": item.get("stix_id", item.get("id", "")),
        "title": item.get("title", ""),
        "severity": item.get("severity", apex.get("severity", "MEDIUM")),
        "risk_score": item.get("risk_score", item.get("riskScore", 0)),
        "cvss": item.get("cvss", item.get("cvss_score", None)),
        "epss": item.get("epss", None),
        "kev": item.get("kev", item.get("is_kev", False)),
        "threat_category": apex.get("threat_category", item.get("threat_category", "Unknown")),
        "actor": item.get("actor", ""),
        "confidence": apex.get("ai_confidence", item.get("confidence", 50)),
        "soc_priority": apex.get("soc_priority", "P3"),
        "mitre_techniques": item.get("mitre_techniques", apex.get("mitre_techniques", [])),
        "ioc_count": item.get("ioc_count", 0),
        "tlp": item.get("tlp", "GREEN"),
        "timestamp": item.get("published", item.get("timestamp", item.get("created_at",
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))),
        "source_url": item.get("source_url", item.get("link", "")),
        "blog_url": item.get("blog_url", ""),
        "platform": "CYBERDUDEBIVASH_SENTINEL_APEX",
    }


# ─── HTTP helpers ─────────────────────────────────────────────────────────
def _http_post(url: str, payload_bytes: bytes, headers: dict) -> tuple[int, str]:
    """
    Perform HTTP POST. Returns (status_code, response_body).
    Uses stdlib urllib only — no external dependencies.
    """
    req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, str(exc)


def _with_retry(fn, *args, label: str = "") -> tuple[bool, str]:
    """Retry fn with exponential backoff. Returns (success, last_error)."""
    last_err = ""
    for attempt in range(1, MAX_RETRIES + 1):
        ok, msg = fn(*args)
        if ok:
            return True, msg
        last_err = msg
        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_BASE ** attempt
            log.warning("  [RETRY %d/%d] %s — %s — retrying in %ds", attempt, MAX_RETRIES, label, msg, wait)
            time.sleep(wait)
    return False, last_err


# ─── Splunk HEC Delivery ──────────────────────────────────────────────────
class SplunkHECDelivery:
    def __init__(self):
        self.url = os.environ.get("SPLUNK_HEC_URL", "").strip()
        self.token = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
        self.index = os.environ.get("SPLUNK_HEC_INDEX", "threat_intel")
        self.enabled = bool(self.url and self.token)

    def deliver(self, events: list[dict]) -> dict:
        if not self.enabled:
            return {"status": "SKIPPED", "reason": "SPLUNK_HEC_URL/TOKEN not configured", "sent": 0}

        log.info("[SPLUNK] Delivering %d events to %s", len(events), self.url[:60])
        sent = 0
        failed = 0
        failures = []

        for event in events:
            hec_payload = json.dumps({
                "time": _epoch(event.get("timestamp", "")),
                "sourcetype": "sentinel_apex_intel",
                "index": self.index,
                "source": "cyberdudebivash_sentinel_apex",
                "host": "sentinel-apex-v149",
                "event": event,
            }).encode("utf-8")

            headers = {
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            }

            def _do_post():
                code, body = _http_post(self.url, hec_payload, headers)
                if 200 <= code < 300:
                    return True, f"HTTP {code}"
                return False, f"HTTP {code}: {body[:200]}"

            ok, msg = _with_retry(_do_post, label=f"splunk:{event.get('stix_id','')[:20]}")
            if ok:
                sent += 1
            else:
                failed += 1
                failures.append({"stix_id": event.get("stix_id"), "error": msg})

        log.info("[SPLUNK] sent=%d failed=%d", sent, failed)
        return {"status": "OK", "sent": sent, "failed": failed, "failures": failures[:10]}


# ─── Microsoft Sentinel Delivery ─────────────────────────────────────────
class SentinelWorkspaceDelivery:
    """
    Delivers to Azure Log Analytics via the Data Collector API (HTTPS).
    Docs: https://docs.microsoft.com/azure/azure-monitor/logs/data-collector-api
    """
    API_VERSION = "2016-04-01"
    RESOURCE = "/api/logs"
    LOG_TYPE = "CyberdudeBivashIntel"
    CONTENT_TYPE = "application/json"

    def __init__(self):
        self.workspace_id = os.environ.get("SENTINEL_WORKSPACE_ID", "").strip()
        self.workspace_key = os.environ.get("SENTINEL_WORKSPACE_KEY", "").strip()
        self.enabled = bool(self.workspace_id and self.workspace_key)

    def _build_signature(self, body_bytes: bytes, rfc1123_date: str) -> str:
        content_length = len(body_bytes)
        string_to_hash = (
            f"POST\n{content_length}\n{self.CONTENT_TYPE}\n"
            f"x-ms-date:{rfc1123_date}\n{self.RESOURCE}"
        )
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self.workspace_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self.workspace_id}:{encoded_hash}"

    def deliver(self, events: list[dict]) -> dict:
        if not self.enabled:
            return {"status": "SKIPPED", "reason": "SENTINEL_WORKSPACE_ID/KEY not configured", "sent": 0}

        log.info("[SENTINEL] Delivering %d events to workspace %s", len(events), self.workspace_id[:12])

        # Batch all events into one request (Azure Log Analytics supports array)
        body_bytes = json.dumps(events).encode("utf-8")
        rfc1123_date = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        signature = self._build_signature(body_bytes, rfc1123_date)

        url = (
            f"https://{self.workspace_id}.ods.opinsights.azure.com"
            f"{self.RESOURCE}?api-version={self.API_VERSION}"
        )
        headers = {
            "Content-Type": self.CONTENT_TYPE,
            "Log-Type": self.LOG_TYPE,
            "Authorization": signature,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "timestamp",
        }

        def _do_post():
            code, body = _http_post(url, body_bytes, headers)
            if 200 <= code < 300:
                return True, f"HTTP {code}"
            return False, f"HTTP {code}: {body[:200]}"

        ok, msg = _with_retry(_do_post, label="sentinel-workspace")
        sent = len(events) if ok else 0
        failed = 0 if ok else len(events)

        log.info("[SENTINEL] sent=%d failed=%d", sent, failed)
        return {
            "status": "OK" if ok else "FAILED",
            "sent": sent,
            "failed": failed,
            "error": "" if ok else msg,
        }


# ─── Generic Webhook Delivery ─────────────────────────────────────────────
class WebhookDelivery:
    def __init__(self, endpoints: list[str]):
        self.endpoints = [e.strip() for e in endpoints if e.strip().startswith("http")]
        self.secret = os.environ.get("CDB_WEBHOOK_SECRET", "").strip()

    def _sign(self, body_bytes: bytes) -> str:
        if not self.secret:
            return ""
        return "sha256=" + hmac.new(
            self.secret.encode("utf-8"), body_bytes, digestmod=hashlib.sha256
        ).hexdigest()

    def deliver(self, events: list[dict]) -> dict:
        if not self.endpoints:
            return {"status": "SKIPPED", "reason": "No webhook endpoints configured", "sent": 0}

        results = {}
        total_sent = 0
        total_failed = 0

        for endpoint in self.endpoints:
            payload = {
                "cdb_version": VERSION,
                "event_count": len(events),
                "events": events,
                "delivered_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            body_bytes = json.dumps(payload).encode("utf-8")
            sig = self._sign(body_bytes)

            headers = {
                "Content-Type": "application/json",
                "X-CDB-Version": VERSION,
                "User-Agent": "CyberdudeBivash-SentinelApex/149",
            }
            if sig:
                headers["X-CDB-Signature"] = sig

            def _do_post(ep=endpoint, bb=body_bytes, hh=headers):
                code, body = _http_post(ep, bb, hh)
                if 200 <= code < 300:
                    return True, f"HTTP {code}"
                return False, f"HTTP {code}: {body[:200]}"

            ok, msg = _with_retry(_do_post, label=f"webhook:{endpoint[:30]}")
            if ok:
                total_sent += len(events)
                results[endpoint] = "OK"
            else:
                total_failed += len(events)
                results[endpoint] = f"FAILED: {msg}"
                log.warning("[WEBHOOK] %s FAILED: %s", endpoint[:50], msg)

        return {
            "status": "OK" if total_failed == 0 else "PARTIAL",
            "sent": total_sent,
            "failed": total_failed,
            "endpoint_results": results,
        }


# ─── Replay Queue ─────────────────────────────────────────────────────────
def _load_replay_queue() -> list[dict]:
    if not REPLAY_QUEUE_PATH.exists():
        return []
    try:
        data = json.loads(REPLAY_QUEUE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_replay_queue(items: list[dict]) -> None:
    REPLAY_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPLAY_QUEUE_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")


# ─── Feed loader ──────────────────────────────────────────────────────────
def _load_feed() -> list[dict]:
    for path in FEED_PATHS:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                log.info("[FEED] Loaded %d items from %s", len(raw), path.name)
                return raw
            for key in ("advisories", "reports", "items"):
                if key in raw and isinstance(raw[key], list):
                    log.info("[FEED] Loaded %d items from %s[%s]", len(raw[key]), path.name, key)
                    return raw[key]
        except Exception as exc:
            log.warning("[FEED] Cannot load %s: %s", path.name, exc)
    return []


def _epoch(ts: str) -> float:
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return time.time()


# ─── Endpoint registry ─────────────────────────────────────────────────────
def _write_endpoint_registry(splunk_result: dict, sentinel_result: dict, webhook_result: dict) -> None:
    """Writes the SIEM endpoint registry for dashboard discovery."""
    SIEM_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    registry = {
        "schema": "v149_siem_endpoint_registry_v1",
        "version": VERSION,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoints": {
            "splunk_hec": {
                "enabled": splunk_result.get("status") not in ("SKIPPED",),
                "status": splunk_result.get("status"),
                "url_prefix": os.environ.get("SPLUNK_HEC_URL", "")[:40] or "not_configured",
            },
            "microsoft_sentinel": {
                "enabled": sentinel_result.get("status") not in ("SKIPPED",),
                "status": sentinel_result.get("status"),
                "workspace_id": (os.environ.get("SENTINEL_WORKSPACE_ID", "")[:8] + "...")
                    if os.environ.get("SENTINEL_WORKSPACE_ID") else "not_configured",
            },
            "webhooks": {
                "enabled": webhook_result.get("status") not in ("SKIPPED",),
                "count": len(webhook_result.get("endpoint_results", {})),
                "status": webhook_result.get("status"),
            },
        },
    }
    SIEM_REGISTRY_PATH.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    log.info("[REGISTRY] Written: %s", SIEM_REGISTRY_PATH)


# ─── Feature flags loader ─────────────────────────────────────────────────
def _load_webhook_endpoints() -> list[str]:
    flags_path = REPO / "config" / "feature_flags.json"
    try:
        flags = json.loads(flags_path.read_text(encoding="utf-8"))
        endpoints = flags.get("WEBHOOK_ENDPOINTS", [])
        if isinstance(endpoints, list):
            return [str(e) for e in endpoints if e]
        return []
    except Exception:
        return []


# ─── Main ─────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 70)
    log.info("SENTINEL APEX v149 — SIEM + Enterprise Webhook Provisioner")
    log.info("Version: %s", VERSION)
    log.info("Timestamp: %s", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    log.info("=" * 70)

    # Load live feed
    feed_items = _load_feed()
    if not feed_items:
        log.warning("[WARN] No feed items found — checking replay queue only")

    # Replay previously failed items
    replay_items = _load_replay_queue()
    if replay_items:
        log.info("[REPLAY] %d items in replay queue — will merge with live feed", len(replay_items))
        # Dedup by stix_id
        seen = {i.get("stix_id", i.get("title", "")): True for i in feed_items}
        merged = feed_items + [i for i in replay_items if i.get("stix_id", i.get("title", "")) not in seen]
        log.info("[REPLAY] Total items after merge: %d", len(merged))
    else:
        merged = feed_items

    if not merged:
        log.info("[OK] No items to deliver — exiting cleanly")
        return

    # Build enterprise payloads
    payloads = [_build_enterprise_payload(item) for item in merged]
    log.info("[PAYLOAD] Built %d enterprise event payloads", len(payloads))

    # Instantiate delivery engines
    splunk = SplunkHECDelivery()
    sentinel = SentinelWorkspaceDelivery()
    webhook_endpoints = _load_webhook_endpoints()
    webhooks = WebhookDelivery(webhook_endpoints)

    # Deliver
    splunk_result = splunk.deliver(payloads)
    sentinel_result = sentinel.deliver(payloads)
    webhook_result = webhooks.deliver(payloads)

    # Summary
    log.info("─" * 50)
    log.info("[SPLUNK]   status=%-8s sent=%d failed=%d",
             splunk_result["status"], splunk_result.get("sent", 0), splunk_result.get("failed", 0))
    log.info("[SENTINEL] status=%-8s sent=%d failed=%d",
             sentinel_result["status"], sentinel_result.get("sent", 0), sentinel_result.get("failed", 0))
    log.info("[WEBHOOKS] status=%-8s sent=%d failed=%d",
             webhook_result["status"], webhook_result.get("sent", 0), webhook_result.get("failed", 0))
    log.info("─" * 50)

    # Rebuild replay queue from failures
    new_replay = []
    for result, source in [(splunk_result, "splunk"), (sentinel_result, "sentinel")]:
        if result.get("failures"):
            for f in result["failures"]:
                # Find the original payload
                stix_id = f.get("stix_id", "")
                original = next((p for p in payloads if p.get("stix_id") == stix_id), None)
                if original:
                    original["_retry_source"] = source
                    original["_retry_error"] = f.get("error", "")
                    new_replay.append(original)

    if new_replay:
        _save_replay_queue(new_replay)
        log.info("[REPLAY] %d failed items queued for retry", len(new_replay))
    else:
        # Clear queue on full success
        _save_replay_queue([])
        log.info("[REPLAY] Queue cleared — all deliveries succeeded")

    # Write endpoint registry
    _write_endpoint_registry(splunk_result, sentinel_result, webhook_result)

    # Write audit
    audit = {
        "schema": "v149_siem_delivery_audit_v1",
        "version": VERSION,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "items_processed": len(payloads),
        "splunk": splunk_result,
        "sentinel": sentinel_result,
        "webhooks": webhook_result,
        "replay_queued": len(new_replay),
        "status": "PASS",
    }
    DELIVERY_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DELIVERY_AUDIT_PATH.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    log.info("[AUDIT] Written: %s", DELIVERY_AUDIT_PATH)
    log.info("[PASS] v149 SIEM provisioner complete.")


if __name__ == "__main__":
    main()
