#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Live Alert System v1.0
========================================================
Real-time threat alert delivery via Server-Sent Events (SSE) with
polling fallback. Zero external dependencies.

Alert Types:
  CRITICAL  → immediate popup + sound trigger (risk ≥ 9.0 or severity=CRITICAL+KEV)
  HIGH      → banner notification (risk ≥ 7.5 or severity=HIGH + new)
  MEDIUM    → feed update badge (risk ≥ 5.0)
  SYSTEM    → platform events (engine run complete, new manifest detected)

Endpoints:
  GET  /api/v1/alerts/stream  — SSE stream (persistent connection)
  GET  /api/v1/alerts/poll    — HTTP polling fallback (returns new alerts since cursor)
  GET  /api/v1/alerts/latest  — Last N alerts (no auth required)
  POST /api/v1/alerts/dismiss — Mark alert(s) dismissed
  GET  /api/v1/alerts/health  — Alert subsystem health
"""
from __future__ import annotations

import asyncio
import json
import time
import hashlib
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, AsyncIterator

from fastapi import APIRouter, Query, Header, Request
from fastapi.responses import StreamingResponse, JSONResponse

# ── Logging ────────────────────────────────────────────────────────────────
logger = logging.getLogger("APEX-Alerts")

# ── Constants ──────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent.parent
MANIFEST_PATH  = BASE_DIR / "data" / "stix" / "feed_manifest.json"
ALERTS_DIR     = BASE_DIR / "data" / "alerts"
ALERTS_DIR.mkdir(parents=True, exist_ok=True)

MAX_QUEUE      = 500          # max alerts kept in memory ring buffer
POLL_INTERVAL  = 30           # seconds between manifest re-scans
SSE_KEEPALIVE  = 25           # seconds between SSE keepalive pings
SSE_TIMEOUT    = 300          # max SSE connection lifetime (seconds)

# ── Alert ring buffer ─────────────────────────────────────────────────────
_alert_queue:   Deque[Dict]  = deque(maxlen=MAX_QUEUE)
_queue_lock     = threading.Lock()
_last_manifest_hash: str     = ""
_alert_seq:     int          = 0   # monotonic sequence counter

# ── SSE subscriber registry ───────────────────────────────────────────────
# key = client_id, value = asyncio.Queue
_sse_subscribers: Dict[str, asyncio.Queue] = {}
_sse_lock = threading.Lock()

# ──────────────────────────────────────────────────────────────────────────
# ALERT FACTORY
# ──────────────────────────────────────────────────────────────────────────

def _make_alert(
    alert_type: str,          # CRITICAL | HIGH | MEDIUM | SYSTEM
    title: str,
    message: str,
    advisory: Optional[Dict] = None,
    tags: Optional[List[str]] = None,
) -> Dict:
    """Create a normalised alert envelope."""
    global _alert_seq
    _alert_seq += 1
    now  = datetime.now(timezone.utc)
    uid  = hashlib.sha256(f"{title}{now.isoformat()}{_alert_seq}".encode()).hexdigest()[:16]

    alert: Dict[str, Any] = {
        "id":         uid,
        "seq":        _alert_seq,
        "type":       alert_type,             # CRITICAL | HIGH | MEDIUM | SYSTEM
        "title":      title[:200],
        "message":    message[:500],
        "timestamp":  now.isoformat(),
        "epoch":      int(now.timestamp() * 1000),  # JS-compatible ms timestamp
        "dismissed":  False,
        "tags":       tags or [],
    }

    if advisory:
        alert["advisory"] = {
            "stix_id":     advisory.get("stix_id", ""),
            "severity":    advisory.get("severity", ""),
            "risk_score":  advisory.get("risk_score", 0),
            "cvss_score":  advisory.get("cvss_score"),
            "epss_score":  advisory.get("epss_score"),
            "kev_present": advisory.get("kev_present", False),
            "actor_tag":   advisory.get("actor_tag", "UNATTRIBUTED"),
            "threat_type": advisory.get("threat_type", ""),
            "blog_url":    advisory.get("blog_url", ""),
            "tlp_label":   advisory.get("tlp_label", "TLP:WHITE"),
        }

    return alert


# ──────────────────────────────────────────────────────────────────────────
# ALERT DISPATCHER
# ──────────────────────────────────────────────────────────────────────────

def _dispatch_alert(alert: Dict) -> None:
    """Push alert to ring buffer + all SSE subscribers."""
    with _queue_lock:
        _alert_queue.append(alert)

    # Persist to JSONL file for durability
    try:
        with open(ALERTS_DIR / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception:
        pass  # non-critical

    # Fan-out to all active SSE subscribers
    dead = []
    with _sse_lock:
        for cid, q in _sse_subscribers.items():
            try:
                q.put_nowait(alert)
            except asyncio.QueueFull:
                dead.append(cid)
            except Exception:
                dead.append(cid)
    for cid in dead:
        with _sse_lock:
            _sse_subscribers.pop(cid, None)


# ──────────────────────────────────────────────────────────────────────────
# MANIFEST SCANNER — background thread
# ──────────────────────────────────────────────────────────────────────────

def _classify_advisory(adv: Dict) -> Optional[str]:
    """Return alert type for an advisory, or None if below threshold."""
    sev   = adv.get("severity", "").upper()
    risk  = float(adv.get("risk_score", 0))
    kev   = bool(adv.get("kev_present", False))

    if sev == "CRITICAL" or risk >= 9.0 or (sev == "HIGH" and kev):
        return "CRITICAL"
    if risk >= 7.5 or sev == "HIGH":
        return "HIGH"
    if risk >= 5.0 or sev == "MEDIUM":
        return "MEDIUM"
    return None


def _load_manifest() -> List[Dict]:
    """Safe manifest loader — returns [] on any error."""
    try:
        if not MANIFEST_PATH.exists():
            return []
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _manifest_hash(manifest: List[Dict]) -> str:
    """Deterministic hash of manifest for change detection."""
    try:
        ids = sorted(str(a.get("stix_id", "")) for a in manifest)
        return hashlib.sha256("|".join(ids).encode()).hexdigest()
    except Exception:
        return ""


def _seen_ids() -> set:
    """Return set of stix_ids already dispatched (from ring buffer)."""
    with _queue_lock:
        seen = set()
        for a in _alert_queue:
            adv = a.get("advisory", {})
            if adv.get("stix_id"):
                seen.add(adv["stix_id"])
        return seen


def _scan_and_dispatch() -> int:
    """Scan manifest for new/upgraded alerts. Returns count dispatched."""
    global _last_manifest_hash

    manifest = _load_manifest()
    if not manifest:
        return 0

    new_hash = _manifest_hash(manifest)
    if new_hash == _last_manifest_hash:
        return 0   # no changes

    seen = _seen_ids()
    dispatched = 0

    for adv in manifest:
        sid = adv.get("stix_id", "")
        if not sid or sid in seen:
            continue

        atype = _classify_advisory(adv)
        if not atype:
            continue

        sev      = adv.get("severity", "UNKNOWN")
        risk     = adv.get("risk_score", 0)
        title    = adv.get("title", "Untitled Advisory")[:100]
        actor    = adv.get("actor_tag", "UNATTRIBUTED")
        kev_str  = " [KEV]" if adv.get("kev_present") else ""
        cvss_str = f" CVSS:{adv.get('cvss_score', '?')}" if adv.get("cvss_score") else ""

        alert = _make_alert(
            alert_type=atype,
            title=f"[{sev}] {title}{kev_str}",
            message=(
                f"Risk {risk}/10{cvss_str} · Actor: {actor} · "
                f"Type: {adv.get('threat_type', 'Unknown')} · "
                f"TLP: {adv.get('tlp_label', 'TLP:WHITE')}"
            ),
            advisory=adv,
            tags=[sev, adv.get("threat_type", ""), actor, "manifest"],
        )
        _dispatch_alert(alert)
        dispatched += 1

    if dispatched > 0 or new_hash != _last_manifest_hash:
        _last_manifest_hash = new_hash
        # Emit a SYSTEM alert summarising the scan
        if dispatched > 0:
            sys_alert = _make_alert(
                alert_type="SYSTEM",
                title="Manifest Updated",
                message=f"{dispatched} new alert(s) from manifest scan · {len(manifest)} total advisories",
                tags=["system", "manifest-update"],
            )
            _dispatch_alert(sys_alert)

    return dispatched


class _AlertScanner(threading.Thread):
    """Background daemon thread — polls manifest every POLL_INTERVAL seconds."""

    def __init__(self):
        super().__init__(daemon=True, name="AlertScanner")

    def run(self):
        logger.info("[AlertScanner] Background scanner started")
        # Initial scan on startup
        try:
            n = _scan_and_dispatch()
            logger.info(f"[AlertScanner] Startup scan: {n} alerts dispatched")
        except Exception as e:
            logger.warning(f"[AlertScanner] Startup scan error: {e}")

        while True:
            time.sleep(POLL_INTERVAL)
            try:
                _scan_and_dispatch()
            except Exception as e:
                logger.warning(f"[AlertScanner] Scan error: {e}")


# Start scanner on module load
_scanner = _AlertScanner()
_scanner.start()

# Emit a startup SYSTEM alert
_dispatch_alert(_make_alert(
    alert_type="SYSTEM",
    title="SENTINEL APEX Alert System Online",
    message="Real-time threat alert subsystem initialised · SSE + polling available",
    tags=["system", "startup"],
))


# ──────────────────────────────────────────────────────────────────────────
# FASTAPI ROUTER
# ──────────────────────────────────────────────────────────────────────────

alerts_router = APIRouter(prefix="/api/v1/alerts", tags=["Live Alerts"])


# ── GET /api/v1/alerts/latest ─────────────────────────────────────────────
@alerts_router.get("/latest")
async def get_latest_alerts(
    n:           int            = Query(default=20, ge=1, le=200),
    alert_type:  Optional[str]  = Query(default=None,
                                        description="CRITICAL | HIGH | MEDIUM | SYSTEM"),
    since_epoch: Optional[int]  = Query(default=None,
                                        description="Only alerts after this ms epoch"),
):
    """Return latest N alerts — no auth required. Used by dashboard polling."""
    with _queue_lock:
        alerts = list(_alert_queue)

    # newest first
    alerts = sorted(alerts, key=lambda a: a["seq"], reverse=True)

    if alert_type:
        alerts = [a for a in alerts if a["type"] == alert_type.upper()]

    if since_epoch is not None:
        alerts = [a for a in alerts if a["epoch"] > since_epoch]

    alerts = alerts[:n]
    return JSONResponse({
        "status":  "ok",
        "count":   len(alerts),
        "total":   len(_alert_queue),
        "data":    alerts,
    })


# ── GET /api/v1/alerts/poll ───────────────────────────────────────────────
@alerts_router.get("/poll")
async def poll_alerts(
    since_seq:   int           = Query(default=0, ge=0,
                                       description="Return only alerts with seq > this"),
    alert_type:  Optional[str] = Query(default=None),
    limit:       int           = Query(default=50, ge=1, le=200),
):
    """
    Polling fallback endpoint for clients that cannot use SSE.
    Client stores `last_seq` and passes it on each poll.
    Returns only NEW alerts (seq > since_seq).
    """
    with _queue_lock:
        alerts = [a for a in _alert_queue if a["seq"] > since_seq]

    if alert_type:
        alerts = [a for a in alerts if a["type"] == alert_type.upper()]

    alerts = sorted(alerts, key=lambda a: a["seq"])[:limit]
    last_seq = alerts[-1]["seq"] if alerts else since_seq

    return JSONResponse({
        "status":   "ok",
        "count":    len(alerts),
        "last_seq": last_seq,
        "data":     alerts,
        "poll_again_ms": POLL_INTERVAL * 1000,
    })


# ── GET /api/v1/alerts/stream  (SSE) ─────────────────────────────────────
@alerts_router.get("/stream")
async def alert_stream(request: Request):
    """
    Server-Sent Events stream. Client connects once and receives push alerts.

    Event format:
        data: {"id":"..","type":"CRITICAL","title":"..","message":".."}

    Clients reconnect using `Last-Event-ID` header if connection drops.
    Keepalive comment lines (``: ``) sent every SSE_KEEPALIVE seconds.
    """
    import uuid
    client_id = str(uuid.uuid4())[:12]

    # Per-client async queue (max 200 buffered events)
    client_q: asyncio.Queue = asyncio.Queue(maxsize=200)

    with _sse_lock:
        _sse_subscribers[client_id] = client_q

    logger.info(f"[SSE] Client {client_id} connected · {len(_sse_subscribers)} active")

    async def event_generator() -> AsyncIterator[str]:
        # Send last 10 alerts immediately on connect so client is not blank
        with _queue_lock:
            backlog = sorted(_alert_queue, key=lambda a: a["seq"])[-10:]
        for a in backlog:
            yield f"id: {a['seq']}\ndata: {json.dumps(a)}\n\n"

        start = time.time()
        try:
            while True:
                if time.time() - start > SSE_TIMEOUT:
                    yield "event: timeout\ndata: {\"msg\":\"reconnect\"}\n\n"
                    break

                # Check for client disconnect
                if await request.is_disconnected():
                    break

                try:
                    alert = await asyncio.wait_for(client_q.get(), timeout=SSE_KEEPALIVE)
                    yield f"id: {alert['seq']}\ndata: {json.dumps(alert)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield ": keepalive\n\n"

        finally:
            with _sse_lock:
                _sse_subscribers.pop(client_id, None)
            logger.info(f"[SSE] Client {client_id} disconnected · {len(_sse_subscribers)} active")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",     # disable nginx buffering
            "Connection":        "keep-alive",
        },
    )


# ── POST /api/v1/alerts/dismiss ───────────────────────────────────────────
@alerts_router.post("/dismiss")
async def dismiss_alerts(alert_ids: List[str]):
    """Mark one or more alerts as dismissed (client-side UX hint)."""
    dismissed = 0
    with _queue_lock:
        for a in _alert_queue:
            if a["id"] in alert_ids:
                a["dismissed"] = True
                dismissed += 1
    return JSONResponse({"status": "ok", "dismissed": dismissed})


# ── POST /api/v1/alerts/emit  (internal / admin use) ─────────────────────
@alerts_router.post("/emit", include_in_schema=False)
async def emit_alert(
    alert_type: str,
    title:      str,
    message:    str,
    x_admin_key: Optional[str] = Header(default=None),
):
    """
    Internal endpoint to manually emit an alert.
    Requires X-Admin-Key header matching ADMIN_SECRET env var.
    """
    import os
    admin_secret = os.environ.get("ADMIN_SECRET", "")
    if not admin_secret or x_admin_key != admin_secret:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Forbidden")

    atype = alert_type.upper()
    if atype not in ("CRITICAL", "HIGH", "MEDIUM", "SYSTEM"):
        from fastapi import HTTPException
        raise HTTPException(400, "alert_type must be CRITICAL|HIGH|MEDIUM|SYSTEM")

    alert = _make_alert(atype, title, message, tags=["manual"])
    _dispatch_alert(alert)
    return JSONResponse({"status": "ok", "alert_id": alert["id"], "seq": alert["seq"]})


# ── GET /api/v1/alerts/health ─────────────────────────────────────────────
@alerts_router.get("/health")
async def alerts_health():
    """Alert subsystem health — public."""
    with _queue_lock:
        total  = len(_alert_queue)
        by_type = {}
        for a in _alert_queue:
            t = a["type"]
            by_type[t] = by_type.get(t, 0) + 1

    with _sse_lock:
        sse_clients = len(_sse_subscribers)

    return JSONResponse({
        "status":         "ok",
        "version":        "v81.0",
        "subsystem":      "live-alerts",
        "queue_size":     total,
        "sse_clients":    sse_clients,
        "poll_interval_s": POLL_INTERVAL,
        "by_type":        by_type,
        "manifest_hash":  _last_manifest_hash[:12] + "..." if _last_manifest_hash else "none",
        "seq_counter":    _alert_seq,
        "generated":      datetime.now(timezone.utc).isoformat(),
    })


# ── Expose internal emit for other modules ────────────────────────────────
def emit_system_alert(title: str, message: str, tags: Optional[List[str]] = None) -> None:
    """Call from other modules to push a SYSTEM alert."""
    alert = _make_alert("SYSTEM", title, message, tags=tags or ["system"])
    _dispatch_alert(alert)


def emit_critical_alert(title: str, message: str, advisory: Optional[Dict] = None) -> None:
    """Call from other modules to push a CRITICAL alert."""
    alert = _make_alert("CRITICAL", title, message, advisory=advisory, tags=["auto"])
    _dispatch_alert(alert)
