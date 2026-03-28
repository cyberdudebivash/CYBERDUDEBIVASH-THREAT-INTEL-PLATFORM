"""
CYBERDUDEBIVASH® SENTINEL APEX — Firewall Responder v1.0
=========================================================
SAFE MODE: Logs block actions + generates firewall rule commands.
           NEVER executes real OS/firewall commands directly.
LIVE MODE: POSTs IOCs to configured firewall API endpoint.
           Only activated via CDB_AUTO_RESPONSE_MODE=live

SAFETY GUARANTEES:
  - Default mode is SAFE (dry-run only)
  - No subprocess/os.system calls — zero system impact
  - All errors swallowed, never crashes pipeline
  - Idempotent: duplicate IPs skipped via block state

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-FIREWALL")

FIREWALL_API_URL  = os.environ.get("CDB_FIREWALL_API_URL", "")
FIREWALL_API_KEY  = os.environ.get("CDB_FIREWALL_API_KEY", "")
RESPONSE_MODE     = os.environ.get("CDB_AUTO_RESPONSE_MODE", "safe").lower()

BASE_DIR          = Path(__file__).resolve().parent.parent.parent
BLOCK_STATE_FILE  = BASE_DIR / "data" / "auto_response" / "blocked_ips.json"

# RFC 1918 + loopback — never block private/internal ranges
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.")


def _is_safe_to_block(ip: str) -> bool:
    """Reject private/loopback IPs. Only block routable public IPs."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not ip:
        return False
    for prefix in _PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return False
    # Basic format check — must look like an IPv4
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _load_block_state() -> Dict[str, str]:
    """Load previously blocked IPs. Returns {ip: iso_timestamp}."""
    try:
        if not BLOCK_STATE_FILE.exists():
            return {}
        with open(BLOCK_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_block_state(state: Dict[str, str]) -> None:
    """Persist block state atomically."""
    try:
        BLOCK_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(BLOCK_STATE_FILE) + ".tmp"
        raw = json.dumps(state, indent=2, ensure_ascii=False)
        with open(tmp, "wb") as f:
            f.write(raw.encode("utf-8"))
        os.replace(tmp, BLOCK_STATE_FILE)
    except Exception as e:
        logger.warning(f"[FIREWALL] Block state save failed (non-fatal): {e}")


def _live_block_ip(ip: str, reason: str) -> bool:
    """POST block request to configured firewall API. Only in LIVE mode."""
    if not FIREWALL_API_URL:
        logger.info(f"[FIREWALL] LIVE mode but no API URL configured — logging only")
        return True
    try:
        import requests
        resp = requests.post(
            FIREWALL_API_URL,
            json={"action": "block", "ip": ip, "reason": reason,
                  "source": "CDB-SENTINEL-APEX", "protocol": "ALL"},
            headers={
                "Content-Type": "application/json",
                "X-API-Key": FIREWALL_API_KEY,
                "X-Source": "CYBERDUDEBIVASH-SENTINEL-APEX",
            },
            timeout=8,
        )
        if resp.status_code in (200, 201, 202, 204):
            logger.info(f"[FIREWALL] LIVE BLOCK: {ip} — HTTP {resp.status_code}")
            return True
        else:
            logger.warning(f"[FIREWALL] Block API HTTP {resp.status_code} for {ip}")
            return False
    except Exception as e:
        logger.warning(f"[FIREWALL] Live block failed (non-fatal): {e}")
        return False


def block_malicious_ips(
    ips: List[str],
    reason: str = "",
    alert_id: str = "",
) -> Dict:
    """
    Block a list of malicious IPs via configured firewall.

    SAFE mode (default): Generates iptables/firewall commands, logs only.
    LIVE mode: POSTs to CDB_FIREWALL_API_URL.

    Args:
        ips:      List of IPv4 addresses to block.
        reason:   Human-readable block reason (advisory title).
        alert_id: Alert ID for correlation.

    Returns:
        {"blocked": [...], "skipped": [...], "mode": "safe"|"live"}
    """
    if not ips:
        return {"blocked": [], "skipped": [], "mode": RESPONSE_MODE}

    state   = _load_block_state()
    blocked = []
    skipped = []

    for ip in ips:
        ip = (ip or "").strip()

        # Safety filter
        if not _is_safe_to_block(ip):
            logger.debug(f"[FIREWALL] Skip non-routable/invalid: {ip}")
            skipped.append({"ip": ip, "reason": "private_or_invalid"})
            continue

        # Dedup — already blocked
        if ip in state:
            logger.debug(f"[FIREWALL] Already blocked: {ip}")
            skipped.append({"ip": ip, "reason": "already_blocked"})
            continue

        block_reason = f"CDB-APEX | {reason[:100]} | Alert: {alert_id}"

        if RESPONSE_MODE == "live":
            success = _live_block_ip(ip, block_reason)
        else:
            # SAFE MODE: generate commands, log only — zero system impact
            cmd_iptables = f"iptables -A INPUT -s {ip} -j DROP"
            cmd_windows  = f"netsh advfirewall firewall add rule name='CDB-BLOCK-{ip}' dir=in action=block remoteip={ip}"
            logger.info(
                f"[FIREWALL] [SAFE-MODE] WOULD BLOCK: {ip}\n"
                f"  Linux:   {cmd_iptables}\n"
                f"  Windows: {cmd_windows}\n"
                f"  Reason:  {block_reason}"
            )
            success = True  # Safe mode always "succeeds" (logged)

        if success:
            state[ip] = datetime.now(timezone.utc).isoformat()
            blocked.append({
                "ip":        ip,
                "mode":      RESPONSE_MODE,
                "reason":    block_reason,
                "blocked_at": state[ip],
            })

    _save_block_state(state)

    logger.info(
        f"[FIREWALL] Completed | mode={RESPONSE_MODE} | "
        f"blocked={len(blocked)} | skipped={len(skipped)}"
    )
    return {"blocked": blocked, "skipped": skipped, "mode": RESPONSE_MODE}
