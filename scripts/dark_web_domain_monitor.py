#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — Dark Web Domain Surveillance Engine v143.0.0              ║
║  Phase IV Asset 4 — Managed Service ($299/mo)                              ║
║                                                                            ║
║  Monitors up to 10 user-defined corporate domains across:                  ║
║    • Paste site aggregators (Pastebin, Ghostbin, etc.)                    ║
║    • Credential breach marketplaces                                        ║
║    • Stealer log feeds (RedLine, Vidar, Raccoon)                          ║
║    • Tor-indexed threat actor forums (via APEX dark web feeds)             ║
║    • CYBERDUDEBIVASH dark web intelligence pipeline                        ║
║                                                                            ║
║  Alerts: Real-time Telegram + Webhook push on credential leak detection    ║
║  SLA: < 15 minute alert latency for CRITICAL findings                      ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python scripts/dark_web_domain_monitor.py --domains cyberdudebivash.com acme.com
    python scripts/dark_web_domain_monitor.py --config data/darkweb/monitor_config.json
    python scripts/dark_web_domain_monitor.py --scan-once
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger("CDB-DARKWEB-MONITOR")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

ROOT              = Path(__file__).parent.parent
DATA_DIR          = ROOT / "data"
DARKWEB_DIR       = DATA_DIR / "darkweb" if (DATA_DIR / "darkweb").exists() \
                    else DATA_DIR / "omnishield"
ALERTS_DIR        = DATA_DIR / "alerts"
CONFIG_FILE       = DARKWEB_DIR / "monitor_config.json" if DARKWEB_DIR.exists() \
                    else DATA_DIR / "darkweb_monitor_config.json"

DARKWEB_DIR  = Path(str(DARKWEB_DIR))
DARKWEB_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_DIR.mkdir(parents=True, exist_ok=True)

MAX_DOMAINS        = 10
ALERT_SEVERITIES   = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
CREDENTIAL_PATTERN = re.compile(
    r"(?:password|passwd|pwd|credentials?|creds?|login|auth)\s*[:=]\s*\S+",
    re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@(?:{domains})", re.IGNORECASE)


# ── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "version": "143.0.0",
    "tier": "managed_service",
    "price_usd_month": 299,
    "max_domains": MAX_DOMAINS,
    "domains": [],
    "alert_channels": {
        "telegram": {
            "enabled": False,
            "bot_token": "",        # Set via env TELEGRAM_BOT_TOKEN
            "chat_id": "",          # Set via env TELEGRAM_CHAT_ID
            "severity_threshold": "HIGH"
        },
        "webhook": {
            "enabled": False,
            "url": "",              # Set via env DARKWEB_WEBHOOK_URL
            "secret": "",           # HMAC signing secret
            "severity_threshold": "MEDIUM",
            "retry_attempts": 3,
            "timeout_sec": 10
        },
        "email": {
            "enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "from_address": "alerts@cyberdudebivash.com",
            "to_addresses": [],
            "severity_threshold": "CRITICAL"
        }
    },
    "scan_interval_minutes": 30,
    "data_sources": {
        "apex_darkweb_feed": True,
        "paste_aggregator":  True,
        "stealer_logs":      True,
        "breach_marketplace": True,
        "forum_mentions":    True,
    },
    "alert_dedup_window_hours": 24,
    "created_at": datetime.now(timezone.utc).isoformat(),
}


def load_config() -> Dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_bytes())
        except Exception as e:
            logger.error(f"Config load failed: {e}")
    return dict(DEFAULT_CONFIG)


def save_config(cfg: Dict) -> None:
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    tmp.rename(CONFIG_FILE)


def register_domains(domains: List[str], cfg: Dict) -> Dict:
    """Register up to MAX_DOMAINS corporate domains for monitoring."""
    if len(domains) > MAX_DOMAINS:
        raise ValueError(
            f"Maximum {MAX_DOMAINS} domains per subscription. "
            f"Received {len(domains)}. Upgrade to ENTERPRISE for higher limits."
        )
    clean = []
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    for d in domains:
        d = d.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        if not domain_re.match(d):
            logger.warning(f"Invalid domain skipped: {d}")
            continue
        clean.append(d)

    cfg["domains"] = list(dict.fromkeys(cfg.get("domains", []) + clean))[:MAX_DOMAINS]
    cfg["domains_registered_at"] = datetime.now(timezone.utc).isoformat()
    save_config(cfg)
    logger.info(f"Registered domains: {cfg['domains']}")
    return cfg


# ── Dark Web Data Loading ─────────────────────────────────────────────────────

def _load_apex_darkweb_intel() -> List[Dict]:
    """Load dark web intelligence from APEX pipeline outputs."""
    sources = [
        DATA_DIR / "genesis" / "darkweb_intel.json",
        DATA_DIR / "omnishield" / "darkweb_scan.json",
        DATA_DIR / "intelligence" / "darkweb.json",
        DARKWEB_DIR / "latest_scan.json",
    ]
    for src in sources:
        if src.exists():
            try:
                raw = json.loads(src.read_bytes())
                items = raw if isinstance(raw, list) else \
                        raw.get("items") or raw.get("findings") or []
                if items:
                    logger.info(f"Dark web intel loaded from {src.name}: {len(items)} items")
                    return items
            except Exception as e:
                logger.warning(f"Failed to load {src}: {e}")
    return []


def scan_domain_matches(domain: str, intel_items: List[Dict]) -> List[Dict]:
    """
    Scan dark web intel items for mentions of a corporate domain.
    Returns list of findings with severity, source, and evidence.
    """
    findings = []
    domain_lower = domain.lower()
    domain_variants = [
        domain_lower,
        "@" + domain_lower,
        domain_lower.replace(".", "\\."),    # regex-escaped
        domain_lower.split(".")[0],          # org name without TLD
    ]

    for item in intel_items:
        text_fields = [
            str(item.get("title", "")),
            str(item.get("description", "")),
            str(item.get("content", "")),
            str(item.get("raw_text", "")),
            " ".join(str(t) for t in item.get("tags", [])),
        ]
        combined_text = " ".join(text_fields).lower()

        # Domain mention check
        for variant in domain_variants:
            if variant in combined_text:
                severity = _classify_finding_severity(item, combined_text)
                finding = {
                    "id":          str(uuid.uuid4()),
                    "domain":      domain,
                    "match_variant": variant,
                    "severity":    severity,
                    "source":      item.get("source") or item.get("origin", "dark_web"),
                    "source_type": item.get("source_type", "unknown"),
                    "title":       item.get("title", "Dark Web Mention Detected"),
                    "evidence_snippet": _extract_snippet(combined_text, variant),
                    "credential_detected": bool(CREDENTIAL_PATTERN.search(combined_text)),
                    "item_timestamp": item.get("timestamp") or item.get("published_at", ""),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "stix_id":     item.get("stix_id") or item.get("id", ""),
                    "risk_score":  item.get("risk_score") or _severity_to_risk(severity),
                    "ioc_count":   item.get("ioc_count", 0),
                    "tlp":         item.get("tlp", "TLP:RED"),
                    "action_required": severity in ("CRITICAL", "HIGH"),
                }
                findings.append(finding)
                break   # one finding per item per domain

    return findings


def _extract_snippet(text: str, term: str, context_chars: int = 120) -> str:
    idx = text.find(term)
    if idx == -1:
        return ""
    start = max(0, idx - context_chars // 2)
    end   = min(len(text), idx + len(term) + context_chars // 2)
    snippet = text[start:end].strip()
    return f"...{snippet}..." if start > 0 or end < len(text) else snippet


def _classify_finding_severity(item: Dict, text: str) -> str:
    """Heuristic severity classification for dark web findings."""
    # Explicit severity from item
    sev = str(item.get("severity", "")).upper()
    if sev in ALERT_SEVERITIES:
        return sev

    # Heuristic rules
    crit_keywords = ["plaintext password", "database dump", "full breach",
                     "credit card", "ssn", "passport", "private key",
                     "master password", "admin credentials"]
    high_keywords = ["credentials", "email:pass", "combo list", "stealer log",
                     "leaked", "breach", "dump", "account takeover"]
    if any(kw in text for kw in crit_keywords):
        return "CRITICAL"
    if any(kw in text for kw in high_keywords):
        return "HIGH"
    if "mention" in text or "discussion" in text:
        return "MEDIUM"
    return "LOW"


def _severity_to_risk(severity: str) -> float:
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(severity, 3.0)


# ── Alert Delivery ────────────────────────────────────────────────────────────

def _build_alert_payload(domain: str, finding: Dict, cfg: Dict) -> Dict:
    return {
        "alert_id":    finding["id"],
        "platform":    "SENTINEL APEX v143.0.0",
        "alert_type":  "DARK_WEB_DOMAIN_DETECTION",
        "domain":      domain,
        "severity":    finding["severity"],
        "risk_score":  finding["risk_score"],
        "title":       finding["title"],
        "source":      finding["source"],
        "credential_detected": finding["credential_detected"],
        "action_required":     finding["action_required"],
        "detected_at": finding["detected_at"],
        "evidence_snippet": finding["evidence_snippet"][:200],
        "tlp":         finding["tlp"],
        "portal_url":  "https://intel.cyberdudebivash.com/dashboard.html",
        "upgrade_url": "https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise",
    }


def send_telegram_alert(finding: Dict, domain: str, cfg: Dict) -> bool:
    """Send Telegram alert for a dark web finding."""
    import os
    try:
        import urllib.request
        tc = cfg["alert_channels"]["telegram"]
        if not tc.get("enabled"):
            return False
        threshold = tc.get("severity_threshold", "HIGH")
        if ALERT_SEVERITIES and list(ALERT_SEVERITIES).index(
                finding["severity"]) > list(ALERT_SEVERITIES).index(threshold):
            return False   # below threshold

        bot_token = tc.get("bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "")
        chat_id   = tc.get("chat_id") or os.getenv("TELEGRAM_CHAT_ID", "")
        if not bot_token or not chat_id:
            logger.warning("Telegram: bot_token or chat_id not configured")
            return False

        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            finding["severity"], "⚪"
        )
        credential_flag = "🔑 CREDENTIALS DETECTED" if finding["credential_detected"] else ""

        message = (
            f"{emoji} *SENTINEL APEX — DARK WEB ALERT*\n\n"
            f"*Domain:* `{domain}`\n"
            f"*Severity:* {finding['severity']}\n"
            f"*Risk Score:* {finding['risk_score']}/10\n"
            f"*Source:* {finding['source']}\n"
            f"*Title:* {finding['title'][:100]}\n"
            f"{credential_flag}\n\n"
            f"*Evidence:* `{finding['evidence_snippet'][:150]}`\n\n"
            f"⏰ Detected: {finding['detected_at']}\n"
            f"🔗 [View Dashboard](https://intel.cyberdudebivash.com/dashboard.html)\n\n"
            f"_GSTIN: 21ARKPN8270G1ZP | TLP:{finding.get('tlp', 'RED')}_"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }).encode()

        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info(f"Telegram alert sent: {domain} [{finding['severity']}]")
                return True
    except Exception as e:
        logger.error(f"Telegram alert failed: {e}")
    return False


def send_webhook_alert(finding: Dict, domain: str, cfg: Dict) -> bool:
    """Send signed webhook alert for a dark web finding."""
    import os
    import hmac as _hmac
    try:
        import urllib.request
        wc = cfg["alert_channels"]["webhook"]
        if not wc.get("enabled"):
            return False

        webhook_url = wc.get("url") or os.getenv("DARKWEB_WEBHOOK_URL", "")
        if not webhook_url:
            logger.warning("Webhook URL not configured")
            return False

        payload_dict = _build_alert_payload(domain, finding, cfg)
        payload_bytes = json.dumps(payload_dict).encode("utf-8")

        # HMAC-SHA256 signature
        secret = (wc.get("secret") or os.getenv("DARKWEB_WEBHOOK_SECRET", "")).encode()
        sig = _hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest() if secret else ""

        headers = {
            "Content-Type": "application/json",
            "X-APEX-Signature": f"sha256={sig}",
            "X-APEX-Platform": "SENTINEL-APEX/143.0.0",
            "X-APEX-Alert-Type": "DARK_WEB_DETECTION",
        }

        for attempt in range(wc.get("retry_attempts", 3)):
            try:
                req = urllib.request.Request(
                    webhook_url, data=payload_bytes, headers=headers, method="POST"
                )
                timeout = wc.get("timeout_sec", 10)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if 200 <= resp.status < 300:
                        logger.info(f"Webhook sent (attempt {attempt+1}): "
                                    f"{domain} [{finding['severity']}]")
                        return True
            except Exception as ex:
                if attempt < wc.get("retry_attempts", 3) - 1:
                    time.sleep(2 ** attempt)
                else:
                    logger.error(f"Webhook failed after {attempt+1} attempts: {ex}")
    except Exception as e:
        logger.error(f"Webhook delivery error: {e}")
    return False


# ── Deduplication ─────────────────────────────────────────────────────────────

_DEDUP_CACHE_PATH = DARKWEB_DIR / "alert_dedup_cache.json"

def _load_dedup_cache() -> Dict:
    if _DEDUP_CACHE_PATH.exists():
        try:
            return json.loads(_DEDUP_CACHE_PATH.read_bytes())
        except Exception:
            return {}
    return {}

def _save_dedup_cache(cache: Dict) -> None:
    tmp = _DEDUP_CACHE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache), encoding="utf-8")
    tmp.rename(_DEDUP_CACHE_PATH)

def _is_duplicate(finding: Dict, dedup_window_hours: int = 24) -> bool:
    cache = _load_dedup_cache()
    key = hashlib.md5(
        f"{finding['domain']}:{finding['source']}:{finding['title'][:50]}".encode()
    , usedforsecurity=False).hexdigest()
    now = time.time()
    if key in cache:
        age_h = (now - cache[key]) / 3600
        if age_h < dedup_window_hours:
            return True
    cache[key] = now
    _save_dedup_cache(cache)
    return False


# ── Persistence ───────────────────────────────────────────────────────────────

def save_findings(domain: str, findings: List[Dict]) -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = DARKWEB_DIR / f"findings_{domain.replace('.', '_')}_{date_str}.json"
    existing = []
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_bytes())
        except Exception:
            pass
    all_findings = existing + findings
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    tmp.rename(out_path)
    return out_path


def write_alert_log(finding: Dict) -> None:
    log_path = ALERTS_DIR / "darkweb_alerts.jsonl"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(finding) + "\n")


# ── Main Scan Engine ─────────────────────────────────────────────────────────

def run_scan(cfg: Dict) -> Dict:
    """
    Full dark web scan cycle for all registered domains.
    Returns scan summary dict.
    """
    domains  = cfg.get("domains", [])
    if not domains:
        logger.warning("No domains configured for monitoring")
        return {"status": "no_domains", "findings": 0}

    logger.info(f"Dark web scan started | {len(domains)} domains")
    t0 = time.monotonic()

    # Load dark web intelligence from APEX pipeline
    intel_items = _load_apex_darkweb_intel()
    logger.info(f"Dark web intel corpus: {len(intel_items)} items")

    scan_id       = str(uuid.uuid4())
    total_findings = 0
    total_alerts   = 0
    domain_results = {}
    dedup_window   = cfg.get("alert_dedup_window_hours", 24)

    for domain in domains:
        findings = scan_domain_matches(domain, intel_items)
        new_findings = [f for f in findings if not _is_duplicate(f, dedup_window)]

        if new_findings:
            save_findings(domain, new_findings)
            for finding in new_findings:
                write_alert_log(finding)
                # Alert delivery
                sent_tg = send_telegram_alert(finding, domain, cfg)
                sent_wh = send_webhook_alert(finding, domain, cfg)
                finding["alerts_sent"] = {
                    "telegram": sent_tg, "webhook": sent_wh
                }
                total_alerts += int(sent_tg) + int(sent_wh)

        total_findings += len(new_findings)
        domain_results[domain] = {
            "findings":    len(new_findings),
            "critical":    sum(1 for f in new_findings if f["severity"] == "CRITICAL"),
            "high":        sum(1 for f in new_findings if f["severity"] == "HIGH"),
            "credentials": sum(1 for f in new_findings if f["credential_detected"]),
        }

    elapsed = time.monotonic() - t0
    summary = {
        "scan_id":        scan_id,
        "status":         "complete",
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "domains_scanned": len(domains),
        "intel_corpus":   len(intel_items),
        "total_findings": total_findings,
        "total_alerts":   total_alerts,
        "domain_results": domain_results,
        "elapsed_sec":    round(elapsed, 3),
    }

    # Save summary
    summary_path = DARKWEB_DIR / "last_scan_summary.json"
    tmp = summary_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    tmp.rename(summary_path)

    logger.info(
        f"Scan complete | domains={len(domains)} | "
        f"findings={total_findings} | alerts={total_alerts} | "
        f"elapsed={elapsed:.2f}s"
    )
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Dark Web Domain Surveillance Engine"
    )
    parser.add_argument("--domains", nargs="+",
                        help=f"Corporate domains to monitor (max {MAX_DOMAINS})")
    parser.add_argument("--config", default=None,
                        help="Path to monitor config JSON")
    parser.add_argument("--scan-once", action="store_true",
                        help="Run one scan and exit")
    parser.add_argument("--register-only", action="store_true",
                        help="Register domains and exit without scanning")
    parser.add_argument("--show-config", action="store_true",
                        help="Print current config and exit")
    args = parser.parse_args()

    cfg = load_config()

    if args.domains:
        cfg = register_domains(args.domains, cfg)

    if args.show_config:
        print(json.dumps(cfg, indent=2))
        return

    if args.register_only:
        print(f"Registered: {cfg['domains']}")
        return

    if args.scan_once or True:   # Always scan when called
        result = run_scan(cfg)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
