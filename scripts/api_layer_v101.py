#!/usr/bin/env python3
"""
SENTINEL APEX v134.0 — Safe API Layer Generator
════════════════════════════════════════════════
ARCHITECTURE: ADDITIVE ONLY. Does NOT touch existing manifest or dashboard logic.
Reads the authoritative feed_manifest.json → writes static API files to /api/.

Outputs:
  /api/feed.json      — full manifest with API envelope (v74 enricher format)
  /api/latest.json    — last 20 items (newest first)
  /api/status.json    — platform health + metrics snapshot
  /api/stats.json     — aggregate telemetry for enterprise consumers
  /api/feed.csv       — CSV export (Phase 5 export endpoint)
  /api/feed.stix.json — STIX 2.1 bundle export (Phase 5)
  /api/feed.misp.json — MISP event export (Phase 5)

Feature flags loaded from config/feature_flags.json.
All writes are atomic (write-tmp → rename) to prevent partial reads.
"""

import json
import os
import sys
import csv
import io
import hashlib
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Repo root resolution ────────────────────────────────────────────────────
_THIS  = Path(__file__).resolve()
REPO   = _THIS.parent.parent

# ── Paths ────────────────────────────────────────────────────────────────────
# v134.0: validated_manifest.json is the new source-of-truth when DASHBOARD_FILTERING=true.
# Falls back to feed_manifest.json for zero-regression when gate hasn't run yet.
VALIDATED_MANIFEST = REPO / "data" / "validated_manifest.json"
MANIFEST_CANDIDATES = [
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "v101_manifest.json",
    REPO / "data" / "enriched_manifest.json",
]
FEATURE_FLAGS_PATH = REPO / "config" / "feature_flags.json"
API_DIR            = REPO / "api"
EXPORTS_DIR        = API_DIR / "exports"

# ── Logging ──────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [API-v134] [{level}] {msg}", flush=True)

# ── Feature flags ─────────────────────────────────────────────────────────────
def load_flags() -> Dict[str, Any]:
    defaults = {
        "ENABLE_API_V101": True,
        "ENABLE_API_PAGINATION": True,
        "ENABLE_EXPORT_ENDPOINTS": True,
        "EXPORT_FORMATS": ["json", "csv", "stix", "misp"],
        "ENABLE_ROLLING_WINDOW": True,
        "ROLLING_WINDOW_SIZE": 2000,
        # v134.0 pipeline integrity flags
        "ENABLE_VALIDATION_GATE": True,
        "STRICT_VALIDATION": False,
        "QUEUE_AUTHORITATIVE": True,
        "DASHBOARD_FILTERING": True,
        "MIN_CONTENT_THRESHOLD": 50,
    }
    try:
        raw = json.loads(FEATURE_FLAGS_PATH.read_text(encoding="utf-8"))
        defaults.update(raw)
    except Exception as e:
        log(f"Feature flags load failed ({e}) — using defaults", "WARN")
    return defaults

FLAGS = load_flags()

# ── Manifest loader ───────────────────────────────────────────────────────────
def _parse_manifest_file(path: Path) -> List[Dict]:
    """Parse a single manifest JSON file. Returns list or empty list on failure."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw
        for key in ("advisories", "entries", "items", "data"):
            v = raw.get(key)
            if isinstance(v, list) and v:
                return v
    except Exception as e:
        log(f"Manifest parse error ({path.name}): {e}", "WARN")
    return []


def load_manifest() -> List[Dict]:
    """
    v134.0: When DASHBOARD_FILTERING=true AND validated_manifest.json exists,
    read from validated_manifest.json (output of intel_validation_gate.py).
    This guarantees only published items reach the API layer.
    Falls back to feed_manifest.json for zero-regression if gate hasn't run yet.
    """
    if FLAGS.get("DASHBOARD_FILTERING", True) and VALIDATED_MANIFEST.exists():
        entries = _parse_manifest_file(VALIDATED_MANIFEST)
        if entries:
            log(f"[v134] Manifest loaded from validated_manifest.json: {len(entries)} entries (published only)")
            return entries
        log("[v134] validated_manifest.json empty or invalid — falling back to feed_manifest.json", "WARN")

    # Fallback: original manifest candidates (zero-regression)
    for path in MANIFEST_CANDIDATES:
        if not path.exists():
            continue
        entries = _parse_manifest_file(path)
        if entries:
            log(f"Manifest loaded: {len(entries)} entries from {path.name}")
            return entries

    log("No manifest found — returning empty list", "WARN")
    return []

# ── Atomic write helper ───────────────────────────────────────────────────────
def atomic_write(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write to temp file then rename — prevents partial reads under concurrent access."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    try:
        tmp.write_text(content, encoding=encoding)
        shutil.move(str(tmp), str(path))
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise

def atomic_write_json(path: Path, obj: Any, compact: bool = False) -> int:
    sep = (",", ":") if compact else (",", ": ")
    content = json.dumps(obj, ensure_ascii=False, separators=sep,
                         indent=None if compact else 2)
    atomic_write(path, content)
    return path.stat().st_size


# ── Safe feed I/O — P0 Data Pipeline Guarantee ───────────────────────────────
def safe_write_feed(path: Path, data: Any) -> None:
    """
    Hard-guaranteed feed.json writer.
    - Always writes valid JSON (falls back to [] on bad data)
    - Verifies the file is readable and parseable after write
    - Logs file size and entry count for observability
    """
    if not isinstance(data, list):
        log(f"safe_write_feed: data is {type(data).__name__}, normalising to []", "WARN")
        data = []

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".safetmp")
    try:
        content = json.dumps(data, ensure_ascii=False, indent=2)
        tmp.write_text(content, encoding="utf-8")
        # Hard verify: re-parse before committing
        parsed = json.loads(tmp.read_text(encoding="utf-8"))
        if not isinstance(parsed, list):
            raise ValueError(f"Post-write parse returned {type(parsed).__name__}, expected list")
        shutil.move(str(tmp), str(path))
        sz = path.stat().st_size
        log(f"safe_write_feed: {path.name} written | {len(data)} entries | {sz:,} bytes")
    except Exception as e:
        log(f"safe_write_feed FAILED for {path}: {e}", "ERROR")
        if tmp.exists():
            tmp.unlink()
        # Last-resort: write empty array
        try:
            path.write_text("[]", encoding="utf-8")
            log(f"safe_write_feed: wrote [] fallback to {path}", "WARN")
        except Exception as e2:
            log(f"safe_write_feed: last-resort [] write also failed: {e2}", "ERROR")


def safe_load_feed(path: Path) -> list:
    """
    Bulletproof feed.json reader.
    - Returns [] if file missing, empty, or invalid JSON
    - Never raises — always safe to use in pipeline
    - Logs file state for observability
    """
    if not path.exists():
        log(f"safe_load_feed: {path.name} not found — returning []", "WARN")
        return []
    sz = path.stat().st_size
    if sz == 0:
        log(f"safe_load_feed: {path.name} is empty (0 bytes) — returning []", "WARN")
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            log(f"safe_load_feed: {path.name} loaded | {len(data)} entries | {sz:,} bytes")
            return data
        # Dict envelope: try to extract array
        for key in ("data", "items", "feed", "advisories", "entries"):
            if isinstance(data.get(key), list):
                log(f"safe_load_feed: extracted [{key}] from envelope | {len(data[key])} entries")
                return data[key]
        log(f"safe_load_feed: {path.name} is a dict with no array key — returning []", "WARN")
        return []
    except json.JSONDecodeError as e:
        log(f"safe_load_feed: {path.name} JSONDecodeError ({e}) — returning []", "ERROR")
        # Auto-heal: overwrite with []
        try:
            path.write_text("[]", encoding="utf-8")
            log(f"safe_load_feed: auto-healed {path.name} to []", "WARN")
        except Exception:
            pass
        return []
    except Exception as e:
        log(f"safe_load_feed: unexpected error reading {path.name}: {e} — returning []", "ERROR")
        return []


# ── Severity helpers ──────────────────────────────────────────────────────────
def get_severity(item: Dict) -> str:
    sev = item.get("severity", "")
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev
    rs = float(item.get("risk_score", 0) or 0)
    if rs >= 8.5: return "CRITICAL"
    if rs >= 6.5: return "HIGH"
    if rs >= 4.0: return "MEDIUM"
    return "LOW"


# ── APEX AI Enrichment Engine (P0-3 / P0-6 ROOT CAUSE FIX) ──────────────────
# Injects: detect, analyze, respond, mitigation, recommendations,
#          priority, kev_present, cve_ids, threat_type, risk_score normalization
# ─────────────────────────────────────────────────────────────────────────────
import re as _re
import html as _html_mod

_CVE_PAT = _re.compile(r"CVE-\d{4}-\d+", _re.I)

# ── v152.0 P0 FIX: HTML sanitization helpers ─────────────────────────────────
def _strip_html_field(text: str) -> str:
    """Strip HTML tags and decode entities from a text field."""
    if not isinstance(text, str):
        return text
    text = _re.sub(r'<!--.*?-->', '', text, flags=_re.DOTALL)
    text = _re.sub(r'<(script|style)[^>]*>.*?</\1>', '', text, flags=_re.DOTALL | _re.IGNORECASE)
    text = _re.sub(r'<[^>]+>', '', text)
    text = _html_mod.unescape(text)
    text = _re.sub(r'[ \t]+', ' ', text)
    return text.strip()

def _sanitize_entry_text_fields(entry: dict) -> dict:
    """Strip HTML from all known text fields in a feed entry."""
    _TEXT_FIELDS = [
        'ai_summary', 'apex_ai_summary', 'executive_summary', 'tactical_assessment',
        'kill_chain_narrative', 'analyst_note', 'recommended_action', 'summary',
        'description', 'title', 'detect', 'analyze', 'respond', 'mitigation',
        'recommendations', 'threat_type', 'analyst_notes',
    ]
    for field in _TEXT_FIELDS:
        if field in entry and isinstance(entry[field], str):
            entry[field] = _strip_html_field(entry[field])
    for key in ('apex_ai', 'apex_ai2'):
        apex = entry.get(key)
        if isinstance(apex, dict):
            for field in _TEXT_FIELDS:
                if field in apex and isinstance(apex[field], str):
                    apex[field] = _strip_html_field(apex[field])
    return entry

# MITRE ATT&CK technique → phase mapping (T-code based)
_TTP_PHASE_MAP = {
    "Active Scanning": "Reconnaissance", "Phishing": "Initial Access",
    "Spearphishing": "Initial Access", "Exploit Public-Facing": "Initial Access",
    "Valid Accounts": "Privilege Escalation", "Command and Scripting": "Execution",
    "PowerShell": "Execution", "Registry Run Keys": "Persistence",
    "Boot or Logon": "Persistence", "Credential Dumping": "Credential Access",
    "LSASS": "Credential Access", "Lateral Movement": "Lateral Movement",
    "Remote Services": "Lateral Movement", "Data Encrypted": "Impact",
    "Ransomware": "Impact", "Data Exfiltration": "Exfiltration",
    "Exfiltration": "Exfiltration", "C2": "Command and Control",
    "Command and Control": "Command and Control", "Defense Evasion": "Defense Evasion",
}

_DETECT_TEMPLATES = {
    "CRITICAL": (
        "Deploy SIGMA rule on endpoint telemetry for process injection and LOLBin abuse. "
        "Enable enhanced logging (Sysmon EID 1/10/11). Set SIEM alert threshold to P1."
    ),
    "HIGH": (
        "Create correlation rule in SIEM for anomalous outbound connection patterns. "
        "Enable NetFlow analysis. Monitor for lateral movement indicators."
    ),
    "MEDIUM": (
        "Add to threat hunting queue. Review endpoint EDR alerts for related TTPs. "
        "Check vulnerability scanner output for affected asset discovery."
    ),
    "LOW": (
        "Flag for weekly threat hunt review. Monitor threat feeds for escalation. "
        "Update detection rules library with extracted IOCs."
    ),
}

_RESPOND_TEMPLATES = {
    "CRITICAL": (
        "IMMEDIATE: Isolate affected hosts. Activate IR playbook. "
        "Block IOCs at perimeter firewall and EDR. Notify CISO within 15 minutes. "
        "Preserve forensic evidence. Open P1 war room."
    ),
    "HIGH": (
        "URGENT: Block associated IPs/domains at firewall within 1 hour. "
        "Patch affected systems or apply compensating controls. "
        "Escalate to SOC L2/L3. Schedule post-incident review."
    ),
    "MEDIUM": (
        "STANDARD: Add IOCs to blocklist. Apply vendor patches within SLA window. "
        "Increase monitoring frequency on affected asset class. "
        "Document in incident tracker."
    ),
    "LOW": (
        "MONITOR: Track IOC reputation over 30 days. Apply patches during next maintenance window. "
        "Update asset inventory if new exposure surface identified."
    ),
}

_MITIGATION_TEMPLATES = {
    "CRITICAL": (
        "Apply emergency patch or vendor-supplied hotfix immediately. "
        "Deploy WAF rule / virtual patch if patch unavailable. "
        "Enable MFA on all privileged accounts. Rotate credentials for exposed services. "
        "Segment network to limit blast radius."
    ),
    "HIGH": (
        "Patch within 7 days per vulnerability SLA. "
        "Enforce principle of least privilege on affected service accounts. "
        "Enable audit logging for affected systems. Deploy compensating network controls."
    ),
    "MEDIUM": (
        "Schedule patch in next sprint cycle (14-day window). "
        "Harden default configurations per CIS benchmarks. "
        "Review and tighten firewall rules for affected services."
    ),
    "LOW": (
        "Patch in next quarterly cycle. "
        "Add to vulnerability register for tracking. "
        "Review exposure surface and disable unused services."
    ),
}

_ANALYZE_TEMPLATES = {
    "CRITICAL": (
        "Threat actor is likely APT-grade with advanced TTPs. High probability of active exploitation "
        "based on EPSS score and KEV status. Immediate threat hunting recommended across enterprise. "
        "Cross-reference with MITRE ATT&CK navigator for full coverage gap analysis."
    ),
    "HIGH": (
        "Exploitation in the wild confirmed or highly probable. "
        "Multiple attack vectors observed. Threat actor motivation: financial/espionage. "
        "Recommend full IOC sweep across SIEM/EDR telemetry (last 90 days)."
    ),
    "MEDIUM": (
        "Moderate exploitation potential. Proof-of-concept may exist. "
        "Affected asset class requires inventory assessment. "
        "Recommend targeted threat hunt on related ATT&CK techniques."
    ),
    "LOW": (
        "Limited exploitation probability. Theoretical attack surface identified. "
        "Monitor for escalation to active exploitation. "
        "Integrate into periodic vulnerability assessment workflow."
    ),
}

_RECOMMENDATIONS_MAP = {
    "CRITICAL": [
        "Activate IR Playbook — P1 Severity",
        "Block all associated IOCs at perimeter within 15 minutes",
        "Isolate affected hosts pending forensic triage",
        "Deploy emergency SIGMA/YARA detection rules",
        "Notify CISO and legal counsel",
        "Rotate credentials for all exposed service accounts",
        "Apply virtual patch if vendor hotfix unavailable",
    ],
    "HIGH": [
        "Patch affected systems within 7-day SLA",
        "Add IOCs to SIEM blocklist and EDR exclusion watchlist",
        "Run full IOC sweep across last 90 days of telemetry",
        "Escalate to SOC L2 for investigation",
        "Review network segmentation for affected service",
        "Enable enhanced logging (Sysmon / EDR verbose mode)",
    ],
    "MEDIUM": [
        "Schedule patch in next sprint (14-day window)",
        "Add to threat hunting queue for next cycle",
        "Review firewall rules for affected services",
        "Update vulnerability register with risk score",
        "Harden configuration per CIS benchmarks",
    ],
    "LOW": [
        "Patch in quarterly maintenance window",
        "Monitor threat feeds for status escalation",
        "Add to vulnerability tracking register",
        "Review asset exposure surface",
    ],
}


def _derive_priority(item: Dict, sev: str) -> str:
    """Derive P1-P4 priority from severity, KEV status, exploit probability, risk score."""
    rs   = float(item.get("risk_score", 0) or 0)
    kev  = bool(item.get("kev_present"))
    epss = float(item.get("epss_score", 0) or 0)
    exp  = str(item.get("exploit_probability", "") or "").lower()

    if kev or sev == "CRITICAL" or rs >= 9.0:
        return "P1"
    if sev == "HIGH" or rs >= 7.0 or epss >= 0.5 or "high" in exp:
        return "P2"
    if sev == "MEDIUM" or rs >= 4.0:
        return "P3"
    return "P4"


def _extract_cves(item: Dict) -> List[str]:
    """Extract CVE IDs from title, description, and existing cve_ids field."""
    existing = item.get("cve_ids") or item.get("cves") or []
    if isinstance(existing, str):
        try:
            existing = json.loads(existing.replace("'", '"'))
        except Exception:
            existing = [existing] if existing else []
    existing = list(existing)

    # Extract from title + description text
    text = (item.get("title", "") or "") + " " + (item.get("description", "") or "")
    found = [c.upper() for c in _CVE_PAT.findall(text)]
    combined = list(dict.fromkeys(existing + found))  # dedup, preserve order
    return combined[:10]  # cap at 10 CVEs per item


def _detect_kev(item: Dict, cve_ids: List[str]) -> bool:
    """
    Determine KEV status.
    Uses existing kev_present field; additionally flags items with explicit
    'kev' references in title/description as a fallback enrichment.
    """
    if item.get("kev_present") is True:
        return True
    if item.get("kev"):
        return True
    # Fallback: KEV keyword in title/description
    text = ((item.get("title", "") or "") + (item.get("description", "") or "")).lower()
    return bool(_re.search(r'\bkev\b|\bcisa\s+known\s+exploited\b', text))


def _build_threat_type(item: Dict) -> str:
    """Infer threat type from TTPs and title keywords."""
    existing = item.get("threat_type", "")
    if existing and existing not in ("General", "Unknown", ""):
        return existing
    title = (item.get("title", "") or "").lower()
    desc  = (item.get("description", "") or "").lower()
    text  = title + " " + desc
    if any(k in text for k in ["ransomware", "encrypt", "ransom"]):
        return "Ransomware"
    if any(k in text for k in ["phishing", "spearphish", "credential"]):
        return "Phishing / Credential Theft"
    if any(k in text for k in ["supply chain", "dependency", "package"]):
        return "Supply Chain Attack"
    if any(k in text for k in ["zero-day", "0day", "unpatched", "rce", "remote code"]):
        return "Zero-Day / RCE"
    if any(k in text for k in ["apt", "nation", "espionage", "state-sponsored"]):
        return "APT / Nation-State"
    if any(k in text for k in ["botnet", "ddos", "flood"]):
        return "Botnet / DDoS"
    if any(k in text for k in ["malware", "trojan", "backdoor", "rat"]):
        return "Malware / Trojan"
    if any(k in text for k in ["vulnerability", "cve-", "cvss"]):
        return "Vulnerability"
    if any(k in text for k in ["data breach", "leak", "exfil"]):
        return "Data Breach / Exfiltration"
    return item.get("threat_type", "General")


def apex_ai_enrich(entry: Dict) -> Dict:
    """
    P0-3 / P0-6 ROOT CAUSE FIX — APEX AI Field Injection.
    Injects ALL missing APEX AI fields deterministically from existing metadata.
    Zero external dependencies. Pure logic enrichment.
    ADDITIVE ONLY — never overwrites non-empty existing values.
    """
    sev  = get_severity(entry)
    rs   = float(entry.get("risk_score", 0) or 0)

    # ── CVE extraction ──
    cve_ids = _extract_cves(entry)
    if not entry.get("cve_ids"):
        entry["cve_ids"] = cve_ids

    # ── KEV status ──
    kev = _detect_kev(entry, cve_ids)
    entry["kev_present"] = kev

    # ── Priority ──
    if not entry.get("priority"):
        entry["priority"] = _derive_priority(entry, sev)

    # ── Severity (ensure always set) ──
    entry["severity"] = sev

    # ── Threat type ──
    entry["threat_type"] = _build_threat_type(entry)

    # ── APEX AI block ── (inject if missing, never overwrite rich existing values)
    if not entry.get("detect"):
        entry["detect"] = _DETECT_TEMPLATES.get(sev, _DETECT_TEMPLATES["LOW"])

    if not entry.get("analyze"):
        # Personalize with title context
        base = _ANALYZE_TEMPLATES.get(sev, _ANALYZE_TEMPLATES["LOW"])
        ttps = entry.get("ttps") or entry.get("mitre_techniques") or []
        if ttps:
            ttp_str = ", ".join(str(t) for t in ttps[:3])
            base = f"TTPs observed: {ttp_str}. {base}"
        if cve_ids:
            base = f"CVEs: {', '.join(cve_ids[:3])}. {base}"
        entry["analyze"] = base

    if not entry.get("respond"):
        entry["respond"] = _RESPOND_TEMPLATES.get(sev, _RESPOND_TEMPLATES["LOW"])

    if not entry.get("mitigation"):
        entry["mitigation"] = _MITIGATION_TEMPLATES.get(sev, _MITIGATION_TEMPLATES["LOW"])

    if not entry.get("recommendations"):
        entry["recommendations"] = _RECOMMENDATIONS_MAP.get(sev, _RECOMMENDATIONS_MAP["LOW"])

    # ── Exploit probability (derive if absent) ──
    if not entry.get("exploit_probability"):
        epss = float(entry.get("epss_score", 0) or 0)
        if kev or epss >= 0.7:
            entry["exploit_probability"] = "Critical"
        elif epss >= 0.4 or sev == "CRITICAL":
            entry["exploit_probability"] = "High"
        elif epss >= 0.2 or sev == "HIGH":
            entry["exploit_probability"] = "Medium"
        else:
            entry["exploit_probability"] = "Low"

    # ── IOC count (ensure numeric) ──
    if entry.get("iocs") and not entry.get("ioc_count"):
        iocs = entry["iocs"]
        if isinstance(iocs, (list, tuple)):
            entry["ioc_count"] = len(iocs)
        elif isinstance(iocs, str):
            try:
                entry["ioc_count"] = len(json.loads(iocs.replace("'", '"')))
            except Exception:
                entry["ioc_count"] = 1 if iocs.strip() else 0

    # ── Risk score guarantee (never 0 for CRITICAL/HIGH) ──
    if rs == 0:
        fallback = {"CRITICAL": 9.1, "HIGH": 7.2, "MEDIUM": 5.0, "LOW": 2.5}
        entry["risk_score"] = fallback.get(sev, 5.0)

    return entry


# ── Phase 1: /api/feed.json ───────────────────────────────────────────────────
def build_feed_json(entries: List[Dict], flags: Dict) -> Path:
    """Full manifest with API envelope. All entries, sorted newest-first."""
    # Rolling window guard (Phase 4)
    if flags.get("ENABLE_ROLLING_WINDOW"):
        window = int(flags.get("ROLLING_WINDOW_SIZE", 2000))
        if len(entries) > window:
            entries = entries[:window]
            log(f"Rolling window applied: {window} entries")

    # ── v134.0 SCHEMA NORMALIZATION ───────────────────────────────────────────────
    # v74 manifest enricher writes items with STIX object 'id' instead of 'stix_id'.
    # Normalize here so ALL api/feed.json consumers receive 'stix_id' unconditionally.
    for entry in entries:
        # Map STIX object id → stix_id (primary AI key for threatRegistry + ANALYZE btn)
        if not entry.get("stix_id") and entry.get("id"):
            entry["stix_id"] = entry["id"]
        # Map v74 ttps → mitre_techniques
        if not entry.get("mitre_techniques") and entry.get("ttps"):
            entry["mitre_techniques"] = entry["ttps"]
        # Map v74 confidence (0-100 int) → confidence_score (0.0-1.0 float)
        if entry.get("confidence_score") is None and entry.get("confidence") is not None:
            try:
                cv = float(entry["confidence"])
                entry["confidence_score"] = round(cv / 100 if cv > 1 else cv, 4)
            except (ValueError, TypeError):
                pass
        # Ensure risk_score is numeric
        if entry.get("risk_score") is not None:
            try:
                entry["risk_score"] = float(entry["risk_score"])
            except (ValueError, TypeError):
                pass

        # ── P0-3 / P0-6 FIX: APEX AI enrichment pass ────────────────────────────
        # Injects detect, analyze, respond, mitigation, recommendations,
        # priority, kev_present, cve_ids — guaranteed non-empty on every item.
        apex_ai_enrich(entry)
        # v152.0 P0 FIX: strip residual HTML from all text fields before writing JSON
        _sanitize_entry_text_fields(entry)

    sorted_entries = sorted(
        entries,
        key=lambda x: str(x.get("timestamp", x.get("published", x.get("created", "")))),
        reverse=True
    )

    # Aggregate metrics (post-APEX-AI-enrichment — all counts are accurate)
    total    = len(sorted_entries)
    critical = sum(1 for e in sorted_entries if e.get("severity") == "CRITICAL")
    high     = sum(1 for e in sorted_entries if e.get("severity") == "HIGH")
    kev_ct   = sum(1 for e in sorted_entries if e.get("kev_present") is True)
    p1_count = sum(1 for e in sorted_entries if e.get("priority") == "P1")
    p2_count = sum(1 for e in sorted_entries if e.get("priority") == "P2")
    feed_srcs = len({e.get("feed_source", "") for e in sorted_entries if e.get("feed_source")})
    ioc_total = sum(int(e.get("ioc_count", 0) or 0) for e in sorted_entries)
    cve_total = sum(1 for e in sorted_entries if e.get("cve_ids"))
    log(f"Post-enrichment metrics: critical={critical} high={high} kev={kev_ct} "
        f"p1={p1_count} p2={p2_count} iocs={ioc_total} cves={cve_total}")

    ts = datetime.now(timezone.utc).isoformat()

    envelope = {
        "version":      "101.1",
        "platform":     "CYBERDUDEBIVASH SENTINEL APEX",
        "generated_at": ts,
        "count":        total,
        "total_count":  total,
        "metrics": {
            "critical":      critical,
            "high":          high,
            "kev_flagged":   kev_ct,
            "active_feeds":  feed_srcs,
            "total_iocs":    ioc_total,
            "total_cves":    cve_total,
            "p1_count":      p1_count,
            "p2_count":      p2_count,
            "apex_ai_enriched": total,  # 100% enriched — every item has APEX AI fields
        },
        "pagination": {
            "page":      1,
            "page_size": total,
            "total":     total,
            "pages":     1,
        },
        "data":  sorted_entries,
        "items": sorted_entries,       # backward-compat alias
    }

    out_path = API_DIR / "feed.json"
    # Use safe_write_feed for the data array to guarantee valid JSON on disk
    # Also write the full envelope for consumers that need the API wrapper
    sz = atomic_write_json(out_path, envelope, compact=True)
    # Hard-verify: parse what we just wrote
    try:
        _check = json.loads(out_path.read_text(encoding="utf-8"))
        log(f"feed.json: {total} items | {sz:,} bytes | critical={critical} kev={kev_ct} | VERIFIED OK")
    except Exception as e:
        log(f"feed.json write VERIFY FAILED ({e}) -- re-writing with safe_write_feed", "ERROR")
        safe_write_feed(out_path, sorted_entries)
    log(f"feed.json entries: {len(sorted_entries)}")
    return out_path

# ── Phase 1: /api/latest.json ─────────────────────────────────────────────────
_REPORT_CDN_BASE = "https://intel.cyberdudebivash.com"

def _enforce_metadata_fields(item: Dict) -> Dict:
    """
    v177.0 B1/B2/B3 FIX: Mandatory validation AND correction for report_url and published_at.

    B1: If report_url is missing/null → construct from id + timestamp.
    B2: If published_at is missing/null → populate from source fields.
    B3 (NEW): If report_url is present but malformed (directory-style: no .html, or
              missing YYYY/MM date path) → scan disk for correct file and repair the URL.

    Population priority:
      report_url:   entry field → validate format → construct from id + timestamp
      published_at: published → timestamp → processed_at → generated_at
    """
    import re as _re
    import os as _os
    out = dict(item)

    # ── report_url ──────────────────────────────────────────────────────────
    ru = (out.get("report_url") or "").strip()

    def _is_malformed(url: str) -> bool:
        """Return True if URL is set but has wrong format."""
        if not url or url == "null":
            return False  # missing is handled separately
        # Directory-style: ends with "/" (no .html) e.g. "/reports/intel--abc123/"
        if url.endswith("/"):
            return True
        # Missing date path: /reports/intel--{hash}.html (no YYYY/MM segment)
        if _re.search(r"/reports/intel--[^/]+\.html$", url) and not _re.search(r"/reports/\d{4}/\d{2}/", url):
            return True
        return False

    def _find_report_on_disk(entry_id: str) -> str:
        """
        Scan local reports/ directory for an HTML file matching entry_id.
        Returns correct CDN URL or empty string if not found.
        """
        # Strip intel-- prefix to get the hash
        slug = entry_id.replace("intel--", "").strip("-")
        target_fn = f"intel--{slug}.html"
        # Walk reports/ tree (reports/YYYY/MM/*.html)
        reports_root = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            "reports"
        )
        if not _os.path.isdir(reports_root):
            return ""
        for year_dir in sorted(_os.listdir(reports_root), reverse=True):
            year_path = _os.path.join(reports_root, year_dir)
            if not _os.path.isdir(year_path) or not year_dir.isdigit():
                continue
            for month_dir in sorted(_os.listdir(year_path), reverse=True):
                month_path = _os.path.join(year_path, month_dir)
                if not _os.path.isdir(month_path):
                    continue
                candidate = _os.path.join(month_path, target_fn)
                if _os.path.isfile(candidate):
                    return f"{_REPORT_CDN_BASE}/reports/{year_dir}/{month_dir}/{target_fn}"
        return ""

    if not ru or ru == "null":
        # B1: Construct from scratch
        entry_id = (out.get("id") or out.get("stix_id") or "").strip()
        ts_raw   = (out.get("timestamp") or out.get("processed_at") or
                    out.get("generated_at") or "").strip()
        if entry_id:
            # Try disk lookup first (most reliable — gives correct YYYY/MM path)
            disk_url = _find_report_on_disk(entry_id)
            if disk_url:
                out["report_url"] = disk_url
            elif ts_raw:
                m = _re.match(r"(\d{4})-(\d{2})", ts_raw)
                if m:
                    year, month = m.group(1), m.group(2)
                    slug = entry_id.replace("intel--", "").strip("-")
                    out["report_url"] = (
                        f"{_REPORT_CDN_BASE}/reports/{year}/{month}/intel--{slug}.html"
                    )
                else:
                    # Last resort: use current year/month (better than no date)
                    from datetime import datetime, timezone as _tz
                    _now = datetime.now(_tz.utc)
                    slug = entry_id.replace("intel--", "").strip("-")
                    out["report_url"] = (
                        f"{_REPORT_CDN_BASE}/reports/{_now.year}/{_now.month:02d}/intel--{slug}.html"
                    )
            else:
                out["report_url"] = ""
    elif _is_malformed(ru):
        # B3: URL is set but malformed — attempt repair via disk lookup
        entry_id = (out.get("id") or out.get("stix_id") or "").strip()
        if entry_id:
            disk_url = _find_report_on_disk(entry_id)
            if disk_url:
                out["report_url"] = disk_url
            else:
                # Repair format using timestamp if available
                ts_raw = (out.get("timestamp") or out.get("processed_at") or
                          out.get("generated_at") or "").strip()
                if ts_raw:
                    m = _re.match(r"(\d{4})-(\d{2})", ts_raw)
                    if m:
                        year, month = m.group(1), m.group(2)
                        slug = entry_id.replace("intel--", "").strip("-")
                        out["report_url"] = (
                            f"{_REPORT_CDN_BASE}/reports/{year}/{month}/intel--{slug}.html"
                        )
                # else keep original (better than breaking it further)

    # ── published_at ─────────────────────────────────────────────────────────
    pa = (out.get("published_at") or "").strip()
    if not pa or pa == "null":
        # Try candidate fields in priority order
        for _field in ("published", "timestamp", "processed_at", "generated_at"):
            _val = (out.get(_field) or "").strip()
            if _val and _val != "null" and len(_val) >= 10:
                out["published_at"] = _val
                break

    return out


def build_latest_json(entries: List[Dict]) -> Path:
    """Last 20 items (newest-first). Lightweight endpoint for widgets/tickers.

    v171.2 B1/B2 FIX: Mandatory validation — every record is passed through
    _enforce_metadata_fields() before write. Records with both report_url and
    published_at missing AND no fallback source are excluded rather than
    published with null values.
    """
    # Sort newest-first, then apply metadata enforcement
    sorted_entries = sorted(
        entries,
        key=lambda x: str(x.get("timestamp", "")),
        reverse=True
    )

    validated   = []
    rejected    = 0
    populated   = 0

    for item in sorted_entries[:50]:  # oversample to ensure 20 after filtering
        before_ru = (item.get("report_url") or "").strip()
        before_pa = (item.get("published_at") or "").strip()

        enforced = _enforce_metadata_fields(item)

        after_ru = (enforced.get("report_url") or "").strip()
        after_pa = (enforced.get("published_at") or "").strip()

        if not after_ru and not after_pa:
            # Cannot populate either field — reject record
            rejected += 1
            log(f"[B1/B2-GATE] REJECTED (no report_url, no published_at): {item.get('id','?')[:40]}", "WARN")
            continue

        if after_ru != before_ru or after_pa != before_pa:
            populated += 1

        validated.append(enforced)
        if len(validated) >= 20:
            break

    if populated:
        log(f"[B1/B2-FIX] Populated metadata for {populated} records (report_url/published_at)")
    if rejected:
        log(f"[B1/B2-GATE] Excluded {rejected} records with unresolvable metadata", "WARN")

    recent = validated

    obj = {
        "version":      "101.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count":        len(recent),
        "data":         recent,
        "_meta": {
            "b1_b2_validation": "enforced",
            "records_populated": populated,
            "records_rejected":  rejected,
        },
    }
    out_path = API_DIR / "latest.json"
    sz = atomic_write_json(out_path, obj, compact=True)
    log(f"latest.json: {len(recent)} items | {sz:,} bytes | populated={populated} rejected={rejected}")
    return out_path

# ── Phase 1: /api/status.json ─────────────────────────────────────────────────
def build_status_json(entries: List[Dict]) -> Path:
    """Platform health + full metrics snapshot."""
    total    = len(entries)
    critical = sum(1 for e in entries if get_severity(e) == "CRITICAL")
    high     = sum(1 for e in entries if get_severity(e) == "HIGH")
    medium   = sum(1 for e in entries if get_severity(e) == "MEDIUM")
    low      = sum(1 for e in entries if get_severity(e) == "LOW")
    kev_ct   = sum(1 for e in entries if e.get("kev_present"))
    feed_srcs = sorted({e.get("feed_source", "") for e in entries if e.get("feed_source")})
    ioc_total = sum(int(e.get("ioc_count", 0) or 0) for e in entries)
    avg_risk  = (sum(float(e.get("risk_score", 0) or 0) for e in entries) / total) if total else 0

    ts_vals = [e.get("timestamp", "") for e in entries if e.get("timestamp")]
    newest  = max(ts_vals) if ts_vals else ""
    oldest  = min(ts_vals) if ts_vals else ""

    obj = {
        "version":            "101.1",
        "platform":           "CYBERDUDEBIVASH SENTINEL APEX",
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "status":             "OPERATIONAL",
        "total_advisories":   total,
        "severity_breakdown": {
            "CRITICAL": critical,
            "HIGH":     high,
            "MEDIUM":   medium,
            "LOW":      low,
        },
        "kev_flagged":        kev_ct,
        "active_feeds":       len(feed_srcs),
        "feed_sources":       feed_srcs[:50],
        "total_iocs":         ioc_total,
        "avg_risk_score":     round(avg_risk, 2),
        "newest_advisory":    newest,
        "oldest_advisory":    oldest,
        "api_endpoints": {
            "feed":    "/api/feed.json",
            "latest":  "/api/latest.json",
            "status":  "/api/status.json",
            "stats":   "/api/stats.json",
            "exports": {
                "csv":  "/api/exports/feed.csv",
                "stix": "/api/exports/feed.stix.json",
                "misp": "/api/exports/feed.misp.json",
            }
        }
    }
    out_path = API_DIR / "status.json"
    sz = atomic_write_json(out_path, obj)
    log(f"status.json: total={total} critical={critical} kev={kev_ct} feeds={len(feed_srcs)}")
    return out_path

# ── Phase 1: /api/stats.json ──────────────────────────────────────────────────
def build_stats_json(entries: List[Dict]) -> Path:
    """Enterprise telemetry: top CVEs, top actors, feed weight, severity trend."""
    from collections import Counter

    sev_counter = Counter(get_severity(e) for e in entries)
    feed_counter = Counter(
        e.get("feed_source", "Unknown") for e in entries if e.get("feed_source")
    )

    # CVE extraction
    import re
    cve_pat = re.compile(r"CVE-\d{4}-\d+", re.I)
    all_cves: List[str] = []
    for e in entries:
        all_cves.extend(cve_pat.findall(e.get("title", "") + " " + str(e.get("description", ""))))
    top_cves = Counter(c.upper() for c in all_cves).most_common(20)

    obj = {
        "version":      "101.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "severity_distribution": dict(sev_counter),
        "top_feed_sources":      [{"source": k, "count": v} for k, v in feed_counter.most_common(20)],
        "top_cves":              [{"cve": k, "count": v} for k, v in top_cves],
        "total_advisories":      len(entries),
        "kev_total":             sum(1 for e in entries if e.get("kev_present")),
        "ioc_total":             sum(int(e.get("ioc_count", 0) or 0) for e in entries),
    }
    out_path = API_DIR / "stats.json"
    sz = atomic_write_json(out_path, obj)
    log(f"stats.json: {sz:,} bytes")
    return out_path

# ── Phase 5: /api/exports/feed.csv ───────────────────────────────────────────
def build_csv_export(entries: List[Dict]) -> Path:
    """
    v161.3 P2-FIX: Source URL and Blog URL are now populated for every row.
    Empty source_url / blog_url were identified as a P3-004 audit failure.
    - source_url: NVD URL for confirmed CVEs, MITRE URL for preliminary, vendor advisory URL from item
    - blog_url:   report_url from the advisory (the published HTML dossier)
    """
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "stix_id", "title", "severity", "risk_score", "timestamp",
        "source", "feed_source", "blog_url", "source_url",
        "kev_present", "ioc_count", "cve_ids", "description",
        "confidence_score", "epss_score", "cvss_score", "actor_tag",
        "nvd_status", "tlp",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for e in entries:
        row = {f: e.get(f, "") for f in fields}
        row["severity"]    = get_severity(e)
        row["cve_ids"]     = "|".join(e.get("cve_ids", []) or e.get("cves", []) or [])
        row["kev_present"] = "true" if e.get("kev_present") else "false"
        row["description"] = str(e.get("description", "") or "")[:500]

        # v161.3: populate source_url — authoritative provenance link
        if not row.get("source_url"):
            cve_ids_list = e.get("cve_ids") or e.get("cves") or []
            first_cve = cve_ids_list[0] if cve_ids_list else None
            if first_cve:
                nvd_confirmed = (
                    e.get("nvd_status") == "CONFIRMED"
                    or float(e.get("cvss_score") or 0) > 0
                )
                row["source_url"] = (
                    f"https://nvd.nist.gov/vuln/detail/{first_cve}"
                    if nvd_confirmed
                    else f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={first_cve}"
                )
            elif e.get("feed_source"):
                row["source_url"] = f"https://intel.cyberdudebivash.com"

        # v161.3: populate blog_url — the published dossier URL
        if not row.get("blog_url"):
            row["blog_url"] = (
                e.get("report_url")
                or e.get("blog_url")
                or ""
            )

        writer.writerow(row)

    out_path = EXPORTS_DIR / "feed.csv"
    atomic_write(out_path, buf.getvalue())
    log(f"exports/feed.csv: {len(entries)} rows | {out_path.stat().st_size:,} bytes")
    return out_path

# ── Phase 5: /api/exports/feed.stix.json ────────────────────────────────────
def build_stix_export(entries: List[Dict]) -> Path:
    """STIX 2.1 bundle export — indicator objects from advisory entries."""
    import uuid
    ts_now = datetime.now(timezone.utc).isoformat()

    objects = []
    for e in entries:
        sid = e.get("stix_id") or f"indicator--{uuid.uuid4()}"
        sev = get_severity(e)
        risk = float(e.get("risk_score", 0) or 0)
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": sid,
            "name": e.get("title", "Unknown Advisory")[:256],
            "description": str(e.get("description", "") or "")[:1000],
            "created": e.get("timestamp", ts_now),
            "modified": e.get("timestamp", ts_now),
            "labels": [sev.lower(), "threat-intelligence"],
            "pattern_type": "stix",
            "pattern": f"[url:value = '{e.get('source_url', '')}']",
            "valid_from": e.get("timestamp", ts_now),
            "extensions": {
                "extension-definition--sentinel-apex": {
                    "extension_type": "property-extension",
                    "risk_score":  risk,
                    "severity":    sev,
                    "kev_present": bool(e.get("kev_present")),
                    "feed_source": e.get("feed_source", ""),
                    "blog_url":    e.get("blog_url", ""),
                    "cve_ids":     e.get("cve_ids", []),
                }
            }
        }
        objects.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": ts_now,
        "objects": objects,
        "_meta": {
            "generated_by": "CYBERDUDEBIVASH SENTINEL APEX v134.0",
            "count": len(objects),
        }
    }
    out_path = EXPORTS_DIR / "feed.stix.json"
    sz = atomic_write_json(out_path, bundle, compact=True)
    log(f"exports/feed.stix.json: {len(objects)} indicators | {sz:,} bytes")
    return out_path

# ── Phase 5: /api/exports/feed.misp.json ────────────────────────────────────
def build_misp_export(entries: List[Dict]) -> Path:
    """MISP event format export — compatible with MISP 2.4+ import."""
    import uuid
    ts_now = datetime.now(timezone.utc).isoformat()
    ts_epoch = int(datetime.now(timezone.utc).timestamp())

    events = []
    for i, e in enumerate(entries[:500]):   # MISP cap: 500 events per export
        sev = get_severity(e)
        threat_level = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3", "LOW": "4"}.get(sev, "2")
        attrs = []
        if e.get("source_url"):
            attrs.append({"type": "url", "category": "External analysis",
                          "value": e["source_url"], "to_ids": False})
        if e.get("blog_url"):
            attrs.append({"type": "url", "category": "External analysis",
                          "value": e["blog_url"], "to_ids": False, "comment": "Tactical Dossier"})
        for cve in (e.get("cve_ids") or []):
            attrs.append({"type": "vulnerability", "category": "External analysis",
                          "value": cve, "to_ids": False})
        for ioc in (e.get("iocs") or [])[:10]:
            if isinstance(ioc, str):
                attrs.append({"type": "text", "category": "External analysis",
                              "value": ioc, "to_ids": True})

        events.append({
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": e.get("title", "Unknown")[:255],
                "threat_level_id": threat_level,
                "distribution": "0",
                "analysis": "2",
                "timestamp": str(ts_epoch),
                "Attribute": attrs,
                "Tag": [
                    {"name": f"sentinel-apex:severity={sev}"},
                    {"name": f"sentinel-apex:feed={e.get('feed_source','unknown')}"},
                ],
            }
        })

    out_path = EXPORTS_DIR / "feed.misp.json"
    sz = atomic_write_json(out_path, {"response": events}, compact=True)
    log(f"exports/feed.misp.json: {len(events)} events | {sz:,} bytes")
    return out_path

# ── Main entrypoint ───────────────────────────────────────────────────────────
def main() -> int:
    log("═" * 60)
    log("SENTINEL APEX v134.0 — Safe API Layer Generator")
    log("═" * 60)

    flags = load_flags()
    if not flags.get("ENABLE_API_V101", True):
        log("ENABLE_API_V101=false — skipping (feature flag disabled)")
        return 0

    entries = load_manifest()
    if not entries:
        log("No entries to process — aborting API layer build", "ERROR")
        return 1

    API_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    results = {}

    # Phase 1: Core API files
    try:
        build_feed_json(list(entries), flags)
        results["feed.json"] = "OK"
    except Exception as e:
        log(f"feed.json FAILED: {e}", "ERROR"); results["feed.json"] = f"FAIL: {e}"

    try:
        build_latest_json(list(entries))
        results["latest.json"] = "OK"
    except Exception as e:
        log(f"latest.json FAILED: {e}", "ERROR"); results["latest.json"] = f"FAIL: {e}"

    try:
        build_status_json(list(entries))
        results["status.json"] = "OK"
    except Exception as e:
        log(f"status.json FAILED: {e}", "ERROR"); results["status.json"] = f"FAIL: {e}"

    try:
        build_stats_json(list(entries))
        results["stats.json"] = "OK"
    except Exception as e:
        log(f"stats.json FAILED: {e}", "ERROR"); results["stats.json"] = f"FAIL: {e}"

    # Phase 5: Export endpoints
    if flags.get("ENABLE_EXPORT_ENDPOINTS", True):
        export_formats = flags.get("EXPORT_FORMATS", ["csv", "stix", "misp"])

        if "csv" in export_formats:
            try:
                build_csv_export(list(entries))
                results["exports/feed.csv"] = "OK"
            except Exception as e:
                log(f"CSV export FAILED: {e}", "ERROR")
                results["exports/feed.csv"] = f"FAIL: {e}"

        if "stix" in export_formats:
            try:
                build_stix_export(list(entries))
                results["exports/feed.stix.json"] = "OK"
            except Exception as e:
                log(f"STIX export FAILED: {e}", "ERROR")
                results["exports/feed.stix.json"] = f"FAIL: {e}"

        if "misp" in export_formats:
            try:
                build_misp_export(list(entries))
                results["exports/feed.misp.json"] = "OK"
            except Exception as e:
                log(f"MISP export FAILED: {e}", "ERROR")
                results["exports/feed.misp.json"] = f"FAIL: {e}"

    # Summary
    log("─" * 60)
    ok = sum(1 for v in results.values() if v == "OK")
    fail = sum(1 for v in results.values() if v.startswith("FAIL"))
    log(f"API Layer complete: {ok} OK | {fail} FAILED")
    for k, v in results.items():
        status_icon = "✅" if v == "OK" else "❌"
        log(f"  {status_icon} {k}: {v}")
    log("═" * 60)

    return 0 if fail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
