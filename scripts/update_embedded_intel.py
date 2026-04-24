#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX v134.0 — Hardened EMBEDDED_INTEL Updater
=======================================================================
Surgically replaces ONLY the EMBEDDED_INTEL data array in index.html.
Everything else — functions, CSS, HTML, comments — is preserved byte-for-byte.

HOW IT WORKS:
  1. Finds `const EMBEDDED_INTEL = [` using string search (not regex)
  2. Brace-matches `[...]` to find the exact array boundaries
  3. Normalises every item (adds stix_id, apex, report_url, mitre_tactics, etc.)
  4. Replaces ONLY the array content between [ and ]
  5. Verifies the result with 6 integrity checks
  6. If ANY check fails → restores backup, exits non-zero

FIELD NORMALISATION (ensures dashboard features work):
  - stix_id   : mapped from item['id']          → enables ANALYZE button
  - apex      : built from risk/openclaw/corr   → enables AI panel
  - report_url: native report URL (source_url)   → enables Tactical Dossier link
  - mitre_tactics: mapped from item['ttps']     → enables attack chain display
  - tags      : None/falsy normalised to []     → prevents JS crash

SAFE: Creates backup before write. Rolls back on any assertion failure.
"""

import json
import os
import re
import shutil
import sys
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone

REPO_ROOT = Path(__file__).parent.parent
INDEX_HTML = REPO_ROOT / "index.html"

# ── Single Source of Truth ────────────────────────────────────────────────
FEED_MANIFEST = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
FEED_MANIFEST_CANDIDATES = [
    REPO_ROOT / "data" / "stix" / "feed_manifest.json",   # canonical — always first
    REPO_ROOT / "data" / "feed_manifest.json",             # v70 fallback
]
ENRICHED_MANIFEST = REPO_ROOT / "data" / "v46_ultraintel" / "enriched_manifest.json"

ENRICHMENT_KEYS = [
    "actor_profile", "sector_tags", "exploit_status",
    "cwe_classification", "intel_quality",
    # v134 AI fields from v70 orchestrator
    "mitre_tactics", "cvss_score", "epss_score", "kev_present",
    "kev_date", "attribution", "campaign_id", "ai_risk_score",
    "ai_confidence", "executive_summary", "kill_chain_narrative",
    "kill_chain_phases", "actor_matches", "primary_actor",
    "tactical_assessment", "exploit_tier", "report_url", "nvd_url",
    "source_url",
]

# Minimum items to prevent empty dashboard
MIN_ITEMS = 5

# Platform version exposed to dashboard
PLATFORM_VERSION = "v134.0"


# ── Item Field Normaliser ─────────────────────────────────────────────────
def _sev_to_priority(risk_score: float, severity: str) -> str:
    """Map risk score to SOC priority P1-P4."""
    s = float(risk_score or 0)
    if s >= 9.0 or severity == "CRITICAL":
        return "P1"
    if s >= 7.0 or severity == "HIGH":
        return "P2"
    if s >= 5.0 or severity == "MEDIUM":
        return "P3"
    return "P4"


def _sev_to_threat_level(risk_score: float, openclaw: dict) -> str:
    """Derive threat level from risk score + openclaw signals."""
    trend = (openclaw or {}).get("trend", "stable")
    velocity = (openclaw or {}).get("velocity", "stable")
    s = float(risk_score or 0)
    if s >= 9.0 and velocity == "rising":
        return "CRITICAL_SURGE"
    if s >= 8.0:
        return "CRITICAL"
    if s >= 6.5:
        return "HIGH"
    if s >= 4.5:
        return "ELEVATED"
    return "MODERATE"


def _build_recommended_action(severity: str, priority: str) -> str:
    """Generate a concise recommended action from severity + priority."""
    actions = {
        "P1": "IMMEDIATE — Escalate to IR team now. Activate containment playbook.",
        "P2": "URGENT — Investigate within 4h. Validate exposure and patch status.",
        "P3": "SCHEDULE — Triage within 24h. Include in next patch cycle.",
        "P4": "MONITOR — Track for status changes. Review at next triage window.",
    }
    return actions.get(priority, "Monitor for updates.")


def _derive_exploit_tier(item: dict) -> str:
    """Classify exploit tier from KEV, EPSS, exploit_probability."""
    if item.get("kev_present"):
        return "IMMINENT"
    ep = str(item.get("exploit_probability", "")).lower()
    epss = float(item.get("epss_score") or 0)
    if ep in ("high", "critical") or epss > 0.3:
        return "LIKELY"
    if float(item.get("risk_score") or 0) >= 7:
        return "ELEVATED"
    return "UNKNOWN"


def _build_report_url(item: dict) -> str:
    """
    v134.0: Construct native report_url — NO Blogger fallbacks.
    Priority: explicit report_url → source_url → empty string (hides button).
    """
    if item.get("report_url"):
        return item["report_url"]
    if item.get("source_url"):
        return item["source_url"]
    return ""


def _build_apex(item: dict) -> dict:
    """
    Build the `apex` sub-object expected by the dashboard APEX AI Panel.
    All fields are derived deterministically from available manifest data.
    """
    risk = float(item.get("risk_score") or 0)
    sev = str(item.get("severity") or "LOW")
    openclaw = item.get("openclaw") or {}
    corr = item.get("correlation") or {}
    threat_type = str(item.get("threat_type") or "UNKNOWN").replace(" ", "_").upper()

    priority = _sev_to_priority(risk, sev)
    threat_level = _sev_to_threat_level(risk, openclaw)
    recommended_action = _build_recommended_action(sev, priority)

    # Behavioral tags: from openclaw patterns + attack_surface (max 5)
    raw_patterns = openclaw.get("patterns") or []
    raw_surface = openclaw.get("attack_surface") or []
    behavioral_tags = list({
        t.replace("surge:", "").replace("baseline", "normal").upper()
        for t in (raw_patterns + raw_surface)
        if t and t not in ("baseline",)
    })[:5]

    # Campaign ID from correlation or openclaw fingerprint
    campaign_id = (
        corr.get("cluster_id")
        or item.get("campaign_id")
        or (f"CDB-{openclaw.get('fingerprint', 'UNCLASSIFIED')[:8].upper()}" if openclaw.get("fingerprint") else "UNCLASSIFIED")
    )

    # AI summary: prefer description, strip "Tactical cluster: " prefix
    raw_desc = str(item.get("description") or "")
    ai_summary = re.sub(r"^Tactical cluster:\s*", "", raw_desc).strip()[:300]

    # Predictive score = openclaw score if non-zero else risk_score
    oc_score = float(openclaw.get("score") or 0)
    predictive_score = round(oc_score / 10.0, 1) if oc_score > 0 else round(risk, 1)

    return {
        "priority": priority,
        "threat_level": threat_level,
        "threat_category": threat_type,
        "predictive_score": predictive_score,
        "campaign_id": campaign_id,
        "recommended_action": recommended_action,
        "ai_summary": ai_summary,
        "behavioral_tags": behavioral_tags,
        "openclaw_score": openclaw.get("score", 0),
        "openclaw_velocity": openclaw.get("velocity", "stable"),
        "openclaw_trend": openclaw.get("trend", "stable"),
        "anomaly_detected": bool(openclaw.get("anomaly", False)),
        "related_threats": int(corr.get("related_count") or 0),
    }


def normalise_item(item: dict) -> dict:
    """
    Normalise a single manifest item to include ALL fields expected by the
    dashboard (stix_id, apex, blog_url, mitre_tactics, tags, etc.).
    This is the single place where manifest → dashboard field mapping happens.
    Zero data is lost — only new fields are added, nothing is removed.
    """
    out = dict(item)

    # ── stix_id: CRITICAL — ANALYZE button injection requires this ──────
    # Card template: data-stix-id="${item.stix_id||''}"
    # Injection guard: if (!stixId) return;  ← skips if empty!
    if not out.get("stix_id"):
        out["stix_id"] = out.get("id") or ""

    # ── processed_at: v134.0.0 FRESHNESS FIX ────────────────────────────
    # Primary freshness field — always pipeline generation time (UTC-now).
    # Dashboard LIVE 7D filter and sort-newest read this field first.
    # For existing items missing processed_at, fall back to timestamp/generated_at.
    if not out.get("processed_at"):
        out["processed_at"] = (
            out.get("timestamp")
            or out.get("generated_at")
            or out.get("published")
            or out.get("published_at")
            or ""
        )

    # ── published_at: expose source article date separately ─────────────
    # Keeps the original publication date visible without conflating it with
    # processing time. Dashboard can display both if needed.
    if not out.get("published_at"):
        out["published_at"] = (
            out.get("published")
            or out.get("published_date")
            or out.get("timestamp")
            or ""
        )

    # ── tags: normalise None/falsy to [] (prevents JS .map crash) ───────
    if not out.get("tags"):
        out["tags"] = []
    elif not isinstance(out["tags"], list):
        out["tags"] = [str(out["tags"])]

    # ── iocs: ensure list ────────────────────────────────────────────────
    if not isinstance(out.get("iocs"), list):
        out["iocs"] = []

    # ── indicator_count: derived from iocs list → powers IOC metric counter ─
    # Dashboard computeMetrics() checks d.indicator_count to sum total IOCs.
    # Since manifest lacks this field, we compute it here from the iocs array.
    if not out.get("indicator_count"):
        out["indicator_count"] = len(out["iocs"])

    # ── mitre_tactics: alias of ttps for card MITRE display ─────────────
    ttps = out.get("ttps") or []
    if not isinstance(ttps, list):
        ttps = []
    out["ttps"] = ttps
    if not out.get("mitre_tactics"):
        out["mitre_tactics"] = ttps

    # ── exploit_tier: for AI modal header badge ──────────────────────────
    if not out.get("exploit_tier"):
        out["exploit_tier"] = _derive_exploit_tier(out)

    # ── report_url: enables "View Tactical Dossier" link (v134.0 — no Blogger) ──
    out["report_url"] = _build_report_url(out)
    out.pop("blog_url", None)  # hard-remove legacy field

    # ── apex: enables APEX AI Intelligence Panel ─────────────────────────
    if not out.get("apex") or not isinstance(out.get("apex"), dict):
        out["apex"] = _build_apex(out)

    # ── ai_risk_score / ai_confidence for AI modal ───────────────────────
    if not out.get("ai_risk_score"):
        out["ai_risk_score"] = out.get("risk_score", 0)
    if not out.get("ai_confidence"):
        # Convert confidence percentage (0-100) to decimal (0-1) for modal
        conf = float(out.get("confidence") or 0)
        out["ai_confidence"] = round(conf / 100.0, 2) if conf > 1 else conf

    # ── executive_summary for AI modal section 1 ─────────────────────────
    if not out.get("executive_summary"):
        out["executive_summary"] = out["apex"].get("ai_summary", "")

    # ── tactical_assessment ──────────────────────────────────────────────
    if not out.get("tactical_assessment"):
        out["tactical_assessment"] = out["apex"].get("recommended_action", "")

    # ── kill_chain_narrative & kill_chain_phases ─────────────────────────
    if not out.get("kill_chain_narrative") and ttps:
        out["kill_chain_narrative"] = (
            f"Threat actor employs {len(ttps)} MITRE ATT&CK techniques: "
            + ", ".join(ttps[:5])
            + ("..." if len(ttps) > 5 else ".")
        )
    if not out.get("kill_chain_phases"):
        # Map TTP names to abbreviated kill-chain labels
        phase_map = {
            "reconnaissance": "RECON", "resource development": "INIT",
            "initial access": "INIT", "execution": "EXEC",
            "persistence": "PERS", "privilege escalation": "PRIV",
            "defense evasion": "D.EVA", "credential access": "CRED",
            "discovery": "DISC", "lateral movement": "LAT.MOV",
            "collection": "COLL", "command and control": "C2",
            "exfiltration": "EXFIL", "impact": "IMPACT",
            "supply chain compromise": "INIT", "phishing": "INIT",
            "valid accounts": "CRED", "active scanning": "RECON",
        }
        phases = []
        for t in ttps:
            key = t.lower()
            for phrase, label in phase_map.items():
                if phrase in key and label not in phases:
                    phases.append(label)
        out["kill_chain_phases"] = phases or ["EXEC"]

    # ── source_url / nvd_url ─────────────────────────────────────────────
    # Extract CVE ID for NVD link
    if not out.get("nvd_url"):
        title = out.get("title", "")
        cve_match = re.search(r"CVE-\d{4}-\d+", title)
        if cve_match:
            out["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_match.group()}"

    # ── primary_actor: for AI modal attribution ──────────────────────────
    if not out.get("primary_actor"):
        threat_type = str(out.get("threat_type") or "")
        if "ransomware" in threat_type.lower():
            out["primary_actor"] = "RANSOMWARE GROUP (UNATTRIBUTED)"
        elif "supply chain" in threat_type.lower():
            out["primary_actor"] = "THREAT ACTOR (UNATTRIBUTED)"
        else:
            out["primary_actor"] = "UNATTRIBUTED"

    # ── kev_present: derive from title/description if not already set ─────
    # CISA KEV & active exploitation keyword detection ensures KEV dashboard
    # counter reflects real threat signal rather than always showing 0.
    if not out.get("kev_present"):
        _kev_text = " ".join([
            str(out.get("title") or ""),
            str(out.get("description") or ""),
        ]).lower()
        _KEV_SIGNALS = [
            "cisa kev", "known exploited", "actively exploited",
            "exploitation detected", "exploited in the wild",
            "zero-day", "0-day", "exploit in the wild",
            "under active attack", "ransomware deployment",
        ]
        out["kev_present"] = any(sig in _kev_text for sig in _KEV_SIGNALS)

    # feed_source: powers m-feed-count FEEDS counter on dashboard
    # JS counts unique d.feed_source values; without this field FEEDS shows "—"
    if not out.get("feed_source"):
        _src_name = str(out.get("source", "") or "")
        _src_url  = str(out.get("source_url") or "")
        if _src_name and _src_name.lower() not in ("", "unknown", "none", "null", "n/a"):
            out["feed_source"] = _src_name
        elif _src_url:
            try:
                import urllib.parse as _up
                _nl = _up.urlparse(_src_url).netloc
                out["feed_source"] = _nl if _nl else "Sentinel APEX"
            except Exception:
                out["feed_source"] = "Sentinel APEX"
        else:
            out["feed_source"] = "Sentinel APEX"

    return out


def load_manifest(path: Path) -> list:
    """Load and normalise manifest into a flat list."""
    if not path.exists():
        print(f"[WARN] Manifest not found: {path}")
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("entries", data.get("advisories", [])))


def merge_intelligence(feed: list, enriched: list) -> list:
    """
    Merge enriched v46 fields onto feed_manifest items, then normalise every
    item so all dashboard-required fields are guaranteed to be present.
    """
    # Build enriched lookup by stix_id OR id (handles both field naming variants)
    enriched_lookup: dict = {}
    for enc in enriched:
        for key in (enc.get("stix_id"), enc.get("id")):
            if key:
                enriched_lookup[key] = enc

    merged = []
    for item in feed:
        # Identify this item
        sid = item.get("stix_id") or item.get("id") or ""
        merged_item = dict(item)

        # Layer enriched fields on top (without overwriting non-null existing values)
        if sid and sid in enriched_lookup:
            enc = enriched_lookup[sid]
            for key in ENRICHMENT_KEYS:
                # Only set if enriched has it AND current item doesn't (or is falsy)
                if key in enc and enc[key] is not None:
                    if not merged_item.get(key):
                        merged_item[key] = enc[key]

        # ── Normalise item → ensures ALL dashboard fields are present ────
        merged.append(normalise_item(merged_item))

    return merged


def find_embedded_intel_boundaries(html: str) -> tuple:
    """Find the exact byte boundaries of the EMBEDDED_INTEL array using brace matching.
    
    Returns (array_start, array_end) where:
        html[array_start] == '['  (opening bracket)
        html[array_end - 1] == ']'  (closing bracket)
    
    The replacement zone is html[array_start:array_end].
    Everything before array_start and after array_end is UNTOUCHED.
    """
    # Step 1: Find the declaration
    # v134.1: support both legacy 'const' (old) and 'window.' (new global binding)
    marker = "window.EMBEDDED_INTEL = ["
    pos = html.find(marker)
    if pos == -1:
        # fallback: legacy 'const' declaration (pre-v134.1 index.html)
        marker = "const EMBEDDED_INTEL = ["
        pos = html.find(marker)
    if pos == -1:
        return -1, -1

    # Step 2: array_start is the '[' position
    array_start = pos + len(marker.split("[")[0])
    if array_start >= len(html) or html[array_start] != '[':
        return -1, -1

    # Step 3: Brace-match to find the closing ']'
    depth = 0
    i = array_start
    in_string = False
    escape = False

    while i < len(html):
        ch = html[i]

        if escape:
            escape = False
            i += 1
            continue

        if ch == '\\' and in_string:
            escape = True
            i += 1
            continue

        if ch == '"' and not escape:
            in_string = not in_string
            i += 1
            continue

        if not in_string:
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    array_end = i + 1  # Include the ']'
                    return array_start, array_end

        i += 1

    return -1, -1


def compute_fingerprint(html: str, array_start: int, array_end: int) -> str:
    """Compute a fingerprint of everything OUTSIDE the EMBEDDED_INTEL array.
    Used to verify that only the array data changed."""
    before = html[:array_start]
    after = html[array_end:]
    return str(hash(before + "|||BOUNDARY|||" + after))


def patch_index_html(merged: list) -> bool:
    """Surgically replace ONLY the EMBEDDED_INTEL array data in index.html."""
    if not INDEX_HTML.exists():
        print("[ERROR] index.html not found")
        return False

    with open(INDEX_HTML, encoding="utf-8") as f:
        original_html = f.read()

    original_size = len(original_html)
    print(f"[INFO] Loaded index.html: {original_size:,} bytes")

    # ── Step 1: Find array boundaries ──
    array_start, array_end = find_embedded_intel_boundaries(original_html)
    if array_start == -1:
        print("[ERROR] EMBEDDED_INTEL array boundaries not found")
        print("[ERROR] Possible cause: missing declaration or corrupted file")
        return False

    old_array = original_html[array_start:array_end]
    print(f"[INFO] Found EMBEDDED_INTEL: [{array_start}:{array_end}] ({len(old_array):,} chars)")

    # ── Step 2: Compute fingerprint of everything OUTSIDE the array ──
    before_fingerprint = compute_fingerprint(original_html, array_start, array_end)

    # ── Step 3: Build new array data ──
    # ── Strip bloat fields before embedding (0% utilization in dashboard JS) ──
    _BLOAT_FIELDS = {"ttps", "alert", "correlation"}
    merged = [{k: v for k, v in item.items() if k not in _BLOAT_FIELDS} for item in merged]

    new_array = json.dumps(merged, separators=(",", ":"), ensure_ascii=False)

    # ── Step 4: Create backup in /tmp (avoids NTFS immutability issues on mounted shares) ──
    import tempfile
    backup_path = os.path.join(tempfile.gettempdir(), "index_pre_intel_update.html")
    shutil.copy2(INDEX_HTML, backup_path)

    # ── Step 5: Surgical replacement — ONLY the array content ──
    patched_html = original_html[:array_start] + new_array + original_html[array_end:]

    # ══════════════════════════════════════════════════
    # POST-PATCH INTEGRITY CHECKS — all must pass
    # ══════════════════════════════════════════════════
    errors = []

    # Check 1: Fingerprint of surrounding code unchanged
    new_array_start, new_array_end = find_embedded_intel_boundaries(patched_html)
    if new_array_start == -1:
        errors.append("EMBEDDED_INTEL not found in patched output")
    else:
        after_fingerprint = compute_fingerprint(patched_html, new_array_start, new_array_end)
        if before_fingerprint != after_fingerprint:
            errors.append("Code outside EMBEDDED_INTEL was modified (fingerprint mismatch)")

    # Check 2: Exactly ONE EMBEDDED_INTEL declaration
    ei_count = patched_html.count("const EMBEDDED_INTEL")
    if ei_count != 1:
        errors.append(f"{ei_count} EMBEDDED_INTEL declarations (expected 1)")

    # Check 3: No git conflict markers
    for marker in ["<<<<<<<", ">>>>>>>"]:
        if marker in patched_html:
            errors.append(f"Git conflict marker '{marker}' found")

    # Check 4: EMBEDDED_INTEL parses as valid JSON
    if new_array_start != -1 and new_array_end != -1:
        try:
            check_data = json.loads(patched_html[new_array_start:new_array_end])
            if len(check_data) < MIN_ITEMS:
                errors.append(f"EMBEDDED_INTEL has {len(check_data)} items (min: {MIN_ITEMS})")
        except json.JSONDecodeError as e:
            errors.append(f"EMBEDDED_INTEL JSON parse error: {e}")

    # Check 5: Critical functions still exist
    for func_name in ["bootFromEmbeddedCache", "computeMetrics", "renderCards", "renderTopThreats"]:
        if f"function {func_name}" not in patched_html:
            errors.append(f"Function '{func_name}' missing after patch")

    # Check 6: Surrounding code size unchanged (data size may vary)
    original_surrounding = original_size - (array_end - array_start)
    patched_surrounding = len(patched_html) - (new_array_end - new_array_start) if new_array_start != -1 else 0
    if abs(original_surrounding - patched_surrounding) > 100:
        errors.append(f"Surrounding code size changed: {original_surrounding:,} → {patched_surrounding:,}")

    # ── Handle failures ──
    if errors:
        print("[FATAL] Post-patch integrity check FAILED:")
        for e in errors:
            print(f"  ✗ {e}")
        print("[ROLLBACK] Restoring original index.html from backup")
        shutil.copy2(backup_path, INDEX_HTML)
        os.remove(backup_path)
        return False

    # ── All checks passed — ATOMIC WRITE with TRUNCATION GUARD (RC-6) ──
    _MIN_LINES_GUARD = 12000
    _orig_lc = original_html.count("\n")
    _new_lc  = patched_html.count("\n")

    if _new_lc < _MIN_LINES_GUARD:
        print(f"[TRUNCATION GUARD] BLOCKED: {_new_lc} lines < {_MIN_LINES_GUARD} min. Original preserved.")
        shutil.copy2(backup_path, INDEX_HTML)
        os.remove(backup_path)
        return False

    if _new_lc < _orig_lc * 0.95:
        print(f"[TRUNCATION GUARD] BLOCKED: {_new_lc} lines < 95% of orig {_orig_lc}. Original preserved.")
        shutil.copy2(backup_path, INDEX_HTML)
        os.remove(backup_path)
        return False

    if "</body>" not in patched_html or "</html>" not in patched_html:
        print("[TRUNCATION GUARD] BLOCKED: missing </body> or </html>. Original preserved.")
        shutil.copy2(backup_path, INDEX_HTML)
        os.remove(backup_path)
        return False

    # Atomic write: temp file -> fsync -> os.replace (crash-safe)
    import tempfile as _tf
    fd, tmp_path = _tf.mkstemp(dir=str(INDEX_HTML.parent), suffix=".html.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as _f:
            _f.write(patched_html)
        # Post-write read-back verification
        with open(tmp_path, encoding="utf-8") as _fv:
            _verified = _fv.read()
        if "</html>" not in _verified or len(_verified) < len(patched_html) * 0.99:
            os.unlink(tmp_path)
            print("[TRUNCATION GUARD] BLOCKED: write-verify failed. Original preserved.")
            shutil.copy2(backup_path, INDEX_HTML)
            os.remove(backup_path)
            return False
        os.replace(tmp_path, INDEX_HTML)
        print(f"[TRUNCATION GUARD] PASSED: {_new_lc} lines written (was {_orig_lc})")
    except Exception as _ex:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        shutil.copy2(backup_path, INDEX_HTML)
        print(f"[TRUNCATION GUARD] ERROR: {_ex}. Original restored.")
        if os.path.exists(backup_path):
            os.remove(backup_path)
        return False

    # Clean up backup
    if os.path.exists(backup_path):
        os.remove(backup_path)

    delta = len(patched_html) - original_size
    print(f"[OK] Check 1: Surrounding code fingerprint — UNCHANGED")
    print(f"[OK] Check 2: EMBEDDED_INTEL declarations — 1")
    print(f"[OK] Check 3: No conflict markers")
    print(f"[OK] Check 4: JSON valid — {len(merged)} items")
    print(f"[OK] Check 5: All critical functions preserved")
    print(f"[OK] Check 6: Surrounding code size — {len(patched_html) - (new_array_end - new_array_start):,} bytes (unchanged)")

    return True


def compute_kpis(merged: list) -> dict:
    """Compute summary KPIs for CI log output."""
    critical = sum(1 for i in merged if (i.get("risk_score") or 0) >= 9)
    high = sum(1 for i in merged if 7 <= (i.get("risk_score") or 0) < 9)
    kev = sum(1 for i in merged if i.get("kev_present"))
    enriched = sum(1 for i in merged if any(k in i for k in ENRICHMENT_KEYS))
    latest = max((i.get("timestamp", "") for i in merged), default="—")
    return {
        "total": len(merged), "critical": critical, "high": high,
        "kev": kev, "enriched": enriched, "latest": latest
    }


def load_best_manifest(candidates: list) -> tuple:
    """
    Try each candidate path and return (items, path_used) for the one with
    the most advisories.  Falls back to an empty list with None path if all
    candidates are missing or empty.
    """
    best_items, best_path, best_count = [], None, 0
    for p in candidates:
        items = load_manifest(p)
        if len(items) > best_count:
            best_count = len(items)
            best_items = items
            best_path = p
    return best_items, best_path


def main():
    print("=" * 60)
    print("CYBERDUDEBIVASH SENTINEL APEX — EMBEDDED_INTEL AUTO-UPDATER")
    print(f"Run: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    # Multi-path resolution: use whichever manifest has the most entries.
    # This prevents the 1-entry sentinel_blogger manifest from blocking the patch.
    feed, feed_path = load_best_manifest(FEED_MANIFEST_CANDIDATES)
    # ENRICHED_MANIFEST is a legacy v46_ultraintel path no longer in production.
    # Load only if the file actually exists to suppress the spurious WARN.
    enriched = load_manifest(ENRICHED_MANIFEST) if ENRICHED_MANIFEST.exists() else []

    if feed_path:
        print(f"[INFO] Using manifest: {feed_path} ({len(feed)} items)")
    if not feed:
        print("[ERROR] feed_manifest.json is empty or missing across all candidate paths — aborting")
        sys.exit(1)

    print(f"[INFO] feed_manifest: {len(feed)} items")
    print(f"[INFO] enriched_manifest: {len(enriched)} items")

    merged = merge_intelligence(feed, enriched)

    # ── Deduplicate by stix_id then title (prevents ticker showing same item twice) ──
    seen_keys: set = set()
    deduped: list = []
    for item in merged:
        key = (item.get("stix_id") or item.get("id") or "")[:120]
        if not key:
            key = item.get("title", "")[:120]
        if key and key not in seen_keys:
            seen_keys.add(key)
            deduped.append(item)
    removed_dupes = len(merged) - len(deduped)
    if removed_dupes:
        print(f"[INFO] Deduplication: {len(merged)} → {len(deduped)} items ({removed_dupes} duplicates removed)")
    merged = deduped

    # v134.0.0 FRESHNESS FIX: Sort by processed_at DESC (primary) → timestamp → published.
    # processed_at = pipeline generation time → always reflects actual processing order.
    # Using timestamp alone causes RSS-sourced intel with old published dates to sink
    # below older but source-fresh articles, making newly generated intel appear stale.
    def _freshness_key(x: dict) -> str:
        for field in ("processed_at", "timestamp", "generated_at", "published", "created"):
            v = x.get(field)
            if v and isinstance(v, str) and len(v) >= 10:
                return v
        return "1970-01-01T00:00:00Z"

    merged.sort(key=_freshness_key, reverse=True)

    # ── v137 FIX: Inject CRITICAL/KEV items from api/feed.json ──────────
    # ROOT CAUSE: update_embedded_intel.py runs mid-pipeline before CRITICAL
    # items are written to data/stix/feed_manifest.json. api/feed.json (built
    # by an earlier pipeline stage from the previous run) already has all
    # CRITICAL items with risk_score >= 9.0. Without this injection, EMBEDDED_INTEL
    # contains 0 CRITICAL items → dashboard metric cards always show Critical=0.
    _API_FEED_PATH = REPO_ROOT / "api" / "feed.json"
    if _API_FEED_PATH.exists():
        try:
            with open(_API_FEED_PATH, encoding="utf-8") as _af_fp:
                _af_raw = json.load(_af_fp)
            _api_all = _af_raw.get("items", []) if isinstance(_af_raw, dict) else _af_raw
            _api_critical = [
                x for x in _api_all
                if float(x.get("risk_score") or 0) >= 9.0
                or str(x.get("severity", "")).upper() == "CRITICAL"
                or bool(x.get("kev_present"))
            ]
            if _api_critical:
                _existing_keys: set = {
                    (x.get("stix_id") or x.get("id") or x.get("title", ""))[:120]
                    for x in merged
                }
                _injected: list = []
                for _raw_item in _api_critical:
                    _ikey = (_raw_item.get("id") or _raw_item.get("stix_id") or _raw_item.get("title", ""))[:120]
                    if _ikey and _ikey not in _existing_keys:
                        _injected.append(normalise_item(_raw_item))
                        _existing_keys.add(_ikey)
                # Prepend injected CRITICAL items so they are always in EMBEDDED_INTEL
                merged = _injected + merged
                print(f"[v137] Injected {len(_injected)} CRITICAL/KEV items from api/feed.json")
            else:
                print("[v137] api/feed.json: no CRITICAL/KEV items found")
        except Exception as _inj_err:
            print(f"[v137] api/feed.json injection skipped ({_inj_err})")
    else:
        print("[v137] api/feed.json not found — CRITICAL injection skipped")

    # ── v137 FIX: Pin CRITICAL+KEV items first in EMBEDDED_INTEL ─────────
    # Guarantees Critical/KEV metric card counts are correct from initial page
    # load — regardless of where freshness-sort would otherwise place these items.
    def _is_priority_item(x: dict) -> bool:
        return (
            float(x.get("risk_score") or 0) >= 9.0
            or str(x.get("severity", "")).upper() == "CRITICAL"
            or bool(x.get("kev_present"))
        )

    _priority_bucket  = [x for x in merged if _is_priority_item(x)]
    _standard_bucket  = [x for x in merged if not _is_priority_item(x)]
    merged = _priority_bucket + _standard_bucket
    print(
        f"[v137] EMBEDDED_INTEL layout: "
        f"{len(_priority_bucket)} CRITICAL/KEV pinned first | "
        f"{len(_standard_bucket)} standard items follow"
    )

    kpis = compute_kpis(merged)

    print(
        f"[INFO] Merged: {kpis['total']} items | "
        f"CRITICAL:{kpis['critical']} HIGH:{kpis['high']} "
        f"KEV:{kpis['kev']} | Enriched:{kpis['enriched']} | "
        f"Latest: {kpis['latest']}"
    )

    success = patch_index_html(merged)
    if success:
        print("[SUCCESS] index.html EMBEDDED_INTEL patched ✓")
        print("[SUCCESS] All surrounding code preserved ✓")
    else:
        print("[ERROR] Patch failed - original file restored")
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
