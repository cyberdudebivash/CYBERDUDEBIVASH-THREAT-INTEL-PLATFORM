#!/usr/bin/env python3
"""
SENTINEL APEX v103.0 — Intel Validation Gate
═════════════════════════════════════════════
ARCHITECTURE: ADDITIVE ONLY. Does NOT touch feed_manifest.json.
Reads the authoritative manifest + queue files → writes validated_manifest.json.

Pipeline position: ENRICH → VALIDATE (this script) → APEX-ENGINE → BLOG → MANIFEST → DASHBOARD

Responsibilities:
  1. Load all pending/failed items from queue files (exclusion set).
  2. Tag every manifest item as status="published" or status="pending".
  3. [v103] Run APEX validation checks: evidence, confidence, SOC context (gate-controlled).
  4. Write data/validated_manifest.json  — source of truth for dashboard + API.
  5. Write data/health/validation_report.json  — observability + audit trail.

Feature-flag controlled (v102 flags — unchanged):
  ENABLE_VALIDATION_GATE   — master switch (default: true)
  STRICT_VALIDATION        — reject items with missing content threshold (default: false)
  QUEUE_AUTHORITATIVE      — exclude pending items from validated manifest (default: true)
  DASHBOARD_FILTERING      — sets 'dashboard_visible' field on each item (default: true)
  MIN_CONTENT_THRESHOLD    — min description char length for STRICT mode (default: 50)

Feature-flag controlled (v103 APEX v1 additions — all default False for zero-regression):
  ENABLE_APEX_VALIDATION          — master switch for APEX v1 validation checks (default: false)
  APEX_REQUIRE_EVIDENCE_GATE      — reject items with LOW evidence reliability (default: false)
  APEX_REQUIRE_CONFIDENCE_GATE    — reject items with LOW detection confidence (default: false)
  APEX_REQUIRE_SOC_GATE           — reject items missing SOC context block (default: false)
  APEX_MIN_EVIDENCE_SCORE         — minimum raw evidence confidence score (default: 0)

Feature-flag controlled (v104 APEX v2 additions — all default False for zero-regression):
  APEX_V2_REQUIRE_PRIORITY_GATE   — reject items missing threat_priority block (default: false)
  APEX_V2_REQUIRE_TIMELINE_GATE   — reject items missing threat_timeline block (default: false)
  APEX_V2_REQUIRE_FEEDBACK_GATE   — reject items with LOW intelligence_maturity (default: false)
  APEX_V2_MIN_PRIORITY_SCORE      — minimum composite priority score threshold (default: 0)
  APEX_V2_STRICT_LIFECYCLE        — reject items with invalid lifecycle_stage (default: false)

Zero-regression guarantee:
  If BOTH queue files are empty/missing → all items receive status="published".
  If QUEUE_AUTHORITATIVE=false → all items pass regardless of queue membership.
  All v103 APEX checks default to False — no behavior change on existing deployments.

Outputs:
  data/validated_manifest.json       — filtered manifest (published items only when QUEUE_AUTHORITATIVE=true)
  data/health/validation_report.json — full audit report with per-item status
"""

import json
import hashlib
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ── Repo root resolution ────────────────────────────────────────────────────
_THIS = Path(__file__).resolve()
REPO  = _THIS.parent.parent

# ── Paths ────────────────────────────────────────────────────────────────────
MANIFEST_CANDIDATES = [
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "v101_manifest.json",
    REPO / "data" / "enriched_manifest.json",
]
QUEUE_FILES = [
    REPO / "data" / "blog_queue" / "pending_posts.json",
    REPO / "data" / "pending_publish.json",
    REPO / "data" / "publish_queue.json",
]
FEATURE_FLAGS_PATH     = REPO / "config" / "feature_flags.json"
VALIDATED_MANIFEST     = REPO / "data" / "validated_manifest.json"
VALIDATION_REPORT      = REPO / "data" / "health" / "validation_report.json"

# ── Logging ──────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [VALIDATION-GATE] [{level}] {msg}", flush=True)

# ── Feature flags ─────────────────────────────────────────────────────────────
def load_flags() -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        # v102 flags (unchanged)
        "ENABLE_VALIDATION_GATE":  True,
        "STRICT_VALIDATION":       False,
        "QUEUE_AUTHORITATIVE":     True,
        "DASHBOARD_FILTERING":     True,
        "MIN_CONTENT_THRESHOLD":   50,
        # v103 APEX v1 validation flags (all default False — zero-regression guarantee)
        "ENABLE_APEX_VALIDATION":       False,
        "APEX_REQUIRE_EVIDENCE_GATE":   False,
        "APEX_REQUIRE_CONFIDENCE_GATE": False,
        "APEX_REQUIRE_SOC_GATE":        False,
        "APEX_MIN_EVIDENCE_SCORE":      0,
        # v104 APEX v2 Evolution Engine validation flags (all default False — zero-regression guarantee)
        "APEX_V2_REQUIRE_PRIORITY_GATE":  False,
        "APEX_V2_REQUIRE_TIMELINE_GATE":  False,
        "APEX_V2_REQUIRE_FEEDBACK_GATE":  False,
        "APEX_V2_MIN_PRIORITY_SCORE":     0,
        "APEX_V2_STRICT_LIFECYCLE":       False,
    }
    try:
        raw = json.loads(FEATURE_FLAGS_PATH.read_text(encoding="utf-8"))
        defaults.update(raw)
    except Exception as e:
        log(f"Feature flags load failed ({e}) — using defaults", "WARN")
    return defaults

# ── Atomic write helper ───────────────────────────────────────────────────────
def atomic_write_json(path: Path, obj: Any, indent: int = 2) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    try:
        content = json.dumps(obj, ensure_ascii=False, indent=indent)
        tmp.write_text(content, encoding="utf-8")
        shutil.move(str(tmp), str(path))
        return path.stat().st_size
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise

# ── Manifest loader ───────────────────────────────────────────────────────────
def load_manifest() -> List[Dict]:
    for path in MANIFEST_CANDIDATES:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            entries: List[Dict] = []
            if isinstance(raw, list):
                entries = raw
            else:
                for key in ("advisories", "entries", "items", "data"):
                    v = raw.get(key)
                    if isinstance(v, list) and v:
                        entries = v
                        break
            if entries:
                log(f"Manifest loaded: {len(entries)} entries from {path.name}")
                return entries
        except Exception as e:
            log(f"Manifest parse error ({path.name}): {e}", "WARN")
    log("No manifest found — returning empty list", "WARN")
    return []

# ── Queue loader: build exclusion set ────────────────────────────────────────
def _item_fingerprints(item: Dict) -> Set[str]:
    """Return all identifier strings for a queue item (covers v74 + legacy schemas)."""
    fps: Set[str] = set()

    # Primary identifiers
    for field in ("id", "stix_id", "stix_object_id"):
        v = item.get(field)
        if v and isinstance(v, str) and v.strip():
            fps.add(v.strip())

    # Title-based fingerprint (normalised lowercase hash)
    title = item.get("title", "")
    if title and isinstance(title, str) and title.strip():
        fps.add("title:" + hashlib.sha1(title.strip().lower().encode()).hexdigest())

    return fps


def load_exclusion_set() -> Set[str]:
    """
    Read all queue files and return a set of identifiers that are pending / failed.
    Empty queue = zero exclusions (zero-regression guarantee).
    """
    exclusions: Set[str] = set()
    total_queue_items = 0

    for qpath in QUEUE_FILES:
        if not qpath.exists():
            log(f"Queue file not found (skipped): {qpath.name}", "DEBUG" if True else "WARN")
            continue
        try:
            raw = json.loads(qpath.read_text(encoding="utf-8"))
            items: List[Dict] = []
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, dict):
                for key in ("pending", "items", "entries", "queue"):
                    v = raw.get(key)
                    if isinstance(v, list):
                        items = v
                        break
            total_queue_items += len(items)
            for item in items:
                exclusions.update(_item_fingerprints(item))
            log(f"Queue '{qpath.name}': {len(items)} pending items → {len(exclusions)} exclusion fingerprints so far")
        except Exception as e:
            log(f"Queue parse error ({qpath.name}): {e}", "WARN")

    if total_queue_items == 0:
        log("All queue files empty — zero exclusions (all items treated as published)")
    else:
        log(f"Exclusion set: {len(exclusions)} fingerprints from {total_queue_items} total queue items")

    return exclusions


# ── Validation: isValidIntel ──────────────────────────────────────────────────
def is_valid_intel(item: Dict, flags: Dict) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, reason: str).
    Enforces: non-empty identifier, non-empty title, content threshold (STRICT only).
    """
    # Must have a non-empty identifier
    ident = item.get("stix_id") or item.get("id") or ""
    if not ident.strip():
        return False, "missing_identifier"

    # Must have a non-empty title
    title = item.get("title") or ""
    if not title.strip():
        return False, "missing_title"

    # Strict mode: description must meet minimum content threshold
    if flags.get("STRICT_VALIDATION"):
        threshold = int(flags.get("MIN_CONTENT_THRESHOLD", 50))
        desc = item.get("description") or ""
        if len(desc.strip()) < threshold:
            return False, f"content_below_threshold_{threshold}"

    return True, "ok"


# ── Core: classify items ──────────────────────────────────────────────────────
def classify_manifest(
    entries: List[Dict],
    exclusions: Set[str],
    flags: Dict,
) -> tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Tag each entry with 'status', 'validation_reason', 'dashboard_visible'.
    v103: Also applies APEX v1 validation tagging (additive — never blocks unless flag enabled).
    v104: Also applies APEX v2 Evolution tagging (additive — never blocks unless v2 flags enabled).
    Returns (published, pending, invalid) lists.
    """
    published: List[Dict] = []
    pending:   List[Dict] = []
    invalid:   List[Dict] = []

    dashboard_filtering  = flags.get("DASHBOARD_FILTERING", True)
    queue_authoritative  = flags.get("QUEUE_AUTHORITATIVE", True)
    apex_enabled         = flags.get("ENABLE_APEX_VALIDATION", False)
    apex_v2_any_gate     = (
        flags.get("APEX_V2_REQUIRE_PRIORITY_GATE", False) or
        flags.get("APEX_V2_REQUIRE_TIMELINE_GATE", False) or
        flags.get("APEX_V2_REQUIRE_FEEDBACK_GATE", False) or
        flags.get("APEX_V2_STRICT_LIFECYCLE", False)
    )

    for item in entries:
        # ── Step 1: structural validity (v102 — unchanged) ───────────────────
        valid, reason = is_valid_intel(item, flags)
        if not valid:
            item["status"]            = "invalid"
            item["validation_reason"] = reason
            item["dashboard_visible"] = False
            invalid.append(item)
            continue

        # ── Step 2: queue exclusion check (v102 — unchanged) ─────────────────
        item_fps = _item_fingerprints(item)
        in_queue = bool(item_fps & exclusions)

        if in_queue and queue_authoritative:
            item["status"]            = "pending"
            item["validation_reason"] = "in_queue"
            item["dashboard_visible"] = False
            pending.append(item)
            continue

        # ── Step 3: APEX v1 intelligence quality gate (v103 — additive) ──────
        # Only rejects items when ENABLE_APEX_VALIDATION=true AND specific gates enabled.
        # Default behavior: always passes, just tags the item.
        apex_tag_item(item)  # Always tag — never blocks
        if apex_enabled:
            apex_passes, apex_reason = apex_validate_item(item, flags)
            if not apex_passes:
                item["status"]            = "invalid"
                item["validation_reason"] = apex_reason
                item["dashboard_visible"] = False
                invalid.append(item)
                continue

        # ── Step 4: APEX v2 Evolution quality gate (v104 — additive) ─────────
        # Only rejects items when APEX_V2_REQUIRE_* flags are explicitly enabled.
        # Default behavior: always passes, just tags the item with v2 status.
        apex_v2_tag_item(item)  # Always tag — never blocks
        if apex_v2_any_gate:
            v2_passes, v2_reason = apex_v2_validate_item(item, flags)
            if not v2_passes:
                item["status"]            = "invalid"
                item["validation_reason"] = v2_reason
                item["dashboard_visible"] = False
                invalid.append(item)
                continue

        item["status"]            = "published"
        item["validation_reason"] = "ok"
        item["dashboard_visible"] = dashboard_filtering
        published.append(item)

    return published, pending, invalid


# ── v103 APEX Validation (ADDITIVE — only runs when ENABLE_APEX_VALIDATION=true) ────
def apex_validate_item(item: Dict, flags: Dict) -> tuple[bool, str]:
    """
    v103 APEX intelligence quality gate.
    Returns (passes: bool, reason: str).
    Only enforced when the specific APEX_REQUIRE_* flag is True.
    Each check is independent — a single failing check produces a specific reason code.

    Zero-regression guarantee:
      All APEX_REQUIRE_* flags default to False in load_flags().
      If ENABLE_APEX_VALIDATION=false (default), this function always returns (True, "apex_gate_disabled").
    """
    if not flags.get("ENABLE_APEX_VALIDATION", False):
        return True, "apex_gate_disabled"

    # ── Evidence validation gate ──────────────────────────────────────────────
    if flags.get("APEX_REQUIRE_EVIDENCE_GATE", False):
        ev = item.get("evidence_validation")
        if ev is None:
            return False, "apex_missing_evidence_validation"
        if ev.get("reliability_score") == "LOW":
            return False, "apex_evidence_reliability_low"
        min_score = int(flags.get("APEX_MIN_EVIDENCE_SCORE", 0))
        if min_score > 0 and (ev.get("raw_confidence_score") or 0) < min_score:
            return False, f"apex_evidence_score_below_{min_score}"

    # ── Detection confidence gate ─────────────────────────────────────────────
    if flags.get("APEX_REQUIRE_CONFIDENCE_GATE", False):
        det = item.get("detection_confidence")
        if det is None:
            return False, "apex_missing_detection_confidence"
        if det.get("confidence") == "LOW":
            return False, "apex_detection_confidence_low"

    # ── SOC context gate ──────────────────────────────────────────────────────
    if flags.get("APEX_REQUIRE_SOC_GATE", False):
        soc = item.get("soc_context")
        if not soc:
            return False, "apex_missing_soc_context"
        if not soc.get("required_log_sources"):
            return False, "apex_soc_missing_log_sources"

    return True, "apex_ok"


# ── v103 APEX enrichment tagger (ADDITIVE — safe to call even without apex enrichment) ──
def apex_tag_item(item: Dict) -> Dict:
    """
    Tag an item with apex_validation_status based on the presence of APEX enrichment fields.
    Additive only — never removes or modifies existing fields.
    Called in classify_manifest to add apex metadata to each item.
    """
    has_evidence   = bool(item.get("evidence_validation"))
    has_confidence = bool(item.get("detection_confidence"))
    has_soc        = bool(item.get("soc_context"))
    has_executive  = bool(item.get("executive_summary"))
    has_analyst    = bool(item.get("analyst_insight"))
    has_revenue    = bool(item.get("revenue_metadata"))
    has_compliance = bool(item.get("compliance_block"))

    modules_present = sum([
        has_evidence, has_confidence, has_soc,
        has_executive, has_analyst, has_revenue, has_compliance
    ])

    if modules_present == 7:
        apex_status = "GOD_LEVEL"
    elif modules_present >= 5:
        apex_status = "ENRICHED"
    elif modules_present >= 2:
        apex_status = "PARTIAL"
    elif modules_present >= 1:
        apex_status = "MINIMAL"
    else:
        apex_status = "UNENRICHED"

    item["apex_validation_status"] = apex_status
    item["apex_modules_present"]   = modules_present
    return item


# ── v104 APEX v2 Validation (ADDITIVE — only runs when APEX_V2_REQUIRE_* flags true) ───
_VALID_LIFECYCLE_STAGES = {"EMERGING", "ACTIVE", "PEAK", "DECLINING", "HISTORICAL"}

def apex_v2_validate_item(item: Dict, flags: Dict) -> tuple:
    """
    v104 APEX v2 Evolution Engine quality gate.
    Returns (passes: bool, reason: str).

    Only enforced when the specific APEX_V2_REQUIRE_* flag is True.
    Each check is independent — failing check returns a specific reason code.

    Zero-regression guarantee:
      All APEX_V2_REQUIRE_* flags default to False in load_flags().
      If all flags are False (default), this function always returns (True, "apex_v2_gate_disabled").
    """
    any_gate = (
        flags.get("APEX_V2_REQUIRE_PRIORITY_GATE", False) or
        flags.get("APEX_V2_REQUIRE_TIMELINE_GATE", False) or
        flags.get("APEX_V2_REQUIRE_FEEDBACK_GATE", False) or
        flags.get("APEX_V2_STRICT_LIFECYCLE", False)
    )
    if not any_gate:
        return True, "apex_v2_gate_disabled"

    # ── Threat priority gate ──────────────────────────────────────────────────
    if flags.get("APEX_V2_REQUIRE_PRIORITY_GATE", False):
        tp = item.get("threat_priority")
        if tp is None:
            return False, "apex_v2_missing_threat_priority"
        min_score = int(flags.get("APEX_V2_MIN_PRIORITY_SCORE", 0))
        if min_score > 0:
            raw_score = tp.get("score") or tp.get("priority_score") or 0
            if int(raw_score) < min_score:
                return False, f"apex_v2_priority_score_below_{min_score}"

    # ── Threat timeline gate ──────────────────────────────────────────────────
    if flags.get("APEX_V2_REQUIRE_TIMELINE_GATE", False):
        tt = item.get("threat_timeline")
        if tt is None:
            return False, "apex_v2_missing_threat_timeline"
        if not tt.get("lifecycle_stage"):
            return False, "apex_v2_timeline_missing_lifecycle_stage"

    # ── Feedback/learning gate ────────────────────────────────────────────────
    if flags.get("APEX_V2_REQUIRE_FEEDBACK_GATE", False):
        fb = item.get("feedback_signal")
        if fb is None:
            return False, "apex_v2_missing_feedback_signal"
        maturity = (fb.get("intelligence_maturity") or "").upper()
        # Engine maturity vocabulary: MATURE > VALIDATED > DEVELOPING > RAW
        # "RAW" = lowest quality state; also reject legacy "LOW" for compat
        if maturity in ("RAW", "LOW"):
            return False, "apex_v2_feedback_maturity_raw"

    # ── Strict lifecycle stage gate ───────────────────────────────────────────
    if flags.get("APEX_V2_STRICT_LIFECYCLE", False):
        tt = item.get("threat_timeline") or {}
        stage = (tt.get("lifecycle_stage") or "").upper()
        if stage and stage not in _VALID_LIFECYCLE_STAGES:
            return False, f"apex_v2_invalid_lifecycle_stage:{stage}"

    return True, "apex_v2_ok"


def apex_v2_tag_item(item: Dict) -> Dict:
    """
    Tag an item with apex_v2_validation_status based on the presence of APEX v2 enrichment fields.
    Additive only — never removes or modifies existing fields.
    Called in classify_manifest to add v2 metadata to each item.

    Status levels:
      PRIORITY_INTEL  — all 3 v2 blocks present (threat_priority + threat_timeline + feedback_signal)
      TEMPORAL_INTEL  — priority + timeline present (missing feedback)
      PRIORITY_ONLY   — only threat_priority present
      UNENRICHED_V2   — no v2 enrichment blocks present
    """
    has_priority = bool(item.get("threat_priority"))
    has_timeline = bool(item.get("threat_timeline"))
    has_feedback = bool(item.get("feedback_signal"))

    v2_modules = sum([has_priority, has_timeline, has_feedback])

    if v2_modules == 3:
        v2_status = "PRIORITY_INTEL"
    elif has_priority and has_timeline:
        v2_status = "TEMPORAL_INTEL"
    elif has_priority:
        v2_status = "PRIORITY_ONLY"
    else:
        v2_status = "UNENRICHED_V2"

    item["apex_v2_validation_status"] = v2_status
    item["apex_v2_modules_present"]   = v2_modules
    return item


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    flags = load_flags()

    if not flags.get("ENABLE_VALIDATION_GATE", True):
        log("ENABLE_VALIDATION_GATE=false — gate bypassed, writing full manifest as-is")
        entries = load_manifest()
        # Tag all as published with no filtering
        for e in entries:
            e.setdefault("status", "published")
            e.setdefault("dashboard_visible", True)
            e.setdefault("validation_reason", "gate_disabled")
        sz = atomic_write_json(VALIDATED_MANIFEST, entries)
        log(f"Wrote {VALIDATED_MANIFEST.name}: {len(entries)} items | {sz:,} bytes (gate disabled)")
        return 0

    log("Validation gate ACTIVE — loading manifest and queues")
    entries    = load_manifest()
    exclusions = load_exclusion_set()

    published, pending, invalid = classify_manifest(entries, exclusions, flags)

    total    = len(entries)
    pub_ct   = len(published)
    pend_ct  = len(pending)
    inv_ct   = len(invalid)

    log(f"Classification: {pub_ct} published | {pend_ct} pending | {inv_ct} invalid (total={total})")

    # ── Write validated_manifest.json ────────────────────────────────────────
    # Contains ONLY published items when QUEUE_AUTHORITATIVE=true
    output_entries = published if flags.get("QUEUE_AUTHORITATIVE", True) else entries
    sz = atomic_write_json(VALIDATED_MANIFEST, output_entries)
    log(f"Wrote validated_manifest.json: {len(output_entries)} items | {sz:,} bytes")

    # ── v103: APEX v1 enrichment quality stats (additive — always computed) ──
    apex_god_level = sum(1 for e in published if e.get("apex_validation_status") == "GOD_LEVEL")
    apex_enriched  = sum(1 for e in published if e.get("apex_validation_status") == "ENRICHED")
    apex_partial   = sum(1 for e in published if e.get("apex_validation_status") == "PARTIAL")
    apex_unenriched= sum(1 for e in published if e.get("apex_validation_status") == "UNENRICHED")

    # ── v104: APEX v2 Evolution Engine quality stats (additive — always computed) ──
    v2_priority_intel = sum(1 for e in published if e.get("apex_v2_validation_status") == "PRIORITY_INTEL")
    v2_temporal_intel = sum(1 for e in published if e.get("apex_v2_validation_status") == "TEMPORAL_INTEL")
    v2_priority_only  = sum(1 for e in published if e.get("apex_v2_validation_status") == "PRIORITY_ONLY")
    v2_unenriched     = sum(1 for e in published if e.get("apex_v2_validation_status") == "UNENRICHED_V2")

    # ── Write validation_report.json ─────────────────────────────────────────
    report = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "gate_version":      "104.0",
        "platform":          "CYBERDUDEBIVASH SENTINEL APEX",
        "flags": {
            "ENABLE_VALIDATION_GATE": flags.get("ENABLE_VALIDATION_GATE"),
            "STRICT_VALIDATION":      flags.get("STRICT_VALIDATION"),
            "QUEUE_AUTHORITATIVE":    flags.get("QUEUE_AUTHORITATIVE"),
            "DASHBOARD_FILTERING":    flags.get("DASHBOARD_FILTERING"),
            "MIN_CONTENT_THRESHOLD":  flags.get("MIN_CONTENT_THRESHOLD"),
            # v103 APEX v1 flags
            "ENABLE_APEX_VALIDATION":       flags.get("ENABLE_APEX_VALIDATION"),
            "APEX_REQUIRE_EVIDENCE_GATE":   flags.get("APEX_REQUIRE_EVIDENCE_GATE"),
            "APEX_REQUIRE_CONFIDENCE_GATE": flags.get("APEX_REQUIRE_CONFIDENCE_GATE"),
            "APEX_REQUIRE_SOC_GATE":        flags.get("APEX_REQUIRE_SOC_GATE"),
            # v104 APEX v2 flags
            "APEX_V2_REQUIRE_PRIORITY_GATE": flags.get("APEX_V2_REQUIRE_PRIORITY_GATE"),
            "APEX_V2_REQUIRE_TIMELINE_GATE": flags.get("APEX_V2_REQUIRE_TIMELINE_GATE"),
            "APEX_V2_REQUIRE_FEEDBACK_GATE": flags.get("APEX_V2_REQUIRE_FEEDBACK_GATE"),
            "APEX_V2_MIN_PRIORITY_SCORE":    flags.get("APEX_V2_MIN_PRIORITY_SCORE"),
            "APEX_V2_STRICT_LIFECYCLE":      flags.get("APEX_V2_STRICT_LIFECYCLE"),
        },
        "summary": {
            "total_input":   total,
            "published":     pub_ct,
            "pending":       pend_ct,
            "invalid":       inv_ct,
            "pass_rate_pct": round(pub_ct / total * 100, 2) if total else 0.0,
            "queue_files_checked": [str(q) for q in QUEUE_FILES if q.exists()],
        },
        # v103: APEX v1 enrichment quality breakdown (additive — no gate impact by default)
        "apex_quality_summary": {
            "god_level_enriched":  apex_god_level,
            "enriched":            apex_enriched,
            "partial":             apex_partial,
            "unenriched":          apex_unenriched,
            "enrichment_rate_pct": round((apex_god_level + apex_enriched) / max(pub_ct, 1) * 100, 1),
            "apex_gate_active":    flags.get("ENABLE_APEX_VALIDATION", False),
        },
        # v104: APEX v2 Evolution Engine quality breakdown (additive — no gate impact by default)
        "apex_v2_quality_summary": {
            "priority_intel":     v2_priority_intel,
            "temporal_intel":     v2_temporal_intel,
            "priority_only":      v2_priority_only,
            "unenriched_v2":      v2_unenriched,
            "v2_enrichment_rate_pct": round(
                (v2_priority_intel + v2_temporal_intel) / max(pub_ct, 1) * 100, 1
            ),
            "apex_v2_gate_active": (
                flags.get("APEX_V2_REQUIRE_PRIORITY_GATE", False) or
                flags.get("APEX_V2_REQUIRE_TIMELINE_GATE", False) or
                flags.get("APEX_V2_REQUIRE_FEEDBACK_GATE", False)
            ),
        },
        "invalid_items": [
            {
                "id":    e.get("stix_id") or e.get("id", ""),
                "title": e.get("title", ""),
                "reason": e.get("validation_reason", ""),
            }
            for e in invalid
        ],
        "pending_items": [
            {
                "id":    e.get("stix_id") or e.get("id", ""),
                "title": e.get("title", ""),
            }
            for e in pending
        ],
    }
    rz = atomic_write_json(VALIDATION_REPORT, report)
    log(f"Wrote validation_report.json: {rz:,} bytes")

    # ── Exit code: fail only if STRICT_VALIDATION and invalid items exist ────
    if flags.get("STRICT_VALIDATION") and inv_ct > 0:
        log(f"STRICT_VALIDATION: {inv_ct} invalid items found — exit 1", "ERROR")
        return 1

    log("Validation gate complete ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
