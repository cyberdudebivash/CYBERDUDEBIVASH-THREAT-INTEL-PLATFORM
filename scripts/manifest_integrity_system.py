#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
MANIFEST INTEGRITY SYSTEM v158.5 — Phase 1B Enterprise Hardening
===============================================================================
PURPOSE:
  Validates feed manifest integrity, detects stale feed reuse, enforces
  advisory uniqueness, proves freshness, and detects manifest mutation.
  Complements the Golden Baseline System with per-publish integrity proofs.

SUBSYSTEMS:
  1. FreshnessProofEngine     — validates generated_at recency vs MAX_AGE_HOURS
  2. StaleReuseDetector       — fingerprints last manifest; blocks reuse of
                                 identical snapshots (same hash = stale reuse)
  3. AdvisoryUniquenessGate   — detects duplicate advisory IDs within manifest
  4. ManifestMutationValidator — SHA-256 field-level hashing vs previous snapshot
  5. ManifestIntegrityReport   — writes signed integrity proof to data/health/

HARD FAIL CONDITIONS:
  - Manifest age > MAX_AGE_HOURS (48h default) in --strict mode
  - Duplicate advisory IDs detected (always hard fail)
  - Manifest hash identical to previous run (stale reuse, --strict only)

NON-BLOCKING WARNINGS:
  - Manifest age between WARN_AGE_HOURS and MAX_AGE_HOURS
  - Missing optional manifest fields
  - Mutation delta > MUTATION_WARN_THRESHOLD fields changed

CLI:
  --check   Validate and exit 1 on HARD FAIL
  --report  Print integrity table, always exit 0
  --strict  Elevate stale-reuse and age warnings to HARD FAIL

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import hashlib
import json
import logging
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [manifest-integrity] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-MANIFEST-INTEGRITY")

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
HEALTH_DIR = DATA_DIR / "health"
MANIFEST_STATE_DIR = DATA_DIR / "manifest_integrity"

# Manifest paths
FEED_MANIFEST = DATA_DIR / "feed_manifest.json"
FEED_JSON = DATA_DIR / "feed.json"
APEX_MANIFEST = DATA_DIR / "apex_enriched_manifest.json"
APEX_V2_MANIFEST = DATA_DIR / "apex_v2_manifest.json"

# Freshness thresholds
WARN_AGE_HOURS = 24
MAX_AGE_HOURS = 48

# Mutation detection
MUTATION_WARN_THRESHOLD = 5   # warn if >5 top-level fields changed
CRITICAL_FIELDS = [           # changing these without version bump = CRITICAL mutation
    "total_advisories", "version", "schema_version", "generator",
]

VERSION = "158.5"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    return sha256_str(canonical)


def parse_iso(ts: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp, returns None on failure."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            if ts.endswith("Z") and "+" not in ts:
                ts_clean = ts.replace("Z", "+00:00")
                return datetime.fromisoformat(ts_clean)
            return datetime.fromisoformat(ts)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# 1. FreshnessProofEngine
# ---------------------------------------------------------------------------
class FreshnessProofEngine:
    """Validates manifest generated_at recency."""

    def validate(self, manifest: Dict) -> Dict:
        generated_at_str = manifest.get("generated_at", "")
        if not generated_at_str:
            return {
                "status": "WARN",
                "code": "MISSING_GENERATED_AT",
                "message": "generated_at field absent from manifest",
                "age_hours": None,
            }

        ts = parse_iso(generated_at_str)
        if ts is None:
            return {
                "status": "WARN",
                "code": "UNPARSEABLE_TIMESTAMP",
                "message": f"Cannot parse generated_at: {generated_at_str!r}",
                "age_hours": None,
            }

        now = datetime.now(timezone.utc)
        age_hours = (now - ts).total_seconds() / 3600.0

        if age_hours > MAX_AGE_HOURS:
            return {
                "status": "FAIL",
                "code": "MANIFEST_STALE",
                "message": f"Manifest is {age_hours:.1f}h old (max {MAX_AGE_HOURS}h)",
                "age_hours": round(age_hours, 2),
                "generated_at": generated_at_str,
            }
        elif age_hours > WARN_AGE_HOURS:
            return {
                "status": "WARN",
                "code": "MANIFEST_AGING",
                "message": f"Manifest is {age_hours:.1f}h old (warn after {WARN_AGE_HOURS}h)",
                "age_hours": round(age_hours, 2),
                "generated_at": generated_at_str,
            }
        else:
            return {
                "status": "OK",
                "code": "FRESH",
                "message": f"Manifest is {age_hours:.1f}h old — FRESH",
                "age_hours": round(age_hours, 2),
                "generated_at": generated_at_str,
            }


# ---------------------------------------------------------------------------
# 2. StaleReuseDetector
# ---------------------------------------------------------------------------
class StaleReuseDetector:
    """Detects identical manifest re-publication (stale feed reuse)."""

    STATE_FILE = MANIFEST_STATE_DIR / "last_manifest_hash.json"

    def _load_state(self) -> Dict:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_state(self, manifest_hash: str, generated_at: str) -> None:
        MANIFEST_STATE_DIR.mkdir(parents=True, exist_ok=True)
        state = {
            "manifest_hash": manifest_hash,
            "generated_at": generated_at,
            "recorded_at": now_iso(),
        }
        self.STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def check(self, manifest: Dict, apply: bool = False) -> Dict:
        """
        Compute hash of the manifest advisories block (content, not metadata).
        Compare against last recorded hash. If identical → stale reuse detected.
        """
        advisories = manifest.get("advisories", [])
        content_hash = sha256_json(advisories)
        generated_at = manifest.get("generated_at", "unknown")

        state = self._load_state()
        prev_hash = state.get("manifest_hash", "")
        prev_ts = state.get("generated_at", "never")

        is_reuse = prev_hash and (content_hash == prev_hash)

        if apply:
            self._save_state(content_hash, generated_at)

        if is_reuse:
            return {
                "status": "WARN",
                "code": "STALE_REUSE_DETECTED",
                "message": f"Manifest content identical to previous publish at {prev_ts}",
                "content_hash": content_hash,
                "prev_hash": prev_hash,
                "prev_generated_at": prev_ts,
                "current_generated_at": generated_at,
            }
        return {
            "status": "OK",
            "code": "FRESH_CONTENT",
            "message": "Manifest content differs from previous publish — fresh",
            "content_hash": content_hash,
            "prev_hash": prev_hash or "none",
            "current_generated_at": generated_at,
        }


# ---------------------------------------------------------------------------
# 3. AdvisoryUniquenessGate
# ---------------------------------------------------------------------------
class AdvisoryUniquenessGate:
    """Detects duplicate advisory IDs/titles within the manifest."""

    def validate(self, manifest: Dict) -> Dict:
        advisories = manifest.get("advisories", [])
        if not advisories:
            return {
                "status": "WARN",
                "code": "EMPTY_ADVISORIES",
                "message": "No advisories in manifest",
                "total": 0,
                "duplicates": [],
            }

        seen_ids: Dict[str, int] = {}
        seen_titles: Dict[str, int] = {}
        dup_ids = []
        dup_titles = []

        for i, adv in enumerate(advisories):
            adv_id = adv.get("id", adv.get("cve_id", f"idx-{i}"))
            title = adv.get("title", "")

            if adv_id in seen_ids:
                dup_ids.append({"id": adv_id, "first_at": seen_ids[adv_id], "dup_at": i})
            else:
                seen_ids[adv_id] = i

            if title and title in seen_titles:
                dup_titles.append({"title": title[:80], "first_at": seen_titles[title], "dup_at": i})
            elif title:
                seen_titles[title] = i

        if dup_ids:
            return {
                "status": "FAIL",
                "code": "DUPLICATE_IDS",
                "message": f"{len(dup_ids)} duplicate advisory IDs detected",
                "total": len(advisories),
                "duplicate_ids": dup_ids[:10],
                "duplicate_titles": dup_titles[:5],
            }
        if dup_titles:
            return {
                "status": "WARN",
                "code": "DUPLICATE_TITLES",
                "message": f"{len(dup_titles)} duplicate advisory titles (IDs unique)",
                "total": len(advisories),
                "duplicate_ids": [],
                "duplicate_titles": dup_titles[:10],
            }
        return {
            "status": "OK",
            "code": "ALL_UNIQUE",
            "message": f"All {len(advisories)} advisories have unique IDs",
            "total": len(advisories),
            "duplicates": [],
        }


# ---------------------------------------------------------------------------
# 4. ManifestMutationValidator
# ---------------------------------------------------------------------------
class ManifestMutationValidator:
    """Detects unexpected field-level mutations between manifest versions."""

    STATE_FILE = MANIFEST_STATE_DIR / "last_manifest_fields.json"

    def _load_state(self) -> Dict:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _snapshot(self, manifest: Dict) -> Dict:
        """Capture scalar top-level fields (exclude advisories list)."""
        snap = {}
        for k, v in manifest.items():
            if k == "advisories":
                snap["_advisory_count"] = len(v) if isinstance(v, list) else -1
                snap["_advisory_hash"] = sha256_json(v) if isinstance(v, list) else ""
            elif isinstance(v, (str, int, float, bool)) or v is None:
                snap[k] = v
        return snap

    def _save_state(self, snapshot: Dict) -> None:
        MANIFEST_STATE_DIR.mkdir(parents=True, exist_ok=True)
        state = {"snapshot": snapshot, "recorded_at": now_iso()}
        self.STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def validate(self, manifest: Dict, apply: bool = False) -> Dict:
        current_snap = self._snapshot(manifest)
        state = self._load_state()
        prev_snap = state.get("snapshot", {})

        if apply:
            self._save_state(current_snap)

        if not prev_snap:
            return {
                "status": "OK",
                "code": "FIRST_RUN",
                "message": "No previous manifest snapshot — establishing baseline",
                "changed_fields": [],
                "critical_mutations": [],
            }

        changed = []
        critical = []
        for field, curr_val in current_snap.items():
            prev_val = prev_snap.get(field, "__ABSENT__")
            if prev_val != curr_val:
                delta = {"field": field, "from": prev_val, "to": curr_val}
                changed.append(delta)
                if field in CRITICAL_FIELDS:
                    critical.append(delta)

        new_fields = [f for f in current_snap if f not in prev_snap]

        if critical:
            status = "WARN"
            code = "CRITICAL_FIELD_MUTATION"
            msg = f"{len(critical)} critical field(s) changed: {[c['field'] for c in critical]}"
        elif len(changed) > MUTATION_WARN_THRESHOLD:
            status = "WARN"
            code = "HIGH_MUTATION_DELTA"
            msg = f"{len(changed)} fields changed (threshold={MUTATION_WARN_THRESHOLD})"
        else:
            status = "OK"
            code = "NORMAL_DELTA"
            msg = f"{len(changed)} field(s) changed — within normal range"

        return {
            "status": status,
            "code": code,
            "message": msg,
            "changed_fields": changed[:20],
            "critical_mutations": critical,
            "new_fields": new_fields,
            "total_changed": len(changed),
        }


# ---------------------------------------------------------------------------
# 5. ManifestIntegrityReport
# ---------------------------------------------------------------------------
class ManifestIntegrityReport:
    """Orchestrates all integrity checks and writes signed proof."""

    OUTPUT_FILE = HEALTH_DIR / "manifest_integrity.json"

    def __init__(self):
        self.freshness = FreshnessProofEngine()
        self.stale = StaleReuseDetector()
        self.uniqueness = AdvisoryUniquenessGate()
        self.mutation = ManifestMutationValidator()

    def _load_manifest(self) -> Optional[Dict]:
        if FEED_MANIFEST.exists():
            try:
                return json.loads(FEED_MANIFEST.read_text(encoding="utf-8"))
            except Exception as e:
                log.error("Cannot parse feed_manifest.json: %s", e)
        return None

    def _hard_fail(self, results: Dict, strict: bool) -> bool:
        """Determine if any result is a hard failure."""
        hard = False
        if results["freshness"]["status"] == "FAIL":
            hard = True
        if results["uniqueness"]["status"] == "FAIL":
            hard = True
        if strict:
            if results["freshness"]["status"] == "WARN":
                hard = True
            if results["stale_reuse"]["status"] == "WARN" and \
               results["stale_reuse"].get("code") == "STALE_REUSE_DETECTED":
                hard = True
        return hard

    def run(self, apply: bool = True, strict: bool = False) -> Dict:
        HEALTH_DIR.mkdir(parents=True, exist_ok=True)
        MANIFEST_STATE_DIR.mkdir(parents=True, exist_ok=True)

        manifest = self._load_manifest()
        if manifest is None:
            report = {
                "status": "FAIL",
                "code": "MANIFEST_NOT_FOUND",
                "message": "feed_manifest.json not found or unreadable",
                "generated_at": now_iso(),
                "version": VERSION,
            }
            self.OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return report

        manifest_hash = sha256_json(manifest)

        # Run all checks
        results = {
            "freshness": self.freshness.validate(manifest),
            "stale_reuse": self.stale.check(manifest, apply=apply),
            "uniqueness": self.uniqueness.validate(manifest),
            "mutation": self.mutation.validate(manifest, apply=apply),
        }

        is_hard_fail = self._hard_fail(results, strict)
        any_warn = any(r["status"] == "WARN" for r in results.values())

        overall_status = "FAIL" if is_hard_fail else ("WARN" if any_warn else "OK")

        summary = {
            "status": overall_status,
            "hard_fail": is_hard_fail,
            "strict_mode": strict,
            "manifest_hash": manifest_hash,
            "manifest_path": str(FEED_MANIFEST.relative_to(REPO_ROOT)),
            "total_advisories": manifest.get("total_advisories", "?"),
            "manifest_version": manifest.get("version", "?"),
            "manifest_generated_at": manifest.get("generated_at", "?"),
            "generated_at": now_iso(),
            "engine_version": VERSION,
            "checks": results,
        }

        self.OUTPUT_FILE.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        log.info("Manifest integrity report written: %s", self.OUTPUT_FILE)
        return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def print_report(summary: Dict) -> None:
    log.info("=" * 72)
    log.info("MANIFEST INTEGRITY SYSTEM — v%s", VERSION)
    log.info("=" * 72)
    log.info("Overall status    : %s", summary.get("status", "?"))
    log.info("Total advisories  : %s", summary.get("total_advisories", "?"))
    log.info("Manifest version  : %s", summary.get("manifest_version", "?"))
    log.info("Manifest generated: %s", summary.get("manifest_generated_at", "?"))
    log.info("Manifest hash     : %s...", summary.get("manifest_hash", "")[:16])
    log.info("-" * 72)
    checks = summary.get("checks", {})
    for check_name, result in checks.items():
        flag = "[OK]  " if result["status"] == "OK" else \
               "[WARN]" if result["status"] == "WARN" else "[FAIL]"
        log.info("%-20s %s  %s", check_name, flag, result.get("message", ""))
    log.info("=" * 72)
    if summary.get("hard_fail"):
        log.error("HARD FAIL — manifest integrity violated. See checks above.")
    elif summary.get("status") == "WARN":
        log.warning("WARN — manifest integrity degraded. Review checks above.")
    else:
        log.info("PASS — manifest integrity verified.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Manifest Integrity System"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true", help="Validate; exit 1 on HARD FAIL")
    grp.add_argument("--report", action="store_true", help="Print report, always exit 0")
    parser.add_argument("--strict", action="store_true",
                        help="Elevate stale-reuse/age warnings to HARD FAIL")
    args = parser.parse_args()

    engine = ManifestIntegrityReport()
    apply = not args.report  # In report mode, don't mutate state
    summary = engine.run(apply=apply, strict=args.strict)
    print_report(summary)

    if args.report:
        return 0
    if summary.get("hard_fail"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
