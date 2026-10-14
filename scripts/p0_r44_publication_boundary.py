"""Apply the existing publication rules after supplemental enrichment writers.

Keep the complete candidate inventory in the existing internal manifest.
Only an eligible nonempty selection may replace the public feed files.
This performs no network requests and does not alter evidence or thresholds.
"""
from collections import Counter
from datetime import datetime, timezone
import json
import logging
from pathlib import Path

from manifest_reconciler import reconcile, _atomic_write
from p0_r35_feed_prewrite_guard import assert_publishable, select_publishable
from tlp_policy import partition_publishable
from public_api_sanitizer import _remove_invalid_stix_alias
from evidence_score_enforcer import compute_evidence_tier, backfill_governance_fields
from severity_epss_truth import epss_percent


def enforce_public_risk_truth(records: list[dict]) -> tuple[list[dict], int]:
    """Recheck risk against quantifiable evidence at the LAST public boundary.

    Later enrichment writers may re-inflate scores after the earlier evidence
    enforcer. Preserve untouched evidence in the internal archive; public
    output gets a bounded, lower claim when evidence is inadequate.
    Do not fabricate CVEs, KEV, EPSS, observables or positive evidence.
    """
    result = []
    adjusted = 0
    for record in records:
        item = dict(record)
        try:
            risk = float(item.get("risk_score") or 0)
        except (TypeError, ValueError):
            risk = 0.0
        if not (0.0 <= risk <= 10.0):
            raise ValueError("P0_PUBLIC_RISK_INVALID")
        if risk >= 9.0:
            # Normalize only on a copy. This conservative evidence tier requires
            # real numeric or affirmative structured evidence, not prose keywords.
            normalized = backfill_governance_fields(item)
            # The canonical customer API stores EPSS in percentage units.
            # The legacy backfill guesses that numbers <=1 are fractions and
            # can turn a VERIFIED 0.9% into 90%. That is false tier-4 evidence.
            # Never use unverified or ambiguously scaled values to authorize a
            # public critical-risk claim. Keep the archive and public source
            # EPSS fields untouched; only correct the evidence-check copy.
            verified_epss = epss_percent(item)
            for key in ("epss", "epss_score", "epss_pct"):
                normalized.pop(key, None)
            if verified_epss is not None:
                normalized["epss_score"] = verified_epss
            tier, cap = compute_evidence_tier(normalized, epss_is_percentage=True)
            if cap < risk:
                item["risk_score"] = round(cap, 1)
                if str(item.get("severity", "")).upper() == "CRITICAL" and cap < 9.0:
                    item["severity"] = "HIGH"
                adjusted += 1
        result.append(item)
    return result, adjusted

log = logging.getLogger(__name__)


def finalize_public_feed(root: Path) -> dict:
    root = Path(root)
    source = root / "api" / "feed.json"
    def reject_constant(token):
        raise ValueError(f"non-standard JSON constant: {token}")
    try:
        records = json.loads(source.read_text(encoding="utf-8"), parse_constant=reject_constant)
    except (OSError, ValueError) as exc:
        raise ValueError("P0_FINAL_PUBLICATION_BLOCKED: missing or malformed source feed") from exc
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        raise ValueError("P0_FINAL_PUBLICATION_BLOCKED: source feed must be a record list")

    # An entirely TLP-denied inventory belongs to the existing deny-first
    # upload/bundle routines, which replace older restricted public objects
    # with tombstones. Do not block that containment with an empty-selection
    # exception; leave these source bytes untouched for those routines.
    tlp_allowed, tlp_held = partition_publishable(records)
    if records and not tlp_allowed:
        log.warning("P0 final publication: all %d candidates TLP-denied; existing tombstone boundary required", len(records))
        return {"candidate_count": len(records), "published_count": 0,
                "withheld_count": len(tlp_held), "tlp_tombstone_boundary_required": True}

    selected, held = select_publishable(records, limit=500)
    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidate_count": len(records), "published_count": len(selected),
        "withheld_count": len(held), "cap_filtered_count": len(records) - len(held) - len(selected),
        "reason_counts": dict(Counter(r["reason_code"] for r in held)), "withheld": held,
    }
    _atomic_write(root / "data/quality/p0_r44_publication_boundary.json", report)
    log.info("P0 final publication: candidates=%d selected=%d withheld=%d reasons=%s",
             len(records), len(selected), len(held), Counter(r["reason"] for r in held).most_common(8))
    # Validate BEFORE replacing either public file. An invalid batch keeps
    # the previous feed and never manufactures source evidence to pass.
    assert_publishable(selected)
    # Existing reconciliation preserves all candidates and the complete
    # historical manifest before the supplemental inventory is withheld.
    reconcile(feed_path=source, manifest_path=root / "data/stix/feed_manifest.json")
    # The internal archive above keeps original candidate identities/evidence.
    # Anonymous feeds must never claim an internal intel-- key is a STIX object.
    # Preserve id and valid STIX identifiers; scrub only invalid aliases from
    # the two public feed copies, without mutating the reconciled inventory.
    public_selected = [dict(record) for record in selected]
    for record in public_selected:
        _remove_invalid_stix_alias(record)
    public_selected, risk_adjustments = enforce_public_risk_truth(public_selected)
    if risk_adjustments:
        log.warning("P0 public evidence fence: %d unsupported high scores capped after archival reconciliation", risk_adjustments)
    _atomic_write(source, public_selected)
    _atomic_write(root / "feed.json", public_selected)
    return report
