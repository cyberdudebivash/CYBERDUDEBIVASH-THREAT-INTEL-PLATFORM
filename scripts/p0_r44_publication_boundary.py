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
    _atomic_write(source, public_selected)
    _atomic_write(root / "feed.json", public_selected)
    return report
