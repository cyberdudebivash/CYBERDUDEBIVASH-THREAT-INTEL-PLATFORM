#!/usr/bin/env python3
"""P0: fail when a signed paid manifest lags the final enriched source.

Read-only and offline. The pipeline regenerates latest_pro.json after its
final KEV, EPSS, P20 evidence-chain and IOC mutations. This validator proves
the fields used by the existing Worker publication engines were preserved
byte-for-byte as decoded JSON, without adding entitlements, guessing missing
evidence, or disclosing report identifiers. The publisher must run this BEFORE
any R2/customer release step; it never accesses cloud services.
"""
from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

SOURCE_PATH = Path("api/feed.json")
PRO_PATH = Path("api/v1/intel/latest_pro.json")
MAX_INPUT_BYTES = 32 * 1024 * 1024

# Only source fields that the PRO sanitizer must preserve; never demand
# ENTERPRISE-only apex_ai, STIX, raw IOC payloads or premium text be exposed.
# Includes the actual P20/P23/P25/P26 inputs as stored by the producer.
PARITY_FIELDS = (
    "tlp", "severity", "processed_at", "published_at",
    "cvss_score", "epss_score", "kev_present",
    "source_url", "evidence_chain", "iocs", "ioc_count", "ttps",
    "mitre_techniques", "corroborating_sources", "sigma_rule",
)


class ParityError(ValueError):
    """Opaque message: do not leak report IDs or source evidence into CI."""


def _items(document: Any, *, source: bool) -> list[dict]:
    if source and isinstance(document, list):
        items = document
    elif isinstance(document, dict):
        items = document.get("items")
    else:
        raise ParityError("INVALID_INPUT_ENVELOPE")
    if not isinstance(items, list) or not items or any(not isinstance(x, dict) for x in items):
        raise ParityError("MISSING_OR_INVALID_ITEMS")
    return items


def _identity(item: dict) -> str | None:
    value = item.get("id") or item.get("stix_id")
    return value if isinstance(value, str) and value.strip() else None


def verify_post_enrichment_manifest(source_document: Any, pro_document: Any) -> dict:
    source_rows = _items(source_document, source=True)
    pro_rows = _items(pro_document, source=False)
    source_by_id = {}
    for item in source_rows:
        key = _identity(item)
        if not key:
            continue
        # A contradictory duplicate in the source cannot be resolved safely
        # by silently picking whichever row happens to appear first.
        if key in source_by_id and any(
            source_by_id[key].get(field) != item.get(field) for field in PARITY_FIELDS
        ):
            raise ParityError("CONFLICTING_SOURCE_DUPLICATES")
        source_by_id.setdefault(key, item)

    seen = set()
    enriched = 0
    enriched_iocs = 0
    for pro_item in pro_rows:
        key = _identity(pro_item)
        if not key or key in seen:
            raise ParityError("INVALID_OR_DUPLICATE_PRO_IDENTITY")
        seen.add(key)
        source_item = source_by_id.get(key)
        if source_item is None:
            raise ParityError("PRO_REPORT_SOURCE_UNRESOLVABLE")
        for field in PARITY_FIELDS:
            if (field in pro_item) != (field in source_item) or pro_item.get(field) != source_item.get(field):
                raise ParityError("MANIFEST_NOT_ALIGNED_TO_ENRICHED_SOURCE")
        if isinstance(source_item.get("evidence_chain"), dict):
            enriched += 1
        if any(isinstance(x, dict) and x.get("p20_hardened") is True
               for x in (source_item.get("iocs") or [])):
            enriched_iocs += 1
    if pro_document.get("count") != len(pro_rows):
        raise ParityError("PRO_COUNT_INCONSISTENT")
    return {
        "verdict": "SOURCE_PARITY_ONLY_NOT_CUSTOMER_CERTIFIED",
        "source_records": len(source_rows),
        "pro_records": len(pro_rows),
        "pro_records_with_evidence_chain": enriched,
        "pro_records_with_hardened_iocs": enriched_iocs,
        "production_delivery_verified": False,
        "cloudflare_requests": 0,
    }


def _read_bounded_json(path: Path) -> Any:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_INPUT_BYTES:
        raise ParityError("MISSING_OR_OVERSIZED_INPUT")
    with path.open("rb") as fh:
        payload = fh.read(MAX_INPUT_BYTES + 1)
    if len(payload) > MAX_INPUT_BYTES:
        raise ParityError("OVERSIZED_INPUT")
    return json.loads(payload)


def main() -> int:
    try:
        status = verify_post_enrichment_manifest(
            _read_bounded_json(SOURCE_PATH), _read_bounded_json(PRO_PATH)
        )
        print(json.dumps(status, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        # Never emit untrusted object content, paths, IOCs or customer tokens.
        code = str(exc) if isinstance(exc, ParityError) else "INPUT_UNAVAILABLE_OR_INVALID"
        print(json.dumps({
            "verdict": "BLOCKED_POST_ENRICHMENT_SOURCE_PARITY",
            "reason": code,
            "production_delivery_verified": False,
            "cloudflare_requests": 0,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
