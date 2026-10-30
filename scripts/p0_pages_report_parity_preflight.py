#!/usr/bin/env python3
"""Fail-closed, zero-network preflight for report catalog vs Pages artifact parity.

This checks local release artifacts only. A pass is NOT R2/Pages delivery,
publication authorization, customer entitlement, or commercial certification.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from strict_report_probe_selection import ReportSelectionBlocked, select_report_probes
from deployment_convergence_validator import _chronology_block_reason

MAX_INPUT_BYTES = 20_000_000


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError("required local release artifact absent")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("required local release artifact exceeds size limit")
    return json.loads(path.read_text(encoding="utf-8"))


def preflight(catalog_path: Path, manifest_path: Path) -> dict[str, Any]:
    """Return only non-sensitive counts and verdict; never emit report URLs."""
    result: dict[str, Any] = {
        "verdict": "BLOCKED", "delivery_certified": False,
        "reason_code": "RELEASE_ARTIFACT_INVALID",
    }
    try:
        catalog = _read_json(catalog_path)
        manifest = _read_json(manifest_path)
        if not isinstance(manifest, dict):
            result["reason_code"] = "PAGES_MANIFEST_INVALID"
            return result
        files = manifest.get("files")
        if not isinstance(files, dict):
            result["reason_code"] = "PAGES_MANIFEST_INVALID"
            return result
        latest, historical = select_report_probes(
            catalog, manifest_files=files, latest_limit=15, historical_limit=5
        )
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        result["reason_code"] = _chronology_block_reason(exc)
        # Preserve the existing fail-closed verdict. Emit bounded, non-sensitive
        # counts to distinguish one missing Pages artifact from a broad drift.
        # Never expose report IDs, paths, URLs, or untrusted exception text.
        if (
            isinstance(exc, ReportSelectionBlocked)
            and result["reason_code"] == "PAGES_MANIFEST_REPORT_MISMATCH"
        ):
            match = re.fullmatch(
                r"([1-9][0-9]*) selected canonical reports missing from Pages manifest",
                str(exc),
            )
            if match is not None:
                result["missing_selected_report_count"] = int(match.group(1))
                result["catalog_report_count"] = len(catalog["reports"])
                result["pages_report_count"] = sum(
                    isinstance(key, str) and key.startswith("reports/")
                    and key.endswith(".html") for key in files
                )
        return result
    result.update({
        "verdict": "PARITY_PRECHECK_ONLY",
        "reason_code": "NONE",
        "selected_probes": len(latest) + len(historical),
        "pages_report_count": sum(
            isinstance(key, str) and key.startswith("reports/")
            and key.endswith(".html") for key in files
        ),
        "catalog_report_count": len(catalog["reports"]),
        "remaining_gates": [
            "independent R2/Pages object delivery and publication status",
            "exact deployed SHA, authorization, and paid entitlement",
            "full scheduled SAST and shared Cloudflare zero-overage attestation",
        ],
    })
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("api/reports/index.json"))
    parser.add_argument("--manifest", type=Path, default=Path("dist/deployment_manifest.json"))
    args = parser.parse_args(argv)
    result = preflight(args.catalog, args.manifest)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "PARITY_PRECHECK_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
