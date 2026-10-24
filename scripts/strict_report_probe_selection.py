#!/usr/bin/env python3
"""Strict, offline selection of report probes from the authoritative R2 catalog.

This adapter deliberately does not probe URLs, mutate storage, or claim delivery.
It is staged separately from the live convergence engine until timestamp provenance
and the legacy test fixtures have been reconciled.
"""
from __future__ import annotations

from typing import Any

try:
    from .report_chronology_integrity import audit_catalog
except ImportError:
    from report_chronology_integrity import audit_catalog


class ReportSelectionBlocked(ValueError):
    """Publication chronology cannot be established from canonical evidence."""


def select_report_probes(
    catalog: Any, *, manifest_files: Any, latest_limit: int = 15,
    historical_limit: int = 5,
) -> tuple[list[str], list[str]]:
    """Select verified UTC-ordered probes with strict catalog/manifest consistency.

    If the deployment manifest includes report paths, all selected catalog paths
    must be present. An empty manifest can be valid for R2-first architectures;
    it is NOT considered independent delivery proof.
    """
    # The live Worker may serve only a customer-authorized v2 catalog.
    # An empty customer-ready selection cannot establish report delivery.
    # Preserve the fail-closed outcome but expose a stable, actionable reason.
    if (isinstance(catalog, dict)
            and catalog.get("feed_type") in ("customer_ready_catalog", "customer_ready_latest")
            and catalog.get("reports") == []):
        raise ReportSelectionBlocked(
            "CUSTOMER_READY_CATALOG_EMPTY: no certified reports available for convergence probes"
        )
    if not isinstance(manifest_files, dict):
        raise ReportSelectionBlocked("Deployment manifest files must be an object")
    result = audit_catalog(
        catalog, latest_limit=latest_limit, history_limit=historical_limit
    )
    if result["verdict"] != "CHRONOLOGY_PRECHECK_ONLY":
        raise ReportSelectionBlocked(
            "Canonical chronology rejected: " + "; ".join(result.get("defects", []))
        )
    latest = result["latest"]
    historical = result["historical"]
    manifest_reports = {
        "/" + p for p in manifest_files
        if isinstance(p, str) and p.startswith("reports/") and p.endswith(".html")
    }
    if manifest_reports:
        expected = {url.split("https://intel.cyberdudebivash.com", 1)[-1]
                    for url in latest + historical}
        absent = expected - manifest_reports
        if absent:
            raise ReportSelectionBlocked(
                f"{len(absent)} selected canonical reports missing from Pages manifest"
            )
    return latest, historical
