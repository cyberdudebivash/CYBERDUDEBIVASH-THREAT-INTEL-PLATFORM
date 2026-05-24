#!/usr/bin/env python3
"""
generate_advisory_pdfs.py — CYBERDUDEBIVASH SENTINEL APEX v161.3
================================================================
Generates a real ReportLab PDF for every advisory in the manifest.
Runs as Stage 3.2.6 in sentinel-blogger.yml.

Output:   reports/pdf/{advisory_id}.pdf
Updates:  data/stix/feed_manifest.json  (pdf_url, pdf_available fields)
R2 path:  reports/pdf/{advisory_id}.pdf  (uploaded by r2_upload.py Stage 3.5)

Non-blocking: exits 0 even on partial failures so pipeline never stalls.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [gen_pdf] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.gen_advisory_pdfs")

REPO_ROOT     = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
PDF_DIR       = REPO_ROOT / "reports" / "pdf"

# ---------------------------------------------------------------------------
# Map advisory dict → generate_premium_pdf.generate_pdf() report dict
# ---------------------------------------------------------------------------

def _build_report_dict(item: dict) -> dict:
    """Convert a manifest advisory item into the report schema for generate_premium_pdf."""
    item_id  = item.get("id") or "unknown"
    title    = item.get("title") or item_id
    severity = (item.get("severity") or "MEDIUM").upper()
    apex_ai  = item.get("apex_ai") or {}
    cves     = item.get("cves") or []
    ioc_objs = item.get("ioc_objects") or []
    actor    = item.get("actor_id") or item.get("actor") or "UNC-CDB"
    cvss_raw = item.get("cvss_score") or item.get("cvss")
    epss_raw = item.get("epss_score") or item.get("epss")
    try:
        cvss = float(cvss_raw) if cvss_raw is not None else None
    except (ValueError, TypeError):
        cvss = None
    try:
        epss_val = float(epss_raw) if epss_raw is not None else None
        # Normalise to 0-1 fraction
        if epss_val is not None and epss_val > 1.0:
            epss_val = min(epss_val / 100.0, 1.0)
    except (ValueError, TypeError):
        epss_val = None

    pub_at = item.get("published_at") or item.get("timestamp") or datetime.now(timezone.utc).isoformat()

    exec_sum = (
        apex_ai.get("executive_summary")
        or apex_ai.get("ai_summary")
        or apex_ai.get("summary")
        or item.get("description")
        or f"Threat advisory: {title}. Severity: {severity}."
    )

    # Build top_threats list (this advisory + its CVEs)
    top_threats = [{
        "id":       cves[0] if cves else item_id,
        "title":    title,
        "severity": severity,
        "cvss":     cvss,
        "epss":     epss_val,
        "actor":    actor,
        "apex_ai":  {"ai_summary": exec_sum[:300]},
    }]
    for cve_id in cves[1:4]:
        top_threats.append({
            "id": cve_id, "title": cve_id, "severity": severity,
            "cvss": cvss, "epss": epss_val, "actor": actor,
            "apex_ai": {"ai_summary": f"Associated CVE: {cve_id}"},
        })

    # Build IOC list
    iocs = []
    for ioc in ioc_objs[:50]:
        ioc_type  = ioc.get("type") or ioc.get("ioc_type") or "unknown"
        ioc_value = ioc.get("value") or ioc.get("indicator") or ""
        if not ioc_value:
            continue
        iocs.append({
            "type":       ioc_type,
            "value":      ioc_value,
            "confidence": ioc.get("confidence", 0.7),
            "first_seen": ioc.get("first_seen") or pub_at[:10],
        })

    # MITRE techniques from apex_ai
    ttp_list = apex_ai.get("ttps") or apex_ai.get("mitre_techniques") or []
    techniques = []
    tactics_seen: dict[str, int] = {}
    for ttp in ttp_list[:20]:
        t_id   = ttp.get("technique_id") or ttp.get("id") or ""
        t_name = ttp.get("technique_name") or ttp.get("name") or t_id
        tactic = ttp.get("tactic") or "Unknown"
        if t_id:
            techniques.append({"id": t_id, "name": t_name, "tactic": tactic, "count": 1})
            tactics_seen[tactic] = tactics_seen.get(tactic, 0) + 1

    mitre_coverage = {
        "density":    min(float(len(techniques)) / 5.0, 10.0),
        "techniques": techniques,
        "tactics":    [{"tactic": t, "count": c} for t, c in tactics_seen.items()],
    }

    # Actor intel
    mitre_group = item.get("mitre_group_id") or ""
    actor_intel = [{
        "actor":    actor + (f" [{mitre_group}]" if mitre_group else ""),
        "count":    1,
        "top_cves": cves[:5],
    }]

    # Recommendations
    recs_raw = apex_ai.get("recommendations") or apex_ai.get("mitigations") or []
    if isinstance(recs_raw, str):
        recs_raw = [r.strip() for r in recs_raw.split("\n") if r.strip()]
    recs = recs_raw[:10]
    if not recs:
        if severity in ("CRITICAL", "HIGH"):
            recs = [f"Apply patches immediately for {title}.",
                    "Enable enhanced monitoring for related IOCs.",
                    "Review SIEM rules for associated MITRE ATT&CK techniques."]
        else:
            recs = [f"Monitor {title} for escalation.", "Apply patches in next maintenance window."]

    # Severity counts for threat_landscape
    sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    sev_map[severity] = sev_map.get(severity, 0) + 1

    return {
        "report_id":         item_id,
        "type":              "cve_focused" if cves else "weekly",
        "title":             title,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "period":            {"from": pub_at, "to": datetime.now(timezone.utc).isoformat()},
        "tier":              "pro",
        "tlp":               item.get("tlp") or "TLP:GREEN",
        "executive_summary": exec_sum,
        "threat_landscape":  {
            "total_advisories": 1,
            "critical": sev_map["CRITICAL"],
            "high":     sev_map["HIGH"],
            "medium":   sev_map["MEDIUM"],
            "low":      sev_map["LOW"],
        },
        "top_threats":    top_threats,
        "mitre_coverage": mitre_coverage,
        "actor_intel":    actor_intel,
        "iocs":           iocs,
        "recommendations": recs,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not MANIFEST_PATH.exists():
        log.error("Manifest not found: %s", MANIFEST_PATH)
        sys.exit(0)  # non-blocking

    try:
        from generate_premium_pdf import generate_pdf
        log.info("ReportLab PDF generator loaded OK.")
    except ImportError as e:
        log.error("Cannot import generate_premium_pdf / ReportLab: %s", e)
        log.error("Run: pip install reportlab --break-system-packages")
        sys.exit(0)  # non-blocking — don't break pipeline

    PDF_DIR.mkdir(parents=True, exist_ok=True)
    log.info("PDF output dir: %s", PDF_DIR)

    with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    advisories = manifest.get("advisories", [])
    log.info("Manifest has %d advisories.", len(advisories))

    stats = {"total": len(advisories), "generated": 0, "skipped": 0, "errors": 0}
    manifest_changed = False

    for item in advisories:
        item_id = (item.get("id") or "").strip()
        if not item_id:
            stats["skipped"] += 1
            continue

        pdf_path = PDF_DIR / f"{item_id}.pdf"

        # Skip if already generated and up-to-date (same day)
        if pdf_path.exists() and pdf_path.stat().st_size > 1024:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            mtime = datetime.fromtimestamp(pdf_path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")
            if mtime == today:
                log.debug("Skip (fresh): %s", item_id[:24])
                # Ensure pdf_url is set even for skipped files
                if not item.get("pdf_url"):
                    item["pdf_url"]       = f"/reports/pdf/{item_id}.pdf"
                    item["pdf_available"] = True
                    manifest_changed = True
                stats["skipped"] += 1
                continue

        try:
            report_dict = _build_report_dict(item)
            pdf_bytes   = generate_pdf(report_dict)

            if len(pdf_bytes) < 512:
                raise ValueError(f"PDF too small ({len(pdf_bytes)} bytes) — likely generation failure")

            pdf_path.write_bytes(pdf_bytes)
            log.info(
                "PDF generated: %s  [%s]  %.1f KB",
                item_id[:28], item.get("severity","?"), len(pdf_bytes) / 1024,
            )

            item["pdf_url"]       = f"/reports/pdf/{item_id}.pdf"
            item["pdf_available"] = True
            manifest_changed = True
            stats["generated"] += 1

        except Exception as exc:
            log.warning("PDF generation failed for %s: %s", item_id[:28], exc)
            stats["errors"] += 1

    # Persist manifest with pdf_url updates
    if manifest_changed:
        import tempfile
        tmp = MANIFEST_PATH.with_suffix(".tmp_pdf")
        tmp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(MANIFEST_PATH)
        log.info("Manifest updated with pdf_url fields.")

    log.info(
        "PDF generation complete: %d generated / %d skipped / %d errors / %d total",
        stats["generated"], stats["skipped"], stats["errors"], stats["total"],
    )

    # Write stats for pipeline self-audit
    stats_path = REPO_ROOT / "data" / "pdf_generation_stats.json"
    stats_path.write_text(json.dumps({
        **stats,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "pdf_dir": str(PDF_DIR),
        "version": "v161.3",
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    # Must run from scripts/ directory so relative imports work
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    os.chdir(Path(__file__).resolve().parent)
    main()
