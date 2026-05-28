#!/usr/bin/env python3
"""CYBERDUDEBIVASH(R) SENTINEL APEX -- Manifest Repair v161.1 (null-byte guard)."""
from __future__ import annotations
import argparse, json, logging, re, shutil
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("manifest-repair")

REPO         = Path(__file__).parent.parent
MANIFEST     = REPO / "data" / "feed_manifest.json"
REPORTS_DIR  = REPO / "reports"
BLOG_BASE    = "https://blog.cyberdudebivash.in"
INTEL_BASE   = "https://intel.cyberdudebivash.com"
DOSSIER_BASE = INTEL_BASE + "/dossiers"
REPORT_BASE  = INTEL_BASE + "/reports"

def _slugify(text: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (text or "").lower())
    return re.sub(r"[\s_-]+", "-", s).strip("-")[:80]

def _atomic_write(path: Path, data) -> None:
    bak = path.with_suffix(".json.bak")
    if path.exists():
        shutil.copy2(path, bak)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)

def _safe_load(manifest_path: Path) -> object:
    """Load JSON with null-byte / trailing-garbage resilience (v161.1)."""
    raw = manifest_path.read_bytes().rstrip(b"\x00")
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(raw.decode("utf-8", errors="replace"))
        log.warning("Manifest had trailing garbage -- extracted first valid JSON object")
        return obj

def repair_manifest(manifest_path: Path, dry_run: bool = False) -> dict:
    if not manifest_path.exists():
        log.error("Manifest not found: %s", manifest_path)
        return {"error": "not_found"}
    data  = _safe_load(manifest_path)
    # fix(v166.2-P0): canonical key detection including "data" key
    if isinstance(data, list):
        items = data
    else:
        items = []
        for _k in ("advisories", "items", "data", "entries", "reports", "intel", "feed"):
            if isinstance(data.get(_k), list) and len(data[_k]) > 0:
                items = data[_k]
                break
    log.info("Loaded %d items from manifest", len(items))
    report_files: dict[str, Path] = {}
    if REPORTS_DIR.exists():
        for p in REPORTS_DIR.glob("*.html"):
            report_files[p.stem.lower()] = p
        log.info("Found %d report files in reports/", len(report_files))
    else:
        log.warning("reports/ directory not found at %s", REPORTS_DIR)
    stats = {"total": len(items), "report_url_backfilled": 0,
             "blog_url_backfilled": 0, "dossier_url_backfilled": 0, "skipped": 0}
    for item in items:
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("headline") or ""
        slug  = _slugify(title)
        if not item.get("report_url"):
            matched = None
            for cs, cp in report_files.items():
                if slug and (slug in cs or cs in slug):
                    matched = cp
                    break
            item["report_url"] = REPORT_BASE + "/" + (matched.name if matched else slug + ".html")
            stats["report_url_backfilled"] += 1
        else:
            stats["skipped"] += 1
        if not item.get("blog_url") and slug:
            item["blog_url"] = BLOG_BASE + "/" + slug + "/"
            stats["blog_url_backfilled"] += 1
        if not item.get("dossier_url") and slug:
            item["dossier_url"] = DOSSIER_BASE + "/" + slug + ".json"
            stats["dossier_url_backfilled"] += 1
    if dry_run:
        log.info("[DRY RUN] No changes written")
    else:
        _atomic_write(manifest_path, data)
        log.info("Manifest written: %s", manifest_path)
    log.info("Repair complete: %s", stats)
    return stats

def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Manifest Repair v161.1")
    parser.add_argument("--manifest", default=str(MANIFEST))
    parser.add_argument("--dry-run", action="store_true")
    args   = parser.parse_args()
    result = repair_manifest(Path(args.manifest), dry_run=args.dry_run)
    if "error" in result:
        return 1
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
