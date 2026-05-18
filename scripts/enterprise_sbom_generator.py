#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/enterprise_sbom_generator.py — Software Bill of Materials Generator (v156.4.0)
========================================================================================
PRODUCTION MANDATE: Enterprise customers and compliance frameworks (SOC 2, FedRAMP,
ISO 27001) require a complete, versioned SBOM on every production deployment.

Generates SPDX 2.3 and CycloneDX 1.4 compatible SBOMs covering:
  - All Python dependencies (installed packages)
  - All Python scripts in scripts/ and api/
  - JavaScript packages (workers/*/package.json)
  - System component declarations

Output:
  data/sbom/sbom-latest.spdx.json      — SPDX 2.3 JSON
  data/sbom/sbom-latest.cyclonedx.json — CycloneDX 1.4 JSON
  data/sbom/sbom-history.jsonl         — Append-only audit trail

Author: CYBERDUDEBIVASH SENTINEL APEX v156.4.0
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(level=logging.INFO, format="[SBOM] %(message)s")
log = logging.getLogger("sbom")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SBOM_DIR = REPO_ROOT / "data" / "sbom"
SPDX_PATH = SBOM_DIR / "sbom-latest.spdx.json"
CDX_PATH = SBOM_DIR / "sbom-latest.cyclonedx.json"
HISTORY_PATH = SBOM_DIR / "sbom-history.jsonl"

PLATFORM = "CYBERDUDEBIVASH-SENTINEL-APEX"
PLATFORM_VERSION = os.environ.get("PIPELINE_VERSION", "unknown")
NAMESPACE = f"https://intel.cyberdudebivash.com/sbom/{PLATFORM}/{PLATFORM_VERSION}"


def _sha256(path: pathlib.Path) -> str:
    try:
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        return h
    except Exception:
        return ""


def _get_python_packages() -> list[dict]:
    """Get all installed Python packages with versions."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format", "json"],
            capture_output=True, text=True, timeout=30
        )
        pkgs = json.loads(result.stdout or "[]")
        return pkgs
    except Exception as e:
        log.warning("Could not list pip packages: %s", e)
        return []


def _get_npm_packages(worker_dir: pathlib.Path) -> list[dict]:
    """Parse package.json for a worker directory."""
    pkg_json = worker_dir / "package.json"
    if not pkg_json.exists():
        return []
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        return [{"name": k, "version": v.lstrip("^~>=")} for k, v in deps.items()]
    except Exception:
        return []


def _get_script_components() -> list[dict]:
    """Enumerate all Python scripts as SBOM file components."""
    scripts = []
    for pattern in ["scripts/*.py", "api/*.py"]:
        for f in sorted(REPO_ROOT.glob(pattern)):
            if f.name.startswith("_"):
                continue
            scripts.append({
                "name": f.relative_to(REPO_ROOT).as_posix(),
                "sha256": _sha256(f),
                "size": f.stat().st_size,
            })
    return scripts


def build_spdx(py_packages: list[dict], npm_packages: list[dict], scripts: list[dict]) -> dict:
    """Build SPDX 2.3 JSON document."""
    now = datetime.now(timezone.utc).isoformat()
    packages = []
    relationships = []
    doc_id = "SPDXRef-DOCUMENT"

    # Platform package
    packages.append({
        "SPDXID": "SPDXRef-Platform",
        "name": PLATFORM,
        "versionInfo": PLATFORM_VERSION,
        "downloadLocation": "https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
    })
    relationships.append({"spdxElementId": doc_id, "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Platform"})

    # Python packages
    for i, pkg in enumerate(py_packages):
        pkg_id = f"SPDXRef-PyPkg-{i}"
        packages.append({
            "SPDXID": pkg_id,
            "name": pkg.get("name", ""),
            "versionInfo": pkg.get("version", ""),
            "downloadLocation": f"https://pypi.org/project/{pkg.get('name','')}/{pkg.get('version','')}",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        })
        relationships.append({"spdxElementId": "SPDXRef-Platform", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": pkg_id})

    # NPM packages
    for i, pkg in enumerate(npm_packages):
        pkg_id = f"SPDXRef-NpmPkg-{i}"
        packages.append({
            "SPDXID": pkg_id,
            "name": pkg.get("name", ""),
            "versionInfo": pkg.get("version", ""),
            "downloadLocation": f"https://www.npmjs.com/package/{pkg.get('name','')}",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        })
        relationships.append({"spdxElementId": "SPDXRef-Platform", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": pkg_id})

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"{PLATFORM}-{PLATFORM_VERSION}",
        "documentNamespace": NAMESPACE,
        "documentDescribes": ["SPDXRef-Platform"],
        "creationInfo": {
            "created": now,
            "creators": [
                "Tool: CYBERDUDEBIVASH-SENTINEL-APEX-SBOM-Generator-v156.4.0",
                f"Organization: CYBERDUDEBIVASH Pvt Ltd",
            ],
            "licenseListVersion": "3.21",
        },
        "packages": packages,
        "relationships": relationships,
        "files": [
            {
                "SPDXID": f"SPDXRef-File-{i}",
                "fileName": s["name"],
                "checksums": [{"algorithm": "SHA256", "checksumValue": s["sha256"]}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            for i, s in enumerate(scripts)
        ],
    }


def build_cyclonedx(py_packages: list[dict], npm_packages: list[dict]) -> dict:
    """Build CycloneDX 1.4 JSON document."""
    now = datetime.now(timezone.utc).isoformat()
    components = []

    for pkg in py_packages:
        components.append({
            "type": "library",
            "purl": f"pkg:pypi/{pkg.get('name','').lower()}@{pkg.get('version','')}",
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "scope": "required",
        })

    for pkg in npm_packages:
        components.append({
            "type": "library",
            "purl": f"pkg:npm/{pkg.get('name','')}@{pkg.get('version','')}",
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "scope": "required",
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{hashlib.md5(NAMESPACE.encode(), usedforsecurity=False).hexdigest()}",
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "CYBERDUDEBIVASH", "name": "SENTINEL-APEX-SBOM", "version": PLATFORM_VERSION}],
            "component": {
                "type": "application",
                "name": PLATFORM,
                "version": PLATFORM_VERSION,
            },
        },
        "components": components,
    }


def main() -> None:
    log.info("Generating SBOM for %s v%s", PLATFORM, PLATFORM_VERSION)
    SBOM_DIR.mkdir(parents=True, exist_ok=True)

    py_packages = _get_python_packages()
    log.info("Python packages: %d", len(py_packages))

    # Scan all worker npm packages
    npm_packages: list[dict] = []
    workers_dir = REPO_ROOT / "workers"
    if workers_dir.exists():
        for worker_dir in workers_dir.iterdir():
            if worker_dir.is_dir():
                pkgs = _get_npm_packages(worker_dir)
                npm_packages.extend(pkgs)
    log.info("NPM packages: %d", len(npm_packages))

    scripts = _get_script_components()
    log.info("Script components: %d", len(scripts))

    # Generate SPDX
    spdx_doc = build_spdx(py_packages, npm_packages, scripts)
    SPDX_PATH.write_text(json.dumps(spdx_doc, indent=2), encoding="utf-8")
    log.info("SPDX 2.3 written: %s (%d packages)", SPDX_PATH, len(spdx_doc["packages"]))

    # Generate CycloneDX
    cdx_doc = build_cyclonedx(py_packages, npm_packages)
    CDX_PATH.write_text(json.dumps(cdx_doc, indent=2), encoding="utf-8")
    log.info("CycloneDX 1.4 written: %s (%d components)", CDX_PATH, len(cdx_doc["components"]))

    # Append to history
    history_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_version": PLATFORM_VERSION,
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "python_packages": len(py_packages),
        "npm_packages": len(npm_packages),
        "script_components": len(scripts),
        "spdx_sha256": _sha256(SPDX_PATH),
        "cyclonedx_sha256": _sha256(CDX_PATH),
    }
    with HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(history_entry) + "\n")

    log.info("SBOM generation complete.")
    print(f"[SBOM] Generated: {len(py_packages)} Python + {len(npm_packages)} NPM + {len(scripts)} scripts")
    print(f"[SBOM] SPDX:      {SPDX_PATH}")
    print(f"[SBOM] CycloneDX: {CDX_PATH}")


if __name__ == "__main__":
    main()
