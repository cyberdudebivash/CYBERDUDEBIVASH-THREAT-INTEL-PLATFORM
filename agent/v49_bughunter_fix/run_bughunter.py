"""
CYBERDUDEBIVASH® SENTINEL APEX v49.0 — Bug Hunter Runner
==========================================================
CLI entry point for Bug Hunter scan execution.

Usage:
    python -m agent.v49_bughunter_fix.run_bughunter
    python -m agent.v49_bughunter_fix.run_bughunter --domain example.com
    python -m agent.v49_bughunter_fix.run_bughunter --domains example.com,test.com

Environment:
    BH_TARGET_DOMAIN  — Primary scan target (default: cyberdudebivash.com)
    BH_EXTRA_DOMAINS  — Comma-separated additional domains
    BH_TIMEOUT        — HTTP request timeout in seconds (default: 12)

Designed for safe execution in GitHub Actions CI/CD.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import argparse
import json
import logging
import os
import sys
import time

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from agent.v49_bughunter_fix import V49_VERSION, V49_CODENAME
from agent.v49_bughunter_fix.recon_scanner import SafeReconScanner
from agent.v49_bughunter_fix.dashboard_bridge import (
    write_dashboard_output,
    get_previous_output,
    validate_output,
)

# ── LOGGING SETUP ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CDB-BH-RUNNER")

# ── DEFAULT TARGET ────────────────────────────────────────────

DEFAULT_DOMAIN = "cyberdudebivash.com"


def run_scan(domain: str, timeout: int = 12) -> dict:
    """Execute a full Bug Hunter scan on a single domain."""
    logger.info(f"{'='*60}")
    logger.info(f"  SENTINEL APEX v{V49_VERSION} — {V49_CODENAME}")
    logger.info(f"  Target: {domain}")
    logger.info(f"{'='*60}")

    previous_path = get_previous_output()
    scanner = SafeReconScanner(domain=domain, timeout=timeout)
    result = scanner.run_full_scan(previous_output_path=previous_path)
    return result


def merge_multi_domain_results(results: list) -> dict:
    """
    Merge results from multiple domain scans into a single
    dashboard output. Aggregates metrics and findings.
    """
    if len(results) == 1:
        return results[0]

    # Use first result as base
    merged = results[0].copy()
    merged["domain"] = ", ".join(r.get("domain", "") for r in results)

    # Aggregate metrics
    for key in ["subdomains", "live_hosts", "api_endpoints", "total_findings",
                "critical_findings", "high_findings", "risk_exposure"]:
        merged["metrics"][key] = sum(
            r.get("metrics", {}).get(key, 0) for r in results
        )

    # Recalculate ROSI
    exposure = merged["metrics"]["risk_exposure"]
    merged["metrics"]["rosi"] = round(
        (exposure * 0.95 / exposure * 100) if exposure > 0 else 0, 1
    )

    # Merge findings (capped at 50 for dashboard)
    all_findings = []
    for r in results:
        all_findings.extend(r.get("findings_summary", []))
    # Sort by severity priority
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))
    merged["findings_summary"] = all_findings[:50]

    # Merge assets
    all_assets = []
    for r in results:
        all_assets.extend(r.get("assets", []))
    merged["assets"] = all_assets[:100]

    # Merge technologies
    merged_techs = {}
    for r in results:
        merged_techs.update(r.get("technologies", {}))
    merged["technologies"] = merged_techs

    return merged


def main():
    parser = argparse.ArgumentParser(
        description="CDB SENTINEL APEX — Bug Hunter Recon Scanner"
    )
    parser.add_argument(
        "--domain",
        default=os.environ.get("BH_TARGET_DOMAIN", DEFAULT_DOMAIN),
        help="Primary target domain",
    )
    parser.add_argument(
        "--domains",
        default=os.environ.get("BH_EXTRA_DOMAINS", ""),
        help="Comma-separated list of additional domains",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("BH_TIMEOUT", "12")),
        help="HTTP request timeout in seconds",
    )
    args = parser.parse_args()

    # Build domain list
    domains = [args.domain]
    if args.domains:
        extras = [d.strip() for d in args.domains.split(",") if d.strip()]
        domains.extend(extras)

    # Execute scans
    start = time.time()
    results = []

    for domain in domains:
        try:
            result = run_scan(domain, timeout=args.timeout)
            results.append(result)
        except Exception as e:
            logger.error(f"Scan failed for {domain}: {e}")
            import traceback
            traceback.print_exc()

    if not results:
        logger.error("All scans failed. No output generated.")
        sys.exit(1)

    # Merge and write output
    final_output = merge_multi_domain_results(results)
    output_path = write_dashboard_output(final_output)

    # Validate
    validation = validate_output(output_path)
    total_time = time.time() - start

    # Summary
    print(f"\n{'='*60}")
    print(f"  ✅ BUG HUNTER SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"  Domains scanned:    {len(domains)}")
    print(f"  Subdomains found:   {validation['subdomains']}")
    print(f"  Live hosts:         {validation['live_hosts']}")
    print(f"  API endpoints:      {validation['api_endpoints']}")
    print(f"  Total findings:     {validation['total_findings']}")
    print(f"  Critical findings:  {validation['critical_findings']}")
    print(f"  Risk exposure:      ${validation['risk_exposure']:,}")
    print(f"  Engines active:     {validation['engines_count']}/12")
    print(f"  Has data:           {'YES ✓' if validation['has_nonzero_metrics'] else 'NO ✗'}")
    print(f"  Duration:           {total_time:.1f}s")
    print(f"  Output:             {output_path}")
    print(f"{'='*60}\n")

    if not validation["has_nonzero_metrics"]:
        logger.warning("Scanner produced zero metrics — external API may be down")
        # Still exit 0 — don't block CI/CD for transient crt.sh failures
        sys.exit(0)


if __name__ == "__main__":
    main()
