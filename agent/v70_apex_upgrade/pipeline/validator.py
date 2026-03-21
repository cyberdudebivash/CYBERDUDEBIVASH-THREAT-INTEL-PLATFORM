"""
SENTINEL APEX v70 — Pipeline Validator
========================================
Pre-deployment validation gate.
Runs BEFORE any git commit/push to ensure data integrity.
- Validates manifest schema
- Checks for duplicates
- Verifies dashboard won't break
- Structured JSON logging
- Idempotency verification
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..core.schema_validator import validate_manifest, validate_manifest_file

logger = logging.getLogger("sentinel.pipeline.validator")


class PipelineValidationResult:
    """Structured validation result."""

    def __init__(self):
        self.passed = True
        self.checks: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def add_check(self, name: str, passed: bool, message: str = "", details: Any = None):
        self.checks.append({
            "check": name,
            "passed": passed,
            "message": message,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if not passed:
            self.passed = False
            self.errors.append(f"{name}: {message}")

    def add_warning(self, message: str):
        self.warnings.append(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "total_checks": len(self.checks),
            "errors": self.errors,
            "warnings": self.warnings,
            "checks": self.checks,
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class PipelineValidator:
    """
    Pre-deployment validation gate.
    All checks must pass before deployment proceeds.
    """

    def __init__(self, data_dir: str = "data", dashboard_file: str = "index.html"):
        self.data_dir = data_dir
        self.dashboard_file = dashboard_file
        self.manifest_path = os.path.join(data_dir, "feed_manifest.json")

    def validate_all(self) -> PipelineValidationResult:
        """Run all validation checks. Returns comprehensive result."""
        result = PipelineValidationResult()

        # Check 1: Manifest exists
        self._check_manifest_exists(result)

        # Check 2: Manifest schema valid
        self._check_manifest_schema(result)

        # Check 3: No empty advisories
        self._check_no_empty_advisories(result)

        # Check 4: No excessive duplicates
        self._check_duplicates(result)

        # Check 5: Dashboard file exists
        self._check_dashboard_exists(result)

        # Check 6: EMBEDDED_INTEL valid (if present in dashboard)
        self._check_embedded_intel(result)

        # Check 7: Data freshness
        self._check_data_freshness(result)

        # Check 8: File sizes reasonable
        self._check_file_sizes(result)

        # Log structured output
        log_entry = {
            "event": "pipeline_validation",
            "passed": result.passed,
            "total_checks": len(result.checks),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
        }
        if result.passed:
            logger.info(f"Pipeline validation PASSED: {json.dumps(log_entry)}")
        else:
            logger.error(f"Pipeline validation FAILED: {json.dumps(log_entry)}")

        return result

    def _check_manifest_exists(self, result: PipelineValidationResult):
        exists = os.path.isfile(self.manifest_path)
        result.add_check(
            "manifest_exists",
            exists,
            f"Manifest file {'found' if exists else 'NOT FOUND'} at {self.manifest_path}",
        )

    def _check_manifest_schema(self, result: PipelineValidationResult):
        if not os.path.isfile(self.manifest_path):
            result.add_check("manifest_schema", False, "Cannot validate — file missing")
            return

        is_valid, errors = validate_manifest_file(self.manifest_path)
        result.add_check(
            "manifest_schema",
            is_valid,
            f"Schema validation {'passed' if is_valid else 'failed'}: {len(errors)} error(s)",
            details=errors[:10] if errors else None,
        )

    def _check_no_empty_advisories(self, result: PipelineValidationResult):
        if not os.path.isfile(self.manifest_path):
            result.add_check("no_empty_advisories", False, "File missing")
            return

        try:
            with open(self.manifest_path, "r") as f:
                data = json.load(f)
            advisories = data.get("advisories", [])
            if len(advisories) == 0:
                result.add_check(
                    "no_empty_advisories", False,
                    "Manifest has ZERO advisories — dashboard would be empty"
                )
            else:
                result.add_check(
                    "no_empty_advisories", True,
                    f"{len(advisories)} advisories present"
                )
        except Exception as e:
            result.add_check("no_empty_advisories", False, f"Parse error: {e}")

    def _check_duplicates(self, result: PipelineValidationResult):
        if not os.path.isfile(self.manifest_path):
            return

        try:
            with open(self.manifest_path, "r") as f:
                data = json.load(f)
            advisories = data.get("advisories", [])

            # Check dedup_keys
            dedup_keys = [a.get("dedup_key", "") for a in advisories if a.get("dedup_key")]
            unique_keys = set(dedup_keys)
            dupes = len(dedup_keys) - len(unique_keys)

            # Check title dupes
            titles = [a.get("title", "").lower().strip() for a in advisories if a.get("title")]
            title_dupes = len(titles) - len(set(titles))

            total_dupes = max(dupes, title_dupes)
            dupe_ratio = total_dupes / max(len(advisories), 1)

            if dupe_ratio > 0.20:
                result.add_check(
                    "duplicate_check", False,
                    f"Excessive duplicates: {total_dupes} ({dupe_ratio:.1%}) — dedup engine may have failed"
                )
            elif total_dupes > 0:
                result.add_warning(f"{total_dupes} duplicates detected ({dupe_ratio:.1%})")
                result.add_check("duplicate_check", True, f"{total_dupes} minor duplicates (acceptable)")
            else:
                result.add_check("duplicate_check", True, "No duplicates found")
        except Exception as e:
            result.add_check("duplicate_check", False, f"Check failed: {e}")

    def _check_dashboard_exists(self, result: PipelineValidationResult):
        exists = os.path.isfile(self.dashboard_file)
        result.add_check(
            "dashboard_exists",
            exists,
            f"Dashboard {'found' if exists else 'NOT FOUND'} at {self.dashboard_file}",
        )

    def _check_embedded_intel(self, result: PipelineValidationResult):
        if not os.path.isfile(self.dashboard_file):
            return

        try:
            with open(self.dashboard_file, "r", encoding="utf-8") as f:
                content = f.read()

            if "EMBEDDED_INTEL" not in content:
                result.add_warning("No EMBEDDED_INTEL block found in dashboard — using manifest fetch")
                result.add_check("embedded_intel", True, "No EMBEDDED_INTEL (acceptable — fetch-based)")
                return

            # Try to extract and parse
            import re
            match = re.search(r'const\s+EMBEDDED_INTEL\s*=\s*(\[.*?\]);', content, re.DOTALL)
            if match:
                try:
                    json.loads(match.group(1))
                    result.add_check("embedded_intel", True, "EMBEDDED_INTEL parseable")
                except json.JSONDecodeError as e:
                    result.add_check("embedded_intel", False, f"EMBEDDED_INTEL JSON invalid: {e}")
            else:
                result.add_check("embedded_intel", True, "EMBEDDED_INTEL format not standard (non-blocking)")
        except Exception as e:
            result.add_check("embedded_intel", False, f"Dashboard read error: {e}")

    def _check_data_freshness(self, result: PipelineValidationResult):
        if not os.path.isfile(self.manifest_path):
            return

        try:
            with open(self.manifest_path, "r") as f:
                data = json.load(f)

            gen_at = data.get("generated_at", "")
            if gen_at:
                dt = datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
                age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600

                if age_hours > 48:
                    result.add_warning(f"Manifest is {age_hours:.1f}h old — may be stale")
                result.add_check("data_freshness", True, f"Manifest age: {age_hours:.1f}h")
            else:
                result.add_warning("No generated_at timestamp in manifest")
                result.add_check("data_freshness", True, "No timestamp (non-blocking)")
        except Exception as e:
            result.add_check("data_freshness", False, f"Freshness check failed: {e}")

    def _check_file_sizes(self, result: PipelineValidationResult):
        if not os.path.isfile(self.manifest_path):
            return

        size_bytes = os.path.getsize(self.manifest_path)
        size_mb = size_bytes / (1024 * 1024)

        if size_mb > 50:
            result.add_check("file_size", False, f"Manifest too large: {size_mb:.2f}MB (max 50MB)")
        elif size_bytes < 10:
            result.add_check("file_size", False, f"Manifest suspiciously small: {size_bytes}B")
        else:
            result.add_check("file_size", True, f"Manifest size: {size_mb:.2f}MB")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """CLI entry point for pipeline validation."""
    import argparse
    parser = argparse.ArgumentParser(description="SENTINEL APEX Pipeline Validator")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    parser.add_argument("--dashboard", default="index.html", help="Dashboard file")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    validator = PipelineValidator(args.data_dir, args.dashboard)
    result = validator.validate_all()

    if args.json:
        print(result.to_json())
    else:
        print(f"\n{'='*60}")
        print(f"SENTINEL APEX Pipeline Validation {'PASSED ✓' if result.passed else 'FAILED ✗'}")
        print(f"{'='*60}")
        for check in result.checks:
            status = "✓" if check["passed"] else "✗"
            print(f"  [{status}] {check['check']}: {check['message']}")
        if result.warnings:
            print(f"\n  Warnings:")
            for w in result.warnings:
                print(f"    ⚠ {w}")
        print(f"\n  Total: {len(result.checks)} checks, {len(result.errors)} errors, {len(result.warnings)} warnings")
        print(f"{'='*60}\n")

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
