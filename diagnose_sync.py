#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0 — Production Sync Diagnostic
==================================================================
Run this script locally or in GitHub Actions to diagnose sync failures.

Usage:
    python diagnose_sync.py
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# DIAGNOSTIC ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class SyncDiagnostic:
    """Production diagnostic engine for sync failure analysis."""
    
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.issues: List[Dict] = []
        self.warnings: List[Dict] = []
        self.passed: List[str] = []
        
    def run_all_checks(self) -> Dict:
        """Execute comprehensive diagnostic suite."""
        print("=" * 70)
        print("SENTINEL APEX v25.0 — PRODUCTION SYNC DIAGNOSTIC")
        print("=" * 70)
        print()
        
        # Check 1: Feed Manifest Health
        self._check_feed_manifest()
        
        # Check 2: Intel Batch Freshness
        self._check_intel_batch()
        
        # Check 3: Status File
        self._check_status_file()
        
        # Check 4: Directory Structure
        self._check_directory_structure()
        
        # Check 5: Module Imports
        self._check_module_imports()
        
        # Check 6: Secrets Availability (CI only)
        self._check_secrets()
        
        # Check 7: Git State
        self._check_git_state()
        
        # Generate Report
        return self._generate_report()
    
    def _check_feed_manifest(self):
        """Verify feed_manifest.json freshness and integrity."""
        print("🔍 CHECK 1: Feed Manifest Health")
        manifest_path = self.base_path / "data" / "stix" / "feed_manifest.json"
        
        if not manifest_path.exists():
            self.issues.append({
                "code": "MANIFEST_MISSING",
                "severity": "CRITICAL",
                "message": "feed_manifest.json does not exist",
                "fix": "Run sentinel_blogger.py to generate initial manifest"
            })
            print("   ❌ CRITICAL: feed_manifest.json MISSING")
            return
        
        try:
            with open(manifest_path) as f:
                data = json.load(f)
            
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = data.get("entries", [])
            else:
                entries = []
            
            if not entries:
                self.issues.append({
                    "code": "MANIFEST_EMPTY",
                    "severity": "CRITICAL",
                    "message": "feed_manifest.json has no entries",
                    "fix": "Run sentinel_blogger.py to populate manifest"
                })
                print("   ❌ CRITICAL: Manifest is EMPTY")
                return
            
            # Check latest entry timestamp
            latest_entry = entries[0]  # First entry should be newest
            latest_ts = latest_entry.get("timestamp", "")
            
            if latest_ts:
                try:
                    latest_dt = datetime.fromisoformat(latest_ts.replace("Z", "+00:00"))
                    age = datetime.now(timezone.utc) - latest_dt
                    age_hours = age.total_seconds() / 3600
                    
                    if age_hours > 24:
                        self.issues.append({
                            "code": "MANIFEST_STALE",
                            "severity": "HIGH",
                            "message": f"Latest entry is {age_hours:.1f} hours old ({age.days}d {age.seconds//3600}h)",
                            "fix": "Trigger sentinel-blogger workflow manually"
                        })
                        print(f"   ⚠️ HIGH: Latest entry is {age_hours:.1f} hours old")
                    elif age_hours > 8:
                        self.warnings.append({
                            "code": "MANIFEST_AGING",
                            "message": f"Latest entry is {age_hours:.1f} hours old"
                        })
                        print(f"   ⚠️ WARNING: Latest entry is {age_hours:.1f} hours old")
                    else:
                        self.passed.append(f"Manifest fresh: {len(entries)} entries, latest {age_hours:.1f}h ago")
                        print(f"   ✅ PASS: {len(entries)} entries, latest {age_hours:.1f} hours ago")
                except Exception as e:
                    self.warnings.append({
                        "code": "TIMESTAMP_PARSE_ERROR",
                        "message": f"Could not parse timestamp: {e}"
                    })
                    print(f"   ⚠️ WARNING: Timestamp parse error")
            else:
                self.warnings.append({
                    "code": "MISSING_TIMESTAMP",
                    "message": "Latest entry has no timestamp field"
                })
                print("   ⚠️ WARNING: No timestamp in latest entry")
                
        except json.JSONDecodeError as e:
            self.issues.append({
                "code": "MANIFEST_CORRUPT",
                "severity": "CRITICAL",
                "message": f"feed_manifest.json is invalid JSON: {e}",
                "fix": "Restore from git or regenerate"
            })
            print(f"   ❌ CRITICAL: Invalid JSON in manifest")
    
    def _check_intel_batch(self):
        """Check latest_intel_batch.json freshness."""
        print("\n🔍 CHECK 2: Intel Batch Freshness")
        batch_path = self.base_path / "data" / "enrichment" / "latest_intel_batch.json"
        
        if not batch_path.exists():
            self.warnings.append({
                "code": "INTEL_BATCH_MISSING",
                "message": "latest_intel_batch.json not found (non-critical)"
            })
            print("   ⚠️ WARNING: latest_intel_batch.json not found")
            return
        
        try:
            with open(batch_path) as f:
                data = json.load(f)
            
            ts = data.get("timestamp", "")
            if ts:
                try:
                    batch_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    age = datetime.now(timezone.utc) - batch_dt
                    age_hours = age.total_seconds() / 3600
                    
                    if age_hours > 8:
                        self.warnings.append({
                            "code": "INTEL_BATCH_STALE",
                            "message": f"Intel batch is {age_hours:.1f} hours old"
                        })
                        print(f"   ⚠️ WARNING: Intel batch {age_hours:.1f} hours old")
                    else:
                        self.passed.append(f"Intel batch fresh: {age_hours:.1f}h ago")
                        print(f"   ✅ PASS: Intel batch {age_hours:.1f} hours ago")
                except:
                    print("   ⚠️ WARNING: Could not parse batch timestamp")
        except:
            print("   ⚠️ WARNING: Could not read intel batch file")
    
    def _check_status_file(self):
        """Check status.json for system health."""
        print("\n🔍 CHECK 3: Status File")
        status_path = self.base_path / "data" / "status" / "status.json"
        
        if not status_path.exists():
            self.warnings.append({
                "code": "STATUS_MISSING",
                "message": "status.json not found"
            })
            print("   ⚠️ WARNING: status.json not found")
            return
        
        try:
            with open(status_path) as f:
                data = json.load(f)
            
            # Check threat_feed status
            feed_status = data.get("components", {}).get("threat_feed", {})
            if feed_status.get("status") == "OPERATIONAL":
                self.passed.append("Threat feed status: OPERATIONAL")
                print("   ✅ PASS: Threat feed OPERATIONAL")
            else:
                self.issues.append({
                    "code": "FEED_NOT_OPERATIONAL",
                    "severity": "HIGH",
                    "message": f"Threat feed status: {feed_status.get('status', 'UNKNOWN')}",
                    "fix": "Check RSS feed connectivity"
                })
                print(f"   ⚠️ HIGH: Threat feed {feed_status.get('status', 'UNKNOWN')}")
            
            # Check age
            age_hours = feed_status.get("age_hours", 999)
            if age_hours > 8:
                self.warnings.append({
                    "code": "STATUS_FEED_AGE",
                    "message": f"Feed age: {age_hours:.1f} hours"
                })
                print(f"   ⚠️ WARNING: Feed age {age_hours:.1f}h")
                
        except Exception as e:
            print(f"   ⚠️ WARNING: Status file read error: {e}")
    
    def _check_directory_structure(self):
        """Verify required directories exist."""
        print("\n🔍 CHECK 4: Directory Structure")
        required_dirs = [
            "data/stix",
            "data/enrichment",
            "data/status",
            "agent",
            ".github/workflows"
        ]
        
        all_ok = True
        for dir_path in required_dirs:
            full_path = self.base_path / dir_path
            if not full_path.exists():
                self.issues.append({
                    "code": "MISSING_DIRECTORY",
                    "severity": "MEDIUM",
                    "message": f"Required directory missing: {dir_path}",
                    "fix": f"mkdir -p {dir_path}"
                })
                print(f"   ❌ MISSING: {dir_path}")
                all_ok = False
        
        if all_ok:
            self.passed.append("All required directories exist")
            print("   ✅ PASS: All directories exist")
    
    def _check_module_imports(self):
        """Test critical module imports."""
        print("\n🔍 CHECK 5: Module Imports")
        
        # Add project root to path
        sys.path.insert(0, str(self.base_path))
        
        modules_to_check = [
            ("agent.enricher", "enricher"),
            ("agent.export_stix", "stix_exporter"),
            ("agent.config", "RSS_FEEDS"),
            ("agent.risk_engine", "risk_engine"),
        ]
        
        all_ok = True
        for module_path, attr in modules_to_check:
            try:
                module = __import__(module_path, fromlist=[attr])
                getattr(module, attr)
                print(f"   ✅ {module_path}.{attr}")
            except ImportError as e:
                self.issues.append({
                    "code": "IMPORT_ERROR",
                    "severity": "CRITICAL",
                    "message": f"Cannot import {module_path}: {e}",
                    "fix": "Check requirements.txt and reinstall dependencies"
                })
                print(f"   ❌ {module_path}: {e}")
                all_ok = False
            except AttributeError as e:
                self.warnings.append({
                    "code": "ATTRIBUTE_MISSING",
                    "message": f"{module_path}.{attr} not found"
                })
                print(f"   ⚠️ {module_path}.{attr}: attribute not found")
        
        if all_ok:
            self.passed.append("All critical module imports successful")
    
    def _check_secrets(self):
        """Check if running in CI with required secrets."""
        print("\n🔍 CHECK 6: Environment & Secrets")
        
        if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
            print("   ℹ️ Running in GitHub Actions")
            
            required_secrets = ["BLOG_ID", "REFRESH_TOKEN", "CLIENT_ID", "CLIENT_SECRET"]
            missing = []
            
            for secret in required_secrets:
                if not os.getenv(secret):
                    missing.append(secret)
            
            if missing:
                self.issues.append({
                    "code": "MISSING_SECRETS",
                    "severity": "CRITICAL",
                    "message": f"Missing secrets: {', '.join(missing)}",
                    "fix": "Add secrets to GitHub repository settings"
                })
                print(f"   ❌ CRITICAL: Missing secrets: {', '.join(missing)}")
            else:
                self.passed.append("All required secrets present")
                print("   ✅ PASS: All required secrets present")
        else:
            print("   ℹ️ Not running in CI (secrets check skipped)")
    
    def _check_git_state(self):
        """Check git repository state."""
        print("\n🔍 CHECK 7: Git State")
        
        import subprocess
        
        try:
            # Check current branch
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, cwd=str(self.base_path)
            )
            branch = result.stdout.strip()
            print(f"   ℹ️ Current branch: {branch}")
            
            # Check for uncommitted changes
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True, text=True, cwd=str(self.base_path)
            )
            if result.stdout.strip():
                self.warnings.append({
                    "code": "UNCOMMITTED_CHANGES",
                    "message": "Repository has uncommitted changes"
                })
                print("   ⚠️ WARNING: Uncommitted changes present")
            else:
                self.passed.append("Git working tree clean")
                print("   ✅ PASS: Working tree clean")
            
            # Check last commit time
            result = subprocess.run(
                ["git", "log", "-1", "--format=%ci"],
                capture_output=True, text=True, cwd=str(self.base_path)
            )
            if result.returncode == 0:
                print(f"   ℹ️ Last commit: {result.stdout.strip()}")
                
        except FileNotFoundError:
            print("   ⚠️ WARNING: git command not found")
        except Exception as e:
            print(f"   ⚠️ WARNING: Git check failed: {e}")
    
    def _generate_report(self) -> Dict:
        """Generate final diagnostic report."""
        print("\n" + "=" * 70)
        print("DIAGNOSTIC SUMMARY")
        print("=" * 70)
        
        critical_issues = [i for i in self.issues if i.get("severity") == "CRITICAL"]
        high_issues = [i for i in self.issues if i.get("severity") == "HIGH"]
        
        if critical_issues:
            print(f"\n🔴 CRITICAL ISSUES ({len(critical_issues)}):")
            for issue in critical_issues:
                print(f"   • [{issue['code']}] {issue['message']}")
                print(f"     FIX: {issue.get('fix', 'N/A')}")
        
        if high_issues:
            print(f"\n🟠 HIGH PRIORITY ISSUES ({len(high_issues)}):")
            for issue in high_issues:
                print(f"   • [{issue['code']}] {issue['message']}")
                print(f"     FIX: {issue.get('fix', 'N/A')}")
        
        if self.warnings:
            print(f"\n🟡 WARNINGS ({len(self.warnings)}):")
            for warn in self.warnings:
                print(f"   • [{warn['code']}] {warn['message']}")
        
        if self.passed:
            print(f"\n🟢 PASSED CHECKS ({len(self.passed)}):")
            for check in self.passed:
                print(f"   ✓ {check}")
        
        # Overall status
        print("\n" + "-" * 70)
        if critical_issues:
            print("🔴 STATUS: CRITICAL — Immediate action required")
            print("\n📋 RECOMMENDED ACTIONS:")
            print("   1. Check GitHub Actions → Settings → Actions → General")
            print("   2. Verify 'Allow all actions' is selected")
            print("   3. Manually trigger 'CDB Sentinel Blogger' workflow")
            print("   4. Check workflow run logs for errors")
        elif high_issues:
            print("🟠 STATUS: DEGRADED — Sync pipeline needs attention")
            print("\n📋 RECOMMENDED ACTIONS:")
            print("   1. Manually trigger sentinel-blogger workflow")
            print("   2. Check workflow logs for silent failures")
        elif self.warnings:
            print("🟡 STATUS: HEALTHY (with warnings)")
        else:
            print("🟢 STATUS: FULLY OPERATIONAL")
        
        print("=" * 70)
        
        return {
            "status": "CRITICAL" if critical_issues else ("HIGH" if high_issues else ("WARNING" if self.warnings else "OK")),
            "critical_issues": critical_issues,
            "high_issues": high_issues,
            "warnings": self.warnings,
            "passed": self.passed,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


if __name__ == "__main__":
    diagnostic = SyncDiagnostic()
    report = diagnostic.run_all_checks()
    
    # Save report
    report_path = Path("data/diagnostic_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Report saved to: {report_path}")
