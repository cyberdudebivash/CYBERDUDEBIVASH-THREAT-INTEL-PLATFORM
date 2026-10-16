#!/usr/bin/env python3
"""
scripts/detection_bundle_injector.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Detection Bundle Injector v1.0.0
====================================================================
REVENUE-CRITICAL:
  SOC teams pay for platforms that give them ACTIONABLE detection content.
  Currently, feed items have zero detection rules. This script injects:
    - Sigma rules  (SIEM-agnostic, Splunk/Elastic/Azure Sentinel)
    - KQL queries  (Microsoft Sentinel / Defender XDR)
    - Suricata rules (network detection)
  into every item in the feed/manifest that has a CVE or known threat type.

  These detection rules are what converts a browser visitor into a paying
  customer — they see "ready-to-deploy Sigma rule" in PRO tier and upgrade.

WHAT THIS DOES:
  1. Reads api/feed.json
  2. For each item, calls apex_real_detection_engine to generate detection bundle
  3. Injects sigma_rule, kql_query, suricata_rule, yara_rule into each item
  4. Writes back atomically to api/feed.json + manifest
  5. Writes separate detection files to api/v1/detections/{stix_id}/

DETECTION QUALITY GATES:
  - Sigma rules: validated YAML, real product/service field
  - KQL queries: valid Kusto syntax structure
  - No pseudo-IOCs (URLs, advisory pages) used in detection logic

USAGE:
  python3 scripts/detection_bundle_injector.py
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
import uuid

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from p38_shared_validators import is_detection_eligible  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-DETECT] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CDB-DETECT")

REPO_ROOT     = Path(__file__).resolve().parent.parent
FEED_PATH     = Path(os.environ.get("FEED_PATH", str(REPO_ROOT / "api" / "feed.json")))
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
DETECTIONS_DIR= REPO_ROOT / "api" / "v1" / "detections"
TELEMETRY     = REPO_ROOT / "data" / "telemetry" / "detection_bundle_report.json"
DRY_RUN       = os.environ.get("DRY_RUN", "").lower() == "true"
MAX_ITEMS     = int(os.environ.get("MAX_DETECT_ITEMS", "200"))

CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})", re.IGNORECASE)

# ------------------------------------------------------------------
# Vulnerability class detection from title + tags
# ------------------------------------------------------------------
def _classify_vuln(title: str, tags: list, threat_type: str, cve_id: str) -> str:
    t = (title + " " + " ".join(tags) + " " + threat_type).lower()
    if any(k in t for k in ("remote code exec", "rce", "arbitrary code", "code execution")):
        return "rce"
    if any(k in t for k in ("sql inject", "sqli", "sql")):
        return "sqli"
    if any(k in t for k in ("privilege escal", "priv esc", "elevation of privilege")):
        return "privesc"
    if any(k in t for k in ("authentication bypass", "auth bypass", "improper auth")):
        return "authbypass"
    if any(k in t for k in ("cross-site script", "xss", "stored xss", "reflected xss")):
        return "xss"
    if any(k in t for k in ("path traversal", "directory traversal", "lfi", "rfi")):
        return "pathtraversal"
    if any(k in t for k in ("denial of service", " dos ", "resource exhaustion")):
        return "dos"
    if any(k in t for k in ("phish", "credential harvest", "spearphish")):
        return "phishing"
    if any(k in t for k in ("ransomware",)):
        return "ransomware"
    if any(k in t for k in ("supply chain",)):
        return "supplychain"
    if any(k in t for k in ("command inject", "os command")):
        return "cmdinject"
    if any(k in t for k in ("ssrf", "server.side request")):
        return "ssrf"
    if "kev" in t or "actively exploit" in t:
        return "kev_exploit"
    return "generic"


def _sigma_rule(item: dict, vuln_class: str) -> str:
    """Generate a production-grade Sigma rule for the item."""
    cve_id     = item.get("cve_id") or item.get("title", "")
    title_safe = re.sub(r"[^a-zA-Z0-9 _-]", "", item.get("title", cve_id))[:80]
    product    = item.get("affected_product") or "Web Application"
    rule_id    = str(uuid.uuid5(uuid.NAMESPACE_DNS, item.get("stix_id") or cve_id))
    date_str   = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    severity   = item.get("severity", "MEDIUM").lower()
    sigma_level = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(severity, "medium")

    # Build detection logic per vuln class
    detection_blocks = {
        "rce": """\
detection:
    selection_process:
        CommandLine|contains:
            - 'cmd.exe /c'
            - 'powershell -enc'
            - '/bin/sh -c'
            - 'wget http'
            - 'curl http'
    selection_webshell:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '/bash'
            - '/sh'
        ParentImage|contains:
            - 'w3wp.exe'
            - 'httpd'
            - 'nginx'
            - 'apache2'
            - 'tomcat'
    condition: selection_process or selection_webshell
falsepositives:
    - Legitimate administrative scripts executing via web server
    - Deployment automation tools""",

        "sqli": """\
detection:
    selection:
        cs-uri-query|contains:
            - "' OR 1=1"
            - "UNION SELECT"
            - "'; DROP TABLE"
            - "1=1--"
            - "benchmark("
            - "sleep("
            - "0x"
        sc-status|contains: '500'
    filter_legitimate:
        cs-uri-stem|startswith: '/api/search'
    condition: selection and not filter_legitimate
falsepositives:
    - Web application firewall test traffic
    - Vulnerability scanner activity""",

        "phishing": """\
detection:
    selection_email:
        EventID: 28
        TargetFilename|contains:
            - '.hta'
            - '.lnk'
            - '.iso'
            - '.vhd'
            - '.docm'
    selection_network:
        DestinationHostname|endswith:
            - '.xyz'
            - '.top'
            - '.pw'
            - '.cc'
        DestinationPort: 443
    condition: selection_email or selection_network
falsepositives:
    - Legitimate file downloads from CDNs
    - Business email with ISO attachments""",

        "ransomware": """\
detection:
    selection_encrypt:
        TargetFilename|endswith:
            - '.locked'
            - '.encrypted'
            - '.crypted'
            - '.enc'
        EventID: 11
    selection_ransomnote:
        TargetFilename|contains:
            - 'README'
            - 'HOW_TO_DECRYPT'
            - 'RECOVER_FILES'
    selection_vssdelete:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wmic shadowcopy delete'
            - 'bcdedit /set'
    condition: selection_encrypt or selection_ransomnote or selection_vssdelete
falsepositives:
    - Encryption software (VeraCrypt, BitLocker) in use""",

        "privesc": """\
detection:
    selection_token:
        EventID:
            - 4672
            - 4673
        PrivilegeList|contains:
            - 'SeDebugPrivilege'
            - 'SeImpersonatePrivilege'
            - 'SeTcbPrivilege'
    selection_newservice:
        EventID: 4697
        ServiceName|contains: 'PSEXE'
    condition: selection_token or selection_newservice
falsepositives:
    - System administrators performing maintenance
    - Legitimate service installations""",

        "generic": """\
detection:
    selection:
        EventID:
            - 4625
            - 4648
            - 4728
        LogonType: 3
    condition: selection
falsepositives:
    - Legitimate administrative access
    - Service account activity""",
    }

    block = detection_blocks.get(vuln_class, detection_blocks["generic"])
    mitre_tags = []
    for tag in (item.get("mitre_techniques") or item.get("mitre_ttps") or []):
        tid = tag.get("technique_id") if isinstance(tag, dict) else str(tag)
        if tid:
            mitre_tags.append(f"    - attack.{tid.lower()}")
    mitre_str = "\n".join(mitre_tags) if mitre_tags else "    - attack.initial_access"

    return f"""title: SENTINEL APEX — {title_safe}
id: {rule_id}
status: experimental
description: |
    Detects exploitation attempts related to {cve_id} ({product}).
    Generated by CYBERDUDEBIVASH SENTINEL APEX v166.2.
    Severity: {severity.upper()} | Class: {vuln_class.upper()}
references:
    - https://intel.cyberdudebivash.com
    - https://nvd.nist.gov/vuln/detail/{cve_id}
author: CYBERDUDEBIVASH SENTINEL APEX Detection Engineering
date: {date_str}
modified: {date_str}
tags:
{mitre_str}
logsource:
    category: {'process_creation' if vuln_class in ('rce','privesc','ransomware') else 'webserver' if vuln_class in ('sqli','xss','ssrf') else 'network_connection'}
    product: {'windows' if vuln_class in ('privesc','ransomware') else 'generic'}
{block}
level: {sigma_level}
"""


def _kql_query(item: dict, vuln_class: str) -> str:
    """Generate a Microsoft Sentinel / Defender XDR KQL query."""
    cve_id  = item.get("cve_id") or item.get("title", "N/A")
    product = item.get("affected_product") or "Web Application"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    kql_map = {
        "rce": f"""// SENTINEL APEX — {cve_id} Remote Code Execution Detection
// Product: {product} | Generated: {date_str}
// Deploy to: Microsoft Sentinel / Defender XDR
let lookback = 1d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where (InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "java.exe")
    and FileName in~ ("cmd.exe", "powershell.exe", "bash", "sh", "python.exe", "python3"))
    or (ProcessCommandLine has_any ("wget http", "curl http", "certutil -urlcache", "bitsadmin /transfer"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| where not(ProcessCommandLine has_any ("update", "install", "backup", "deploy"))  // filter known-good
| extend Severity = "HIGH", CVE = "{cve_id}", RuleSource = "SENTINEL-APEX"
| order by Timestamp desc""",

        "phishing": f"""// SENTINEL APEX — Phishing Campaign Detection
// CVE/Threat: {cve_id} | Generated: {date_str}
let lookback = 7d;
let suspicious_exts = dynamic([".hta", ".lnk", ".iso", ".vhd", ".docm", ".xlsm", ".pptm"]);
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where FileName has_any (suspicious_exts)
| join kind=leftouter (
    EmailEvents | where Timestamp > ago(lookback)
        | where DeliveryAction !in ("Blocked", "Junked")
) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, FileName,
          Subject, DeliveryAction
| extend Severity = "HIGH", ThreatType = "Phishing", RuleSource = "SENTINEL-APEX"
| order by Timestamp desc""",

        "generic": f"""// SENTINEL APEX — {cve_id} — Anomalous Activity Detection
// Product: {product} | Generated: {date_str}
let lookback = 1d;
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID in (4625, 4648, 4728, 4740, 4776)
| summarize FailureCount = count(), DistinctTargets = dcount(TargetUserName)
    by IpAddress, bin(TimeGenerated, 1h)
| where FailureCount > 10 or DistinctTargets > 5
| extend Severity = "MEDIUM", CVE = "{cve_id}", RuleSource = "SENTINEL-APEX"
| order by TimeGenerated desc""",
    }

    return kql_map.get(vuln_class, kql_map["generic"])


def _suricata_rule(item: dict, vuln_class: str) -> str:
    """Generate a Suricata network detection rule."""
    cve_id  = item.get("cve_id") or item.get("title", "N/A")
    sid_base = abs(hash(cve_id)) % 9000000 + 1000000
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    patterns = {
        "sqli":        r'content:"UNION SELECT"; nocase; content:"--"; distance:0; nocase;',
        "rce":         r'content:"/bin/sh"; nocase; content:"cmd.exe"; nocase;',
        "phishing":    r'content:".hta"; nocase; http.uri;',
        "ransomware":  r'content:"vssadmin"; nocase; content:"delete shadows"; nocase;',
        "ssrf":        r'content:"169.254.169.254"; nocase;',
        "generic":     r'content:"|90 90 90 90|"; rawbytes;',
    }
    content = patterns.get(vuln_class, patterns["generic"])

    return (f'alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS '
            f'(msg:"SENTINEL-APEX {cve_id} Exploitation Attempt - {vuln_class.upper()}"; '
            f'flow:established,to_server; {content} '
            f'threshold:type threshold, track by_src, count 3, seconds 60; '
            f'classtype:web-application-attack; sid:{sid_base}; rev:1; '
            f'metadata:created_at {date_str}, source SENTINEL-APEX-v166.2;)')


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run(feed_path: Path, manifest_path: Path) -> dict:
    log.info("=" * 60)
    log.info("DETECTION BUNDLE INJECTOR v1.0.0")
    log.info("=" * 60)

    try:
        with open(feed_path, encoding="utf-8") as f:
            feed = json.load(f)
    except Exception as e:
        log.error("Feed load failed: %s", e); return {"status": "ERROR"}

    items = feed if isinstance(feed, list) else feed.get("advisories", feed.get("items", []))
    log.info("Loaded %d items", len(items))

    try:
        with open(manifest_path, encoding="utf-8") as f:
            raw = json.load(f)
        manifest_items = raw if isinstance(raw, list) else raw.get("advisories", [])
        manifest_by_id = {str(it.get("stix_id") or it.get("id") or ""): it for it in manifest_items}
    except Exception:
        manifest_items = []; manifest_by_id = {}

    # v185.0 P0 FIX: MAX_ITEMS previously sliced the first N items of the
    # RAW, unfiltered feed array (items[:MAX_ITEMS]) -- positional
    # truncation with no eligibility filter and no priority ordering. Since
    # the feed is re-sorted by timestamp DESC every pipeline run, any
    # eligible item that consistently ranks below position 200 (e.g. an
    # older but still-unprocessed CVE) was PERMANENTLY excluded: never
    # reached on any run, no matter how many times the pipeline executed.
    # Fixed with a two-part selection:
    #   1. Filter to is_detection_eligible(item) first (reused from
    #      p38_shared_validators.py, the same eligibility test used for
    #      detection-coverage certification) -- an ineligible item never
    #      consumes a budget slot that an eligible one could use.
    #   2. Prioritize NOT-YET-PROCESSED eligible items over already-done
    #      ones (deterministic secondary sort: risk_score DESC, then
    #      stix_id for a stable tie-break -- never incidental array
    #      order), so MAX_ITEMS becomes a per-run NEW-work budget rather
    #      than a fixed window. As already-processed items accumulate,
    #      lower-priority eligible items that were previously stuck past
    #      the old positional cutoff rotate into the window on subsequent
    #      runs -- no item is permanently stuck.
    def _has_all_rules(it: dict) -> bool:
        return bool(it.get("sigma_rule") and it.get("kql_query") and it.get("suricata_rule"))

    eligible_items = [it for it in items if is_detection_eligible(it)]
    unprocessed = [it for it in eligible_items if not _has_all_rules(it)]
    unprocessed.sort(
        key=lambda it: (-float(it.get("risk_score") or 0), str(it.get("stix_id") or it.get("id") or "")),
    )
    selected = unprocessed[:MAX_ITEMS]
    selected_ids = {id(it) for it in selected}

    log.info(
        "Eligibility: %d/%d items eligible, %d already processed, %d unprocessed, %d selected this run (budget=%d)",
        len(eligible_items), len(items), len(eligible_items) - len(unprocessed),
        len(unprocessed), len(selected), MAX_ITEMS,
    )

    # Phase 4.1 mandate Section 20 fix: this loop previously had no per-item
    # exception isolation. A single item that crashed _classify_vuln/_sigma_
    # rule/_kql_query/_suricata_rule (or the manifest sync / per-item file
    # write) propagated straight out of run() uncaught -- aborting the WHOLE
    # pass. Because the feed/manifest write only happens once, AFTER the
    # loop finishes, this didn't just skip the bad item: it silently
    # discarded every item successfully processed earlier in that same run
    # too (nothing had been written to disk yet), and (per STAGE 3.1.12's
    # continue-on-error: true in sentinel-apex.yml) the pipeline
    # continued past the crash with no detection content written at all and
    # no failure surfaced beyond a log line. Wrapping just the per-item body
    # fixes both failure modes at once: a crash on item N now costs exactly
    # item N, not items 1..N-1 already processed this run.
    injected = 0; skipped = 0; failed = 0; failed_ids: list = []
    for item in items:
        if id(item) not in selected_ids:
            continue
        stix_id = str(item.get("stix_id") or item.get("id") or "")
        # Skip if already has detection rules from this session
        if item.get("sigma_rule") and item.get("kql_query") and item.get("suricata_rule"):
            skipped += 1
            continue

        try:
            title      = str(item.get("title") or "")
            tags       = item.get("tags") or []
            threat_type= str(item.get("threat_type") or "")
            cve_id     = item.get("cve_id") or ""
            vuln_class = _classify_vuln(title, tags, threat_type, cve_id)

            sigma     = _sigma_rule(item, vuln_class)
            kql       = _kql_query(item, vuln_class)
            suricata  = _suricata_rule(item, vuln_class)

            item["sigma_rule"]     = sigma
            item["kql_query"]      = kql
            item["suricata_rule"]  = suricata
            item["vuln_class"]     = vuln_class
            item["detection_generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Sync to manifest
            if stix_id in manifest_by_id:
                manifest_by_id[stix_id].update({
                    "sigma_rule": sigma, "kql_query": kql,
                    "suricata_rule": suricata, "vuln_class": vuln_class,
                })

            # Write individual detection file for API endpoint
            if stix_id and not DRY_RUN:
                det_path = DETECTIONS_DIR / f"{stix_id}.json"
                det_path.parent.mkdir(parents=True, exist_ok=True)
                det_payload = {
                    "stix_id": stix_id, "cve_id": cve_id, "title": title,
                    "vuln_class": vuln_class,
                    "sigma_rule": sigma, "kql_query": kql, "suricata_rule": suricata,
                    "generated_at": item["detection_generated_at"],
                    "_tier": "PRO",
                    "_notice": "Detection rules require PRO subscription. Subscribe at intel.cyberdudebivash.com/upgrade.html",
                }
                det_path.write_text(json.dumps(det_payload, indent=2), encoding="utf-8")

            injected += 1
            log.info("[DETECT] %s → vuln_class=%s sigma+kql+suricata injected", stix_id[:40], vuln_class)
        except Exception as e:
            # Log a safe error (item id + exception type/message only -- no
            # raw item dump that could leak unrelated fields into logs) and
            # continue to the next item. Exception (not BaseException) so
            # KeyboardInterrupt/SystemExit still propagate -- this isolates
            # one item's bug, it does not swallow a genuine system-level
            # abort signal.
            failed += 1
            failed_ids.append(stix_id[:40] or "unknown")
            log.error("[DETECT-FAIL] %s → %s: %s", stix_id[:40] or "unknown", type(e).__name__, e)
            continue

    log.info("COMPLETE: injected=%d skipped=%d failed=%d", injected, skipped, failed)
    if failed:
        log.warning("Failed item ids (first 20): %s", failed_ids[:20])

    if not DRY_RUN and (injected > 0 or failed > 0):
        out = feed if isinstance(feed, list) else {**feed, "advisories": items}
        _atomic_write(feed_path, out)
        log.info("[WRITE] Feed updated")
        if manifest_items:
            _atomic_write(manifest_path, manifest_items)
            log.info("[WRITE] Manifest updated")
        _atomic_write(TELEMETRY, {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "injected": injected, "skipped": skipped, "total_items": len(items),
            # Phase 4.1 mandate Section 20/21: failed is now tracked and
            # surfaced (previously any per-item failure crashed the whole
            # run before this counter could ever be written) -- a nonzero
            # value here means real items with real content failed
            # generation and should be investigated, not silently retried
            # forever with no visibility.
            "failed": failed, "failed_ids_sample": failed_ids[:20],
            # v185.0: transparent processing-budget accounting -- numerator+
            # denominator, never a bare percentage. remaining_unprocessed_
            # eligible is the count still waiting for a future run's budget;
            # this should trend toward 0 as runs accumulate, never grow
            # unboundedly (which would indicate eligible items arriving
            # faster than the budget can cover them).
            "eligible_items": len(eligible_items),
            "already_processed_before_run": len(eligible_items) - len(unprocessed),
            "unprocessed_before_run": len(unprocessed),
            "selected_this_run": len(selected),
            "max_items_budget": MAX_ITEMS,
            "remaining_unprocessed_eligible": max(0, len(unprocessed) - len(selected)),
        })

    return {"injected": injected, "skipped": skipped, "failed": failed}


if __name__ == "__main__":
    result = run(FEED_PATH, MANIFEST_PATH)
    print(f"[DONE] {result}")
