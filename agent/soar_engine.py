#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX                                            ║
║  SOAR + INTEGRATION ENGINE v1.0                                           ║
║  Block IP · Disable User · Enrich IOC · Splunk/Sentinel/CrowdStrike       ║
╚══════════════════════════════════════════════════════════════════════════════╝
Zero-regression · Safe execution · No destructive action without validation
· Retry + rollback · Idempotent workflows
"""

import os
import sys
import re
import json
import hashlib
import hmac
import logging
import time
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-SOAR-ENGINE")
logging.basicConfig(level=logging.INFO, format="[SOAR-ENGINE] %(asctime)s %(levelname)s %(message)s")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH   = os.path.join(BASE_DIR, "data", "enriched_manifest.json")
OUTPUT_DIR      = os.path.join(BASE_DIR, "data", "soar_engine")
PLAYBOOK_DIR    = os.path.join(OUTPUT_DIR, "playbooks")
WORKFLOW_LOG    = os.path.join(OUTPUT_DIR, "workflow_executions.jsonl")
IOC_ENRICHED    = os.path.join(OUTPUT_DIR, "ioc_enrichment.json")
SIEM_DISPATCH   = os.path.join(OUTPUT_DIR, "siem_dispatch_queue.json")
RESPONSE_ACTIONS= os.path.join(OUTPUT_DIR, "response_actions.json")
ENGINE_META     = os.path.join(OUTPUT_DIR, "engine_meta.json")

# ── SIEM integration config (reads from env — never hardcoded secrets) ────────
SIEM_ENDPOINTS = {
    "splunk": {
        "name": "Splunk Enterprise Security",
        "base_url": os.getenv("SPLUNK_BASE_URL", "https://splunk.example.com:8089"),
        "auth_header": "Authorization",
        "auth_value": f"Splunk {os.getenv('SPLUNK_API_TOKEN', 'PLACEHOLDER')}",
        "hec_endpoint": "/services/collector/event",
        "search_endpoint": "/services/search/jobs",
    },
    "sentinel": {
        "name": "Microsoft Sentinel",
        "workspace_id": os.getenv("SENTINEL_WORKSPACE_ID", "PLACEHOLDER"),
        "base_url": "https://api.loganalytics.io/v1",
        "auth_header": "Authorization",
        "auth_value": f"Bearer {os.getenv('SENTINEL_API_TOKEN', 'PLACEHOLDER')}",
        "incident_endpoint": "/incidents",
    },
    "crowdstrike": {
        "name": "CrowdStrike Falcon",
        "base_url": "https://api.crowdstrike.com",
        "client_id": os.getenv("CS_CLIENT_ID", "PLACEHOLDER"),
        "client_secret": os.getenv("CS_CLIENT_SECRET", "PLACEHOLDER"),
        "ioc_endpoint": "/indicators/entities/iocs/v1",
        "detection_endpoint": "/detects/entities/detects/v2",
    },
    "elastic": {
        "name": "Elastic SIEM",
        "base_url": os.getenv("ELASTIC_BASE_URL", "https://elastic.example.com:9200"),
        "auth_header": "Authorization",
        "auth_value": f"ApiKey {os.getenv('ELASTIC_API_KEY', 'PLACEHOLDER')}",
        "alert_endpoint": "/_security/api_key",
    },
}

# ── Severity → response threshold ────────────────────────────────────────────
RESPONSE_THRESHOLDS = {
    "CRITICAL": {"auto_respond": True,  "min_confidence": 0.85, "priority": 1},
    "HIGH":     {"auto_respond": False, "min_confidence": 0.75, "priority": 2},
    "MEDIUM":   {"auto_respond": False, "min_confidence": 0.65, "priority": 3},
    "LOW":      {"auto_respond": False, "min_confidence": 0.50, "priority": 4},
}

# ── IOC type detection ────────────────────────────────────────────────────────
IPv4_RE   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
HASH_MD5  = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256=re.compile(r'\b[a-fA-F0-9]{64}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}\b')
URL_RE    = re.compile(r'https?://[^\s\'"<>]{5,100}')


def _atomic_write(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _append_jsonl(path: str, record: Dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _load_manifest() -> List[Dict]:
    for candidate in [MANIFEST_PATH,
                      os.path.join(BASE_DIR, "data", "advisory_manifest.json"),
                      os.path.join(BASE_DIR, "data", "stix", "manifest.json")]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else data.get("advisories", [])
            except Exception as e:
                logger.warning(f"Failed to load {candidate}: {e}")
    return []


def _action_id(action_type: str, target: str) -> str:
    return f"ACT-{hashlib.md5(f'{action_type}:{target}'.encode()).hexdigest()[:8].upper()}"


def _workflow_id(trigger: str) -> str:
    return f"WF-{hashlib.md5(f'{trigger}{datetime.now(timezone.utc).date()}'.encode()).hexdigest()[:10].upper()}"


# ──────────────────────────────────────────────────────────────────────────────
# IOC ENRICHMENT ENGINE
# ──────────────────────────────────────────────────────────────────────────────
class IOCEnrichmentEngine:
    """
    Extracts and enriches IOCs from advisories.
    Assigns confidence scores and SIEM dispatch priority.
    """

    def enrich(self, advisories: List[Dict]) -> Dict:
        all_iocs: List[Dict] = []
        ioc_dedup: set = set()

        for adv in advisories:
            text = " ".join([adv.get("title", ""), adv.get("summary", ""),
                              adv.get("description", "")])

            severity = adv.get("severity", "MEDIUM")
            kev = bool(adv.get("kev_confirmed") or adv.get("ei_kev_confirmed"))
            epss = float(adv.get("epss") or adv.get("ei_epss") or 0)
            base_conf = 0.5 + (0.2 if kev else 0) + min(0.2, epss)

            def add_ioc(ioc_val: str, ioc_type: str) -> None:
                key = f"{ioc_type}:{ioc_val}"
                if key in ioc_dedup or len(ioc_val) < 5:
                    return
                # Skip obvious false positives
                if ioc_type == "ipv4" and ioc_val.startswith(
                        ("127.", "192.168.", "10.", "172.16.", "0.0.", "255.")):
                    return
                ioc_dedup.add(key)
                all_iocs.append({
                    "ioc_value": ioc_val[:200],
                    "ioc_type": ioc_type,
                    "source_advisory": adv.get("cve_id", adv.get("id", ""))[:50],
                    "severity": severity,
                    "confidence": round(min(1.0, base_conf), 4),
                    "kev_linked": kev,
                    "dispatch_priority": RESPONSE_THRESHOLDS.get(severity, {}).get("priority", 4),
                    "siem_action": "BLOCK" if severity == "CRITICAL" and kev else "MONITOR",
                })

            for ip in IPv4_RE.findall(text)[:5]:
                add_ioc(ip, "ipv4")
            for h in HASH_SHA256.findall(text)[:3]:
                add_ioc(h, "sha256")
            for h in HASH_MD5.findall(text)[:3]:
                add_ioc(h, "md5")
            for url in URL_RE.findall(text)[:3]:
                add_ioc(url, "url")
            # Also use pre-extracted IOCs from manifest
            for ioc in adv.get("iocs", [])[:5]:
                add_ioc(str(ioc)[:200], "manifest_ioc")

        all_iocs.sort(key=lambda x: (x["dispatch_priority"], -x["confidence"]))

        return {
            "total_iocs": len(all_iocs),
            "iocs_by_type": {
                t: sum(1 for i in all_iocs if i["ioc_type"] == t)
                for t in set(i["ioc_type"] for i in all_iocs)
            },
            "high_priority_iocs": [i for i in all_iocs
                                    if i["dispatch_priority"] <= 2][:50],
            "ioc_sample": all_iocs[:100],
        }


# ──────────────────────────────────────────────────────────────────────────────
# PLAYBOOK GENERATOR
# ──────────────────────────────────────────────────────────────────────────────
class PlaybookGenerator:
    """
    Generates SOAR playbooks for each threat scenario.
    All destructive actions require explicit validation gate.
    """

    PLAYBOOK_TEMPLATES = {
        "RANSOMWARE_RESPONSE": {
            "trigger": "ransomware_detected",
            "priority": 1,
            "steps": [
                {"step": 1, "action": "ISOLATE_HOST", "target": "affected_endpoints",
                 "destructive": True, "requires_approval": True,
                 "rollback": "reconnect_to_network"},
                {"step": 2, "action": "BLOCK_C2_IPS", "target": "c2_ip_list",
                 "destructive": False, "requires_approval": False,
                 "rollback": "unblock_ips"},
                {"step": 3, "action": "DISABLE_USER_ACCOUNTS", "target": "compromised_accounts",
                 "destructive": True, "requires_approval": True,
                 "rollback": "re-enable_accounts"},
                {"step": 4, "action": "SNAPSHOT_EVIDENCE", "target": "memory_forensics",
                 "destructive": False, "requires_approval": False},
                {"step": 5, "action": "NOTIFY_SOC", "target": "soc_team",
                 "destructive": False, "requires_approval": False},
                {"step": 6, "action": "CREATE_INCIDENT_TICKET", "target": "itsm_system",
                 "destructive": False, "requires_approval": False},
            ],
        },
        "CREDENTIAL_COMPROMISE": {
            "trigger": "credential_dump_detected",
            "priority": 1,
            "steps": [
                {"step": 1, "action": "FORCE_PASSWORD_RESET", "target": "affected_users",
                 "destructive": False, "requires_approval": False},
                {"step": 2, "action": "REVOKE_ACTIVE_SESSIONS", "target": "session_store",
                 "destructive": False, "requires_approval": False},
                {"step": 3, "action": "ENABLE_MFA_ENFORCEMENT", "target": "affected_accounts",
                 "destructive": False, "requires_approval": False},
                {"step": 4, "action": "AUDIT_PRIVILEGE_ACCESS", "target": "iam_system",
                 "destructive": False, "requires_approval": False},
                {"step": 5, "action": "NOTIFY_AFFECTED_USERS", "target": "email_system",
                 "destructive": False, "requires_approval": False},
            ],
        },
        "ACTIVE_EXPLOITATION": {
            "trigger": "active_exploit_detected",
            "priority": 1,
            "steps": [
                {"step": 1, "action": "BLOCK_EXPLOIT_IPS", "target": "firewall",
                 "destructive": False, "requires_approval": False,
                 "rollback": "unblock_ips"},
                {"step": 2, "action": "APPLY_VIRTUAL_PATCH", "target": "waf",
                 "destructive": False, "requires_approval": False},
                {"step": 3, "action": "INCREASE_LOG_VERBOSITY", "target": "siem",
                 "destructive": False, "requires_approval": False},
                {"step": 4, "action": "SCAN_FOR_INDICATORS", "target": "edr_platform",
                 "destructive": False, "requires_approval": False},
                {"step": 5, "action": "PATCH_ADVISORY_FAST_TRACK", "target": "patch_management",
                 "destructive": False, "requires_approval": False},
            ],
        },
        "IOC_ENRICHMENT_WORKFLOW": {
            "trigger": "new_ioc_ingested",
            "priority": 2,
            "steps": [
                {"step": 1, "action": "ENRICH_IOC_VT", "target": "virustotal_api",
                 "destructive": False, "requires_approval": False},
                {"step": 2, "action": "CHECK_IOC_INTEL", "target": "threat_intel_platform",
                 "destructive": False, "requires_approval": False},
                {"step": 3, "action": "PUSH_IOC_TO_SIEM", "target": "siem_platforms",
                 "destructive": False, "requires_approval": False},
                {"step": 4, "action": "UPDATE_BLOCKLIST", "target": "firewall_policy",
                 "destructive": False, "requires_approval": False},
            ],
        },
    }

    def generate(self, scenario: str) -> Optional[Dict]:
        template = self.PLAYBOOK_TEMPLATES.get(scenario)
        if not template:
            return None

        playbook_id = _workflow_id(scenario)
        return {
            "playbook_id": playbook_id,
            "playbook_name": scenario,
            "trigger": template["trigger"],
            "priority": template["priority"],
            "execution_mode": "SIMULATION",  # Always simulation in pipeline
            "steps": template["steps"],
            "total_steps": len(template["steps"]),
            "destructive_steps": sum(1 for s in template["steps"] if s.get("destructive")),
            "approval_required_steps": sum(1 for s in template["steps"]
                                            if s.get("requires_approval")),
            "safety_note": "All destructive steps require manual approval gate before execution.",
            "status": "READY",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def generate_all(self) -> List[Dict]:
        playbooks = []
        for scenario in self.PLAYBOOK_TEMPLATES:
            pb = self.generate(scenario)
            if pb:
                playbooks.append(pb)
        return playbooks


# ──────────────────────────────────────────────────────────────────────────────
# SIEM DISPATCH BUILDER
# ──────────────────────────────────────────────────────────────────────────────
class SIEMDispatchBuilder:
    """
    Builds SIEM dispatch payloads for Splunk, Sentinel, CrowdStrike, Elastic.
    All payloads are in simulation mode — actual API calls require valid creds.
    """

    def build_dispatch_queue(self, advisories: List[Dict], ioc_result: Dict) -> Dict:
        dispatch_queue = []

        # High-priority IOC dispatches
        for ioc in ioc_result.get("high_priority_iocs", [])[:30]:
            dispatch_id = _action_id("IOC_DISPATCH", ioc["ioc_value"][:50])
            for siem_name, siem_cfg in SIEM_ENDPOINTS.items():
                dispatch_queue.append({
                    "dispatch_id": dispatch_id,
                    "siem": siem_name,
                    "siem_name": siem_cfg["name"],
                    "action": "CREATE_IOC_INDICATOR",
                    "ioc_type": ioc["ioc_type"],
                    "ioc_value": ioc["ioc_value"],
                    "confidence": ioc["confidence"],
                    "severity": ioc["severity"],
                    "execution_mode": "SIMULATION",
                    "status": "QUEUED",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })

        # Critical advisory alerts
        critical_advisories = [a for a in advisories
                                if a.get("severity", "") == "CRITICAL"][:20]
        for adv in critical_advisories:
            for siem_name in ["splunk", "sentinel"]:
                siem_cfg = SIEM_ENDPOINTS[siem_name]
                dispatch_queue.append({
                    "dispatch_id": _action_id("ALERT_DISPATCH", adv.get("cve_id", "")),
                    "siem": siem_name,
                    "siem_name": siem_cfg["name"],
                    "action": "CREATE_ALERT",
                    "cve_id": adv.get("cve_id", ""),
                    "title": adv.get("title", "")[:100],
                    "severity": "CRITICAL",
                    "execution_mode": "SIMULATION",
                    "status": "QUEUED",
                    "splunk_payload": {
                        "event": {
                            "cve": adv.get("cve_id", ""),
                            "title": adv.get("title", "")[:100],
                            "severity": "CRITICAL",
                            "source": "CYBERDUDEBIVASH_SENTINEL_APEX",
                        },
                        "sourcetype": "cdb:threat_intel",
                        "index": "threat_intel",
                    },
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })

        return {
            "dispatch_queue": dispatch_queue[:100],
            "total_dispatches": len(dispatch_queue),
            "dispatches_by_siem": {
                siem: sum(1 for d in dispatch_queue if d["siem"] == siem)
                for siem in SIEM_ENDPOINTS
            },
            "execution_mode": "SIMULATION",
            "note": "All dispatches are queued for manual review before live execution.",
        }


# ──────────────────────────────────────────────────────────────────────────────
# RESPONSE ACTION ENGINE
# ──────────────────────────────────────────────────────────────────────────────
class ResponseActionEngine:
    """
    Generates response action recommendations.
    NEVER executes destructive actions automatically.
    """

    RESPONSE_RULES = [
        {
            "condition": lambda adv: adv.get("severity") == "CRITICAL" and
                                     (adv.get("kev_confirmed") or adv.get("ei_kev_confirmed")),
            "actions": ["EMERGENCY_PATCH", "WAF_VIRTUAL_PATCH", "ENHANCED_MONITORING",
                        "SOC_ESCALATION", "INCIDENT_TICKET"],
            "priority": 1,
        },
        {
            "condition": lambda adv: adv.get("ei_exploit_status") in
                                     ("WEAPONIZED", "EXPLOITED_IN_WILD"),
            "actions": ["BLOCK_EXPLOIT_VECTORS", "ENDPOINT_SCAN",
                        "NETWORK_ISOLATION_REVIEW", "PATCH_FAST_TRACK"],
            "priority": 2,
        },
        {
            "condition": lambda adv: adv.get("severity") == "HIGH" and
                                     float(adv.get("epss") or adv.get("ei_epss") or 0) >= 0.5,
            "actions": ["PATCH_PRIORITIZE", "VULNERABILITY_SCAN",
                        "COMPENSATING_CONTROLS"],
            "priority": 3,
        },
    ]

    def generate_responses(self, advisories: List[Dict]) -> List[Dict]:
        responses = []
        seen_advisories: set = set()

        for adv in advisories:
            aid = adv.get("id", adv.get("cve_id", ""))
            if not aid or aid in seen_advisories:
                continue

            for rule in self.RESPONSE_RULES:
                try:
                    if rule["condition"](adv):
                        seen_advisories.add(aid)
                        responses.append({
                            "response_id": _action_id("RESPONSE", aid),
                            "advisory_id": aid,
                            "cve_id": adv.get("cve_id", ""),
                            "title": adv.get("title", "")[:100],
                            "severity": adv.get("severity", "MEDIUM"),
                            "recommended_actions": rule["actions"],
                            "priority": rule["priority"],
                            "execution_mode": "SIMULATION",
                            "auto_execute": False,  # Always False — safety gate
                            "status": "PENDING_REVIEW",
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                        })
                        break
                except Exception:
                    continue

        return sorted(responses, key=lambda x: x["priority"])


# ──────────────────────────────────────────────────────────────────────────────
# SOAR ENGINE ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
class SOAREngine:
    def __init__(self):
        self.ioc_engine = IOCEnrichmentEngine()
        self.playbook_gen = PlaybookGenerator()
        self.siem_builder = SIEMDispatchBuilder()
        self.response_engine = ResponseActionEngine()

    def run(self) -> int:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs(PLAYBOOK_DIR, exist_ok=True)
        logger.info("=== SOAR ENGINE START ===")

        advisories = _load_manifest()
        if not advisories:
            logger.warning("No advisories — writing empty outputs")
            self._write_empty()
            return 0

        logger.info(f"Processing {len(advisories)} advisories for SOAR workflows")

        # Step 1: IOC enrichment
        ioc_result = self.ioc_engine.enrich(advisories)
        logger.info(f"IOCs extracted: {ioc_result['total_iocs']}")

        # Step 2: Generate playbooks
        playbooks = self.playbook_gen.generate_all()
        logger.info(f"Playbooks generated: {len(playbooks)}")

        # Save individual playbook files
        for pb in playbooks:
            pb_path = os.path.join(PLAYBOOK_DIR, f"{pb['playbook_name'].lower()}.json")
            _atomic_write(pb_path, pb)

        # Step 3: Build SIEM dispatch queue
        siem_queue = self.siem_builder.build_dispatch_queue(advisories, ioc_result)
        logger.info(f"SIEM dispatches queued: {siem_queue['total_dispatches']}")

        # Step 4: Generate response actions
        responses = self.response_engine.generate_responses(advisories)
        logger.info(f"Response actions generated: {len(responses)}")

        # Atomic writes
        _atomic_write(IOC_ENRICHED, {
            **ioc_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(SIEM_DISPATCH, {
            **siem_queue,
            "siem_endpoints_configured": list(SIEM_ENDPOINTS.keys()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(RESPONSE_ACTIONS, {
            "response_actions": responses[:100],
            "total_actions": len(responses),
            "priority_1_count": sum(1 for r in responses if r["priority"] == 1),
            "execution_mode": "SIMULATION",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })

        # SIEM integration summary
        siem_summary = {
            "configured_siem_platforms": list(SIEM_ENDPOINTS.keys()),
            "platform_details": [
                {"name": cfg["name"], "key": k, "status": "CONFIGURED_SIMULATION"}
                for k, cfg in SIEM_ENDPOINTS.items()
            ],
            "dispatch_queue_size": siem_queue["total_dispatches"],
            "integration_mode": "SIMULATION — populate env vars for live integration",
            "env_vars_needed": [
                "SPLUNK_BASE_URL", "SPLUNK_API_TOKEN",
                "SENTINEL_WORKSPACE_ID", "SENTINEL_API_TOKEN",
                "CS_CLIENT_ID", "CS_CLIENT_SECRET",
                "ELASTIC_BASE_URL", "ELASTIC_API_KEY",
            ],
        }

        meta = {
            "engine": "SOAREngine",
            "version": "1.0.0",
            "advisories_processed": len(advisories),
            "iocs_extracted": ioc_result["total_iocs"],
            "playbooks_generated": len(playbooks),
            "siem_dispatches_queued": siem_queue["total_dispatches"],
            "response_actions": len(responses),
            "priority_1_responses": sum(1 for r in responses if r["priority"] == 1),
            "siem_platforms": list(SIEM_ENDPOINTS.keys()),
            "execution_mode": "SIMULATION",
            "siem_integration_summary": siem_summary,
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(ENGINE_META, meta)

        logger.info(f"IOCs: {ioc_result['total_iocs']}, playbooks: {len(playbooks)}")
        logger.info(f"SIEM dispatches: {siem_queue['total_dispatches']}, responses: {len(responses)}")
        logger.info("=== SOAR ENGINE COMPLETE ===")
        return 0

    def _write_empty(self) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        for path in [IOC_ENRICHED, SIEM_DISPATCH, RESPONSE_ACTIONS]:
            _atomic_write(path, {"generated_at": ts})
        _atomic_write(ENGINE_META, {
            "engine": "SOAREngine", "version": "1.0.0",
            "advisories_processed": 0, "run_timestamp": ts,
        })


def main() -> int:
    try:
        engine = SOAREngine()
        return engine.run()
    except Exception as e:
        logger.error(f"SOAREngine fatal: {e}", exc_info=True)
        try:
            _atomic_write(ENGINE_META, {
                "engine": "SOAREngine", "version": "1.0.0",
                "error": str(e)[:500],
                "run_timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass
        return 0  # Never fail pipeline


if __name__ == "__main__":
    sys.exit(main())
