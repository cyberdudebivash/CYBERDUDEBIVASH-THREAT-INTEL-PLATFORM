#!/usr/bin/env python3
"""
SENTINEL APEX — Operational IOC Validator v1.0.0
Valid IOC types: IPv4, IPv6, Domain, URL, SHA256, SHA1, MD5,
                Registry Key, Mutex, Email, YARA, Sigma, Suricata artifacts.
Invalid: vendor URLs, advisory links, filenames, function names.
Outputs: api/ioc_quality.json
"""
from __future__ import annotations
import argparse, json, logging, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

ENGINE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [ioc-validator] %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

RE_IPV4   = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?$")
RE_IPV6   = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
RE_MD5    = re.compile(r"^[0-9a-fA-F]{32}$")
RE_SHA1   = re.compile(r"^[0-9a-fA-F]{40}$")
RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
RE_EMAIL  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_REGKEY = re.compile(r"^(?:HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)[\\\w\s\-\.]+$", re.I)
RE_URL    = re.compile(r"^https?://[^\s\"\'<>]{4,}")

FP_DOMAINS = frozenset([
    "nvd.nist.gov","cve.mitre.org","vulners.com","cvefeed.io","cz.nic",
    "github.com","raw.githubusercontent.com","gist.github.com",
    "microsoft.com","support.microsoft.com","intel.cyberdudebivash.com",
    "cyberdudebivash.com","cisa.gov","cert.org","us-cert.gov",
    "bleepingcomputer.com","securityweek.com","therecord.media",
    "rapid7.com","sophos.com","kaspersky.com","checkpoint.com",
    "paloaltonetworks.com","crowdstrike.com","mandiant.com",
    "securelist.com","unit42.paloaltonetworks.com","blog.checkpoint.com",
    "news.sophos.com","talos-intelligence.com",
])
FP_URL_PATTERNS = [
    r"nvd\.nist\.gov/vuln",r"cve\.mitre\.org/cgi",r"github\.com/advisories",
    r"github\.com/.*/(issues|pull|commit|releases)",r"/advisories?/",
    r"/security-advisories?/",r"\.microsoft\.com/",r"cyberdudebivash\.com",
    r"bleepingcomputer\.com",r"securityweek\.com",r"rapid7\.com/blog",
    r"sophos\.com/",r"kaspersky\.com/",r"securelist\.com/",r"checkpoint\.com/",
]
FP_STRINGS = re.compile(
    r"(\.ts$|\.js$|\.py$|\.md$|\.txt$|\.json$|README|function |class |import |"
    r"package |module |node_modules|CVE-\d{4}-\d+|GHSA-|RHSA-|USN-)", re.I)
RESERVED_PREFIXES = (
    "0.","10.","127.","169.254.","172.16.","172.17.","172.18.","172.19.",
    "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.",
    "172.27.","172.28.","172.29.","172.30.","172.31.","192.168.","224.","240.","255.",
)
SIGMA_GENERIC_MARKERS = [
    r"EventID.*4625",r"EventID.*4648",r"EventID.*4728",r"LogonType:\s*3",
    r"Class:\s*GENERIC",r"category:\s*network_connection\b",r"product:\s*generic",
]
SURICATA_GENERIC_MARKERS = [r"\|90\s+90\s+90\s+90\|",r"msg:.*GENERIC",r"threshold:.*type threshold.*track by_src.*count 3.*seconds 60"]


def classify_ioc(value: str) -> Tuple[str, bool, str]:
    v = str(value).strip()
    if not v or len(v) < 4: return "UNKNOWN", False, "too short"
    if RE_SHA256.match(v): return "SHA256", True, "valid SHA-256 hash"
    if RE_SHA1.match(v):   return "SHA1",   True, "valid SHA-1 hash"
    if RE_MD5.match(v):    return "MD5",    True, "valid MD5 hash"
    if RE_REGKEY.match(v): return "REGISTRY_KEY", True, "Windows registry key"
    if RE_EMAIL.match(v):  return "EMAIL",  True, "email address"
    if RE_IPV4.match(v.split("/")[0]):
        ip = v.split("/")[0]
        if any(ip.startswith(p) for p in RESERVED_PREFIXES):
            return "IPV4", False, f"reserved/non-routable: {ip}"
        return "IPV4", True, "operational IPv4 address"
    if RE_IPV6.match(v): return "IPV6", True, "operational IPv6 address"
    if RE_URL.match(v):
        for fp in FP_URL_PATTERNS:
            if re.search(fp, v, re.I): return "URL", False, f"advisory/vendor URL: {fp}"
        try:
            from urllib.parse import urlparse
            host = urlparse(v).hostname or ""
            if host in FP_DOMAINS or any(host.endswith("."+d) for d in FP_DOMAINS):
                return "URL", False, f"known vendor/advisory domain: {host}"
        except Exception: pass
        return "URL", True, "operational URL indicator"
    if RE_DOMAIN.match(v):
        if v in FP_DOMAINS or any(v.endswith("."+d) for d in FP_DOMAINS):
            return "DOMAIN", False, f"known advisory/vendor domain: {v}"
        tld = v.rsplit(".",1)[-1].lower()
        if len(tld) > 6: return "DOMAIN", False, f"suspicious TLD length: .{tld}"
        return "DOMAIN", True, "operational domain"
    if FP_STRINGS.search(v): return "STRING", False, "filesystem/code artifact"
    return "UNKNOWN", False, "unrecognized format"


def validate_sigma(sigma_text: str) -> Tuple[bool, str]:
    if not sigma_text: return False, "empty rule"
    for marker in SIGMA_GENERIC_MARKERS:
        if re.search(marker, sigma_text, re.I): return False, f"generic pattern: {marker}"
    has_specific = bool(re.search(
        r"(CVE-\d{4}-\d+|sha256|md5|CommandLine\|contains|Image\|contains|"
        r"TargetFilename|RegistryKey|RegistryValue|DestinationHostname\|contains|"
        r"DestinationIp\||Hash\||User-Agent\|contains)",
        sigma_text, re.I))
    if not has_specific: return False, "no specific artifact (CVE, hash, process, registry, network)"
    return True, "production-ready: references specific artifact"


def validate_suricata(rule_text: str) -> Tuple[bool, str]:
    if not rule_text: return False, "empty rule"
    for marker in SURICATA_GENERIC_MARKERS:
        if re.search(marker, rule_text, re.I): return False, f"generic pattern: {marker}"
    has_specific = bool(re.search(
        r'(content:"[A-Za-z0-9/\-_\.]{8,}"|pcre:\"/.{8,}/|http\.uri\s*;|'
        r'http\.header\s*;|tls\.sni\s*;|dns\.query\s*;|CVE-\d{4}-\d+|file\.data\s*;)',
        rule_text, re.I))
    if not has_specific: return False, "no specific content/pcre match"
    return True, "production-ready"


def extract_iocs_from_item(item: Dict) -> List[Dict]:
    candidates = []
    for ioc in (item.get("iocs") or []):
        if isinstance(ioc, dict):
            val = ioc.get("value") or ioc.get("indicator") or ""
            candidates.append({"value": val, "declared_type": ioc.get("type",""), "source_field": "iocs"})
        elif isinstance(ioc, str):
            candidates.append({"value": ioc, "declared_type": "", "source_field": "iocs"})
    ibt = item.get("iocs_by_type") or {}
    if isinstance(ibt, dict):
        for ioc_type, vals in ibt.items():
            if isinstance(vals, list):
                for v in vals:
                    candidates.append({"value": str(v), "declared_type": ioc_type, "source_field": "iocs_by_type"})
    for field in ("ip","domain","hash","url","email","mutex","registry_key"):
        val = item.get(field)
        if val: candidates.append({"value": str(val), "declared_type": field, "source_field": field})
    return candidates


def validate_item_iocs(item: Dict) -> Dict:
    candidates = extract_iocs_from_item(item)
    operational, false_positive = [], []
    for c in candidates:
        ioc_type, is_op, reason = classify_ioc(c["value"])
        record = {**c, "detected_type": ioc_type, "operational": is_op, "reason": reason}
        if is_op: operational.append(record)
        elif ioc_type != "UNKNOWN": false_positive.append(record)
    sigma_ready, sigma_reason = validate_sigma(item.get("sigma_rule") or "")
    suricata_ready, suricata_reason = validate_suricata(item.get("suricata_rule") or "")
    return {
        "id": item.get("id",""),
        "operational_ioc_count": len(operational),
        "false_positive_count": len(false_positive),
        "operational_iocs": operational,
        "false_positive_iocs": false_positive,
        "sigma_production_ready": sigma_ready,
        "sigma_reason": sigma_reason,
        "suricata_production_ready": suricata_ready,
        "suricata_reason": suricata_reason,
        "deployable_detection_count": int(sigma_ready) + int(suricata_ready),
    }


def process_feed(items: List[Dict]) -> Dict:
    results = []
    total_op, total_fp, total_deploy = 0, 0, 0
    for item in items:
        r = validate_item_iocs(item)
        results.append(r)
        total_op += r["operational_ioc_count"]
        total_fp += r["false_positive_count"]
        total_deploy += r["deployable_detection_count"]
    ioc_quality_score = 0
    if total_op + total_fp > 0:
        ioc_quality_score = int(total_op / (total_op + total_fp) * 100)
    elif total_deploy > 0:
        ioc_quality_score = 40
    return {
        "operational_ioc_total": total_op,
        "false_ioc_total": total_fp,
        "deployable_detection_total": total_deploy,
        "ioc_quality_score": ioc_quality_score,
        "items_with_operational_iocs": sum(1 for r in results if r["operational_ioc_count"] > 0),
        "items_with_deployable_detections": sum(1 for r in results if r["deployable_detection_count"] > 0),
        "per_item": results,
        "engine_version": ENGINE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Operational IOC Validator v{ENGINE_VERSION}")
    parser.add_argument("feed", nargs="?", default=str(REPO_ROOT / "api" / "feed.json"))
    parser.add_argument("--output", default=str(REPO_ROOT / "api" / "ioc_quality.json"))
    parser.add_argument("--report", default=None)
    args = parser.parse_args()
    raw = Path(args.feed).read_bytes().rstrip(b"\x00")
    data = json.loads(raw)
    items = data if isinstance(data, list) else data.get("threats", data.get("items", []))
    log.info("[ioc-validator] Processing %d items", len(items))
    result = process_feed(items)
    log.info("[ioc-validator] operational=%d false=%d deployable_detections=%d quality_score=%d",
             result["operational_ioc_total"], result["false_ioc_total"],
             result["deployable_detection_total"], result["ioc_quality_score"])
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("[ioc-validator] Output written to %s", out)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0

if __name__ == "__main__":
    sys.exit(main())
