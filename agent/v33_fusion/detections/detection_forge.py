#!/usr/bin/env python3
"""
detection_forge.py — CYBERDUDEBIVASH® SENTINEL APEX v33.0
==========================================================
DetectionForge — Unified multi-format detection artifact generation engine.
Consolidates Sigma, YARA, Suricata, Snort, Elastic, and KQL generation
into a single pipeline that auto-generates detection packs from fusion contexts.

Integrates with existing v27 auto_rules/* modules (non-breaking).
Adds: Suricata, Snort, Elastic DSL, KQL output formats.

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os
import re
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-DetectionForge")

DETECTION_DIR = os.environ.get("DETECTION_DIR", "data/fusion/detections")


@dataclass
class DetectionPack:
    """Complete detection artifact pack for a threat."""
    pack_id: str
    threat_title: str
    created_at: str
    sigma_rules: List[str] = field(default_factory=list)
    yara_rules: List[str] = field(default_factory=list)
    suricata_rules: List[str] = field(default_factory=list)
    snort_rules: List[str] = field(default_factory=list)
    elastic_queries: List[str] = field(default_factory=list)
    kql_queries: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "pack_id": self.pack_id,
            "threat_title": self.threat_title,
            "created_at": self.created_at,
            "sigma_count": len(self.sigma_rules),
            "yara_count": len(self.yara_rules),
            "suricata_count": len(self.suricata_rules),
            "snort_count": len(self.snort_rules),
            "elastic_count": len(self.elastic_queries),
            "kql_count": len(self.kql_queries),
            "total_rules": (
                len(self.sigma_rules) + len(self.yara_rules) +
                len(self.suricata_rules) + len(self.snort_rules) +
                len(self.elastic_queries) + len(self.kql_queries)
            ),
        }


class DetectionForge:
    """Unified detection artifact generation engine."""

    def __init__(self, output_dir: str = DETECTION_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def forge_from_iocs(self, title: str, iocs: Dict, cves: List[str] = None,
                         techniques: List[str] = None, actor: str = None) -> DetectionPack:
        """Generate complete detection pack from IOC data."""
        pack_id = f"dp-{hashlib.md5(title.encode()).hexdigest()[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        cves = cves or []
        techniques = techniques or []

        ips = iocs.get("ips", iocs.get("ipv4", []))
        domains = iocs.get("domains", [])
        hashes = iocs.get("sha256", []) + iocs.get("md5", []) + iocs.get("sha1", [])
        urls = iocs.get("urls", [])
        files = iocs.get("files", iocs.get("filenames", []))

        pack = DetectionPack(pack_id=pack_id, threat_title=title, created_at=now)

        # Generate Sigma rules
        if ips or domains or hashes:
            pack.sigma_rules.append(self._gen_sigma_network(title, ips, domains, actor))
        if hashes:
            pack.sigma_rules.append(self._gen_sigma_hash(title, hashes, actor))
        if files:
            pack.sigma_rules.append(self._gen_sigma_file(title, files, actor))

        # Generate YARA rules
        if hashes or files:
            pack.yara_rules.append(self._gen_yara(title, hashes, files, actor))

        # Generate Suricata rules
        for ip in ips[:20]:
            pack.suricata_rules.append(self._gen_suricata_ip(title, ip, pack_id))
        for domain in domains[:20]:
            pack.suricata_rules.append(self._gen_suricata_domain(title, domain, pack_id))

        # Generate Snort rules
        for ip in ips[:20]:
            pack.snort_rules.append(self._gen_snort_ip(title, ip, pack_id))

        # Generate Elastic queries
        if ips or domains or hashes:
            pack.elastic_queries.append(self._gen_elastic_query(title, ips, domains, hashes))

        # Generate KQL queries
        if ips or domains or hashes:
            pack.kql_queries.append(self._gen_kql_query(title, ips, domains, hashes))

        return pack

    def forge_from_manifest_entry(self, entry: Dict) -> DetectionPack:
        """Generate detection pack from a manifest entry."""
        title = entry.get("title", "Unknown Threat")

        # Extract IOCs from STIX bundle
        stix_file = entry.get("stix_file", "")
        iocs = {}
        if stix_file:
            stix_path = os.path.join("data/stix", stix_file)
            if os.path.exists(stix_path):
                try:
                    import re as _re
                    with open(stix_path, 'r') as f:
                        bundle = json.load(f)
                    ips, domains, urls, hashes, files = [], [], [], [], []
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "indicator":
                            pattern = obj.get("pattern", "")
                            name = obj.get("name", "")
                            ip_m = _re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
                            if ip_m: ips.append(ip_m.group(1))
                            dom_m = _re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
                            if dom_m: domains.append(dom_m.group(1))
                            url_m = _re.search(r"url:value\s*=\s*'([^']+)'", pattern)
                            if url_m: urls.append(url_m.group(1))
                            hash_m = _re.search(r"file:hashes\.'[^']+'\s*=\s*'([^']+)'", pattern)
                            if hash_m: hashes.append(hash_m.group(1))
                            if "Malicious File:" in name:
                                fname = name.replace("Malicious File:", "").strip()
                                if fname: files.append(fname)
                    iocs = {"ips": ips, "domains": domains, "urls": urls, "sha256": hashes, "filenames": files}
                except Exception:
                    pass

        cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE)))
        techniques = entry.get("mitre_tactics", [])
        actor = entry.get("actor_tag", entry.get("actor_id", ""))
        return self.forge_from_iocs(title, iocs, cves, techniques, actor)

    def batch_forge(self, entries: List[Dict], max_entries: int = 50) -> List[DetectionPack]:
        """Generate detection packs for multiple entries."""
        packs = []
        for entry in entries[:max_entries]:
            # Check if entry has IOC indicators (ioc_counts or indicator_count)
            ioc_counts = entry.get("ioc_counts", {})
            indicator_count = entry.get("indicator_count", 0)
            total_iocs = sum(v for v in ioc_counts.values() if isinstance(v, (int, float))) if isinstance(ioc_counts, dict) else indicator_count
            if total_iocs > 0:
                pack = self.forge_from_manifest_entry(entry)
                if pack.to_dict()["total_rules"] > 0:
                    packs.append(pack)
        return packs

    def save_pack(self, pack: DetectionPack):
        """Save detection pack to filesystem."""
        pack_dir = os.path.join(self.output_dir, pack.pack_id)
        os.makedirs(pack_dir, exist_ok=True)

        # Save individual format files
        if pack.sigma_rules:
            with open(os.path.join(pack_dir, "sigma_rules.yml"), 'w') as f:
                f.write("\n---\n".join(pack.sigma_rules))

        if pack.yara_rules:
            with open(os.path.join(pack_dir, "yara_rules.yar"), 'w') as f:
                f.write("\n\n".join(pack.yara_rules))

        if pack.suricata_rules:
            with open(os.path.join(pack_dir, "suricata.rules"), 'w') as f:
                f.write("\n".join(pack.suricata_rules))

        if pack.snort_rules:
            with open(os.path.join(pack_dir, "snort.rules"), 'w') as f:
                f.write("\n".join(pack.snort_rules))

        if pack.elastic_queries:
            with open(os.path.join(pack_dir, "elastic_queries.json"), 'w') as f:
                f.write("\n".join(pack.elastic_queries))

        if pack.kql_queries:
            with open(os.path.join(pack_dir, "kql_queries.txt"), 'w') as f:
                f.write("\n\n".join(pack.kql_queries))

        # Save manifest
        with open(os.path.join(pack_dir, "pack_manifest.json"), 'w') as f:
            json.dump(pack.to_dict(), f, indent=2)

    # ─── SIGMA GENERATION ─────────────────────────────────────────────────

    def _gen_sigma_network(self, title: str, ips: List, domains: List, actor: str = None) -> str:
        safe_title = re.sub(r'[^a-zA-Z0-9_]', '_', title[:60])
        rule = f"""title: CDB APEX — Network IOC Detection — {title[:80]}
id: {hashlib.md5(f'sigma-net-{title}'.encode()).hexdigest()[:8]}-{hashlib.md5(title.encode()).hexdigest()[:4]}-{hashlib.md5(title.encode()).hexdigest()[4:8]}-{hashlib.md5(title.encode()).hexdigest()[8:12]}-{hashlib.md5(title.encode()).hexdigest()[:12]}
status: experimental
description: Detects network connections to IOCs from {title[:80]}
references:
    - https://intel.cyberdudebivash.com/
author: CyberDudeBivash SENTINEL APEX v33.0
date: {datetime.now().strftime('%Y/%m/%d')}
tags:
    - attack.command_and_control"""

        if actor:
            rule += f"\n    - attack.{actor.lower().replace(' ', '_')[:30]}"

        rule += """
logsource:
    category: firewall
detection:
    selection_ip:
        dst_ip:"""
        for ip in ips[:15]:
            rule += f"\n            - '{ip}'"

        if domains:
            rule += """
    selection_dns:
        query:"""
            for domain in domains[:15]:
                rule += f"\n            - '*{domain}*'"

        if ips and domains:
            rule += "\n    condition: selection_ip or selection_dns"
        elif ips:
            rule += "\n    condition: selection_ip"
        else:
            rule += "\n    condition: selection_dns"

        rule += f"""
falsepositives:
    - Legitimate traffic to shared infrastructure
level: high"""
        return rule

    def _gen_sigma_hash(self, title: str, hashes: List, actor: str = None) -> str:
        rule = f"""title: CDB APEX — Hash IOC Detection — {title[:80]}
id: {hashlib.md5(f'sigma-hash-{title}'.encode()).hexdigest()[:36]}
status: experimental
description: Detects file hashes from {title[:80]}
author: CyberDudeBivash SENTINEL APEX v33.0
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:"""
        for h in hashes[:20]:
            rule += f"\n            - '{h}'"
        rule += """
    condition: selection
level: critical"""
        return rule

    def _gen_sigma_file(self, title: str, files: List, actor: str = None) -> str:
        rule = f"""title: CDB APEX — Suspicious File Detection — {title[:80]}
id: {hashlib.md5(f'sigma-file-{title}'.encode()).hexdigest()[:36]}
status: experimental
description: Detects suspicious files from {title[:80]}
author: CyberDudeBivash SENTINEL APEX v33.0
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:"""
        for f_name in files[:15]:
            safe_name = re.sub(r'[^a-zA-Z0-9._\-]', '', str(f_name))
            rule += f"\n            - '{safe_name}'"
        rule += """
    condition: selection
level: high"""
        return rule

    # ─── YARA GENERATION ──────────────────────────────────────────────────

    def _gen_yara(self, title: str, hashes: List, files: List, actor: str = None) -> str:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', title[:50])
        rule = f"""rule CDB_APEX_{safe_name} {{
    meta:
        description = "CDB APEX v33.0 — {title[:80]}"
        author = "CyberDudeBivash SENTINEL APEX"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        reference = "https://intel.cyberdudebivash.com/"
        severity = "high"
"""
        if actor:
            rule += f'        actor = "{actor}"\n'

        rule += "    strings:\n"
        for i, h in enumerate(hashes[:10]):
            if len(h) == 64:  # SHA256
                rule += f'        $hash_{i} = "{h}" ascii nocase\n'
            elif len(h) == 32:  # MD5
                rule += f'        $md5_{i} = "{h}" ascii nocase\n'
        for i, fname in enumerate(files[:5]):
            safe = re.sub(r'[^a-zA-Z0-9._\-]', '', str(fname))
            if safe:
                rule += f'        $file_{i} = "{safe}" ascii nocase\n'

        rule += "    condition:\n        any of them\n}"
        return rule

    # ─── SURICATA GENERATION ──────────────────────────────────────────────

    def _gen_suricata_ip(self, title: str, ip: str, pack_id: str) -> str:
        sid = abs(hash(f"suricata-{ip}-{pack_id}")) % 9000000 + 1000000
        safe_msg = re.sub(r'[^a-zA-Z0-9 _\-]', '', title[:60])
        return (
            f'alert ip any any -> {ip} any '
            f'(msg:"CDB APEX — C2 IOC — {safe_msg}"; '
            f'sid:{sid}; rev:1; '
            f'metadata: created_by CyberDudeBivash, severity high;)'
        )

    def _gen_suricata_domain(self, title: str, domain: str, pack_id: str) -> str:
        sid = abs(hash(f"suricata-dns-{domain}-{pack_id}")) % 9000000 + 1000000
        safe_msg = re.sub(r'[^a-zA-Z0-9 _\-]', '', title[:60])
        return (
            f'alert dns any any -> any any '
            f'(msg:"CDB APEX — DNS IOC — {safe_msg}"; '
            f'dns.query; content:"{domain}"; nocase; '
            f'sid:{sid}; rev:1; '
            f'metadata: created_by CyberDudeBivash, severity high;)'
        )

    # ─── SNORT GENERATION ─────────────────────────────────────────────────

    def _gen_snort_ip(self, title: str, ip: str, pack_id: str) -> str:
        sid = abs(hash(f"snort-{ip}-{pack_id}")) % 9000000 + 1000000
        safe_msg = re.sub(r'[^a-zA-Z0-9 _\-]', '', title[:60])
        return (
            f'alert ip any any -> {ip} any '
            f'(msg:"CDB APEX C2 IOC {safe_msg}"; '
            f'sid:{sid}; rev:1;)'
        )

    # ─── ELASTIC DSL GENERATION ───────────────────────────────────────────

    def _gen_elastic_query(self, title: str, ips: List, domains: List, hashes: List) -> str:
        query = {"bool": {"should": [], "minimum_should_match": 1}}

        if ips:
            query["bool"]["should"].append({
                "terms": {"destination.ip": ips[:20]}
            })
        if domains:
            query["bool"]["should"].append({
                "terms": {"dns.question.name": domains[:20]}
            })
        if hashes:
            query["bool"]["should"].append({
                "terms": {"file.hash.sha256": [h for h in hashes if len(h) == 64][:20]}
            })

        return json.dumps({
            "_comment": f"CDB APEX v33.0 — {title[:80]}",
            "query": query,
        }, indent=2)

    # ─── KQL GENERATION ───────────────────────────────────────────────────

    def _gen_kql_query(self, title: str, ips: List, domains: List, hashes: List) -> str:
        parts = []
        comment = f"// CDB APEX v33.0 — {title[:80]}\n"

        if ips:
            ip_list = ", ".join(f'"{ip}"' for ip in ips[:15])
            parts.append(f"DeviceNetworkEvents\n| where RemoteIP in ({ip_list})")

        if domains:
            domain_list = ", ".join(f'"{d}"' for d in domains[:15])
            parts.append(f"DeviceNetworkEvents\n| where RemoteUrl has_any ({domain_list})")

        if hashes:
            hash_list = ", ".join(f'"{h}"' for h in hashes[:15] if len(h) == 64)
            if hash_list:
                parts.append(f"DeviceFileEvents\n| where SHA256 in ({hash_list})")

        return comment + "\n\n// OR\n\n".join(parts) if parts else comment + "// No actionable IOCs for KQL"


def main():
    """CLI entry point for DetectionForge."""
    logging.basicConfig(level=logging.INFO, format="[DETECTION-FORGE] %(asctime)s — %(message)s")

    manifest_path = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
    try:
        with open(manifest_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load manifest: {e}")
        return

    entries = data if isinstance(data, list) else data.get("entries", [])
    forge = DetectionForge()
    packs = forge.batch_forge(entries[-50:])

    for pack in packs:
        forge.save_pack(pack)
        logger.info(f"Generated detection pack: {pack.pack_id} — {pack.to_dict()['total_rules']} rules")

    logger.info(f"DetectionForge complete: {len(packs)} packs generated")


if __name__ == "__main__":
    main()
