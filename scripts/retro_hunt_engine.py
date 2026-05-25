#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/retro_hunt_engine.py — Retro-Hunt Automation Engine v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Generates production-grade retrospective threat hunting queries from
  APEX intelligence advisories. Supports 7 SIEM/hunting platforms.

SUPPORTED PLATFORMS:
  1. Microsoft Sentinel (KQL)
  2. Splunk ES (SPL)
  3. Elastic SIEM (DSL + EQL)
  4. IBM QRadar (AQL)
  5. Google Chronicle (YARA-L + UDM)
  6. CrowdStrike (NG-SIEM / Event Query Language)
  7. Generic SQL (for normalized lake queries)

LOOKBACK WINDOWS: 30d | 60d | 90d | 180d | 365d
================================================================================
"""
from __future__ import annotations
import hashlib,json,logging,re
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-RHE"
log = logging.getLogger("apex.retro_hunt")


@dataclass
class RetroHuntPack:
    advisory_id: str
    title: str
    techniques: List[str]
    iocs: List[Dict]
    threat_type: str = ""
    actor: str       = ""
    lookback_days: int = 90
    queries: Dict[str,str] = field(default_factory=dict)
    hunt_context: str      = ""
    hunt_priority: str     = "MEDIUM"  # LOW|MEDIUM|HIGH|CRITICAL
    generated_at: str      = ""
    engine_version: str    = ENGINE_VERSION

    def to_dict(self): return asdict(self)


class RetroHuntEngine:
    """Generates retro-hunt queries for all major SIEM platforms."""

    def generate_full_pack(self, advisory:Dict, lookback_days:int=90) -> RetroHuntPack:
        """Generate complete retro-hunt query pack for an advisory."""
        advisory_id  = advisory.get("stix_id","")
        title        = advisory.get("title","Unknown Advisory")
        techniques   = advisory.get("ttp_ids",[]) or advisory.get("techniques",[])
        iocs         = advisory.get("iocs",[])
        threat_type  = advisory.get("threat_type","")
        actor        = advisory.get("actor_tag","") or advisory.get("actor","")
        risk_score   = float(advisory.get("risk_score") or advisory.get("apex_score",{}).get("composite",0) or 0)
        kev          = advisory.get("kev_present",False) or advisory.get("kev",False)
        epss         = float(advisory.get("epss_score") or advisory.get("epss",0) or 0)

        # Determine hunt priority
        if kev or epss > 0.5 or risk_score >= 7:
            priority = "CRITICAL"
        elif epss > 0.1 or risk_score >= 5:
            priority = "HIGH"
        elif risk_score >= 3:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        # Extract IOC buckets
        ips      = [i["indicator"] for i in iocs if i.get("type") in ("ip","ipv4","ipv6") and self._is_real_ioc(i)]
        domains  = [i["indicator"] for i in iocs if i.get("type") in ("domain","hostname","fqdn") and self._is_real_ioc(i)]
        urls     = [i["indicator"] for i in iocs if i.get("type") == "url" and self._is_real_ioc(i)]
        hashes   = [i["indicator"] for i in iocs if i.get("type") in ("hash","sha256","md5","sha1") and self._is_real_ioc(i)]
        filenames= [i["indicator"] for i in iocs if i.get("type") in ("filename","filepath") and self._is_real_ioc(i)]
        cves     = [i["indicator"] for i in iocs if i.get("type") == "cve" or re.match(r'CVE-\d{4}-\d+',i.get("indicator",""))]

        # Extract CVE from title if not in IOCs
        title_cves = re.findall(r'CVE-\d{4}-\d+', title)
        for cv in title_cves:
            if cv not in cves: cves.append(cv)

        queries = {}
        tech_str = ", ".join(techniques[:5]) if techniques else "Unknown"

        queries["kql_sentinel"]       = self._kql_sentinel(advisory_id,title,techniques,ips,domains,hashes,cves,lookback_days)
        queries["spl_splunk"]         = self._spl_splunk(advisory_id,title,techniques,ips,domains,hashes,cves,lookback_days)
        queries["elastic_eql"]        = self._elastic_eql(advisory_id,title,techniques,ips,domains,hashes,lookback_days)
        queries["elastic_dsl"]        = self._elastic_dsl(advisory_id,title,ips,domains,hashes,lookback_days)
        queries["qradar_aql"]         = self._qradar_aql(advisory_id,title,ips,domains,hashes,lookback_days)
        queries["chronicle_udm"]      = self._chronicle_udm(advisory_id,title,techniques,ips,domains,hashes,lookback_days)
        queries["crowdstrike_eql"]    = self._crowdstrike_eql(advisory_id,title,techniques,domains,hashes,lookback_days)
        queries["generic_sql"]        = self._generic_sql(advisory_id,title,ips,domains,hashes,lookback_days)

        return RetroHuntPack(
            advisory_id=advisory_id, title=title,
            techniques=techniques, iocs=iocs,
            threat_type=threat_type, actor=actor,
            lookback_days=lookback_days, queries=queries,
            hunt_context=f"{advisory_id} | {tech_str} | {threat_type} | Actor: {actor or 'Unknown'}",
            hunt_priority=priority,
            generated_at=datetime.now(timezone.utc).isoformat()
        )

    def _is_real_ioc(self, ioc:Dict) -> bool:
        """Check if IOC is a real indicator (not a pseudo-IOC)."""
        indicator = str(ioc.get("indicator",""))
        conf = float(ioc.get("confidence",50))
        if conf < 35: return False
        if re.match(r'^[\w_\-]+\.(ts|js|py|rb|go|java|php|jsp|asp)$', indicator): return False
        if re.match(r'^[a-z]{1,3}$', indicator): return False
        if indicator in ("localhost","127.0.0.1","::1"): return False
        return True

    def _ip_list(self, ips:List[str], fallback:str='"<ip_indicator>"') -> str:
        if not ips: return fallback
        return ", ".join(f'"{ip}"' for ip in ips[:10])

    def _domain_list(self, domains:List[str], fallback:str='"<domain_indicator>"') -> str:
        if not domains: return fallback
        return ", ".join(f'"{d}"' for d in domains[:10])

    def _hash_list(self, hashes:List[str], fallback:str='"<hash_indicator>"') -> str:
        if not hashes: return fallback
        return ", ".join(f'"{h}"' for h in hashes[:5])

    def _kql_sentinel(self, adv_id:str,title:str,techs:List[str],
                     ips:List[str],domains:List[str],hashes:List[str],
                     cves:List[str],lookback:int) -> str:
        tech_str = ", ".join(techs[:5]) or "Unknown"
        cve_str  = " or ".join(f'ProcessCommandLine contains "{c}"' for c in cves[:3]) if cves else ""
        return f"""// ============================================================
// RETRO-HUNT: {adv_id}
// Title   : {title[:80]}
// Techniques: {tech_str}
// Platform: Microsoft Sentinel (KQL)
// Lookback: {lookback} days
// Generated: CYBERDUDEBIVASH SENTINEL APEX v{ENGINE_VERSION}
// ============================================================
let lookback = {lookback}d;
let malicious_ips = dynamic([{self._ip_list(ips)}]);
let malicious_domains = dynamic([{self._domain_list(domains)}]);
let malicious_hashes = dynamic([{self._hash_list(hashes)}]);
// --- NETWORK INDICATORS ---
let network_hits = union DeviceNetworkEvents, DnsEvents
| where TimeGenerated > ago(lookback)
| where RemoteIP has_any (malicious_ips)
    or DnsQuestion_Name has_any (malicious_domains)
    or RemoteUrl has_any (malicious_domains)
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl,
          DnsQuestion_Name, InitiatingProcessCommandLine,
          HuntCategory="Network-Indicator";
// --- FILE/HASH INDICATORS ---
let file_hits = DeviceFileEvents
| where TimeGenerated > ago(lookback)
| where SHA256 has_any (malicious_hashes)
    or MD5 has_any (malicious_hashes)
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          SHA256, MD5, InitiatingProcessCommandLine,
          HuntCategory="File-Hash";
// --- PROCESS INDICATORS ---
let process_hits = DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where SHA256 has_any (malicious_hashes)
    or MD5 has_any (malicious_hashes)
    {("or " + cve_str) if cve_str else ""}
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256, AccountName,
          HuntCategory="Process-Indicator";
// --- COMBINE ALL HITS ---
union network_hits, file_hits, process_hits
| summarize HuntHits=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    AffectedDevices=dcount(DeviceName), Categories=make_set(HuntCategory)
    by DeviceName, HuntCategory
| extend AdvisoryID="{adv_id}", Techniques="{tech_str}",
    DaysSinceFirst=datetime_diff('day', now(), FirstSeen)
| order by HuntHits desc, DaysSinceFirst asc"""

    def _spl_splunk(self, adv_id:str,title:str,techs:List[str],
                   ips:List[str],domains:List[str],hashes:List[str],
                   cves:List[str],lookback:int) -> str:
        tech_str    = " ".join(techs[:5]) or "unknown"
        ip_terms    = " OR ".join(f'"{ip}"' for ip in ips[:5]) if ips else '"<ip_indicator>"'
        dom_terms   = " OR ".join(f'"{d}"' for d in domains[:5]) if domains else '"<domain_indicator>"'
        hash_terms  = " OR ".join(f'"{h}"' for h in hashes[:3]) if hashes else '"<hash_indicator>"'
        return f"""| comment "RETRO-HUNT: {adv_id} | {title[:60]} | Techniques: {tech_str}"
index=* earliest=-{lookback}d latest=now
(
    ({ip_terms})
    OR ({dom_terms})
    OR ({hash_terms})
)
| eval hunt_advisory="{adv_id}"
| eval hunt_techniques="{tech_str}"
| eval hunt_ts=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| eval indicator_type=case(
    match(_raw, "({"|".join(ips[:3]) if ips else "x.x.x.x"}"), "IP",
    match(_raw, "({"|".join(domains[:3]) if domains else "domain"}"), "Domain",
    match(_raw, "({"|".join(hashes[:2]) if hashes else "hash"}"), "Hash",
    1==1, "Unknown"
  )
| stats count AS hits,
    min(_time) AS first_seen,
    max(_time) AS last_seen,
    dc(host) AS affected_hosts,
    values(sourcetype) AS sources
    BY hunt_advisory, indicator_type, host
| where hits > 0
| eval first_seen=strftime(first_seen,"%Y-%m-%dT%H:%M:%SZ"),
       last_seen=strftime(last_seen,"%Y-%m-%dT%H:%M:%SZ")
| sort - hits"""

    def _elastic_eql(self, adv_id:str,title:str,techs:List[str],
                    ips:List[str],domains:List[str],hashes:List[str],lookback:int) -> str:
        tech_str = ", ".join(techs[:5]) or "Unknown"
        ip_list  = [f'"{ip}"' for ip in ips[:5]] or ['"<ip>"']
        dom_list = [f'"{d}"' for d in domains[:5]] or ['"<domain>"']
        hash_list= [f'"{h}"' for h in hashes[:3]] or ['"<hash>"']
        return f"""/* RETRO-HUNT EQL: {adv_id} | Techniques: {tech_str} | Lookback: {lookback}d */
sequence with maxspan={lookback}d
  [network where
    destination.ip in ({", ".join(ip_list)})
    or dns.question.name in ({", ".join(dom_list)})
  ] by host.id
  [process where
    process.hash.sha256 in ({", ".join(hash_list)})
    or process.hash.md5 in ({", ".join(hash_list)})
  ] by host.id"""

    def _elastic_dsl(self, adv_id:str,title:str,
                    ips:List[str],domains:List[str],hashes:List[str],lookback:int) -> str:
        should_clauses=[]
        for ip in ips[:5]:
            should_clauses.append(f'{{"term":{{"destination.ip":"{ip}"}}}}')
        for d in domains[:5]:
            should_clauses.append(f'{{"term":{{"dns.question.name":"{d}"}}}}')
        for h in hashes[:3]:
            should_clauses.append(f'{{"term":{{"file.hash.sha256":"{h}"}}}}')
        if not should_clauses:
            should_clauses = ['{"term":{"event.category":"network"}}']
        should_str = ",\n          ".join(should_clauses)
        return f"""/* RETRO-HUNT DSL: {adv_id} | Lookback: {lookback}d */
{{
  "query": {{
    "bool": {{
      "must": [
        {{"range": {{"@timestamp": {{"gte": "now-{lookback}d"}}}}}}
      ],
      "should": [
        {should_str}
      ],
      "minimum_should_match": 1
    }}
  }},
  "aggs": {{
    "hosts": {{"terms": {{"field": "host.name", "size": 50}}}},
    "timeline": {{"date_histogram": {{"field": "@timestamp", "calendar_interval": "1d"}}}}
  }},
  "size": 100
}}"""

    def _qradar_aql(self, adv_id:str,title:str,
                   ips:List[str],domains:List[str],hashes:List[str],lookback:int) -> str:
        ip_list  = ", ".join(f"'{ip}'" for ip in ips[:5]) if ips else "'<ip>'"
        dom_list = ", ".join(f"'{d}'" for d in domains[:5]) if domains else "'<domain>'"
        lookback_secs = lookback * 86400
        return f"""/* RETRO-HUNT AQL: {adv_id} | Lookback: {lookback}d */
SELECT
    DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
    sourceip, destinationip, destinationhostname,
    username, "Application", "Event Category",
    LOGSOURCENAME(logsourceid) AS LogSource,
    QIDNAME(qid) AS EventName,
    '{adv_id}' AS HuntAdvisoryID
FROM events
WHERE (
    destinationip IN ({ip_list})
    OR sourceip IN ({ip_list})
    OR destinationhostname IN ({dom_list})
    OR LOOKUPHOSTNAME(destinationip) IN ({dom_list})
)
AND devicetime > (NOW() - {lookback_secs})
ORDER BY devicetime DESC
LIMIT 10000
START '{lookback}d ago'
STOP 'now'"""

    def _chronicle_udm(self, adv_id:str,title:str,techs:List[str],
                      ips:List[str],domains:List[str],hashes:List[str],lookback:int) -> str:
        tech_str = ", ".join(techs[:5]) or "Unknown"
        ip_conds   = " or ".join(f'target.ip = "{ip}"' for ip in ips[:3]) if ips else 'target.ip = "<ip>"'
        dom_conds  = " or ".join(f'network.dns.questions.name = "{d}"' for d in domains[:3]) if domains else 'network.dns.questions.name = "<domain>"'
        hash_conds = " or ".join(f'target.file.sha256 = "{h}"' for h in hashes[:2]) if hashes else 'target.file.sha256 = "<hash>"'
        return f"""/* RETRO-HUNT CHRONICLE UDM: {adv_id} | Techniques: {tech_str} | Lookback: {lookback}d */
/* Google SecOps (Chronicle) UDM Search */
metadata.event_timestamp.seconds > unix_seconds(timestamp_sub(current_timestamp(), interval {lookback} day))
AND (
    ({ip_conds})
    OR ({dom_conds})
    OR ({hash_conds})
)
/* Aggregate by principal hostname */
| group_by principal.hostname
| order_by count() desc"""

    def _crowdstrike_eql(self, adv_id:str,title:str,techs:List[str],
                        domains:List[str],hashes:List[str],lookback:int) -> str:
        tech_str  = ", ".join(techs[:5]) or "Unknown"
        hash_cond = " or ".join(f'sha256 = "{h}"' for h in hashes[:3]) if hashes else 'sha256 = "<hash>"'
        dom_cond  = " or ".join(f'DomainName = "{d}"' for d in domains[:3]) if domains else 'DomainName = "<domain>"'
        return f"""/* RETRO-HUNT CrowdStrike Event Query: {adv_id} | Techniques: {tech_str} */
#type=ProcessRollup2 | head 1000
| eval hunt_id="{adv_id}"
| search ({hash_cond}) OR ({dom_cond})
| stats count by HostName, FileName, CommandLine, UserSid, TimeStamp
| sort count desc"""

    def _generic_sql(self, adv_id:str,title:str,
                    ips:List[str],domains:List[str],hashes:List[str],lookback:int) -> str:
        ip_list  = ", ".join(f"'{ip}'" for ip in ips[:5]) if ips else "'<ip>'"
        dom_list = ", ".join(f"'{d}'" for d in domains[:5]) if domains else "'<domain>'"
        hash_list= ", ".join(f"'{h}'" for h in hashes[:3]) if hashes else "'<hash>'"
        return f"""/* RETRO-HUNT Generic SQL: {adv_id} | Lookback: {lookback}d */
/* Compatible with: Splunk Data Lake, Snowflake, BigQuery, Azure Data Explorer */
SELECT
    event_timestamp,
    host_name,
    source_ip,
    destination_ip,
    destination_domain,
    file_hash_sha256,
    process_name,
    process_command_line,
    user_name,
    '{adv_id}' AS hunt_advisory_id
FROM security_events
WHERE event_timestamp > CURRENT_TIMESTAMP - INTERVAL '{lookback} days'
  AND (
    destination_ip IN ({ip_list})
    OR source_ip IN ({ip_list})
    OR destination_domain IN ({dom_list})
    OR file_hash_sha256 IN ({hash_list})
  )
ORDER BY event_timestamp DESC
LIMIT 50000;"""


def generate_retro_hunt_for_advisory(advisory:Dict, lookback_days:int=90) -> RetroHuntPack:
    """Entry point for pipeline integration."""
    engine = RetroHuntEngine()
    return engine.generate_full_pack(advisory, lookback_days)


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    engine = RetroHuntEngine()
    test_advisory = {
        "stix_id": "intel--test001",
        "title": "KnowledgeDeliver LMS Zero-Day Exploited to Deploy BLUEBEAM Web Shell",
        "ttp_ids": ["T1190","T1505.003"],
        "threat_type": "Vulnerability",
        "actor": "CDB-RU-02",
        "kev": True,
        "epss": 0.08,
        "risk_score": 3.54,
        "iocs": [
            {"type":"ip","indicator":"185.234.219.42","confidence":85,"source":"OSINT"},
            {"type":"domain","indicator":"bluebeam-c2.ru","confidence":90,"source":"HONEYPOT"},
            {"type":"hash","indicator":"a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd","confidence":95,"source":"SANDBOX"},
        ]
    }
    pack = engine.generate_full_pack(test_advisory, 90)
    print(f"[RHE] Priority: {pack.hunt_priority} | Platforms: {len(pack.queries)}")
    print(f"\n--- KQL Sentinel Query ---\n{pack.queries['kql_sentinel'][:500]}...")
    print(f"\n--- SPL Splunk Query ---\n{pack.queries['spl_splunk'][:300]}...")
