#!/usr/bin/env python3
"""
signal_pipeline.py — CYBERDUDEBIVASH® SENTINEL APEX v35.0 (ZERO-DAY HUNTER)
==============================================================================
Unified Signal Pipeline — collects, normalizes, correlates, and forecasts
threat signals from multiple intelligence sources.

Pipeline: Collect → Normalize → Correlate → Forecast → Output

Collectors:
  ManifestCollector  — Extracts signals from existing STIX manifest (always available)
  STIXBundleCollector— Extracts IOCs directly from STIX bundle files
  NVDCollector       — CVE publication velocity from NVD API 2.0
  KEVCollector       — CISA Known Exploited Vulnerabilities additions
  GitHubPoCCollector — Exploit PoC repository detection
  FusionCollector    — Signals from v33 fusion entity store

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""
import os, re, json, math, hashlib, logging, time
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-SignalPipeline")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
STIX_DIR = os.environ.get("STIX_DIR", "data/stix")
FUSION_DIR = os.environ.get("FUSION_DIR", "data/fusion")
OUTPUT_DIR = os.environ.get("ZDH_OUTPUT_DIR", "data/zerodayhunter")

try:
    import requests; _HTTP = True
except ImportError:
    _HTTP = False

# ═══════════════════════════════════════════════════════════════════════════════
# NORMALIZED SIGNAL SCHEMA
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatSignal:
    signal_id: str
    signal_type: str    # cve_pub, kev_add, poc_release, scan_spike, severity_spike, actor_activity, ioc_volume, patch_gap, exploit_sub, fusion_entity
    source: str         # sentinel_apex, nvd, cisa_kev, github, exploitdb, fusion
    timestamp: str
    entity: str
    entity_type: str    # cve, actor, malware, infrastructure, vulnerability
    context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    severity: str = "MEDIUM"
    related: List[str] = field(default_factory=list)
    def to_dict(self) -> Dict:
        return {"signal_id": self.signal_id, "signal_type": self.signal_type, "source": self.source,
                "timestamp": self.timestamp, "entity": self.entity, "entity_type": self.entity_type,
                "context": self.context, "confidence": round(self.confidence, 3),
                "severity": self.severity, "related": self.related[:15]}

def _mkid(*parts) -> str:
    return f"sig-{hashlib.md5(':'.join(str(p) for p in parts).encode()).hexdigest()[:14]}"

def _sev(risk: float) -> str:
    if risk >= 9: return "CRITICAL"
    if risk >= 7: return "HIGH"
    if risk >= 4: return "MEDIUM"
    return "LOW"

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTORS
# ═══════════════════════════════════════════════════════════════════════════════

class BaseCollector(ABC):
    def __init__(self, name: str): self.name = name; self.errors: List[str] = []
    @abstractmethod
    def collect(self, window_hours: int = 72) -> List[ThreatSignal]: ...
    def _http(self, url: str, timeout: int = 15, headers: Dict = None) -> Optional[Any]:
        if not _HTTP: return None
        try:
            r = requests.get(url, timeout=timeout, headers=headers or {"User-Agent": "CDB-APEX/35.0"})
            r.raise_for_status(); return r
        except Exception as e:
            self.errors.append(f"{url}: {e}"); return None


class ManifestCollector(BaseCollector):
    """Extracts signals from existing feed_manifest.json — always available."""
    def __init__(self): super().__init__("manifest")
    def collect(self, window_hours: int = 72) -> List[ThreatSignal]:
        sigs = []
        try:
            with open(MANIFEST_PATH) as f: data = json.load(f)
        except Exception: return sigs
        entries = data if isinstance(data, list) else data.get("entries", [])
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        recent = [e for e in entries if e.get("timestamp", "") >= cutoff] or entries[-100:]

        for e in recent:
            title, risk = e.get("title", ""), e.get("risk_score", 0)
            ts, sf = e.get("timestamp", ""), e.get("stix_file", "")
            kev, epss, cvss = e.get("kev_present", False), e.get("epss_score"), e.get("cvss_score")

            # CVE signals
            for cve in CVE_RE.findall(title):
                cve = cve.upper()
                conf = 0.5 + (0.3 if kev else 0) + (0.2 if epss and epss > 0.5 else 0) + (0.15 if cvss and cvss >= 9 else 0)
                sigs.append(ThreatSignal(_mkid("m", cve, sf), "cve_pub", "sentinel_apex", ts, cve, "cve",
                    {"risk": risk, "kev": kev, "epss": epss, "cvss": cvss, "title": title[:100]}, min(1.0, conf), _sev(risk), e.get("mitre_tactics", [])))

            # Actor signals
            actor = e.get("actor_tag", "")
            if actor and not actor.startswith("UNC-CDB"):
                sigs.append(ThreatSignal(_mkid("ma", actor, ts), "actor_activity", "sentinel_apex", ts, actor, "actor",
                    {"risk": risk, "title": title[:100]}, 0.6, "HIGH" if risk >= 7 else "MEDIUM", e.get("mitre_tactics", [])))

            # Severity spikes
            if risk >= 9.0:
                sigs.append(ThreatSignal(_mkid("ms", sf), "severity_spike", "sentinel_apex", ts, title[:80], "vulnerability",
                    {"risk": risk, "supply_chain": e.get("supply_chain", False), "kev": kev}, 0.7, "CRITICAL"))

            # IOC volume
            ioc_counts = e.get("ioc_counts", {})
            total_iocs = sum(v for v in ioc_counts.values() if isinstance(v, (int, float)))
            if total_iocs >= 10:
                sigs.append(ThreatSignal(_mkid("mi", sf), "ioc_volume", "sentinel_apex", ts, title[:80], "infrastructure",
                    {"ioc_counts": ioc_counts, "total": total_iocs}, 0.55, "HIGH" if total_iocs >= 20 else "MEDIUM"))

            # Scan spike keywords
            tl = title.lower()
            scan_kw = [k for k in ["scanning", "mass scan", "brute force", "botnet", "honeypot", "probing", "exploit attempt"] if k in tl]
            if scan_kw:
                sigs.append(ThreatSignal(_mkid("msc", sf), "scan_spike", "sentinel_apex", ts, title[:80], "infrastructure",
                    {"keywords": scan_kw, "risk": risk}, min(0.9, 0.5 + len(scan_kw) * 0.1), _sev(risk)))

            # Patch gap (high risk CVE, no patch mention)
            if CVE_RE.findall(title) and risk >= 7.0 and not any(k in tl for k in ["patch", "fix", "update"]):
                for cve in CVE_RE.findall(title):
                    sigs.append(ThreatSignal(_mkid("mpg", cve.upper()), "patch_gap", "sentinel_apex", ts, cve.upper(), "cve",
                        {"risk": risk, "kev": kev}, 0.65 if kev else 0.5, "HIGH" if risk >= 8 else "MEDIUM"))

        logger.info(f"ManifestCollector: {len(sigs)} signals from {len(recent)} entries")
        return sigs


class STIXBundleCollector(BaseCollector):
    """Extracts IOCs directly from STIX bundle files for enrichment."""
    def __init__(self): super().__init__("stix_bundle")
    def collect(self, window_hours: int = 72) -> List[ThreatSignal]:
        sigs = []
        try:
            with open(MANIFEST_PATH) as f: data = json.load(f)
        except Exception: return sigs
        entries = data if isinstance(data, list) else data.get("entries", [])
        for e in entries[-30:]:
            sf = e.get("stix_file", "")
            path = os.path.join(STIX_DIR, sf)
            if not os.path.exists(path): continue
            try:
                with open(path) as f: bundle = json.load(f)
                for obj in bundle.get("objects", []):
                    if obj.get("type") != "indicator": continue
                    pattern = obj.get("pattern", "")
                    # Extract IPs
                    m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
                    if m:
                        sigs.append(ThreatSignal(_mkid("sb-ip", m.group(1), sf), "ioc_extracted", "stix_bundle",
                            e.get("timestamp", ""), m.group(1), "infrastructure",
                            {"type": "ipv4", "stix_file": sf}, 0.8, "HIGH"))
                    # Extract domains
                    m = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
                    if m:
                        sigs.append(ThreatSignal(_mkid("sb-dom", m.group(1), sf), "ioc_extracted", "stix_bundle",
                            e.get("timestamp", ""), m.group(1), "infrastructure",
                            {"type": "domain", "stix_file": sf}, 0.8, "HIGH"))
            except Exception: pass
        logger.info(f"STIXBundleCollector: {len(sigs)} IOC signals")
        return sigs


class FusionCollector(BaseCollector):
    """Extracts signals from v33 Fusion Engine entity store."""
    def __init__(self): super().__init__("fusion")
    def collect(self, window_hours: int = 168) -> List[ThreatSignal]:
        sigs = []
        epath = os.path.join(FUSION_DIR, "entity_store.json")
        if not os.path.exists(epath): return sigs
        try:
            with open(epath) as f: entities = json.load(f)
            for eid, ent in entities.items():
                etype = ent.get("entity_type", "")
                if etype in ("threat_actor", "malware", "cve") and ent.get("mention_count", 0) >= 2:
                    sigs.append(ThreatSignal(_mkid("fus", eid), "fusion_entity", "fusion",
                        ent.get("last_seen", ""), ent.get("canonical_name", eid), etype.replace("threat_", ""),
                        {"mentions": ent.get("mention_count", 0), "confidence": ent.get("confidence", 0.5)},
                        min(1.0, ent.get("confidence", 0.5)), "HIGH" if ent.get("mention_count", 0) >= 3 else "MEDIUM",
                        ent.get("aliases", [])))
        except Exception: pass
        logger.info(f"FusionCollector: {len(sigs)} signals")
        return sigs


class NVDCollector(BaseCollector):
    """CVE publication velocity from NVD API 2.0."""
    def __init__(self): super().__init__("nvd")
    def collect(self, window_hours: int = 72) -> List[ThreatSignal]:
        sigs = []
        start = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H:%M:%S.000")
        end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        r = self._http(f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=50", 20)
        if not r: return sigs
        try:
            for v in r.json().get("vulnerabilities", [])[:50]:
                c = v.get("cve", {}); cid = c.get("id", "")
                if not cid: continue
                cvss = max((m.get("cvssData", {}).get("baseScore", 0) for ms in [c.get("metrics", {}).get("cvssMetricV31", []), c.get("metrics", {}).get("cvssMetricV40", [])] for m in ms), default=0)
                desc = " ".join(d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en")
                conf = 0.4 + cvss / 20 + (0.2 if any(k in desc.lower() for k in ["rce", "remote code", "actively exploited", "auth bypass"]) else 0)
                sigs.append(ThreatSignal(_mkid("nvd", cid), "cve_pub", "nvd",
                    c.get("published", ""), cid, "cve", {"cvss": cvss, "desc": desc[:250]}, min(1.0, conf), _sev(cvss)))
        except Exception as e: self.errors.append(str(e))
        logger.info(f"NVDCollector: {len(sigs)} signals"); return sigs


class KEVCollector(BaseCollector):
    """CISA Known Exploited Vulnerabilities additions."""
    def __init__(self): super().__init__("cisa_kev")
    def collect(self, window_hours: int = 168) -> List[ThreatSignal]:
        sigs = []
        r = self._http("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 20)
        if not r: return sigs
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%d")
            for v in r.json().get("vulnerabilities", []):
                if v.get("dateAdded", "") >= cutoff:
                    cid = v.get("cveID", "")
                    sigs.append(ThreatSignal(_mkid("kev", cid, v["dateAdded"]), "kev_add", "cisa_kev",
                        f"{v['dateAdded']}T00:00:00Z", cid, "cve",
                        {"vendor": v.get("vendorProject"), "product": v.get("product"), "ransomware": v.get("knownRansomwareCampaignUse", "Unknown")},
                        0.95, "CRITICAL", [v.get("vendorProject", ""), v.get("product", "")]))
        except Exception as e: self.errors.append(str(e))
        logger.info(f"KEVCollector: {len(sigs)} signals"); return sigs


class GitHubPoCCollector(BaseCollector):
    """GitHub exploit PoC repository detection."""
    def __init__(self): super().__init__("github_poc")
    def collect(self, window_hours: int = 72) -> List[ThreatSignal]:
        sigs = []
        since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%d")
        r = self._http(f"https://api.github.com/search/repositories?q=CVE+exploit+poc+created:>{since}&sort=updated&per_page=30",
                       headers={"Accept": "application/vnd.github.v3+json"})
        if not r: return sigs
        try:
            for repo in r.json().get("items", [])[:30]:
                n, d, s = repo.get("full_name", ""), repo.get("description", "") or "", repo.get("stargazers_count", 0)
                for cve in CVE_RE.findall(f"{n} {d}"):
                    cve = cve.upper()
                    conf = 0.6 + (0.1 if s >= 10 else 0) + (0.1 if s >= 50 else 0) + (0.15 if any(k in d.lower() for k in ["rce", "pre-auth"]) else 0)
                    sigs.append(ThreatSignal(_mkid("gh", cve, n), "poc_release", "github",
                        repo.get("created_at", ""), cve, "cve",
                        {"repo": n, "stars": s, "url": repo.get("html_url", "")}, min(1.0, conf), "HIGH"))
        except Exception as e: self.errors.append(str(e))
        logger.info(f"GitHubPoCCollector: {len(sigs)} signals"); return sigs


# ═══════════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

CHAIN_STAGES = ["cve_pub", "patch_gap", "poc_release", "kev_add", "scan_spike",
                "exploit_sub", "severity_spike", "actor_activity", "ioc_volume", "ioc_extracted", "fusion_entity"]
STAGE_WEIGHTS = {"cve_pub": .10, "patch_gap": .15, "poc_release": .20, "kev_add": .25,
                 "scan_spike": .15, "severity_spike": .10, "actor_activity": .15,
                 "ioc_volume": .10, "ioc_extracted": .08, "fusion_entity": .12, "exploit_sub": .20}

@dataclass
class SignalCluster:
    cluster_id: str; entity: str; entity_type: str; signals: List[ThreatSignal]
    chain: List[str]; completeness: float; confidence: float; severity: str
    velocity: float; first_ts: str; last_ts: str; related: List[str]
    def to_dict(self) -> Dict:
        return {"cluster_id": self.cluster_id, "entity": self.entity, "entity_type": self.entity_type,
                "signal_count": len(self.signals), "chain": self.chain, "completeness": round(self.completeness, 3),
                "confidence": round(self.confidence, 3), "severity": self.severity,
                "velocity": round(self.velocity, 2), "sources": list(set(s.source for s in self.signals)),
                "related": self.related[:10]}


def correlate_signals(signals: List[ThreatSignal]) -> List[SignalCluster]:
    """Group signals by entity, build attack chain clusters."""
    groups: Dict[str, List[ThreatSignal]] = defaultdict(list)
    for s in signals:
        k = s.entity.upper().strip()
        if k: groups[k].append(s)
        for r in s.related:
            if r and len(r) > 3: groups[r.upper().strip()].append(s)

    clusters = []
    for entity, gsigs in groups.items():
        types = Counter(s.entity_type for s in gsigs)
        etype = max(types, key=types.get) if types else "unknown"
        stages = list(set(s.signal_type for s in gsigs))
        chain = [st for st in CHAIN_STAGES if st in stages]
        completeness = min(1.0, sum(STAGE_WEIGHTS.get(st, .05) for st in chain))

        confs = [s.confidence for s in gsigs]
        base = max(confs) if confs else 0.5
        src_boost = min(0.2, (len(set(s.source for s in gsigs)) - 1) * 0.05)
        stg_boost = min(0.15, (len(chain) - 1) * 0.05) if len(chain) > 1 else 0
        comp_conf = min(1.0, base + src_boost + stg_boost)

        sevs = [s.severity for s in gsigs]
        sev = "CRITICAL" if "CRITICAL" in sevs else "HIGH" if "HIGH" in sevs else "MEDIUM"

        tss = sorted(s.timestamp for s in gsigs if s.timestamp)
        vel = 0.0
        if len(tss) > 1:
            try:
                t1 = datetime.fromisoformat(tss[0].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(tss[-1].replace("Z", "+00:00"))
                vel = len(gsigs) / max(1, (t2 - t1).total_seconds() / 3600)
            except: vel = float(len(gsigs))

        all_rel: Set[str] = set()
        for s in gsigs: all_rel.update(s.related)
        all_rel.discard(entity)

        clusters.append(SignalCluster(
            f"cl-{hashlib.md5(entity.encode()).hexdigest()[:12]}", entity, etype, gsigs,
            chain, completeness, comp_conf, sev, vel, tss[0] if tss else "", tss[-1] if tss else "",
            list(all_rel)[:20]))

    clusters.sort(key=lambda c: c.completeness * c.confidence, reverse=True)
    logger.info(f"Correlated {len(signals)} signals → {len(clusters)} clusters")
    return clusters


# ═══════════════════════════════════════════════════════════════════════════════
# FORECAST ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

STAGE_PROB = {"cve_pub": .05, "patch_gap": .15, "poc_release": .25, "kev_add": .30,
              "scan_spike": .20, "exploit_sub": .20, "severity_spike": .10,
              "actor_activity": .15, "ioc_volume": .10, "ioc_extracted": .08, "fusion_entity": .10}

SECTOR_KW = {"Finance": ["bank", "financial", "payment", "fin7", "fin12"],
             "Healthcare": ["health", "hospital", "medical", "pharma"],
             "Government": ["government", "federal", "defense", "military", "apt-"],
             "Energy": ["energy", "oil", "gas", "power", "ics", "scada"],
             "Technology": ["cloud", "saas", "software", "api", "kubernetes"],
             "Telecom": ["telecom", "5g", "carrier", "salt typhoon"],
             "Manufacturing": ["manufacturing", "industrial", "supply chain", "ot"],
             "Critical Infrastructure": ["critical infrastructure", "water", "dam"]}

@dataclass
class Forecast:
    forecast_id: str; entity: str; entity_type: str; prob: float; prob_pct: int
    window_hrs: int; window_label: str; confidence: float; sectors: List[str]
    vector: str; risk_level: str; posture: str; reasoning: List[str]
    chain: List[str]; signal_count: int; timestamp: str
    def to_dict(self) -> Dict:
        return {"forecast_id": self.forecast_id, "entity": self.entity, "probability_pct": self.prob_pct,
                "window": self.window_label, "window_hours": self.window_hrs, "confidence": round(self.confidence, 3),
                "sectors": self.sectors, "vector": self.vector, "risk_level": self.risk_level,
                "posture": self.posture, "reasoning": self.reasoning, "chain": self.chain,
                "signal_count": self.signal_count, "timestamp": self.timestamp}


def forecast_clusters(clusters: List[SignalCluster]) -> List[Forecast]:
    forecasts = []
    for cl in clusters:
        base = sum(STAGE_PROB.get(st, .03) for st in cl.chain)
        if len(cl.signals) >= 5: base += 0.1
        elif len(cl.signals) >= 3: base += 0.05
        vel_boost = 0.15 if cl.velocity > 2 else 0.1 if cl.velocity > 1 else 0.05 if cl.velocity > 0.5 else 0
        raw = min(1.0, base + vel_boost) * cl.confidence
        prob = 1.0 / (1.0 + math.exp(-8 * (raw - 0.5)))  # sigmoid

        # Window
        if "kev_add" in cl.chain: wh = 0
        elif prob >= 0.9: wh = 24
        elif prob >= 0.75: wh = 72
        elif prob >= 0.6: wh = 168
        elif prob >= 0.4: wh = 336
        elif prob >= 0.2: wh = 720
        else: wh = 2160

        wl = {0: "ACTIVE — Exploitation in progress", 24: "≤24 hours", 72: "24-72 hours",
              168: "1-7 days", 336: "1-2 weeks", 720: "2-4 weeks"}.get(wh, "1-3 months")

        # Sectors
        ftxt = " ".join(f"{s.entity} {s.context.get('title','')} {s.context.get('desc','')}" for s in cl.signals).lower()
        sectors = [sec for sec, kws in SECTOR_KW.items() if any(k in ftxt for k in kws)] or ["All Industries"]

        # Vector
        if "kev_add" in cl.chain: vec = "Confirmed Active Exploitation"
        elif "poc_release" in cl.chain and "scan_spike" in cl.chain: vec = "Weaponized Exploit + Active Scanning"
        elif "poc_release" in cl.chain: vec = "Public Exploit Available"
        elif "scan_spike" in cl.chain: vec = "Mass Scanning / Opportunistic"
        elif "patch_gap" in cl.chain: vec = "Unpatched Vulnerability Window"
        else: vec = "Potential Exploitation Vector"

        # Risk/posture
        if prob >= 0.85 or wh <= 24: rl, ps = "IMMINENT", "CRITICAL_RESPONSE"
        elif prob >= 0.65 or wh <= 72: rl, ps = "HIGH", "HIGH_ALERT"
        elif prob >= 0.4 or wh <= 168: rl, ps = "ELEVATED", "ELEVATED_MONITORING"
        elif prob >= 0.2: rl, ps = "MODERATE", "STANDARD"
        else: rl, ps = "LOW", "STANDARD"

        # Reasoning
        reasons = [f"{len(cl.chain)} chain stages: {', '.join(cl.chain)}"]
        if "kev_add" in cl.chain: reasons.append("CISA KEV confirms active exploitation")
        if "poc_release" in cl.chain: reasons.append("Public PoC exploit lowers exploitation barrier")
        if "patch_gap" in cl.chain: reasons.append("No patch available — window remains open")
        if "scan_spike" in cl.chain: reasons.append("Mass scanning detected")
        if cl.velocity > 1: reasons.append(f"High velocity: {cl.velocity:.1f} signals/hour")
        if len(set(s.source for s in cl.signals)) > 2: reasons.append(f"Corroborated by {len(set(s.source for s in cl.signals))} sources")
        reasons.append(f"Exploitation probability: {prob*100:.0f}%")
        reasons.append(f"Window: {wl}")

        forecasts.append(Forecast(f"fc-{cl.cluster_id[3:]}", cl.entity, cl.entity_type,
            round(prob, 4), round(prob * 100), wh, wl, cl.confidence, sectors, vec, rl, ps,
            reasons, cl.chain, len(cl.signals), datetime.now(timezone.utc).isoformat()))

    forecasts.sort(key=lambda f: f.prob, reverse=True)
    logger.info(f"Generated {len(forecasts)} forecasts")
    return forecasts


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class SignalPipeline:
    """Unified signal collection → correlation → forecasting pipeline."""
    def __init__(self, enable_external: bool = True):
        self.collectors: List[BaseCollector] = [ManifestCollector(), STIXBundleCollector(), FusionCollector()]
        if enable_external:
            self.collectors.extend([NVDCollector(), KEVCollector(), GitHubPoCCollector()])

    def run(self, window_hours: int = 72) -> Tuple[List[ThreatSignal], List[SignalCluster], List[Forecast]]:
        all_sigs: List[ThreatSignal] = []
        for c in self.collectors:
            try: all_sigs.extend(c.collect(window_hours))
            except Exception as e: logger.error(f"{c.name}: {e}")

        # Deduplicate
        seen: Set[str] = set(); unique = []
        for s in all_sigs:
            if s.signal_id not in seen: seen.add(s.signal_id); unique.append(s)
        unique.sort(key=lambda s: s.confidence, reverse=True)

        clusters = correlate_signals(unique)
        forecasts = forecast_clusters(clusters)
        return unique, clusters, forecasts
