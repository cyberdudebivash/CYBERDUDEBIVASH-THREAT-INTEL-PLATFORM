"""
CYBERDUDEBIVASH® SENTINEL APEX — Natural Language Query (NLQ) Engine
POST /api/v1/nlq/query      — Ask anything in natural language
GET  /api/v1/nlq/examples   — Example queries
GET  /api/v1/nlq/health     — Engine health

Revenue: PRO ($49/mo includes NLQ) · ENTERPRISE (advanced NLQ + LLM)
Enables non-technical users: SOC managers, executives, risk teams

Examples:
  "Show me all critical ransomware threats from the last 7 days"
  "What APT groups are targeting financial sector?"
  "List IOCs for LockBit ransomware"
  "What vulnerabilities have CISA KEV confirmed exploitation?"
  "How many threats from China this month?"
  "What should I do about CVE-2024-12345?"
"""
from __future__ import annotations

import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-NLQ")
_FASTAPI_OK = False

try:
    from fastapi import APIRouter, HTTPException, Header
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# ── Intent patterns ───────────────────────────────────────────────────────────
INTENT_PATTERNS: List[Tuple[str, str, Dict]] = [
    # Threat listing
    (r"(?:show|list|get|find|give me).*(?:critical|high|medium|low)\s*(?:threats?|advisories?|alerts?)",
     "FILTER_BY_SEVERITY", {"extract": "severity"}),
    (r"(?:show|list|get|find).*(?:ransomware|malware|phishing|apt|supply chain|vulnerability).*(?:threats?|advisories?)?",
     "FILTER_BY_TYPE", {"extract": "type"}),
    (r"(?:show|list|get).*(?:kev|cisa kev|actively exploited|confirmed exploitation)",
     "FILTER_KEV", {}),
    (r"(?:show|list|get).*(?:new|latest|recent|last \d+ days?|today|this week)",
     "FILTER_RECENT", {"extract": "time"}),

    # IOC queries
    (r"(?:iocs?|indicators?|hashes?|ips?|domains?|urls?)\s+(?:for|from|related to)\s+(.+)",
     "GET_IOCS", {"extract": "subject"}),
    (r"(?:show|find|list)\s+(?:all\s+)?iocs?",
     "LIST_IOCS", {}),

    # Actor queries
    (r"(?:what|which)\s+(?:apt|threat actor|group)s?\s+(?:are\s+)?(?:targeting|attacking|targeting)\s+(.+)",
     "ACTORS_TARGETING", {"extract": "target"}),
    (r"(?:tell me about|show|what is|info on)\s+(?:apt\d+|lazarus|fancy bear|cozy bear|sandworm|\w+\s+group)",
     "ACTOR_PROFILE", {"extract": "actor"}),

    # CVE/vulnerability queries
    (r"(?:cve-?\d{4}-?\d+)",
     "CVE_LOOKUP", {"extract": "cve_id"}),
    (r"(?:what|which)\s+(?:vulnerabilities?|cves?|exploits?)\s+(?:have|has|are)\s+(?:kev|actively exploited)",
     "LIST_KEV_VULNS", {}),
    (r"(?:vulnerabilities?|cves?)\s+(?:in|for|affecting)\s+(.+)",
     "VULNS_FOR_PRODUCT", {"extract": "product"}),

    # Country/geo queries
    (r"(?:how many|count|number of)\s+(?:threats?|attacks?|advisories?)\s+(?:from|by)\s+(china|russia|north korea|iran|\w+)",
     "COUNT_BY_COUNTRY", {"extract": "country"}),
    (r"(?:threats?|attacks?)\s+(?:from|by|attributed to)\s+(china|russia|north korea|iran|\w+)",
     "FILTER_BY_ACTOR_COUNTRY", {"extract": "country"}),

    # Action/response queries
    (r"(?:what should i do|how do i respond|how to respond|action plan|response)\s+(?:about|for|to)\s+(.+)",
     "RESPONSE_GUIDANCE", {"extract": "threat"}),
    (r"(?:how to|how do i|how can i)\s+(?:detect|hunt for|find)\s+(.+)",
     "HUNT_GUIDANCE", {"extract": "subject"}),

    # Statistics
    (r"(?:how many|count|number of|total)\s+(?:threats?|advisories?|incidents?|iocs?)",
     "STATS_COUNT", {}),
    (r"(?:statistics?|stats?|summary|overview|dashboard)",
     "STATS_OVERVIEW", {}),

    # Risk queries
    (r"(?:risk score|risk level|severity)\s+(?:for|of)\s+(.+)",
     "RISK_QUERY", {"extract": "subject"}),

    # Catch-all general question
    (r".*",
     "GENERAL_QUERY", {}),
]

# ── Severity aliases ──────────────────────────────────────────────────────────
SEVERITY_ALIASES: Dict[str, List[str]] = {
    "CRITICAL": ["critical", "p1", "highest", "maximum", "emergency"],
    "HIGH":     ["high", "p2", "serious", "severe"],
    "MEDIUM":   ["medium", "p3", "moderate", "mid"],
    "LOW":      ["low", "p4", "informational", "info", "minimal"],
}

# ── Threat type aliases ────────────────────────────────────────────────────────
TYPE_ALIASES: Dict[str, List[str]] = {
    "Ransomware":     ["ransomware", "ransom", "lockbit", "revil", "cl0p", "alphv", "blackcat"],
    "APT":            ["apt", "nation.state", "advanced persistent", "state.sponsored"],
    "Phishing":       ["phishing", "spear.phish", "credential", "bec"],
    "Malware":        ["malware", "trojan", "backdoor", "rat", "infostealer", "stealer"],
    "Vulnerability":  ["vulnerability", "cve", "exploit", "0.day", "zero.day", "patch"],
    "Supply Chain":   ["supply.chain", "dependency", "sbom", "package"],
    "Data Breach":    ["breach", "data.leak", "exfiltration"],
}

# ── Country → actor mapping for geo queries ───────────────────────────────────
COUNTRY_ACTORS: Dict[str, List[str]] = {
    "china":       ["APT41", "APT40", "Volt Typhoon", "APT10", "Hafnium"],
    "russia":      ["APT28", "APT29", "Sandworm", "Turla", "Gamaredon"],
    "north korea": ["Lazarus", "APT38", "Kimsuky", "Andariel"],
    "iran":        ["APT33", "APT34", "APT35", "MuddyWater"],
    "belarus":     ["Ghostwriter", "UNC1151"],
}

# ── NLQ Examples ─────────────────────────────────────────────────────────────
NLQ_EXAMPLES = [
    {"query": "Show me all critical ransomware threats",           "intent": "FILTER_BY_SEVERITY+TYPE"},
    {"query": "What APT groups are targeting financial services?", "intent": "ACTORS_TARGETING"},
    {"query": "List all CISA KEV vulnerabilities",                "intent": "LIST_KEV_VULNS"},
    {"query": "How many threats from Russia this month?",          "intent": "COUNT_BY_COUNTRY"},
    {"query": "Show me IOCs for LockBit ransomware",               "intent": "GET_IOCS"},
    {"query": "What should I do about a ransomware infection?",    "intent": "RESPONSE_GUIDANCE"},
    {"query": "Find CVE-2024-12345",                               "intent": "CVE_LOOKUP"},
    {"query": "What are the latest critical threats?",             "intent": "FILTER_RECENT+SEVERITY"},
    {"query": "How do I detect Volt Typhoon activity?",            "intent": "HUNT_GUIDANCE"},
    {"query": "Give me a threat summary",                          "intent": "STATS_OVERVIEW"},
]


class NLQEngine:
    """Natural Language Query engine for threat intelligence."""

    def __init__(self):
        self._feed_cache: Optional[List[Dict]] = None
        self._cache_ts: float = 0

    def _load_feed(self) -> List[Dict]:
        now = time.time()
        if self._feed_cache is not None and now - self._cache_ts < 300:
            return self._feed_cache
        paths = [
            BASE_DIR / "api" / "feed.json",
            BASE_DIR / "api" / "feed_enterprise.json",
        ]
        for path in paths:
            try:
                if path.exists():
                    with open(path, encoding="utf-8") as f:
                        raw = json.load(f)
                    items = raw if isinstance(raw, list) else raw.get("data", [])
                    if items:
                        self._feed_cache = items
                        self._cache_ts   = now
                        return items
            except Exception:
                continue
        return []

    def parse_intent(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Detect intent from natural language query."""
        q = query.lower().strip()
        for pattern, intent, context in INTENT_PATTERNS:
            m = re.search(pattern, q, re.I | re.S)
            if m:
                extracted: Dict[str, Any] = {}
                if context.get("extract") == "severity":
                    for sev, aliases in SEVERITY_ALIASES.items():
                        if any(a in q for a in aliases):
                            extracted["severity"] = sev
                            break
                elif context.get("extract") == "type":
                    for ttype, aliases in TYPE_ALIASES.items():
                        if any(re.search(a, q) for a in aliases):
                            extracted["threat_type"] = ttype
                            break
                elif context.get("extract") == "country":
                    for country in COUNTRY_ACTORS:
                        if country in q:
                            extracted["country"] = country
                            extracted["actors"]  = COUNTRY_ACTORS[country]
                            break
                elif context.get("extract") == "cve_id":
                    cve_match = re.search(r"cve-?(\d{4})-?(\d+)", q, re.I)
                    if cve_match:
                        extracted["cve_id"] = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
                elif context.get("extract") in ("subject", "threat", "product", "actor", "target"):
                    if m.lastindex:
                        extracted[context["extract"]] = m.group(m.lastindex).strip()
                elif context.get("extract") == "time":
                    days_match = re.search(r"last (\d+) days?", q)
                    extracted["days"] = int(days_match.group(1)) if days_match else 7
                return intent, extracted
        return "GENERAL_QUERY", {}

    def execute(self, query: str, limit: int = 25) -> Dict[str, Any]:
        """Parse intent and execute against threat feed."""
        t0     = time.time()
        intent, params = self.parse_intent(query)
        feed   = self._load_feed()

        results: List[Dict] = []
        answer:  str = ""
        stats:   Dict = {}

        if intent == "FILTER_BY_SEVERITY":
            sev = params.get("severity", "HIGH")
            results = [i for i in feed if (i.get("severity") or "").upper() == sev]
            answer  = f"Found {len(results)} {sev} severity advisories."
            results = results[:limit]

        elif intent == "FILTER_BY_TYPE":
            ttype = params.get("threat_type", "")
            if ttype:
                results = [i for i in feed if ttype.lower() in (i.get("threat_type") or "").lower()]
                answer  = f"Found {len(results)} {ttype} advisories."
            else:
                results = feed[:limit]
                answer  = "Showing all advisories."
            results = results[:limit]

        elif intent == "FILTER_KEV":
            results = [i for i in feed if i.get("kev_present")]
            answer  = f"Found {len(results)} advisories with CISA KEV-confirmed exploitation."
            results = results[:limit]

        elif intent in ("FILTER_RECENT", "LIST_IOCS"):
            days    = params.get("days", 7)
            results = feed[:limit]
            answer  = f"Showing {len(results)} most recent advisories."

        elif intent == "GET_IOCS":
            subject = params.get("subject", "")
            results = [i for i in feed
                       if subject.lower() in (i.get("title") or "").lower()
                       or subject.lower() in (i.get("actor_tag") or "").lower()
                       or subject.lower() in (i.get("threat_type") or "").lower()]
            total_iocs = sum(
                sum(v for v in (i.get("ioc_counts") or {}).values() if isinstance(v, (int, float)))
                for i in results
            )
            answer = f"Found {len(results)} advisories with {total_iocs} total IOCs related to '{subject}'."
            results = results[:limit]

        elif intent == "ACTORS_TARGETING":
            target  = params.get("target", "")
            results = [i for i in feed
                       if target.lower() in (i.get("title") or "").lower()
                       or i.get("actor_tag") not in ("UNATTRIBUTED", "UNC-UNKNOWN", "UNC-CDB-99")]
            actors  = list({i.get("actor_tag", "") for i in results if i.get("actor_tag")})
            answer  = f"APT groups targeting '{target}': {', '.join(actors[:10])}. {len(results)} related advisories."
            results = results[:limit]

        elif intent == "CVE_LOOKUP":
            cve_id  = params.get("cve_id", "")
            results = [i for i in feed
                       if cve_id.lower() in (i.get("title") or "").lower()
                       or cve_id.lower() in str(i).lower()]
            answer  = f"Found {len(results)} advisories mentioning {cve_id}."
            results = results[:limit]

        elif intent == "LIST_KEV_VULNS":
            results = [i for i in feed if i.get("kev_present") and
                       "vulnerab" in (i.get("threat_type") or "").lower()]
            if not results:
                results = [i for i in feed if i.get("kev_present")]
            answer = f"Found {len(results)} advisories with CISA KEV-confirmed exploitation."
            results = results[:limit]

        elif intent == "COUNT_BY_COUNTRY":
            country = params.get("country", "")
            actors  = params.get("actors", [])
            matches = [i for i in feed if
                       any(a.lower() in (i.get("actor_tag") or "").lower() for a in actors)]
            answer  = (f"Found {len(matches)} advisories attributed to {country.title()} "
                       f"(actors: {', '.join(actors[:5])}).")
            results = matches[:limit]
            stats   = {"country": country, "attributed_count": len(matches), "actors": actors}

        elif intent == "FILTER_BY_ACTOR_COUNTRY":
            country = params.get("country", "")
            actors  = params.get("actors", [])
            results = [i for i in feed if
                       any(a.lower() in (i.get("actor_tag") or "").lower() for a in actors)]
            answer  = f"Found {len(results)} advisories attributed to {country.title()}-nexus actors."
            results = results[:limit]

        elif intent == "RESPONSE_GUIDANCE":
            threat = params.get("threat", "")
            # Find matching advisory, then route to copilot
            results = [i for i in feed
                       if threat.lower() in (i.get("title") or "").lower()
                       or threat.lower() in (i.get("threat_type") or "").lower()][:3]
            from api.copilot import get_engine
            if results:
                eng = get_engine()
                playbook = eng.what_to_do(results[0], query)
                answer = f"Response guidance for '{threat}'."
                return {
                    "query":      query,
                    "intent":     intent,
                    "answer":     answer,
                    "mode":       "response_guidance",
                    "playbook":   playbook,
                    "results":    self._summarize(results),
                    "result_count": len(results),
                    "processed_in_ms": round((time.time() - t0) * 1000),
                    "engine":     "NLQ v1.0",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            else:
                answer = f"No specific advisories found for '{threat}'. Showing general guidance."
                results = feed[:3]

        elif intent == "HUNT_GUIDANCE":
            subject = params.get("subject", query)
            results = [i for i in feed
                       if subject.lower() in (i.get("title") or "").lower()
                       or subject.lower() in (i.get("actor_tag") or "").lower()][:3]
            answer  = f"Threat hunting guidance for '{subject}'."

        elif intent == "STATS_COUNT":
            answer = (f"Total advisories: {len(feed)} | "
                      f"Critical: {sum(1 for i in feed if (i.get('severity') or '').upper() == 'CRITICAL')} | "
                      f"KEV: {sum(1 for i in feed if i.get('kev_present'))} | "
                      f"With IOCs: {sum(1 for i in feed if sum((i.get('ioc_counts') or {}).values() or [0]) > 0)}")
            stats = {
                "total":      len(feed),
                "critical":   sum(1 for i in feed if (i.get("severity") or "").upper() == "CRITICAL"),
                "high":       sum(1 for i in feed if (i.get("severity") or "").upper() == "HIGH"),
                "kev_count":  sum(1 for i in feed if i.get("kev_present")),
                "with_iocs":  sum(1 for i in feed if sum((i.get("ioc_counts") or {}).values() or [0]) > 0),
            }

        elif intent == "STATS_OVERVIEW":
            sev_dist = {}
            for item in feed:
                s = (item.get("severity") or "UNKNOWN").upper()
                sev_dist[s] = sev_dist.get(s, 0) + 1
            type_dist = {}
            for item in feed:
                t = item.get("threat_type") or "Unknown"
                type_dist[t] = type_dist.get(t, 0) + 1
            answer = f"Threat intelligence overview: {len(feed)} advisories across {len(type_dist)} threat types."
            stats  = {
                "total_advisories": len(feed),
                "severity_distribution": sev_dist,
                "top_threat_types": sorted(type_dist.items(), key=lambda x: -x[1])[:10],
                "kev_confirmed":    sum(1 for i in feed if i.get("kev_present")),
                "attributed_to_apt": sum(1 for i in feed if i.get("actor_tag") not in ("UNATTRIBUTED", "UNC-UNKNOWN", "", None)),
                "supply_chain":     sum(1 for i in feed if i.get("supply_chain")),
            }
            results = feed[:5]

        else:  # GENERAL_QUERY
            q_lower = query.lower()
            results = [i for i in feed
                       if any(word in (i.get("title") or "").lower() for word in q_lower.split()
                              if len(word) > 3)][:limit]
            if not results:
                results = feed[:limit // 2]
            answer = f"Found {len(results)} relevant advisories for your query."

        return {
            "query":          query,
            "intent":         intent,
            "intent_params":  params,
            "answer":         answer,
            "result_count":   len(results),
            "results":        self._summarize(results),
            "stats":          stats,
            "processed_in_ms": round((time.time() - t0) * 1000),
            "engine":         "NLQ v1.0",
            "generated_at":   datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _summarize(items: List[Dict]) -> List[Dict]:
        return [
            {
                "stix_id":    i.get("stix_id"),
                "title":      i.get("title"),
                "severity":   i.get("severity"),
                "risk_score": i.get("risk_score"),
                "threat_type": i.get("threat_type"),
                "actor":      i.get("actor_tag"),
                "kev":        i.get("kev_present"),
                "ioc_count":  sum((i.get("ioc_counts") or {}).values() or [0]),
                "timestamp":  i.get("timestamp"),
            }
            for i in items
        ]


_nlq_engine: Optional[NLQEngine] = None

def get_nlq_engine() -> NLQEngine:
    global _nlq_engine
    if _nlq_engine is None:
        _nlq_engine = NLQEngine()
    return _nlq_engine


if _FASTAPI_OK:
    nlq_router = APIRouter(prefix="/api/v1/nlq", tags=["Natural Language Query"])

    class NLQRequest(BaseModel):
        query: str
        limit: int = 25

    @nlq_router.post("/query", summary="Natural language threat intelligence query")
    async def nlq_query(req: NLQRequest):
        if not req.query or len(req.query.strip()) < 3:
            raise HTTPException(400, {"error": "query must be at least 3 characters"})
        if len(req.query) > 500:
            raise HTTPException(400, {"error": "query too long (max 500 chars)"})
        try:
            engine = get_nlq_engine()
            result = engine.execute(req.query, max(1, min(100, req.limit)))
            return {"status": "success", **result}
        except Exception as e:
            logger.error(f"NLQ error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "NLQ engine error", "detail": str(e)})

    @nlq_router.get("/examples", summary="Example NLQ queries")
    async def nlq_examples():
        return {
            "status":   "success",
            "examples": NLQ_EXAMPLES,
            "tip":      "Ask anything about threats, actors, IOCs, vulnerabilities, or get response guidance.",
        }

    @nlq_router.get("/health", summary="NLQ engine health")
    async def nlq_health():
        engine = get_nlq_engine()
        feed   = engine._load_feed()
        return {
            "status":         "ok",
            "engine":         "NLQ v1.0",
            "feed_loaded":    len(feed) > 0,
            "feed_size":      len(feed),
            "intent_patterns": len(INTENT_PATTERNS),
            "llm_available":  bool(__import__("os").getenv("OPENROUTER_API_KEY", "") or __import__("os").getenv("DEEPSEEK_API_KEY", "")),
        }

else:
    nlq_router = None
