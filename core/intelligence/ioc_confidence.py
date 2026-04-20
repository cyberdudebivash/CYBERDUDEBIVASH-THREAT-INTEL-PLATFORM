#!/usr/bin/env python3
"""
core/intelligence/ioc_confidence.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.0 -- IOC CONFIDENCE SCORING ENGINE
=========================================================================
Weighted confidence score (0-100%) per IOC.

Weights: ioc_type=30%  source_trust=25%  mitre_mapping=25%  kev_presence=20%

Rules:
  - Min confidence  : 15%  (no IOC ever ships at 0%)
  - Max confidence  : 99%  (never claim 100% certainty)
  - Synthetic IOCs  : capped at 78%
  - KEV-linked IOCs : minimum 75%

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-IOC-CONFIDENCE")

MIN_CONFIDENCE = 15.0
MAX_CONFIDENCE = 99.0
SYNTHETIC_CAP  = 78.0
KEV_MINIMUM    = 75.0

_IOC_TYPE_QUALITY: Dict[str, float] = {
    "sha256": 1.00, "sha1": 0.95, "md5": 0.90, "ssdeep": 0.85, "tlsh": 0.85,
    "ipv4": 0.80, "ipv6": 0.80, "domain": 0.75, "url": 0.70, "email": 0.65,
    "cve": 0.88, "cpe": 0.80, "yara": 0.90, "sigma": 0.88,
    "registry": 0.70, "filepath": 0.65, "filename": 0.55, "mutex": 0.72,
    "useragent": 0.60, "ja3": 0.78, "behavioral": 0.68, "asn": 0.55,
    "cidr": 0.60, "bitcoin": 0.75, "monero": 0.75,
}

_SOURCE_TRUST: Dict[str, float] = {
    "kev": 1.00, "nvd": 0.95, "mitre": 0.95,
    "abuseipdb": 0.85, "malwarebazaar": 0.88, "virustotal": 0.82,
    "threatfox": 0.80, "circl": 0.85, "abuse_ch": 0.83,
    "alienvault": 0.75, "opencti": 0.78, "misp": 0.76,
    "feedly": 0.65, "rss": 0.55, "community": 0.50,
    "synthetic": 0.30, "generated": 0.30, "unknown": 0.40,
}

_MITRE_SPECIFICITY: Dict[str, float] = {
    "subtechnique": 1.00, "technique": 0.80, "tactic": 0.55, "none": 0.00,
}

_SUBTECHNIQUE_RE = re.compile(r"T\d{4}\.\d{3}")
_TECHNIQUE_RE    = re.compile(r"T\d{4}")
_TACTIC_RE       = re.compile(r"TA\d{4}")


class IOCConfidenceEngine:
    """Weighted multi-factor IOC confidence scoring engine."""

    WEIGHTS = {
        "ioc_type":      0.30,
        "source_trust":  0.25,
        "mitre_mapping": 0.25,
        "kev_presence":  0.20,
    }

    def score(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        ioc = dict(ioc)
        ioc_type     = (ioc.get("type") or "unknown").lower()
        source       = self._resolve_source(ioc)
        mitre_refs   = self._extract_mitre_refs(ioc)
        is_kev       = self._is_kev_linked(ioc)
        is_synthetic = self._is_synthetic(ioc)

        type_score  = _IOC_TYPE_QUALITY.get(ioc_type, 0.45) * 100.0
        trust_score = _SOURCE_TRUST.get(source, 0.40) * 100.0
        mitre_score = self._compute_mitre_score(mitre_refs) * 100.0
        kev_score   = 100.0 if is_kev else (40.0 if self._is_cve(ioc) else 0.0)

        raw_score = (
            type_score  * self.WEIGHTS["ioc_type"]      +
            trust_score * self.WEIGHTS["source_trust"]  +
            mitre_score * self.WEIGHTS["mitre_mapping"] +
            kev_score   * self.WEIGHTS["kev_presence"]
        )

        confidence = max(MIN_CONFIDENCE, min(raw_score, MAX_CONFIDENCE))
        if is_synthetic:
            confidence = min(confidence, SYNTHETIC_CAP)
        if is_kev and confidence < KEV_MINIMUM:
            confidence = KEV_MINIMUM
        confidence = round(confidence, 1)

        ioc["confidence"] = confidence
        ioc["confidence_factors"] = {
            "ioc_type":     round(type_score, 1),
            "source_trust": round(trust_score, 1),
            "mitre_mapping":round(mitre_score, 1),
            "kev_presence": round(kev_score, 1),
            "weighted_raw": round(raw_score, 1),
            "synthetic":    is_synthetic,
            "kev_linked":   is_kev,
        }
        ioc["confidence_version"] = "1.0"
        return ioc

    def score_batch(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.score(ioc) for ioc in iocs]

    def audit_report(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        scored = [ioc for ioc in iocs if "confidence" in ioc]
        if not scored:
            return {"total": 0, "violations": [], "avg": 0.0, "min": 0.0, "max": 0.0}
        confidences = [float(i["confidence"]) for i in scored]
        violations  = [
            {"type": i.get("type"), "value": str(i.get("value",""))[:40], "confidence": i["confidence"]}
            for i in scored if float(i["confidence"]) < MIN_CONFIDENCE
        ]
        buckets = {"HIGH_GE80": 0, "MEDIUM_60_79": 0, "LOW_40_59": 0, "MINIMAL_LT40": 0}
        for c in confidences:
            if   c >= 80: buckets["HIGH_GE80"]    += 1
            elif c >= 60: buckets["MEDIUM_60_79"] += 1
            elif c >= 40: buckets["LOW_40_59"]    += 1
            else:         buckets["MINIMAL_LT40"] += 1
        return {
            "total":      len(scored),
            "avg":        round(sum(confidences)/len(confidences), 1),
            "min":        min(confidences),
            "max":        max(confidences),
            "buckets":    buckets,
            "violations": violations,
            "compliant":  len(violations) == 0,
        }

    def ensure_minimum_confidence(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        result = []
        for ioc in iocs:
            if "confidence" not in ioc:
                ioc = self.score(ioc)
            elif float(ioc["confidence"]) < MIN_CONFIDENCE:
                ioc = dict(ioc)
                ioc["confidence"] = MIN_CONFIDENCE
                ioc["confidence_floored"] = True
            result.append(ioc)
        return result

    def _resolve_source(self, ioc: Dict[str, Any]) -> str:
        for key in ("source", "feed_source", "source_id", "origin"):
            val = str(ioc.get(key) or "").lower()
            if val:
                if "kev"      in val: return "kev"
                if "nvd"      in val: return "nvd"
                if "abuse"    in val: return "abuseipdb"
                if "bazaar"   in val or "mwdb" in val: return "malwarebazaar"
                if "mitre"    in val: return "mitre"
                if "opencti"  in val: return "opencti"
                if "misp"     in val: return "misp"
                if "feedly"   in val: return "feedly"
                if "rss"      in val: return "rss"
                if "generated" in val or "synthetic" in val: return "synthetic"
                if val in _SOURCE_TRUST: return val
        if ioc.get("generated") or ioc.get("synthetic"):
            return "synthetic"
        return "unknown"

    def _extract_mitre_refs(self, ioc: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        for field in ("mitre_technique","mitre_tactic","technique_id","ttps","mitre","context","tags"):
            val = ioc.get(field)
            if not val:
                continue
            text = _safe_str(val)
            refs.extend(_SUBTECHNIQUE_RE.findall(text))
            refs.extend(_TECHNIQUE_RE.findall(text))
            refs.extend(_TACTIC_RE.findall(text))
        return list(set(refs))

    def _compute_mitre_score(self, refs: List[str]) -> float:
        if not refs:
            return _MITRE_SPECIFICITY["none"]
        best = _MITRE_SPECIFICITY["none"]
        for ref in refs:
            if _SUBTECHNIQUE_RE.match(ref): best = max(best, _MITRE_SPECIFICITY["subtechnique"])
            elif _TECHNIQUE_RE.match(ref):  best = max(best, _MITRE_SPECIFICITY["technique"])
            elif _TACTIC_RE.match(ref):     best = max(best, _MITRE_SPECIFICITY["tactic"])
        count_bonus = min(len(refs) * 0.05, 0.15)
        return min(best + count_bonus, 1.0)

    def _is_kev_linked(self, ioc: Dict[str, Any]) -> bool:
        if ioc.get("kev_listed") or ioc.get("in_kev"): return True
        if "kev" in str(ioc.get("source") or "").lower(): return True
        return bool(ioc.get("cve_id") and ioc.get("exploited_in_wild"))

    def _is_synthetic(self, ioc: Dict[str, Any]) -> bool:
        return bool(ioc.get("generated") or ioc.get("synthetic") or
                    str(ioc.get("source") or "").lower() in ("synthetic", "generated"))

    def _is_cve(self, ioc: Dict[str, Any]) -> bool:
        return bool(ioc.get("cve_id") or ioc.get("cve") or
                    (ioc.get("type") or "").lower() == "cve")


def _safe_str(val: Any) -> str:
    if isinstance(val, str):          return val
    if isinstance(val, (list,tuple)): return " ".join(str(v) for v in val)
    if isinstance(val, dict):         return " ".join(str(v) for v in val.values())
    return str(val)


_engine: Optional[IOCConfidenceEngine] = None

def get_confidence_engine() -> IOCConfidenceEngine:
    global _engine
    if _engine is None:
        _engine = IOCConfidenceEngine()
    return _engine

def score_ioc(ioc: Dict[str, Any]) -> Dict[str, Any]:
    return get_confidence_engine().score(ioc)

def score_iocs(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return get_confidence_engine().score_batch(iocs)

def ensure_no_zero_confidence(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return get_confidence_engine().ensure_minimum_confidence(iocs)


if __name__ == "__main__":
    import json, sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    samples = [
        {"type": "sha256",     "value": "abc123def456",  "source": "malwarebazaar", "mitre_technique": "T1059.001"},
        {"type": "ipv4",       "value": "185.234.1.99",  "source": "abuseipdb"},
        {"type": "domain",     "value": "c2-evil.xyz",   "generated": True},
        {"type": "cve",        "value": "CVE-2024-1234", "source": "kev", "kev_listed": True},
        {"type": "behavioral", "value": "LSASS dump",    "source": "mitre", "mitre_technique": "T1003.001"},
    ]
    engine = IOCConfidenceEngine()
    scored = engine.score_batch(samples)
    report = engine.audit_report(scored)
    print(json.dumps({"samples": scored, "audit": report}, indent=2, default=str))
