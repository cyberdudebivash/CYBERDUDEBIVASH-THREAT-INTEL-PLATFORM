#!/usr/bin/env python3
"""
quality_gate.py — CYBERDUDEBIVASH® SENTINEL APEX v19.0
CONTENT INTELLIGENCE RELEVANCE GATE

Prevents editorial/opinion/marketing articles from being processed as
threat intelligence. Scores each incoming article before it enters
the expensive processing pipeline.

Examples that PASS:  "CVE-2025-1234 Exploited in Wild" ✅
                     "LockBit Ransomware Hits Healthcare" ✅
                     "APT29 Using New Backdoor in Campaign" ✅

Examples that FAIL:  "Alert Fatigue Isn't Going Away" ❌
                     "New eBook: SOC Analyst's Playbook" ❌
                     "Best Practices for Cloud Security" ❌

NON-BREAKING: If this module fails, sentinel_blogger.py continues as before.
Called BEFORE process_entry() — no impact on existing reports.
"""

import re
import logging
from typing import Tuple

logger = logging.getLogger("CDB-QUALITY-GATE")

# ── STRONG THREAT INTEL SIGNALS ──────────────────────────────────────────────
THREAT_SIGNALS = {
    "cve-":                3.0,  "zero-day":            3.5,  "0-day":               3.5,
    "actively exploited":  3.0,  "in the wild":         2.5,  "remote code exec":    3.0,
    "rce":                 2.5,  "privilege escalation":2.5,  "authentication bypass":2.5,
    "nation-state":        3.0,  "state-sponsored":     3.0,
    "ransomware attack":   3.0,  "supply chain attack": 3.0,
    "data breach":         2.5,  "records exposed":     2.5,  "records leaked":      2.5,
    "malware":             2.0,  "ransomware":          2.5,  "trojan":              2.0,
    "backdoor":            2.5,  "botnet":              2.0,  "infostealer":         2.5,
    "stealer":             2.0,  "loader":              2.0,  "dropper":             2.0,
    "apt":                 2.5,  "threat actor":        2.0,  "threat group":        2.0,
    "lazarus":             3.0,  "lockbit":             3.0,  "blackcat":            2.5,
    "volt typhoon":        3.0,  "fancy bear":          3.0,  "cobalt strike":       3.0,
    "indicators of compromise": 3.0,  "ioc":            2.5,
    "command and control": 2.5,  "c2 server":           2.5,  "c&c":                2.0,
    "cisa":                2.0,  "kev":                 2.5,  "advisory":            1.0,
    "sigma":               2.0,  "yara":                2.5,  "stix":                2.0,
    "exploited":           2.0,  "exploit":             1.5,  "vulnerability":       1.5,
    "patch":               1.0,  "security update":     1.0,
    "phishing campaign":   2.0,  "spear-phishing":      2.5,  "spearphishing":       2.5,
    "credential theft":    2.0,  "credential harvest":  2.0,
    "compromised":         1.5,  "hacked":              1.5,  "breach":              1.5,
    "data exfiltration":   2.5,  "exfiltration":        2.0,
    "malicious":           1.5,  "infected":            1.5,
    "supply chain":        2.5,  "dependency":          1.0,
}

# ── NOISE / NON-THREAT SIGNALS (NEGATIVE) ────────────────────────────────────
NOISE_SIGNALS = {
    "new ebook":           -5.0,  "download our":        -5.0,  "free ebook":         -5.0,
    "we created":          -3.0,  "why we built":        -3.0,  "we're excited":      -3.0,
    "register now":        -4.0,  "free webinar":        -4.0,  "join our webinar":   -4.0,
    "best practices":      -2.0,  "how to avoid":        -2.0,  "tips for":           -2.0,
    "guide to":            -2.0,  "introduction to":     -2.5,  "what is":            -2.0,
    "here's how":          -3.0,  "fighting back":       -3.0,  "isn't going away":   -3.0,
    "you should":          -2.0,  "you need to":         -2.0,  "why you":            -2.0,
    "our new":             -2.0,  "announcing":          -2.5,  "product launch":     -3.0,
    "job posting":         -5.0,  "we are hiring":       -5.0,  "career opportunity": -5.0,
    "conference talk":     -3.0,  "event recap":         -3.0,  "year in review":     -3.0,
    "opinion:":            -3.5,  "editorial:":          -3.5,  "commentary:":        -3.0,
    "predictions for":     -2.0,  "trends in":           -1.5,  "future of":          -1.5,
    "alert fatigue":       -3.0,  "soc analyst's playbook": -4.0,
    "customer story":      -3.0,  "case study:":         -2.0,
    "burnout":             -1.5,  "security culture":    -1.5,  "hiring":             -3.0,
}

# Absolute skip phrases — immediate fail
INSTANT_FAIL_PHRASES = [
    "new ebook", "download our ebook", "free webinar", "register for webinar",
    "product announcement", "we are hiring", "join our team", "open position",
    "soc analyst's playbook", "isn't going away. here's how",
    "here's how modern socs are fighting back",
]

# Minimum relevance score to process
THRESHOLD = 3.5

# Minimum words in content
MIN_WORDS = 60


def score_article(title: str, content: str) -> Tuple[float, str]:
    """Score article for threat intelligence relevance. Returns (score, reason)."""
    text = f"{title} {content}".lower()

    # Instant fail check
    for phrase in INSTANT_FAIL_PHRASES:
        if phrase in text:
            return -10.0, f"instant_fail:'{phrase[:40]}'"

    score = 0.0
    hits = []

    for signal, w in THREAT_SIGNALS.items():
        if signal in text:
            score += w
            hits.append(f"+{w}[{signal}]")

    for signal, w in NOISE_SIGNALS.items():
        if signal in text:
            score += w
            hits.append(f"{w}[{signal}]")

    # CVE bonus
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    if cves:
        bonus = min(len(cves) * 2.0, 8.0)
        score += bonus
        hits.append(f"+{bonus}[{len(cves)}CVEs]")

    # Hash bonus (SHA256/MD5 = confirmed IOCs)
    if re.search(r'\b[a-fA-F0-9]{64}\b', text):
        score += 4.0; hits.append("+4.0[sha256]")
    elif re.search(r'\b[a-fA-F0-9]{32}\b', text):
        score += 2.5; hits.append("+2.5[md5]")

    # IP address bonus
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if len(ips) >= 3:
        score += 2.0; hits.append(f"+2.0[{len(ips)}IPs]")

    reason = f"score={score:.1f} top_signals={' '.join(hits[:4])}"
    return score, reason


def is_relevant_threat(title: str, content: str) -> Tuple[bool, float, str]:
    """
    Gate function. Returns (should_process, score, reason).
    Usage: relevant, score, reason = is_relevant_threat(title, content)
    """
    wc = len(content.split())
    if wc < MIN_WORDS:
        return False, 0.0, f"thin_content:{wc}words"

    score, reason = score_article(title, content)
    if score >= THRESHOLD:
        return True, score, reason
    return False, score, f"low_relevance({score:.1f}):{reason}"
