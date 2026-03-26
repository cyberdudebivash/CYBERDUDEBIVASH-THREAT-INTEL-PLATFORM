#!/usr/bin/env python3
"""
quality_gate.py — CyberDudeBivash® SENTINEL APEX v22.1
=======================================================
v77.2 FIXES:
  1. THRESHOLD lowered 6.0 → 4.5
     WHY: Legitimate threats like "OpenAI AI Safety Bug Bounty" (score=4.0,
     3 strong signals) were being blocked. Threshold was too aggressive.
     4.5 still blocks all noise (score <= 0) while passing real threats.

  2. INSTANT_FAIL_PHRASES: Added vendor award/marketing phrases
     "recognized for innovations", "global infosec awards", etc.
     WHY: "ANY.RUN Recognized for Innovations at Global InfoSec Awards"
     had 0 IOCs, 0 CVEs, risk=1.9 but passed the gate and got published.

  3. NOISE_SIGNALS: Added vendor award negative weights (-6 to -8)
     WHY: Belt-and-suspenders — even if title doesn't match instant_fail,
     the score will be negative enough to fail threshold.

All v22.0 fixes (HARD_BLOCKED_PATTERNS, product announcement blocking, etc.)
are preserved with zero regression.
"""

import re
import logging
from typing import Tuple

logger = logging.getLogger("CDB-QUALITY-GATE")

# ── STRONG THREAT INTEL SIGNALS ──────────────────────────────────────────────
THREAT_SIGNALS = {
    "cve-":                3.0,  "zero-day":            3.5,  "0-day":               3.5,
    "actively exploited":  4.0,  "in the wild":         3.0,  "remote code exec":    3.5,
    "rce":                 3.0,  "privilege escalation": 3.0, "authentication bypass": 3.0,
    "nation-state":        3.5,  "state-sponsored":     3.5,
    "ransomware attack":   3.5,  "supply chain attack": 3.5,
    "data breach":         3.0,  "records exposed":     3.0,  "records leaked":      3.0,
    "malware":             2.5,  "ransomware":          3.0,  "trojan":              2.5,
    "backdoor":            3.0,  "botnet":              2.5,  "infostealer":         3.0,
    "stealer":             2.5,  "loader":              2.5,  "dropper":             2.5,
    "apt":                 3.0,  "threat actor":        2.5,  "threat group":        2.5,
    "lazarus":             3.5,  "lockbit":             3.5,  "blackcat":            3.0,
    "volt typhoon":        3.5,  "fancy bear":          3.5,  "cobalt strike":       3.5,
    "indicators of compromise": 3.5, "ioc":             3.0,
    "command and control": 3.0,  "c2 server":           3.0,  "c&c":                2.5,
    "cisa":                2.5,  "kev":                 3.0,
    "exploited":           2.5,  "exploit":             2.0,
    "phishing campaign":   2.5,  "spear-phishing":      3.0,
    "credential theft":    2.5,  "credential harvest":  2.5,
    "hacked":              2.5,  "breach":              2.5,
    "data exfiltration":   3.0,  "exfiltration":        2.5,
    "compromised":         2.5,  "unauthorized access": 3.0,
    "malicious":           2.0,
    "proof of concept":    3.0,  "poc released":        3.5,
    "actively being exploited": 4.0,
    "emergency patch":     3.5,  "critical patch":      3.0,
    "under active attack": 4.0,
    "vulnerability":       1.5,  "patch tuesday":       2.0,
    # v77.2 NEW: bug bounty programs = legitimate threat research signal
    "bug bounty":          2.0,  "bounty program":      1.5,
    "security researcher": 1.5,  "disclosed":           1.5,
}

# ── NOISE / NON-THREAT SIGNALS (NEGATIVE) ────────────────────────────────────
NOISE_SIGNALS = {
    "new ebook":           -8.0,  "download our":        -6.0,  "free ebook":        -8.0,
    "we created":          -5.0,  "why we built":        -5.0,  "we're excited":     -5.0,
    "register now":        -6.0,  "free webinar":        -6.0,  "join our webinar":  -6.0,
    "best practices":      -3.0,  "how to avoid":        -3.0,  "tips for":          -3.0,
    "guide to":            -3.0,  "introduction to":     -4.0,  "what is":           -3.0,
    "here's how":          -4.0,  "fighting back":       -4.0,
    "you should":          -3.0,  "you need to":         -3.0,  "why you":           -3.0,
    "our new":             -4.0,  "announcing":          -4.0,  "product launch":    -5.0,
    "job posting":         -8.0,  "we are hiring":       -8.0,  "career opportunity":-8.0,
    "conference talk":     -5.0,  "event recap":         -5.0,  "year in review":    -4.0,
    "opinion:":            -5.0,  "editorial:":          -5.0,  "commentary:":       -4.0,
    "predictions for":     -3.0,  "trends in":           -2.0,  "future of":         -2.0,
    "alert fatigue":       -4.0,  "burnout":             -3.0,  "hiring":            -5.0,
    "customer story":      -5.0,  "case study:":         -3.0,
    "will make":           -5.0,  "makes it easier":     -5.0,  "making it safer":   -6.0,
    "will be safer":       -6.0,  "safer than":          -5.0,  "more secure than":  -4.0,
    "introducing":         -4.0,  "rolling out":         -4.0,  "launching":         -4.0,
    "feature announcement":-7.0,  "new feature":         -5.0,  "now available":     -4.0,
    "google announces":    -6.0,  "apple announces":     -6.0,  "microsoft releases":-5.0,
    "android update":      -4.0,  "android feature":     -6.0,  "ios update":        -4.0,
    "sideloading safer":   -8.0,  "advanced flow":       -6.0,
    "week in security":    -5.0,  "security roundup":    -5.0,  "security news":     -3.0,
    "lock and code":       -5.0,  "podcast":             -4.0,
    # v77.2: vendor award/marketing content — zero threat intel value
    "infosec award":       -8.0,  "recognized for":      -6.0,  "award winner":      -7.0,
    "market leadership":   -7.0,  "innovation award":    -8.0,  "industry award":    -7.0,
    "cyber 150":           -6.0,  "fastest growing":     -6.0,
}

# ── INSTANT FAIL — any of these = immediate rejection ────────────────────────
INSTANT_FAIL_PHRASES = [
    # Marketing content
    "new ebook", "download our ebook", "free webinar", "register for webinar",
    "product announcement", "we are hiring", "join our team", "open position",
    "soc analyst's playbook", "isn't going away. here's how",
    "here's how modern socs are fighting back",
    # Feature / improvement announcements
    "will make android sideloading safer",
    "make android sideloading safer",
    "sideloading safer",
    "advanced flow will make",
    "week in security (",
    "lock and code s0",
    "a week in security",
    "safer for users",
    "improving security for",
    "security improvements in",
    "new security feature",
    "security feature rollout",
    # News roundups
    "this week in security",
    "security news roundup",
    "monthly security digest",
    # v77.2: vendor award/marketing articles — zero threat intel value
    "recognized for innovations",
    "recognized for market leadership",
    "global infosec awards",
    "innovation award",
    "industry award",
    "enters cyber 150",
    "fastest growing",
    "market leadership",
]

# ── HARD TOPIC BLOCKLIST ─────────────────────────────────────────────────────
HARD_BLOCKED_PATTERNS = [
    r'will make .{0,40} safer',
    r'makes .{0,40} more secure',
    r'introducing .{0,40} protection',
    r'new .{0,40} security feature',
    r'week in security',
    r'security podcast',
    r'a week in',
    r'\badvanced flow\b',
    # v77.2: vendor award patterns
    r'recognized for .{0,40} (award|innovation|leadership)',
    r'(infosec|cybersecurity) award',
]

# v77.2 FIX: Lowered from 6.0 → 4.5
# WHY: Legitimate threats were being blocked (score=4.0 with 3 strong signals).
# 4.5 still filters all noise (score <= 0) while passing real threat content.
THRESHOLD = 4.5

# RSS-summary word count minimum (NOT fetched article word count)
MIN_WORDS = 80

TRUSTED_SOURCES = {
    "bleepingcomputer.com", "krebsonsecurity.com", "darkreading.com",
    "securityweek.com", "therecord.media", "cyberscoop.com",
    "securityaffairs.com", "infosecurity-magazine.com", "cisa.gov",
    "ncsc.gov.uk", "cert.europa.eu", "zerodayinitiative.com",
    "sentinelone.com", "unit42.paloaltonetworks.com", "securelist.com",
    "crowdstrike.com", "mandiant.com", "microsoft.com", "talosintelligence.com",
    "research.checkpoint.com", "rapid7.com", "helpnetsecurity.com",
    "cybersecuritynews.com", "malwarebytes.com", "theregister.com",
    "arstechnica.com", "wired.com", "404media.co",
}

MIN_STRONG_SIGNAL_COUNT = 2
STRONG_SIGNAL_THRESHOLD = 2.5


def score_article(title: str, content: str) -> Tuple[float, str, int]:
    text = f"{title} {content}".lower()

    for pattern in HARD_BLOCKED_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return -15.0, f"hard_blocked:'{pattern[:40]}'", 0

    for phrase in INSTANT_FAIL_PHRASES:
        if phrase.lower() in text:
            return -10.0, f"instant_fail:'{phrase[:40]}'", 0

    score = 0.0
    hits = []
    strong_signal_count = 0

    for signal, w in THREAT_SIGNALS.items():
        if signal in text:
            score += w
            hits.append(f"+{w}[{signal}]")
            if w >= STRONG_SIGNAL_THRESHOLD:
                strong_signal_count += 1

    for signal, w in NOISE_SIGNALS.items():
        if signal in text:
            score += w
            hits.append(f"{w}[{signal}]")

    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    if cves:
        bonus = min(len(cves) * 2.5, 10.0)
        score += bonus
        strong_signal_count += len(cves)
        hits.append(f"+{bonus}[{len(cves)}CVEs]")

    if re.search(r'\b[a-fA-F0-9]{64}\b', text):
        score += 5.0
        strong_signal_count += 1
        hits.append("+5.0[sha256_ioc]")
    elif re.search(r'\b[a-fA-F0-9]{32}\b', text):
        score += 3.0
        strong_signal_count += 1
        hits.append("+3.0[md5_ioc]")

    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    real_ips = [ip for ip in ips if not any(
        ip.startswith(p) for p in ['10.', '192.168.', '127.', '172.16.']
    )]
    if len(real_ips) >= 3:
        score += 3.0
        strong_signal_count += 1
        hits.append(f"+3.0[{len(real_ips)}real_IPs]")

    if re.search(r'\b(google|apple|microsoft|android|ios)\b.{0,30}\b(will|is|has|have)\b.{0,40}\b(safer|secure|protect|better)\b', text):
        score -= 8.0
        hits.append("-8.0[vendor_improvement_news]")

    reason = f"score={score:.1f} strong_signals={strong_signal_count} top={' '.join(hits[:4])}"
    return score, reason, strong_signal_count


def is_relevant_threat(title: str, content: str, source_url: str = "") -> Tuple[bool, float, str]:
    wc = len(content.split())

    is_trusted_source = False
    if source_url:
        try:
            from urllib.parse import urlparse
            domain = urlparse(source_url).netloc.replace("www.", "").lower()
            is_trusted_source = any(t in domain for t in TRUSTED_SOURCES)
        except Exception:
            pass

    title_has_cve = bool(re.search(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE))

    if wc < MIN_WORDS and not title_has_cve and not is_trusted_source:
        return False, 0.0, f"thin_content:{wc}words"
    if wc < 10 and title_has_cve:
        return False, 0.0, f"thin_content_cve:{wc}words"

    score, reason, strong_count = score_article(title, content)

    if score < THRESHOLD:
        return False, score, f"low_relevance({score:.1f}):{reason}"

    min_signals = 1 if (title_has_cve or is_trusted_source) else MIN_STRONG_SIGNAL_COUNT
    if strong_count < min_signals:
        return False, score, f"insufficient_threat_signals({strong_count}<{min_signals}):{reason}"

    return True, score, reason
