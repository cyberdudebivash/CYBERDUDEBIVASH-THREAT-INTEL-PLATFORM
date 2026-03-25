#!/usr/bin/env python3
"""
quality_gate.py — CyberDudeBivash® SENTINEL APEX v22.0 (INTELLIGENCE INTEGRITY ENGINE)
========================================================================================
PERMANENT FIX: Complete rewrite of content relevance gate.

v22.0 CHANGES (permanent fixes for report credibility):
  1. Raised THRESHOLD from 3.5 → 6.0 — only genuine threats pass
  2. Added PRODUCT_NEWS_PHRASES instant-fail list — Google/MS announcements blocked
  3. Added POSITIVE_FEATURE_SIGNALS — "safer", "will make", "introducing" = instant fail
  4. Requires MIN_THREAT_SIGNALS >= 2 strong signals to pass (not just score)
  5. Added ANDROID_SECURITY_FEATURE_PATTERNS — blocks feature announcements disguised as threats
  6. MIN_WORDS raised 60 → 80

NON-BREAKING: If import fails, sentinel_blogger.py continues as before.
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
    # ── v22.0 NEW: Product / Feature announcement signals ──────────────────
    "will make":           -5.0,  "makes it easier":     -5.0,  "making it safer":   -6.0,
    "will be safer":       -6.0,  "safer than":          -5.0,  "more secure than":  -4.0,
    "introducing":         -4.0,  "rolling out":         -4.0,  "launching":         -4.0,
    "feature announcement":-7.0,  "new feature":         -5.0,  "now available":     -4.0,
    "google announces":    -6.0,  "apple announces":     -6.0,  "microsoft releases":-5.0,
    "android update":      -4.0,  "android feature":     -6.0,  "ios update":        -4.0,
    "sideloading safer":   -8.0,  "advanced flow":       -6.0,
    "week in security":    -5.0,  "security roundup":    -5.0,  "security news":     -3.0,
    "lock and code":       -5.0,  "podcast":             -4.0,
}

# ── INSTANT FAIL — any of these = immediate rejection ────────────────────────
INSTANT_FAIL_PHRASES = [
    # Marketing content
    "new ebook", "download our ebook", "free webinar", "register for webinar",
    "product announcement", "we are hiring", "join our team", "open position",
    "soc analyst's playbook", "isn't going away. here's how",
    "here's how modern socs are fighting back",
    # ── v22.0 NEW: Feature / improvement announcements ──
    "will make android sideloading safer",
    "make android sideloading safer",
    "sideloading safer",
    "advanced flow will make",
    "week in security (",
    "lock and code s0",
    "a week in security",
    # Positive product news framing
    "safer for users",
    "improving security for",
    "security improvements in",
    "new security feature",
    "security feature rollout",
    # News roundups
    "this week in security",
    "security news roundup",
    "monthly security digest",
]

# ── v22.0 NEW: HARD TOPIC BLOCKLIST ─────────────────────────────────────────
# These topic patterns are NEVER threat intel regardless of score
HARD_BLOCKED_PATTERNS = [
    r'will make .{0,40} safer',        # "will make sideloading safer"
    r'makes .{0,40} more secure',      # "makes Android more secure"
    r'introducing .{0,40} protection', # "introducing new protection"
    r'new .{0,40} security feature',   # "new Android security feature"
    r'week in security',               # Weekly roundups
    r'security podcast',               # Podcasts
    r'a week in',                      # Weekly summaries
    r'\badvanced flow\b',              # Google's Advanced Flow feature
]

# Minimum score to process
THRESHOLD = 6.0

# Minimum words in combined content
# v75.1 NOTE: This is the RSS-summary word count, NOT the fetched article word count.
# Premium tier-1 sources (BleepingComputer, Dark Reading, SecurityWeek, TheRecord etc.)
# return RSS excerpts of only 20-40 words. Those sources are checked by TRUSTED_SOURCES.
MIN_WORDS = 80

# Trusted tier-1 sources — bypass MIN_WORDS gate entirely and let source_fetcher
# retrieve the full article. These sources NEVER publish low-quality content.
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

# ── v22.0: Minimum strong signals required (prevents score gaming) ───────────
# A story must have at least 2 strong threat signals (score >= 2.5 each)
# This prevents a story with many weak signals from sneaking through
MIN_STRONG_SIGNAL_COUNT = 2
STRONG_SIGNAL_THRESHOLD = 2.5


def score_article(title: str, content: str) -> Tuple[float, str, int]:
    """
    Score article for threat intelligence relevance.
    Returns (score, reason, strong_signal_count).
    """
    text = f"{title} {content}".lower()

    # Hard blocked patterns (regex)
    for pattern in HARD_BLOCKED_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return -15.0, f"hard_blocked:'{pattern[:40]}'", 0

    # Instant fail check
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

    # CVE bonus — real CVE = high-confidence threat
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    if cves:
        bonus = min(len(cves) * 2.5, 10.0)
        score += bonus
        strong_signal_count += len(cves)
        hits.append(f"+{bonus}[{len(cves)}CVEs]")

    # Hash bonus (confirmed IOCs = real threat)
    if re.search(r'\b[a-fA-F0-9]{64}\b', text):
        score += 5.0
        strong_signal_count += 1
        hits.append("+5.0[sha256_ioc]")
    elif re.search(r'\b[a-fA-F0-9]{32}\b', text):
        score += 3.0
        strong_signal_count += 1
        hits.append("+3.0[md5_ioc]")

    # IP address bonus (network IOCs = real threat)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    real_ips = [ip for ip in ips if not any(
        ip.startswith(p) for p in ['10.', '192.168.', '127.', '172.16.']
    )]
    if len(real_ips) >= 3:
        score += 3.0
        strong_signal_count += 1
        hits.append(f"+3.0[{len(real_ips)}real_IPs]")

    # v22.0: "Google/Apple/Microsoft will" → heavy penalty
    if re.search(r'\b(google|apple|microsoft|android|ios)\b.{0,30}\b(will|is|has|have)\b.{0,40}\b(safer|secure|protect|better)\b', text):
        score -= 8.0
        hits.append("-8.0[vendor_improvement_news]")

    reason = f"score={score:.1f} strong_signals={strong_signal_count} top={' '.join(hits[:4])}"
    return score, reason, strong_signal_count


def is_relevant_threat(title: str, content: str, source_url: str = "") -> Tuple[bool, float, str]:
    """
    Gate function. Returns (should_process, score, reason).

    v75.1 UPGRADE: Three-tier word-count logic:
      1. Trusted tier-1 sources bypass MIN_WORDS entirely — full article fetched downstream
      2. CVE-titled entries bypass MIN_WORDS — short CVE advisories are always real intel
      3. All others: require MIN_WORDS=80

    v22.0: Requires BOTH score >= THRESHOLD AND >= MIN_STRONG_SIGNAL_COUNT strong signals.
    """
    wc = len(content.split())

    # v75.1: Trusted tier-1 source bypass — don't gate on RSS excerpt length
    is_trusted_source = False
    if source_url:
        try:
            from urllib.parse import urlparse
            domain = urlparse(source_url).netloc.replace("www.", "").lower()
            is_trusted_source = any(t in domain for t in TRUSTED_SOURCES)
        except Exception:
            pass

    # v75.0: CVE bypass — always real intel regardless of word count
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
