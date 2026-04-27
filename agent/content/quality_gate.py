#!/usr/bin/env python3
"""
quality_gate.py - CyberDudeBivash(R) SENTINEL APEX v22.0 (INTELLIGENCE INTEGRITY ENGINE)
========================================================================================
PERMANENT FIX: Complete rewrite of content relevance gate.

v22.0 CHANGES (permanent fixes for report credibility):
  1. Raised THRESHOLD from 3.5 -> 6.0 - only genuine threats pass
  2. Added PRODUCT_NEWS_PHRASES instant-fail list - Google/MS announcements blocked
  3. Added POSITIVE_FEATURE_SIGNALS - "safer", "will make", "introducing" = instant fail
  4. Requires MIN_THREAT_SIGNALS >= 2 strong signals to pass (not just score)
  5. Added ANDROID_SECURITY_FEATURE_PATTERNS - blocks feature announcements disguised as threats
  6. MIN_WORDS raised 60 -> 80

NON-BREAKING: If import fails, sentinel_blogger.py continues as before.
"""

import re
import logging
from typing import Tuple

logger = logging.getLogger("CDB-QUALITY-GATE")

# -- STRONG THREAT INTEL SIGNALS ----------------------------------------------
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

# -- NOISE / NON-THREAT SIGNALS (NEGATIVE) ------------------------------------
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
    # -- v22.0 NEW: Product / Feature announcement signals ------------------
    "will make":           -5.0,  "makes it easier":     -5.0,  "making it safer":   -6.0,
    "will be safer":       -6.0,  "safer than":          -5.0,  "more secure than":  -4.0,
    "introducing":         -4.0,  "rolling out":         -4.0,  "launching":         -4.0,
    "feature announcement":-7.0,  "new feature":         -5.0,  "now available":     -4.0,
    "google announces":    -6.0,  "apple announces":     -6.0,  "microsoft releases":-5.0,
    "android update":      -4.0,  "android feature":     -6.0,  "ios update":        -4.0,
    "sideloading safer":   -8.0,  "advanced flow":       -6.0,
    "week in security":    -5.0,  "security roundup":    -5.0,  "security news":     -3.0,
    "lock and code":       -5.0,  "podcast":             -4.0,
    # v77.2: vendor award/marketing
    "infosec award":       -8.0,  "recognized for":      -6.0,  "award winner":      -7.0,
    "market leadership":   -7.0,  "innovation award":    -8.0,  "industry award":    -7.0,
    "cyber 150":           -6.0,  "fastest growing":     -6.0,
    # v142.1: advisory/educational content
    "steps for cisos":     -9.0,  "steps for security":  -7.0,  "for security teams":-5.0,
    "how to detect":       -5.0,  "detection that works":-7.0,  "how to prevent":    -5.0,
    "security tips":       -6.0,  "awareness training":  -8.0,  "security awareness":-7.0,
    "for defenders":       -5.0,  "defender's guide":    -7.0,  "ciso guide":        -7.0,
    "too powerful for":    -6.0,  "withheld from public":-6.0,
}

# -- INSTANT FAIL - any of these = immediate rejection ------------------------
INSTANT_FAIL_PHRASES = [
    # Marketing content
    "new ebook", "download our ebook", "free webinar", "register for webinar",
    "product announcement", "we are hiring", "join our team", "open position",
    "soc analyst's playbook", "isn't going away. here's how",
    "here's how modern socs are fighting back",
    # -- v22.0 NEW: Feature / improvement announcements --
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
    # v77.2: Vendor award/marketing articles - zero threat intel value
    "recognized for innovations",
    "recognized for market leadership",
    "global infosec awards",
    "innovation award",
    "industry award",
    "enters cyber 150",
    "fastest growing",
    "market leadership",
    # v142.1: Advisory/educational/CISO-guidance content -- zero operational intel value
    "steps for cisos",
    "steps for security teams",
    "steps for socs",
    "detection that works",
    "how phishing detection",
    "guide for security",
    "awareness training",
    "security awareness",
    "an ai tool too powerful",
    "too powerful for public release",
    "ai tool too powerful",
    "getting started with",
    "beginners guide",
    "beginner's guide",
    "complete guide to",
    "ultimate guide",
    "everything you need to know",
]

# -- v22.0 NEW: HARD TOPIC BLOCKLIST -----------------------------------------
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
    # v142.1: Advisory/CISO-guidance titles
    r'\d+\s+steps?\s+for\s+(cisos?|security|socs?|defenders?|teams?)',
    r'how\s+\w+\s+detection\s+(works?|that)',
    r'(what|why|how)\s+.{0,30}\s+(cisos?|security\s+teams?)\s+(should|need|must|can)',
    r'too powerful for (public release|release)',
]

# -- v142.1: URL PATH BLOCKLIST -----------------------------------------------
# Specific URL path patterns indicating marketing/advisory content.
BLOCKED_URL_PATHS = [
    "/cybersecurity-blog/phishing-detection",
    "/cybersecurity-blog/phishing-",
    "/blog/tips/",
    "/blog/how-to/",
    "/blog/guide/",
    "/blog/best-practices/",
    "/blog/news/",
    "cybersecurity-blog/",
]

# Minimum score to process
# v77.2 FIX: Lowered from 6.0 -> 4.5 - prevents blocking legitimate threats
# like "OpenAI AI Safety Bug Bounty" (score=4.0, 3 strong signals, APT keyword)
# while still filtering pure noise (score < 0)
THRESHOLD = 4.5

# Minimum words in combined content
# v142.0: Raised from 80 to 300 — enforce technical depth.
# Thin content (<300 words) is rejected as insufficient for enterprise-grade intel.
# Trusted tier-1 sources bypass this (they return RSS excerpts, full article fetched downstream).
# CVE-titled entries bypass this (short CVE advisories are always real intel).
MIN_WORDS = 300

# Trusted tier-1 sources - bypass MIN_WORDS gate entirely and let source_fetcher
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

# -- v22.0: Minimum strong signals required (prevents score gaming) -----------
# A story must have at least 2 strong threat signals (score >= 2.5 each)
# This prevents a story with many weak signals from sneaking through
MIN_STRONG_SIGNAL_COUNT = 2
STRONG_SIGNAL_THRESHOLD = 2.5




# ---------------------------------------------------------------------------
# v142.0 — TECHNICAL DEPTH SCORING (added to quality gate)
# ---------------------------------------------------------------------------
# Articles with genuine technical depth score higher. These signals reward
# primary research, vendor advisories, and exploit reports — the ONLY sources
# that belong in an enterprise threat intel platform.
TECHNICAL_DEPTH_SIGNALS = {
    # CVE / vulnerability specifics
    "cve-20":              2.0,   # Specific CVE year reference
    "cvss":                1.5,   # CVSS scoring present
    "cvss score":          2.0,
    "affected versions":   1.5,
    "patch available":     1.5,
    "proof-of-concept":    2.5,
    "proof of concept":    2.5,
    "poc":                 1.5,
    "exploit code":        2.5,
    "exploit public":      2.0,
    # Malware technical indicators
    "sha256":              3.0,   # File hash present
    "md5:":                2.5,
    "c2 ip":               2.5,
    "command and control": 2.0,
    "registry key":        2.0,
    "hkcu\\":            2.0,
    "hklm\\":            2.0,
    "process injection":   2.5,
    "dll injection":       2.5,
    "shellcode":           2.5,
    "packed with":         1.5,
    "yara rule":           2.0,
    "sigma rule":          2.0,
    "suricata":            1.5,
    # Network indicators
    "ip address":          1.5,
    "malicious domain":    2.0,
    "c2 domain":           2.5,
    "phishing domain":     2.0,
    # Execution chain
    "initial access":      2.0,
    "lateral movement":    2.0,
    "persistence mechanism": 2.0,
    "privilege escalation": 2.0,
    "exfiltration":        2.0,
    "defense evasion":     2.0,
    "credential dumping":  2.5,
    # Attribution quality
    "attributed to":       2.0,
    "linked to":           1.5,
    "identified as":       1.5,
    "threat actor":        2.0,
    "apt group":           2.5,
    # Industry primary research
    "analysis reveals":    1.5,
    "investigation found": 1.5,
    "technical analysis":  2.0,
    "reverse engineered":  2.5,
    "disassembly":         2.5,
    "decompiled":          2.0,
    "memory forensics":    2.5,
    "network capture":     2.0,
    "pcap":                2.0,
    "indicators of compromise": 2.5,
    "ioc list":            2.0,
}

# Technical depth score required to pass (on top of THRESHOLD)
# If tech_depth_score >= 3.0 → bonus +2.0 to main score (rewards primary research)
# If tech_depth_score < 1.0 AND score < 7.0 → thin-content penalty -1.5
TECH_DEPTH_BONUS_THRESHOLD = 3.0
TECH_DEPTH_BONUS = 2.0
TECH_DEPTH_THIN_THRESHOLD = 1.0
TECH_DEPTH_THIN_PENALTY = -1.5


def compute_technical_depth(text: str) -> float:
    """Score technical depth of content. Returns 0.0–20.0."""
    t = text.lower()
    return sum(w for sig, w in TECHNICAL_DEPTH_SIGNALS.items() if sig in t)

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

    # v142.0 — Technical depth bonus/penalty
    tech_depth = compute_technical_depth(text)
    if tech_depth >= TECH_DEPTH_BONUS_THRESHOLD:
        score += TECH_DEPTH_BONUS
        hits.append(f"+{TECH_DEPTH_BONUS}[tech_depth:{tech_depth:.1f}]")
    elif tech_depth < TECH_DEPTH_THIN_THRESHOLD and score < 7.0:
        score += TECH_DEPTH_THIN_PENALTY
        hits.append(f"{TECH_DEPTH_THIN_PENALTY}[thin_content:depth={tech_depth:.1f}]")

    # CVE bonus - real CVE = high-confidence threat
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

    # v22.0: "Google/Apple/Microsoft will" -> heavy penalty
    if re.search(r'\b(google|apple|microsoft|android|ios)\b.{0,30}\b(will|is|has|have)\b.{0,40}\b(safer|secure|protect|better)\b', text):
        score -= 8.0
        hits.append("-8.0[vendor_improvement_news]")

    reason = f"score={score:.1f} strong_signals={strong_signal_count} top={' '.join(hits[:4])}"
    return score, reason, strong_signal_count


# -- v78.0: Title-signal instant pass (ISSUE #6 FIX) ─────────────────────────
# Legitimate high-value threat intel articles often have thin RSS summaries
# but HIGHLY specific threat-signal titles. A title containing "malicious LNK"
# or "nation-state toolkit" is unambiguously threat intel regardless of summary length.
TITLE_INSTANT_PASS_SIGNALS = {
    "malicious lnk":       10.0,  "lnk file":            8.0,
    "zero-day":            10.0,  "zero day":             10.0,  "0-day": 10.0,
    "actively exploited":  10.0,  "exploited in the wild": 10.0,
    "ransomware attack":    9.0,  "wiper attack":          9.0,
    "supply chain attack":  9.0,  "supply chain compromise": 9.0,
    "backdoor":             8.0,  "infostealer":           8.0,
    "apt":                  7.0,  "nation-state":          9.0,  "state-sponsored": 9.0,
    "lazarus":              9.0,  "volt typhoon":          9.0,   "fancy bear": 9.0,
    "cobalt strike":        9.0,  "lockbit":               9.0,
    "data breach":          7.0,  "records exposed":       8.0,
    "remote code execution": 9.0, "rce":                   8.0,
    "authentication bypass": 9.0, "privilege escalation":  8.0,
    "rootkit":              9.0,  "spyware":               8.0,
    "toolkit":              6.0,  "exploit kit":           8.0,
    "indicators of compromise": 9.0, "ioc":               7.0,
    "hijack":               7.0,  "campaign":              5.0,
    "hidden":               5.0,  "covert":                6.0,
}
TITLE_INSTANT_PASS_THRESHOLD = 9.0  # Single strong signal or combined >= 9.0


def _score_title_signals(title: str) -> float:
    """v78.0: Score title against high-signal threat intel patterns."""
    title_lower = title.lower()
    total = 0.0
    for signal, weight in TITLE_INSTANT_PASS_SIGNALS.items():
        if signal in title_lower:
            total += weight
    return total


def is_relevant_threat(title: str, content: str, source_url: str = "") -> Tuple[bool, float, str]:
    """
    Gate function. Returns (should_process, score, reason).

    v78.0 UPGRADE: Title-signal instant pass (Issue #6 fix):
      0. [NEW] High-signal title bypasses thin-content gate entirely
    v75.1 UPGRADE: Three-tier word-count logic:
      1. Trusted tier-1 sources bypass MIN_WORDS entirely - full article fetched downstream
      2. CVE-titled entries bypass MIN_WORDS - short CVE advisories are always real intel
      3. All others: require MIN_WORDS=80

    v22.0: Requires BOTH score >= THRESHOLD AND >= MIN_STRONG_SIGNAL_COUNT strong signals.
    """
    wc = len(content.split())

    # v142.1: URL path block -- marketing/advisory blog paths regardless of domain
    if source_url:
        url_lower = source_url.lower()
        for blocked_path in BLOCKED_URL_PATHS:
            if blocked_path in url_lower:
                logger.info(
                    "[QUALITY-GATE] URL-path block (%s): %s", blocked_path[:40], title[:60]
                )
                return False, -10.0, f"blocked_url_path:{blocked_path}"

    # v78.0: Title-signal instant pass -- high-signal titles bypass thin-content gate
    title_signal_score = _score_title_signals(title)
    if title_signal_score >= TITLE_INSTANT_PASS_THRESHOLD:
        logger.info(f"[QUALITY-GATE] Title instant pass (score={title_signal_score:.0f}): {title[:60]}")
        return True, title_signal_score, f"title_instant_pass:{title_signal_score:.0f}"

    # v75.1: Trusted tier-1 source bypass - don't gate on RSS excerpt length
    # v142.1: Trusted source bypass does NOT override URL path blocks (checked above)
    is_trusted_source = False
    if source_url:
        try:
            from urllib.parse import urlparse
            domain = urlparse(source_url).netloc.replace("www.", "").lower()
            is_trusted_source = any(t in domain for t in TRUSTED_SOURCES)
        except Exception:
            pass

    # v75.0: CVE bypass - always real intel regardless of word count
    title_has_cve = bool(re.search(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE))

    if wc < MIN_WORDS and not title_has_cve and not is_trusted_source:
        return False, 0.0, f"thin_content:{wc}words"
    if wc < 10 and title_has_cve:
        return False, 0.0, f"thin_content_cve:{wc}words"

    score, reason, strong_count = score_article(title, content)

    if score < THRESHOLD:
        return False, score, f"low_relevance({score:.1f}):{reason}"

    # v142.1: Trusted sources need score >= THRESHOLD+1.5 to block advisory content
    if is_trusted_source and not title_has_cve:
        min_signals = 1
        trusted_threshold = THRESHOLD + 1.5
        if score < trusted_threshold:
            return False, score, f"trusted_source_low_score({score:.1f}<{trusted_threshold}):{reason}"
    else:
        min_signals = 1 if title_has_cve else MIN_STRONG_SIGNAL_COUNT

    if strong_count < min_signals:
        return False, score, f"insufficient_threat_signals({strong_count}<{min_signals}):{reason}"

    return True, score, reason
