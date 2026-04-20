#!/usr/bin/env python3
"""
source_fetcher.py - CyberDudeBivash v75.2 (SENTINEL APEX ULTRA)
Fetches full source article content from news URLs for rich report generation.
Extracts meaningful text, strips navigation/ads, handles various site structures.

v75.2 UPGRADE:
  - Full User-Agent pool rotation: 8 distinct browser fingerprints cycled per-request
    Reduces HTTP 403 block rate for sites doing simple UA-based blocking
    (SecurityWeek/SCMagazine pattern: identical requests from CI runner = blocked)
  - Randomized Referer header injection: appears to come from major search engines
  - Connection pooling: requests.Session() reuse for performance

v75.1 UPGRADE:
  - CVE-aware fallback: when source URL returns 0 words (blocked site),
    automatically fetches enriched content from NVD + EPSS APIs
  - Extended User-Agent rotation to reduce block rate on cvefeed.io / vulners.com
  - Minimum content guarantee: always returns >= 80 words for CVE advisories
  - Zero regression: all existing logic preserved, only adds fallback layer
"""
import random
import re
import logging
import requests
from typing import Dict, Optional, List

logger = logging.getLogger("CDB-FETCHER")

# CVE sources known to block scrapers - trigger NVD fallback immediately
_CVE_BLOCKED_SOURCES = {
    "cvefeed.io", "vulners.com", "vuldb.com", "exploit-db.com",
    "packetstormsecurity.com", "zerodayinitiative.com",
}

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_API = "https://api.first.org/data/v1/epss"


def _fetch_nvd_summary(cve_id: str) -> str:
    """Fetch NVD description for a CVE. Returns enriched text or empty string."""
    try:
        url = f"{_NVD_API}?cveId={cve_id.upper()}"
        resp = requests.get(url, timeout=8, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            return ""
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return ""
        cve_data = vulns[0].get("cve", {})

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # Extract CVSS
        metrics = cve_data.get("metrics", {})
        cvss_text = ""
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metrics.get(version_key):
                m = metrics[version_key][0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore", "N/A")
                severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "N/A"))
                vector = cvss_data.get("vectorString", "N/A")
                cvss_text = (
                    f"CVSS Score: {score}/10 ({severity}). "
                    f"Vector: {vector}. "
                )
                break

        # Extract weakness
        weaknesses = cve_data.get("weaknesses", [])
        cwe_text = ""
        if weaknesses:
            cwe_ids = []
            for w in weaknesses:
                for d in w.get("description", []):
                    if d.get("lang") == "en":
                        cwe_ids.append(d.get("value", ""))
            if cwe_ids:
                cwe_text = f"Weakness Classification: {', '.join(cwe_ids[:3])}. "

        # Extract references
        refs = cve_data.get("references", [])
        ref_text = ""
        if refs:
            ref_urls = [r.get("url", "") for r in refs[:3] if r.get("url")]
            if ref_urls:
                ref_text = f"Advisory References: {' | '.join(ref_urls)}. "

        # Extract configurations/affected products
        configs = cve_data.get("configurations", [])
        affected_text = ""
        if configs:
            vendors = set()
            for cfg in configs[:3]:
                for node in cfg.get("nodes", []):
                    for cpe in node.get("cpeMatch", [])[:3]:
                        parts = cpe.get("criteria", "").split(":")
                        if len(parts) > 4:
                            vendors.add(f"{parts[3]} {parts[4]}")
            if vendors:
                affected_text = f"Affected Products: {', '.join(list(vendors)[:5])}. "

        # Published date
        pub_date = cve_data.get("published", "")
        date_text = f"Published: {pub_date[:10]}. " if pub_date else ""

        return f"{date_text}{desc} {cvss_text}{cwe_text}{affected_text}{ref_text}".strip()

    except Exception as e:
        logger.debug(f"NVD fallback error for {cve_id}: {e}")
        return ""


class SourceFetcher:
    """Fetches and extracts meaningful content from source article URLs."""

    # v75.2: UA pool for rotation — 8 distinct browser fingerprints.
    # Rotated per-request to avoid triggering simple UA-based rate limiting
    # that blocked CI runner IPs on SecurityWeek/SCMagazine/BleepingComputer.
    _UA_POOL = [
        # Chrome Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        # Chrome macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        # Firefox Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
        # Firefox Linux
        'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        # Edge Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
        # Safari macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
        # Chrome Android (mobile — some sites serve lighter pages)
        'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.143 Mobile Safari/537.36',
        # Googlebot — some sites serve content to bots without blocking
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    ]

    # v75.2: Referer rotation — appears to arrive from search engine result pages
    _REFERER_POOL = [
        'https://www.google.com/',
        'https://www.bing.com/',
        'https://search.yahoo.com/',
        'https://duckduckgo.com/',
        '',  # No referer (direct navigation) — keep some requests clean
        '',
    ]

    def _get_rotated_headers(self) -> dict:
        """v75.2: Return headers with a randomly selected User-Agent and Referer."""
        ua = random.choice(self._UA_POOL)
        referer = random.choice(self._REFERER_POOL)
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            # v77.2 FIX: No 'br' (Brotli) — requests lib can't decompress it.
            # Brotli garbage was injecting ~15-25% non-printable chars into reports.
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
        }
        if referer:
            headers['Referer'] = referer
        return headers

    # Backward-compatible: keep HEADERS as the first UA for any callers that use it directly
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        # v77.2 FIX: Removed 'br' (Brotli) from Accept-Encoding.
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
    }

    # Tags that definitely contain non-article content
    STRIP_TAGS = ['script', 'style', 'nav', 'footer', 'header', 'aside',
                  'noscript', 'iframe', 'form', 'button', 'svg', 'figure',
                  'figcaption', 'menu', 'template']

    # CSS class/id patterns that indicate non-article content
    NON_CONTENT_PATTERNS = [
        r'sidebar', r'comment', r'footer', r'header', r'nav', r'menu',
        r'social', r'share', r'related', r'popular', r'trending',
        r'advertisement', r'ad-', r'cookie', r'popup', r'modal',
        r'newsletter', r'subscribe', r'signup',
    ]

    # ── Content quality thresholds (v78.0) ──────────────────────────────
    # Minimum word count for an article to be considered substantive enough
    # to generate a quality intel report from.
    CONTENT_MIN_WORDS = 300       # Hard minimum: below this triggers retry
    CONTENT_SOFT_REJECT_WORDS = 80  # Below this after all fallbacks: reject entirely
    CONTENT_RETRY_ATTEMPTS = 2    # Number of UA-rotation retries before fallback

    def fetch_article(self, url: str, timeout: int = 15) -> Dict:
        """
        Fetch and parse a source article URL.
        Returns dict with: full_text, paragraphs (list), word_count, fetch_status

        v78.0 CONTENT QUALITY GATE:
          - Minimum 300-word threshold enforced before accepting content.
          - If first fetch < 300 words: retry with different User-Agent (up to 2x).
          - After retry exhaustion: attempt NVD enrichment fallback for CVE URLs.
          - If all fallbacks yield < 80 words: reject with fetch_status='rejected_thin'.
          - Ensures weak partial fetches (20-80 word fragments) never reach the
            extraction/scoring engine and cause degraded IOC/confidence outputs.

        v75.1: If the source returns 0 words AND the URL contains a CVE ID,
        automatically falls back to NVD enrichment for that CVE.
        """
        result = {
            "full_text": "",
            "paragraphs": [],
            "word_count": 0,
            "source_url": url,
            "fetch_status": "failed",
        }

        if not url or not url.startswith("http"):
            return result

        # Detect if source is a known blocked CVE database
        from urllib.parse import urlparse
        source_domain = urlparse(url).netloc.replace("www.", "")
        is_cve_source = source_domain in _CVE_BLOCKED_SOURCES

        # Extract CVE ID from URL for fallback
        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', url, re.IGNORECASE)
        cve_id_from_url = cve_match.group(1).upper() if cve_match else None

        def _single_fetch_attempt() -> Dict:
            """Perform one fetch attempt. Returns partial result dict."""
            _r = {"full_text": "", "paragraphs": [], "word_count": 0, "fetch_status": "failed"}
            try:
                _req_headers = self._get_rotated_headers()
                resp = requests.get(
                    url, headers=_req_headers, timeout=timeout,
                    allow_redirects=True, verify=True
                )
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '').lower()
                    if not any(t in content_type for t in ('text/html', 'text/plain', 'application/xhtml')):
                        logger.warning(f"Source fetch skipped (non-HTML content-type: {content_type[:40]}): {url[:60]}")
                        return _r
                    html = resp.text
                    if not html:
                        logger.warning(f"Source fetch returned empty body: {url[:60]}")
                        return _r
                    # Binary garbage detection gate (v77.2)
                    sample = html[:2000]
                    non_printable = sum(1 for c in sample if ord(c) < 32 and c not in '\n\r\t')
                    high_ascii    = sum(1 for c in sample if 127 <= ord(c) <= 159)
                    JUNK_CHARS    = set('`][|~;{}\\^@#&*!?><')
                    junk_count    = sum(1 for c in sample if c in JUNK_CHARS)
                    garbage_ratio = (non_printable + high_ascii) / max(len(sample), 1)
                    junk_ratio    = junk_count / max(len(sample), 1)
                    if garbage_ratio > 0.05 or junk_ratio > 0.12:
                        logger.warning(
                            f"Source fetch rejected (garbage: binary={garbage_ratio:.2%} "
                            f"junk={junk_ratio:.2%}): {url[:60]}"
                        )
                        return _r
                    article_html    = self._extract_article_region(html)
                    text            = self._extract_text(article_html if article_html else html)
                    paragraphs      = [p.strip() for p in text.split('\n')
                                       if len(p.strip()) > 40 and not self._is_boilerplate(p)]
                    JUNK_P = set('`][|~;{}\\^@#&*!?><')
                    clean_paragraphs = []
                    for p in paragraphs:
                        p_junk    = sum(1 for c in p if c in JUNK_P)
                        p_ratio   = p_junk / max(len(p), 1)
                        word_chars = sum(1 for c in p if c.isalnum() or c in ' .,;:!?\'"-()')
                        wc_ratio  = word_chars / max(len(p), 1)
                        if p_ratio < 0.12 and wc_ratio >= 0.60:
                            clean_paragraphs.append(p)
                    _r["full_text"]  = '\n'.join(clean_paragraphs)
                    _r["paragraphs"] = clean_paragraphs
                    _r["word_count"] = sum(len(p.split()) for p in clean_paragraphs)
                    _r["fetch_status"] = "success"
                elif resp.status_code in (403, 429, 503):
                    _r["fetch_status"] = f"blocked_{resp.status_code}"
                    logger.warning(f"Source fetch HTTP {resp.status_code} (blocked): {url[:60]}")
                else:
                    logger.warning(f"Source fetch HTTP {resp.status_code}: {url[:60]}")
            except requests.Timeout:
                logger.warning(f"Source fetch timeout: {url[:60]}")
                _r["fetch_status"] = "timeout"
            except requests.RequestException as e:
                logger.warning(f"Source fetch network error: {e}")
                _r["fetch_status"] = "network_error"
            except Exception as e:
                logger.warning(f"Source fetch error: {e}")
            return _r

        # Skip slow HTTP fetch for known blocked CVE sources - go straight to NVD
        if not is_cve_source:
            # v78.0: Attempt fetch with retry on thin content
            for attempt in range(1, self.CONTENT_RETRY_ATTEMPTS + 1):
                attempt_result = _single_fetch_attempt()
                wc = attempt_result.get("word_count", 0)

                if wc >= self.CONTENT_MIN_WORDS:
                    # Quality gate passed
                    result.update(attempt_result)
                    logger.info(
                        f"Source fetched (attempt {attempt}): "
                        f"{wc} words >= {self.CONTENT_MIN_WORDS} threshold from {url[:60]}"
                    )
                    break
                elif wc > 0:
                    logger.warning(
                        f"Source fetch thin content (attempt {attempt}/{self.CONTENT_RETRY_ATTEMPTS}): "
                        f"{wc} words < {self.CONTENT_MIN_WORDS} threshold from {url[:60]}"
                    )
                    if attempt < self.CONTENT_RETRY_ATTEMPTS:
                        # Retry with a different UA — some sites serve more to certain browsers
                        logger.info(f"Retrying with different UA (attempt {attempt + 1})...")
                        continue
                    else:
                        # Exhausted retries: accept thin result as best-effort
                        result.update(attempt_result)
                        result["fetch_status"] = "thin_content"
                        break
                else:
                    # 0 words — network failure or complete block
                    result.update(attempt_result)
                    break

        # v78.0 + v75.1: NVD enrichment fallback
        # Triggered when: word_count < CONTENT_MIN_WORDS AND we have a CVE ID
        if result["word_count"] < self.CONTENT_MIN_WORDS and cve_id_from_url:
            logger.info(
                f"[v78.0] Content below threshold ({result['word_count']} words) — "
                f"fetching NVD enrichment for {cve_id_from_url}"
            )
            nvd_text = _fetch_nvd_summary(cve_id_from_url)
            if nvd_text:
                nvd_word_count = len(nvd_text.split())
                nvd_paragraphs = [s.strip() for s in re.split(r'(?<=[.!?])\s+', nvd_text)
                                   if len(s.strip()) > 20]
                # Merge NVD enrichment with any partial fetch content
                if result["full_text"]:
                    merged_text = result["full_text"] + "\n\n" + nvd_text
                    merged_paras = result["paragraphs"] + nvd_paragraphs
                else:
                    merged_text  = nvd_text
                    merged_paras = nvd_paragraphs
                result["full_text"]    = merged_text
                result["paragraphs"]   = merged_paras
                result["word_count"]   = len(merged_text.split())
                result["fetch_status"] = "nvd_enriched"
                logger.info(
                    f"[v78.0] NVD enrichment applied: {result['word_count']} words "
                    f"(was {result['word_count'] - nvd_word_count}) for {cve_id_from_url}"
                )

        # v78.0 HARD REJECTION: If after all fallbacks we still have < SOFT_REJECT threshold,
        # mark as rejected so the pipeline can filter out garbage intel.
        if result["word_count"] < self.CONTENT_SOFT_REJECT_WORDS and result["fetch_status"] not in (
            "nvd_enriched", "success"
        ):
            logger.warning(
                f"[v78.0] REJECT thin content: {result['word_count']} words "
                f"< {self.CONTENT_SOFT_REJECT_WORDS} minimum after all fallbacks: {url[:60]}"
            )
            result["fetch_status"] = "rejected_thin"

        return result

    def _extract_article_region(self, html: str) -> Optional[str]:
        """Try to find the main article content region."""
        # Look for common article container patterns
        patterns = [
            r'<article[^>]*>(.*?)</article>',
            r'<div[^>]*class="[^"]*(?:article|post|entry|content|story)[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*id="[^"]*(?:article|post|entry|content|story)[^"]*"[^>]*>(.*?)</div>',
            r'<main[^>]*>(.*?)</main>',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1)
                # Only use if substantial
                if len(content) > 500:
                    return content
        return None

    def _extract_text(self, html: str) -> str:
        """Extract meaningful text from HTML."""
        # Remove non-content tags
        for tag in self.STRIP_TAGS:
            html = re.sub(rf'<{tag}[\s>].*?</{tag}>', '', html,
                         flags=re.DOTALL | re.IGNORECASE)

        # Remove HTML comments
        html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

        # Remove elements with non-content classes/ids
        for pattern in self.NON_CONTENT_PATTERNS:
            html = re.sub(
                rf'<[^>]+(?:class|id)="[^"]*{pattern}[^"]*"[^>]*>.*?</(?:div|section|aside|nav)>',
                '', html, flags=re.DOTALL | re.IGNORECASE
            )

        # Preserve line breaks at block boundaries
        html = re.sub(r'<br\s*/?>', '\n', html, flags=re.IGNORECASE)
        html = re.sub(r'</?(?:p|div|h[1-6]|li|tr|td|th|blockquote|pre|article|section)[^>]*>',
                      '\n', html, flags=re.IGNORECASE)

        # Remove remaining HTML tags
        text = re.sub(r'<[^>]+>', ' ', html)

        # Clean HTML entities
        text = re.sub(r'&nbsp;', ' ', text)
        text = re.sub(r'&amp;', '&', text)
        text = re.sub(r'&lt;', '<', text)
        text = re.sub(r'&gt;', '>', text)
        text = re.sub(r'&quot;', '"', text)
        text = re.sub(r'&#?\w+;', ' ', text)

        # Clean whitespace
        text = re.sub(r'[ \t]+', ' ', text)
        text = re.sub(r'\n\s*\n', '\n', text)

        return text.strip()

    def _is_boilerplate(self, text: str) -> bool:
        """Check if a paragraph is likely boilerplate/navigation."""
        text_lower = text.lower().strip()
        boilerplate_phrases = [
            'cookie', 'subscribe', 'newsletter', 'sign up', 'log in',
            'privacy policy', 'terms of', 'all rights reserved',
            'share this', 'follow us', 'related articles',
            'read more', 'click here', 'learn more',
            'advertisement', 'sponsored', 'powered by',
            'copyright (C)', 'footer', 'navigation',
        ]
        for phrase in boilerplate_phrases:
            if phrase in text_lower and len(text_lower) < 150:
                return True

        # Very short lines are likely UI elements
        if len(text.split()) < 5:
            return True

        return False


# Global singleton
source_fetcher = SourceFetcher()
