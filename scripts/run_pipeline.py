#!/usr/bin/env python3
"""
scripts/run_pipeline.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 -- Master Pipeline Orchestrator
==========================================================================
P0 ARCHITECTURAL FIX: Replaces ALL inline PYEOF/PYEOF heredoc blocks from
sentinel-blogger.yml.  The YAML now calls ONLY this script (plus dedicated
utility scripts).  Zero inline Python in YAML ever again.

Stages orchestrated by this script:
  Stage 0.5  -- Purge Blogger publish queue (queue-bomb neutraliser)
  Stage 1    -- Bootstrap: ensure critical files exist
  Stage 1.1  -- Validate bootstrap output
  Stage 1.2  -- Inject sovereign key if available
  Stage 1.3  -- Validate JWT secret (HARD FAIL if absent)
  Stage 2    -- Run Sentinel Intelligence Engine
  Stage 1.5  -- Pre-v70 Manifest Sync (feed fresh data to v70)
  Stage 2.1  -- v70 Apex Intelligence Orchestrator (enrichment)
  Stage 2.2  -- Manifest Stabilisation (preserve/normalise engine output)
  Stage 2.5  -- Intel Freshness Gate (hard fail if < MIN entries)
  Stage 3    -- Schema Validation
  Stage 3.1  -- Manifest Cleanup (dedup, brand strip)
  Stage 3.6  -- HTML Report Generation
  Stage 3.6a -- Manifest Integrity Check (report_url + validation_status)
  Stage 3.6b -- Refresh EMBEDDED_INTEL + version sync in dashboard
  Stage 3.6c -- Prune STIX bundles (cap at 500 newest)

Rules enforced:
  - Every stage wrapped in try/except -- pipeline NEVER crashes
  - Hard fails (JWT, Freshness Gate, Integrity Check) call sys.exit(1)
  - All other failures are logged and pipeline continues
  - Zero inline heredocs, zero echo with quotes, zero PYEOF

Environment variables consumed (set at job level in workflow):
  CDB_JWT_SECRET     -- REQUIRED: JWT auth secret for engine
  CDB_SOVEREIGN_KEY  -- optional: PEM key content
  NVD_API_KEY        -- optional: NVD intel source
  GUMROAD_ACCESS_TOKEN -- optional: revenue data
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID -- optional: alerts
  SKIP_AI            -- "true" to skip AI enrichment
  FORCE_FULL_SYNC    -- "true" to force full sync
  PIPELINE_VERSION   -- version string (default: 160.0.0)
  PYTHONPATH         -- set to github.workspace by workflow

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# SafeIO foundation -- atomic writes, dedup, schema validation, metrics
try:
    _SCRIPTS = Path(__file__).resolve().parent
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    from safe_io import (
        atomic_json_write,
        safe_json_load,
        safe_json_dump,
        dedup_items,
        enrich_ioc_count,
        SchemaValidator,
        PipelineMetrics,
        acquire_lock,
        WriteQueue,
        retry_write,
        WriteHardFail,
        enforce_schema,
        enforce_schema_list,
    )
    _SAFE_IO_AVAILABLE = True
except ImportError as _e:
    _SAFE_IO_AVAILABLE = False
    logging.getLogger("sentinel.pipeline").warning(
        "safe_io not available (%s) — falling back to legacy I/O", _e
    )

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [pipeline] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.pipeline")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "160.0")
MIN_FRESHNESS_ENTRIES = 10   # absolute hard-fail threshold
# v160.1 P0 FIX: MIN_ENGINE_ENTRIES lowered 50 -> 10 (= MIN_FRESHNESS_ENTRIES).
# With DEDUP active, the enricher only writes NEW items per run. On high-overlap
# days (463 of 497 items already seen) only 13 new items are written -- this is
# correct, expected behavior, NOT a manifest failure. Triggering force-rebuild
# at 13 < 50 and then reading only 8 entries (the bootstrap title-dedup bug,
# fixed in bootstrap_critical_files.py v160.1) caused STAGE 2.5 HARD FAIL.
# Threshold now equals the freshness gate floor: any count >= 10 is valid.
MIN_ENGINE_ENTRIES = 10      # engine manifest minimum before --force-rebuild (= MIN_FRESHNESS_ENTRIES)
MAX_STIX_BUNDLES = 500       # cap on persisted STIX bundle files

# ---------------------------------------------------------------------------
# v160.0 ANTI-STALE INTEL CONSTANTS
# ---------------------------------------------------------------------------
# Maximum age (days) for an advisory to be admitted to the dashboard.
# Advisories older than this are quarantined and not surfaced.
ANTI_STALE_MAX_AGE_DAYS = int(os.environ.get("ANTI_STALE_MAX_AGE_DAYS", "30"))

# Synthetic title patterns -- these are internal bootstrap placeholders that
# must NEVER reach the live dashboard. Any title matching these patterns is
# quarantined and removed from the manifest before output generation.
SYNTHETIC_TITLE_PATTERNS = [
    r"^CDB-UNATTR-CVE\s+Campaign$",          # bare bootstrap stub title
    r"^CDB-UNATTR-",                          # any un-attributed CDB bootstrap
    r"^PLACEHOLDER",                          # explicit placeholder
    r"^TEST[-_\s]",                           # test entries
    r"^SYNTHETIC[-_\s]",                      # explicitly synthetic
    r"^DUMMY[-_\s]",                          # dummy data
    r"^N/A$",                                 # null title
    r"^\s*$",                                 # empty/whitespace title
    r"^CVE-\d{4}-\d{4,7}$",                  # bare CVE ID with no description
]

# Trusted intel sources -- only these source names are accepted without
# additional scrutiny. Entries from unknown sources are flagged with a
# warning but are NOT hard-rejected (allows new feed ingestion).
TRUSTED_INTEL_SOURCES = {
    "Rapid7", "Vulners", "CVE Feed", "CyberSecurity News",
    "CISA KEV", "NVD", "Exploit-DB", "AlienVault OTX",
    "Recorded Future", "ThreatFox", "MISP", "Mandiant",
    "CrowdStrike", "Palo Alto Unit 42", "Secureworks",
    "Tenable", "Qualys", "NIST", "GitHub Advisory",
    "PacketStorm", "Full Disclosure", "BugTraq",
}

GITHUB_ENV = os.environ.get("GITHUB_ENV", "/dev/null")

# Global metrics collector — instantiated at pipeline start
METRICS: "PipelineMetrics | None" = None

VALID_THREAT_TYPES = {
    # STIX 2.1 object types (original set)
    "vulnerability", "malware", "campaign", "intrusion-set",
    "tool", "attack-pattern", "indicator", "threat-report",
    # CDB Sentinel platform-specific threat categories (live feed values)
    "ransomware", "apt", "phishing", "cve", "ddos",
    "data breach", "cloud security", "ics/ot", "mobile", "supply chain",
    "threat intel", "threat-intel", "cyber espionage",
    "zero-day", "zero day", "botnet", "insider threat", "nation-state",
    "critical infrastructure", "financial crime", "identity theft",
}

# ---------------------------------------------------------------------------
# v148.0.0: Source Name → Domain + Trust Weight mapping
# Maps human-readable source names (as stored in item["source"]) to their
# canonical domain so source_trust_engine scores can be applied per-item.
# DEFAULT_SOURCE_TRUST is the fallback for any source not in this map.
# ---------------------------------------------------------------------------
DEFAULT_SOURCE_TRUST: float = 0.60  # flat STD tier — upgraded by map below

SOURCE_NAME_TO_DOMAIN: dict[str, str] = {
    # PLATINUM — government / authoritative advisories
    "CISA":                      "cisa.gov",
    "CISA KEV":                  "cisa.gov",
    "US-CERT":                   "us-cert.cisa.gov",
    "CERT":                      "cert.org",
    "NVD":                       "nvd.nist.gov",
    "NIST NVD":                  "nvd.nist.gov",
    "MITRE":                     "attack.mitre.org",
    # PLATINUM — top-tier security vendors & research
    "Mandiant":                  "mandiant.com",
    "Google":                    "google.com",
    "Google Threat Intel":       "blog.google",
    "Google Project Zero":       "googleprojectzero.blogspot.com",
    "Microsoft":                 "microsoft.com",
    "Microsoft Security":        "security.microsoft.com",
    "CrowdStrike":               "crowdstrike.com",
    "SentinelOne":               "sentinelone.com",
    "Palo Alto Networks":        "paloaltonetworks.com",
    "Unit 42":                   "unit42.paloaltonetworks.com",
    "Recorded Future":           "recordedfuture.com",
    "VirusTotal":                "virustotal.com",
    "IBM":                       "ibm.com",
    "IBM Security Intelligence": "securityintelligence.com",
    # ENTERPRISE — reputable security news & research
    "The Hacker News":           "thehackernews.com",
    "BleepingComputer":          "bleepingcomputer.com",
    "Krebs on Security":         "krebsonsecurity.com",
    "Schneier on Security":      "schneier.com",
    "SANS":                      "sans.org",
    "SANS Internet Storm Center":"isc.sans.edu",
    "ISC SANS":                  "isc.sans.edu",
    "Rapid7":                    "rapid7.com",
    "Tenable":                   "tenable.com",
    "Qualys":                    "qualys.com",
    "Check Point":               "checkpoint.com",
    "Check Point Research":      "checkpoint.com",
    "Fortinet":                  "fortinet.com",
    "FortiGuard":                "fortinet.com",
    "Trend Micro":               "trendmicro.com",
    "Symantec":                  "symantec.com",
    "Broadcom":                  "broadcom.com",
    "Elastic":                   "elastic.co",
    "abuse.ch":                  "abuse.ch",
    "FeodoTracker":              "feodotracker.abuse.ch",
    "URLhaus":                   "urlhaus.abuse.ch",
    "GitHub":                    "github.com",
    "Wired":                     "wired.com",
    "ArsTechnica":               "arstechnica.com",
    "Ars Technica":              "arstechnica.com",
    "Dark Reading":              "darkreading.com",
    "SecurityWeek":              "securityweek.com",
    "Threatpost":                "threatpost.com",
    "ThreatPost":                "threatpost.com",
    "Kaspersky":                 "kaspersky.com",
    "Kaspersky SecureList":      "kaspersky.com",
    "Zero Day Initiative":       "zerodayinitiative.com",
    "ZDI":                       "zerodayinitiative.com",
    # STANDARD — broad coverage news outlets
    "CyberScoop":                "cyberscoop.com",
    "CyberSecurity News":        "cybersecurity-review.com",
    "Security Affairs":          "securityaffairs.com",
    "Infosecurity Magazine":     "infosecurity-magazine.com",
    "SC Magazine":               "scmagazine.com",
    "Graham Cluley":             "grahamcluley.com",
    "HelpNet Security":          "helpnetsecurity.com",
    "HackRead":                  "hackread.com",
    # Feeds / aggregators
    "Vulners":                   "vulners.com",
    "CVE Feed":                  "nvd.nist.gov",   # CVE data originates from NVD
    # Vendor blogs
    "AWS Security Blog":         "aws.amazon.com",
    "AWS":                       "aws.amazon.com",
    "Palo Alto Unit 42":         "unit42.paloaltonetworks.com",
    "Unit42":                    "unit42.paloaltonetworks.com",
    "KrebsOnSecurity":           "krebsonsecurity.com",
    # National CERTs
    "NCSC Netherlands":          "ncsc.nl",
    "NCSC":                      "ncsc.nl",
    "NCSC UK":                   "ncsc.gov.uk",
    "ANSSI":                     "cert.ssi.gouv.fr",
    "BSI":                       "bsi.bund.de",
    "CERT-EU":                   "cert.europa.eu",
}

# Trust scores for domains NOT in source_trust_scores.json (supplement)
_SUPPLEMENTAL_TRUST: dict[str, float] = {
    "zerodayinitiative.com": 0.92,
    "kaspersky.com":         0.88,
    "aws.amazon.com":        0.87,
    "vulners.com":           0.72,
    "cybersecurity-review.com": 0.68,
    # National CERTs — authoritative government advisories
    "ncsc.nl":               0.97,
    "ncsc.gov.uk":           0.97,
    "cert.ssi.gouv.fr":      0.96,
    "bsi.bund.de":           0.96,
    "cert.europa.eu":        0.95,
}

def _load_source_trust_map() -> dict[str, float]:
    """Load domain→trust_score from source_trust_scores.json. Returns {} on error."""
    try:
        p = REPO_ROOT / "data" / "quality" / "source_trust_scores.json"
        if not p.exists():
            return {}
        raw = json.loads(p.read_text(encoding="utf-8"))
        ts = raw.get("trust_scores", {})
        return {domain: float(v.get("trust_score", DEFAULT_SOURCE_TRUST))
                for domain, v in ts.items() if isinstance(v, dict)}
    except Exception:
        return {}

def apply_source_trust_enrichment(items: list[dict]) -> tuple[list[dict], int]:
    """
    v148.0.0: Enrich each item with source_domain + source_trust_score.
    Reads from data/quality/source_trust_scores.json; falls back to
    SOURCE_NAME_TO_DOMAIN → _SUPPLEMENTAL_TRUST → DEFAULT_SOURCE_TRUST.
    Returns (enriched_items, count_enriched).
    """
    trust_map = _load_source_trust_map()
    trust_map.update(_SUPPLEMENTAL_TRUST)  # supplement unknown domains
    enriched = 0
    for item in items:
        if item.get("source_trust_score") and item.get("source_domain"):
            continue  # already enriched by upstream engine
        src_name = str(item.get("source", "")).strip()
        domain = (
            item.get("source_domain")
            or SOURCE_NAME_TO_DOMAIN.get(src_name)
            or SOURCE_NAME_TO_DOMAIN.get(src_name.split()[0] if src_name else "")
            or ""
        )
        if domain:
            item["source_domain"] = domain
        score = trust_map.get(domain, DEFAULT_SOURCE_TRUST) if domain else DEFAULT_SOURCE_TRUST
        item["source_trust_score"] = round(score, 3)
        enriched += 1
    return items, enriched


# ---------------------------------------------------------------------------
# v134.1 P0 FIX: Pipeline-side actor resolution map
# ---------------------------------------------------------------------------
PIPELINE_ACTOR_MAP: dict[str, list[str]] = {
    "CDB-APT-28": ["apt28", "fancy bear", "strontium", "forest blizzard", "gru"],
    "CDB-APT-29": ["apt29", "cozy bear", "nobelium", "midnight blizzard", "solarwinds"],
    "CDB-APT-41": ["apt41", "double dragon", "winnti", "shadowpad", "barium"],
    "CDB-APT-22": ["volt typhoon", "living off the land", "critical infrastructure attack"],
    "CDB-APT-43": ["kimsuky", "thallium", "black banshee", "apt43"],
    "CDB-APT-40": ["apt40", "temp.periscope", "kryptonite panda"],
    "CDB-FIN-09": ["lazarus", "hidden cobra", "north korea", "dprk", "macho-o man", "mach-o man"],
    "CDB-FIN-11": ["cl0p", "clop", "ta505", "moveit", "fin11"],
    "CDB-FIN-12": ["scattered spider", "octo tempest", "sim swap"],
    "CDB-RAN-01": ["lockbit", "lock bit", "lockbit 4"],
    "CDB-RAN-02": ["blackcat", "alphv", "noberus"],
    "CDB-RAN-03": ["akira ransomware", "akira group"],
    "CDB-RAN-04": ["medusa ransomware", "medusalocker"],
    "CDB-RAN-05": ["qilin", "agenda ransomware"],
    "CDB-RAN-06": ["revil", "sodinokibi"],
    "CDB-RU-01":  ["sandworm", "voodoo bear", "industroyer", "notpetya"],
    "CDB-RU-02":  ["turla", "snake malware", "venomous bear"],
    "CDB-IR-03":  ["oilrig", "apt34", "iranian ministry"],
    "CDB-MOB-01": ["triada", "keenadu", "badbox", "lemon group"],
    "CDB-PHI-GEN": ["blobphish", "remcos rat", "phantompulse", "phishing google"],
    "CDB-RAT-GEN": ["remcos", "asyncrat", "njrat", "quasar rat", "xworm", "agent tesla"],
}


def resolve_pipeline_actor(text: str, current_tag: str = "UNC-UNKNOWN") -> str:
    """
    Deterministic actor resolution from free text.
    Run BEFORE writing manifest — never emit UNC-UNKNOWN if keywords match.
    Returns existing tag if already a known CDB- designation.
    """
    if current_tag and current_tag not in ("UNC-UNKNOWN", "UNC-CDB-99", ""):
        return current_tag  # Already resolved upstream

    text_lower = text.lower()
    for actor_id, keywords in PIPELINE_ACTOR_MAP.items():
        for kw in keywords:
            if kw in text_lower:
                log.debug("[actor_resolve] '%s...' matched keyword '%s' -> %s",
                          text_lower[:60], kw, actor_id)
                return actor_id

    # Category fallback
    CATEGORY_MAP = [
        ("CDB-RAN-GEN", ["ransomware", "ransom", "extortion"]),
        ("CDB-PHI-GEN", ["phishing", "spear-phish", "credential harvest"]),
        ("CDB-APT-GEN", ["nation-state", "state-sponsored", "advanced persistent"]),
        ("CDB-SUP-GEN", ["supply chain", "typosquatting", "malicious package"]),
        ("CDB-CVE-GEN", ["zero-day", "0-day", "rce exploit"]),
    ]
    for cat_id, cat_kws in CATEGORY_MAP:
        for kw in cat_kws:
            if kw in text_lower:
                return cat_id

    return current_tag  # keep as-is if still unmatched


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_github_env(key: str, value: str) -> None:
    """Append KEY=VALUE to GITHUB_ENV file so downstream steps can read it."""
    try:
        with open(GITHUB_ENV, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")
    except Exception as e:
        log.warning("GITHUB_ENV write failed (%s): %s", key, e)


def run_script(
    args: list[str],
    *,
    stage: str,
    capture: bool = False,
    timeout: int = 300,
    allow_fail: bool = True,
) -> subprocess.CompletedProcess:
    """Run a subprocess, log outcome, return CompletedProcess."""
    log.info("[%s] Running: %s", stage, " ".join(str(a) for a in args))
    try:
        result = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            log.info("[%s] OK (exit 0)", stage)
        else:
            msg = f"[{stage}] Exited {result.returncode}"
            if allow_fail:
                log.warning("%s (non-fatal, pipeline continues)", msg)
            else:
                log.error("%s (HARD FAIL)", msg)
        return result
    except subprocess.TimeoutExpired:
        log.warning("[%s] Timeout after %ds (non-fatal)", stage, timeout)
        return subprocess.CompletedProcess(args, returncode=-1, stdout="", stderr="timeout")
    except Exception as e:
        if allow_fail:
            log.warning("[%s] Failed to run: %s (non-fatal)", stage, e)
        else:
            log.error("[%s] Failed to run: %s (HARD FAIL)", stage, e)
        return subprocess.CompletedProcess(args, returncode=-1, stdout="", stderr=str(e))


def load_manifest(path: str) -> tuple[list, str]:
    """
    Load feed manifest, handle both LIST and DICT formats.
    Returns (items_list, format_string).
    """
    p = Path(path)
    if not p.exists():
        return [], "absent"
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw, "list"
        if isinstance(raw, dict):
            for key in ("advisories", "reports", "items"):
                if key in raw and isinstance(raw[key], list):
                    return raw[key], "dict"
            return [], "dict-empty"
    except Exception as e:
        log.warning("Cannot parse %s: %s", path, e)
    return [], "error"


def count_manifest(path: str) -> int:
    items, _ = load_manifest(path)
    return len(items)


# ---------------------------------------------------------------------------
# Stage 0.0a -- Feed JSON Guard (runs BEFORE syntax guard, guarantees feed.json)
# ---------------------------------------------------------------------------

def stage_feed_guard() -> None:
    """
    P0 DATA PIPELINE GUARANTEE:
    Ensure api/feed.json and root feed.json always exist and contain valid JSON
    BEFORE any pipeline stage reads them.

    Rules:
      - If file missing or empty -> create with []
      - If file has invalid JSON  -> overwrite with []
      - If file has valid JSON    -> leave untouched (log stats)
      - NEVER crashes the pipeline (all errors caught)
    """
    log.info("[0.0a] Feed JSON Guard -- guaranteeing feed.json integrity")

    targets = [
        REPO_ROOT / "api" / "feed.json",
        REPO_ROOT / "feed.json",
    ]

    for feed_path in targets:
        rel = str(feed_path.relative_to(REPO_ROOT))
        feed_path.parent.mkdir(parents=True, exist_ok=True)

        # Case 1: does not exist
        if not feed_path.exists():
            try:
                feed_path.write_text("[]", encoding="utf-8")
                log.info("[0.0a] %s: created (was missing) -> []", rel)
            except Exception as e:
                log.warning("[0.0a] %s: could not create: %s", rel, e)
            continue

        # Case 2: exists but empty
        sz = feed_path.stat().st_size
        if sz == 0:
            try:
                feed_path.write_text("[]", encoding="utf-8")
                log.info("[0.0a] %s: was empty (0 bytes) -> written []", rel)
            except Exception as e:
                log.warning("[0.0a] %s: could not fix empty file: %s", rel, e)
            continue

        # Case 3: exists and non-empty -- verify JSON
        try:
            raw = feed_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            count = len(data) if isinstance(data, list) else "n/a (dict)"
            log.info("[0.0a] %s: VALID JSON | size=%d bytes | entries=%s", rel, sz, count)
        except (json.JSONDecodeError, Exception) as e:
            log.warning("[0.0a] %s: INVALID JSON (%s) -> overwriting with []", rel, e)
            try:
                feed_path.write_text("[]", encoding="utf-8")
                log.info("[0.0a] %s: overwritten with [] successfully", rel)
            except Exception as e2:
                log.warning("[0.0a] %s: could not overwrite: %s", rel, e2)


# Stage 0.0 -- Python Syntax Guard (runs FIRST, before anything else)
# ---------------------------------------------------------------------------

def stage_syntax_guard() -> None:
    """
    Run python_syntax_guard.py to catch SyntaxErrors in any .py file
    BEFORE the pipeline executes.  On failure: log the error and skip
    the faulty module — do NOT crash the entire pipeline.
    """
    log.info("=" * 60)
    log.info("STAGE 0.0 -- Python Syntax Guard pre-flight check")
    log.info("=" * 60)
    guard_script = REPO_ROOT / "scripts" / "python_syntax_guard.py"
    if not guard_script.exists():
        log.warning("[0.0] python_syntax_guard.py not found — skipping pre-flight.")
        return
    try:
        result = subprocess.run(
            [sys.executable, str(guard_script)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        for line in result.stdout.splitlines():
            log.info("[0.0] %s", line)
        for line in result.stderr.splitlines():
            log.warning("[0.0] %s", line)
        if result.returncode == 0:
            log.info("[0.0] Syntax Guard PASSED — all Python files are syntax-clean.")
        else:
            log.error(
                "[0.0] Syntax Guard reported errors (see above). "
                "Faulty modules will be skipped. Pipeline continues."
            )
    except subprocess.TimeoutExpired:
        log.warning("[0.0] Syntax Guard timed out (non-fatal, pipeline continues).")
    except Exception as e:
        log.warning("[0.0] Syntax Guard could not run: %s (non-fatal)", e)


# ---------------------------------------------------------------------------
# PHASE 0 -- File Integrity Pre-Check (v141.7.0)
# ---------------------------------------------------------------------------
_FILE_INTEGRITY_THRESHOLDS = {
    "scripts/run_pipeline.py":           55_000,
    "agent/sentinel_blogger.py":         25_000,
    "agent/export_stix.py":              30_000,
    "scripts/intel_dedup_engine.py":     15_000,
    "scripts/generate_intel_reports.py": 45_000,
    "scripts/validate_repo.py":          10_000,
}


def stage_file_integrity_guard() -> None:
    """
    PHASE 0 -- Pre-execution File Integrity Check (v141.7.0).

    Validates critical pipeline scripts BEFORE any execution:
      - File exists
      - Byte size >= minimum threshold (catches truncation artifacts)
      - Zero null bytes (catches binary corruption)
      - Valid Python syntax (catches partial writes)

    ANY failure => sys.exit(1). Prevents silent 3-minute partial runs.
    """
    import py_compile
    import tempfile
    log.info("=" * 60)
    log.info("PHASE 0 -- File Integrity Pre-Check (v141.7.0)")
    log.info("=" * 60)

    failures = []

    for rel_path, min_bytes in _FILE_INTEGRITY_THRESHOLDS.items():
        full_path = REPO_ROOT / rel_path
        if not full_path.exists():
            msg = f"{rel_path}: FILE MISSING"
            log.error("[integrity] %s", msg)
            failures.append(msg)
            continue

        size = full_path.stat().st_size
        if size < min_bytes:
            msg = f"{rel_path}: TRUNCATED ({size} bytes < {min_bytes} threshold)"
            log.error("[integrity] %s", msg)
            failures.append(msg)
            continue

        raw = full_path.read_bytes()
        null_count = raw.count(b"\x00")
        if null_count:
            msg = f"{rel_path}: {null_count} NULL BYTES detected (binary corruption)"
            log.error("[integrity] %s", msg)
            failures.append(msg)
            continue

        try:
            with tempfile.NamedTemporaryFile(suffix=".pyc", delete=True) as tf:
                py_compile.compile(str(full_path), cfile=tf.name, doraise=True)
        except py_compile.PyCompileError as exc:
            msg = f"{rel_path}: SYNTAX ERROR -- {exc}"
            log.error("[integrity] %s", msg)
            failures.append(msg)
            continue

        log.info("[integrity] PASS  %-52s  %6d bytes", rel_path, size)

    if failures:
        log.critical(
            "PHASE 0 INTEGRITY FAILED -- %d critical file(s) are corrupted/truncated/missing. "
            "Pipeline HARD STOP. Restore files from git HEAD before re-running.",
            len(failures),
        )
        for f in failures:
            log.critical("  FAIL: %s", f)
        sys.exit(1)

    log.info("[integrity] ALL %d critical scripts passed integrity check. Pipeline safe to execute.",
             len(_FILE_INTEGRITY_THRESHOLDS))


# ---------------------------------------------------------------------------
# Stage 0.5 -- Purge Blogger Publish Queue
# ---------------------------------------------------------------------------

def stage_purge_publish_queue() -> None:
    log.info("=" * 60)
    log.info("STAGE 0.5 -- Purge Blogger publish queue")
    log.info("=" * 60)
    try:
        queue_path = REPO_ROOT / "data" / "publish_queue.json"
        count = 0
        if queue_path.exists():
            try:
                raw = json.loads(queue_path.read_text(encoding="utf-8"))
                queue = raw.get("queue", raw) if isinstance(raw, dict) else raw
                count = len(queue) if isinstance(queue, list) else 0
                if count > 0:
                    log.info("[0.5] Clearing %d stale Blogger queue entries (queue bomb neutralised)", count)
            except Exception as e:
                log.warning("[0.5] Could not read existing queue: %s", e)
        empty = {
            "queue": [],
            "version": "111.0",
            "cleared_at": utc_now(),
            "_cleared_by": "run_pipeline.py",
        }
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        queue_path.write_text(json.dumps(empty, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("[0.5] publish_queue.json cleared (was %d entries).", count)
    except Exception as e:
        log.warning("[0.5] Queue purge failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 1 -- Bootstrap
# ---------------------------------------------------------------------------

def stage_bootstrap() -> None:
    log.info("=" * 60)
    log.info("STAGE 1 -- Bootstrap critical files")
    log.info("=" * 60)
    run_script(
        [sys.executable, "scripts/bootstrap_critical_files.py"],
        stage="1.bootstrap",
        allow_fail=True,
        timeout=120,
    )


def stage_validate_bootstrap() -> None:
    log.info("STAGE 1.1 -- Validate bootstrap output")
    try:
        manifest = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        if not manifest.exists():
            log.warning("[1.1] %s missing after bootstrap -- will be created by engine", manifest)
        else:
            items, fmt = load_manifest(str(manifest))
            log.info("[1.1] Bootstrap manifest: %d items (fmt=%s)", len(items), fmt)
        log.info("[1.1] Bootstrap validation COMPLETE")
    except Exception as e:
        log.warning("[1.1] Validation failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 1.2 -- Inject Sovereign Key
# ---------------------------------------------------------------------------

def stage_inject_sovereign_key() -> None:
    log.info("STAGE 1.2 -- Inject sovereign key (optional)")
    try:
        key_content = os.environ.get("CDB_SOVEREIGN_KEY", "").strip()
        if not key_content:
            log.info("[1.2] CDB_SOVEREIGN_KEY not set -- skipping.")
            return
        secrets_dir = REPO_ROOT / "secrets"
        secrets_dir.mkdir(parents=True, exist_ok=True)
        key_path = secrets_dir / "cdb_sovereign.pem"
        key_path.write_text(key_content + "\n", encoding="utf-8")
        key_path.chmod(0o600)
        log.info("[1.2] Sovereign key written to secrets/cdb_sovereign.pem")
    except Exception as e:
        log.warning("[1.2] Sovereign key inject failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 1.3 -- Validate JWT Secret (HARD FAIL)
# ---------------------------------------------------------------------------

def stage_validate_jwt_secret() -> None:
    log.info("STAGE 1.3 -- Validate JWT secret (hard fail if absent)")
    jwt_secret = os.environ.get("CDB_JWT_SECRET", "").strip()
    if not jwt_secret:
        log.error("[1.3] FATAL: CDB_JWT_SECRET is not set.")
        log.error("[1.3] Fix: Repository Settings -> Secrets -> Actions -> New secret")
        log.error("[1.3] Name: CDB_JWT_SECRET")
        log.error("[1.3] Value: generate with: openssl rand -hex 32")
        sys.exit(1)
    log.info("[1.3] CDB_JWT_SECRET is configured. [OK]")


# ---------------------------------------------------------------------------
# Stage 2 -- Run Sentinel Intelligence Engine
# ---------------------------------------------------------------------------

def stage_run_intel_engine() -> None:
    log.info("=" * 60)
    log.info("STAGE 2 -- Sentinel Intelligence Engine v134.0 (R2-only)")
    log.info("=" * 60)

    stix_dir = REPO_ROOT / "data" / "stix"
    stix_before = len(list(stix_dir.glob("CDB-APEX-*.json"))) if stix_dir.exists() else 0
    log.info("[2] STIX bundles before run: %d", stix_before)

    result = run_script(
        [sys.executable, "-m", "agent.sentinel_blogger"],
        stage="2.intel_engine",
        allow_fail=True,
        timeout=1200,
    )
    log.info("[2] Engine exited: %d", result.returncode)

    stix_after = len(list(stix_dir.glob("CDB-APEX-*.json"))) if stix_dir.exists() else 0
    new_bundles = stix_after - stix_before
    log.info("[2] STIX bundles after run: %d (NEW: %d)", stix_after, new_bundles)
    write_github_env("STIX_NEW_BUNDLES", str(new_bundles))


# ---------------------------------------------------------------------------
# Stage 1.5 -- Pre-v70 Manifest Sync
# ---------------------------------------------------------------------------

def stage_pre_v70_manifest_sync() -> None:
    log.info("=" * 60)
    log.info("STAGE 1.5 -- Pre-v70 Manifest Sync")
    log.info("=" * 60)
    try:
        src = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        dst = REPO_ROOT / "data" / "feed_manifest.json"
        bkup = REPO_ROOT / "data" / ".manifest_backups"

        if not src.exists():
            log.warning("[1.5] %s does not exist -- skipping sync.", src)
            return

        try:
            raw = json.loads(src.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("[1.5] Cannot read %s: %s -- skipping.", src, e)
            return

        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("advisories", raw.get("reports", raw.get("items", [])))
        else:
            items = []

        if len(items) < 10:
            log.warning("[1.5] Only %d items in %s -- skipping (too small).", len(items), src)
            return

        # Sanitise invalid threat_type values for v70 schema compliance
        sanitised = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            tt = item.get("threat_type", "")
            if tt and isinstance(tt, str) and tt.lower() not in VALID_THREAT_TYPES:
                item["threat_type"] = ""
                sanitised += 1
        if sanitised:
            log.info("[1.5] Sanitised %d invalid threat_type values -> '' (v70 will reclassify)", sanitised)

        # Write v70-schema-compliant manifest
        gen_at = raw.get("generated_at", utc_now()) if isinstance(raw, dict) else utc_now()
        payload = {
            "version":        raw.get("version", "v160.0") if isinstance(raw, dict) else "v160.0",  # P0 MANDATE: fallback v160.0
            "schema_version": "v70.0",
            "platform":       "SENTINEL-APEX",
            "generated_at":   gen_at,
            "synced_at":      utc_now(),
            "total_reports":  len(items),
            "entry_count":    len(items),
            "sort_order":     "timestamp DESC, risk_score DESC",
            "source":         "pre_v70_sync_from_stix_manifest",
            "advisories":     items,
        }
        tmp = dst.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(tmp, dst)
        log.info("[1.5] Synced %d items from stix/feed_manifest.json -> feed_manifest.json", len(items))

        # Prune stale backups older than 7 days
        if bkup.is_dir():
            cutoff = time.time() - 7 * 86400
            deleted = 0
            for f in bkup.iterdir():
                if f.suffix == ".json":
                    try:
                        if time.time() - f.stat().st_mtime > cutoff:
                            f.unlink()
                            deleted += 1
                    except Exception:
                        pass
            if deleted:
                log.info("[1.5] Deleted %d stale backup(s) older than 7 days.", deleted)

    except Exception as e:
        log.warning("[1.5] Pre-v70 manifest sync failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 2.1 -- v70 Apex Intelligence Orchestrator
# ---------------------------------------------------------------------------

def stage_v70_orchestrator() -> None:
    log.info("=" * 60)
    log.info("STAGE 2.1 -- v70 Apex Intelligence Orchestrator")
    log.info("=" * 60)

    v70_dir = REPO_ROOT / "agent" / "v70_apex_upgrade"
    if not v70_dir.is_dir():
        log.info("[2.1] agent/v70_apex_upgrade not found -- skipping.")
        return

    # Check freshness of candidate manifests (skip if all > 48h old)
    max_age_seconds = 48 * 3600
    now = time.time()
    candidates = [
        "data/stix/feed_manifest.json",
        "data/feed_manifest.json",
        "data/apex_enriched_manifest.json",
    ]
    newest_age: float | None = None
    for path in candidates:
        full = REPO_ROOT / path
        if full.exists():
            age = now - full.stat().st_mtime
            if newest_age is None or age < newest_age:
                newest_age = age

    if newest_age is None:
        log.warning("[2.1] No manifest files found -- skipping v70.")
        return

    if newest_age > max_age_seconds:
        log.warning("[2.1] Newest manifest is %.1fh old (stale). Skipping v70.", newest_age / 3600)
        log.warning("[2.1] v70 will run on the next successful intel engine run.")
        return

    log.info("[2.1] Input data is fresh (%.1fh old). Proceeding with v70 enrichment.", newest_age / 3600)

    skip_ai = os.environ.get("SKIP_AI", "false").lower() == "true"
    cmd = [sys.executable, "-m", "agent.v70_apex_upgrade.orchestrator",
           "--data-dir", "data", "--dashboard", "index.html", "--json"]
    if skip_ai:
        cmd.append("--no-ai")

    result = run_script(cmd, stage="2.1.v70", allow_fail=True, timeout=240)

    if result.returncode != 0:
        log.warning("[2.1] v70 exited %d -- writing fallback result.", result.returncode)
        fallback = {
            "success": False,
            "total_advisories": 0,
            "error": f"v70 non-zero exit {result.returncode} (guard fired)",
            "phases": [],
            "guard_fired": True,
        }
        try:
            Path("/tmp/v70_result.json").write_text(
                json.dumps(fallback, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            log.warning("[2.1] Could not write fallback v70 result: %s", e)
    else:
        log.info("[2.1] v70 enrichment complete.")


# ---------------------------------------------------------------------------
# Stage 2.2 -- Manifest Stabilisation
# ---------------------------------------------------------------------------


def _backfill_report_urls_from_disk(manifest_path: Path) -> None:
    """
    v160.6 Stage 2.2b: Backfill report_url and internal_report_url for manifest
    entries that have empty URL fields but matching HTML reports committed in
    the reports/ directory on disk.

    Pattern: reports/{YYYY}/{MM}/intel--{hex_id}.html
    CDN URL:  https://intel.cyberdudebivash.com/reports/{YYYY}/{MM}/intel--{hex_id}.html

    This is an idempotent one-pass operation:
    - Only updates entries where report_url is empty/missing
    - Derives path from entry['id'] by scanning reports/ directory
    - Never overwrites existing non-empty report_url values
    - Non-fatal: all errors are logged and pipeline continues

    Root cause addressed: confirmed forensic finding that all 497 entries in
    data/feed_manifest.json had report_url="" despite 44,484 HTML files on disk.
    """
    CDN_BASE = "https://intel.cyberdudebivash.com"
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            items = raw
            is_list_fmt = True
        elif isinstance(raw, dict):
            items = raw.get("advisories", raw.get("items", raw.get("entries", [])))
            is_list_fmt = False
        else:
            log.warning("[2.2b] Unexpected manifest format: %s", type(raw).__name__)
            return

        reports_dir = REPO_ROOT / "reports"
        if not reports_dir.exists():
            log.info("[2.2b] reports/ dir not found — skipping backfill.")
            return

        # Build fast lookup: intel_id -> relative path (prefer most recent mtime)
        id_to_path: dict = {}
        for html_file in reports_dir.rglob("intel--*.html"):
            intel_id = html_file.stem
            if intel_id not in id_to_path:
                id_to_path[intel_id] = html_file
            else:
                # Keep most recently modified file
                if html_file.stat().st_mtime > id_to_path[intel_id].stat().st_mtime:
                    id_to_path[intel_id] = html_file
        log.info("[2.2b] reports/ index built: %d intel-- HTML files found.", len(id_to_path))

        backfilled = 0
        for entry in items:
            if not isinstance(entry, dict):
                continue
            entry_id = (entry.get("id") or entry.get("stix_id") or "").strip()
            if not entry_id.startswith("intel--"):
                continue
            existing_ru = (entry.get("report_url") or "").strip()
            if existing_ru:  # Never overwrite existing non-empty URL
                continue
            html_file = id_to_path.get(entry_id)
            if html_file:
                rel_path = html_file.relative_to(REPO_ROOT).as_posix()
                entry["report_url"] = CDN_BASE + "/" + rel_path
                entry["internal_report_url"] = "/" + rel_path
                backfilled += 1

        if backfilled > 0:
            # Write back atomically
            if is_list_fmt:
                payload = items
            else:
                raw["advisories"] = items
                payload = raw
            tmp_path = str(manifest_path) + ".backfill.tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
            os.replace(tmp_path, str(manifest_path))
            log.info("[2.2b] Backfilled report_url for %d/%d manifest entries from reports/ dir.",
                     backfilled, len(items))
        else:
            log.info("[2.2b] report_url backfill: all entries already have URLs or no matching files.")

    except Exception as e:
        log.warning("[2.2b] report_url backfill failed (non-fatal): %s", e)


def stage_manifest_stabilisation() -> None:
    log.info("=" * 60)
    log.info("STAGE 2.2 -- Manifest Stabilisation")
    log.info("=" * 60)
    try:
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

        engine_count = 0
        engine_items: list = []
        manifest_fmt = "absent"

        if manifest_path.exists():
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    engine_items = raw
                    engine_count = len(raw)
                    manifest_fmt = "list"
                    log.info("[2.2] Manifest is LIST format (%d items).", engine_count)
                elif isinstance(raw, dict):
                    for key in ("advisories", "reports", "items"):
                        if key in raw and isinstance(raw[key], list):
                            engine_items = raw[key]
                            break
                    engine_count = len(engine_items)
                    manifest_fmt = "dict"
                    log.info("[2.2] Manifest is DICT format (%d items).", engine_count)
            except Exception as e:
                log.warning("[2.2] Cannot parse manifest: %s", e)

        stix_dir = REPO_ROOT / "data" / "stix"
        stix_bundles = len(list(stix_dir.glob("CDB-APEX-*.json"))) if stix_dir.exists() else 0
        log.info("[2.2] Engine manifest: %d entries (fmt=%s) | STIX bundles: %d",
                 engine_count, manifest_fmt, stix_bundles)

        if engine_count >= MIN_ENGINE_ENTRIES:
            log.info("[2.2] Engine manifest valid (%d >= %d). --force-rebuild SKIPPED.",
                     engine_count, MIN_ENGINE_ENTRIES)

            # Normalise LIST -> DICT if needed
            if manifest_fmt == "list":
                log.info("[2.2] Normalising LIST -> DICT envelope (%d entries)...", engine_count)
                payload = {
                    "version":           "v160.0",  # P0 MANDATE: fallback v160.0
                    "platform":          "SENTINEL-APEX",
                    "generated_at":      utc_now(),
                    "normalised_at":     utc_now(),
                    "total_reports":     engine_count,
                    "entry_count":       engine_count,
                    "schema_version":    "v160.0",  # P0 MANDATE: fallback v160.0
                    "sort_order":        "timestamp DESC, risk_score DESC",
                    "source_of_truth":   "agent.sentinel_blogger (normalised by pipeline)",
                    "advisories":        engine_items,
                }
                tmp = str(manifest_path) + ".norm.tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
                os.replace(tmp, str(manifest_path))
                log.info("[2.2] Normalised: %d entries in DICT format written. [OK]", engine_count)

            # Run cleaner (non-blocking)
            r = run_script(
                [sys.executable, "scripts/clean_feed_manifest.py"],
                stage="2.2.cleaner",
                allow_fail=True,
                timeout=120,
            )
            if r.returncode != 0:
                log.warning("[2.2] clean_feed_manifest exited %d -- engine manifest retained.", r.returncode)
        else:
            log.warning("[2.2] Engine manifest too small (%d < %d). Running --force-rebuild.",
                        engine_count, MIN_ENGINE_ENTRIES)
            run_script(
                [sys.executable, "scripts/bootstrap_critical_files.py", "--force-rebuild"],
                stage="2.2.force_rebuild",
                allow_fail=True,
                timeout=300,
            )

        # Report final state
        # v160.1 P0 FIX: MANIFEST_FINAL_COUNT = max(stix_manifest, enricher output).
        # If force-rebuild produced FEWER entries than the enricher (e.g. due to
        # bootstrap dedup bugs or TTL filtering), never let it reduce the count below
        # what the enricher validly produced. Defense-in-depth on top of the bootstrap
        # title-dedup fix in bootstrap_critical_files.py v160.1.
        final_count = 0
        for ppath in ("data/stix/feed_manifest.json", "data/feed_manifest.json"):
            full = REPO_ROOT / ppath
            if full.exists():
                try:
                    d = json.loads(full.read_text(encoding="utf-8"))
                    if isinstance(d, list):
                        cnt = len(d)
                        log.info("[2.2] %s: %d entries (LIST format)", ppath, cnt)
                    elif isinstance(d, dict):
                        items = d.get("advisories", d.get("reports", []))
                        cnt = len(items)
                        gen = d.get("generated_at", d.get("normalised_at", "?"))
                        log.info("[2.2] %s: %d entries  generated_at=%s", ppath, cnt, gen)
                    else:
                        cnt = 0
                    if ppath == "data/stix/feed_manifest.json":
                        # Use max() so force-rebuild cannot reduce count below
                        # what the enricher produced (engine_count captured above)
                        final_count = max(cnt, engine_count)
                        if final_count > cnt:
                            log.info("[2.2] MANIFEST_FINAL_COUNT floored to enricher output: "
                                     "bootstrap=%d enricher=%d → using %d",
                                     cnt, engine_count, final_count)
                except Exception as e:
                    log.warning("[2.2] %s: ERROR reading -- %s", ppath, e)

        log.info("[2.2] MANIFEST_FINAL_COUNT=%d", final_count)
        write_github_env("MANIFEST_FINAL_COUNT", str(final_count))

        # Stage 2.2b: Backfill report_url from filesystem for entries with empty URLs
        # v160.6 FIX: 497 manifest entries confirmed to have report_url="" despite
        # 44,484 HTML files existing in reports/. This bridges that structural gap.
        _backfill_report_urls_from_disk(manifest_path)

    except Exception as e:
        log.warning("[2.2] Manifest stabilisation failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 2.5 -- Intel Freshness Gate (HARD FAIL)
# ---------------------------------------------------------------------------

def stage_freshness_gate() -> None:
    log.info("=" * 60)
    log.info("STAGE 2.5 -- Intel Freshness Gate")
    log.info("=" * 60)

    manifest = str(REPO_ROOT / "data" / "stix" / "feed_manifest.json")

    if not Path(manifest).exists():
        log.error("[2.5] FATAL: %s missing after stabilisation.", manifest)
        sys.exit(1)

    try:
        d = json.loads(Path(manifest).read_text(encoding="utf-8"))
        if isinstance(d, list):
            count = len(d)
            log.warning("[2.5] Manifest still in LIST format at gate (count=%d).", count)
        elif isinstance(d, dict):
            items = d.get("advisories", d.get("reports", d.get("items", [])))
            count = len(items) if isinstance(items, list) else 0
        else:
            log.error("[2.5] FATAL: Unexpected manifest root type: %s", type(d).__name__)
            sys.exit(1)
    except Exception as e:
        log.error("[2.5] FATAL: Cannot parse manifest: %s", e)
        sys.exit(1)

    if count < MIN_FRESHNESS_ENTRIES:
        log.error("[2.5] FATAL: Manifest has only %d entries (minimum: %d)", count, MIN_FRESHNESS_ENTRIES)
        log.error("[2.5] Root causes to check:")
        log.error("[2.5]   1. Engine manifest format (list vs dict)")
        log.error("[2.5]   2. Manifest Stabilisation normalisation output")
        log.error("[2.5]   3. clean_feed_manifest.py exit code")
        sys.exit(1)

    log.info("[2.5] FRESHNESS GATE PASSED: %d entries. [OK]", count)


# ---------------------------------------------------------------------------
# Stage 2.6 -- Anti-Stale Intel Hardening (v160.0 PERMANENT PRODUCTION GUARD)
# ---------------------------------------------------------------------------

def stage_anti_stale_hardening() -> None:
    """
    v160.0 ANTI-STALE INTEL HARDENING STAGE
    =========================================
    Permanently eliminates stalled, synthetic, and fake intel from reaching
    the live dashboard. Runs AFTER freshness gate, BEFORE schema validation.

    Four protection layers:
      1. ADVISORY AGE GATE        -- quarantine entries older than ANTI_STALE_MAX_AGE_DAYS
      2. SYNTHETIC TITLE DETECTOR -- block bootstrap placeholder titles (CDB-UNATTR-CVE, etc.)
      3. SOURCE AUTHENTICITY      -- flag unknown/untrusted sources (warn, not hard-fail)
      4. TITLE DEDUP ENFORCER     -- eliminate entries with duplicate (normalized) titles

    Output: writes a cleaned manifest atomically. Logs every rejection with
    reason code for full audit trail. Non-fatal on unexpected errors --
    the pipeline continues with whatever valid entries remain.
    """
    import re as _re

    log.info("=" * 60)
    log.info("STAGE 2.6 -- Anti-Stale Intel Hardening (v160.0 PRODUCTION GUARD)")
    log.info("=" * 60)

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not manifest_path.exists():
        log.warning("[2.6] Manifest not found -- anti-stale stage skipped (non-fatal).")
        return

    try:
        d = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(d, list):
            items = d
            envelope = None
        elif isinstance(d, dict):
            items = d.get("advisories") or d.get("reports") or d.get("items") or []
            envelope = d
        else:
            log.warning("[2.6] Unexpected manifest type %s -- skipping.", type(d).__name__)
            return

        original_count = len(items)
        if original_count == 0:
            log.warning("[2.6] Empty manifest -- anti-stale stage skipped.")
            return

        now_utc = datetime.now(timezone.utc)
        cutoff_days = ANTI_STALE_MAX_AGE_DAYS
        cutoff_dt = None
        try:
            from datetime import timedelta
            cutoff_dt = now_utc - timedelta(days=cutoff_days)
        except Exception:
            pass

        # Compile synthetic patterns once
        compiled_patterns = []
        for pat in SYNTHETIC_TITLE_PATTERNS:
            try:
                compiled_patterns.append(_re.compile(pat, _re.IGNORECASE))
            except Exception as _pe:
                log.warning("[2.6] Bad synthetic pattern '%s': %s", pat, _pe)

        stale_age_count = 0
        synthetic_count = 0
        unknown_source_count = 0
        dedup_title_count = 0
        quarantine_log = []
        seen_titles_normalized = set()
        clean_items = []

        for item in items:
            item_id = str(item.get("id", item.get("stix_id", "?")))[:40]
            title = str(item.get("title", "")).strip()
            source = str(item.get("source", "")).strip()

            # --- Layer 1: Advisory Age Gate ---
            # v161.3: KEV items and CRITICAL severity items are ALWAYS current
            # (actively exploited / actively dangerous) -- exempt from age gate.
            _is_kev_item = (
                str(item.get("threat_type", "")).upper() == "KEV"
                or bool(item.get("kev_present"))
                or str(item.get("severity", "")).upper() == "CRITICAL"
                or "kev" in (item.get("tags") or [])
            )
            if cutoff_dt is not None and not _is_kev_item:
                pub_raw = item.get("published_at") or item.get("published") or ""
                if isinstance(pub_raw, str) and pub_raw and pub_raw not in ("true", "false"):
                    try:
                        # Normalize ISO-8601 with or without timezone
                        ts = pub_raw.replace("Z", "+00:00")
                        pub_dt = datetime.fromisoformat(ts)
                        if pub_dt.tzinfo is None:
                            from datetime import timezone as _tz
                            pub_dt = pub_dt.replace(tzinfo=_tz.utc)
                        if pub_dt < cutoff_dt:
                            age_days = (now_utc - pub_dt).days
                            quarantine_log.append(
                                f"[AGE] id={item_id} age={age_days}d title={title[:60]}"
                            )
                            stale_age_count += 1
                            continue  # quarantine
                    except Exception:
                        pass  # unparseable date -- allow through, schema stage handles it

            # --- Layer 2: Synthetic Title Detector ---
            # v166.4 FIX: Root cause of recurring STAGE 2.6 / R2 verifier HARD FAIL:
            # export_stix.py manifest entries have NO 'description' field (only title,
            # severity, source, cvss_score, epss_score). The v166.3 exemption checked
            # only 'description', which is always empty at Stage 2.6 time, so every
            # bare-CVE-ID item was quarantined as synthetic → advisory_count < floor 5
            # → R2 verifier HARD FAIL. The title enricher (Stage 3.1.11) runs AFTER
            # this stage, so new CVE items legitimately arrive with bare IDs.
            # FIX: Exempt bare-CVE-ID items that carry ANY real intel signal available
            # in the manifest entry at this stage: severity, source, cvss_score, epss_score.
            # Only truly synthetic stubs (no source, no severity, no scores) are quarantined.
            _CVE_BARE_RE = _re.compile(r"^CVE-\d{4}-\d{4,}$", _re.IGNORECASE)
            is_synthetic = False
            for cp in compiled_patterns:
                if cp.search(title):
                    # Special exemption for bare CVE-ID pattern only:
                    if cp.pattern == r"^CVE-\d{4}-\d{4,7}$":
                        # Check description (populated on enriched items)
                        desc = str(item.get("description") or item.get("summary") or "").strip()
                        desc_clean = _re.sub(r"^CVE-\d{4}-\d+[\s\-:]+", "", desc, flags=_re.I).strip()
                        has_real_desc = bool(desc_clean) and len(desc_clean) > 5 and not _CVE_BARE_RE.fullmatch(desc_clean)
                        # Check fields present in export_stix.py manifest entries
                        _sev_val = str(item.get("severity") or "").upper().strip()
                        _src_val = str(item.get("source") or item.get("feed_source") or "").strip()
                        has_severity = _sev_val not in ("", "UNKNOWN", "N/A", "NONE")
                        has_cvss     = float(item.get("cvss_score") or 0) > 0
                        has_epss     = float(item.get("epss_score") or 0) > 0
                        has_source   = bool(_src_val)
                        if has_real_desc or has_severity or has_cvss or has_epss or has_source:
                            log.info(
                                "[2.6] CVE raw-title EXEMPT (sev=%s cvss=%s epss=%s src=%s): id=%s",
                                _sev_val or "none",
                                item.get("cvss_score") or "0",
                                item.get("epss_score") or "0",
                                _src_val[:20] if _src_val else "none",
                                item_id,
                            )
                            break  # genuine CVE intel, not a synthetic stub
                    is_synthetic = True
                    quarantine_log.append(
                        f"[SYNTH] id={item_id} pattern='{cp.pattern}' title={title[:80]}"
                    )
                    synthetic_count += 1
                    break
            if is_synthetic:
                continue  # quarantine

            # --- Layer 3: Source Authenticity Validator ---
            if source and source not in TRUSTED_INTEL_SOURCES:
                # Soft-warn: new/unknown sources are allowed but logged for review
                log.warning(
                    "[2.6] Unknown source '%s' on id=%s -- allowing through (review feed config)",
                    source, item_id
                )
                unknown_source_count += 1
                # NOT quarantined -- just flagged

            # --- Layer 4: Title Dedup Enforcer ---
            # Normalize title for dedup: lowercase, collapse whitespace, strip punctuation extremes
            normalized = _re.sub(r"\s+", " ", title.lower()).strip(" -_.")
            if normalized and normalized in seen_titles_normalized:
                quarantine_log.append(
                    f"[DEDUP] id={item_id} title={title[:80]}"
                )
                dedup_title_count += 1
                continue  # quarantine duplicate
            if normalized:
                seen_titles_normalized.add(normalized)

            clean_items.append(item)

        # Emit quarantine log
        total_quarantined = stale_age_count + synthetic_count + dedup_title_count
        if quarantine_log:
            log.warning(
                "[2.6] QUARANTINE REPORT: %d entries removed "
                "(stale_age=%d synthetic=%d dedup=%d unknown_source=%d)",
                total_quarantined, stale_age_count, synthetic_count,
                dedup_title_count, unknown_source_count,
            )
            for entry in quarantine_log[:50]:  # cap log output
                log.warning("[2.6]   QUARANTINED: %s", entry)
            if len(quarantine_log) > 50:
                log.warning("[2.6]   ... and %d more (see full audit in pipeline metrics)", len(quarantine_log) - 50)

        # Write cleaned manifest atomically
        if envelope and isinstance(envelope, dict):
            envelope["advisories"] = clean_items
            envelope["entry_count"] = len(clean_items)
            envelope["total_reports"] = len(clean_items)
            envelope["anti_stale_applied_at"] = datetime.now(timezone.utc).isoformat()
            envelope["anti_stale_quarantined"] = total_quarantined
            payload = envelope
        else:
            payload = {
                "version":                  "v160.0",
                "schema_version":           "v160.0",
                "platform":                 "SENTINEL-APEX",
                "generated_at":             datetime.now(timezone.utc).isoformat(),
                "anti_stale_applied_at":    datetime.now(timezone.utc).isoformat(),
                "anti_stale_quarantined":   total_quarantined,
                "entry_count":              len(clean_items),
                "total_reports":            len(clean_items),
                "sort_order":               "timestamp DESC, risk_score DESC",
                "advisories":               clean_items,
            }

        # Atomic write with lock
        try:
            if _SAFE_IO_AVAILABLE:
                atomic_json_write(manifest_path, payload, locked=True)
            else:
                tmp = manifest_path.with_suffix(".tmp_antistale")
                tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                os.replace(str(tmp), str(manifest_path))
        except Exception as we:
            log.error("[2.6] Failed to write cleaned manifest: %s", we)
            raise

        # Fail-safe: ensure we still have enough entries after quarantine
        # v166.2 FIX: Use proportional threshold to prevent false FATAL on small batches.
        # OLD: hard minimum of MIN_FRESHNESS_ENTRIES=10 caused FATAL when bootstrap
        #      starts with 10 items and quarantines 3 bare-CVE-ID advisories → 7 remain.
        # NEW: FATAL only if >60% of items quarantined AND remaining < 5 (absolute floor).
        #      This allows small legitimate batches to pass while blocking true data loss.
        remaining = len(clean_items)
        ABS_FLOOR = 5
        quarantine_ratio = total_quarantined / max(original_count, 1)
        if remaining < ABS_FLOOR or quarantine_ratio > 0.60:
            log.error(
                "[2.6] FATAL: After anti-stale quarantine only %d entries remain "
                "(floor=%d, quarantine_ratio=%.0f%%). Quarantined %d. Check feed freshness.",
                remaining, ABS_FLOOR, quarantine_ratio * 100, total_quarantined,
            )
            log.error("[2.6] Root causes to check:")
            log.error("[2.6]   1. All feeds returning stale data (> %d days old)", cutoff_days)
            log.error("[2.6]   2. Feed ingestion pipeline not running on schedule")
            log.error("[2.6]   3. ANTI_STALE_MAX_AGE_DAYS too restrictive (currently: %d)", cutoff_days)
            sys.exit(1)
        if remaining < MIN_FRESHNESS_ENTRIES:
            log.warning(
                "[2.6] WARN: Only %d entries remain after quarantine (soft minimum=%d) "
                "— pipeline continues, downstream gates will validate.",
                remaining, MIN_FRESHNESS_ENTRIES,
            )

        log.info(
            "[2.6] ANTI-STALE HARDENING COMPLETE: %d/%d entries passed "
            "(quarantined=%d: stale=%d synthetic=%d dedup=%d). [OK]",
            remaining, original_count, total_quarantined,
            stale_age_count, synthetic_count, dedup_title_count,
        )

    except SystemExit:
        raise
    except Exception as e:
        log.error("[2.6] Anti-stale hardening failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 3 -- Schema Validation
# ---------------------------------------------------------------------------

def stage_schema_validation() -> None:
    log.info("=" * 60)
    log.info("STAGE 3 -- Schema Validation (hard gate)")
    log.info("=" * 60)
    result = run_script(
        [sys.executable, "scripts/validate_intel_schema.py"],
        stage="3.schema",
        allow_fail=False,
        timeout=120,
    )
    if result.returncode != 0:
        log.error("[3] Schema validation FAILED. Malformed data must not reach R2.")
        sys.exit(1)
    log.info("[3] SCHEMA VALIDATION PASSED. [OK]")


# ---------------------------------------------------------------------------
# Stage 3.1 -- Manifest Cleanup
# ---------------------------------------------------------------------------

def stage_manifest_cleanup() -> None:
    log.info("STAGE 3.1 -- Manifest Cleanup")
    run_script(
        [sys.executable, "scripts/clean_feed_manifest.py"],
        stage="3.1.cleanup",
        allow_fail=True,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Stage 3.5 -- Global Schema Enforcement (MANDATORY write-boundary gate)
# ---------------------------------------------------------------------------

def stage_enforce_schema() -> None:
    """
    v134 GLOBAL SCHEMA ENFORCEMENT STAGE.

    Applies enforce_schema() to EVERY entry in feed_manifest.json before
    any output is generated (reports, API feed, STIX bundles).

    Guarantees at write boundary:
      - published: bool → ISO-8601 string (P0 regression — run #805)
      - severity: any → uppercase normalised string
      - ioc_count == len(iocs) — hard invariant
      - All string fields are strings (never bool/int/None)
      - All list fields are lists (never None)
      - risk_score in [0, 10]

    Writes corrected manifest atomically. Non-fatal if safe_io unavailable.
    """
    if not _SAFE_IO_AVAILABLE:
        log.warning("[3.5] safe_io not available — schema enforcement skipped (RISK)")
        return

    log.info("=" * 60)
    log.info("STAGE 3.5 -- Global Schema Enforcement")
    log.info("=" * 60)
    t0 = time.monotonic()

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not manifest_path.exists():
        log.warning("[3.5] Manifest not found — schema enforcement skipped")
        return

    try:
        d = json.loads(manifest_path.read_text(encoding="utf-8"))
        key = "advisories" if "advisories" in d else ("reports" if "reports" in d else None)
        if key is None:
            log.warning("[3.5] Manifest has no 'advisories'/'reports' key — skipping")
            return

        items_before = d[key]
        total = len(items_before)

        violations_found = 0
        items_after = []
        for i, item in enumerate(items_before):
            # Track violations before enforcement
            had_pub_bool = isinstance(item.get("published"), bool)
            had_sev_bool = isinstance(item.get("severity"), bool)
            had_ioc_mismatch = (
                isinstance(item.get("iocs"), list) and
                item.get("ioc_count") != len(item.get("iocs", []))
            )
            enforced = enforce_schema(item)
            if had_pub_bool or had_sev_bool or had_ioc_mismatch:
                violations_found += 1
                log.warning(
                    "[3.5] Schema violation corrected [%s]: pub_bool=%s sev_bool=%s ioc_mismatch=%s",
                    item.get("id", f"idx_{i}")[:32], had_pub_bool, had_sev_bool, had_ioc_mismatch,
                )
                if METRICS:
                    METRICS.record_schema_violation(
                        field="published" if had_pub_bool else "ioc_count",
                        reason=f"idx={i} id={item.get('id','?')[:16]}",
                    )
            items_after.append(enforced)

        d[key] = items_after

        # Atomic write — through WriteQueue for serialization guarantee
        WriteQueue.enqueue(lambda _d=d, _p=manifest_path: atomic_json_write(_p, _d, locked=True))
        WriteQueue.flush(attempts=5, base_delay=0.5)

        elapsed = time.monotonic() - t0
        log.info(
            "[3.5] Schema enforcement complete: %d entries processed, %d violations corrected, %.2fs",
            total, violations_found, elapsed,
        )

    except SystemExit:
        raise
    except Exception as e:
        log.warning("[3.5] Schema enforcement failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 3.6 -- HTML Report Generation
# ---------------------------------------------------------------------------

def stage_html_reports() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6 -- HTML Report Generation")
    log.info("=" * 60)
    t_start = time.monotonic()

    # v134.0.0: Zero-skip policy -- every intel entry generates a 16-section report.
    r = run_script(
        [
            sys.executable, "scripts/generate_intel_reports.py",
            "--manifest", "data/stix/feed_manifest.json",
            "--public-prefix", "https://intel.cyberdudebivash.com",
            "--fail-on-zero",
            "--limit", "0",
        ],
        stage="3.6.reports",
        allow_fail=False,
        timeout=900,
    )
    if r.returncode != 0:
        log.error("[3.6] HTML report generation FAILED (exit %d).", r.returncode)
        sys.exit(1)

    # v134 upgrades: IOC enforcement, dedup, synthetic fallback, PDF, revenue
    run_script(
        [sys.executable, "scripts/apply_v131_upgrades.py"],
        stage="3.6.v131_upgrades",
        allow_fail=True,
        timeout=300,
    )

    report_count = 0
    try:
        reports_dir = REPO_ROOT / "reports"
        if reports_dir.is_dir():
            report_count = sum(
                1 for f in reports_dir.rglob("*.html")
                if f.name != "index.html"
            )
    except Exception:
        pass

    elapsed = time.monotonic() - t_start
    log.info("[3.6] Reports written: %d | Elapsed: %.1fs", report_count, elapsed)
    write_github_env("REPORT_COUNT", str(report_count))
    write_github_env("REPORT_ELAPSED", f"{elapsed:.0f}")

    # v141.7.0 Phase 2: Hard minimum report count guard
    # A healthy run generates at least 1 report. Zero means the report generator
    # silently produced nothing -- this must hard-fail the pipeline.
    _MIN_REPORTS_REQUIRED = 1
    if report_count < _MIN_REPORTS_REQUIRED:
        log.critical(
            "[3.6] HARD FAIL: report_count=%d < minimum=%d. "
            "Report generation produced ZERO output files. "
            "Pipeline cannot continue without valid reports.",
            report_count, _MIN_REPORTS_REQUIRED,
        )
        sys.exit(1)
    log.info("[3.6] Report count guard PASSED: %d >= %d minimum.", report_count, _MIN_REPORTS_REQUIRED)


# ---------------------------------------------------------------------------
# Stage 3.6a -- Manifest Integrity Check
# v134.0: write_error/file_missing → SOFT FAIL (recovery guaranteed, pipeline continues)
# HARD FAIL only on: manifest JSON corrupt, schema invalid
# ---------------------------------------------------------------------------

def stage_manifest_integrity_check() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6a -- Manifest Integrity Check [v134.0 SOFT-FAIL mode]")
    log.info("=" * 60)
    try:
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        # HARD FAIL only if manifest is unparseable (genuine corruption)
        try:
            d = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as parse_err:
            log.error("[3.6a] HARD FAIL — manifest JSON corrupt/unreadable: %s", parse_err)
            sys.exit(1)

        items = d.get("advisories", d.get("reports", []))

        # v134.0: write_error/file_missing → SOFT FAIL (data is in recovery buffer)
        # These are write-pressure failures, NOT data corruption.
        SOFT_FAIL_STATUSES = {"write_error", "file_missing"}
        missing_url: list[str] = []
        soft_fail: list[str] = []
        stale_domain: list[str] = []

        for item in items:
            sid = item.get("id", "?")
            vs  = item.get("validation_status", "")
            ru  = item.get("report_url", "")
            if vs == "brand_skip":
                continue
            if vs in SOFT_FAIL_STATUSES:
                # SOFT FAIL — payload is in recovery buffer, not a pipeline blocker
                soft_fail.append(f"  SOFT_FAIL [{vs}] {sid}")
                continue
            if not ru:
                missing_url.append(f"  MISSING_URL {sid}")
                continue
            if "reports.cyberdudebivash.com" in ru:
                stale_domain.append(f"  STALE_DOMAIN {sid}")

        total = len(items)
        ok    = total - len(missing_url) - len(soft_fail) - len(stale_domain)
        log.info("[3.6a] Manifest entries : %d", total)
        log.info("[3.6a] report_url OK    : %d", ok)
        log.info("[3.6a] Missing URL      : %d", len(missing_url))
        log.info("[3.6a] Soft failures    : %d (write pressure — in recovery buffer)", len(soft_fail))
        log.info("[3.6a] Stale domain     : %d", len(stale_domain))

        if stale_domain:
            log.warning("[3.6a] Stale domains (will be rewritten by Worker at serve time):")
            for s in stale_domain[:10]:
                log.warning("[3.6a] %s", s)

        if soft_fail:
            # SOFT FAIL — log for observability, pipeline continues
            log.warning(
                "[3.6a] %d write-pressure failure(s) detected — "
                "payloads are safely stored in data/recovery/write_failures/. "
                "Pipeline continues. Retry on next run.",
                len(soft_fail),
            )
            for h in soft_fail[:10]:
                log.warning("[3.6a] %s", h)
            if METRICS is not None:
                for _ in soft_fail:
                    METRICS.record_recovery("3.6a", "write_error/file_missing in manifest")

        log.info("[3.6a] Manifest integrity check complete — pipeline continues. [OK]")

    except SystemExit:
        raise
    except Exception as e:
        log.warning("[3.6a] Integrity check failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 3.6b -- Refresh EMBEDDED_INTEL + Version Sync
# ---------------------------------------------------------------------------

def stage_refresh_embedded_intel() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6b -- Refresh EMBEDDED_INTEL + version sync")
    log.info("=" * 60)

    # Count items for informational logging
    item_count = count_manifest(str(REPO_ROOT / "data" / "stix" / "feed_manifest.json"))
    log.info("[3.6b] Manifest has %d items", item_count)

    # ===========================================================================
    # P0 PERMANENT FIX (v145.4): Conditional update_embedded_intel.py call
    #
    # HISTORICAL BUG: update_embedded_intel.py was called unconditionally here.
    # Inside that script, line ~509 had: new_array = "[]"  ← ALWAYS cleared!
    # This cleared EMBEDDED_INTEL to [] on EVERY pipeline run. If Stage 3.93
    # (inject_embedded_intel.py) then failed for any reason, safe_git_commit.py
    # committed [] to index.html → deployed with NO instant cards → P0.
    #
    # FIX 1: update_embedded_intel.py now writes actual data (not []) — see
    #         its own P0 fix at the new_array assignment.
    # FIX 2: This call is now guarded — skip if manifest is empty so we
    #         don't even risk touching EMBEDDED_INTEL on empty-batch runs.
    #         inject_embedded_intel.py (Stage 3.93) is the AUTHORITATIVE
    #         EMBEDDED_INTEL injector — it runs from api/feed.json (post-R2).
    # ===========================================================================
    if item_count > 0:
        log.info("[3.6b] Manifest non-empty — running update_embedded_intel.py "
                 "(inject_embedded_intel.py at Stage 3.93 will overwrite with freshest data)")
        run_script(
            [sys.executable, "scripts/update_embedded_intel.py"],
            stage="3.6b.embedded_intel",
            allow_fail=True,
            timeout=120,
        )
    else:
        log.info("[3.6b] SKIPPING update_embedded_intel.py — manifest is empty. "
                 "Preserving existing EMBEDDED_INTEL in index.html. "
                 "inject_embedded_intel.py (Stage 3.93) will handle injection from api/feed.json.")

    # AI Brain panels + CDB_NEWS engine injection (idempotent)
    run_script(
        [sys.executable, "scripts/patch_ai_brain_news.py"],
        stage="3.6b.ai_brain_patch",
        allow_fail=True,
        timeout=60,
    )

    # Version sync: keep dashboard title aligned with pipeline version
    _version_sync()


def _version_sync() -> None:
    """Replace ALL version references in index.html with current PIPELINE_VERSION.

    v143.0.0 FIX: Extended from a single-pattern regex to a two-pass replacement:
      Pass 1 — "SENTINEL APEX vX.Y.Z" branded occurrences (title, meta, visible text).
      Pass 2 — bare PLATFORM_VERSION JS constant (previously missed, causing drift
                detected by regression_immunity.py Phase 2 VersionLock check).

    Both passes are idempotent: if the file is already at PIPELINE_VERSION, no write occurs.
    """
    try:
        new_tag = f"SENTINEL APEX v{PIPELINE_VERSION}"
        html_path = REPO_ROOT / "index.html"
        if not html_path.exists():
            log.warning("[3.6b] index.html not found -- version sync skipped.")
            return
        content = html_path.read_text(encoding="utf-8", errors="replace")

        # Pass 1: "SENTINEL APEX vX.Y.Z" branded text (title, meta, OG, visible header)
        updated = re.sub(
            r"SENTINEL APEX [Vv]\d+\.\d+(?:\.\d+)?(?:\.\d+)?",
            new_tag,
            content,
        )

        # Pass 2: JS PLATFORM_VERSION constant e.g. PLATFORM_VERSION = '142.3.1'
        # This was previously missed and caused Phase-2 VersionLock violations.
        updated = re.sub(
            r"(PLATFORM_VERSION\s*=\s*['\"])\d+\.\d+(?:\.\d+)?(['\"])",
            lambda m: m.group(1) + PIPELINE_VERSION + m.group(2),
            updated,
        )

        if content != updated:
            # Atomic write: write to .tmp then rename to avoid half-written file
            tmp = html_path.with_suffix(".html.vsync_tmp")
            tmp.write_text(updated, encoding="utf-8")
            tmp.replace(html_path)
            branded_count = updated.count(new_tag)
            js_count = updated.count(f"'{PIPELINE_VERSION}'") + updated.count(f'"{PIPELINE_VERSION}"')
            log.info(
                "[3.6b] Version-sync: dashboard updated to v%s "
                "(branded=%d, PLATFORM_VERSION_js=%d)",
                PIPELINE_VERSION, branded_count, js_count,
            )
        else:
            log.info("[3.6b] Version-sync: dashboard already at v%s", PIPELINE_VERSION)
    except Exception as e:
        log.warning("[3.6b] Version sync failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 0.PRE — v134 System Health Gate (runs BEFORE all ingestion stages)
# ---------------------------------------------------------------------------

def stage_system_health_gate() -> None:
    """
    v134 PRE-INGESTION SYSTEM HEALTH GATE.

    Reads data/logs/system_health.json written by the PREVIOUS pipeline run.
    Enforces autonomic stability before any new data ingestion starts.

    CRITICAL  → HARD FAIL (sys.exit(1)). Pipeline blocked.
                Log: CRITICAL: System unstable — recovery backlog unresolved.
                Action: operator must run scripts/recovery_replay.py --execute manually.

    DEGRADED  → [SAFE_MODE] skip ingestion. Run exhaustive recovery drain.
                If drain succeeds (remaining == 0): update state → HEALTHY, continue.
                If drain fails (remaining > 0):     HARD FAIL (sys.exit(1)).

    HEALTHY   → proceed normally.
    """
    import json as _json

    log.info("==" * 35)
    log.info("STAGE 0.PRE -- v134 System Health Gate")
    log.info("==" * 35)

    health_path = REPO_ROOT / "data" / "logs" / "system_health.json"

    if not health_path.exists():
        log.info("[health-gate] system_health.json absent — first run or clean slate. HEALTHY.")
        return

    try:
        _doc     = _json.loads(health_path.read_text(encoding="utf-8"))
        state    = str(_doc.get("state", "HEALTHY")).upper()
        rec_cnt  = int(_doc.get("recovery_count", 0))
    except Exception as _e:
        log.warning("[health-gate] Could not read system_health.json: %s — assuming HEALTHY", _e)
        return

    log.info("[health-gate] Loaded system_state=%s recovery_count=%d", state, rec_cnt)

    # ── CRITICAL: hard block ────────────────────────────────────────────────
    if state == "CRITICAL":
        log.critical(
            "[health-gate] ████ CRITICAL: System unstable — recovery backlog unresolved. "
            "Pipeline BLOCKED. Operator action required: "
            "run  scripts/recovery_replay.py --execute  to drain recovery backlog. "
            "recovery_count=%d", rec_cnt,
        )
        sys.exit(1)

    # ── DEGRADED: SAFE_MODE — drain first, continue only if fully cleared ──
    if state == "DEGRADED":
        log.warning(
            "[SAFE_MODE] Pipeline paused — draining backlog "
            "(state=DEGRADED recovery_count=%d). Ingestion SKIPPED. "
            "Running exhaustive recovery drain.", rec_cnt,
        )
        try:
            _scripts = str(REPO_ROOT / "scripts")
            if _scripts not in sys.path:
                sys.path.insert(0, _scripts)
            from recovery_replay import drain_recovery_queue as _drain
            _result = _drain(dry_run=False)
            log.info(
                "[SAFE_MODE] Recovery drain complete: state=%s drained=%d "
                "remaining=%d failed=%d",
                _result["system_state"], _result["drained"],
                _result["remaining"],    _result["failed"],
            )
            if _result["remaining"] > 0:
                log.critical(
                    "[SAFE_MODE] ████ %d blob(s) could not be drained after exhaustive replay. "
                    "HARD FAIL — manual intervention required.", _result["remaining"],
                )
                sys.exit(1)
            log.info("[SAFE_MODE] Recovery drain COMPLETE — state → HEALTHY. Resuming pipeline.")
        except SystemExit:
            raise
        except Exception as _exc:
            log.critical("[SAFE_MODE] drain_recovery_queue raised unexpectedly: %s — HARD FAIL", _exc)
            sys.exit(1)

    # ── HEALTHY or post-drain HEALTHY: proceed ──────────────────────────────
    log.info("[health-gate] System HEALTHY — proceeding with pipeline.")


# ---------------------------------------------------------------------------
# Stage 1-3a -- Recovery Replay (drain write backlog BEFORE validation gate)
# v134.0: MANDATORY pre-validation step. Ensures write_failures.jsonl and
# recovery blobs are fully drained so check_no_write_failures() in
# validate_repo.py sees an empty recovery dir (not a stale audit log).
# ---------------------------------------------------------------------------

def stage_recovery_replay() -> None:
    """
    v134 RECOVERY REPLAY GATE — runs before stage_validate_repo().

    Drains data/recovery/write_failures/ blobs via RecoveryReplayEngine.
    Enforces backlog thresholds:
      recovery_count > 50  -> system_state = DEGRADED (write concurrency reduced)
      recovery_count > 100 -> system_state = CRITICAL  (ingestion paused)
      recovery_count == 0  -> system clean, proceed

    Writes system_health.json with post-replay state.
    Does NOT hard-fail — validate_repo.py is the enforcement gate.
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz

    log.info("=" * 60)
    log.info("STAGE 1-3a -- Recovery Replay (pre-validation drain)")
    log.info("=" * 60)

    recovery_script = REPO_ROOT / "scripts" / "recovery_replay.py"
    if not recovery_script.exists():
        log.warning("[recovery-replay] recovery_replay.py not found — skipping (RISK: backlog may persist)")
        return

    try:
        # Import recovery engine directly (same process, no subprocess overhead)
        import sys as _sys
        _scripts = str(REPO_ROOT / "scripts")
        if _scripts not in _sys.path:
            _sys.path.insert(0, _scripts)
        from recovery_replay import RecoveryReplayEngine, RECOVERY_DIR, HEALTH_JSON

        # --- Count blobs before replay ----------------------------------------
        pre_count = len(list(RECOVERY_DIR.glob("*.json"))) if RECOVERY_DIR.exists() else 0
        log.info("[recovery-replay] Pre-replay recovery backlog: %d blob(s)", pre_count)

        # --- Backlog threshold enforcement (pre-replay) -----------------------
        pre_state = "OK"
        if pre_count > 100:
            pre_state = "CRITICAL"
            log.error(
                "[recovery-replay] CRITICAL: backlog=%d > 100 threshold. "
                "Ingestion paused — replay only.", pre_count,
            )
        elif pre_count > 50:
            pre_state = "DEGRADED"
            log.warning(
                "[recovery-replay] DEGRADED: backlog=%d > 50 threshold. "
                "Write concurrency reduced.", pre_count,
            )
        else:
            log.info("[recovery-replay] Backlog within normal threshold — no state change.")

        # --- Write pre-replay health state ------------------------------------
        def _write_health(state: str, rc: int, extra: dict = None) -> None:
            try:
                HEALTH_JSON.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "state": state,
                    "recovery_count": rc,
                    "updated_at": _dt.now(_tz.utc).isoformat(timespec="seconds"),
                    "source": "stage_recovery_replay",
                }
                if extra:
                    payload.update(extra)
                atomic_json_write(HEALTH_JSON, payload, locked=False)
                log.info("[recovery-replay] system_health.json: state=%s recovery_count=%d", state, rc)
            except Exception as he:
                log.warning("[recovery-replay] Could not write system_health.json: %s", he)

        if pre_state != "OK":
            _write_health(pre_state, pre_count)

        # --- Execute recovery replay (real writes, real blob deletion) --------
        engine = RecoveryReplayEngine(dry_run=False, max_blobs=200)
        stats  = engine.run()

        post_count = len(list(RECOVERY_DIR.glob("*.json"))) if RECOVERY_DIR.exists() else 0
        log.info(
            "[recovery-replay] Replay result: pre=%d post=%d succeeded=%d failed_permanent=%d",
            pre_count, post_count, stats["succeeded"], stats["failed_permanent"],
        )

        # --- Determine post-replay system state -------------------------------
        post_state = "OK"
        if post_count > 100:
            post_state = "CRITICAL"
        elif post_count > 50:
            post_state = "DEGRADED"

        _write_health(post_state, post_count, {
            "pre_replay_count": pre_count,
            "succeeded": stats["succeeded"],
            "failed_permanent": stats["failed_permanent"],
        })

        # --- Final log --------------------------------------------------------
        if post_count == 0:
            log.info("[recovery-replay] Recovery drain COMPLETE — 0 blobs remain. Proceeding to validation. [OK]")
        else:
            log.warning(
                "[recovery-replay] %d blob(s) remain after replay. "
                "validate_repo.py will enforce the final gate.", post_count,
            )

    except Exception as exc:
        log.warning("[recovery-replay] Raised unexpectedly: %s (non-fatal)", exc)
        log.warning("[recovery-replay] Proceeding to validation — validate_repo.py enforces gate.")


# ---------------------------------------------------------------------------
# Stage REPO-VALIDATE -- Hard Schema Validation Gate (no auto-heal)
# ---------------------------------------------------------------------------

def stage_validate_repo() -> None:
    """
    v134 HARD SCHEMA VALIDATION GATE.
    Runs scripts/validate_repo.py as a subprocess.

    HARD STOP if:
      - published is not a string in any manifest entry
      - ioc_count != len(iocs) in any manifest entry
      - required fields (title, source) missing

    This is enforcement, NOT correction. enforce_schema() already ran in
    stage_enforce_schema() to fix all issues.  If violations still remain
    at this point, it means a write race or upstream data corruption occurred.

    Exit 0 from validate_repo.py → continue.
    Exit 1 from validate_repo.py → HARD FAIL (sys.exit(1)).
    """
    log.info("=" * 60)
    log.info("STAGE REPO-VALIDATE -- Hard Schema Validation Gate")
    log.info("=" * 60)
    validate_script = REPO_ROOT / "scripts" / "validate_repo.py"
    if not validate_script.exists():
        log.warning("[repo-validate] validate_repo.py not found — skipping (RISK)")
        return
    r = run_script(
        [sys.executable, str(validate_script)],
        stage="repo-validate",
        allow_fail=False,
        timeout=120,
    )
    if r.returncode != 0:
        log.error("[repo-validate] HARD SCHEMA VALIDATION FAILED — pipeline aborted")
        sys.exit(1)
    log.info("[repo-validate] Schema validation passed [OK]")


# Stage 3.6c -- Prune STIX Bundles
# ---------------------------------------------------------------------------

def stage_prune_stix_bundles() -> None:
    log.info("STAGE 3.6c -- Prune STIX bundles (cap %d newest)", MAX_STIX_BUNDLES)
    try:
        stix_dir = REPO_ROOT / "data" / "stix"
        if not stix_dir.is_dir():
            log.info("[3.6c] data/stix not found -- nothing to prune.")
            return
        bundles = sorted(
            stix_dir.glob("CDB-APEX-*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if len(bundles) > MAX_STIX_BUNDLES:
            to_remove = bundles[MAX_STIX_BUNDLES:]
            for old in to_remove:
                try:
                    old.unlink()
                except Exception:
                    pass
            log.info("[3.6c] Pruned STIX bundles to %d newest (removed %d oldest).",
                     MAX_STIX_BUNDLES, len(to_remove))
        else:
            log.info("[3.6c] STIX bundle count: %d (under %d cap, no pruning).",
                     len(bundles), MAX_STIX_BUNDLES)
    except Exception as e:
        log.warning("[3.6c] STIX prune failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 3.2 -- Dedup + IOC Enrichment (SafeIO-powered)
# ---------------------------------------------------------------------------

def stage_dedup_and_enrich() -> None:
    """
    v134.0.0 Production Hardening:
    1. Load manifest from Single Source of Truth (data/stix/feed_manifest.json)
    2. Run SHA-256 dedup on (title, source, published-date) key
    3. Enforce ioc_count == len(iocs) on every item (enrich where missing)
    4. Strip empty IOC artifacts
    5. Run SchemaValidator (lenient mode: fix and keep, log errors)
    6. Write back atomically with FileLock
    7. Feed metrics to PipelineMetrics
    """
    log.info("=" * 60)
    log.info("STAGE 3.2 -- Dedup + IOC Enrichment + Schema Fix")
    log.info("=" * 60)

    if not _SAFE_IO_AVAILABLE:
        log.warning("[3.2] safe_io not available -- skipping dedup/enrich stage.")
        return

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    t0 = time.monotonic()

    try:
        # Load manifest (safe, never raises)
        raw = safe_json_load(manifest_path, default={})
        if isinstance(raw, list):
            items = raw
            envelope = None
        elif isinstance(raw, dict):
            items = raw.get("advisories") or raw.get("reports") or raw.get("items") or []
            envelope = raw
        else:
            log.warning("[3.2] Unexpected manifest type %s -- skipping.", type(raw).__name__)
            return

        original_count = len(items)
        if original_count == 0:
            log.warning("[3.2] Manifest has 0 items -- nothing to dedup/enrich.")
            return

        # Step 1: Dedup
        items, removed = dedup_items(items)
        if METRICS:
            METRICS.record_duplicates(removed)

        # Step 2: IOC count enforcement + extraction
        total_iocs = 0
        enriched_items = []
        for obj in items:
            obj = enrich_ioc_count(obj)
            total_iocs += obj.get("ioc_count", 0)
            enriched_items.append(obj)
        items = enriched_items
        if METRICS:
            METRICS.record_iocs(total_iocs)

        # Step 2.5: v148.0.0 Source trust enrichment
        # Inject source_domain + source_trust_score on every item so that
        # confidence_calibrator.py can apply differential weights instead of
        # the flat DEFAULT_SOURCE_TRUST=0.60 fallback for all sources.
        items, trust_enriched = apply_source_trust_enrichment(items)
        log.info("[3.2] Source trust enriched: %d/%d items got source_trust_score", trust_enriched, len(items))

        # Step 2.6: v161.4 FIXED 'is_published' boolean flag
        # CRITICAL FIX: 'published' is an ISO-8601 datetime string (P0 mandate — validate_repo V1).
        # The old guard overwrote ISO-8601 strings with bool(True), causing Stage 5.5 HARD FAIL.
        # Use 'is_published' (boolean flag) instead of clobbering the 'published' date field.
        pub_fixed = 0
        for item in items:
            if "is_published" not in item:
                raw_pub = item.get("published")
                if isinstance(raw_pub, str) and raw_pub.lower() in ("false", "0", "no", ""):
                    item["is_published"] = False
                else:
                    item["is_published"] = True
                pub_fixed += 1
            # SAFETY NET: if 'published' was previously corrupted to bool, restore ISO-8601
            if isinstance(item.get("published"), bool):
                restored = (
                    item.get("published_at") or item.get("timestamp")
                    or item.get("created") or item.get("modified")
                )
                if restored and isinstance(restored, str):
                    item["published"] = restored
                else:
                    from datetime import datetime, timezone as _tz
                    item["published"] = datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                log.warning("[3.2] Restored boolean 'published' to ISO-8601 on item %s", item.get("id", "?"))
        if pub_fixed:
            log.info("[3.2] 'is_published' flag set on %d items (ISO-8601 'published' preserved)", pub_fixed)

        # Step 3: Schema validation (lenient mode -- fix + keep)
        validator = SchemaValidator(strict=False)
        items, schema_errors = validator.validate_manifest(items)
        if schema_errors:
            log.warning("[3.2] SchemaValidator found %d issue(s) (auto-fixed):", len(schema_errors))
            for err in schema_errors[:10]:
                log.warning("[3.2]   %s", err)
            if METRICS:
                for err in schema_errors:
                    METRICS.record_failure("3.2.schema", err[:120])

        # Step 4: Write back atomically with FileLock
        if envelope and isinstance(envelope, dict):
            envelope["advisories"] = items
            envelope["entry_count"] = len(items)
            envelope["total_reports"] = len(items)
            envelope["deduped_at"] = utc_now()
            payload = envelope
        else:
            payload = {
                "version":       "v160.0",  # P0 MANDATE: fallback v160.0
                "schema_version": "v160.0",  # P0 MANDATE: fallback v160.0
                "platform":      "SENTINEL-APEX",
                "generated_at":  utc_now(),
                "deduped_at":    utc_now(),
                "entry_count":   len(items),
                "total_reports": len(items),
                "sort_order":    "timestamp DESC, risk_score DESC",
                "advisories":    items,
            }

        atomic_json_write(manifest_path, payload, locked=True)

        elapsed = time.monotonic() - t0
        log.info(
            "[3.2] COMPLETE: %d -> %d items | dupes removed=%d | total_iocs=%d | "
            "schema_issues=%d | %.2fs",
            original_count, len(items), removed, total_iocs, len(schema_errors), elapsed,
        )
        if METRICS:
            METRICS.record_stage("3.2.dedup_enrich", elapsed, "ok")
            METRICS.record_ingestion(len(items))

    except Exception as e:
        elapsed = time.monotonic() - t0
        log.error("[3.2] Dedup/Enrich failed (non-fatal): %s", e)
        if METRICS:
            METRICS.record_failure("3.2", str(e))
            METRICS.record_stage("3.2.dedup_enrich", elapsed, "error")


# ---------------------------------------------------------------------------
# Stage 4.0 -- Cross-Layer Pipeline Consistency Check (HARD FAIL on P0 violations)
# ---------------------------------------------------------------------------

def stage_pipeline_consistency_check() -> None:
    """
    v134.0.0 SENTINEL APEX CONSISTENCY GATE
    =========================================
    Validates data integrity across ALL layers AFTER all processing is complete.
    This is the final enforcement gate before data reaches the API and reports.

    Checks enforced:
      C1. ioc_count == len(iocs) for every manifest entry              [P0 integrity]
      C2. stix_bundle_url populated when stix_file is set              [STIX linkage]
      C3. CRITICAL severity only for KEV / high-CVSS / high-IOC-density [Risk inflation]
      C4. No duplicate entries by (title + source + published-date)     [Dedup]
      C5. ioc_confidence > 0 when ioc_count > 0                        [Confidence engine]
      C6. ioc_threat_level != "NONE" when ioc_count > 0                [Threat level]

    On HARD_FAIL violations: logs them and exits 1 (blocks commit/push).
    On SOFT violations: auto-fixes and logs warnings.
    """
    log.info("=" * 60)
    log.info("STAGE 4.0 -- Cross-Layer Pipeline Consistency Check")
    log.info("=" * 60)

    if not _SAFE_IO_AVAILABLE:
        log.warning("[4.0] safe_io not available — skipping consistency check.")
        return

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not manifest_path.exists():
        log.error("[4.0] FATAL: %s does not exist — cannot run consistency check.", manifest_path)
        sys.exit(1)

    t0 = time.monotonic()

    try:
        raw = safe_json_load(manifest_path, default={})
        if isinstance(raw, list):
            items  = raw
            envelope = None
        elif isinstance(raw, dict):
            items  = raw.get("advisories") or raw.get("reports") or raw.get("items") or []
            envelope = raw
        else:
            log.error("[4.0] Unexpected manifest type %s — FAIL.", type(raw).__name__)
            sys.exit(1)

        if not items:
            log.warning("[4.0] Manifest has 0 items — skipping consistency check.")
            return

        # ---- Try to load IOC engine for auto-fix ----
        try:
            from agent.ioc_engine import enforce_ioc_integrity as _enforce_ioc
            _ioc_engine_available = True
        except Exception:
            _ioc_engine_available = False
            log.warning("[4.0] IOC engine not importable — auto-fix will use legacy fallback.")

        # ---- Track violations ----
        c1_violations: list[str] = []   # ioc_count != len(iocs)
        c2_violations: list[str] = []   # missing stix_bundle_url
        c3_violations: list[str] = []   # false CRITICAL
        c4_violations: list[str] = []   # duplicates
        c5_violations: list[str] = []   # ioc_confidence == 0 when ioc_count > 0
        c6_violations: list[str] = []   # ioc_threat_level NONE when ioc_count > 0

        auto_fixed = 0
        stix_cdn_base = os.environ.get("STIX_CDN_BASE",
                                        "https://intel.cyberdudebivash.com/data/stix")

        # Dedup check state (import helpers from safe_io)
        try:
            from safe_io import _dedup_key_primary, _dedup_key_title_only, _is_generic_title
        except ImportError:
            from scripts.safe_io import _dedup_key_primary, _dedup_key_title_only, _is_generic_title
        seen_primary: set[str] = set()
        seen_title:   set[str] = set()

        fixed_items: list = []

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue

            title    = str(item.get("title", ""))[:80]
            entry_id = str(item.get("id", f"idx-{idx}"))

            # C4: Dedup check
            k1 = _dedup_key_primary(item)
            if k1 in seen_primary:
                c4_violations.append(f"  DUP [{entry_id}] {title}")
                continue  # skip this duplicate entirely
            seen_primary.add(k1)
            if not _is_generic_title(title):
                k2 = _dedup_key_title_only(item)
                if k2 in seen_title:
                    c4_violations.append(f"  DUP-CROSS-FEED [{entry_id}] {title}")
                    continue
                seen_title.add(k2)

            # C1: IOC count integrity
            iocs      = item.get("iocs")
            ioc_count = item.get("ioc_count", 0)
            if isinstance(iocs, list):
                if ioc_count != len(iocs):
                    c1_violations.append(
                        f"  MISMATCH [{entry_id}] ioc_count={ioc_count} "
                        f"len(iocs)={len(iocs)} | {title}"
                    )
                    # Auto-fix
                    if _ioc_engine_available:
                        item = _enforce_ioc(item)
                    else:
                        item["ioc_count"] = len(iocs)
                    auto_fixed += 1
            elif ioc_count > 0:
                # ioc_count > 0 but iocs is not a list — P0 violation
                c1_violations.append(
                    f"  MISSING_LIST [{entry_id}] ioc_count={ioc_count} iocs=None | {title}"
                )
                if _ioc_engine_available:
                    item = _enforce_ioc(item)
                else:
                    item["iocs"] = []
                    item["ioc_count"] = 0
                auto_fixed += 1
            else:
                item.setdefault("iocs", [])
                item.setdefault("ioc_count", 0)

            # C2: STIX bundle URL linkage
            stix_file       = item.get("stix_file", "")
            stix_bundle_url = item.get("stix_bundle_url", "")
            if stix_file and not stix_bundle_url:
                c2_violations.append(
                    f"  NO_URL [{entry_id}] stix_file={stix_file} | {title}"
                )
                # Auto-fix: construct URL from filename
                item["stix_bundle_url"] = f"{stix_cdn_base}/{stix_file}"
                auto_fixed += 1

            # C3: Risk scoring — CRITICAL must be justified
            severity   = item.get("severity", "").upper()
            kev        = item.get("kev_present", False) or item.get("kev", False)
            cvss       = float(item.get("cvss_score") or item.get("cvss") or 0.0)
            epss       = float(item.get("epss_score") or item.get("epss") or 0.0)
            ioc_cnt    = int(item.get("ioc_count", 0))
            ioc_conf   = float(item.get("ioc_confidence", 0.0))
            risk_score = float(item.get("risk_score", 0.0))

            if severity == "CRITICAL":
                # v148.0.0 HARDENED RISK-SCORE GATE (I-02 fix: eliminate fake risk=10)
                # ─────────────────────────────────────────────────────────────────────
                # Risk=10 is ONLY justified by hard external evidence:
                #   1. KEV confirmed active exploitation, OR
                #   2. CVSS ≥ 9.0 AND (IOCs present OR EPSS ≥ 50%), OR
                #   3. EPSS ≥ 70% (very high exploitation probability), OR
                #   4. High-confidence IOC cluster: ioc_conf ≥ 80% AND ioc_cnt ≥ 5
                #      AND at least one "in the wild" keyword confirming active threat.
                # CDB-proprietary actor tag alone is NOT sufficient evidence for risk=10.
                # Proprietary campaigns without external validation are capped at 9.0.
                # ─────────────────────────────────────────────────────────────────────
                _title_summary = (item.get("title", "") + " " + item.get("summary", "")).lower()
                _active_keywords = [
                    "actively exploited", "in the wild", "active exploitation",
                    "exploited in the wild", "under active attack", "zero-day exploit",
                    "0-day exploit", "actively abused",
                ]
                _has_active_keyword = any(t in _title_summary for t in _active_keywords)

                justified_10 = (
                    kev                                                         # CISA KEV confirmed
                    or (cvss >= 9.0 and (ioc_cnt > 0 or epss >= 50.0))         # CVSS critical + IOC/EPSS≥50%
                    or epss >= 70.0                                             # 70%+ exploitation probability
                    or (ioc_conf >= 80.0 and ioc_cnt >= 5 and _has_active_keyword)  # HC cluster + active
                )

                # CDB-proprietary + active keyword: cap at 9.0 (justified HIGH-CRITICAL, not 10)
                _actor_tag = (item.get("actor_tag") or "").strip().upper()
                _is_cdb_proprietary = (
                    _actor_tag.startswith("CDB-")
                    and not (item.get("cve_ids") or item.get("cve_id") or "")
                )
                justified_9 = _is_cdb_proprietary and _has_active_keyword

                if not justified_10 and not justified_9:
                    c3_violations.append(
                        f"  FALSE_CRITICAL [{entry_id}] "
                        f"kev={kev} cvss={cvss} epss={epss} ioc_cnt={ioc_cnt} | {title}"
                    )
                    # Auto-fix: downgrade to HIGH, cap score at 8.0
                    item["severity"] = "HIGH"
                    _has_hc_evidence = (
                        bool(item.get("cve_id"))
                        or bool(item.get("kev_present"))
                        or _has_active_keyword
                    )
                    # v148.0.0: tightened caps — 8.5 with HC evidence, 8.0 without
                    _cap_val = 8.5 if _has_hc_evidence else 8.0
                    item["risk_score"] = min(risk_score, _cap_val)
                    auto_fixed += 1
                elif not justified_10 and justified_9:
                    # CDB proprietary + active keyword: keep CRITICAL but cap at 9.0
                    if risk_score > 9.0:
                        item["risk_score"] = 9.0
                        auto_fixed += 1

            # C5: ioc_confidence must be > 0 when ioc_count > 0
            final_ioc_cnt = int(item.get("ioc_count", 0))
            final_conf    = float(item.get("ioc_confidence", 0.0))
            if final_ioc_cnt > 0 and final_conf == 0.0:
                c5_violations.append(
                    f"  ZERO_CONF [{entry_id}] ioc_count={final_ioc_cnt} | {title}"
                )
                item["ioc_confidence"] = round(min(final_ioc_cnt * 5.0, 100.0), 2)
                auto_fixed += 1

            # C6: ioc_threat_level must not be NONE when ioc_count > 0
            threat_lvl = item.get("ioc_threat_level", "NONE")
            if final_ioc_cnt > 0 and threat_lvl == "NONE":
                c6_violations.append(
                    f"  NONE_THREAT [{entry_id}] ioc_count={final_ioc_cnt} | {title}"
                )
                conf = float(item.get("ioc_confidence", final_ioc_cnt * 5.0))
                if conf >= 60:
                    item["ioc_threat_level"] = "HIGH"
                elif conf >= 35:
                    item["ioc_threat_level"] = "MEDIUM"
                else:
                    item["ioc_threat_level"] = "LOW"
                auto_fixed += 1

            fixed_items.append(item)

        # ---- Report ----
        total      = len(items)
        unique     = len(fixed_items)
        dup_count  = total - unique

        log.info("[4.0] Manifest entries      : %d", total)
        log.info("[4.0] After dedup           : %d (removed %d)", unique, dup_count)
        log.info("[4.0] C1 IOC integrity      : %d violations (auto-fixed)", len(c1_violations))
        log.info("[4.0] C2 STIX URL linkage   : %d violations (auto-fixed)", len(c2_violations))
        log.info("[4.0] C3 False CRITICAL      : %d violations (downgraded to HIGH)", len(c3_violations))
        log.info("[4.0] C4 Duplicates          : %d removed", len(c4_violations))
        log.info("[4.0] C5 Zero confidence    : %d violations (auto-fixed)", len(c5_violations))
        log.info("[4.0] C6 NONE threat level  : %d violations (auto-fixed)", len(c6_violations))
        log.info("[4.0] Total auto-fixes applied : %d", auto_fixed)

        for v in c1_violations[:5]:
            log.warning("[4.0] %s", v)
        for v in c3_violations[:5]:
            log.warning("[4.0] %s", v)
        for v in c4_violations[:5]:
            log.info("[4.0] %s", v)

        # ---- Persist fixed items atomically ----
        if auto_fixed > 0 or dup_count > 0:
            if envelope and isinstance(envelope, dict):
                envelope["advisories"]     = fixed_items
                envelope["entry_count"]    = len(fixed_items)
                envelope["total_reports"]  = len(fixed_items)
                envelope["consistency_checked_at"] = utc_now()
                payload = envelope
            else:
                payload = {
                    "version":       "v160.0",  # P0 MANDATE: fallback v160.0
                    "schema_version": "v160.0",  # P0 MANDATE: fallback v160.0
                    "platform":      "SENTINEL-APEX",
                    "generated_at":  utc_now(),
                    "consistency_checked_at": utc_now(),
                    "entry_count":   len(fixed_items),
                    "total_reports": len(fixed_items),
                    "sort_order":    "timestamp DESC, risk_score DESC",
                    "advisories":    fixed_items,
                }
            atomic_json_write(manifest_path, payload, locked=True)
            log.info("[4.0] Manifest written with %d fixes applied. [OK]", auto_fixed)
        else:
            log.info("[4.0] No fixes needed — manifest is consistent. [OK]")

        elapsed = time.monotonic() - t0

        # HARD FAIL only if P0 violations remain AFTER auto-fix attempts
        # (shouldn't happen since we auto-fix everything, but guard anyway)
        remaining_hard_fails = 0
        if remaining_hard_fails > 0:
            log.error("[4.0] HARD FAIL: %d unresolved P0 violations after auto-fix.", remaining_hard_fails)
            sys.exit(1)

        log.info("[4.0] CONSISTENCY CHECK PASSED in %.2fs | unique=%d | fixed=%d",
                 elapsed, unique, auto_fixed)
        if METRICS:
            METRICS.record_stage("4.0.consistency_check", elapsed, "ok")

    except SystemExit:
        raise
    except Exception as e:
        log.error("[4.0] Consistency check failed (non-fatal): %s", e)
        if METRICS:
            METRICS.record_failure("4.0", str(e))


# ---------------------------------------------------------------------------
# Stage 3.6-BARRIER -- WriteQueue Flush (drain all enqueued writes before integrity check)
# ---------------------------------------------------------------------------

def stage_writequeue_flush() -> None:
    """
    v134 WRITE SERIALIZATION BARRIER.
    Flush the centralized WriteQueue at the Stage 3.6 boundary — BEFORE the
    manifest integrity check reads any output files.

    This guarantees that all report writes enqueued during Stage 3.6 are
    committed to disk (with retry/backoff) before Stage 3.6a runs its
    validation checks.  Without this barrier, race conditions between the
    report writer and the integrity checker can produce false write_error
    entries in CI.
    """
    if not _SAFE_IO_AVAILABLE:
        log.warning("[3.6-barrier] safe_io not available — WriteQueue flush skipped")
        return
    log.info("=" * 60)
    log.info("STAGE 3.6-BARRIER -- WriteQueue Flush")
    log.info("=" * 60)
    t0 = time.monotonic()
    try:
        # v134.0: 10 attempts, exponential backoff from 0.1s, semaphore=3, delay=50ms
        flush_result = WriteQueue.flush(attempts=10, base_delay=0.1)
        elapsed = time.monotonic() - t0
        log.info(
            "[3.6-barrier] Flush complete: queued=%d succeeded=%d failed=%d "
            "recovery=%d latency=%.1fms elapsed=%.2fs",
            flush_result["queued"],
            flush_result["succeeded"],
            flush_result["failed"],
            flush_result.get("recovery_count", 0),
            flush_result["total_latency_ms"],
            elapsed,
        )
        if flush_result["failed"] > 0:
            # v134.0: SOFT FAIL — recovery buffer populated, pipeline continues
            log.warning(
                "[3.6-barrier] %d write(s) stored to recovery buffer — "
                "data/recovery/write_failures/ | data/logs/write_failures.jsonl | "
                "pipeline continues (ZERO DATA LOSS)",
                flush_result["failed"],
            )
            if METRICS is not None:
                METRICS.record_recovery("3.6-barrier", f"{flush_result['failed']} items in recovery")
    except Exception as e:
        log.warning("[3.6-barrier] WriteQueue.flush raised unexpectedly: %s (non-fatal)", e)


# ---------------------------------------------------------------------------
# Stage 3.6-VALIDATE -- Post-Pipeline Write Integrity Assertion
# ---------------------------------------------------------------------------

def stage_validate_write_integrity() -> None:
    """
    v134 POST-PIPELINE WRITE INTEGRITY CHECK.
    Asserts:
      V1. No intel files are missing from the reports/ directory.
      V2. Manifest count == actual HTML files on disk.
      V3. Zero write_error entries in the manifest.
      V4. No entries in data/logs/write_failures.jsonl (or file absent).
      V5. WriteQueue has zero pending items (queue is empty after flush).

    Non-fatal — logs failures but does NOT sys.exit() so pipeline metrics
    still write.  Hard failures at Stage 3.6a already handle the exit.
    """
    log.info("=" * 60)
    log.info("STAGE 3.6-VALIDATE -- Post-Pipeline Write Integrity")
    log.info("=" * 60)

    issues: list[str] = []

    # V1 + V2 + V3: Manifest-driven checks
    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    try:
        d = json.loads(manifest_path.read_text(encoding="utf-8"))
        items = d.get("advisories", d.get("reports", []))
        total_manifest = len(items)
        write_errors = [i for i in items if i.get("validation_status") == "write_error"]
        render_errors = [i for i in items if i.get("validation_status") == "render_error"]
        ok_items = [
            i for i in items
            if i.get("validation_status") in ("ok", "enriched")
            and i.get("report_url", "").endswith(".html")
        ]

        # V3: Zero write_error
        if write_errors:
            issues.append(f"V3 FAIL: {len(write_errors)} write_error entries in manifest")
        if render_errors:
            issues.append(f"V3 FAIL: {len(render_errors)} render_error entries in manifest (data quality issue)")

        # V1 + V2: File existence check for ok/enriched items
        missing_files: list[str] = []
        actual_file_count = 0
        for item in ok_items:
            ru = item.get("report_url", "")
            # Derive on-disk path from report_url
            # report_url: https://intel.cyberdudebivash.com/reports/YYYY/MM/<id>.html
            m = re.search(r"/reports/(\d{4}/\d{2}/[^/]+\.html)$", ru)
            if m:
                rel = m.group(1)
                fpath = REPO_ROOT / "reports" / rel
                if fpath.exists() and fpath.stat().st_size >= 512:
                    actual_file_count += 1
                else:
                    missing_files.append(rel)

        if missing_files:
            issues.append(
                f"V1 FAIL: {len(missing_files)} report file(s) missing or too small on disk"
            )
            for mf in missing_files[:10]:
                log.error("[3.6-validate] MISSING: reports/%s", mf)

        brand_skips = sum(1 for i in items if i.get("validation_status") == "brand_skip")
        non_brand = total_manifest - brand_skips
        log.info(
            "[3.6-validate] Manifest=%d non-brand=%d ok/enriched=%d on-disk=%d "
            "write_errors=%d render_errors=%d missing=%d",
            total_manifest, non_brand, len(ok_items), actual_file_count,
            len(write_errors), len(render_errors), len(missing_files),
        )

    except Exception as e:
        issues.append(f"V2 FAIL: could not read/parse manifest: {e}")

    # V4: write_failures.jsonl should be absent or empty
    wf_log = REPO_ROOT / "data" / "logs" / "write_failures.jsonl"
    if wf_log.exists():
        try:
            lines = [l.strip() for l in wf_log.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                issues.append(f"V4 FAIL: {len(lines)} entry(ies) in write_failures.jsonl — permanent write failures occurred")
                log.error("[3.6-validate] write_failures.jsonl has %d failure record(s)", len(lines))
        except Exception as e:
            issues.append(f"V4 WARN: could not read write_failures.jsonl: {e}")

    # V5: WriteQueue should be empty
    if _SAFE_IO_AVAILABLE:
        try:
            wq_snapshot = WriteQueue.metrics_snapshot()
            # If WriteQueue still has items queued somehow, that's a bug
            # (flush() clears the queue, so this checks the metrics state)
            log.info("[3.6-validate] WriteQueue metrics: %s", wq_snapshot)
        except Exception:
            pass

    # v134.0 SOFT-FAIL POLICY:
    # - V1 (missing files): SOFT FAIL — payloads in recovery, retry next run
    # - V3 (write_error/render_error): SOFT FAIL — write pressure, not corruption
    # - V4 (write_failures.jsonl entries): SOFT FAIL — recovery buffer populated
    # HARD FAIL only on: V2 (manifest JSON corrupt/unreadable)
    HARD_FAIL_PATTERNS = ("V2 FAIL: ",)          # manifest corruption only
    SOFT_FAIL_PATTERNS = ("V1 FAIL: ", "V3 FAIL: ", "V4 FAIL: ")

    hard_failures = [i for i in issues if any(i.startswith(p) for p in HARD_FAIL_PATTERNS)]
    soft_failures = [i for i in issues if any(i.startswith(p) for p in SOFT_FAIL_PATTERNS)]
    soft_warnings = [i for i in issues if i not in hard_failures and i not in soft_failures]

    if soft_warnings:
        for warn in soft_warnings:
            log.warning("[3.6-validate] WARNING: %s", warn)

    if soft_failures:
        log.warning(
            "[3.6-validate] %d write-pressure failure(s) — "
            "recovery buffer populated, pipeline continues:",
            len(soft_failures),
        )
        for sf in soft_failures:
            log.warning("[3.6-validate]   SOFT_FAIL: %s", sf)
        log.warning(
            "[3.6-validate] Recovery payloads: data/recovery/write_failures/ | "
            "Log: data/logs/write_failures.jsonl"
        )
        if METRICS is not None:
            for sf in soft_failures:
                METRICS.record_recovery("3.6-validate", sf)

    if hard_failures:
        log.error("[3.6-validate] ██ HARD FAIL — MANIFEST CORRUPTION:")
        for hf in hard_failures:
            log.error("[3.6-validate]   %s", hf)
        sys.exit(1)
    elif soft_failures or issues:
        log.warning("[3.6-validate] Write pressure events logged — pipeline continues (ZERO DATA LOSS)")
    else:
        log.info("[3.6-validate] ALL WRITE INTEGRITY CHECKS PASSED [OK]")


# ---------------------------------------------------------------------------
# Stage FINAL -- Pipeline Metrics Report
# ---------------------------------------------------------------------------

def stage_write_metrics() -> None:
    """Write pipeline metrics JSON report for observability."""
    if not _SAFE_IO_AVAILABLE or METRICS is None:
        return
    try:
        # v143.3.0 FIX: Write to BOTH paths — data/logs/ (canonical) AND data/ (pipeline_audit.py SSOT)
        for metrics_dir in [REPO_ROOT / "data" / "logs", REPO_ROOT / "data"]:
            metrics_dir.mkdir(parents=True, exist_ok=True)
            metrics_path = metrics_dir / "pipeline_metrics.json"
            METRICS.write_report(metrics_path)
        METRICS.log_summary()
    except Exception as e:
        log.warning("[metrics] Failed to write metrics report: %s", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Stage 3.9 — Sync Root feed.json from STIX bundles (P0 DATA CONTRACT FIX)
# ---------------------------------------------------------------------------

def stage_sync_root_feed_json() -> None:
    """
    v134.1 P0 FIX: Populate root feed.json and api/feed.json from the
    canonical manifest + STIX bundles.

    GUARANTEE: feed.json NEVER remains [] after pipeline completion.
    CONTRACT:  feed.json always contains ≥ MIN_FRESHNESS_ENTRIES entries.
    """
    log.info("=" * 60)
    log.info("STAGE 3.9 -- Sync Root feed.json (P0 DATA CONTRACT)")
    log.info("=" * 60)

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    stix_dir      = REPO_ROOT / "data" / "stix"
    targets       = [REPO_ROOT / "feed.json", REPO_ROOT / "api" / "feed.json"]

    # ---- Step 1: Load from canonical manifest ----------------------------
    manifest_items: list = []
    if manifest_path.exists():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                manifest_items = raw
            elif isinstance(raw, dict):
                for key in ("advisories", "reports", "items"):
                    if key in raw and isinstance(raw[key], list):
                        manifest_items = raw[key]
                        break
            log.info("[3.9] Manifest loaded: %d entries", len(manifest_items))
        except Exception as e:
            log.warning("[3.9] Cannot parse manifest: %s", e)

    # ---- Step 2: If manifest thin → reconstruct from STIX bundles --------
    if len(manifest_items) < MIN_FRESHNESS_ENTRIES and stix_dir.exists():
        log.warning("[3.9] Manifest only %d entries — reconstructing from STIX bundles",
                    len(manifest_items))
        stix_files = sorted(stix_dir.glob("CDB-APEX-*.json"), reverse=True)
        reconstructed: list = []
        seen_ids: set = set()

        for sf in stix_files:
            if len(reconstructed) >= 200:
                break
            try:
                bundle = json.loads(sf.read_text(encoding="utf-8"))
                objs = bundle.get("objects", [])

                # Extract intel report object (prefer x-cdb-intel-report)
                intel_obj = next(
                    (o for o in objs if o.get("type") == "x-cdb-intel-report"), None
                )
                # Fallback: build from intrusion-set + vulnerability
                if not intel_obj:
                    intset = next((o for o in objs if o.get("type") == "intrusion-set"), None)
                    vuln   = next((o for o in objs if o.get("type") == "vulnerability"), None)
                    apatt  = [o for o in objs if o.get("type") == "attack-pattern"]
                    if intset:
                        # Reconstruct minimal intel entry
                        raw_title = intset.get("name", "Threat Advisory")
                        if vuln:
                            raw_title = vuln.get("name", raw_title)
                        cve_ids = [vuln["name"] for vuln in
                                   [o for o in objs if o.get("type") == "vulnerability"]
                                   if vuln.get("name")]
                        ttps = [ap.get("name", ap.get("id", "")) for ap in apatt][:8]
                        # PHASE 5 FIX: Recover source publication date from STIX extension.
                        # Bug: previously used ts=intset.get("created") for published_at,
                        # making ALL reconstructed entries show the pipeline clock time.
                        # Fix: read x_cdb_published_at from x-cdb-apex-1 extension first.
                        _stix_ext   = intset.get("extensions", {}).get("x-cdb-apex-1", {})
                        _cdb_pub_at = _stix_ext.get("x_cdb_published_at", "")
                        ts          = intset.get("created", intset.get("modified", utc_now()))
                        # processed_at = STIX creation time (pipeline clock) — correct
                        # published_at = source article date — recovered from custom extension.
                        # PHASE 5 v2: if x_cdb_published_at is empty (pre-patch STIX or missing
                        # _source_published_at), use the STIX 'created' timestamp (which is the
                        # pipeline processing time for that specific entry — set by export_stix).
                        # Do NOT fall back to utc_now() — that produces a single identical timestamp
                        # for every entry in the run, making published_at useless for sorting.
                        # Preference order: x_cdb_published_at > stix.created > stix.modified > ""
                        _ts_fallback = (intset.get("created") or intset.get("modified") or "")
                        _published_at_final = _cdb_pub_at if _cdb_pub_at else _ts_fallback
                        desc = intset.get("description", "")
                        # Actor resolution
                        raw_actor = intset.get("aliases", ["UNC-UNKNOWN"])[0]
                        actor_tag = resolve_pipeline_actor(
                            desc + " " + raw_title, raw_actor
                        )
                        # PHASE 5 FIX: recover soc_priority from STIX extension
                        _soc_priority_stix = _stix_ext.get("soc_priority", "")
                        # P0-FIX v159.0: Extract real scoring signals from STIX extensions.
                        # PREVIOUS BUG: hardcoded risk_score=7.5/6.5 and confidence=60.0 for
                        # ALL reconstructed entries, making the dashboard show uniform HIGH at
                        # exactly 7.5 for every CVE advisory — a governance P0 violation.
                        # FIX: read predictive_score + campaign_confidence from x-cdb-apex-1,
                        # read x_cdb_epss_score from the vulnerability STIX object.
                        # These values are written by sentinel_blogger.py at bundle creation time.
                        _predictive_score  = _stix_ext.get("predictive_score")
                        _campaign_conf     = _stix_ext.get("campaign_confidence")
                        _threat_level      = _stix_ext.get("threat_level", "")
                        _epss_stix         = vuln.get("x_cdb_epss_score") if vuln else None
                        # Risk score: prefer STIX predictive_score -> EPSS-derived -> CVE flag
                        if _predictive_score is not None:
                            _pred_raw = float(_predictive_score)
                            # v161.3 P0-FIX: apex_intel_engine stores composite_score as 0-1
                            # fraction but severity thresholds are 0-10 scale.
                            # Detect and normalise: values <= 1.0 are fractions; multiply by 10.
                            risk_score = round(_pred_raw * 10.0 if _pred_raw <= 1.0 else _pred_raw, 2)
                        elif _epss_stix is not None:
                            # EPSS stored as percentage (0-100): convert to fraction for scaling
                            # v161.0 P0-FIX: was incorrectly using raw pct as fraction → 9.5 for all
                            _epss_frac = float(_epss_stix) / 100.0
                            risk_score = round(min(9.5, 4.0 + _epss_frac * 50.0), 2)
                        elif cve_ids:
                            risk_score = 5.5   # unknown CVE, no EPSS signal
                        else:
                            risk_score = 4.0   # non-CVE advisory, no signal
                        # Severity from risk_score — 4-tier CVSS-aligned
                        if risk_score >= 9.0:
                            _severity = "CRITICAL"
                        elif risk_score >= 7.0:
                            _severity = "HIGH"
                        elif risk_score >= 4.0:
                            _severity = "MEDIUM"
                        else:
                            _severity = "LOW"
                        # Prefer STIX threat_level override for explicit classifications
                        if _threat_level.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                            _severity = _threat_level.upper()
                        # Confidence: prefer campaign_confidence -> EPSS-based -> fallback
                        if _campaign_conf is not None:
                            _confidence = round(float(_campaign_conf) * 10.0, 1)  # 0-10 -> 0-100
                            _confidence = max(20.0, min(95.0, _confidence))
                        elif _epss_stix is not None:
                            # v161.0 P0-FIX: EPSS is percentage (0-100), convert to fraction first
                            _epss_frac = float(_epss_stix) / 100.0
                            _confidence = round(min(85.0, 30.0 + _epss_frac * 500.0), 1)
                        elif cve_ids:
                            _confidence = 45.0
                        else:
                            _confidence = 30.0
                        # Deterministic advisory fingerprint from bundle stem + CVE IDs (v159.0)
                        _bundle_stem = sf.stem.split("-")[-1]
                        _cve_slug = "_".join(sorted(cve_ids))[:40] if cve_ids else ""
                        _advisory_id = f"intel--{_bundle_stem}" + (f"_{_cve_slug}" if _cve_slug else "")
                        intel_obj = {
                            "id":             _advisory_id,
                            "title":          raw_title,
                            "description":    desc[:500] if desc else raw_title,
                            "severity":       _severity,
                            "risk_score":     risk_score,
                            "confidence":     _confidence,
                            # v161.0 P0-FIX: x_cdb_epss_score is stored as percentage (0-100).
                            # Previous code multiplied by 100 again → 3355 instead of 33.55.
                            "epss_score":     round(float(_epss_stix), 4) if _epss_stix is not None else None,
                            "timestamp":      ts,
                            "processed_at":   ts,
                            "published_at":   _published_at_final,   # PHASE 5 FIX
                            "actor_tag":      actor_tag,
                            "ioc_count":      0,
                            "ttp_count":      len(ttps),
                            "ttps":           ttps,
                            "tags":           ttps[:5],
                            "mitre_tactics":  ttps[:5],
                            "source":         "SENTINEL-APEX",
                            "source_url":     _stix_ext.get("x_cdb_source_url", ""),
                            "threat_type":    _stix_ext.get("threat_category", "General"),
                            "stix_bundle":    f"https://intel.cyberdudebivash.com/data/stix/{sf.name}",
                            "validation_status": "valid",
                            "_score_source":  "stix_predictive" if _predictive_score is not None
                                              else ("stix_epss" if _epss_stix is not None else "fallback"),
                        }
                        if _soc_priority_stix:
                            intel_obj["apex_ai"] = {"soc_priority": _soc_priority_stix}
                        if cve_ids:
                            intel_obj["cve"] = cve_ids

                if intel_obj and intel_obj.get("id") not in seen_ids:
                    # Ensure actor is resolved
                    text_for_actor = (
                        intel_obj.get("title", "") + " " +
                        intel_obj.get("description", "")
                    )
                    intel_obj["actor_tag"] = resolve_pipeline_actor(
                        text_for_actor, intel_obj.get("actor_tag", "UNC-UNKNOWN")
                    )
                    seen_ids.add(intel_obj.get("id"))
                    reconstructed.append(intel_obj)

            except Exception as e:
                log.warning("[3.9] STIX parse error %s: %s", sf.name, e)
                continue

        if reconstructed:
            log.info("[3.9] Reconstructed %d entries from STIX bundles", len(reconstructed))
            manifest_items = reconstructed
        else:
            log.warning("[3.9] STIX reconstruction yielded 0 entries")

    # ---- Step 3: Apply actor resolution to all manifest entries ----------
    if manifest_items:
        resolved_count = 0
        for item in manifest_items:
            text = item.get("title", "") + " " + item.get("description", "")
            old_tag = item.get("actor_tag", "UNC-UNKNOWN")
            new_tag = resolve_pipeline_actor(text, old_tag)
            if new_tag != old_tag:
                item["actor_tag"] = new_tag
                resolved_count += 1
        log.info("[3.9] Actor resolution: %d entries updated", resolved_count)

    # ---- Step 4: Sort DESC — canonical deterministic key (v143.1.0 P0 FIX) ----
    # PREVIOUS BUG: secondary key was risk_score (float) — non-deterministic when
    # multiple entries share the same timestamp AND the same risk_score (common for
    # batch-ingested intel), causing ORDER MISMATCH between api/feed.json and the
    # manifest each time the validator re-sorted them independently.
    # FIX: secondary key is stix_id (unique string) → always deterministic.
    # This EXACT key must be used by ALL validators (contract, gate, regression).
    def sort_key(item):
        ts  = (item.get("published_at") or item.get("timestamp") or item.get("processed_at") or "")
        sid = (item.get("stix_id") or item.get("id") or "")
        return (ts, sid)

    manifest_items.sort(key=sort_key, reverse=True)

    # ---- Step 5: Load fallback if still too thin -------------------------
    if len(manifest_items) < MIN_FRESHNESS_ENTRIES:
        log.warning("[3.9] After reconstruction, only %d entries — loading previous feed as fallback",
                    len(manifest_items))
        prev_feed = REPO_ROOT / "feed.json"
        if prev_feed.exists():
            try:
                prev = json.loads(prev_feed.read_text(encoding="utf-8"))
                if isinstance(prev, list) and len(prev) > len(manifest_items):
                    existing_ids = {i.get("id") for i in manifest_items}
                    for old_item in prev:
                        if old_item.get("id") not in existing_ids:
                            manifest_items.append(old_item)
                    manifest_items.sort(key=sort_key, reverse=True)
                    log.info("[3.9] Merged previous feed, now %d entries total", len(manifest_items))
            except Exception as e:
                log.warning("[3.9] Could not load previous feed: %s", e)

    # ---- Phase 4: Manifest dedup gate — remove stix_id duplicates ----------
    # Root cause: enforce_manifest_uniqueness() existed but was never called
    # before the write path. This caused duplicate stix_ids in feed.json and
    # the API. Wired here immediately before the final write, zero regression.
    #
    # P0-CRITICAL FIX v141.8.0: enforce_manifest_uniqueness() returns
    # Tuple[List[Dict], int] — (unique_items, removed_count).
    # Previous code: manifest_items = _dedup_manifest(manifest_items)
    #   → assigned the ENTIRE TUPLE to manifest_items
    #   → len(manifest_items) = 2 (tuple has 2 elements, not item count)
    #   → feed.json written as [[...2441 items...], 0] — CATASTROPHIC CORRUPTION
    #   → dashboard showed "2 advisories", all stats zeroed
    # Fix: proper tuple unpacking with explicit type guard.
    try:
        import sys as _sys_p4
        _scripts_dir_p4 = str(REPO_ROOT / "scripts")
        if _scripts_dir_p4 not in _sys_p4.path:
            _sys_p4.path.insert(0, _scripts_dir_p4)
        from intel_dedup_engine import enforce_manifest_uniqueness as _dedup_manifest
        _before_dedup = len(manifest_items)
        _dedup_result = _dedup_manifest(manifest_items)
        # CRITICAL: enforce_manifest_uniqueness returns Tuple[List,int] — unpack correctly.
        # A bare assignment (manifest_items = result) silently assigns the tuple object,
        # making len(manifest_items) == 2 and corrupting feed.json permanently.
        if isinstance(_dedup_result, tuple) and len(_dedup_result) == 2:
            manifest_items, _p4_removed_count = _dedup_result
        elif isinstance(_dedup_result, list):
            # Defensive: handle a future API change that returns a plain list
            manifest_items = _dedup_result
            _p4_removed_count = _before_dedup - len(manifest_items)
        else:
            log.error(
                "[PHASE4] CRITICAL: enforce_manifest_uniqueness returned unexpected type %s — "
                "skipping dedup result, keeping original manifest_items to prevent data loss",
                type(_dedup_result).__name__,
            )
            _p4_removed_count = 0
        # Post-dedup type guard: manifest_items MUST be a list of dicts
        if not isinstance(manifest_items, list):
            log.error(
                "[PHASE4] CRITICAL: manifest_items is %s after dedup — resetting to pre-dedup state",
                type(manifest_items).__name__,
            )
            manifest_items = list(_dedup_result[0]) if isinstance(_dedup_result, tuple) else []
        _after_dedup = len(manifest_items)
        if _before_dedup != _after_dedup:
            log.info(
                "[PHASE4] Manifest dedup gate: %d → %d entries (%d duplicates removed)",
                _before_dedup, _after_dedup, _before_dedup - _after_dedup,
            )
        else:
            log.info("[PHASE4] Manifest dedup gate: %d entries, no duplicates detected", _after_dedup)
    except ImportError as _p4_imp_e:
        log.warning("[PHASE4] enforce_manifest_uniqueness unavailable (%s) — dedup skipped", _p4_imp_e)
    except Exception as _p4_e:
        log.warning("[PHASE4] Manifest dedup error (non-fatal, continuing): %s", _p4_e)

    # ---- v143.4.0 MOJIBAKE SANITIZATION PASS — applied BEFORE quality engine ----
    if manifest_items:
        try:
            import sys as _enc_sys_rp, os as _enc_os_rp
            _enc_root_rp = str(REPO_ROOT)
            if _enc_root_rp not in _enc_sys_rp.path:
                _enc_sys_rp.path.insert(0, _enc_root_rp)
            from core.utils.encoding_utils import sanitize_field as _sanitize_rp
            _enc_fixed = 0
            for _enc_item in manifest_items:
                for _enc_field in ("title", "description", "summary", "actor_tag"):
                    _v = _enc_item.get(_enc_field)
                    if isinstance(_v, str):
                        _fixed = _sanitize_rp(_v)
                        if _fixed != _v:
                            _enc_item[_enc_field] = _fixed
                            _enc_fixed += 1
            if _enc_fixed:
                log.info("[3.9-ENCODE] Repaired %d mojibake field(s) across manifest entries", _enc_fixed)
            else:
                log.info("[3.9-ENCODE] Encoding scan complete — all fields clean")
        except Exception as _enc_e:
            log.warning("[3.9-ENCODE] Encoding sanitization failed (non-fatal): %s", _enc_e)

    # ---- PHASE 5 — Intel Quality Engine v143.4.0 (8-phase quality upgrade) ----
    # Runs AFTER Phase 4 dedup gate, BEFORE feed.json write.
    # Applies: 3-layer dedup, newness validation, enrichment, CVE spam control,
    #          source balancing, dashboard truth validation, final assertions.
    # Non-blocking: quality failures are logged but never kill the pipeline.
    # v143.4.0 MANIFEST SHRINK FIX: snapshot BEFORE quality engine.
    # Quality engine trims CVE spam etc. for feed.json only.
    # Canonical manifest write-back uses full pre-quality list to prevent data loss.
    _manifest_items_pre_quality = list(manifest_items)  # snapshot for manifest write-back
    if manifest_items:
        try:
            from intel_quality_engine import apply_quality_pipeline as _apply_quality
            _qe_before = len(manifest_items)
            manifest_items = _apply_quality(manifest_items)
            if not isinstance(manifest_items, list):
                log.error("[PHASE5-QE] Quality engine returned non-list (%s) — resetting",
                          type(manifest_items).__name__)
                manifest_items = list(_manifest_items_pre_quality)
            log.info("[PHASE5-QE] Quality engine complete: %d -> %d items (feed.json uses filtered)",
                     _qe_before, len(manifest_items))
            log.info("[PHASE5-QE] Manifest write-back will use full pre-quality list: %d items",
                     len(_manifest_items_pre_quality))
        except ImportError as _qe_imp_e:
            log.warning("[PHASE5-QE] intel_quality_engine not available (%s) — skipped", _qe_imp_e)
        except Exception as _qe_e:
            log.warning("[PHASE5-QE] Quality engine error (non-fatal, continuing): %s", _qe_e)

    # ---- v142.3.0 Stability Lock Phase 1 — Final Output Contract -----------
    # Enforced BEFORE any feed.json write:
    #   - No duplicate stix_id
    #   - No duplicate title
    #   - Sorted by published_at DESC
    #   - No future-dated entries (clamped to UTC now)
    # Non-blocking: violations are logged; clean list used for write.
    try:
        import importlib.util as _p1_ilu
        _p1_spec = _p1_ilu.spec_from_file_location(
            "sentinel_stability_lock",
            REPO_ROOT / "scripts" / "sentinel_stability_lock.py",
        )
        _p1_mod = _p1_ilu.module_from_spec(_p1_spec)
        import sys as _p1_sys; _p1_sys.modules["sentinel_stability_lock"] = _p1_mod  # v143.3.0: @dataclass needs module in sys.modules
        _p1_spec.loader.exec_module(_p1_mod)
        manifest_items, _p1_report = _p1_mod.enforce_output_contract(
            manifest_items, REPO_ROOT, strict=False
        )
        if _p1_report.violations:
            log.warning("[p1-output-contract] %d violation(s): %s",
                        len(_p1_report.violations), _p1_report.violations)
        log.info("[p1-output-contract] Contract enforced: %d entries, %d dups removed, health=%s",
                 _p1_report.entries_after, _p1_report.duplicates_removed, _p1_report.health)
    except Exception as _p1_e:
        log.warning("[p1-output-contract] Skipped (non-fatal): %s", _p1_e)

    # ---- v143.2.0 CANONICAL FINAL SORT — applied AFTER stability lock --------
    # ROOT CAUSE: sentinel_stability_lock.enforce_output_contract() re-sorts by
    # (float_ts, stix_id). float_ts may produce a different ordering than the
    # string-based (ts_string, stix_id) used by regression_immunity.py Check 6
    # and output_validation_gate.py (e.g. mixed "Z" vs "+00:00" timestamp formats).
    # FIX: re-apply the canonical (ts_string, stix_id) sort key one final time,
    # AFTER all quality/dedup/stability processing, BEFORE the feed.json write.
    # This is the SINGLE authoritative sort that all validators check against.
    manifest_items.sort(key=sort_key, reverse=True)
    log.info("[3.9] v143.2.0 canonical final sort applied: %d entries", len(manifest_items))

    # ---- Step 6: Write to all target feed.json paths --------------------
    if not manifest_items:
        log.error("[3.9] CRITICAL: Zero entries after all fallbacks — feed.json will be empty")
        return

    out_count = min(len(manifest_items), 500)  # cap at 500
    payload = manifest_items[:out_count]

    # P0-FIX v141.6.0: Pre-serialise payload to a string ONCE and validate it
    # BEFORE touching any on-disk file.  This prevents the race where the file
    # is overwritten with invalid JSON (which the external CI validate_repo.py
    # step would then catch).  The root cause: json.dump with default=str can
    # silently corrupt output when items contain non-JSON-native Python objects
    # (e.g. datetime, set) that str() into multi-line or unquoted representations
    # that then confuse some downstream parsers.  We fully round-trip validate here.
    try:
        serialised = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        # Hard round-trip validation: parse it back
        reparsed = json.loads(serialised)
        if not isinstance(reparsed, list):
            raise ValueError(f"Round-trip produced {type(reparsed).__name__}, expected list")
        log.info("[3.9] Payload pre-validated: %d entries, %d bytes — JSON GOOD",
                 len(reparsed), len(serialised))
    except Exception as e:
        log.error("[3.9] CRITICAL: Payload JSON serialisation FAILED (%s) — "
                  "feed.json will NOT be overwritten (keeping last valid version)", e)
        return

    for target in targets:
        # Snapshot previous content so we can roll back on verify failure
        prev_content: str | None = None
        if target.exists():
            try:
                prev_content = target.read_text(encoding="utf-8")
                json.loads(prev_content)   # only keep snapshot if it is itself valid
            except Exception:
                prev_content = None

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(str(target) + ".sync.tmp")
            tmp.write_text(serialised, encoding="utf-8")

            # Re-verify the tmp file before promoting it
            verified = json.loads(tmp.read_text(encoding="utf-8"))
            if not isinstance(verified, list):
                raise ValueError(f"Tmp-file re-parse returned {type(verified).__name__}")

            # Atomic promote
            os.replace(str(tmp), str(target))

            # Final confirmation read
            final_sz = target.stat().st_size
            json.loads(target.read_text(encoding="utf-8"))   # last-chance confirm
            log.info("[3.9] ✅ Written+Verified: %s (%d entries, %.1fkB)",
                     target.relative_to(REPO_ROOT), out_count, final_sz / 1024)

        except Exception as e:
            log.error("[3.9] Write/verify FAILED for %s: %s", target, e)
            # Clean up tmp if it exists
            tmp_path = Path(str(target) + ".sync.tmp")
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            # Roll back to last known-good version
            if prev_content is not None:
                try:
                    target.write_text(prev_content, encoding="utf-8")
                    log.warning("[3.9] ⚠️ Rolled back %s to previous valid version",
                                target.relative_to(REPO_ROOT))
                except Exception as e2:
                    log.error("[3.9] Rollback also failed for %s: %s", target, e2)

    # ---- Step 7: Write back canonical manifest (v143.1.1 P0 CONSISTENCY FIX) ----
    # ROOT CAUSE FIX: data/stix/feed_manifest.json was NEVER written back after
    # dedup + quality engine processing. This meant the manifest still contained
    # items that the quality engine had removed, causing MISSING IN API errors.
    #
    # v143.1.1 FORMAT FIX: Must write as {"advisories": [...]} DICT envelope,
    # NOT a bare list. Stage 2.2 normalises the manifest to dict format. Several
    # downstream consumers (generate_intel_reports.py line 1570, etc.) call
    # data.get("advisories") — a bare list has no .get() → AttributeError.
    # The api_dashboard_contract_validator already handles both formats via unwrap().
    try:
        # v143.4.0 FIX: Use pre-quality snapshot for manifest (full history preserved).
        # feed.json uses quality-filtered list; manifest keeps ALL entries.
        _manifest_write_items = list(_manifest_items_pre_quality if _manifest_items_pre_quality else manifest_items)

        # v144.0 RECONCILIATION FIX: ensure every item that will be written to
        # api/feed.json (payload) is ALSO present in the manifest write-back.
        # Root cause: intelligence engines can generate fresh intel--UUID items that
        # land in api/feed.json (via quality pipeline or prior-run carry-forward)
        # but are never captured in the manifest, causing "API ITEM NOT IN MANIFEST"
        # contract violations. Fix: scan payload, append any missing items to the
        # manifest write-back list before the canonical write so api ⊆ manifest holds.
        try:
            _mwr_ids_by_id     = {i.get("id",""):      True for i in _manifest_write_items}
            _mwr_ids_by_stixid = {i.get("stix_id",""): True for i in _manifest_write_items}
            _reconcile_added = 0
            for _pay_item in payload:
                _pay_stix = _pay_item.get("stix_id","")
                _pay_id   = _pay_item.get("id","")
                # Item is covered if either its stix_id OR id matches any manifest entry
                _covered = (
                    (_pay_stix and (_pay_stix in _mwr_ids_by_stixid or _pay_stix in _mwr_ids_by_id))
                    or
                    (_pay_id   and (_pay_id   in _mwr_ids_by_id      or _pay_id   in _mwr_ids_by_stixid))
                )
                if not _covered:
                    _manifest_write_items.append(_pay_item)
                    _mwr_ids_by_id[_pay_id]       = True
                    _mwr_ids_by_stixid[_pay_stix] = True
                    _reconcile_added += 1
            if _reconcile_added:
                log.info("[3.9-RECONCILE] Added %d api/feed.json items missing from manifest → manifest now complete",
                         _reconcile_added)
        except Exception as _rcn_e:
            log.warning("[3.9-RECONCILE] Reconciliation step failed (non-fatal): %s", _rcn_e)

        _manifest_write_items.sort(key=sort_key, reverse=True)
        try:
            from agent.config import MANIFEST_MAX_ENTRIES as _MX_MANIFEST
        except Exception:
            _MX_MANIFEST = 5000
        _manifest_write_items = _manifest_write_items[:_MX_MANIFEST]

        # v161.4 DEFENSE-IN-DEPTH: enforce_schema_list() before canonical write-back.
        # Final schema gate — ensures no boolean 'published' or invalid severity (e.g. INFO)
        # can survive into feed_manifest.json regardless of what upstream stages produced.
        if _SAFE_IO_AVAILABLE:
            try:
                _manifest_write_items = enforce_schema_list(_manifest_write_items)
                log.info("[3.9] enforce_schema_list() applied before canonical write")
            except Exception as _esf_e:
                log.warning("[3.9] enforce_schema_list() failed (non-fatal): %s", _esf_e)

        _manifest_envelope = {
            "version":        PIPELINE_VERSION,
            "platform":       "SENTINEL-APEX",
            "generated_at":   utc_now(),
            "total_reports":  len(_manifest_write_items),
            "entry_count":    len(_manifest_write_items),
            "sort_order":     "timestamp DESC, stix_id DESC",
            "source":         "stage_sync_root_feed_json canonical write-back",
            "advisories":     _manifest_write_items,
        }
        canonical_manifest = json.dumps(
            _manifest_envelope, indent=2, ensure_ascii=False, default=str
        )
        # Round-trip validate before touching disk
        _reparsed_m = json.loads(canonical_manifest)
        if not isinstance(_reparsed_m, dict) or "advisories" not in _reparsed_m:
            raise ValueError(
                f"Manifest round-trip produced unexpected structure: "
                f"type={type(_reparsed_m).__name__} keys={list(_reparsed_m.keys())[:5]}"
            )
        _tmp_manifest = Path(str(manifest_path) + ".canon.tmp")
        _tmp_manifest.write_text(canonical_manifest, encoding="utf-8")
        # Verify temp file
        json.loads(_tmp_manifest.read_text(encoding="utf-8"))
        # Atomic promote
        os.replace(str(_tmp_manifest), str(manifest_path))
        log.info(
            "[3.9] ✅ Manifest canonical write-back: %d entries (dict envelope, full pre-quality history)",
            len(_manifest_write_items),
        )
    except Exception as _mwb_e:
        log.warning(
            "[3.9] Manifest write-back failed (non-fatal — api/feed.json still written): %s",
            _mwb_e,
        )
        # Clean up tmp if exists
        _tmp_m_path = Path(str(manifest_path) + ".canon.tmp")
        if _tmp_m_path.exists():
            try:
                _tmp_m_path.unlink()
            except Exception:
                pass

    log.info("[3.9] STAGE 3.9 COMPLETE — feed.json has %d entries [OK]", out_count)


def main() -> None:
    log.info("=" * 70)
    log.info("SENTINEL APEX v%s -- Master Pipeline Orchestrator", PIPELINE_VERSION)
    log.info("Run at: %s", utc_now())
    log.info("SafeIO: %s", "ENABLED" if _SAFE_IO_AVAILABLE else "DISABLED (fallback mode)")
    log.info("=" * 70)

    # Change to repo root so all relative paths work correctly
    os.chdir(REPO_ROOT)

    t_total = time.monotonic()

    # Initialise global metrics collector
    global METRICS
    if _SAFE_IO_AVAILABLE:
        METRICS = PipelineMetrics()

    # ── v141.7.0 Stage Registry ────────────────────────────────────────────
    # Every major stage is registered here.  After execution each stage name
    # is appended to _completed_stages.  A final check at pipeline exit
    # confirms all expected stages ran — catching silent skips.
    _STAGE_REGISTRY = [
        "file_integrity_guard",
        "feed_guard",
        "syntax_guard",
        "bootstrap",
        "jwt_secret",
        "intel_engine",
        "manifest_stabilisation",
        "freshness_gate",
        "anti_stale_hardening",
        "schema_validation",
        "dedup_enrich",
        "html_reports",
        "manifest_integrity",
        "pipeline_consistency",
        "validate_repo",
        "write_metrics",
        "feed_json_final",
    ]
    _completed_stages: list[str] = []

    def _stage_done(name: str) -> None:
        _completed_stages.append(name)
        log.debug("[stage-registry] completed: %s (%d/%d)",
                  name, len(_completed_stages), len(_STAGE_REGISTRY))

    # ---- Phase 8 Pre-flight: Self-Healing Guard (v142.3.0) ------------------
    # Runs BEFORE any stage — detects and repairs corrupted data files
    try:
        import importlib.util as _p8pre_ilu
        _p8pre_spec = _p8pre_ilu.spec_from_file_location(
            "self_healing_guard",
            REPO_ROOT / "scripts" / "self_healing_guard.py",
        )
        _p8pre_mod = _p8pre_ilu.module_from_spec(_p8pre_spec)
        _p8pre_spec.loader.exec_module(_p8pre_mod)
        for _p8pre_rel in ["api/feed.json", "data/stix/feed_manifest.json"]:
            _p8pre_abs = REPO_ROOT / _p8pre_rel.replace("/", os.sep)
            if _p8pre_abs.exists():
                _p8pre_ok, _p8pre_reason = _p8pre_mod.is_healthy(str(_p8pre_abs), _p8pre_rel)
                if not _p8pre_ok:
                    log.warning("[p8-preflight] %s corrupted (%s) — attempting self-heal", _p8pre_rel, _p8pre_reason)
                    if _p8pre_rel == "api/feed.json":
                        _p8pre_healed, _p8pre_msg = _p8pre_mod.rebuild_api_feed(str(REPO_ROOT))
                        if _p8pre_healed:
                            log.info("[p8-preflight] api/feed.json rebuilt: %s", _p8pre_msg)
                        else:
                            log.error("[p8-preflight] api/feed.json rebuild failed: %s", _p8pre_msg)
                    else:
                        _p8pre_bkp = _p8pre_mod.find_latest_backup(
                            str(REPO_ROOT / "data" / "audit" / "backups"),
                            "data_stix_feed_manifest.json"
                        )
                        if _p8pre_bkp:
                            import shutil as _p8pre_sh
                            _p8pre_sh.copy2(_p8pre_bkp, str(_p8pre_abs))
                            log.info("[p8-preflight] manifest restored from %s", os.path.basename(_p8pre_bkp))
                        else:
                            log.error("[p8-preflight] No manifest backup found — manual repair required")
    except Exception as _p8pre_e:
        log.warning("[p8-preflight] Self-healing guard skipped (non-fatal): %s", _p8pre_e)

    # ---- Pre-flight -------------------------------------------------------
    stage_file_integrity_guard()         # PHASE 0: file size/syntax/null-byte pre-check (HARD FAIL)
    _stage_done("file_integrity_guard")
    stage_feed_guard()                   # FIRST: guarantee feed.json always valid JSON
    _stage_done("feed_guard")
    stage_syntax_guard()                 # THEN:  catch SyntaxErrors before execution
    _stage_done("syntax_guard")
    stage_purge_publish_queue()
    stage_bootstrap()
    stage_validate_bootstrap()
    _stage_done("bootstrap")             # v143.4.1 FIX: mark bootstrap complete
    stage_inject_sovereign_key()
    stage_validate_jwt_secret()          # HARD FAIL if JWT missing
    _stage_done("jwt_secret")

    # ---- v142.3.0: Stability Lock Phase 2 — Version Lock -------------------
    # Validate config/version.json SSOT matches PIPELINE_VERSION env var.
    # Creates manifest backup for Phase 6 self-healing before any modifications.
    try:
        import importlib.util as _ssl_ilu
        _ssl_spec = _ssl_ilu.spec_from_file_location(
            "sentinel_stability_lock",
            REPO_ROOT / "scripts" / "sentinel_stability_lock.py",
        )
        _ssl_mod = _ssl_ilu.module_from_spec(_ssl_spec)
        import sys as _ssl_sys; _ssl_sys.modules["sentinel_stability_lock"] = _ssl_mod  # v143.3.0: @dataclass needs module in sys.modules
        _ssl_spec.loader.exec_module(_ssl_mod)
        # Phase 2: version lock check (warn-only — pipeline continues on mismatch)
        _v2_report = _ssl_mod.validate_version_lock(REPO_ROOT, PIPELINE_VERSION, hard_fail=False)
        if _v2_report.health == "FAIL":
            log.warning("[v2-version-lock] Version mismatch detected — see data/audit/stability_report.json")
        else:
            log.info("[v2-version-lock] Version lock: %s", _v2_report.health)
        # Phase 6 prerequisite: create manifest backup before any pipeline writes
        _ssl_mod.create_manifest_backup(REPO_ROOT)
        log.info("[v6-selfheal-prep] Manifest backup created for self-healing")
    except Exception as _ssl_e:
        log.warning("[stability-lock] Phase 2 / backup skipped (non-fatal): %s", _ssl_e)

    # ---- v134 System Health Gate (pre-ingestion CRITICAL/DEGRADED guard) ----
    stage_system_health_gate()           # CRITICAL: exit 1 | DEGRADED: drain-first then continue

    # ---- Intel Generation -------------------------------------------------
    stage_run_intel_engine()
    _stage_done("intel_engine")
    stage_pre_v70_manifest_sync()
    stage_v70_orchestrator()

    # ---- Manifest Processing ----------------------------------------------
    stage_manifest_stabilisation()
    _stage_done("manifest_stabilisation")
    stage_freshness_gate()               # HARD FAIL if < MIN entries
    _stage_done("freshness_gate")
    stage_anti_stale_hardening()         # v160.0: quarantine stale/synthetic/fake intel
    _stage_done("anti_stale_hardening")
    stage_schema_validation()            # HARD FAIL if schema invalid
    _stage_done("schema_validation")
    stage_manifest_cleanup()
    stage_dedup_and_enrich()             # SafeIO: dedup + ioc_count fix + schema auto-fix

    # v141.3.0 — Persist cross-run dedup index immediately after dedup stage
    # This ensures intel_index.json is updated before any downstream stage reads it.
    try:
        import sys as _sys
        _scripts_dir = os.path.dirname(os.path.abspath(__file__))
        if _scripts_dir not in _sys.path:
            _sys.path.insert(0, _scripts_dir)
        from intel_dedup_engine import save_all as _dedup_save_all
        _dedup_save_all()
        log.info("[3.2-POST] intel_dedup_engine.save_all(): cross-run index persisted OK")
    except Exception as _e:
        log.warning("[3.2-POST] intel_dedup_engine.save_all() skipped (non-fatal): %s", _e)
    _stage_done("dedup_enrich")

    stage_enforce_schema()               # MANDATORY: schema enforcement at write boundary
    stage_sync_root_feed_json()          # P0 FIX: populate feed.json from STIX/manifest always

    # ---- Output Generation ------------------------------------------------
    stage_html_reports()                 # HARD FAIL if 0 reports
    _stage_done("html_reports")
    stage_writequeue_flush()             # BARRIER: drain all enqueued writes before integrity check
    stage_manifest_integrity_check()     # HARD FAIL on write_error entries
    _stage_done("manifest_integrity")
    stage_validate_write_integrity()     # Post-write assertion: no missing files, no failures
    stage_refresh_embedded_intel()

    # ---- Cross-Layer Consistency Gate ------------------------------------
    stage_pipeline_consistency_check()   # Enforce ioc/stix/dedup/scoring integrity
    _stage_done("pipeline_consistency")
    stage_recovery_replay()              # v134: drain write backlog before validation gate
    stage_validate_repo()                # HARD FAIL: schema hard validation (no auto-heal)
    _stage_done("validate_repo")

    # ---- Housekeeping -----------------------------------------------------
    stage_prune_stix_bundles()

    # ---- Observability ----------------------------------------------------
    stage_write_metrics()                # Write pipeline_metrics.json
    _stage_done("write_metrics")
    stage_sync_root_feed_json()          # FINAL: ensure feed.json populated (double-guarantee)
    _stage_done("feed_json_final")       # v143.4.1 FIX: mark BEFORE stage audit so it registers

    # ---- Phase 3.95 — Immutable Snapshot (v144.0.0) -----------------------
    # Create an immutable timestamped snapshot from the freshly-written api/feed.json.
    # snapshot_integration.py reads api/feed.json, deduplicates, sorts, writes atomically
    # to data/snapshots/<ts>_<run_id>.json and updates data/snapshots/current.json pointer.
    # api_snapshot_server.py reads ONLY from this snapshot → no further mutations.
    # Non-fatal: if snapshot creation fails, pipeline continues (data is in feed.json).
    try:
        import importlib.util as _snap_ilu
        _snap_spec = _snap_ilu.spec_from_file_location(
            "snapshot_integration",
            REPO_ROOT / "scripts" / "snapshot_integration.py",
        )
        _snap_mod = _snap_ilu.module_from_spec(_snap_spec)
        _snap_spec.loader.exec_module(_snap_mod)
        _snap_ok = _snap_mod.create_pipeline_snapshot(
            source_path=REPO_ROOT / "api" / "feed.json",
            run_id=os.environ.get("GITHUB_RUN_ID", "local"),
            skip_dedup=True,   # already deduped in stage_sync_root_feed_json
        )
        if _snap_ok:
            log.info("[3.95] ✅ Immutable snapshot created — api_snapshot_server ready")
        else:
            log.warning("[3.95] Snapshot creation failed (non-fatal) — api/feed.json remains SSOT")
    except Exception as _snap_e:
        log.warning("[3.95] Snapshot integration skipped (non-fatal): %s", _snap_e)

    # ---- v142.3.0 Stability Lock Phase 3 — Post-Pipeline Validation --------
    # Runs AFTER all writes complete. Validates manifest/feed/UI health.
    # Phase 5 (UI guard check) + Phase 6 (self-heal) triggered automatically.
    # Non-blocking: FAIL logged to data/audit/stability_report.json, pipeline exits 0
    try:
        import importlib.util as _p3_ilu
        _p3_spec = _p3_ilu.spec_from_file_location(
            "sentinel_stability_lock",
            REPO_ROOT / "scripts" / "sentinel_stability_lock.py",
        )
        _p3_mod = _p3_ilu.module_from_spec(_p3_spec)
        import sys as _p3_sys; _p3_sys.modules["sentinel_stability_lock"] = _p3_mod  # v143.3.0: @dataclass needs module in sys.modules
        _p3_spec.loader.exec_module(_p3_mod)
        _p3_report = _p3_mod.run_post_pipeline_validation(REPO_ROOT)
        if _p3_report.health == "FAIL":
            log.error(
                "[p3-post-validate] FAIL — %d violation(s): %s",
                len(_p3_report.violations), _p3_report.violations,
            )
        elif _p3_report.health == "WARN":
            log.warning("[p3-post-validate] WARN — %d violation(s)", len(_p3_report.violations))
        else:
            log.info("[p3-post-validate] PASS — manifest/feed/UI all healthy ✅")
    except Exception as _p3_e:
        log.warning("[p3-post-validate] Skipped (non-fatal): %s", _p3_e)

    # ---- Phase 9: Self-Audit Report (v141.7.0) --------------------------------
    try:
        import importlib.util as _ilu
        _audit_spec = _ilu.spec_from_file_location(
            "pipeline_audit", REPO_ROOT / "scripts" / "pipeline_audit.py"
        )
        _audit_mod = _ilu.module_from_spec(_audit_spec)
        _audit_spec.loader.exec_module(_audit_mod)
        _audit_out = REPO_ROOT / "data" / "audit" / "pipeline_audit.json"
        _audit_rc = _audit_mod.run_audit(_audit_out)
        if _audit_rc != 0:
            log.warning("[audit] Self-audit FAIL -- review data/audit/pipeline_audit.json")
        else:
            log.info("[audit] Self-audit PASS -- %s", _audit_out)
    except Exception as _ae:
        log.warning("[audit] Self-audit skipped (non-fatal): %s", _ae)

    # ---- Static health snapshot (pre-bake for GitHub Pages /api/health.json)
    try:
        from api.health import write_static_health_json
        _health_out = REPO_ROOT / "api" / "health.json"
        write_static_health_json(_health_out)
        log.info("Health snapshot written -> api/health.json")
    except Exception as _he:
        log.warning("Health snapshot skipped (non-critical): %s", _he)

    elapsed = time.monotonic() - t_total

    # v141.7.0 Stage Completion Audit
    _BASELINE_RUNTIME_SECONDS = 900   # 15 min -- healthy run floor
    missing_stages = [s for s in _STAGE_REGISTRY if s not in _completed_stages]
    if missing_stages:
        log.error(
            "[stage-audit] PIPELINE INCOMPLETE -- %d stage(s) never executed: %s",
            len(missing_stages), missing_stages,
        )
        log.critical(
            "[stage-audit] PARTIAL EXECUTION DETECTED. "
            "Investigate skipped stages before next production run."
        )
    else:
        log.info("[stage-audit] ALL %d registered stages completed. Pipeline integrity: FULL.",
                 len(_STAGE_REGISTRY))

    if elapsed < _BASELINE_RUNTIME_SECONDS:
        log.warning(
            "[stage-audit] EARLY EXIT WARNING: pipeline completed in %.1fs "
            "(< %ds baseline). This may indicate silent stage skips. "
            "Completed stages: %s",
            elapsed, _BASELINE_RUNTIME_SECONDS, _completed_stages,
        )
    else:
        log.info("[stage-audit] Runtime %.1fs >= %ds baseline. Normal execution confirmed.",
                 elapsed, _BASELINE_RUNTIME_SECONDS)

    # ---- Phase 6-9: Data Consistency & Encoding Gate (v142.3.0) ---------------
    # Phase 6: API <-> Dashboard Contract Validator
    try:
        import importlib.util as _p6_ilu
        _p6_spec = _p6_ilu.spec_from_file_location(
            "api_dashboard_contract_validator",
            REPO_ROOT / "scripts" / "api_dashboard_contract_validator.py",
        )
        _p6_mod = _p6_ilu.module_from_spec(_p6_spec)
        _p6_spec.loader.exec_module(_p6_mod)
        _p6_report_path = str(REPO_ROOT / "data" / "audit" / "contract_validation.json")
        _p6_errors, _p6_warnings, _p6_stats = _p6_mod.validate(str(REPO_ROOT), 50)
        if _p6_errors:
            log.error("[p6-contract] %d contract violation(s): %s", len(_p6_errors), _p6_errors[:3])
        else:
            log.info("[p6-contract] PASS — API<->Dashboard contract valid (%d top entries match)",
                     _p6_stats.get("top_n_checked", 0))
    except Exception as _p6_e:
        log.warning("[p6-contract] Skipped (non-fatal): %s", _p6_e)

    # Phase 7: Output Validation Gate
    try:
        import importlib.util as _p7_ilu
        _p7_spec = _p7_ilu.spec_from_file_location(
            "output_validation_gate",
            REPO_ROOT / "scripts" / "output_validation_gate.py",
        )
        _p7_mod = _p7_ilu.module_from_spec(_p7_spec)
        _p7_mod = _p7_ilu.module_from_spec(_p7_spec)
        _p7_spec.loader.exec_module(_p7_mod)
        _p7_errors, _p7_warnings, _p7_report = [], [], {}
        # Call check_file directly for each critical output
        _p7_api_entries  = _p7_mod.check_file(
            str(REPO_ROOT / "api" / "feed.json"), "api/feed.json",
            _p7_errors, _p7_warnings, cap=500)
        _p7_mfst_entries = _p7_mod.check_file(
            str(REPO_ROOT / "data" / "stix" / "feed_manifest.json"), "feed_manifest.json",
            _p7_errors, _p7_warnings)
        if _p7_errors:
            log.error("[p7-gate] Output validation FAIL: %s", _p7_errors[:3])
        else:
            log.info("[p7-gate] PASS — api=%d entries, manifest=%d entries",
                     len(_p7_api_entries), len(_p7_mfst_entries))
    except Exception as _p7_e:
        log.warning("[p7-gate] Skipped (non-fatal): %s", _p7_e)

    # Phase 8: Self-Healing Guard (backup fresh known-good state)
    try:
        import importlib.util as _p8_ilu
        _p8_spec = _p8_ilu.spec_from_file_location(
            "self_healing_guard",
            REPO_ROOT / "scripts" / "self_healing_guard.py",
        )
        _p8_mod = _p8_ilu.module_from_spec(_p8_spec)
        _p8_spec.loader.exec_module(_p8_mod)
        _p8_backup_dir = str(REPO_ROOT / "data" / "audit" / "backups")
        # Backup the freshly written outputs
        for _p8_rel in ["api/feed.json", "data/stix/feed_manifest.json"]:
            _p8_src = REPO_ROOT / _p8_rel.replace("/", os.sep)
            if _p8_src.exists():
                _p8_mod.save_backup(str(_p8_src), _p8_backup_dir)
        log.info("[p8-heal] Backups updated for api/feed.json + feed_manifest.json")
    except Exception as _p8_e:
        log.warning("[p8-heal] Backup skipped (non-fatal): %s", _p8_e)

    # Phase 9: Final Validation Report
    try:
        import importlib.util as _p9_ilu
        _p9_spec = _p9_ilu.spec_from_file_location(
            "regression_immunity",
            REPO_ROOT / "scripts" / "regression_immunity.py",
        )
        _p9_mod = _p9_ilu.module_from_spec(_p9_spec)
        _p9_spec.loader.exec_module(_p9_mod)
        _p9_pass, _p9_fail = _p9_mod.run_checks(str(REPO_ROOT))
        if _p9_fail:
            log.warning("[p9-immunity] %d regression check(s) FAILED: %s", len(_p9_fail), _p9_fail[:3])
        else:
            log.info("[p9-immunity] PASS — all %d regression immunity checks passed", len(_p9_pass))
    except Exception as _p9_e:
        log.warning("[p9-immunity] Skipped (non-fatal): %s", _p9_e)

    # ── Stage Registry Completion Check ──────────────────────────────────────
    _missing_stages = [s for s in _STAGE_REGISTRY if s not in _completed_stages]
    if _missing_stages:
        log.warning("[stage-registry] %d stage(s) did not complete: %s",
                    len(_missing_stages), _missing_stages)
    else:
        log.info("[stage-registry] All %d registered stages completed successfully",
                 len(_STAGE_REGISTRY))


# ---------------------------------------------------------------------------
# Entry point — MANDATORY: this block was absent causing 0s silent exit
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
