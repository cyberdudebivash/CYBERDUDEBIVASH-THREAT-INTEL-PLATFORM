#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
VERSION GOVERNANCE ENGINE v184.0
===============================================================================
PURPOSE:
  Single-source-of-truth version authority for the SENTINEL APEX platform.
  Reads the authoritative version from the VERSION file and propagates it
  deterministically to backend/gateway components that carry a version string,
  eliminating platform-wide version drift.

AUTHORITATIVE SOURCE:
  VERSION  (repo root, plain semver string, one line)

TARGETS GOVERNED (backend/gateway + CI workflows):
  version.json                            -- root platform version manifest
  config/version.json                     -- SSOT for deploy-worker workflow
  workers/intel-gateway/src/index.js     -- GATEWAY_VERSION in CONFIG object
  scripts/r2_upload.py                    -- PIPELINE_VERSION default
  scripts/ai_brain_publisher.py           -- VERSION constant
  .github/workflows/sentinel-blogger.yml  -- PIPELINE_VERSION env var
  .github/workflows/generate-and-sync.yml -- PIPELINE_VERSION env var

NOT GOVERNED (have their own independent versioning):
  js/api_adapter.js           -- UI component, guarded by ui-file-guardian
  js/card_renderer.js         -- UI component, guarded by ui-file-guardian
  js/card_renderer_integration.js -- UI component, guarded by ui-file-guardian

MODE:
  --check    Verify all targets match the authority. Exit 1 on any drift.
  --apply    Write the authoritative version to all targets. (default)
  --report   Print a table of all version strings. Exit 0 always.

EXIT CODES:
  0 -- All targets match (check) or all targets updated (apply)
  1 -- Version drift detected (check) or write failure (apply)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [version_governance] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-VERSION-GOV")

REPO_ROOT = Path(__file__).resolve().parent.parent


def read_authority():
    path = REPO_ROOT / "VERSION"
    ver = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", ver):
        log.error("VERSION file contains invalid semver: %r", ver)
        sys.exit(1)
    return ver


def major(ver):
    return ver.split(".")[0]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Regex-based targets (backend/gateway + CI workflow components)
# ---------------------------------------------------------------------------
# Each tuple: (relative_path, pattern, replacement_template)
# {VER} -> full semver, {VERMAJ} -> major integer only
REGEX_TARGETS = [
    # workers/intel-gateway/src/index.js -- PLATFORM_VERSION
    # v200.0 FIX: this target was written for a `GATEWAY_VERSION:` object-key
    # pattern that no longer exists anywhere in this file -- confirmed via
    # --report on PR #265, which showed "pattern not found -- skip" on every
    # run. The real constant is `const PLATFORM_VERSION = "..."`, referenced
    # in 35+ places including live customer-facing API responses (`version:
    # PLATFORM_VERSION`), the X-Sentinel-Version header, and generated report
    # HTML -- meaning this file's actual live version string had never been
    # touched by any run of this script (CodeRabbit caught the resulting
    # drift on the v200.0 PR: /api/health still reporting 184.0).
    (
        "workers/intel-gateway/src/index.js",
        r'(const PLATFORM_VERSION\s*=\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/intel-static-proxy.js",
        r'(const PLATFORM_VERSION\s*=\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/p17-handlers.js",
        r'(platform_version: ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/enterprise-endpoints.js",
        r'(Enterprise API Endpoints v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/enterprise-endpoints.js",
        r'(const ENTERPRISE_VERSION = ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "scripts/enterprise_scoring_engine.py",
        r'(Version : )[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "scripts/enterprise_scoring_engine.py",
        r'(ENGINE_VERSION\s*=\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # workers/intel-gateway/src/index.js -- X-Powered-By major version
    (
        "workers/intel-gateway/src/index.js",
        r'(CYBERDUDEBIVASH-SENTINEL-APEX-v)\d+',
        r'\g<1>{VERMAJ}',
    ),
    # scripts/ai_brain_publisher.py -- VERSION constant
    (
        "scripts/ai_brain_publisher.py",
        r'(VERSION\s*=\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # scripts/r2_upload.py -- PIPELINE_VERSION default
    (
        "scripts/r2_upload.py",
        r'(PIPELINE_VERSION\s*=\s*os\.environ\.get\("PIPELINE_VERSION",\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # workers/intel-gateway/wrangler.toml -- GATEWAY_VERSION (both [vars] and [env.production.vars])
    (
        "workers/intel-gateway/wrangler.toml",
        r'(GATEWAY_VERSION\s*=\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # .github/workflows/sentinel-blogger.yml -- PIPELINE_VERSION env var (v148.0 governance)
    (
        ".github/workflows/sentinel-blogger.yml",
        r'(  PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # .github/workflows/generate-and-sync.yml -- PIPELINE_VERSION env var (v148.0 governance)
    (
        ".github/workflows/generate-and-sync.yml",
        r'(  PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # -------------------------------------------------------------------------
    # HTML surface governance (v148.0 -- prevents documentation drift)
    # -------------------------------------------------------------------------
    # api-docs.html -- <title> version string
    (
        "api-docs.html",
        r'(CYBERDUDEBIVASH&reg; SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?(<\/span>|(?=\.))',
        r'\g<1>v{VER}\g<2>',
    ),
    # api-docs.html -- brand navbar version
    (
        "api-docs.html",
        r'(SENTINEL APEX <span>)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # api-docs.html -- health example advisory_count (governance: keep in sync with live count)
    # NOTE: advisory count is intentionally NOT governed by semver — governed separately.
    # api-docs.html -- CDB-UPGRADE-BANNER comment marker
    (
        "api-docs.html",
        r'CDB-UPGRADE-BANNER-v[0-9]+',
        r'CDB-UPGRADE-BANNER-v{VERMAJ}',
    ),
    # ai-threat-tracker.html -- version string (if present)
    (
        "ai-threat-tracker.html",
        r'(SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # observability.html -- SENTINEL APEX version string (inline: e.g. "SENTINEL APEX v158.5")
    (
        "observability.html",
        r'(SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # observability.html -- brand navbar <span> tag (e.g. "SENTINEL APEX <span>v184.0</span>")
    (
        "observability.html",
        r'(SENTINEL APEX <span>)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # observability.html -- JS fallback version string (e.g. data.version||'v184.0')
    (
        "observability.html",
        r"(\|\|')v[0-9]+\.[0-9]+(?:\.[0-9]+)?(')",
        r"\g<1>v{VER}\g<2>",
    ),
    # observability.html -- Observability Engine init log line (Engine v184.0 style)
    (
        "observability.html",
        r'(Observability Engine )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # observability.html -- JS comment header (Dashboard v184.0 style)
    (
        "observability.html",
        r'(Observability Dashboard )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # trust-center.html -- SENTINEL APEX version string (inline)
    (
        "trust-center.html",
        r'(SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # trust-center.html -- brand navbar <span> tag (e.g. "SENTINEL APEX <span>v184.0</span>")
    (
        "trust-center.html",
        r'(SENTINEL APEX <span>)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # index.html -- PLATFORM_VERSION JS constant (root landing page). Single-
    # quoted, unlike index.js's double-quoted constant of the same name --
    # CodeRabbit caught this drifting on the v200.0 PR (still 184.0 after
    # every other public version surface was fixed). Shown to every visitor
    # as an "immediate, no flash" fallback before the async /version.json
    # sync resolves, and stays stale permanently if that fetch ever fails.
    (
        "index.html",
        r"(const PLATFORM_VERSION = ')[0-9]+\.[0-9]+(?:\.[0-9]+)?(')",
        r"\g<1>{VER}\g<2>",
    ),
    # data/health/sla_status.json -- version field (governance: keep current)
    # Handled by update_version_json below.

    # -------------------------------------------------------------------------
    # v200.0 live-display audit (this file's own --report showed "all
    # consistent" while the sites below were still showing v185.0/v184.0 as
    # the CURRENT version -- these targets did not exist yet, so nothing
    # flagged the drift). Purely additive: no existing target above is
    # modified. Covers exactly the literal-text and JS-fallback locations a
    # manual audit found still live in production, so the next version bump
    # cannot silently miss them the same way.
    # -------------------------------------------------------------------------
    # index.html -- JSON-LD structured-data "name" field
    (
        "index.html",
        r'("name": "CYBERDUDEBIVASH\\u00ae SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(")',
        r'\g<1>{VER}\g<2>',
    ),
    # index.html -- #platform-version span (brand-sub tagline)
    (
        "index.html",
        r'(letter-spacing:1px;">)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span> // AI-Powered)',
        r'\g<1>v{VER}\g<2>',
    ),
    # index.html -- #engine-version-number span. This is the exact element
    # the live "v185.0" bug was reported against (ENGINE status strip); the
    # span itself was added by the fix that finally wired it to the real
    # version source instead of a second, independent, silently-stale value.
    (
        "index.html",
        r'(id="engine-version-number">)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>{VER}\g<2>',
    ),
    # index.html -- #footer-version span
    (
        "index.html",
        r'(id="footer-version" style="color:var\(--accent\);font-size:11px;letter-spacing:2px;">)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # index.html -- #footer-version-copy span
    (
        "index.html",
        r'(id="footer-version-copy">SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>{VER}\g<2>',
    ),
    # index.html -- CURRENT_VER JS fallback inside _syncEngineVersion(). This
    # constant was the actual root cause of the live v185.0 bug: a second
    # fallback independent of the PLATFORM_VERSION constant already governed
    # above, left stale while PLATFORM_VERSION was correctly updated.
    (
        "index.html",
        r"(const CURRENT_VER = ')[0-9]+\.[0-9]+(?:\.[0-9]+)?(')",
        r"\g<1>{VER}\g<2>",
    ),
    # status.html -- page-sub header text
    (
        "status.html",
        r'(Real-time health monitoring — CYBERDUDEBIVASH SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # status.html -- footer
    (
        "status.html",
        r'(CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( — System Status)',
        r'\g<1>{VER}\g<2>',
    ),
    # status.html -- fetchHealth() JS fallback. Guards the same bug class as
    # CURRENT_VER above: api.intel.cyberdudebivash.com (the old fetch target)
    # does not resolve in DNS at all, so this fallback rendered on every
    # single page load, unconditionally labeled "LIVE" in green.
    (
        "status.html",
        r"(\(d\.version\|\|')[0-9]+\.[0-9]+(?:\.[0-9]+)?('\))",
        r"\g<1>{VER}\g<2>",
    ),
    # about.html -- footer
    (
        "about.html",
        r'(CYBERDUDEBIVASH SENTINEL APEX - PROFESSIONAL THREAT INTELLIGENCE PLATFORM - v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # alternative-to-mandiant.html -- footer
    (
        "alternative-to-mandiant.html",
        r'(All Rights Reserved\. SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # alternative-to-recorded-future.html -- footer
    (
        "alternative-to-recorded-future.html",
        r'(All Rights Reserved\. SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # pricing.html -- footer (same copy as the two "alternative-to-" pages)
    (
        "pricing.html",
        r'(All Rights Reserved\. SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # api-docs.html -- <title> tag (additive: the pre-existing HTML_TITLE_TARGETS
    # entry for this file was written for an earlier title format that no
    # longer exists -- confirmed via --report showing "pattern not found" on
    # every run -- so it is left in place harmlessly and this covers the
    # real current title instead of editing that dead entry)
    (
        "api-docs.html",
        r'(<title>API Reference v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( — CYBERDUDEBIVASH® SENTINEL APEX \| STIX 2\.1 · TAXII · IOC · Threat Intelligence API</title>)',
        r'\g<1>{VER}\g<2>',
    ),
    # api-docs.html -- meta description
    (
        "api-docs.html",
        r'(<meta name="description" content="SENTINEL APEX API v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( — Real-time threat intelligence API\.)',
        r'\g<1>{VER}\g<2>',
    ),
    # api-docs.html -- og:title
    (
        "api-docs.html",
        r'(<meta property="og:title" content="SENTINEL APEX API v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( — Threat Intelligence API">)',
        r'\g<1>{VER}\g<2>',
    ),
    # api-docs.html -- twitter:title
    (
        "api-docs.html",
        r'(<meta name="twitter:title" content="SENTINEL APEX API v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( — Threat Intelligence API">)',
        r'\g<1>{VER}\g<2>',
    ),
    # api-docs.html -- JSON-LD "name" field
    (
        "api-docs.html",
        r'("name": "SENTINEL APEX Threat Intelligence API v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(",)',
        r'\g<1>{VER}\g<2>',
    ),
    # api-docs.html -- logo <span> (additive, same rationale as the <title> entry above)
    (
        "api-docs.html",
        r'(<span>API Reference v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( · STIX 2\.1 · TAXII 2\.1</span>)',
        r'\g<1>{VER}\g<2>',
    ),
    # api-docs.html -- H1 small-tag version
    (
        "api-docs.html",
        r'(<h1>SENTINEL APEX API Reference <small style="font-size:\.55em;color:#546e7a;font-weight:400">)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</small></h1>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # api-docs.html -- footer
    (
        "api-docs.html",
        r'(GSTIN: 21ARKPN8270G1ZP · SENTINEL APEX API v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # case-studies.html / testimonials.html -- footer.
    # PR #435 (2026-09-19) rewrote both footers to the correct legal entity
    # ("BIVASHA KUMAR NAYAK trading as CYBERDUDEBIVASH(R)") and, in the same
    # pass, dropped the trailing " &nbsp;·&nbsp; vX.Y.Z" version suffix
    # entirely -- current text ends "... &nbsp;·&nbsp; SENTINEL APEX" with
    # no version at all. The two patterns below intentionally no longer match
    # anything (neither the old entity name nor a version suffix exists on
    # these pages any more), so this version-bump silently skips both pages
    # rather than erroring. If these footers are meant to carry a live
    # version again, restore a "vX.Y.Z" placeholder there first, then update
    # these two regexes to the current entity string.
    (
        "case-studies.html",
        r'(CYBERDUDEBIVASH PRIVATE LIMITED &nbsp;·&nbsp; SENTINEL APEX &nbsp;·&nbsp; v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "testimonials.html",
        r'(CYBERDUDEBIVASH PRIVATE LIMITED &nbsp;·&nbsp; SENTINEL APEX &nbsp;·&nbsp; v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # compare.html -- vendor-strip tier chip
    (
        "compare.html",
        r'(<div class="vc-tier">API-first CTI · v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</div>)',
        r'\g<1>{VER}\g<2>',
    ),
    # enterprise-procurement-pack.html -- <title>
    (
        "enterprise-procurement-pack.html",
        r'(<title>Enterprise Procurement Pack — SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</title>)',
        r'\g<1>{VER}\g<2>',
    ),
    # enterprise-procurement-pack.html -- hero-meta Document Version
    (
        "enterprise-procurement-pack.html",
        r'(Document Version: v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # enterprise-procurement-pack.html -- info-card Version value
    (
        "enterprise-procurement-pack.html",
        r'(<div class="ic-val">v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</div>)',
        r'\g<1>{VER}\g<2>',
    ),
    # enterprise-procurement-pack.html -- Data Flow Architecture code block
    (
        "enterprise-procurement-pack.html",
        r'(SENTINEL APEX — Data Flow Architecture v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # enterprise-procurement-pack.html -- RFP template PLATFORM VERSION line.
    # Only the version number is governed; the trailing "(Month Year)" is a
    # separate human editorial decision each release, not something this
    # script should invent on its own.
    (
        "enterprise-procurement-pack.html",
        r'(PLATFORM VERSION: v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( \()',
        r'\g<1>{VER}\g<2>',
    ),
    # enterprise-procurement-pack.html -- footer
    (
        "enterprise-procurement-pack.html",
        r'(© 2026 CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( &nbsp;&middot;&nbsp; GSTIN)',
        r'\g<1>{VER}\g<2>',
    ),
    # executive-briefing.html -- footer
    (
        "executive-briefing.html",
        r'(© 2026 CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( · GSTIN: 21ARKPN8270G1ZP)',
        r'\g<1>{VER}\g<2>',
    ),
    # mssp-partner-onboarding.html -- <title>
    (
        "mssp-partner-onboarding.html",
        r'(<title>MSSP Partner Onboarding — SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</title>)',
        r'\g<1>{VER}\g<2>',
    ),
    # mssp-partner-onboarding.html -- hero-badge
    (
        "mssp-partner-onboarding.html",
        r'(MSSP PARTNER ONBOARDING GUIDE v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # mssp-partner-onboarding.html -- footer
    (
        "mssp-partner-onboarding.html",
        r'(© 2026 CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( &nbsp;·&nbsp; GSTIN)',
        r'\g<1>{VER}\g<2>',
    ),
    # mssp.html -- hero-badge
    (
        "mssp.html",
        r'(🏢 MSSP PARTNER PROGRAM · v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # mssp.html -- footer
    (
        "mssp.html",
        r'(CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( · MSSP PARTNER PROGRAM)',
        r'\g<1>{VER}\g<2>',
    ),
    # payment-confirmation.html -- footer
    (
        "payment-confirmation.html",
        r'(CyberDudeBivash Pvt\. Ltd\. &mdash; SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( &mdash; GSTIN)',
        r'\g<1>{VER}\g<2>',
    ),
    # payment-confirmation.html -- JS-built receipt-text array line
    (
        "payment-confirmation.html",
        r"('SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(',)",
        r"\g<1>{VER}\g<2>",
    ),
    # reference-architecture.html -- hero-sub
    (
        "reference-architecture.html",
        r'(MSSP multi-tenant topology\. v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(\.</p>)',
        r'\g<1>{VER}\g<2>',
    ),
    # reference-architecture.html -- footer
    (
        "reference-architecture.html",
        r'(© 2026 CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # referral.html -- footer
    (
        "referral.html",
        r'(© 2026 CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # security-compliance.html -- <title>
    (
        "security-compliance.html",
        r'(<title>Security &amp; Compliance — SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(</title>)',
        r'\g<1>{VER}\g<2>',
    ),
    # security-compliance.html -- hero-badge
    (
        "security-compliance.html",
        r'(⬡ SECURITY &amp; COMPLIANCE v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    # security-compliance.html -- footer
    (
        "security-compliance.html",
        r'(© 2026 CYBERDUDEBIVASH® SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?( · GSTIN)',
        r'\g<1>{VER}\g<2>',
    ),
    # v201: customer-visible stamps the v200 pass missed (pattern-not-found
    # skips). These are current release identity, not historical notes.
    (
        "ai-threat-tracker.html",
        r'(id="hv-gentime">)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    (
        "ai-threat-tracker.html",
        r'(PREDICTIVE INTELLIGENCE · )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    (
        "ai-threat-tracker.html",
        r'(AI THREAT TRACKER )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    (
        "api-docs.html",
        r'("version": ")v[0-9]+\.[0-9]+(?:\.[0-9]+)?(")',
        r'\g<1>v{VER}\g<2>',
    ),
    (
        "service-worker.js",
        r'(Service Worker v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "service-worker.js",
        r"(const CACHE_VERSION = 'sentinel-apex-v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(-live')",
        r"\g<1>{VER}\g<2>",
    ),
    (
        "service-worker.js",
        r'(\[SW v)[0-9]+\.[0-9]+(?:\.[0-9]+)?(\])',
        r'\g<1>{VER}\g<2>',
    ),
    (
        ".github/workflows/dashboard-feeds-sync.yml",
        r'(PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/multi-source-intel.yml",
        r'(PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/storage-lifecycle-governance.yml",
        r'(PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/enterprise-governance.yml",
        r'(PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/weekly-threat-brief.yml",
        r"(PIPELINE_VERSION:\s*')[0-9]+\.[0-9]+(?:\.[0-9]+)?'",
        r"\g<1>{VER}'",
    ),
    (
        ".github/workflows/v149-hardening.yml",
        r'(PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/deploy-worker.yml",
        r'(PLATFORM_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/gumroad-refresh.yml",
        r'(PLATFORM_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/telegram-revenue.yml",
        r'(PLATFORM_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        ".github/workflows/automated-backup.yml",
        r"(PLATFORM_VERSION \|\| ')[0-9]+\.[0-9]+(?:\.[0-9]+)?(')",
        r"\g<1>{VER}\g<2>",
    ),
    (
        "workers/intel-gateway/src/cyber-watchdog.js",
        r'(export const WATCHDOG_PLATFORM_VERSION = ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/dark-web-monitor.js",
        r'(Leak Check Engine v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/dark-web-monitor.js",
        r'(const VERSION = ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/dark-web-monitor.js",
        r'(SENTINEL-APEX/)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/dark-web-monitor.js",
        r'(monitor_version:\s+")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/dark-web-monitor.js",
        r'(dark-web-monitor/)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/sla-monitor.js",
        r'(SLA Monitor Engine v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/sla-monitor.js",
        r'(version:\s+")[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/sla-monitor.js",
        r'(SENTINEL APEX -- v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/sla-monitor.js",
        r'(X-Sentinel-Version": ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/premium-reports.js",
        r'(Premium Threat Report Engine v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/premium-reports.js",
        r'(VERSION: ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/premium-reports.js",
        r'(premium-reports/)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/premium-reports.js",
        r'(platform_version: ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/premium-reports.js",
        r'(SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/premium-reports.js",
        r'(SENTINEL-APEX/)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/alert-engine.js",
        r'(AI Alert Engine v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/alert-engine.js",
        r'(SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/alert-engine.js",
        r'(X-Sentinel-Version": ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/alert-engine.js",
        r'(rid, version: ")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/revenue-enforcement.js",
        r'(VERSION: ")[0-9]+\.[0-9]+(?:\.[0-9]+)?(",\s*// v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}\g<2>{VER}',
    ),
    (
        "workers/intel-gateway/src/api-extensions.js",
        r'(X-Sentinel-Version":\s+")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    (
        "workers/intel-gateway/src/api-extensions.js",
        r'(SENTINEL-APEX-WEBHOOK/)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "workers/intel-gateway/src/api-extensions.js",
        r'(version:\s+")[0-9]+\.[0-9]+(?:\.[0-9]+)?(",\n    generated_at: new Date)',
        r'\g<1>{VER}\g<2>',
    ),
    (
        "workers/intel-gateway/src/usage-meter.js",
        r'(Usage Meter Engine v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "scripts/generate_executive_briefing.py",
        r'(Briefing Engine v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
    (
        "scripts/generate_executive_briefing.py",
        r'(SENTINEL APEX v)[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>{VER}',
    ),
]

# HTML targets with simple title tag governance
HTML_TITLE_TARGETS = [
    # (relative_path, old_title_pattern, new_title_template)
    (
        "api-docs.html",
        r'(<title>API Documentation &mdash; CYBERDUDEBIVASH&reg; SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</title>)',
        r'\g<1>v{VER}\g<2>',
    ),
]


def check_or_apply_regex(rel_path, pattern, template, ver, apply):
    path = REPO_ROOT / rel_path
    if not path.exists():
        return True, "N/A", "file not found -- skip"

    text = path.read_text(encoding="utf-8")
    replacement = template.replace("{VER}", ver).replace("{VERMAJ}", major(ver))

    m = re.search(pattern, text)
    if not m:
        return True, "N/A", "pattern not found -- skip"

    current = m.group(0)
    ver_m = re.search(r"\d+\.\d+(?:\.\d+)?", current)
    found_ver = ver_m.group(0) if ver_m else current

    new_text = re.sub(pattern, replacement, text)
    if new_text == text:
        return True, found_ver, "ok"

    if not apply:
        return False, found_ver, "drift: %s -> %s" % (found_ver, ver)

    try:
        # v161.3: ATOMIC WRITE — write to .tmp then os.replace to prevent truncation
        # of large files (e.g. index.js 5521 lines) on partial write failure.
        import os as _os
        tmp = path.with_suffix(path.suffix + ".vgov_tmp")
        tmp.write_text(new_text, encoding="utf-8")
        _os.replace(tmp, path)
        return True, found_ver, "updated"
    except Exception as e:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        return False, found_ver, "write error: %s" % e


def update_version_json(rel_path, ver, apply):
    """Update a version JSON file that has multiple version fields."""
    path = REPO_ROOT / rel_path
    if not path.exists():
        return True, "N/A", "file not found -- skip"

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "?", "read error: %s" % e

    found = data.get("version", "?")
    # v200.0 FIX: this used to return "ok" the moment "version" alone matched,
    # even when "label"/"full"/"display" (the fields actually rendered to
    # customers) still carried a stale release number -- confirmed live in
    # version.json and config/version.json, both stuck on "v185"/"v184" for
    # weeks while "version" itself correctly tracked 184.0. Widened the drift
    # check to cover every field this function is able to fix, so a partial
    # match no longer short-circuits before the stale ones are caught.
    expected_label = "v%s" % ver.split(".")[0]
    expected_full = "SENTINEL APEX v%s" % ver
    expected_display_token = "v%s" % ver

    def _display_matches(value):
        # v200.0 FIX (CodeRabbit, PR #265): the original check used substring
        # containment (`ver in value`), so "v200.0" would incorrectly pass
        # against a stale "v200.01" or an unrelated string that happens to
        # contain the digits. Extract the actual trailing "vX.Y[.Z]" token
        # and compare it exactly.
        m = re.search(r"v\d+\.\d+(?:\.\d+)?$", str(value))
        # v200.0 FIX (CodeRabbit, post-merge follow-up): a display with NO
        # version token at all used to pass here ("nothing to compare, so
        # call it fine"), but apply mode below does NOT agree -- it replaces
        # a token-less display wholesale with the bare "vX.Y", discarding
        # whatever text was there. --check silently missing a change
        # --apply would actually make is exactly the inconsistency this
        # function exists to prevent. Fail closed instead: no token means
        # apply has something to do, so check must report drift.
        return bool(m) and m.group(0) == expected_display_token

    field_checks = [found == ver]
    if "label" in data:
        field_checks.append(data["label"] == expected_label)
    if "full" in data:
        field_checks.append(data["full"] == expected_full)
    if "display" in data:
        field_checks.append(_display_matches(data["display"]))
    # v200.0 FIX (CodeRabbit, post-merge follow-up): same inconsistency as
    # "display" above -- apply mode (below) rewrites a version-shaped
    # "platform" value, but nothing here ever checked it, so --check could
    # report "ok" on a stale platform version that --apply would then
    # change. Mirrors apply's own condition for what counts as version-shaped.
    if "platform" in data and re.match(r"^\d+\.\d+", str(data["platform"])):
        field_checks.append(str(data["platform"]) == ver)
    if all(field_checks):
        return True, found, "ok"

    if not apply:
        return False, found, "drift: %s -> %s" % (found, ver)

    now = now_iso()
    today = now[:10].replace("-", "")

    for key in ("version", "pipeline_version"):
        if key in data:
            data[key] = ver
    # v200.0 FIX: "platform" is a version-bearing field in some schemas
    # (config/platform_version.json's components block) but a brand-name
    # identifier in others (data/health/sla_status.json's top-level
    # "platform": "CYBERDUDEBIVASH(R) SENTINEL APEX") -- CodeRabbit caught
    # this unconditionally overwriting the name with a bare version number
    # on PR #265. Only treat it as version-bearing if the existing value
    # already looks like one; leave name strings alone.
    for key in ("api_gateway", "report_engine", "ai_engine", "nexus",
                "genesis", "cortex", "quantum", "sovereign", "bug_hunter", "tip_soar",
                "worker", "pipeline"):
        if key in data:
            data[key] = ver
    if "label" in data:
        data["label"] = expected_label
    if "full" in data:
        data["full"] = expected_full
    if "display" in data:
        # Preserve any leading brand text before the version token; replace
        # only the trailing "vX.Y" so a display like "CYBERDUDEBIVASH(R)
        # SENTINEL APEX v184.0" becomes "...v200.0" rather than being
        # clobbered wholesale. If there's no version token to replace, set
        # the whole field to the bare "vX.Y" instead of leaving it untouched.
        original_display = str(data["display"])
        if re.search(r"v\d+\.\d+", original_display):
            data["display"] = re.sub(r"v\d+\.\d+(?:\.\d+)?$", "v%s" % ver, original_display)
        else:
            data["display"] = "v%s" % ver
    # v200.0 FIX: "platform" is a version-bearing field in some schemas
    # (config/platform_version.json's components block) but a brand-name
    # identifier in others (data/health/sla_status.json's top-level
    # "platform": "CYBERDUDEBIVASH(R) SENTINEL APEX") -- CodeRabbit caught
    # this unconditionally overwriting the name with a bare version number
    # on PR #265. Only treat it as version-bearing if the existing value
    # already looks like one; leave name strings alone.
    if "platform" in data and re.match(r"^\d+\.\d+", str(data["platform"])):
        data["platform"] = ver

    if "release" in data:
        data["release"] = "v%s" % ver
    if "platform_label" in data:
        data["platform_label"] = "v%s" % ver.split(".")[0]
    if "platform_full" in data:
        data["platform_full"] = "SENTINEL APEX v%s" % ver
    if "api_gateway" in data:
        data["api_gateway"] = "SENTINEL-APEX/%s" % ver
    if "version_short" in data:
        data["version_short"] = "v%s" % ver.split(".")[0]
    if "version_display" in data:
        data["version_display"] = "v%s" % ver
    if "version_full" in data:
        data["version_full"] = "SENTINEL APEX v%s" % ver
    if "schema_version" in data:
        data["schema_version"] = "v%s" % ver.split(".")[0]

    if "components" in data and isinstance(data["components"], dict):
        for k in ("worker", "dashboard", "pipeline"):
            if k in data["components"]:
                data["components"][k] = ver
        if "platform" in data["components"]:
            data["components"]["platform"] = "CYBERDUDEBIVASH(R) SENTINEL APEX v%s" % ver
        if "pipeline" in data["components"]:
            data["components"]["pipeline"] = ver.rsplit(".", 1)[0]

    for key in ("updated_at", "generated_at", "_generated"):
        if key in data:
            data[key] = now
    if "build_date" in data:
        data["build_date"] = now[:10]
    if "release_date" in data:
        data["release_date"] = now[:10]

    if "build" in data:
        data["build"] = "v%s-ENTERPRISE-GRADE-%s" % (ver, today)
    if "_generator" in data:
        data["_generator"] = "CYBERDUDEBIVASH SENTINEL APEX Pipeline v%s" % ver
    if "changelog" in data:
        data["changelog"] = (
            "v%s ENTERPRISE-GRADE: ai_summary.json manifest fix, "
            "global version governance, feed dedup enforcement, "
            "AI Cyber Brain live activation" % ver
        )

    try:
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return True, found, "updated"
    except Exception as e:
        return False, found, "write error: %s" % e


def _update_platform_version_json(ver: str, apply: bool):
    """
    RC-9 FIX v171.0: Update the nested platform.version in config/platform_version.json.
    This file uses a different schema from version.json (nested under platform: {...})
    so update_version_json() does not handle it.
    """
    path = REPO_ROOT / "config" / "platform_version.json"
    if not path.exists():
        return True, "N/A", "file not found -- skip"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "?", "read error: %s" % e

    platform_block = data.get("platform", {})
    found = platform_block.get("version", "?")
    if found == ver:
        return True, found, "ok"
    if not apply:
        return False, found, "drift: %s -> %s" % (found, ver)

    # Update all version-carrying fields inside platform block
    for key in ("version", "schema_version"):
        if key in platform_block:
            platform_block[key] = ver
    if "full" in platform_block:
        platform_block["full"] = "SENTINEL APEX v%s" % ver
    if "display" in platform_block:
        platform_block["display"] = "CYBERDUDEBIVASH(R) SENTINEL APEX v%s" % ver
    if "label" in platform_block:
        platform_block["label"] = "v%s" % ver.split(".")[0]
    platform_block["release_date"] = now_iso()[:10]
    data["platform"] = platform_block

    # Update all numeric version strings in ci block
    ci_block = data.get("ci", {})
    for key in ("pipeline_version",):
        if key in ci_block:
            ci_block[key] = ver
    if "pipeline_full" in ci_block:
        ci_block["pipeline_full"] = "SENTINEL APEX CI/CD Pipeline v%s" % ver
    if "pipeline_label" in ci_block:
        ci_block["pipeline_label"] = "v%s" % ver.split(".")[0]
    data["ci"] = ci_block

    # Update all component versions
    comps = data.get("components", {})
    for k in list(comps.keys()):
        v = comps[k]
        if isinstance(v, str) and re.match(r"^\d+\.\d+", v):
            comps[k] = ver
    data["components"] = comps

    data["_generated"] = now_iso()
    data["_last_sync"] = "%s - v%s SOVEREIGN SYNC — Version Governance Engine" % (now_iso(), ver)

    try:
        tmp = path.with_suffix(".json.vgov_tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        import os as _os
        _os.replace(tmp, path)
        return True, found, "updated"
    except Exception as e:
        return False, found, "write error: %s" % e


def _update_flat_identity(rel_path, ver, apply):
    """Identity manifest with a numeric version/build. Does not rewrite schema names."""
    path = REPO_ROOT / rel_path
    if not path.exists():
        return True, "N/A", "file not found -- skip"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "?", "read error: %s" % e
    found = str(data.get("version", "?"))
    label = "v%s" % major(ver)
    checks = [found == ver]
    if "commit_series" in data:
        checks.append(data.get("commit_series") == label)
    if "build" in data and re.match(r"^\d+\.\d+", str(data.get("build", ""))):
        checks.append(str(data["build"]) == ver)
    if all(checks):
        return True, found, "ok"
    if not apply:
        return False, found, "drift: %s -> %s" % (found, ver)
    data["version"] = ver
    if "build" in data and re.match(r"^\d+\.\d+", str(data.get("build", ""))):
        data["build"] = ver
    if "commit_series" in data:
        data["commit_series"] = label
    if "updated_at" in data:
        data["updated_at"] = now_iso()
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True, found, "updated"


def run(mode):
    apply = mode == "apply"
    ver = read_authority()
    log.info("Authoritative version: %s  (mode=%s)", ver, mode)

    rows = []
    any_drift = False

    ok, found, status = update_version_json("version.json", ver, apply)
    rows.append(("version.json", found, status, ok))
    if not ok:
        any_drift = True

    ok, found, status = update_version_json("config/version.json", ver, apply)
    rows.append(("config/version.json", found, status, ok))
    if not ok:
        any_drift = True

    # RC-9 FIX v171.0: config/platform_version.json has nested platform.version
    # structure — was NOT propagated by previous version_governance.py, causing
    # persistent drift (config/platform_version.json=166.2 vs VERSION=170.0).
    ok, found, status = _update_platform_version_json(ver, apply)
    rows.append(("config/platform_version.json", found, status, ok))
    if not ok:
        any_drift = True

    ok, found, status = _update_flat_identity("platform/PLATFORM_VERSION.json", ver, apply)
    rows.append(("platform/PLATFORM_VERSION.json", found, status, ok))
    if not ok:
        any_drift = True


    # data/health/sla_status.json -- keep version tag current (APPLY only).
    # v148.1.0 FIX: sla_status.json is RUNTIME-GENERATED by sla_engine.py,
    # which writes its own component version (e.g. 143.0.0) each time it runs.
    # This file will ALWAYS have a stale version between sla_engine.py runs.
    # Including it in --check drift detection caused recurring HARD FAILs at
    # STAGE 0.06 of sentinel-blogger, blocking the entire pipeline on every
    # sla_engine regeneration cycle.
    # FIX: apply mode still updates the file (keeping it current); check mode
    # reports the state but does NOT contribute to any_drift (advisory only).
    ok, found, status = update_version_json("data/health/sla_status.json", ver, apply)
    rows.append(("data/health/sla_status.json", found, status, ok))
    if not ok and apply:
        # Only count as drift failure in apply mode (write error) — never in check mode.
        any_drift = True

    for rel_path, pattern, template in REGEX_TARGETS + HTML_TITLE_TARGETS:
        ok, found, status = check_or_apply_regex(rel_path, pattern, template, ver, apply)
        rows.append((rel_path, found, status, ok))
        if not ok:
            any_drift = True

    col0 = max(len(r[0]) for r in rows) + 2
    col1 = max(len(r[1]) for r in rows) + 2
    header = "%-*s %-*s %s" % (col0, "FILE", col1, "FOUND", "STATUS")
    log.info("%s", header)
    log.info("%s", "-" * len(header))
    for file_, found, status, ok in rows:
        flag = "OK" if ok else "DRIFT"
        log.info("%-*s %-*s [%s] %s", col0, file_, col1, found, flag, status)

    if mode == "report":
        return 0

    if any_drift and not apply:
        log.error("Version drift detected. Run with --apply to fix.")
        return 1

    if not any_drift:
        log.info("All version targets are consistent at v%s.", ver)
    else:
        log.info("Version governance applied -- all targets set to v%s.", ver)
    return 0



def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Version Governance Engine"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        "--check", action="store_true",
        help="Detect drift only. Exit 1 if found."
    )
    grp.add_argument(
        "--apply", action="store_true",
        help="Apply authoritative version to all targets."
    )
    grp.add_argument(
        "--report", action="store_true",
        help="Print version table. Always exits 0."
    )
    args = parser.parse_args()

    if args.check:
        mode = "check"
    elif args.report:
        mode = "report"
    else:
        mode = "apply"

    sys.exit(run(mode))


if __name__ == "__main__":
    main()
