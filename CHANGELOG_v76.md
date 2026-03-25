# CHANGELOG — SENTINEL APEX v76.0 / v76.1
**Platform:** intel.cyberdudebivash.com
**Released:** 2026-03-26
**Based on:** Run #549 → #551 analysis + full 24-workflow audit

---

## v76.1.0 (2026-03-26) — STABILITY + MONETIZATION HARDENING

### Pipeline Stability
- **FIX:** `v75 Pipeline Hardener` — removed `::group::` wrapper, added `python3 -u`
  for unbuffered stdout. Output now visible in CI logs every run.
- **FIX:** `v76 Platform Finalizer` — same fix. Full 7-task health report now visible.
- **FIX:** `multi-source-intel.yml` — added `concurrency: sentinel-data-writer` group.
  Previously missing, caused race condition with sentinel-blogger at :00 cron.
- **FIX:** `sync-dashboard.yml` — manifest format bug fixed (v70 dict envelope).
  `items[-1]` corrected to `items[0]` for newest entry detection.
- **FIX:** `weekly-analyst-briefing.yml` — manifest format bug fixed (both read sites).

### Monetization
- **FIX:** `quality_gate.py` — added `TRUSTED_SOURCES` set (26 tier-1 domains).
  BleepingComputer, DarkReading, SecurityWeek, TheRecord, CyberScoop etc. bypass
  `MIN_WORDS=80` gate. Their RSS excerpts are short but full articles are fetched
  downstream. Prevents ~15-20 quality-gate blocks per run from premium intel sources.
- **FIX:** `sentinel_blogger.py` — both quality gate call sites updated to pass
  `source_url=entry.get('link', '')` enabling trusted-source bypass.
- **FIX:** `threat_page_generator.py` — replaced `datetime.utcnow()` (deprecated)
  with `datetime.now(timezone.utc)`. Eliminates DeprecationWarning in every run.

### Intelligence Quality
- **RUN #549:** 4 advisories published, archive created (521 entries), 8/8 gate checks
- **RUN #551:** 18 advisories published (best run), archive at 555 entries, 60 premium items,
  reports 2954-3167 words, 40 feeds active (up from 32), all 8 gate checks PASS

---

## v76.0.0 (2026-03-25) — PLATFORM FINALIZER + FULL AUDIT

### New Features
- `scripts/v76_platform_finalizer.py` — 7-task post-pipeline orchestrator:
  API sync, feed health, archive retention, STIX cap, VERSION update, health snapshot,
  pending queue cleanup. Runs after every deploy cycle.
- `scripts/v75_pipeline_hardener.py` — sort + 3-layer dedup + daily archive + atomic write.
  Daily archive at `data/archive/YYYY-MM-DD.json`, indexed at `data/archive/index.json`.
- `scripts/v75_stix_cleanup.py` — monthly STIX bundle orphan archiver (never deletes).
- `scripts/pre_deploy_gate.py` — upgraded from 5 to 8 checks:
  [6/8] manifest sort order, [7/8] no duplicate advisory_ids, [8/8] EMBEDDED_INTEL alignment.

### Bug Fixes
- `agent/export_stix.py` — atomic write via `os.replace()` + sort-before-trim fix.
- `agent/v56_publish_guard/publisher.py` — title sanitizer for `<=` in CVE titles (HTTP 400).
- `agent/content/source_fetcher.py` — NVD fallback when cvefeed.io returns 0 words.
  Reports now consistently 2500-3167 words (was 1720-1930w).
- `agent/config.py` — 12 dead feeds replaced with 11 active feeds. Feeds OK: 40 (was 24).
- `scripts/data_bridge.py` — `ioc_counts` dict forwarded to v70 pipeline (was always 0).
- `agent/quality_gate_audit.py` — manifest format bug fixed (handles v70 dict envelope).
- `.gitignore` — `data/blogger_processed.json` uncommented (was gitignored, causing
  dedup state reset on every CI run — root cause of re-publishing old advisories).
- `.github/workflows/multi-source-intel.yml` — concurrency group added (was missing).

### Infrastructure
- All 24 workflows audited. Concurrency gaps identified and closed.
- `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` at workflow env level.
- Daily archive growing: 521 → 555 entries between run #549 and #551.
- `api/feed.json` (500 items) + `api/latest.json` (20 items) synced every run.
- `data/status/pipeline_health.json` + `data/status/feed_health.json` written every run.

---

## Confirmed Production Metrics (Run #551)
| Metric | Value |
|---|---|
| Advisories published | 18 (best run to date) |
| Report word count | 2954–3167w (all above 2500 target) |
| Pre-deploy gate | 8/8 checks PASS |
| Archive entries | 555 (growing daily) |
| Active feeds | 40 / 58 configured |
| Quality gate premium items | 60 identified |
| Correlations | 101,630 |
| KEV confirmed | 24 advisories |
| CRITICAL advisories | 112 in manifest |
| Revenue CTAs | Dual CTA on every published advisory |
| Email threshold | score ≥ 6.5 triggers executive briefing |

---

## Monetization Architecture (Active)
- **Gumroad store:** https://cyberdudebivash.gumroad.com
- **CTA products:**
  - Vulnerability kit: `/l/pwynns` (SIGMA + YARA + IR playbook)
  - Malware response: `/l/ytqra` (IOC block lists + YARA + triage runbook)
  - Breach kit: `/l/yrjznw` (IR templates + containment scripts)
- **UTM tracking:** Every CTA link includes utm_source/medium/campaign/content
- **Revenue log:** `data/revenue_log.json` (last 200 events, committed to repo)
- **Email dispatch:** `agent/email_dispatcher.py` via SendGrid
  - Requires: `SENDGRID_API_KEY`, `SENDER_EMAIL`, `SUBSCRIBER_EMAILS` GitHub secrets
- **Tier thresholds:** score ≥ 6.5 → email + CTA; score ≥ 7.0 → Enterprise package CTA;
  score ≥ 9.0 → Emergency kit CTA
- **Subscription tiers:** Free / Pro $19/kit / Enterprise custom / MSSP $1,999/mo

---

## Remaining Items (Non-blocking)
- `api_server: DOWN` — FastAPI code exists in `sentinel-apex-api/`, needs Railway/Render deploy
- `EPSS = None` for brand-new 2026 CVEs — expected (FIRST.org API lag), not a bug
- `Total IOCs: 0` in telemetry summary — cosmetic only; per-advisory IOC extraction works
- SendGrid secrets not configured — email dispatch silently skipped until secrets added
- Node.js 20 deprecation warning at job cleanup — GitHub forces Node.js 24 June 2026, harmless

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
