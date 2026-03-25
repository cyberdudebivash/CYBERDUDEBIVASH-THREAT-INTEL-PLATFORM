# CHANGELOG — SENTINEL APEX v76.0 / v76.1 / v76.2
**Platform:** intel.cyberdudebivash.com
**Released:** 2026-03-26
**Based on:** Run #549 → #551 analysis + full 24-workflow audit + dashboard card audit

---

## v76.2.0 (2026-03-26) — DASHBOARD INTELLIGENCE CARD ACCURACY

### Critical Dashboard Fixes (11 bugs closed)

**BUG 1 — PRIORITY: P4 displayed on 10/10 CRITICAL advisories** *(root cause confirmed in screenshots)*
- Root cause: when `cvss_score = null`, old logic defaulted `_prioNum = 4` unconditionally
- Fix: added Rule 7 — `risk_score` is now the universal fallback when CVSS is absent
- Risk ≥ 9 → P1, ≥ 7 → P2, ≥ 5 → P3, else P4

**BUG 2 — ACTION: "ASSESS" displayed on 10/10 CRITICAL advisories**
- Root cause: with old P4 the action fell through to ASSESS
- Fix: P1 + risk ≥ 9 now shows `PATCH NOW`; P1/P2 shows `INVESTIGATE`

**BUG 3 — EPSS: 0.29% displayed as "MEDIUM" likelihood**
- Root cause: threshold `_epss >= 0.1` was too low — 0.29% = 1-in-345 chance
- Fix: <1% = LOW, 1-10% = LOW-MED, 10-50% = MEDIUM, ≥50% = HIGH

**BUG 4 — EXPLOIT badge: fired at EPSS ≥ 70% (inconsistent)**
- Fix: unified exploit threshold to EPSS ≥ 50% across all signals

**BUG 5 — `_exploit` variable used 70% threshold**
- Fix: changed to 50% to match badge and likelihood logic

**BUG 6 — LIKELIHOOD: MEDIUM shown for 0.29% EPSS advisory**
- Fix: corrected thresholds + risk_score fallback when EPSS is null

**BUG 7 — EPSS bar: red at ≥70%, orange at ≥40% (misaligned)**
- Fix: red ≥ 50%, orange ≥ 10%, amber ≥ 1%, green below 1%

**BUG 8 — IMPACT: purely score-based, ignored `threat_type` from manifest**
- Fix: uses `item.threat_type` first, falls back to score threshold

**BUG 9 — `item.kev` wrong field name in two functions**
- `getLiveExploitedThreats()` used `item.kev` — never matched
- `getThreatPriorityScore()` used `item.kev === true || item.kev === 1` — never matched
- Fix: both corrected to `item.kev_present === true`

**BUG 10 — Exploit narrative: "Moderate exploitation probability" for 0.29% EPSS**
- Fix: now says "Low exploitation probability (EPSS X%)" for values < 1%

**BUG 11 — SOC CONFIDENCE: LOW on 10/10 no-CVSS advisories**
- Fix: risk score fallback — risk ≥ 9 → MEDIUM confidence, risk ≥ 7 → MEDIUM

### Additional Dashboard Fixes
- Modal EPSS bar color thresholds aligned (was 70/40, now 50/10/1)
- `generateAINarrative()` EPSS thresholds aligned (was 70/40, now 50/10/1)
- Playbook SIEM threshold raised from 0.1% to 1% — more accurate SOC guidance
- `_actionCtx` updated to cover both `IMMEDIATE PATCH` and `PATCH NOW` labels
- Workflow concurrency: `detection-engine.yml` and `revenue-orchestrator.yml` added groups
- `ai-predictions.yml`: concurrency added + manifest format bug fixed

### Before vs After (from screenshots)

| Card | Field | Before (Wrong) | After (Correct) |
|---|---|---|---|
| Schneider Electric Risk 10/10 | Priority | **P4** | **P1** |
| Schneider Electric Risk 10/10 | Action | **ASSESS** | **PATCH NOW** |
| Schneider Electric EPSS 0.29% | Likelihood | **MEDIUM** | **LOW** |
| Schneider Electric Risk 10/10 | SOC Confidence | **LOW** | **MEDIUM** |
| LiteLLM Risk 9.4/10 | Priority | **P4** | **P1** |
| LiteLLM Risk 9.4/10 | Action | **ASSESS** | **PATCH NOW** |
| LiteLLM Risk 9.4/10 | SOC Confidence | **LOW** | **MEDIUM** |

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
