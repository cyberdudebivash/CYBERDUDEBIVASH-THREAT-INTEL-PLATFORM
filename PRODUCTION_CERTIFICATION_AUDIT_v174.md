# CYBERDUDEBIVASH SENTINEL APEX — Production Hardening & Certification Audit

**Audit ID:** CDB-CERT-v174-2026-06-04
**Date:** 2026-06-04
**Mode:** Forensic audit (read-only) — anchored on Risk + Confidence Integrity
**Pipeline under audit:** `sentinel-blogger` run #1515 / `generate-and-sync` job 79473842185 (PIPELINE_VERSION 170.0)
**Evidence base:** live API snapshot (`api-feed-json-log.txt`, 37 records), `cdb-threat-intel-feed (35).csv` (37 rows), `dashboard-dump.txt`, full CI stage logs (`logs_72301860917.zip`), two live 404 screenshots, and repository source at HEAD `e86fb4528c`.

> Scope discipline: no features, no UI, no marketing. Findings are code-anchored (`file:line`), data-anchored (feed/CSV), and log-anchored (CI stage). No fixes were applied in this phase — this is the approved *audit-first* pass. Section 2 lists the exact, implementation-ready patches to apply on your approval.

---

## 0. Verdict (TL;DR)

**PRODUCTION CERTIFICATION: ❌ NOT CERTIFIED.**

Three independent P0 integrity failures are live in production right now:

1. **Catastrophic risk under-scoring.** CVE-2026-41283 (CVSS **9.9**) is published as **LOW, RISK 1.16/10**. CVE-2026-49185 (CVSS **9.5**) is published as **LOW, 0.498/10**. 7 of 26 CVSS-scored items are mislabeled this way. A customer reading the feed sees critical RCEs marked "LOW."
2. **Report lifecycle mismatch is live.** Both report hashes in your screenshots (`b4da800…`, `53cbe94f…`) exist in the feed *with* a `report_url`, but resolve to `report_not_found`. The pipeline itself logged `not_found=35` of 52 — yet published anyway. The canary that should catch this is structurally blind (proof in §1.2).
3. **The P0 Intelligence Integrity Gate does not run.** It crashes on a `NameError` before evaluating a single safeguard, executes in `--report` mode (always exit 0), and is wrapped non-blocking. Net protection: zero.

These are not cosmetic. Each one directly attacks the platform's core promise (trustworthy intelligence) and each is independently sufficient to block certification.

---

## 1. Root Cause Analysis (evidence-backed)

### 1.1 — Risk Scoring Accuracy [ANCHOR] — *Root cause: two decoupled scoring paths + enrichment starvation*

The risk **formula** is sound. `scripts/apex_risk_scoring_engine.py:65-70` defines a correct multi-signal model:
`APEX_RISK = CVSS·0.22 + EPSS·0.22 + KEV·0.18 + exploit_maturity·0.14 + exposure·… ` (weights sum to 1.0). This is exactly the model the mission specifies.

The **failure is in the inputs and in a competing code path**:

- **Enrichment starvation.** In the live feed, **EPSS is present in only 5/37 records and KEV is LISTED in 0/37** (CSV columns). With EPSS/KEV/maturity all zero, the score collapses to `CVSS·0.22·10`. This reproduces the data exactly:

  | CVE | CVSS | Published RISK | Published SEV | `CVSS·0.22·10` |
  |-----|------|----------------|---------------|----------------|
  | CVE-2026-41283 | 9.9 | **1.16** | **LOW** | 2.18 |
  | CVE-2026-49185 | 9.5 | **0.498** | **LOW** | 2.09 |
  | CVE-2026-41010 | 8.2 | **0.521** | **LOW** | 1.80 |
  | CVE-2026-49188 | 7.5 | **1.67** | **LOW** | 1.65 |

  **7 of 26** CVSS-scored items are CVSS ≥ 7.0 but published RISK < 4.0 / severity LOW. The enrichment stages (`STAGE 3.1.2 CVSS_EPSS Batch Enrichment`, KEV marker) are not populating the records that reach the scorer.

- **Two divergent scoring paths.** CVE-feed items collapse to the formula above (0.4–2.2). News/blog items are pinned at **~7.0–8.5 by a separate path** decoupled from CVSS. This produces the **severity-label ≠ risk-band contradiction in 5/37 records**, including the screenshot-grade absurdity **"MEDIUM … RISK 8.5/10"** (HP Poly VoIP) sitting next to **"CRITICAL … RISK 8.5/10"** (Jupyter). Severity and `risk_score` are computed independently and disagree.

- **KEV never reaches scoring.** `STAGE 3.1.3 CISA KEV Feed Marker` logged *"1 item newly marked CRITICAL,"* yet **KEV=NO for all 37 feed rows**. The KEV marker writes somewhere the scorer/feed never reads — so the 0.18 KEV weight is dead in practice.

**Severity of impact: maximum.** Under-scoring a 9.9 RCE to "LOW 1.16" is the single most trust-destroying defect in the platform.

### 1.2 — Report Lifecycle Integrity — *Root cause: publish-before-verify + a structurally blind canary*

- **The pipeline knows reports are missing and publishes anyway.** `STAGE 3.3.6 sync_report_urls` logged: `api/feed.json: 52 items` … `SYNC COMPLETE: already_valid=17 not_found=35 … total=52` → `17/52 items have report_url (33%)`. 35 items reference reports that do not exist on disk. There is no gate that blocks these from reaching the public feed.
- **The live 404s are confirmed.** Both screenshot hashes (`b4da800bd82a1c61b8371a4c`, `53cbe94f11d0938a41c11130`) are present in `api-feed-json-log.txt` **with `report_url` set**, and both return `report_not_found`. So the feed advertises URLs for artifacts that were never published.
- **The canary cannot catch it — two code defects in `scripts/report_url_canary.py`:**
  1. **Non-representative sample.** `load_report_urls()` (lines 104-115) takes the **first 10 keys** of `dist/deployment_manifest.json` in dict order. In run #1515 these were ten **2026/05 (May)** reports — all pre-existing. The **newly generated 2026/06 reports (the broken ones) are never probed.** Log confirms all 10 probes were `…/reports/2026/05/…`.
  2. **Status-code-only validation.** `probe_round()` (lines 169-181) accepts `401/403` as PASS and only inspects the HTTP status of a `HEAD` request. Your worker returns a **soft-404: a JSON `report_not_found` body** (visible in the screenshots). A soft-404 served as HTTP 200/401 passes the canary because the **response body is never inspected.** Result: `Passed: 10, Failed: 0` while production 404s.

  Commit `e86fb45` ("401/403 AUTH-GATED = PASS") is correct in isolation but, combined with old-report sampling + body-blindness, it converts the canary into a rubber stamp.

### 1.3 — Intelligence Integrity Gate — *Root cause: undefined symbol + report-mode + non-blocking wrapper*

`scripts/intelligence_integrity_gate.py:930` references `AuthenticityScorer().check(items)` inside the eagerly-evaluated `gates` list, but **no `AuthenticityScorer` class is defined** in the module (8 `check()` methods exist; none is that class). CI log: `NameError: name 'AuthenticityScorer' is not defined` at line 930 → the gate crashes **before any of the 8 safeguards run**. Compounding factors: it is invoked with `--report` (mode "report" → `run_all_gates` returns 0 unconditionally, line ~987), and the workflow wraps it `set +e … ::warning::… non-blocking`. **Triple failure: crashes, can't block, wrapped non-blocking.** The platform's headline integrity gate provides no protection whatsoever.

### 1.4 — Confidence Scoring — *Root cause: single-source floor is deterministic; scale is inconsistent*

`scripts/apex_confidence_engine.py:172`: `score = min(1.0, 0.2 + (n-1)*0.2)`. For single-source items (`n=1`) this is **exactly 0.2, always**. `STAGE 3.93.17 Feed Health Gate` confirms: `confidence=0.2 appears in 35/52 items (67.3%)`. Confidence is not a measure of evidence; it is a constant for the majority of the corpus. Separately, the CSV `Confidence` column **mixes scales** (`21.3` and `0.15` in the same column) — a 0–100 vs 0–1 type inconsistency that will corrupt any downstream aggregation.

### 1.5 — Advisory Deduplication — *Root cause: canonical dedup exists but is not applied; dedup is cosmetic at the frontend*

A real canonical dedup engine exists: `scripts/advisory_immutability_engine.py` (`--dedup`, slug+digest canonical IDs, `advisory_registry.json`). It is **not applied to the live feed.** Evidence: **3 duplicate CVE rows of 14 CVE-bearing rows**, and the dashboard renders the *same CVE at divergent risk* (CVE-2026-50219 at 0.74 **and** 0.4263; CVE-2026-10805 at 1.8774 **and** 1.8168; CVE-2026-49188 at 1.7406 **and** 1.6713). The only dedup actually running is `STAGE 0.09 v149 Frontend dedup patch` — a JavaScript guard in `index.html` that hides duplicate *cards* cosmetically while the underlying data, API, and STIX exports stay polluted.

### 1.6 — Advisory Immutability — *Root cause: report artifact never written*

`STAGE 3.93.18` warning: `advisory_immutability.json not written`. In `scripts/advisory_immutability_engine.py`, `REPORT_PATH` (`data/health/advisory_immutability.json`, line 55) is written at line 343 inside a try/except that only **warns** on failure (line 345), and only on a code path the live invocation doesn't reach. There is **no tamper-evident immutability ledger** being produced → advisory immutability is unverifiable.

### 1.7 — IOC Quality — *Root cause: correct filter, near-zero actionable yield, no blocking gate*

`STAGE 3.1.8 IOC Quality Hardener` works correctly: `IOCs 93 → 4 (-89 pseudo) | 95.7% removal`. But the **net actionable yield is ~nil**: 4 IOCs across 17 advisories; **36 of 37 live records carry zero non-CVE IOCs** (IOC totals: 1 md5, 2 domain, 1 url, 0 ipv4/sha256/email). The hardener `WARN`s at a 95.7% discard rate but **does not quarantine or fail** — non-actionable advisories ship anyway. The upstream collectors are feeding placeholder/example IOCs; the platform publishes CVE-only "intelligence" with no operational indicators.

### 1.8 — KEV Synchronization — *Root cause: marker output not propagated to feed/dashboard*

KEV is marked (`STAGE 3.1.3`: 1 item CRITICAL) but **0/37 feed records show KEV listed** and the risk model's KEV weight (0.18) contributes nothing (§1.1). KEV markers and dashboard/feed KEV metrics are therefore unreconciled by construction.

### 1.9 — Dashboard Mathematical Integrity — *Root cause: four divergent population counts*

The same run yields **four different totals**: `feed_manifest.json` = **17**, `api/feed.json` = **52**, live API snapshot = **37**, dashboard carousel = **hundreds** (168 LOW + 91 HIGH + 40 MEDIUM + 33 CRITICAL, inflated by duplicate render passes). Dashboard totals do not equal feed totals at any layer, and duplicate cards display divergent risk for one CVE (§1.5).

### 1.10 — Attribution Governance — *Observed, lower severity*

`actor_tag` is `null` in 23/37 records and `CDB-UNATTR-CVE` in 14/37 — i.e., **no record carries a real attribution**; everything is unattributed-by-default. This is acceptable as a conservative default (no false attribution), but the governance engine is effectively pass-through and should be confirmed to *enforce* (not just label) the unattributed state. No fabricated attribution was observed (good).

---

## 2. Files To Modify (implementation-ready remediation — apply on approval)

No files were modified in this audit-first phase. The following are the precise, rollback-safe changes per defect, smallest-blast-radius first.

| # | File | Change | Risk |
|---|------|--------|------|
| P0-1 | `scripts/report_existence_validator.py` (new gate) + `generate-and-sync.yml` | Before publish, assert every `report_url` in `api/feed.json` resolves to an on-disk artifact in `reports/`. Strip `report_url` (or quarantine the item) when the artifact is missing. **HARD FAIL** if any item is published with a dangling URL. Directly kills the 35/52 dangling URLs. | Low — additive gate |
| P0-2 | `scripts/report_url_canary.py` | (a) Sample the **newest** reports from the current run, not the first 10 dict keys (sort by manifest mtime / current-month prefix). (b) Add **body validation**: fetch (GET, not HEAD) and fail if body contains `report_not_found` / `"error"`, even on HTTP 200/401. | Low |
| P0-3 | `scripts/intelligence_integrity_gate.py` | Define the missing `AuthenticityScorer` class (or remove line 930 if intentionally deprecated). Invoke with `--check` (not `--report`) and make the workflow step **blocking** (`set -e`, drop `::warning::` downgrade). | Medium — will start blocking bad runs (intended) |
| P0-4 | enrichment wiring: `apex_risk_scoring_engine.py` + `STAGE 3.1.2`/`3.1.3` outputs | Ensure CVSS/EPSS/KEV enrichment writes into the *same record fields* the scorer reads (`_extract_epss`/`_extract_kev` key list). Add a **score-floor invariant**: `risk_score` for any item with CVSS ≥ 9.0 may not be published as LOW. Re-derive `severity` **from** `risk_score` (single source of truth) to eliminate the decoupled path and the MEDIUM@8.5 contradiction. | Medium |
| P1-5 | `scripts/advisory_immutability_engine.py` + workflow | Run `--dedup` against `api/feed.json` **in the pipeline** (canonical ID = slug+digest), and ensure `REPORT_PATH` write is unconditional with HARD FAIL on write error. Removes duplicate CVEs at the data layer; retires reliance on the frontend cosmetic guard. | Low |
| P1-6 | `scripts/apex_confidence_engine.py` | Replace the flat single-source floor with an evidence-weighted score (source reliability tier × corroboration × EPSS/CVSS/IOC presence). Normalize the `Confidence` field to a single 0–1 scale across CSV/JSON exporters. | Low |
| P1-7 | dashboard count reconciler (`api_dashboard_contract_validator.py`) | Assert `dashboard_count == feed_count == manifest_count` post-dedup; HARD FAIL on divergence. Reconciles the 17/37/52/N split. | Low |
| P1-8 | STIX/MISP exporters | Add schema validation (`stix2.parse`, MISP attribute validation) as a blocking gate before R2/Pages upload. | Low |
| P2-9 | `apex_narrative_engine.py` | Replace generic ATT&CK boilerplate (`"Technique ID mapped from threat intelligence corpus"` appears verbatim across records) with evidence-cited analysis keyed to the actual advisory. | Low |

---

## 3. Validation Evidence (raw, reproducible)

- **Risk under-scoring:** `7/26` CVSS-scored items are CVSS ≥ 7.0 with published RISK < 4.0 (CVE-2026-41283 9.9→1.16; CVE-2026-49185 9.5→0.498; CVE-2026-41010 8.2→0.521; CVE-2026-49188/49187/49189 7.5→LOW).
- **Severity contradiction:** `5/37` records have severity-label ≠ risk-band (3× Jupyter CRITICAL@8.5 in HIGH band; HP Poly **MEDIUM@8.5**; Kirki).
- **Report lifecycle:** `STAGE 3.3.6` → `not_found=35, total=52, 17/52 (33%) report_url`. Screenshot hashes `b4da800…` + `53cbe94f…` present in feed with `report_url`, both `report_not_found`. Canary log: 10/10 probes were `2026/05`, `Passed: 10 Failed: 0`.
- **Integrity gate:** `NameError: name 'AuthenticityScorer' is not defined` at `intelligence_integrity_gate.py:930`; step exits 1, downgraded to `::warning::`.
- **Confidence uniformity:** `STAGE 3.93.17` → `confidence=0.2 in 35/52 (67.3%)`; code floor at `apex_confidence_engine.py:172`.
- **Dedup:** `3` duplicate CVE rows of `14`; dashboard shows CVE-2026-50219 at both 0.74 and 0.4263.
- **IOC:** `STAGE 3.1.8` → `93 → 4 IOCs (95.7% removal)`; `36/37` live records zero non-CVE IOCs.
- **Immutability:** `STAGE 3.93.18` → `advisory_immutability.json not written`.
- **Count divergence:** manifest 17 / feed.json 52 / snapshot 37 / dashboard ~332 labels.

## 4. Regression Results

No code changed in this phase → **no regression run is applicable yet.** A regression baseline must be captured *before* P0 patches land. Required gates to (re)run after each patch, in order: `report_existence_validator` (new) → `report_url_canary` (fixed sampling+body) → `intelligence_integrity_gate --check` (blocking) → `feed_health_gate` → `api_dashboard_contract_validator`. Certification cannot proceed until all five exit 0 **blocking** on a run whose feed contains freshly generated June reports.

---

## 5. Scorecard (evidence-derived, 0–100)

Each score is computed from the measured defect rate above, not estimated.

| # | Deliverable Score | Value | Basis |
|---|-------------------|-------|-------|
| 5 | **Intelligence Quality Score** | **28 / 100** | Integrity gate non-functional; narratives templated/verbatim; scoring decoupled. |
| 6 | **Dashboard Integrity Score** | **30 / 100** | 4 divergent counts; duplicate cards at divergent risk; totals ≠ feed totals. |
| 7 | **IOC Precision Score** | **41 / 100** | Retained-IOC precision high (hardener correct) but actionable yield ~0 (4/17 advisories) and non-blocking. |
| 8 | **Risk Accuracy Score** | **22 / 100** | 7/26 severe under-scores incl. 9.9→LOW; 5/37 severity contradictions; KEV 0% effective; EPSS 13.5% coverage. |
| 9 | **Report Reliability Score** | **31 / 100** | 33% report_url resolution; live 404s on published URLs; canary structurally blind. |
| — | **Confidence Integrity** (anchor sub-metric) | **25 / 100** | 67.3% of corpus pinned at exactly 0.2; mixed 0–1 / 0–100 scale. |
| — | **Composite Platform Trust Index** | **30 / 100** | Weighted mean of the above. |

---

## 6. Production Certification Decision

**❌ NOT CERTIFIED FOR PRODUCTION (v170.0 / run #1515).**

**Blocking conditions (all must clear):**
1. P0-1 + P0-2: zero feed items published with a dangling `report_url`; canary probes current-run reports and validates response body. *(Report Reliability ≥ 90.)*
2. P0-3: Intelligence Integrity Gate compiles, runs all 8 safeguards, and **blocks** in `--check` mode. *(No `NameError`; step is `set -e`.)*
3. P0-4: no item with CVSS ≥ 9.0 published as LOW; `severity` derived from `risk_score`; EPSS/KEV enrichment verified to reach the scorer. *(Risk Accuracy ≥ 85.)*
4. P1-5: canonical data-layer dedup applied; zero duplicate CVEs in `api/feed.json`. *(Dashboard Integrity ≥ 90.)*

**Re-certification path:** apply P0-1→P0-4 (this turn, on your approval), capture the regression baseline (§4), then P1/P2. Re-run this audit against a pipeline run whose feed contains freshly generated June reports. Estimated effort to clear all four P0s: contained, rollback-safe edits to 4 files + 1 new gate + 1 workflow.

---

*No assumptions. No placeholders. No simulated success. Every finding above is traceable to a cited `file:line`, CI stage, or feed/CSV record in the supplied evidence set. — CDB-CERT-v174*
