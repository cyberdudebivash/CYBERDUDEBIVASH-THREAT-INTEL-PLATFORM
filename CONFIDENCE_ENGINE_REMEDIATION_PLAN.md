# CYBERDUDEBIVASH® SENTINEL APEX — Confidence Engine Remediation Plan
**Classification:** Internal — Intelligence Engineering
**Component:** `scripts/apex_confidence_engine.py` (version 152.0.0)
**Platform:** SENTINEL APEX CTI Platform — v174.1
**Document Date:** 2026-06-04
**Prepared By:** Principal Enterprise CTI Architect
**Status:** ACTIVE — remediation in planning

---

## 1. Problem Statement

The SENTINEL APEX confidence engine produces scores that are deterministic, explainable, and methodologically sound (Admiralty Scale / NATO-UKUSA model). However, the **current source mix produces a compressed, low-confidence distribution** that reduces the feed's actionability for SOC triage and alert routing. This is not a bug — it is an accurate reflection of the current source portfolio. Remediation requires expanding and diversifying the source portfolio and improving enrichment coverage, not adjusting scoring weights in isolation.

---

## 2. Current State — Evidence

### 2.1 Confidence Distribution (v174.1 Feed, 2026-06-04)

| Metric | Value |
|---|---|
| Minimum confidence | 0.120 |
| Maximum confidence | 0.370 |
| Average confidence | 0.203 |
| Unique confidence values | 11 of 19 items |
| Items at 0.14 | 4 (highest frequency) |
| Items at 0.12 | 4 (second highest) |
| Items in LOW band (0.12–0.20) | Majority of feed |
| `confidence_uniformity` warning | ACTIVE |

### 2.2 Source Mix Analysis

| Source | Items | % of Feed | Admiralty Tier | Base Score |
|---|---|---|---|---|
| GitHub Security Advisories | 9 | 47% | C — Fairly Reliable | 0.75 |
| CVE Feed (NVD/MITRE) | 5 | 26% | C — Fairly Reliable | 0.68 |
| SecurityAffairs | 3 | 16% | NOT VERIFIED — tier TBD | ~0.70 est. |
| Vulners | 1 | 5% | NOT VERIFIED — tier TBD | ~0.65 est. |
| BleepingComputer | 1 | 5% | NOT VERIFIED — tier TBD | ~0.70 est. |

**Single-source concentration: 74% of feed items from top-2 sources (GitHub + CVE Feed).**

### 2.3 Enrichment Coverage Gaps

| Enrichment Type | Coverage | Target |
|---|---|---|
| EPSS Score (exploitation probability) | 5/19 (26%) | >15/19 (>79%) |
| KEV Cross-validation | 0/19 confirmed (correct) | Daily CISA catalog check |
| Multi-source corroboration | 0/19 corroborated | >5/19 within 30 days |
| `report_url` presence | 6/19 (32%) | >12/19 (>63%) |

### 2.4 Admiralty Scale Model (Current Implementation)

The confidence engine implements the Admiralty Scale (NATO/UKUSA) with the following signal weights:

| Signal | Current Weight |
|---|---|
| Source reliability (A–F tier) | 30% |
| IOC validity rate | 20% |
| Corroboration count | 15% |
| EPSS score contribution | Variable |
| KEV boost | Variable |
| Other signals | Remaining % |

**Root cause of uniformity:** With 74% of items from C-tier sources (score ~0.68–0.75), minimal EPSS coverage (26%), no KEV boosts (all CVE-2026), and no corroboration events, the 30% source reliability signal dominates output and produces a narrow band.

---

## 3. Remediation Plan

### 3.1 Source Diversification — Primary Fix

**Objective:** Reduce single-source dominance from 74% to <30%.
**Target state:** No single source contributes >30% of feed items.

**Implementation Steps:**

**Step 1 — Assign Admiralty tiers to all active sources (Sprint N)**
- GitHub Security Advisories: C (Fairly Reliable) — confirmed
- CVE Feed (NVD/MITRE): C (Fairly Reliable) — confirmed
- SecurityAffairs: Assign B (Usually Reliable) or C — requires editorial review
- BleepingComputer: Assign B (Usually Reliable) — established security media
- Vulners: Assign C (Fairly Reliable) — aggregator, variable quality

**Step 2 — Onboard 3–4 additional high-tier sources (Sprint N+1)**
Priority targets for A-tier or B-tier sources:
- **CISA Advisories** (Tier A — Completely Reliable): Government CVE advisories, ICS-CERT
- **CERT/CC or national CERTs**: Tier A–B depending on origin
- **Vendor security bulletins** (Microsoft, Cisco, Palo Alto, CrowdStrike): Tier B — Usually Reliable
- **Shodan/Censys exposure data**: Tier B for corroboration signal
- **GreyNoise**: Tier B — mass-scan and exploitation activity

**Step 3 — Implement source diversity gate**
Add a pipeline check: if any single source contributes >30% of the ingest batch, flag `source_concentration_warning` and trigger diversification sampling.

**Expected confidence impact:** Introducing A-tier and B-tier sources (score range 0.85–0.95) will raise average confidence to the 0.30–0.50 range for items sourced from those feeds. The overall average should move from 0.203 toward 0.30–0.40 as the source mix diversifies.

---

### 3.2 Corroboration Boost — Signal Enhancement

**Objective:** Reward items that appear in multiple independent sources.
**Current state:** 0/19 items have corroboration. Corroboration weight is 15%.

**Implementation Steps:**

**Step 1 — Build cross-source CVE deduplication index**
When the ingest pipeline processes a CVE ID, check if that CVE ID has already been ingested from a different source within the current feed window. Track `corroboration_sources` list per CVE.

**Step 2 — Apply corroboration multiplier**
- 1 source: no corroboration bonus (current behavior)
- 2 independent sources: +0.10 confidence boost
- 3+ independent sources: +0.15 confidence boost
- Same CVE from two sub-feeds of the same parent (e.g., two GitHub Advisories): does NOT qualify as corroboration

**Step 3 — Increase corroboration weight from 15% to 25%**
Rationale: Corroboration is the highest-signal quality indicator in threat intelligence. The current 15% weight undervalues this signal. Increase to 25%, reducing source reliability weight from 30% to 25% proportionally.

**New signal weights (proposed):**

| Signal | Current Weight | Proposed Weight |
|---|---|---|
| Source reliability | 30% | 25% |
| IOC validity rate | 20% | 20% |
| Corroboration count | 15% | 25% |
| EPSS contribution | Variable | Variable |
| KEV boost | Variable | Variable |
| Other signals | Remaining | Remaining |

**Validation requirement:** Score delta analysis before and after weight change must confirm no item drops more than 0.05 in confidence without a corresponding quality reduction. All changes must remain deterministic and explainable.

---

### 3.3 EPSS Coverage Improvement — Enrichment Cadence

**Objective:** Increase EPSS coverage from 5/19 (26%) to >15/19 (>79%).
**Target:** >80% of feed items carry an EPSS score within 24 hours of ingest.

**Implementation Steps:**

**Step 1 — Implement scheduled EPSS enrichment job**
- Schedule: every 6 hours
- API: FIRST.org EPSS API (`https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN`)
- Batch all CVE IDs in current feed; query EPSS API in single batch call
- Write EPSS score and percentile back to feed item

**Step 2 — Backfill existing 14 unscored items**
Run one-time EPSS backfill for all 14 CVE IDs currently missing EPSS scores.

**Step 3 — Handle CVE-2026 EPSS lag**
New CVEs may not have EPSS scores immediately (EPSS model typically lags 2–4 weeks for brand-new CVEs). For CVE-2026-series items with no EPSS score after 7 days, apply a `epss_pending` flag and a neutral EPSS contribution to the confidence score (neither boost nor penalty).

**Expected impact:** EPSS scores in the 0.01–0.10 range (low exploitation probability) will modestly reduce confidence for items with low EPSS. High EPSS items (>0.10) will receive a confidence boost that better differentiates truly dangerous items from theoretical vulnerabilities.

---

### 3.4 KEV Cross-Enrichment — Daily CISA Catalog Check

**Objective:** Automatically detect when current feed items are added to the CISA KEV catalog.
**Current state:** Live CISA catalog check is implemented (P0-3c fix in v174.1). No items are currently KEV-confirmed.

**Implementation Steps:**

**Step 1 — Daily KEV enrichment job**
- Schedule: once per day at 00:00 UTC
- Source: CISA KEV catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- For each CVE in current feed: check if CVE ID appears in KEV catalog
- If found: set `kev_confirmed=true`, apply KEV confidence boost (+0.15 to +0.20)

**Step 2 — KEV promotion alert**
When an item transitions from `kev_confirmed=false` to `kev_confirmed=true`, generate a priority alert for platform consumers. KEV addition is a high-confidence signal of active exploitation.

**Step 3 — Feed re-publication on KEV hit**
KEV confirmation should trigger immediate feed re-publication rather than waiting for the next scheduled ingest cycle. Confidence and risk scores must be recalculated with the KEV boost applied.

**Expected impact:** For CVE-2026-series items, KEV confirmation will be sparse in the short term. However, when it occurs, the +0.15–0.20 boost will push affected items from the 0.20–0.30 range to 0.35–0.50, clearly differentiating actively-exploited items from unconfirmed vulnerabilities.

---

## 4. Implementation Roadmap

| Step | Action | Owner | Sprint | Expected Confidence Impact |
|---|---|---|---|---|
| 4.1 | Assign Admiralty tiers to SecurityAffairs, BleepingComputer, Vulners | Intel Eng | N | Baseline alignment |
| 4.2 | Onboard CISA Advisories as A-tier source | Intel Eng | N | +0.05–0.10 avg |
| 4.3 | Implement EPSS enrichment job | Backend Eng | N | +0.02–0.05 avg |
| 4.4 | Build corroboration index | Backend Eng | N+1 | +0.05–0.08 per corroborated item |
| 4.5 | Increase corroboration weight 15%→25% | Intel Eng | N+1 | Redistributes weight |
| 4.6 | Onboard 2 vendor bulletin sources (B-tier) | Intel Eng | N+1 | +0.03–0.07 avg |
| 4.7 | Implement source diversity gate (<30% per source) | Backend Eng | N+1 | Structural improvement |
| 4.8 | Daily KEV enrichment job | Backend Eng | N+1 | +0.15–0.20 per KEV hit |
| 4.9 | Backfill EPSS for existing 14 unscored items | Backend Eng | N | One-time |

---

## 5. Validation Metrics

The following metrics define success for this remediation plan. Measured against a feed of at least 25 items:

| Metric | Current | Target | Measurement |
|---|---|---|---|
| Average confidence | 0.203 | >0.280 | Mean of all feed item confidence scores |
| Confidence range | 0.120–0.370 | 0.100–0.600 | Min/max spread |
| Unique confidence values | 11/19 (58%) | >70% unique | Distinct values / total items |
| LOW band concentration | ~67% | <35% | % items in 0.12–0.20 band |
| Source concentration (top 1 source) | 47% | <30% | Max single-source % |
| EPSS coverage | 26% | >79% | Items with EPSS score / total |
| Corroborated items | 0% | >25% | Items with 2+ sources / total |
| `confidence_uniformity` warning | ACTIVE | RESOLVED | Gate passes without warning |

---

## 6. Principles and Constraints

1. **No score inflation.** All confidence score changes must be grounded in evidence. No adjustment may increase a score without a corresponding quality signal (EPSS, KEV, corroboration, or source tier upgrade).
2. **Deterministic scoring.** The confidence engine must remain deterministic — same inputs produce same output. No randomness, no decay without evidence basis.
3. **Explainability.** Every score must be traceable to its input signals. The engine must log: `base_source_score`, `epss_contribution`, `kev_boost`, `corroboration_boost`, `final_score`.
4. **No fabrication.** It is preferable to report a low-confidence but accurate score than a high-confidence score without supporting evidence.
5. **Backward compatibility.** Weight changes must not cause existing feed items to drop below their current scores without a corresponding quality reduction.

---

*Document generated: 2026-06-04 | CYBERDUDEBIVASH® SENTINEL APEX | Principal CTI Architecture*
*Confidential — Internal Use Only*
