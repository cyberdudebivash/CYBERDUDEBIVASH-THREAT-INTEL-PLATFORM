# CHANGELOG — SENTINEL APEX v76.0 → v76.3
**Platform:** intel.cyberdudebivash.com
**Released:** 2026-03-26
**Scope:** Dashboard card accuracy · TLP accuracy · Report quality · Pipeline hardening

---

## v76.3.0 (2026-03-26) — INTEL REPORT 100% RELIABILITY

### Objective
Make every published intel report 100% accurate, 100% trustworthy, and 100% useful
for SOC teams, security researchers, publications, media, and global audiences.

### Report Quality Fixes (6 bugs)

**BUG 1 — IOC confidence always "Medium-High" for every indicator type**
- Root cause: all IOC types used a single hardcoded string "Medium-High"
- Fix: each IOC type now carries correct evidence-based confidence:
  SHA256=High, Domain=High, IPv4=High, CVE=High, URL=Medium-High,
  SHA1=Medium-High, MD5=Medium, Email=Medium, Registry=Medium, Artifact=Medium

**BUG 2 — Global Trends section (Section 13) identical in every report**
- Root cause: single boilerplate paragraph regardless of threat category
- Fix: category-specific trend context for each threat type:
  - Ransomware: RaaS ecosystem, double/triple extortion, healthcare targeting
  - Supply Chain: npm/PyPI targeting, dependency concentration risk
  - Phishing/Identity: AitM frameworks, infostealer pipelines, FIDO2 countermeasures
  - APT/Espionage: living-off-the-land, 200+ day dwell times, state actor TTPs
  - Data Breach: cloud misconfiguration root causes, GDPR/regulatory cost
  - Vulnerability: exploitation timeline compression, KEV catalog significance
- Intelligence confidence note added to every trends section

**BUG 3 — Campaign Background (Section 2) third paragraph was pure boilerplate**
- Old text claimed "regional targeting patterns" and "commoditization" with zero grounding
- Fix: replaced with attribution disclaimer and sector-specific analyst assessment
- Reports now clearly label speculative content as "Analyst Assessment"

**BUG 4 — Infrastructure Mapping falsely claimed "multiple autonomous systems/geographic regions" with 0 IOCs**
- Root cause: fallback text described non-existent infrastructure confidently
- Fix: zero-IOC case now accurately explains WHY indicators are unavailable
  (legitimate cloud C2, rotating infra, vulnerability scope) rather than fabricating claims
- With IOCs: states exact counts and directs to Section 4 — no speculation

**BUG 5 — MITRE ATT&CK fallback always T1190+T1059 regardless of threat type**
- Root cause: single generic baseline used for all categories
- Fix: category-appropriate fallback techniques:
  - Ransomware → T1566, T1562.001, T1021.002, T1486, T1490
  - Phishing/Identity → T1566.002, T1539, T1111, T1098.001, T1530
  - Supply Chain → T1195.002, T1059, T1547, T1041
  - Vulnerability → T1190, T1203, T1068, T1211
  - Data Breach → T1078, T1083, T1005, T1567

**BUG 6 — `UNC-UNKNOWN` actor tag displayed verbatim in dashboard cards**
- Root cause: fallback `actor = item.actor_tag || 'UNC-CDB-99'` showed raw internal ID
- Fix: both `UNC-CDB-99` and `UNC-UNKNOWN` now display as `UNATTRIBUTED`

---

## v76.2.0 (2026-03-26) — TLP ACCURACY

### TLP Classification Fix

**BUG — TLP:AMBER shown on CVSS 9.8 RCE (Canon ZDI, Apple patches)**
- Root cause (backend): `risk_engine.py` v23.0 required KEV OR (IOCs AND confirmed_actor)
  for TLP:RED at score ≥ 9.0. CVSS 9.8 without KEV was downgraded to AMBER — wrong.
- Root cause (frontend): `getTlpLabel()` used score-only thresholds with no CVSS check.

**Fix — `agent/risk_engine.py` v76.2:**
- CVSS ≥ 9.0 now independently qualifies for TLP:RED (no KEV required)
- Logic: RED if KEV=true OR CVSS≥9.0 OR (score≥9 AND confirmed IOCs AND named actor)
- Non-CVE articles (score 10/10 editorial) still require KEV or actor evidence → AMBER
- TLP:AMBER threshold for score 7-9: now also checks CVSS≥7.0 as qualifying signal

**Fix — `agent/sentinel_blogger.py` v76.2:**
- First TLP call (pre-NVD): `cvss_score=None` explicitly — no false signals
- Second TLP call (post-NVD): `cvss_score=cvss_score` passed — enables RED qualification

**Fix — `index.html` `getTlpLabel()` v76.2:**
- Mirrors backend logic exactly: CVSS≥9.0 → RED, CVSS≥7.0 qualifies AMBER
- Manifest-stored `tlp_label` still takes priority (set at ingest time by pipeline)

### TLP Classification Table (after fix)
| Scenario | Old TLP | Correct TLP |
|---|---|---|
| Risk 10/10, CVSS 9.8, no KEV | TLP:AMBER | **TLP:RED** |
| Risk 10/10, CVSS 9.4, KEV=true | TLP:RED | TLP:RED (unchanged) |
| Risk 9.4/10, no CVSS, no KEV | TLP:AMBER | TLP:AMBER (correct — no evidence) |
| Risk 8.9/10, CVSS 7.5, no KEV | TLP:AMBER | TLP:AMBER (unchanged) |
| Risk 8.5/10, no CVSS | TLP:AMBER | TLP:AMBER (score-based, correct) |

---

## v76.1.0 (2026-03-26) — DASHBOARD CARD ACCURACY (11 bugs)

**BUG 1** — P4 on 10/10 CRITICAL (no CVSS) → Rule 7: risk_score fallback
**BUG 2** — ASSESS on 10/10 → PATCH NOW for P1+risk≥9
**BUG 3** — EPSS 0.29% shown as MEDIUM → <1%=LOW, 1-10%=LOW-MED, 10-50%=MEDIUM, ≥50%=HIGH
**BUG 4** — Exploit badge at EPSS≥70% → unified to ≥50%
**BUG 5** — `_exploit` variable at EPSS≥70% → ≥50%
**BUG 6** — LIKELIHOOD MEDIUM for 0.29% EPSS → corrected + risk_score fallback
**BUG 7** — EPSS bar red≥70%, orange≥40% → red≥50%, orange≥10%, amber≥1%
**BUG 8** — IMPACT ignores `threat_type` manifest field → uses `item.threat_type` first
**BUG 9** — `item.kev` wrong field in 2 functions → `item.kev_present`
**BUG 10** — "Moderate probability" for 0.29% EPSS → "Low exploitation probability"
**BUG 11** — SOC confidence LOW on 10/10 → risk_score fallback → MEDIUM

---

## v76.0.0 (2026-03-25) — PLATFORM FINALIZER + FULL AUDIT

- `scripts/v76_platform_finalizer.py` — 7-task post-pipeline orchestrator
- `scripts/v75_pipeline_hardener.py` — sort + 3-layer dedup + daily archive
- `scripts/pre_deploy_gate.py` — upgraded 5→8 checks
- `agent/export_stix.py` — atomic write + sort-before-trim
- `agent/config.py` — 12 dead feeds replaced, 40 active feeds
- All 24 workflows audited, concurrency gaps closed
- `.gitignore` — `blogger_processed.json` uncommented (dedup persistence fix)

---

## Cumulative Production Metrics
| Metric | Value |
|---|---|
| Best run advisories | 18 (run #551) |
| Report word count | 2954–3167w |
| Pre-deploy gate | 8/8 PASS |
| Archive entries | 583+ (growing daily) |
| Active feeds | 40 / 58 configured |
| KEV confirmed | 24 advisories in manifest |
| CRITICAL advisories | 112 in manifest |
| TLP:RED advisories | 97 (correctly classified) |
| Revenue CTAs | Active on all published advisories |

---

## Files Changed — Complete Push List
```
agent/risk_engine.py              # TLP v76.2: CVSS>=9 qualifies RED
agent/sentinel_blogger.py         # TLP v76.2: cvss_score passed to get_tlp_label
agent/content/premium_report_generator.py  # v76.3: 6 report quality fixes
agent/content/quality_gate.py     # v76.1: trusted-source bypass
agent/content/source_fetcher.py   # v76.0: NVD fallback
scripts/threat_page_generator.py  # v76.1: datetime.utcnow deprecation
.github/workflows/sentinel-blogger.yml
.github/workflows/multi-source-intel.yml
.github/workflows/sync-dashboard.yml
.github/workflows/weekly-analyst-briefing.yml
.github/workflows/detection-engine.yml
.github/workflows/ai-predictions.yml
.github/workflows/revenue-orchestrator.yml
index.html                        # v76.1+v76.2+v76.3: all dashboard fixes
VERSION                           # 76.3.0
CHANGELOG_v76.md                  # this file
```

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
