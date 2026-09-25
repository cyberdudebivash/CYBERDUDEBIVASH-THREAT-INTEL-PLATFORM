# Customer dashboard data contract (v1.0, 2026-09-24)

One authority for what the homepage intelligence widgets show, and what
each value means.

## Data authority

```
Before                                           After
------                                           -----
EICC engine ── api/feed.json (10 s timeout)      /api/health ─┐ (freshness contract)
   └── on failure: raw.githubusercontent.com      /api/feed.json ┴─> js/apex-dashboard-snapshot.js
       (frozen 109-item mirror) shown "API LIVE"                     └─> EICC: ticker, metrics, Last Sync,
   └── errors rendered as "no intelligence"                             preview, geo panel (one snapshot)
sentinel-live-feeds ── latest.json (0.9 MB, 2 min)
   (into containers the homepage does not have)  Worker (same loadFeedItems() generation per request):
NEXUS renderers ── items / engine file,             /api/v1/intel/stats    -> Last Sync alias, feeds
   partial technique map -> all zeros               /api/v1/intel/defcon   -> threat level + evidence
Worker /campaigns: every CRITICAL = "campaign"      /api/v1/intel/campaigns -> ATT&CK tactics, campaigns
                                                    /api/v1/intel/ransomware -> monitor + activity
                                                    /api/v1/intel/cybermap -> attribution coverage
                                                  └─> js/sentinel-live-feeds.js (gadgets, #nexus-killchain)
```

Every operational DOM node has one runtime owner
(`workers/intel-gateway/src/__tests__/dashboard-frontend-contract.test.js`).

## Semantics

| Widget | Source | Meaning |
|---|---|---|
| Ticker / total | `/api/feed.json` via snapshot | `ticker_count == feed items`. Empty, stale and error are distinct: `NO CURRENT ADVISORIES IN THE AUTHORITATIVE FEED` / `INTELLIGENCE DEGRADED — LAST AUTHORITATIVE UPDATE: <UTC>` / `INTELLIGENCE TEMPORARILY UNAVAILABLE` |
| Last Sync | `/api/health` `intelligence.generated_at` | Feed generation time (relative + UTC). Not the newest item date, not page time. `N/A` when unknown |
| API / INTEL | `/api/health` | `API ● LIVE` = the API answered. `INTEL ● FRESH/DEGRADED/UNVERIFIED/UNAVAILABLE` = the freshness contract. Never inferred from each other |
| Sources in feed | snapshot | Distinct `feed_source` hosts in the current feed; `N/A` when unmeasured |
| Total IOCs | snapshot | Sum of per-item `ioc_count` (else `iocs.length`) |
| Geo panel | `actor_country` only | Threat-actor attribution. Publisher, vendor, victim and IP geography are not origin. With no attribution: `0 of N advisories carry authoritative country attribution. Origins are not estimated.` |
| Ransomware | `/api/v1/intel/ransomware` | `MONITOR ● OPERATIONAL` is separate from activity. Classifier `ransomware-classifier/1.2`: threat_type, tags, malware family, then title; never description. Pipeline-generated titles (see Campaigns) are not read. Pipeline actor labels (`actor`, `mitre_group_name`) are keyword-inferred, so they are supporting evidence only (`actor_label:<name>`, placeholders dropped): they never classify an item or make a group active. A group is active only when one of those fields of a current ransomware-classified item names it. Victims are not measured (`null`, shown `N/A`) |
| Threat level | `/api/v1/intel/defcon` | `threat-level/1.0`: `min(10, min(avg_risk,10) + min(kev*0.15,1.5) + min(critical*0.05,0.5))`; bands ≥8.5 CRITICAL, ≥7 HIGH, ≥5 ELEVATED, ≥3 GUARDED. Shown `LIVE` only when the publication is fresh; otherwise `THREAT LEVEL STALE/UNAVAILABLE`, no score |
| ATT&CK coverage | `/api/v1/intel/campaigns` `attack_tactics` | `attack-tactics/1.1`, the 14 Enterprise tactics. Per item: `mitre_tactics[].tactic`, else `attck_techniques[].tactic`, else technique ids mapped through the technique/tactic pairs in the same feed generation, else technique ids mapped through the MITRE ATT&CK reference (`attck_reference`), else legacy `kill_chain_phases`. Severity never produces a tactic. See *ATT&CK reference map* below |
| Campaigns | `/api/v1/intel/campaigns` | `campaign-evidence/1.3`: campaign threat_type or tag, or "campaign" / "<actor> operation" in the title. Pipeline-generated titles are not read: actor-cluster labels (`CDB-UNATTR-PHI Campaign`) and the invented headlines `intelligence_quality_hardener.py` used to write (`APT41 Espionage Campaign — …`). Pipeline campaign links (`campaign_id`, `campaign`, `campaign_name`) and MITRE group labels are keyword-inferred, so they are supporting evidence only. Severity, risk, KEV, a campaign id or an actor label alone never make a campaign |
| Derived kill chain (gadget) | `phases` (deprecated) | Lockheed buckets derived from the ATT&CK tactics above; labelled "DERIVED KILL CHAIN (FROM ATT&CK)" |
| AI tracker | `/api/ai/tracker.json` | Probabilities only when the model reports one. `escalation_tracker` risk scores render as `RISK x/10`, never as a percentage. No model output: `PREDICTION DATA UNAVAILABLE` |

## ATT&CK reference map (attack-tactics/1.1)

Live feeds carry technique ids (`attck_technique_ids`) but no tactic: `attck_techniques` entries are `{id, name}` and
`mitre_tactics` holds technique names (the STIX re-ingest in `run_pipeline.py` writes `ttps[:5]` there). With only
in-feed pairs to map through, coverage read 0 of 45 on 2026-09-25.

`workers/intel-gateway/src/attack-technique-tactics.js` is generated by `scripts/build_attack_tactic_map.py` from
`data/attck/enterprise-attack.json` (the MITRE reference sync, `scripts/true_intel_ingestor.py`). 222 parent
techniques; a sub-technique uses its parent's tactics (identical for all 475 in the reference). The reference is
ATT&CK v18, which split TA0005 into Stealth (TA0005) and Defense Impairment (TA0112); on the dashboard's 14-tactic
matrix both are Defense Evasion, so the response shape is unchanged. `dashboard-contract.test.js` recomputes the
table from the reference and fails when it is stale: rerun the script after updating the reference.

Live recompute (45 items): 17 carry technique ids, 17 map, 7 tactics observed; the 28 without ids stay uncounted.

## Advisory titles

Titles come from the advisory. `run_pipeline.py` (`stix_advisory_title`) no longer uses a STIX intrusion-set name that
is an actor-cluster label as the title (476 of 503 committed platform bundles); it uses the description headline.
`intelligence_quality_hardener.py` `[C]` restores that headline instead of writing template headlines; the templates
are deprecated and kept only to recognise titles written by earlier runs (`tests/test_advisory_title_integrity.py`).

## Deprecations

- `/api/v1/intel/campaigns` `phases`, `coverage_pct`, `total_tactics`: kept for existing readers
  (`phases_model` marks them); replacement `attack_tactics`. Removal not before the next major release.
- `/api/v1/intel/stats` `last_sync` remains the newest item's publish time; `last_feed_sync_utc`
  is the feed generation time (the service worker aliases it for the dashboard).

## Gates

- `workers/intel-gateway/src/__tests__/dashboard-contract.test.js`: derivations.
- `workers/intel-gateway/src/__tests__/dashboard-frontend-contract.test.js`: zero-fabrication scan,
  single DOM owner, escaping, template == shipped block, service-worker invariants.
- `js/__tests__/apex-dashboard-snapshot.test.js`: snapshot states.
- `workers/intel-gateway/scripts/dashboard-negative-controls.mjs`: 21 mutation controls.
- `render-test/verify_dashboard_data_contract.js`: real Chromium, 5 scenarios, 3 viewports.
