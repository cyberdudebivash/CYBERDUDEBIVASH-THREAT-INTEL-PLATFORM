# P33_ENGINE_MAP.md
## CYBERDUDEBIVASH® SENTINEL APEX — P33 Engine Map
**Date:** 2026-06-27

---

## P33 IMPORT / REUSE MAP

```
P33 Component          Imports / Reuses From
────────────────────────────────────────────────────────────────────────────
P33.1 Case Intel       computeP20QualityScore        (p20-handlers.js)
                       computeEnterpriseTrustScore   (p25-handlers.js)
                       computeActionabilityScore     (p23-handlers.js)
                       buildIRPackageBlock           (p23-handlers.js)
                       [orchestrates into unified case document]

P33.2 Campaign Intel   buildP31CampaignBlock         (p31-handlers.js)
                       computeEnterpriseTrustScore   (p25-handlers.js)
                       [adds cross-feed aggregation on top]

P33.3 SOC Mission      buildP28ActionCenterBlock     (p28-handlers.js)
                       buildP29DecisionEngineBlock   (p29-handlers.js)
                       computeActionabilityScore     (p23-handlers.js)
                       [aggregates into prioritized work queues per role]

P33.4 Recommendations  buildP32DecisionBlock         (p32-handlers.js)
                       buildP29DecisionEngineBlock   (p29-handlers.js)
                       computeP26Grade               (p26-handlers.js)
                       [adds time-horizoned horizon to existing decisions]

P33.5 Coverage Matrix  computeActionabilityScore     (p23-handlers.js)
                       [builds MITRE→format matrix across full feed]

P33.6 Heatmap          computeEnterpriseTrustScore   (p25-handlers.js)
                       computeP26Grade               (p26-handlers.js)
                       [aggregates per-item platform signals into heatmap]

P33.7 Explorer         [references P31 /api/v1/p31/graph + /api/v1/p31/search]
                       [dashboard UX layer — no engine duplication]

P33.8 Automation       computeP20QualityScore        (p20-handlers.js)
                       computeEnterpriseTrustScore   (p25-handlers.js)
                       buildP32MaturityBlock         (p32-handlers.js)
                       [orchestrates 11-step automation pipeline status]

P33.9 Ops Dashboard    computeP26Grade               (p26-handlers.js)
                       buildP32MetricsBlock          (p32-handlers.js)
                       computeActionabilityScore     (p23-handlers.js)
                       [synthesizes real-time threat level + business risk]

P33.12 Customer Layer  buildP32MaturityBlock         (p32-handlers.js)
                       computeEnterpriseTrustScore   (p25-handlers.js)
                       [adds customer success measurement on maturity]
```

---

## P33 COMPONENT → API ROUTE MAP

| Component | API Route | Handler |
|---|---|---|
| P33.1 Case Intelligence | /api/v1/p33/cases | handleP33Cases |
| P33.2 Campaign Intelligence | /api/v1/p33/campaigns | handleP33Campaigns |
| P33.5/P33.6 Heatmap + Coverage | /api/v1/p33/heatmap | handleP33Heatmap |
| P33.3 SOC Mission Planner | /api/v1/p33/mission | handleP33Mission |
| P33.4 Recommendations | /api/v1/p33/recommendations | handleP33Recommendations |
| P33.7 Knowledge Explorer | /api/v1/p33/explorer | handleP33Explorer |
| P33.9 Ops Dashboard | /api/v1/p33/dashboard | handleP33Dashboard |
| P33.8/P33.11 Automation + Reliability | /api/v1/p33/operations | handleP33Operations |
| P33.14 Certification Status | /api/v1/p33/status | handleP33Status |
| P33.12/P33.13 Customer + Marketplace | /api/v1/p33/metrics | handleP33Metrics |

---
*CYBERDUDEBIVASH® SENTINEL APEX — P33 Engine Map v1.0*
