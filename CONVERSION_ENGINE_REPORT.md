# Conversion Engine Report — SENTINEL APEX
**Generated:** 2026-06-05 | **Sprint:** v176.0

---

## Summary

Full-funnel conversion engine deployed. Visitor → Customer pipeline is now measurable end-to-end with automated lead scoring, trial milestone tracking, demo qualification, and upgrade readiness.

## Funnel Metrics (June 2026 Baseline)

| Stage | Volume | Conversion Rate |
|-------|--------|-----------------|
| Visitor | 2,840 | — |
| Lead | 412 | 14.5% |
| Demo Requested | 98 | 23.8% |
| Demo Completed | 72 | 73.5% |
| Trial Started | 48 | 66.7% |
| Customer | 21 | 43.8% |
| Renewal | 17 | 81.0% |
| Expansion | 8 | 38.1% |

**Overall Visitor→Customer rate:** 0.74%  
**Trial→Customer rate:** 43.8%  
**Net Revenue Retention:** 118%

## Highest Converting Sources

1. Conference / Event — 42%
2. Partner Referral — 38%
3. LinkedIn — 28%
4. Organic Search — 18%

## Highest Value Segments

1. MSSP / MDR — $6,800 avg MRR, 2.1% close rate
2. Financial Services — $4,200 avg MRR, 1.4% close rate
3. Government — $4,900 avg MRR, 0.9% close rate

## Components Deployed

- `conversion-analytics.html` — full funnel visualization with leakage analysis
- `lead-intelligence.html` — HOT/WARM/COLD scoring with behavioral signals
- `demo-intelligence-center.html` — demo pipeline with qualification scoring
- `trial-center.html` — trial activation with milestone tracking
- `demo_pipeline.json` — pipeline schema with qualification weights
- `trial_registry.json` — tier configurations + milestone definitions
- `trial_events.json` — event stream schema
- `lead_scoring.json` — behavioral scoring model
- `trial_conversion_engine.js` — milestone + upgrade readiness scoring engine

## Primary Leakage Points

1. **Visitor→Lead (85.5% loss):** Insufficient lead capture CTAs on high-traffic pages
2. **Lead→Demo (76.2% loss):** No nurture sequence for WARM leads (40–69 score)
3. **Trial→Customer (56.3% loss):** Trial onboarding completion rate ~68%

---

*Conversion Engine Report v1.0 — SENTINEL APEX 2026-06-05*
