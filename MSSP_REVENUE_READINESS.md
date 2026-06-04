# MSSP REVENUE READINESS REPORT
## SENTINEL APEX v175.0 — Phase 8 Commercial Readiness Sprint
**Audited:** 2026-06-04 | **Auditor Role:** Principal MSSP Commercialization Strategist

---

## AUDIT SCOPE

Files audited: `mssp.html`, `mssp-console.html`, `mssp-customer-center.html`, `partner.html`, `PARTNER_ONBOARDING.md`, `COMMERCIAL_LICENSE.md`, `enterprise.html`, `agent/api/enterprise_api.py`, `agent/api/auth.py`

---

## MSSP PROGRAM OVERVIEW (as marketed)

From `mssp.html`:
- Price: $1,999/month (≈ ₹1,65,000/month)
- Positioning: Multi-tenant CTI platform for MSSPs
- Claims: White-label, dedicated feeds, SLA-backed, API-first
- Contact: mssp.html links to a contact form

---

## READINESS DIMENSION 1 — FEED LICENSING

### Current State
- `COMMERCIAL_LICENSE.md` exists — commercial licensing framework present
- `agent/api/enterprise_api.py` and `premium_api.py` exist — separate API tiers for feeds
- STIX 2.1 / TAXII feed delivery infrastructure exists (referenced in onboarding.html)
- Feed licensing for resale is not explicitly defined in any public document

### Gaps

| Gap | Severity |
|-----|---------|
| No MSSP-specific feed license agreement (separate from end-user license) | P0 |
| No defined limit on number of clients an MSSP can serve on one subscription | P1 |
| No per-client sub-feed endpoint — MSSP cannot serve different data to different clients from one key | P1 |
| No documented feed refresh rate SLA for MSSP tier | P1 |

### Recommended MSSP Feed License Terms
```
SENTINEL APEX MSSP Feed License:
- MSSP may sub-license data feeds to up to [X] end clients
- Each end client must agree to SENTINEL APEX EULA
- White-label is permitted — MSSP may brand feeds under their name
- MSSP may NOT resell raw API access to end clients
- MSSP may NOT sublicense to other resellers (no multi-tier resale)
- MSSP feed SLA: 99.9% uptime, 15-minute data freshness
```

**Certification: CONDITIONAL PASS** — Framework exists, MSSP-specific license needed.

---

## READINESS DIMENSION 2 — RESELLER CAPABILITY

### Current State
- `partner.html` exists — partner/reseller page
- `PARTNER_ONBOARDING.md` exists — partner onboarding documentation
- No revenue-share structure documented in accessible format
- No reseller portal or dashboard

### Gaps

| Gap | Severity |
|-----|---------|
| No documented revenue-share model (e.g., 20% back to MSSP for client referrals) | P1 |
| No reseller agreement template | P0 |
| No reseller dashboard — MSSP cannot see their client usage | P0 |
| mssp.html "Contact Us" button — no self-service MSSP purchase path | P0 |

### Recommended Reseller Structure
```
MSSP Tier ($1,999/mo):
  - 1 Master API key (MSSP tier = 500,000 calls/day)
  - Up to 25 sub-client configurations
  - Revenue share: N/A (flat fee model for Phase 1)
  - MSSP sells their own services; SENTINEL APEX provides the data layer

Future (Phase 2):
  - Referral program: MSSP earns 15% of referred direct sales
  - Channel partner tier: 20% discount + co-marketing
```

**Certification: FAIL** — No MSSP purchase path exists. MSSP must contact sales with no automated flow.

---

## READINESS DIMENSION 3 — WHITE-LABEL POTENTIAL

### Current State
- White-label is mentioned in `mssp.html` marketing copy
- `agent/api/enterprise_api.py` exists with potential for customized endpoints
- No white-label configuration system found in codebase
- No per-MSSP branding configuration

### White-Label Capabilities Assessment

| Capability | Status | Effort |
|-----------|--------|--------|
| MSSP can serve data under their own brand | ✅ (data portability) | Low |
| API responses can be white-labeled (remove "SENTINEL APEX" branding) | ❌ Not implemented | Medium |
| Threat reports carry MSSP branding | ❌ Not implemented | Medium |
| Custom domain for MSSP API endpoint (api.msspname.com) | ❌ Not implemented | High |
| White-labeled dashboard for MSSP's clients | ❌ Not implemented | High |
| MSSP-branded PDF reports | ❌ Not implemented | Medium |

**Phase 1 White-Label (What Can Be Done Now):**
- MSSP receives STIX/JSON data — they can display it under their brand in their own tools
- Report PDFs: MSSP can add their logo/cover page manually
- This is "data white-label" not "platform white-label"

**Phase 2 (Recommended):**
- Add `X-MSSP-ID` header to API requests → API responds with MSSP-branded metadata
- PDF report generation includes MSSP logo (stored in MSSP profile)
- Sub-client API endpoints: `api.sentinel-apex.com/mssp/[MSSP_ID]/[CLIENT_ID]/`

**Certification: CONDITIONAL PASS** — Data portability enables practical white-label for Phase 1.

---

## READINESS DIMENSION 4 — SUB-TENANT SUPPORT

### Current State
- `mssp-console.html` exists — multi-tenant console UI shell
- Backend: No sub-tenant model found in `agent/api/` code
- Auth system (`auth.py`) does not have a parent/child key relationship
- No sub-tenant provisioning API

### Sub-Tenant Requirements for MSSP

| Requirement | Status |
|------------|--------|
| Create sub-client API key from master MSSP key | ❌ Not implemented |
| Set per-client rate limits | ❌ Not implemented |
| Isolate client data (client A cannot see client B's queries) | ❌ Not implemented |
| MSSP can revoke a client key without affecting others | ❌ Not implemented |
| MSSP dashboard showing all client usage | ❌ Not implemented (UI shell only) |

### Phase 1 Sub-Tenant Workaround

Until backend sub-tenancy is built, deliver MSSP tier as:
```
MSSP Master Key → Single high-quota key (500,000 calls/day)
MSSP manages their own client routing internally
MSSP generates sub-keys manually (using generate_key.py with MSSP tier)
Each sub-client gets their own API key issued by MSSP
SENTINEL APEX provides: key generation support, quota top-ups, direct MSSP support
```

This is a "concierge sub-tenancy" model — practical for first 1-5 MSSP clients.

**Certification: CONDITIONAL PASS** — Manual workaround viable for Phase 1 (1-5 MSSP clients).

---

## READINESS DIMENSION 5 — ENTERPRISE ONBOARDING FOR MSSP CLIENTS

### Current State
- `sentinel-onboarding.html` has multi-step onboarding UI
- `onboarding.html` has SIEM integration guides (Splunk, Sentinel, Elastic, QRadar)
- No MSSP-specific onboarding guide (how to set up for multiple clients)
- No "onboard a client" checklist for MSSPs

### Required: MSSP Client Onboarding Checklist
```
MSSP ONBOARDING — NEW CLIENT CHECKLIST

[ ] Collect client: company name, primary SIEM, sector, country, POC email
[ ] Generate client API key (via SENTINEL APEX support or self-service)
[ ] Configure client SIEM integration (use onboarding.html guides)
[ ] Configure client-specific alert thresholds (sector-relevant CVEs)
[ ] Test first API pull from client SIEM
[ ] Deliver first threat digest to client
[ ] Schedule monthly threat briefing
[ ] Configure client access to reports (STIX/PDF download)
```

**Certification: CONDITIONAL PASS** — SIEM guides exist; MSSP-specific workflow not documented.

---

## MSSP PRICING & COMMERCIAL MODEL

### Current Pricing
- $1,999/month (≈ ₹1,65,000/month)
- Positioned vs. commercial CTI feeds (Recorded Future: $50,000+/yr, Mandiant: $30,000+/yr)

### Value Proposition
- 1 MSSP subscription → covers up to 25 clients → MSSP earns service margin
- If MSSP charges ₹15,000/client/month × 10 clients = ₹1,50,000/month revenue
- MSSP cost: ₹1,65,000 → margin at 10 clients = approximately break-even
- At 15 clients: ₹2,25,000 revenue - ₹1,65,000 cost = **₹60,000/month margin**
- At 25 clients: ₹3,75,000 revenue - ₹1,65,000 cost = **₹2,10,000/month margin**

This is a compelling value proposition — needs to be communicated on mssp.html.

### Recommended: Add MSSP ROI Calculator to mssp.html
```
Slider: Number of clients (1-50)
MSSP platform cost: ₹1,65,000/month (fixed)
Revenue per client: ₹15,000/month (adjustable)
→ Shows: Gross margin, break-even point, 12-month projection
```

---

## MSSP READINESS SCORECARD

| Dimension | Score | Status |
|-----------|-------|--------|
| Feed Licensing | 5/10 | License framework exists, MSSP-specific terms missing |
| Reseller Capability | 3/10 | No purchase path, no dashboard |
| White-Label | 4/10 | Data portability only, no platform white-label |
| Sub-Tenant Support | 3/10 | UI shell only, no backend |
| Enterprise Onboarding | 6/10 | SIEM guides exist, MSSP workflow missing |
| Commercial Model | 7/10 | Strong pricing, poor on-page communication |
| **Overall MSSP Readiness** | **4.7/10** | **NOT READY for autonomous MSSP acquisition** |

---

## PHASE 1 MSSP GO-TO-MARKET (MANUAL — HIGH-TOUCH)

For the first 1-3 MSSP clients, use a high-touch concierge model:

```
MSSP Discovery (mssp.html contact form)
        ↓
Bivash personal outreach within 24h
        ↓
30-minute discovery call
        ↓
Custom proposal email (plan, pricing, client count)
        ↓
MSSP agreement sent (PDF email)
        ↓
Payment via approved method (UPI/PayPal/Bank Transfer)
        ↓
Manual onboarding session (90 minutes) with Bivash
        ↓
Master API key issued
        ↓
First 3 client sub-keys generated manually
        ↓
Monthly check-in + usage review
```

**Target: First MSSP client within 60 days. 3 MSSP clients within 90 days.**

---

## TOP 5 MSSP FIXES REQUIRED

1. Add MSSP purchase path to mssp.html (contact form → email → payment → manual activation)
2. Write MSSP License Agreement template (PDF)
3. Add MSSP ROI calculator to mssp.html
4. Write MSSP Client Onboarding Checklist document
5. Add MSSP tier to backend auth.py (TIER_MSSP with 500,000 calls/day)

---

*Audit completed: 2026-06-04 | SENTINEL APEX v175.0 Commercial Readiness Sprint*
