# SENTINEL APEX MSSP WHITE-LABEL ONBOARDING KIT
## Version 1.0 | Date: 2026-06-04

---

## PURPOSE

This kit gives MSSP partners everything needed to deploy SENTINEL APEX intelligence under their own brand and deliver it to their managed clients.

---

## PART 1 — WHITE-LABEL USAGE RIGHTS

Under the MSSP Agreement (MSSP_AGREEMENT_TEMPLATE.md, Section 2), you may:

**Permitted:**
- Brand threat intelligence reports as "[YOUR COMPANY] Threat Intelligence"
- Deliver STIX 2.1 bundles to clients without SENTINEL APEX attribution (except source fields)
- Customize report headers, footers, and executive summaries
- Deliver weekly/monthly briefings under your brand
- Describe the service as "our threat intelligence platform"

**Not Permitted:**
- Share or resell raw API access to clients directly
- Remove STIX object source attribution from STIX bundles
- Claim intellectual property ownership of the intelligence
- Sublicense to other resellers

---

## PART 2 — WHAT YOUR CLIENTS SEE

### Branded Deliverable Options

**Option A — White-Label Weekly Briefing**

Deliver a weekly email briefing branded as your company using the weekly briefing template (PREMIUM_ANALYST_BRIEFING_TEMPLATE.md) with your logo/name substituted.

**Option B — White-Label STIX Bundle Delivery**

Deliver STIX 2.1 bundles from the API to your clients' OpenCTI/MISP instances. Bundle structure doesn't change; you deliver it.

**Option C — SIEM Rule Delivery**

Pull Sigma/YARA/Snort rules from SENTINEL APEX API and deliver to client SIEM as "[YOUR COMPANY] Detection Pack".

**Option D — Custom Client Reports**

Use the PREMIUM_ANALYST_BRIEFING_TEMPLATE.md to generate monthly per-client reports. Customize the header, logo, and executive summary for each client.

---

## PART 3 — YOUR MASTER KEY

Your MSSP Master Key gives you:
- 500,000 API calls/day — covers all your managed clients
- Full PRO + Enterprise tier access
- STIX 2.1 bundles
- Detection rules (Sigma/YARA/Snort)
- AI predictions (30-day exploitation forecasts)
- Full IOC tables
- Executive briefings

**Master Key format:** `SA-MSSP-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

**Keep your master key confidential.** Only use it within your own infrastructure — not in client-facing tools that clients could read from.

---

## PART 4 — SUB-KEY PROVISIONING FOR CLIENTS

When an MSSP client needs direct API access (advanced integration), request a sub-key:

**To request a sub-key:**
```
Email: bivash@cyberdudebivash.com
Subject: Sub-key request — [YOUR_COMPANY] for client [CLIENT_NAME]
Body:
  - Client name: [NAME]
  - Client email: [EMAIL]
  - Tier requested: PRO or ENTERPRISE
  - Duration: 30 or 365 days
  - Reference: [YOUR_MSSP_PARTNER_ID]
```

**Delivery:** Sub-key provisioned within 2 hours of request.
**Capacity:** Unlimited sub-keys included in MSSP subscription.
**Sub-key format:** `SA-PRO-XXXX` or `SA-ENT-XXXX` (not SA-MSSP-)

---

## PART 5 — SIEM INTEGRATION GUIDE FOR YOUR CLIENTS

### Splunk Integration
```
# Add to Splunk HEC inputs or use lookup:
curl -H "X-API-Key: [CLIENT_SUBKEY]" \
  "https://intel.cyberdudebivash.com/api/feed?format=splunk" \
  | splunk add oneshot -

# For real-time push (Enterprise tier):
SIEM Webhook URL: Configure at API settings
Push format: JSON
Frequency: Every 6 hours (standard) or live (Enterprise)
```

### Microsoft Sentinel Integration
```
# STIX ingestion via Logic App or Sentinel TAXII connector:
API Root: https://intel.cyberdudebivash.com/api/taxii/
Auth: X-API-Key header
Collection: /api/taxii/collections/main/

# Sigma rules via Azure Automation:
GET https://intel.cyberdudebivash.com/api/rules/sigma?severity=HIGH
```

### IBM QRadar Integration
```
# REST API endpoint for QRadar reference data:
GET https://intel.cyberdudebivash.com/api/iocs?format=qradar
Header: X-API-Key: [KEY]

# STIX via TAXII feed connector in QRadar:
TAXII Server: https://intel.cyberdudebivash.com/api/taxii/
```

### Elastic SIEM Integration
```
# Filebeat integration:
module: cti
var.url: https://intel.cyberdudebivash.com/api/feed
var.api_token: [KEY]

# Or direct Elasticsearch ingest:
POST https://intel.cyberdudebivash.com/api/feed?format=elastic
```

---

## PART 6 — CLIENT REPORTING WORKFLOW

### Monthly Client Report Process

1. Pull this month's HIGH/CRITICAL advisories from the API:
   `GET /api/feed?severity=HIGH,CRITICAL&from=2026-06-01`

2. Filter by client's sector (if known)

3. Use PREMIUM_ANALYST_BRIEFING_TEMPLATE.md to structure the report

4. Customize:
   - Replace "SENTINEL APEX" in header with "[YOUR COMPANY] Threat Intelligence"
   - Add client logo/name in header
   - Customize executive summary to reference their specific environment
   - Include their relevant SIEM integration status

5. Export as PDF and deliver by email

**Delivery schedule:** Within 5 business days of month-end (recommended)

---

## PART 7 — MSSP PRICING GUIDANCE

You are free to price your managed clients at any rate that covers your MSSP subscription ($1,999/month) plus your margin.

**Example pricing models:**

| Model | Suggested Price to Client | Your Margin |
|-------|--------------------------|-------------|
| CTI as a service add-on | $199-499/client/month | High at scale |
| Included in SOC retainer | Bundle into $2,500-5,000/month | Undifferentiated |
| Standalone intel service | $299/client/month | 85%+ at 10+ clients |
| Annual contract | $2,988/client/year | Strong recurring |

**Break-even analysis:**
- At 1 client: Break even at $1,999/month client pricing
- At 3 clients: Break even at $667/month per client
- At 10 clients: Break even at $200/month per client — $17,990/month at $1,999/client

---

## PART 8 — ONBOARDING CHECKLIST FOR NEW MSSP

```
WEEK 1:
[ ] Master key delivered and tested (GET /api/feed — should return live advisories)
[ ] First SIEM integration completed (see integration guides above)
[ ] WhatsApp support group created
[ ] First advisory accessed at PRO+ tier (verify full IOC tables visible)
[ ] Sub-key provisioning tested (request 1 sub-key for a test client)

WEEK 2:
[ ] First client integration delivered
[ ] First weekly briefing draft prepared (using PREMIUM_ANALYST_BRIEFING_TEMPLATE.md)
[ ] API call volume reviewed (should have 1,000+ calls in first week)
[ ] Sigma rules imported to client SIEM

MONTH 1:
[ ] All active clients integrated
[ ] Monthly report delivered to first client
[ ] Renewal reminder set for Day 17 of each client's cycle
[ ] Sub-key audit: all client keys active and correct tier
```

---

*MSSP White-Label Onboarding Kit v1.0 · SENTINEL APEX v177.0 · 2026-06-04*
*Contact: bivash@cyberdudebivash.com | +91 8179881447*
