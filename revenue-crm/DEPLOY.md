# CYBERDUDEBIVASH® SENTINEL APEX — Revenue System Deployment v123.0.0

## STEP 1 — Provision KV + D1 namespaces

```bash
# Revenue CRM KV
npx wrangler kv namespace create "REVENUE_CRM_KV"
npx wrangler kv namespace create "EMAIL_QUEUE_KV"

# D1 SQLite CRM database
npx wrangler d1 create sentinel-crm

# Apply CRM schema
npx wrangler d1 execute sentinel-crm --file=revenue-crm/schema.sql
```

Update wrangler.toml with the printed IDs.

## STEP 2 — Set secrets

```bash
cd workers/revenue-engine

npx wrangler secret put REVENUE_ADMIN_SECRET   # your secure admin key
npx wrangler secret put SENDGRID_API_KEY       # from sendgrid.com
npx wrangler secret put SLACK_WEBHOOK_URL      # from Slack app settings
npx wrangler secret put RAZORPAY_KEY_ID
npx wrangler secret put RAZORPAY_KEY_SECRET
npx wrangler secret put STRIPE_SECRET_KEY
```

## STEP 3 — Deploy revenue engine

```bash
cd workers/revenue-engine
npx wrangler deploy
# → https://sentinel-revenue-engine.<your-subdomain>.workers.dev

# Set custom domain
npx wrangler deploy --env production
# Configure DNS: revenue.intel.cyberdudebivash.com → worker
```

## STEP 4 — Wire revenue enforcement into intel-gateway

In `workers/intel-gateway/src/index.js`, add at the top:
```js
import {
  enforceTierGate,
  trackUsageAndEnforce,
  buildUpgradeTrigger,
  buildUsageLimitResponse,
  handleLeadCapture,
  handleTrialIssuance,
  handleRevenueAnalytics,
  applyTierGateV2,
  trackRevenueEvent,
} from "./revenue-enforcement.js";
```

Add routes in the fetch handler:
```js
if (pathname === "/api/leads/capture" && method === "POST") return handleLeadCapture(request, env, rid);
if (pathname === "/api/leads/trial"   && method === "POST") return handleTrialIssuance(request, env, rid);
if (pathname === "/api/revenue/analytics" && method === "GET") return handleRevenueAnalytics(request, env, rid);
```

In the auth middleware — add usage tracking per request:
```js
const usageState = await trackUsageAndEnforce(env, auth.key_id, auth.tier);
if (!usageState.allowed) return buildUsageLimitResponse(usageState, rid);
```

Replace `applyTierGate` with `applyTierGateV2` in handleFeed and handleReport.

## STEP 5 — Inject frontend revenue system into index.html

Add before `</body>`:
```html
<script src="/revenue-crm/frontend-injection.js"></script>
```

Or inline the content of `revenue-crm/frontend-injection.js` as a `<script>` block.

Add data attributes to gated buttons:
```html
<button data-cdb-gate="ioc_access">View IOC Array</button>
<button data-cdb-gate="stix_request">Export STIX Bundle</button>
<button data-cdb-gate="report_full">Read Full Report</button>
```

## PHASE 6 — ₹10L MRR SCALE MODEL

### Revenue Mix

| Plan        | Price/mo | Customers Needed | MRR Contribution |
|-------------|----------|-----------------|-----------------|
| Enterprise  | ₹14,999  | 47              | ₹7,04,953       |
| Pro         | ₹2,499   | 120             | ₹2,99,880       |
| **TOTAL**   |          | **167**         | **₹10,04,833**  |

### Outreach Math (Enterprise — back-calculated from funnel)

| Funnel Stage         | Rate | Volume/month |
|---------------------|------|-------------|
| Cold email → Reply  | 8%   | 5,875 emails/mo → 470 replies |
| Reply → Demo        | 40%  | 470 → 188 demos |
| Demo → Trial        | 60%  | 188 → 113 trials |
| Trial → Paid        | 18%  | 113 → 20 enterprise closes |
| **Target**          |      | **47 deals** (scale over 3 months) |

**Cold emails/day needed: ~267/day** (achievable via Apollo.io + Instantly.ai + SendGrid)

### PLG Math (Pro — product-led growth)

| Funnel Stage         | Rate | Volume/month |
|---------------------|------|-------------|
| Website visitors     | 4%  → lead | ~75,000 visitors |
| Lead → Trial        | 15%  | 3,000 leads → 450 trials |
| Trial → Paid (Pro)  | 22%  | 450 → 99 Pro subs |
| **Target**          |      | **120 Pro subs** |

### 90-Day Revenue Ramp

| Month | Enterprise | Pro | MRR (INR) |
|-------|-----------|-----|-----------|
| M1    | 5         | 20  | ₹1,24,975 |
| M2    | 20        | 60  | ₹4,49,820 |
| M3    | 47        | 120 | ₹10,04,833 |

### Target ICP for Cold Outreach

**Enterprise targets:**
- CISOs, VPs of Security, SOC Leads
- Industries: Banking/BFSI, Telco, Healthcare, Government, IT services
- Company size: 200–5,000 employees
- Tools they use: Splunk, QRadar, Sentinel, CrowdStrike, Palo Alto

**Apollo.io search filters:**
- Title: CISO OR "VP Security" OR "Head of Security" OR "SOC Manager"
- Industry: Financial Services, Telecommunications, Healthcare, Defense
- Location: India, US, UK, Singapore, UAE

**Outreach tools:**
- Apollo.io — lead sourcing ($49/mo)
- Instantly.ai — cold email at scale ($37/mo)
- SendGrid — transactional + nurture (included)
- Slack — deal alerts (free)

### Revenue Trigger Wiring

| User Action            | System Response               | Automation Fired       |
|-----------------------|------------------------------|------------------------|
| Hit API limit         | 402 + upgrade trigger JSON    | `usage_limit_hit` email |
| Access IOC (blocked)  | Upgrade modal opens           | `ioc_upgrade_prompt` email |
| STIX request (blocked)| Enterprise upgrade CTA        | Demo request pushed    |
| 80% usage used        | Usage banner shown            | `usage_approaching_limit` |
| Trial day 3           | Cron fires nudge email        | `trial_nudge_d3`       |
| Trial day 6           | Urgency email sent            | `trial_expiry_d1`      |
| Trial expired         | Key downgrades, email sent    | `trial_expired`        |
| Deal closed           | Contract triggered            | Enterprise onboard seq |
| Pro user, high usage  | Enterprise upsell email       | `pro_enterprise_upsell`|

## API Endpoints Live

### Public
- `POST /api/leads/capture` — email capture gate
- `POST /api/leads/trial` — 7-day Pro trial issuance
- `POST /api/demo/request` — enterprise demo request
- `GET  /api/demo/live?token=<id>` — live demo endpoint

### Admin (X-Admin-Secret required)
- `GET  /api/crm/leads` — full lead list with scores
- `GET  /api/deals` — deal pipeline with weighted ARR
- `POST /api/deals` — create deal manually
- `PUT  /api/deals/:id` — move deal stage
- `POST /api/outreach/sequence` — start email sequence
- `GET  /api/revenue/dashboard` — full revenue view
- `GET  /api/revenue/mrr` — MRR + pipeline
- `GET  /api/revenue/scale-model` — live scale math
- `POST /api/enterprise/onboard` — start enterprise onboarding
- `POST /api/enterprise/contract` — trigger contract send
