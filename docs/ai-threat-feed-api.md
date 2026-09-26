# SENTINEL APEX™ AI THREAT FEED — API

SKU `cdb-aish-feed` · module `workers/intel-gateway/src/ai-threat-feed.js` (v1.1.0) · a lens under Cyber Watchdog.

## What it is

AI-security intelligence covering MCP servers, LLM gateways and SDKs, coding agents, prompt injection, agent egress and the model supply chain. It has two inputs and nothing else:

1. **Live Sentinel APEX advisories** that match the AI vocabulary (word-bounded) **and** carry their source's own `https` URL. No ruling, timeline or action is generated for these. The timeline holds only the real `published_at` / `processed_at`.
2. **Hub objects** with id `CDB-AISH-FEED-YYYY-MMDD-NN`, each requiring an `https` `source_url`:
   - the seed catalog, `config/ai-threat-feed-catalog.json`, which is mirrored in the module and parity-tested;
   - plus operator ingest, persisted in `SECURITY_HUB_KV` under `ai_feed:hub_catalog:v1`.

It does not crawl the internet. It is never served as live on a feed that is not FRESH.

## Contract (reused from Cyber Watchdog, not re-implemented)

| Concern | Source |
|---|---|
| Tier | `effectiveTier(auth)`: cancelled, refunded or expired keys collapse to FREE |
| Freshness | `watchdogPublication(feed)`: the public freshness contract (6 h) |
| Prices | `planPrice(tier)`: the runtime pricing provider (the same values Razorpay charges). The module has no price literal; a test fails on one. |
| Entitlements | `config/commercial-contract.json` → `features.ai_threat_feed` must equal `AI_FEED_FEATURES` (test) |
| Billing | Included with the existing plans. No separate price, no second invoice. |

## Entitlements

| Plan | Items | Summary, source URL, CVEs, Hub ruling, exploitation | Item detail | Timeline, triggers, actions | TLP:AMBER |
|---|---|---|---|---|---|
| FREE | 5 | locked card (id, title, severity, first seen, source name) | — | — | hidden |
| PRO | 25 | yes | yes | locked (Enterprise upgrade offered) | yes |
| ENTERPRISE | 100 | yes | yes | yes | yes |
| MSSP | 100 | yes | yes | yes | yes |

## Routes

| Route | Access | Behaviour |
|---|---|---|
| `GET /api/ai-feed/offer` | public, CORS wildcard | Plans, entitlements, checkout links, runtime prices |
| `GET /api/ai-feed/health` | public, CORS wildcard | Freshness plus catalog and AI item counts. 200 FRESH, 503 otherwise |
| `GET /api/ai-feed/live` | public (FREE projection); API key or Watchdog session for paid | Tier projection. Not FRESH → 503 `intelligence_degraded`, `items: []`, plus `last_authoritative` (`live: false`, "NOT LIVE") while STALE ≤ 48 h |
| `GET /api/ai-feed/item/{id}` | PRO+ (API key or Watchdog session) | FREE → 403 `tier_required` with checkout. Not FRESH → 503. Unknown → 404 |
| `POST /api/ai-feed/ingest` | operator (`X-Admin-Key`) | `{items: [...], retract: [ids]}`. All-or-nothing: any invalid object → 400 `invalid_items` with per-item reasons, nothing written. No `https` `source_url` → `source_url_required` |

Every response is `Cache-Control: no-store`.

### Sessions and planes

- A Cyber Watchdog session token (`aud: cdb-watchdog`) is accepted on `GET /live` and `GET /item/{id}` only; everywhere else it remains `token_audience_mismatch`.
- `/offer`, `/health` and `/live` are on the first-party web read plane (anonymous dashboard budget).

## Ingest example (operator)

```bash
curl -sS -X POST https://intel.cyberdudebivash.com/api/ai-feed/ingest \
  -H "X-Admin-Key: $ADMIN_SECRET" -H "Content-Type: application/json" \
  -d '{"items":[{"id":"CDB-AISH-FEED-2026-0926-01","title":"...","status":"NEW_PUBLIC","tlp":"CLEAR",
       "severity":"HIGH","source_url":"https://...","source_name":"...","first_seen":"2026-09-26T00:00:00Z",
       "summary":"...","hub_ruling":"...","timeline":[{"at":"2026-09-25","event":"..."}],
       "triggers":["..."],"actions":["..."],"exploitation":"UNKNOWN","cves":[]}]}'
```

Validated fields:
- `id`: `CDB-AISH-FEED-YYYY-MMDD-NN`
- `source_url`: `https`
- `title`: at least 8 characters
- `source_name`
- `status`: `NEW_PUBLIC` | `STILL_OPEN` | `RESOLVED`
- `tlp`: `CLEAR` | `AMBER`
- `severity`: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- `first_seen`: ISO 8601
- `exploitation`: `CONFIRMED` | `NOT_CONFIRMED` | `UNKNOWN`
- `timeline[].at`: ISO 8601

Markup is stripped from every string.

## Dashboards

- **Homepage (`index.html`)**
  - The panel sits directly under Cyber Watchdog. Anonymous visitors see the FREE projection: locked rows (id · severity · title · first seen · source).
  - Clicking a row shows the lock and a same-site checkout link. The CTA carries the runtime price.
  - STALE shows the last authoritative rows labelled NOT LIVE.
- **Cyber Watchdog (`cyber-watchdog.html`, Intelligence view)**
  - Uses the signed-in session.
  - Clicking a row opens the item: summary, source link (`https` only, `noopener`) and Hub ruling. Enterprise and MSSP also get the timeline, triggers and actions; PRO gets an Enterprise upgrade prompt in their place.

## Verification

- `workers/intel-gateway/src/__tests__/ai-threat-feed.test.js`: the module plus the real `index.js` router. Covers:
  - stale → 503; FREE never sees details, timeline or actions; ingest without an `https` `source_url` → 400
  - tier caps, TLP:AMBER, tier collapse, operator auth and the session audience
  - no price literal; contract and seed parity
- `workers/intel-gateway/scripts/watchdog-negative-controls.mjs`: 12 AI feed mutation controls, all must be caught.
- `render-test/verify_ai_threat_feed.js` (in `pages-fast-publish`): both pages, per plan, stale and too old, and raw markup from the API rendered as text.
