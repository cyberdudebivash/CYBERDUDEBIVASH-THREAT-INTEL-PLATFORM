# CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG API

Version 2.0.0. Prices are read from `config/commercial-contract.json`. Freshness is `config/public_freshness_contract.json` via `evaluatePublicIntelligence()`. Watchdog does not watch the entire internet.

## Authentication

`X-API-Key` or the existing bearer session. Tier and subscription state come from the server-side key record. A cancelled, refunded, suspended, or expired key is FREE. The request body cannot choose the customer.

The browser page still keeps a key in `sessionStorage` for this phase. It is not written to `localStorage`, cookies, or the URL. A scoped browser token is not available on this page yet.

## Routes

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/api/watchdog/offer` | public | Canonical plan prices. No feed. |
| GET | `/api/watchdog/health` | public | Freshness only. No customer data. |
| GET | `/api/watchdog/brief` | public read, tier-redacted | 200 only when the feed is FRESH. Otherwise 503 `intelligence_degraded`. |
| GET/POST/PATCH/DELETE | `/api/watchdog/watches` | PRO+ | Saved watch definitions. |
| GET | `/api/watchdog/matches` | PRO+ | Evaluates watches and stores new match events. |
| GET | `/api/watchdog/events` | PRO+ | Durable inbox. `limit` and `offset`. |
| POST | `/api/watchdog/events/ack` | PRO+ | Body `{ "ids": [] }`. |
| GET/POST/DELETE | `/api/watchdog/destinations` | ENTERPRISE or MSSP | HTTPS webhook. PRO receives 403. |
| GET | `/api/watchdog/deploy` | PRO+ | Poller package. Webhooks are null on PRO. |

## Freshness

`freshness_status` is `FRESH`, `STALE`, `EMPTY`, `UNAVAILABLE`, or `INVALID`. A stale feed does not return brief items and does not create match events.

`feed_item_count` is the canonical advisory count: items with a non-empty string id. The same count is `/api/health` `intelligence.advisory_count` and `/api/platform/stats` `total_advisories`. `total_reports` is the report catalog and is not the advisory count.

## Watch definition

`logic` is `AND` or `OR`. Criteria that the feed actually carries: keywords, CVE ids, vendors, products, actors, malware families, sources, min severity, CISA KEV, minimum EPSS, minimum CVSS, ATT&CK technique ids, sectors, countries, IOC types, and lenses. Unknown keys are rejected. Customer text is matched literally. It is never compiled as a regular expression.

## Match events

Stored per customer, capped at 200. Dedupe key is watch id + item id + the item revision token (`processed_at`, else `published`, else title). The same advisory does not create another event until that token changes. Evaluation runs when a paid client calls `GET /api/watchdog/events` or `GET /api/watchdog/matches` (the page, or the poller). There is no background sweep of every customer. Webhook payload contains watch identity, item identity, title, severity, source, match reasons, entitled CVE ids, lenses, feed timestamp, reference, and TLP. It does not invent remediation. There is no Splunk, Sentinel, Elastic, or MISP connector. HTTPS POST is the delivery channel.

Webhook URLs must be `https`, with no userinfo. Loopback, link-local, RFC1918, link-local metadata (`169.254.169.254`), decimal IP forms, and non-global IPv6 (including IPv4-mapped addresses) are rejected. Query strings are not stored.

Error bodies never include the ledger. A request body `customer_id` or `subject` is ignored. Ownership is the authenticated subject.

A `PATCH` may send `{ "enabled": false }` without repeating criteria. Omitted criteria stay as stored.

## Errors

403 `tier_required` or `tenant_mismatch`. 400 invalid watch. 404 missing watch. 503 intelligence degraded or watch store unavailable. 429 is the existing platform rate limit, not a Watchdog-specific limiter.
