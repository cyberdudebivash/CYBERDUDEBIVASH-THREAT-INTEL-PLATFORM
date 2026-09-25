# SENTINEL APEX AI THREAT FEED API

SKU `cdb-aish-feed`. Version 1.0.0. Sits under Cyber Watchdog.
Does not crawl the internet. 503 when freshness is not FRESH.
Prices from config/commercial-contract.json. No SOC 2 claim.

GET /api/ai-feed/offer public
GET /api/ai-feed/health public
GET /api/ai-feed/live public redacted; 503 if not FRESH
GET /api/ai-feed/item/:id PRO+
POST /api/ai-feed/ingest operator

FREE 5 locked cards. PRO 25 + ruling. ENTERPRISE/MSSP 100 + timeline/actions.
Hub items require https source_url and CDB-AISH-FEED-YYYY-MMDD-NN id.
See deploy/ai-threat-feed/INDEX_HOOK.md to wire index.js.
