# DEPRECATED: AI Threat Feed index.js hook (wiring is done)

**Status:** superseded. `routeAiFeed` is dispatched in `workers/intel-gateway/src/index.js`, directly after the Cyber Watchdog block. See `docs/ai-threat-feed-api.md` for the live contract. This note is kept for history and will be removed with the next gateway major release.

The sketch that used to be here did not match the module and must not be applied. It passed `freshness_status` / `hubCatalog` / `pricingSnapshot` and read the catalog from the feed object. The module actually takes:

- `feed`: the R2 `api/v1/intel/latest.json` object; freshness comes from `watchdogPublication`
- `readCatalog()` / `writeCatalog(obj)`: `SECURITY_HUB_KV` key `ai_feed:hub_catalog:v1`
- `isOperator`: `X-Admin-Key` on `/api/ai-feed/ingest` only

Registration is also done:

- `first-party-plane.js`: `/api/ai-feed/offer`, `/health`, `/live`
- `cors-policy.js` `PUBLIC_EXACT_PATHS` plus `config/cors_public_wildcard_allowlist.json`: `/api/ai-feed/offer`, `/health` (`/live` stays BROWSER)
- The Watchdog session audience accepts `GET /api/ai-feed/live` and `/item/{id}`
