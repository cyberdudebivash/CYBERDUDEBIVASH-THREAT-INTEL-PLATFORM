# SENTINEL APEX UI system (command-center surfaces)

Applies to two pages only:

- `cyber-watchdog.html`: the Cyber Watchdog application shell.
- `index.html`: the `#apex-command-surface` block at the top of the homepage.

Files:

| File | Role |
|---|---|
| `css/apex-design-tokens.css` | `--ax-*` tokens and `ax-` components (LED, panel, KPI, table, drawer, shell, chips). Also holds the `acs-` homepage block. |
| `js/apex-status-model.js` | Pure functions: API payload in, display state out. Used by both pages and unit-tested in Node. |
| `workers/intel-gateway/src/__tests__/watchdog-apex-ui.test.js` | Status-model unit tests, page invariants and the two display-data additions. |
| `workers/intel-gateway/scripts/watchdog-negative-controls.mjs` | `ui_*` mutations that prove those tests catch each regression. |

No CDN, no framework and no remote font or icon dependency. Icons are inline SVG. Charts are inline SVG built with DOM calls. CSP is unchanged.

## Relationship to `css/tokens.css`

`css/tokens.css` (`--sapx-*`) is the token set for marketing and content pages (`enterprise-*.html`, `developer-portal.html`). It supports light and dark themes. It is not linked by `index.html` or `cyber-watchdog.html`.

The command-center surfaces need a denser, dark-only SOC palette with status, LED and severity shape tokens that `tokens.css` does not define, so `--ax-*` ships as a separate layer.

This is a second token namespace. It is flagged here as a consolidation item rather than hidden. The follow-up is to alias the overlapping base scales to `--sapx-*`:

- font stacks
- radius
- spacing
- text primary and secondary

That can happen once `tokens.css` is safe to load on the legacy homepage.

## State model: a state is green only when a response proved it

The LED carries state through shape as well as colour, and it always sits next to a text label. Colour is never the only signal.

| `data-state` | Shape | Colour | Meaning |
|---|---|---|---|
| `ok`, `fresh`, `active`, `delivered`, `verified` | filled circle, glow; pulses only when `prefers-reduced-motion: no-preference` | green | a response proved it |
| `degraded`, `pending`, `warning` | triangle | amber | reachable but not fully healthy (for example a stale feed) |
| `offline`, `failed`, `critical` | square | red | request failed or store unavailable |
| `unknown`, `disabled`, `info` | hollow ring | grey (`info` violet) | not yet loaded, unreadable, or intentionally off |

Every status rail renders `unknown` in the static HTML, and the page replaces it only after a fetch returns.

| Function | Input | Rules |
|---|---|---|
| `intelligenceState(payload, failed)` | `/api/watchdog/health` or `/brief` | failed → `offline`; no `freshness_status` → `unknown`; `FRESH` → `fresh`; `STALE` → `degraded` "Intelligence stale"; anything else → `degraded` |
| `watchdogState(health, failed)` | `/api/watchdog/health` | failed → `offline`; no `watch_store` → `unknown`; store not `ok` → `offline`; evaluation not `configured` → `degraded`; else `active` |
| `apiState(json, failed)` | any parsed JSON response | only `true` → `ok` |
| `releaseLabel(health)` | `platform_version` | `vNNN.N` only when it matches `^\d{3}\.\d+$`, otherwise `null` (rendered as NOT AVAILABLE, never guessed) |
| `destinationState(state)` | webhook destination | `active` → `verified`, `pending`, `failed`, `disabled`, else `unknown` |
| `deliveryState(status)` | event delivery | `delivered`, `pending`, `failed`/`partial` → `failed`, `no_destinations` → `disabled`, else `unknown` |
| `triageState(status)` | triage status | `RESOLVED` and `IGNORED` are terminal and need an inline confirmation in the drawer |
| `trendSeries(analytics)` | `/api/watchdog/analytics` | `null` unless `history === "stored-match-events"` and `daily_7d` exists. `null` renders INSUFFICIENT HISTORY, never a placeholder chart |
| `priorityDistribution(analytics)` | `by_priority` | `null` when the total is 0 |

## Data rules

- Every intelligence field is untrusted: title, source, watch name, tenant name, notes and URLs.
- Both pages build DOM with `document.createElement` and `textContent`.
  - `cyber-watchdog.html` renders only through `h()`, which appends strings as text nodes and ignores `on*` attributes.
  - Links pass `safeHref()`, which allows only a same-site path or `https:`.
- Numbers on the homepage (release, freshness, advisory count, critical and high, last update) are empty in the HTML. They come from `/api/watchdog/health` and `/api/watchdog/brief?limit=5`.
  - The brief promise is shared with the existing Cyber Watchdog panel, so the page makes one brief request.
- Prices are read from `/api/watchdog/offer` at runtime. The pages contain no literal price.
- Compliance wording is exactly "ISO 27001 / SOC 2: aligned, not certified." No seal, badge or "certified" claim.
- Relevance wording says "matches your exposure profile". It never says a customer is vulnerable, compromised or exposed.

## Cyber Watchdog shell

Hash-routed views. The nav lists only sections that exist:

- Overview
- Matches
- Watches
- Intelligence
- Integrations
- Tenants (MSSP only)
- Plan

The command bar shows:

- tenant context: a `TENANT: X` badge, the document title prefix, and a switcher for unbound MSSP sessions
- the plan
- the status rail
- sign-in and sign-out

Sessions:

- The key is exchanged for a short-lived session at `/api/watchdog/session`.
- The input is cleared before the request.
- Only the session token is kept, in `sessionStorage`. `localStorage` is not used.

MSSP tenants:

- The session response lists `managed_tenants` for MSSP credentials. This is display data only.
- Every tenant request is still re-authorized server-side per request.

The evidence drawer is a native `<dialog>` with these sections:

- Triage
- Threat summary
- Why prioritized
- Why matched
- Customer relevance
- Vulnerability evidence
- Provenance and current context
- Delivery
- Triage history

Focus returns to the originating row when the drawer closes.

## Homepage command surface

The surface contains:

- a hero with the three primary actions: Open Cyber Watchdog, View live intelligence, API documentation
- a proof strip
- a live operations rail
- four panels: Live threat priority, Cyber Watchdog, API and integrations, Trust and security

Navigation changes:

- Cyber Watchdog moves into the primary chips.
- The other modules sit behind an "All modules" disclosure. No route is removed.

The legacy floating AI pulse and the first status-strip cell are hidden, not deleted.

The sticky upgrade bar:

- It is never shown to PRO, ENTERPRISE or MSSP.
- It reads the tier from `cdbAuth.getUser()`, and only while `cdbAuth.getToken()` is live.
- It reserves its own height (`body.cdb-scta-on`) so it never covers content.

## Security fixes made alongside the redesign

A DOM XSS probe was run with the fixture feed poisoned with `<img onerror>`, `<svg onload>` and `javascript:` URLs in the title, source and source URL fields. It found two pre-existing injection points on `origin/main`, and both are fixed:

1. `renderTopThreats()` in `index.html` (the "TOP 10 ACTIVE THREATS" widget) concatenated the feed title, actor, tactics and report URL into HTML.
   - Text now goes through `_tt()` (HTML escape).
   - Links go through `_tu()`, which allows only a same-site path or `http(s)`.
2. `renderTrustFooter()` in `js/card_renderer.js` escaped `source_url`, but a `javascript:` scheme still ran on click. The link now uses `sourceHref`, which allows `http(s)` only.

After the fix, the same probe finds on both pages:

- 0 script executions
- 0 injected elements
- 0 `javascript:` links

## Verification

- `node --test workers/intel-gateway/src/__tests__/watchdog-apex-ui.test.js` covers:
  - the status model
  - landmarks, unique ids, labelled controls and resolvable ARIA references
  - no HTML-string rendering on the Watchdog page
  - no literal prices
  - no certification claims
  - no static homepage metrics
  - the paid-tier sticky bar
  - escaping in the legacy top-threats widget
  - focus ring, overflow containment, LED shapes and reduced motion
  - the session tenant list and daily counts
- `node workers/intel-gateway/scripts/watchdog-negative-controls.mjs` runs the `ui_*` controls. Each applies one defect and requires the tests to fail:
  - fresh LED removed
  - unknown shown as healthy
  - literal price
  - paid upgrade bar
  - escaping removed
  - overflow containment removed
  - focus ring removed
  - "SOC 2 Certified" added
  - fake metric
  - homepage title unescaped
  - card source-link scheme unchecked
- The Pages render suites in `render-test/` still run against `index.html`.
