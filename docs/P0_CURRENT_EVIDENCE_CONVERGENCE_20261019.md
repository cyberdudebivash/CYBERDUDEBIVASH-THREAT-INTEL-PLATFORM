# P0 — Current CTI evidence and stale operational-panel convergence (19 October 2026)

## Observed customer impact
Screenshots of intel.cyberdudebivash.com show:
- APT Actor Radar: no current APT-classified reports and no measured sector/technique data.
- GENESIS G11: 0 geolocated actor→target flows.
- Bug Hunter: historical 2026-10-15 scan, correctly marked "Re-scan required."
- TIP + SOAR: historical incident, response and hunt files older than seven days, correctly marked "Not current."

Read-only production API queries during diagnosis:
- GET /api/feed.json: 173 CTI advisories, publication timestamp 2026-10-19T05:24:04Z.
- GET /api/v1/intel/apt: 0 APT-classified reporting among 173 evaluated advisories.
- GET /api/health: reachable and public intelligence status fresh at time observed.
- GET /api/v1/intel/campaigns: active_campaign_count 0.
These are snapshots, not guarantees of future collection or customer-tenant telemetry.

## Confirmed code paths
- js/sentinel-live-feeds.js::loadAPT renders the actual evidence-only APT API; it does not invent attribution.
- agent/v43_genesis/genesis_engine.py::GlobalAttackMap requires actor_country plus target_country/victim_country on the **same advisory**. Zero flows is a valid result.
- js/homepage-dashboard-engine.js::ENGINE_URLS reads Bug Hunter, incident, response and hunt files from raw GitHub main, which does not guarantee operational freshness. renderBugHunterEngine suppresses a scan older than 24 hours; TIP renderers reject their own generated_at older than 7 days.
- .github/workflows/bughunter-resilient.yml includes scheduled recon, but the displayed scan did not demonstrate a more recent completed run. Check workflow execution and authorized scan scope separately.

## Change in this PR — customer trust and immediate CTI utility
- Include js/dashboard-evidence-bridge.js on the homepage.
- One same-origin public GET /api/feed.json at load and at most one per 15 minutes while the page is visible; no new Worker endpoint, R2 writes or third-party network requests.
- Reject missing/unbounded/mismatched schema and publications older than 6 hours. Fail closed with an unavailable state (never retain old evidence as live).
- Render source-linked CTI rows in four adjacent panels:
  * APT: actual APT-related reporting; when none, clearly labeled general CTI context, **not APT attribution**.
  * G11: count explicit country-paired advisory metadata independently of authoritative GENESIS flow measurements; do not turn publisher country or inferred origin into an attack flow.
  * Bug Hunter: current vulnerability/exploitation CTI **not** scanner output or confirmed vulnerabilities in the owner's assets.
  * TIP/SOAR: high-risk CTI for analyst triage **not** confirmed incidents, completed hunts or automated containment actions.
- All report titles and metadata are inserted through textContent. Only credential-free HTTPS source URLs become links with rel="noopener noreferrer". Only TLP:CLEAR records are eligible.
- No modification to historical operational files, existing measured counters, entitlements, customer data, scan scope or audit records.

## Explicitly NOT solved by this PR — remaining P0 operational blockers
1. Re-enable verified Bug Hunter scan execution (authorized target/scope and scan policy first). Confirm successful completion, objective findings evidence and a recent timestamp; do not retimestamp the 15 October artifact.
2. Restore incident/hunt/response producers with clear event-vs-advisory provenance and durable R2 publication. Separate incident **observations**, response **proposals** and actions that have independent execution receipts.
3. Publish current, classification-checked customer derivatives using one canonical publisher, within Cloudflare per-run and account-wide paid-plan limits. The old raw-GitHub-main files are not a trustworthy real-time source.
4. Extend APT and actor-country tagging only with **verifiable** source-supported identity and origin/target metadata, preserving restrictions and paid entitlements.
5. Restore the separate Week 42 Weekly Brief API 503 incident and verify live E2E API and browser data before release.
6. Validate real browser rendering under active and blocked API conditions; obtain business/customer acceptance.

## Local and release gates
- node --test tests/dashboard-current-cti-evidence.test.cjs
- node --test tests/tipsoar-rendering-security.test.cjs tests/recon-evidence-presentation.test.cjs
- No fake attribution, inferred attack flow, fake recon scan, created incident or response execution.
- Check publication age and source hyperlinks in the live rendered page.
- Confirm no customer PII/tenant payloads are exposed to anonymous viewers.
- Confirm no added recurring GitHub workflows or Cloudflare storage mutations.

**Release status:** code-review candidate only. No production deployment or sign-off is implied by a merged PR.
