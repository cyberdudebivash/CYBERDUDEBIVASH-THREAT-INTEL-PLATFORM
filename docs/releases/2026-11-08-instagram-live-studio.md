# SENTINEL APEX Instagram Broadcast Studio — Local Verification Instructions

**Status:** staged in an isolated PR; no production deploy. This page exists on the
repository branch as `instagram-live-studio.html`; it is not publicly served at
the production hostname until an approved and verified release.

## Design decisions

- OBS Browser Source only: **no Display Capture**, Window Capture, desktop audio,
  microphone or webcam. Do not put streaming credentials in source URLs.
- A self-contained, 9:16 HTML presenter with large type, native dark palette,
  no image fonts/CDN/ads, and no CSS scroll transforms or fullscreen side effects.
- Five broadcast scenes: intro, public health, published intelligence,
  **illustrative** analyst workflow, and contact/CTA.
- The live-data view performs only two unauthenticated same-origin public GET
  requests, once per page load: `/api/health` and `/api/preview/`.
  It does **not** repeatedly poll Cloudflare. On timeout, bad status, missing
  freshness or an unusable record it displays an explicit failure/unknown state
  and invents no advisory.
- Readiness gate `scripts/check_instagram_live_studio.py` statically checks
  absence of embedded video, iframe, capture APIs, credentials, and repetitive
  polling. It does **not** prove runtime behavior.
- Default mode changes scenes only on Left/Right arrow keys. Optional
  `?autoplay=1` changes scenes locally with no new network fetches.
  Autoplay is intentionally NOT an investigation workflow simulator.

## Run self-contained local visual rehearsal — *not* live data certification

From a checkout containing the PR files:

```powershell
py scripts\check_instagram_live_studio.py
py scripts\instagram_live_demo_preflight.py --self-test
py -m http.server 8765 --bind 127.0.0.1
```

Use a NEW temporary OBS Browser Source with URL
`http://127.0.0.1:8765/instagram-live-studio.html?autoplay=1`,
Width `1080`, Height `1920`. OBS canvas and output also `1080x1920`,
30 FPS. Do not add screen capture.

**Local data caveat:** the origin is localhost so `/api/health` and
`/api/preview/` will show unavailable/unknown, as designed. This test checks
presentation, readability, scene transitions and workstation stability only,
not live intel quality.

After deployment approval, use a verified public URL on the official intel
hostname. Validate fresh real health and preview data and all scene behavior
before broadcasting; never use the GitHub raw file URL as OBS source.

## Operator release checklist

1. Perform 30-minute uninterrupted recording without the old OBS Lua tour
   or Color Correction. Confirm machine never hangs.
2. Check output at phone size; capture 9:16 and 30 FPS with original colors.
3. Confirm no login forms, stale feed claims, fabricated detections, customer
   identifiers or unauthorized activity.
4. Validate current public API fields and render at least one real, sourced
   intelligence record; if not verified, leave status UNVERIFIED and skip it.
5. Show CTA and correct trading/seller identity only after legal authority
   issue is resolved; a public contact email is not a tax representation.
6. Rotate old exposed Instagram stream key; conduct private live preview.
7. Public Go Live requires the operator's final approval, not a script action.
8. End Instagram Live first, then OBS stream; record real leads and paid
   conversions after the event, not simulated outcomes.

## Required browser and security tests before release

- Live desktop Chrome and OBS Browser Source: layout rendering,
  contrast, memory/CPU, error messages, scene cycling.
- Validate CSP/security headers actually allow the page's inline script on
  the approved hostname; if disallowed, move JS to local bundled file with
  an approved nonce or hash — do not weaken origin-wide CSP.
- Confirm public endpoints do not require private authentication or redirect.
- Check the public preview's real JSON shape; update the fail-closed renderer
  only based on evidence.
- Compare live preview to captured video to eliminate previously observed
  dimming/freeze.
- Verify service robots or access controls permit the presentation endpoint.
- Record the production commit SHA and test gates; rollback only via the
  authorized Windows/manual deployment process.

## Fail-safe behavior

A page displaying **Unverified** or **Preview unavailable** is not a product
outage proof. It explicitly shows that the broadcast page cannot certify the
customer-facing data. Remove that segment from public broadcast until resolved.

This studio is a **presentation view**, not an authorization bypass, scanner,
SOC case-management proof, checkout test, or substitute for actual live product
workflows on AI Hub, SOC, Academy and Labs.
