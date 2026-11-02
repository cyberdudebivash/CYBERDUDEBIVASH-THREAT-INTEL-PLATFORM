# SENTINEL APEX — Instagram Enterprise Demo Release Gate
**Event target:** Sunday 2026-11-08, evening Asia/Kolkata; **duration:** 30 minutes  
**State:** NO-GO until gates below are independently evidenced  
**Branch scope:** Source-only rehearsal tooling and operations; no production deployment, payments, posts, or live broadcast.

## Executive objective

Show a real customer's path from fresh, sourced intelligence to analyst action and
then to a functioning trial, quote or checkout. Only claim what the currently running
service demonstrably provides. Publicly identify any **synthetic** scenario or replay as
synthetic; never present sample, stale, inferred or mocked data as a real incident.

Avoid overclaiming SOC 2 compliance, customer relationships, live MDR coverage,
guaranteed detection, SIEM deployments, or certifications without supporting evidence.

## P0 release gates — ALL required before public event

| Gate | Evidence | Failure action |
|---|---|---|
| Public routes | Bounded read-only response report, source code and timestamp | Remove route from show; fix and retest before promotion |
| Fresh CTI | `/api/health`: `intelligence.age_seconds <= 21600` or authoritative generated_at; advisory provenance present | Don't describe stale data as current; NO-GO for live-feed segment |
| Live function | Analyst can open a real record, pivot and show evidence without credentials in OBS | Skip capability; do not click unauthorized controls |
| SOC | Actual customer-safe watchlist/alert workflow and delivery receipts where claimed | Present only verified public read-only view; no managed-alert promise |
| AI Hub | Real scanner request, result and report access, including negative/failed path | No live scanner demo if response or fulfillment not evidenced |
| Labs / Academy | Public safe evaluation, sample results and observable purchase/enrollment path | Do not suggest a feature is paid/delivered until validated |
| Payments | Razorpay test purchase with verified entitlement, invoice/tax and refund terms in authorized test environment; no real customer charge on stream | NO-GO for payment demonstration; use sales contact only |
| Legal identity | Compare authoritative GST certificate, PAN holder, actual MCA filings and merchant KYC against current seller copy | NO-GO for procurement/legal claims while mismatch unresolved |
| OBS source privacy | Active scene contains only approved browser source + branded scene, no screen/window capture, webcam, audio input or notification exposure | STOP, never go live |
| Video quality | 9:16 1080x1920 or Instagram accepted format; >=30 FPS, phone-readable text, native palette, stable transition, no dim overlay | Reframe or produce pre-recorded truthful preview |
| Stability | Full 30-minute local recording, no GPU hang, freezing, black frames, missing pages | NO-GO public |
| Instagram security | Newly rotated single-use stream key, private preview test, human approval of public audience | NO-GO public |
| Conversion | A working and reachable CTA: pricing/trial/demo booking/contact@cyberdudebivash.in; business contact verified | Hold marketing launch until one reliable path exists |

## One-shot read-only preflight

From the Threat Intelligence repository root on Windows PowerShell:

```powershell
py scripts\instagram_live_demo_preflight.py --self-test
py scripts\instagram_live_demo_preflight.py --output "$env:USERPROFILE\Desktop\sentinel_apex_demo_preflight.json"
```

At most **11 GET requests per explicit invocation**; no polling, write calls or
premium keys. Avoid repetitive runs against Cloudflare Workers during the same
session. Returns exit code 2 on a confirmed failure, 1 on an unverified check and
0 only when public HTTP checks pass. **Even exit 0 is NOT broadcast approval**:
it does not exercise JavaScript, authentication, checkout, alert delivery, mobile
rendering or streaming. Rate limits and anti-bot denials are classified as
UNVERIFIED, not as proven outages.

## Planned 30-minute show — editorial clock, not feature certification

| Time (minutes) | Segment | Candidate verified demonstration |
|---|---|---|
| 00:00–02:00 | Opening | SENTINEL APEX identity, scope, honest no-customer-endorsement language |
| 02:00–08:00 | Threat Intel | Feed freshness, live advisory, severity, provenance, MITRE context |
| 08:00–12:00 | Investigation | Real item dossier or explicitly labeled public **synthetic** replay |
| 12:00–17:00 | SOC | Verified alerts, watchlist and evidence only when safe/public |
| 17:00–22:00 | AI Security Hub | Functional scan and report generation where certified |
| 22:00–25:00 | Labs / Academy | Actual evaluation and verified learner onboarding |
| 25:00–28:00 | Commercial | Pricing, working trial/consultation/enterprise purchase journey |
| 28:00–30:00 | Closing | Contact URL, brand slate for 15–20 seconds; end Instagram, then stop OBS |

Do not fit desktop-width text into a tiny portrait iframe. Use a read-only scene
switch or focused viewport for each feature, while preserving **browser-only**
capture; never capture an entire monitor. Click and scroll slowly. The previous
OBS Lua CSS tour is **not approved**: earlier testing showed dimming, unintended
sign-in views, and workstation instability. Re-enable only after source-level
investigation and a successful uninterrupted rehearsal.

## Operations and rollback

- The event operator alone approves Public **Go Live** after private preview.
- Keep the laptop plugged in and ventilated; close simultaneous FFmpeg encoding.
- Confirm CPU, GPU, memory, dropped frames, and OBS reconnect behavior before show.
- If the feed becomes unreadable or freezes: switch to locally vetted branded
  slate, end Instagram Live, then stop OBS. Do not expose the desktop in recovery.
- Never share streaming keys, cookies, internal error logs, unpublished customer
  data or auth credentials in Instagram or support screenshots.
- Post-event: confirm Instagram End Live, preserve sanitized local recording,
  collect CTA clicks and leads without claiming revenue not yet collected.
- Cloudflare: no new metered services, cron schedules, elevated polling or
  production deployments as part of this preparation branch.

## Evidence gaps currently observed (2026-11-02)

1. AI Hub and SOC customer P0 reports remain release blockers until certified
   on the live service. Repository documentation is not runtime evidence.
2. Labs `src/lib/company.ts` describes Private Limited Company but its
   own comment and `legal-identity.ts` flag PAN/GST structural mismatch and
   unresolved authoritative identity. Do not change legal fields without original
   GST / MCA / Razorpay KYC evidence.
3. Threat Intel homepage last-update and "FRESH" signals must be reconciled
   against `/api/health` before a public freshness claim.
4. SOC outbox documentation explicitly says paid automated notification release
   is NO-GO without operational delivery evidence.
5. Instagram/OBS video did not pass a 30-minute stability or color test; earlier
   Browser Source and Lua automation caused unreadable recordings and a local freeze.

## Change-management boundary

All actual product fixes require isolated patches, local tests, CI or equivalent
manual evidence, customer-safe staging, planned rollback, owner authorization
and production smoke checks. This preflight documentation and script **do not**
constitute any product fix, verified release or Sunday commitment.
