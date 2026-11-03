# Revenue Engine P0 — Automation queue acknowledgment must reflect queue availability

Date: 2026-11-03. Source-level independent remediation of a customer notification integrity defect.

## Observed defect

`workers/revenue-engine/src/index.js` exposes an authenticated `POST /api/automation/trigger` endpoint, including `usage_80pct`. It calls `queueEmail()`, which uses optional chaining for `env.EMAIL_QUEUE_KV?.put(...)`. If that binding is absent, the put is silently skipped and the automation endpoint can still return HTTP 200 `{status:"triggered",trigger:"usage_80pct"}`. This response is interpreted by an external gateway as an acknowledgment that the customer's warning has been queued. PR #966 separately delays the gateway's 25-hour deduplication marker until it receives this receipt, so the receipt must not be falsely positive.

## Minimal source fix

Immediately after the existing `isAdmin` check, and before parsing/request-side effects, `automationTrigger` now requires `EMAIL_QUEUE_KV` with a callable `put` method. Missing or malformed queue bindings respond HTTP 503 `{error:"email_queue_unavailable"}`, never `triggered`. The original secret authentication and all trigger names/payloads remain unchanged. A failed asynchronous queue put already throws, so the handler cannot produce a success response. This change does not assert that an email provider sent or delivered a queued message; provider acceptance remains a separate lifecycle event.

## Regression evidence required

Node tests cover: authorized success queues exactly once, missing queue binding returns 503, malformed queue binding returns 503, unauthenticated requests still return 401 before queue checks, and a failing KV write never returns success. These are exercised within the existing mandatory Revenue Manual Payment Authority Gate and full commercial regression suite. Other PRs' concurrent customer/browser/intel gateway gates are independent.

## Production and cost controls

No new resources, payment providers, scheduled work, secrets, KV/D1 bindings, Cloudflare deployment or metered service are created by this PR. In correctly configured Workers, this is an additive precondition check with no new KV/network I/O. If a production binding is absent, notifying the caller of actual failure is safer than claiming success. Customer API access in intel-gateway remains best-effort and unaffected.

This fix is necessary but **not sufficient** for `REVENUE_OPERATOR_ACCESS_MODE=required`. The operator Access policy and client machine identities remain unverified; PR #965 documents cutover blockers. The gateway-side best-effort retry is in PR #966. Until independently authorized Cloudflare configuration/deployment attestation and real-world positive/negative testing, production release remains HOLD and VDP issues stay open.
