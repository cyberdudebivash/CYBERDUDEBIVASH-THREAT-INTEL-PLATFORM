# P0 — Customer quota-alert delivery and operator-JWT cutover resilience

Date: 2026-11-03. Source scope: intel-gateway customer 80% daily quota notification, not general billing or webhook flows.

## Confirmed source-level defect

Before this change, `maybeDispatchQuotaAlert` wrote `alert_sent:80pct:<identifier>:<UTC date>` to `RATE_LIMIT_KV` with a 90,000-second TTL **before** checking whether `REVENUE_ADMIN_SECRET` was configured, sending the POST to Revenue Engine, or examining its response. A 403 from `REVENUE_OPERATOR_ACCESS_MODE=required`, a network error, or an upstream 5xx left the customer treated as notified for 25 hours even though Revenue Engine had **not** acknowledged queuing a message.

This is especially relevant to the pending operator-JWT rollout: the current intel-gateway sender supplies `X-Admin-Secret` but not a valid Cloudflare Access assertion. The operator cutover in PR #965 remains blocked independently. This PR does not solve that authentication migration.

## Narrow remediation

- Check configured admin secret before any KV work, then perform the original **cheap daily-marker lookup** before fetching the customer's email. This preserves the existing already-alerted hot-path cost (one KV marker read) rather than looking up the customer on every high-quota API request. Missing prerequisites make no dedupe marker and do not disrupt legitimate API requests.
- Keep the same existing `RATE_LIMIT_KV` key and existing 90,000-second success marker to avoid invalidating historical records. The previous `"1"` value is still honored.
- Reserve the key with `"pending"` and a **3,600-second** TTL before outbound dispatch. This tempers concurrent dispatch and limits retry traffic under persistent 403/5xx incidents.
- Promote `"pending"` to `"sent"` with a 90,000-second TTL **only** after an HTTP 200 response containing `{ "status": "triggered", "trigger": "usage_80pct" }`. That response means the Revenue Engine reports the email **queued**, not that the email provider has delivered it to the recipient.
- Denied or malformed responses, 5xx, network errors and unsuccessful KV post-ack writes never produce a full-day success marker. The short pending marker expires and a subsequent customer API request **may** retry.
- Run in-memory tests for positive acknowledgment, prior-sent compatibility, 403 recovery, 5xx/invalid JSON, KV outages, overlapping calls, and exact production call-site/credential ordering. Require those tests early in the existing Intel Gateway Regression Gate, then continue its complete suite and commercial negative controls.

## Cost and reliability boundaries

No new Cloudflare resource, service, cron, DO, plan, or binding is introduced. The existing rate-limit KV is reused. Relative to the old one-write success path, a successful alert now takes two KV writes (short reservation plus sent marker), and a failed send leaves one short-lived reservation. Under a single consistent KV view, repeated failures are throttled to roughly **one attempt per hour per customer key**. Workers KV is eventually consistent globally, so this is a useful cost guard but **not a hard global quota guarantee**; sustained or geographically concurrent failures can exceed that rate.

A 403 remains an **authentication rollout blocker**, not a transient-error cure. The 3,600-second retry interval trades latency for bounded cost. A failed alert can recover only if the customer subsequently makes another eligible request after the reservation expires. No background queue-repair or exactly-once guarantee is claimed. Concurrent cross-region attempts and lost post-ack KV writes can still cause duplicate emails; strong exactly-once semantics would require separately designed durable server-side idempotency and explicit cost approval.

## Release/VDP safety

This is source/CI-only. Do not deploy until exact-head gates pass, production operator authentication is assessed, and an owner approves a separate release. Do not activate `REVENUE_OPERATOR_ACCESS_MODE=required`, rotate the shared admin key, create a service token or incur new Cloudflare charges from this PR. No real customer email, payment, KV write, or production deployment is performed by the tests. Researcher issue status remains OPEN pending independent live positive/negative validation.
