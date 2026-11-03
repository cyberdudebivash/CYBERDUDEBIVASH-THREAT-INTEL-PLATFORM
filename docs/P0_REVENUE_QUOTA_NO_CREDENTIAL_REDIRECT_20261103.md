# P0 Revenue quota notification: prohibit credential forwarding on redirect

Date: 2026-11-03. Isolated source/CI change only; production deployment is NOT authorized by this change.

## Evidence and threat model

`workers/intel-gateway/src/index.js` performs a newly constructed Worker `fetch("https://revenue.intel.cyberdudebivash.com/api/automation/trigger", ...)` with sensitive `X-Admin-Secret` and, when separately provisioned, `CF-Access-Client-Id` and `CF-Access-Client-Secret`. Its options previously omitted `redirect`.

Cloudflare's official Workers `Request` runtime documentation explicitly states that `fetch` defaults to redirect `follow`, and on redirects **all headers, including application-specific secrets, are forwarded even to a different hostname or domain**. The warning applies to subrequests newly created by a Worker and is directly relevant to this call. Source: https://developers.cloudflare.com/workers/runtime-apis/request/ .

A 3xx response could therefore disclose the shared Revenue Engine admin secret and newly added Access service token to an unintended redirect destination. This is a potential source-level exploit path, not evidence that any actual production redirect or disclosure occurred. A real attacker would also need control or influence over an upstream redirect target; none is claimed here.

## Minimal remediation

Add **`redirect: "manual"`** to only this single POST's fetch options. Do not follow any 3xx response, including 301/302/307/308, and do not implement a manual secondary fetch to the Location URL. The already merged `dispatchQuotaAlertOnce()` demands an exact HTTP 200 `{status:"triggered",trigger:"usage_80pct"}`. A 3xx now counts as unqueued and leaves only the existing short retry reservation; it never promotes the 25-hour sent marker. The signed Revenue service-token opt-in and legacy secret-only default are unchanged.

Regression tests assert the exact quota call site uses `redirect:"manual"` and never `follow`, and that a synthetic redirect response cannot be counted as a queue acknowledgment. Existing quota warning, JWT, billing, gateway, Cloudflare FinOps and security gates continue independently.

## Release and cost gates

No additional Worker, route, binding, KV/D1/R2 resource, request fan-out, paid service, secret provisioning, payment or customer email. Blocking redirect follow prevents credential-bearing cross-host retries and unnecessary follow-up subrequests. Legitimate first-hop HTTP 200 success remains unchanged.

This does **not** certify any live Cloudflare state. PR #965's complete operator-client inventory, #968's optional service-token path, and #969's synthetic contract test are separate from actual Access policy, real JWT issuer/audience/allowlist, browser operator clients and payment/webhook non-regression. Do not activate `REVENUE_OPERATOR_ACCESS_MODE=required` without explicit owner approval and independent staging validation. Researcher cases remain open.
