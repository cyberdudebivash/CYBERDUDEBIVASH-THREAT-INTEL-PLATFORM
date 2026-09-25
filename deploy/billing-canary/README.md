# Billing canary (S28)

`canary.mjs` probes a deployment's commercial boundaries and prints JSON
evidence. Credentials come from the environment only; no secret, key or full
id is ever printed.

| Mode | Needs | Mutates | Checks |
|---|---|---|---|
| `public` | nothing | nothing | 15 boundaries: billing account / readiness / cancel / refund approval / holds refuse without credentials; Razorpay and Gumroad webhooks refuse unsigned pings **and are configured** (a 500 "secret not configured" fails); checkout refuses an unknown tier; both manual-payment routes answer 410; `billing.html` is served; `admin.html` is complete |
| `admin` | `CDB_BILLING_CANARY_ADMIN_SECRET` | nothing | + admin health carries the commercial summary; readiness verdict reported |
| `live` | same | nothing | as `admin`, and a `BLOCKED` verdict **fails** (production go-live gate) |
| `test-checkout` | same, on a Razorpay **test-mode** deployment | one unpaid test subscription | + checkout passes the Plan price check against the real test Plan, retry is reused, status needs payment proof. Refused (exit 13) unless readiness proves a `rzp_test_` key |

```
node deploy/billing-canary/canary.mjs public
CDB_BILLING_CANARY_ADMIN_SECRET=... node deploy/billing-canary/canary.mjs live
```

Optional: `CDB_BILLING_CANARY_BASE` (default `https://intel.cyberdudebivash.com`),
`CDB_BILLING_CANARY_REVENUE_BASE` (default `https://revenue.intel.cyberdudebivash.com`),
`CDB_BILLING_CANARY_EMAIL` (test-checkout buyer).

Exit codes: 0 PASS, 1 FAIL, 10 OPERATOR_CREDENTIAL_REQUIRED, 13 LIVE_MODE_REFUSED.

`canary.test.mjs` certifies the steps against both Workers' production entry
points in-process (Razorpay test mode faked at the network edge), including
that the canary fails on a wrong Plan price, a missing webhook secret, a
missing Billing Center and a truncated admin page. It runs in the gateway
regression gate and under `billing-negative-controls.mjs`.
