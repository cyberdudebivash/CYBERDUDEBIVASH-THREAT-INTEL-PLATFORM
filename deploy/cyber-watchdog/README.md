# CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG

Customer-environment poller for the hosted Sentinel APEX brief.

This process does **not** crawl the internet and does **not** watch private networks. It calls `GET /api/watchdog/brief` with the customer's API key and writes the JSON locally. Schedule it every 15 minutes.

## Who can buy it

| Plan | List | What you get |
|---|---|---|
| Pro Defense | $49/mo \| INR 4,067/mo book | Hosted brief + 25 watches. Checkout: `/upgrade.html?plan=pro&feature=cyber-watchdog` |
| Enterprise SOC | $499/mo \| INR 41,417/mo book | Hosted brief + 200 watches + this poller. Checkout: `/upgrade.html?plan=enterprise&feature=cyber-watchdog` |

Book rate: 83 INR per USD, locked 2026-09-20. The Razorpay charge is the existing plan price. There is no second invoice.

Seller: CYBERDUDEBIVASH Pvt. Ltd. · GSTIN 21ARKPN8270G1ZP · PAN ARKPN8270G.

ISO 27001 / SOC 2: aligned, not certified.

## Run

```bash
export SENTINEL_APEX_API_KEY="your-key"
export SENTINEL_APEX_OUT="./watchdog-brief.json"
node poll.mjs
```

Requires Node.js 18+.
