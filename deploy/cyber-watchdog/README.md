# CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG

Customer-environment poller for the hosted Sentinel APEX brief.

This process does **not** crawl the internet. It calls `GET /api/watchdog/brief` with the customer's API key and, when that brief is `FRESH`, writes the JSON locally. A stale, empty, unauthorized, or malformed response never replaces the last good file.

The poller is a Pro+ client. It is not an Enterprise entitlement boundary. HTTPS webhook delivery is the Enterprise and MSSP capability (`POST /api/watchdog/destinations`).

## Who can buy it

Prices come from `config/commercial-contract.json`. There is no second Watchdog invoice.

| Plan | Canonical list | What you get |
|---|---|---|
| Pro Defense | $49/mo, INR 4,100/mo | Hosted brief, 25 watches, this poller |
| Enterprise SOC | $499/mo, INR 41,600/mo | Pro features plus HTTPS webhook delivery |
| MSSP | $999/mo, INR 83,300/mo | Same delivery right on the canonical MSSP plan |

Checkout: Razorpay is primary and Gumroad is the alternative, both on `/upgrade.html`.

Seller fields are the canonical contract values. GSTIN 21ARKPN8270G1ZP.

ISO 27001 / SOC 2: aligned, not certified.

## Run

```bash
export SENTINEL_APEX_API_KEY="your-key"
export SENTINEL_APEX_OUT="./watchdog-brief.json"
node poll.mjs
```

Requires Node.js 18+. The key is read only from the environment. It is not written to the output file or the log.

Exit codes: 0 success, 2 missing key, 3 unauthorized, 4 previous file kept because the feed was not FRESH, 5 malformed, 6 network or server failure after retries.

## Schedule

Linux cron, every 15 minutes:

```cron
*/15 * * * * SENTINEL_APEX_API_KEY=your-key SENTINEL_APEX_OUT=/var/lib/watchdog/brief.json /usr/bin/node /opt/watchdog/poll.mjs
```

systemd is the same command on a 15-minute timer. Windows Task Scheduler can run `node poll.mjs` with `SENTINEL_APEX_API_KEY` set as a task environment variable. Kubernetes is not required.

Set `SENTINEL_APEX_EVENTS=0` to skip the durable match-event call. The default also calls `GET /api/watchdog/events` after a fresh brief so repeated polls do not require the browser.
