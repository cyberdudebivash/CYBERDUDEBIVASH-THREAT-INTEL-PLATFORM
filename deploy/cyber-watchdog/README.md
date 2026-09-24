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

systemd timer, same command, no Kubernetes:

```ini
# /etc/systemd/system/apex-watchdog.service
[Service]
Environment=SENTINEL_APEX_API_KEY=your-key
Environment=SENTINEL_APEX_OUT=/var/lib/watchdog/brief.json
ExecStart=/usr/bin/node /opt/watchdog/poll.mjs
```

```ini
# /etc/systemd/system/apex-watchdog.timer
[Timer]
OnUnitActiveSec=15min
Persistent=true
```

Docker, local only. This image is not a new hosted product:

```dockerfile
FROM node:22-alpine
WORKDIR /opt/watchdog
COPY poll.mjs poll-lib.mjs ./
ENV SENTINEL_APEX_OUT=/data/brief.json
CMD ["node", "poll.mjs"]
```

Windows Task Scheduler: program `node`, arguments `C:\watchdog\poll.mjs`, and `SENTINEL_APEX_API_KEY` plus `SENTINEL_APEX_OUT` set on the task environment. Do not put the key in the command line.

Set `SENTINEL_APEX_EVENTS=0` to skip the durable match-event call. The default also calls `GET /api/watchdog/events` after a fresh brief so repeated polls do not require the browser.
