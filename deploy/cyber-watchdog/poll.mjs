/**
 * CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG
 * Customer-environment poller.
 *
 * Pulls the entitled hosted brief. Does not scan the internet.
 * Enterprise SOC or MSSP key required for /api/watchdog/deploy;
 * this poller itself only needs a key that can read /api/watchdog/brief.
 *
 *   SENTINEL_APEX_API_KEY=... node poll.mjs
 *   SENTINEL_APEX_API_KEY=... SENTINEL_APEX_OUT=./brief.json node poll.mjs
 */
import { writeFile } from 'node:fs/promises';

const base = (process.env.SENTINEL_APEX_BASE || 'https://intel.cyberdudebivash.com').replace(/\/$/, '');
const key = process.env.SENTINEL_APEX_API_KEY || '';
const out = process.env.SENTINEL_APEX_OUT || '';
const lens = process.env.SENTINEL_APEX_LENS || 'all';

if (!key) {
  console.error('Set SENTINEL_APEX_API_KEY. Refusing to call the brief without a customer key.');
  process.exit(1);
}

const url = new URL('/api/watchdog/brief', base);
if (lens && lens !== 'all') url.searchParams.set('lens', lens);
url.searchParams.set('limit', process.env.SENTINEL_APEX_LIMIT || '50');

const res = await fetch(url, {
  headers: {
    Accept: 'application/json',
    'X-API-Key': key,
    'User-Agent': 'CYBERDUDEBIVASH-SENTINEL-APEX-CYBER-WATCHDOG/1.0',
  },
});
const text = await res.text();
if (!res.ok) {
  console.error(`Cyber Watchdog brief failed: HTTP ${res.status}`);
  console.error(text.slice(0, 500));
  process.exit(1);
}
if (out) {
  await writeFile(out, text);
  console.log(`Wrote ${out}`);
} else {
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
}
