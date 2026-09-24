/**
 * CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG
 * Customer-environment poller. Node.js 18+.
 *
 * Pulls the hosted brief. Does not scan the internet.
 * Refuses to replace a local file with a stale, empty, unauthorized,
 * or malformed response.
 *
 *   SENTINEL_APEX_API_KEY=... node poll.mjs
 *   SENTINEL_APEX_API_KEY=... SENTINEL_APEX_OUT=./brief.json node poll.mjs
 *
 * Exit codes: 0 written or printed, 2 missing key, 3 unauthorized,
 * 4 kept previous file because intelligence was not FRESH,
 * 5 malformed, 6 server/network after retries.
 */
import { open, rename, unlink } from "node:fs/promises";
import { pollDecision, retryDelayMs } from "./poll-lib.mjs";

const base = (process.env.SENTINEL_APEX_BASE || "https://intel.cyberdudebivash.com").replace(/\/$/, "");
const key = process.env.SENTINEL_APEX_API_KEY || "";
const out = process.env.SENTINEL_APEX_OUT || "";
const lens = process.env.SENTINEL_APEX_LENS || "all";
const timeoutMs = Math.min(30000, Math.max(1000, Number(process.env.SENTINEL_APEX_TIMEOUT_MS) || 10000));

function log(event, fields) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

if (!key) {
  log("refused", { reason: "missing_api_key" });
  process.exit(2);
}

function briefUrl() {
  const url = new URL("/api/watchdog/brief", base);
  if (lens && lens !== "all") url.searchParams.set("lens", lens);
  url.searchParams.set("limit", process.env.SENTINEL_APEX_LIMIT || "50");
  return url;
}

async function call(url) {
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "X-API-Key": key,
      "User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX-CYBER-WATCHDOG/2.0",
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  return { status: res.status, text, retryAfter: res.headers.get("retry-after") };
}

let last = null;
for (let attempt = 0; attempt < 4; attempt += 1) {
  try {
    last = await call(briefUrl());
  } catch (err) {
    log("network", { attempt, name: err.name || "Error" });
    last = { status: 599, text: "", retryAfter: null };
  }
  const decision = pollDecision(last.status, last.text);
  if (decision.action !== "retry") break;
  const wait = retryDelayMs(attempt, last.retryAfter);
  log("retry", { attempt, status: last.status, wait_ms: wait });
  await new Promise((resolve) => setTimeout(resolve, wait));
}

const decision = pollDecision(last.status, last.text);
if (!decision.replace) {
  log("kept_previous", { status: last.status, exit: decision.exitCode, freshness: decision.parsed?.freshness_status || null });
  process.exit(decision.exitCode);
}

if (out) {
  const tmp = out + ".tmp";
  const fh = await open(tmp, "w");
  await fh.writeFile(last.text.endsWith("\n") ? last.text : last.text + "\n");
  await fh.sync();
  await fh.close();
  await rename(tmp, out);
  log("wrote", { path: out, feed_item_count: decision.parsed.feed_item_count, freshness_status: decision.parsed.freshness_status });
} else {
  process.stdout.write(last.text.endsWith("\n") ? last.text : last.text + "\n");
}

if (process.env.SENTINEL_APEX_EVENTS !== "0") {
  try {
    const events = await call(new URL("/api/watchdog/events?limit=20", base));
    const eventDecision = pollDecision(events.status, events.text);
    if (eventDecision.action === "write") {
      log("events", { stored: eventDecision.parsed.total ?? null, inserted_history: eventDecision.parsed.analytics?.history || null });
    } else if (events.status === 403) {
      log("events_not_entitled", { status: 403 });
    } else {
      log("events_skipped", { status: events.status });
    }
  } catch (err) {
    log("events_network", { name: err.name || "Error" });
  }
}
process.exit(0);
