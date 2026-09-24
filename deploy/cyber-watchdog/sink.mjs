#!/usr/bin/env node
/**
 * CYBER WATCHDOG reference webhook receiver (customer side / owner canary sink).
 *
 * Run it on a host YOU control, behind HTTPS on port 443 (e.g. a reverse
 * proxy terminating TLS). It:
 *   - answers the destination verification challenge;
 *   - verifies every delivery signature when WATCHDOG_SECRET is set
 *     (signature = hex(HMAC-SHA256(secret, timestamp + "." + raw_body)),
 *      header X-CDB-Watchdog-Signature: v1=<hex>, 300 s timestamp tolerance);
 *   - deduplicates on X-CDB-Watchdog-Delivery-ID (retries reuse it);
 *   - keeps the last 100 requests for the canary at GET /__inspect
 *     (Bearer SINK_TOKEN), and lets the canary force a status with
 *     POST /__inspect/mode {"status":503,"retry_after":120}.
 *
 *   PORT=8787 SINK_TOKEN=... [WATCHDOG_SECRET=whsec_...] node sink.mjs
 */
import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

const port = Number(process.env.PORT || 8787);
const token = process.env.SINK_TOKEN || "";
const secret = process.env.WATCHDOG_SECRET || "";
const records = [];
const seenDeliveries = new Set();
let mode = { status: 204, retry_after: null };

if (!token || token.length < 24) {
  console.error("SINK_TOKEN (24+ chars) is required");
  process.exit(2);
}

function verify(headers, raw) {
  if (!secret) return "unchecked";
  const ts = Number(headers["x-cdb-watchdog-timestamp"]);
  const sig = String(headers["x-cdb-watchdog-signature"] || "");
  if (!Number.isInteger(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return "timestamp_rejected";
  const m = /^v1=([0-9a-f]{64})$/.exec(sig);
  if (!m) return "bad_signature_format";
  const want = createHmac("sha256", secret).update(ts + "." + raw).digest();
  return timingSafeEqual(want, Buffer.from(m[1], "hex")) ? "valid" : "invalid";
}

function authorized(req) {
  const got = Buffer.from(String(req.headers.authorization || ""));
  const want = Buffer.from("Bearer " + token);
  return got.length === want.length && timingSafeEqual(got, want);
}

http.createServer((req, res) => {
  let raw = "";
  req.setEncoding("utf8");
  req.on("data", (c) => { raw += c; if (raw.length > 262144) req.destroy(); });
  req.on("end", () => {
    const url = new URL(req.url, "http://sink");
    if (url.pathname.startsWith("/__inspect")) {
      if (!authorized(req)) { res.writeHead(401).end(); return; }
      if (req.method === "POST" && url.pathname === "/__inspect/mode") {
        try { const m = JSON.parse(raw); mode = { status: Number(m.status) || 204, retry_after: m.retry_after || null }; } catch { /* keep */ }
        res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(mode));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ records }));
      return;
    }
    if (req.method !== "POST") { res.writeHead(405).end(); return; }
    let body = null;
    try { body = JSON.parse(raw); } catch { body = null; }
    const signature = verify(req.headers, raw);
    const deliveryId = req.headers["x-cdb-watchdog-delivery-id"] || null;
    const duplicate = deliveryId ? seenDeliveries.has(deliveryId) : false;
    records.unshift({ at: new Date().toISOString(), headers: req.headers, raw, signature, duplicate });
    records.length = Math.min(records.length, 100);
    if (signature === "invalid" || signature === "timestamp_rejected" || signature === "bad_signature_format") { res.writeHead(401).end(); return; }
    if (body && body.type === "watchdog.verification") {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ challenge: body.challenge }));
      return;
    }
    const headers = mode.retry_after ? { "Retry-After": String(mode.retry_after) } : {};
    if (mode.status >= 200 && mode.status < 300 && deliveryId) seenDeliveries.add(deliveryId);
    res.writeHead(mode.status, headers).end();
  });
}).listen(port, () => console.log(JSON.stringify({ sink: "listening", port, signature_check: secret ? "on" : "off" })));
