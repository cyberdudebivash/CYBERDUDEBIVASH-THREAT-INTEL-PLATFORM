import assert from "node:assert/strict";
import { test } from "node:test";
import http from "node:http";
import ApexDataPlane from "../apex-data-plane.js";

// ---------------------------------------------------------------------------
// STAGE 2 (SENTINEL APEX Dynamic Frontend Transformation) -- js/apex-data-plane.js
// Exercises the shared fetch/contract-safety/race-safety primitives against a
// real local HTTP server (not mocks) so timeout, non-2xx, and malformed-JSON
// behavior reflects what fetch() actually does, matching this repo's existing
// js/__tests__/ convention (node:test, real reproduction over mocking).
// ---------------------------------------------------------------------------

function startServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}
function urlFor(server, path) {
  return `http://127.0.0.1:${server.address().port}${path}`;
}
async function withServer(handler, fn) {
  const server = await startServer(handler);
  try {
    await fn(server);
  } finally {
    server.close();
  }
}

test("fetchJSON: successful 200 JSON response returns ok:true with the parsed body", async () => {
  await withServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ items: [1, 2, 3] }));
  }, async (server) => {
    const result = await ApexDataPlane.fetchJSON(urlFor(server, "/ok"));
    assert.equal(result.ok, true);
    assert.deepEqual(result.data, { items: [1, 2, 3] });
    assert.equal(result.failureClass, null);
  });
});

test("fetchJSON: a 404 is classified as http_4xx, not thrown or treated as empty success", async () => {
  await withServer((req, res) => {
    res.writeHead(404, {});
    res.end("not found");
  }, async (server) => {
    const result = await ApexDataPlane.fetchJSON(urlFor(server, "/missing"));
    assert.equal(result.ok, false);
    assert.equal(result.failureClass, ApexDataPlane.FAILURE_CLASS.HTTP_4XX);
    assert.equal(result.status, 404);
  });
});

test("fetchJSON: a 500 is classified as http_5xx, distinct from http_4xx", async () => {
  await withServer((req, res) => {
    res.writeHead(500, {});
    res.end("boom");
  }, async (server) => {
    const result = await ApexDataPlane.fetchJSON(urlFor(server, "/err"));
    assert.equal(result.ok, false);
    assert.equal(result.failureClass, ApexDataPlane.FAILURE_CLASS.HTTP_5XX);
  });
});

test("fetchJSON: malformed JSON on a 200 is classified as malformed_json, not silently treated as success or a generic network error", async () => {
  await withServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("{not valid json");
  }, async (server) => {
    const result = await ApexDataPlane.fetchJSON(urlFor(server, "/bad-json"));
    assert.equal(result.ok, false);
    assert.equal(result.failureClass, ApexDataPlane.FAILURE_CLASS.MALFORMED_JSON);
  });
});

test("fetchJSON: a request that never responds times out and is classified as 'timeout', not a generic network error", async () => {
  await withServer((req, res) => { /* deliberately never respond */ }, async (server) => {
    const result = await ApexDataPlane.fetchJSON(urlFor(server, "/hang"), { timeoutMs: 150 });
    assert.equal(result.ok, false);
    assert.equal(result.failureClass, ApexDataPlane.FAILURE_CLASS.TIMEOUT);
  });
});

test("fetchWithRetry: does not retry a 4xx (retrying an unchanged validation/auth failure wastes a round trip)", async () => {
  let calls = 0;
  await withServer((req, res) => { calls++; res.writeHead(404, {}); res.end(); }, async (server) => {
    await ApexDataPlane.fetchWithRetry(urlFor(server, "/x"), { maxRetry: 2, retryBackoffMs: 5 });
    assert.equal(calls, 1, "must not retry a 4xx");
  });
});

test("fetchWithRetry: retries a 5xx up to maxRetry, then returns the last failure", async () => {
  let calls = 0;
  await withServer((req, res) => { calls++; res.writeHead(500, {}); res.end(); }, async (server) => {
    const result = await ApexDataPlane.fetchWithRetry(urlFor(server, "/x"), { maxRetry: 2, retryBackoffMs: 5 });
    assert.equal(calls, 3, "1 initial attempt + 2 retries");
    assert.equal(result.ok, false);
    assert.equal(result.failureClass, ApexDataPlane.FAILURE_CLASS.HTTP_5XX);
  });
});

test("fetchWithRetry: stops retrying as soon as a retry succeeds", async () => {
  let calls = 0;
  await withServer((req, res) => {
    calls++;
    if (calls < 2) { res.writeHead(500, {}); res.end(); return; }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  }, async (server) => {
    const result = await ApexDataPlane.fetchWithRetry(urlFor(server, "/x"), { maxRetry: 3, retryBackoffMs: 5 });
    assert.equal(calls, 2);
    assert.equal(result.ok, true);
  });
});

test("createRequestGuard: a superseded request's token is no longer current (race-safety primitive)", () => {
  const guard = ApexDataPlane.createRequestGuard();
  const first = guard.start();
  const second = guard.start();
  assert.equal(guard.isCurrent(first.token), false, "the first, now-stale token must not read as current");
  assert.equal(guard.isCurrent(second.token), true, "the newest token must read as current");
});

test("createRequestGuard: starting a new request aborts the previous one's AbortSignal", () => {
  const guard = ApexDataPlane.createRequestGuard();
  const first = guard.start();
  assert.equal(first.signal.aborted, false);
  guard.start();
  assert.equal(first.signal.aborted, true, "starting a newer request must abort the in-flight older one");
});

test("createRequestGuard + fetchJSON: an aborted-by-supersession fetch reports failureClass aborted_superseded, not a fabricated success or a generic network error", async () => {
  await withServer((req, res) => { /* never respond within the test window */ }, async (server) => {
    const guard = ApexDataPlane.createRequestGuard();
    const stale = guard.start();
    const pending = ApexDataPlane.fetchJSON(urlFor(server, "/slow"), { signal: stale.signal, timeoutMs: 5000 });
    guard.start(); // supersede it immediately
    const result = await pending;
    assert.equal(result.ok, false);
    assert.equal(result.failureClass, ApexDataPlane.FAILURE_CLASS.ABORTED_SUPERSEDED);
  });
});

test("messageForFailure: every failure class produces non-empty, honest text -- never implies a healthy/empty/live result", () => {
  Object.values(ApexDataPlane.FAILURE_CLASS).forEach(function (cls) {
    if (cls === ApexDataPlane.FAILURE_CLASS.ABORTED_SUPERSEDED) return; // internal signal, no customer-facing copy
    const msg = ApexDataPlane.messageForFailure(cls, 500);
    assert.equal(typeof msg, "string");
    assert.ok(msg.length > 0, `failure class "${cls}" must have real message text`);
    assert.doesNotMatch(msg.toLowerCase(), /no threats found|0 threats|\blive\b/, `failure message for "${cls}" must not imply a healthy/empty/live result: "${msg}"`);
  });
});

test("messageForFailure: 401/403 and 429 get distinct, more specific copy than a generic 4xx", () => {
  const auth = ApexDataPlane.messageForFailure(ApexDataPlane.FAILURE_CLASS.HTTP_4XX, 401);
  const rateLimited = ApexDataPlane.messageForFailure(ApexDataPlane.FAILURE_CLASS.HTTP_4XX, 429);
  const generic = ApexDataPlane.messageForFailure(ApexDataPlane.FAILURE_CLASS.HTTP_4XX, 418);
  assert.match(auth.toLowerCase(), /auth/);
  assert.match(rateLimited.toLowerCase(), /rate limit/);
  assert.notEqual(auth, generic);
  assert.notEqual(rateLimited, generic);
});
