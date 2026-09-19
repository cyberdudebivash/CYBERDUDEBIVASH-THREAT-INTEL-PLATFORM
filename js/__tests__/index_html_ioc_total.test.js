import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";

// ---------------------------------------------------------------------------
// P0 regression suite -- CYBERDUDEBIVASH SENTINEL APEX
//
// Live production investigation found the dashboard's "TOTAL IOCs" metric
// (#eicc-m-iocs) displaying an astronomically invalid value:
//   490000000000000000000000000000000  (33 digits)
//
// Root cause, in index.html's eiccEngine() -> fillMetrics():
//   iocs += (it.ioc_count||it.iocs||0)
// `it.iocs` on real feed items is an empty array `[]` -- truthy in JS -- so
// once ioc_count is 0 the `||` chain picks the array. `0 + []` then coerces
// via Array.prototype.toString() ('') to the STRING "0", and every
// subsequent `+=` becomes string concatenation of digit characters instead
// of numeric addition. Reproduced exactly (byte-for-byte) against live
// api/feed.json data before the fix.
//
// This test extracts and executes the real _iocContribution() function
// straight out of index.html (not a reimplementation), so it cannot
// silently drift from what the dashboard actually runs.
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const INDEX_HTML = path.join(__dirname, "..", "..", "index.html");

function loadIocContribution() {
  const src = readFileSync(INDEX_HTML, "utf-8");
  const start = src.indexOf("function _iocContribution(it){");
  assert.ok(start !== -1, "_iocContribution() not found in index.html -- has the fix been reverted?");
  const end = src.indexOf("\n            }", start);
  assert.ok(end !== -1, "could not locate the end of _iocContribution() in index.html");
  const fnSrc = src.slice(start, end + "\n            }".length);
  const context = {};
  vm.createContext(context);
  vm.runInContext(fnSrc + "\nthis._iocContribution = _iocContribution;", context);
  return context._iocContribution;
}

const _iocContribution = loadIocContribution();

function sumIocsCorrectly(items) {
  let total = 0;
  for (const it of items) total += _iocContribution(it);
  return total;
}

test("numeric ioc_count is used directly", () => {
  assert.equal(_iocContribution({ ioc_count: 16, iocs: [] }), 16);
});

test("empty iocs array (the live failure trigger) contributes 0, as a number", () => {
  const c = _iocContribution({ ioc_count: 0, iocs: [] });
  assert.equal(c, 0);
  assert.equal(typeof c, "number");
});

test("array iocs field with entries contributes its length when ioc_count is absent", () => {
  assert.equal(_iocContribution({ iocs: ["a", "b", "c"] }), 3);
});

test("item with neither field contributes 0", () => {
  assert.equal(_iocContribution({}), 0);
});

test("summing a realistic mixed feed never produces a string or NaN", () => {
  const items = [
    { ioc_count: 0, iocs: [] },
    { ioc_count: 0, iocs: [] },
    { ioc_count: 16, iocs: [] },
    { ioc_count: 0, iocs: null },
    { ioc_count: 3, iocs: [] },
  ];
  const total = sumIocsCorrectly(items);
  assert.equal(total, 19);
  assert.equal(typeof total, "number");
  assert.ok(!Number.isNaN(total));
});

test("39-item live-shaped feed reproduces a small correct number, not the astronomical string", () => {
  // Same shape as the real live api/feed.json at the time of investigation:
  // 38 items with ioc_count 0 (iocs: []), 1 item with ioc_count 16.
  const items = [];
  for (let i = 0; i < 38; i++) items.push({ ioc_count: 0, iocs: [] });
  items.push({ ioc_count: 16, iocs: [] });
  const total = sumIocsCorrectly(items);
  assert.equal(total, 16);
  assert.equal(typeof total, "number");
  // The exact defect this guards against: a 33-digit string total.
  assert.notEqual(String(total).length, 33);
});

test("rejects the exact reported astronomically invalid total as impossible for this input size", () => {
  const items = [];
  for (let i = 0; i < 38; i++) items.push({ ioc_count: 0, iocs: [] });
  items.push({ ioc_count: 16, iocs: [] });
  const total = sumIocsCorrectly(items);
  assert.notEqual(total, 490000000000000000000000000000000);
  assert.ok(total < 1000, "IOC total for a 39-item feed must be a small, sane number");
});
