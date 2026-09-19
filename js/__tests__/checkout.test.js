import assert from "node:assert/strict";
import { test } from "node:test";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// js/checkout.js is a classic browser <script src> (IIFE attaching
// window.SentinelCheckout), matching pricing.html/upgrade.html's own
// zero-build-step, no-ES-modules convention -- it is not itself an ES
// module, so it's loaded here via vm.runInContext with minimal window/
// navigator/Intl/sessionStorage stubs, exactly the browser surface the
// script actually touches. This exercises the real shipped file, not a
// reimplementation of its logic.
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = fs.readFileSync(path.join(__dirname, "../checkout.js"), "utf8");

function fakeSessionStorage(initial) {
  const data = Object.assign({}, initial);
  return {
    getItem: (k) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null),
    setItem: (k, v) => { data[k] = v; },
  };
}

function load({ setCurrency, timeZone, language, storedCurrency } = {}) {
  const sandbox = {
    window: {},
    navigator: { language: language || "en-US" },
    Intl: {
      DateTimeFormat: () => ({ resolvedOptions: () => ({ timeZone: timeZone || "America/New_York" }) }),
    },
    sessionStorage: fakeSessionStorage(storedCurrency ? { currency: storedCurrency } : {}),
    alert: () => {},
    console,
  };
  if (setCurrency) sandbox.window.setCurrency = setCurrency;
  vm.createContext(sandbox);
  vm.runInContext(SOURCE, sandbox);
  return { SentinelCheckout: sandbox.window.SentinelCheckout, sandbox };
}

// --- detectRegionDefaultCurrency ---------------------------------------------

test("detectRegionDefaultCurrency sets INR for an Asia/Kolkata timezone visitor", () => {
  const calls = [];
  const { SentinelCheckout } = load({ setCurrency: (c) => calls.push(c), timeZone: "Asia/Kolkata", language: "en-IN" });
  SentinelCheckout.detectRegionDefaultCurrency();
  assert.deepEqual(calls, ["INR"]);
});

test("detectRegionDefaultCurrency sets INR for an en-IN browser language even with a non-IST timezone (e.g. VPN)", () => {
  const calls = [];
  const { SentinelCheckout } = load({ setCurrency: (c) => calls.push(c), timeZone: "America/New_York", language: "en-IN" });
  SentinelCheckout.detectRegionDefaultCurrency();
  assert.deepEqual(calls, ["INR"]);
});

test("detectRegionDefaultCurrency leaves USD default alone for a non-Indian visitor", () => {
  const calls = [];
  const { SentinelCheckout } = load({ setCurrency: (c) => calls.push(c), timeZone: "America/New_York", language: "en-US" });
  SentinelCheckout.detectRegionDefaultCurrency();
  assert.deepEqual(calls, []);
});

test("detectRegionDefaultCurrency never overrides a currency the visitor already chose this session", () => {
  const calls = [];
  const { SentinelCheckout } = load({ setCurrency: (c) => calls.push(c), timeZone: "Asia/Kolkata", storedCurrency: "USD" });
  SentinelCheckout.detectRegionDefaultCurrency();
  assert.deepEqual(calls, [], "an explicit prior choice must win over region detection");
});

test("detectRegionDefaultCurrency is a no-op (never throws) on a page with no currency selector", () => {
  const { SentinelCheckout } = load({ timeZone: "Asia/Kolkata" }); // no setCurrency defined -- e.g. upgrade.html
  assert.doesNotThrow(() => SentinelCheckout.detectRegionDefaultCurrency());
});

// --- validateTaxId -------------------------------------------------------------

test("validateTaxId accepts an empty value -- the field is optional", () => {
  const { SentinelCheckout } = load();
  const res = SentinelCheckout.validateTaxId("  ");
  assert.equal(res.ok, true);
  assert.equal(res.value, "");
});

test("validateTaxId accepts a well-formed 15-character GSTIN", () => {
  const { SentinelCheckout } = load();
  const res = SentinelCheckout.validateTaxId("22aaaaa0000a1z5");
  assert.equal(res.ok, true);
  assert.equal(res.value, "22AAAAA0000A1Z5"); // normalized uppercase
});

test("validateTaxId flags a 15-character value that doesn't match the GSTIN shape", () => {
  const { SentinelCheckout } = load();
  const res = SentinelCheckout.validateTaxId("123456789012345");
  assert.equal(res.ok, false);
  assert.match(res.reason, /GSTIN/);
});

test("validateTaxId accepts a non-15-character value as-is (international VAT formats vary too widely to validate generically)", () => {
  const { SentinelCheckout } = load();
  const res = SentinelCheckout.validateTaxId("DE123456789");
  assert.equal(res.ok, true);
  assert.equal(res.value, "DE123456789");
});

// --- bindPaymentFailedHandler ---------------------------------------------------

test("bindPaymentFailedHandler registers on 'payment.failed' and forwards a readable message", () => {
  const { SentinelCheckout } = load();
  let registeredEvent = null;
  let registeredFn = null;
  const fakeRzp = { on: (evt, fn) => { registeredEvent = evt; registeredFn = fn; } };

  let received = null;
  SentinelCheckout.bindPaymentFailedHandler(fakeRzp, (msg, err) => { received = { msg, err }; });

  assert.equal(registeredEvent, "payment.failed");
  registeredFn({ error: { description: "Insufficient funds" } });
  assert.match(received.msg, /declined/i);
  assert.match(received.msg, /Insufficient funds/);
});

test("bindPaymentFailedHandler tolerates a missing/invalid rzp instance without throwing", () => {
  const { SentinelCheckout } = load();
  assert.doesNotThrow(() => SentinelCheckout.bindPaymentFailedHandler(null, () => {}));
  assert.doesNotThrow(() => SentinelCheckout.bindPaymentFailedHandler({}, () => {}));
});

// --- buildOnboardingSnippets -----------------------------------------------------

test("buildOnboardingSnippets embeds the real API key in both the cURL and Python snippets", () => {
  const { SentinelCheckout } = load();
  const { curl, python } = SentinelCheckout.buildOnboardingSnippets("sk_live_TESTKEY123");
  assert.match(curl, /X-API-Key: sk_live_TESTKEY123/);
  assert.match(curl, /https:\/\/intel\.cyberdudebivash\.com\/api\/feed/);
  assert.match(python, /sk_live_TESTKEY123/);
  assert.match(python, /requests\.get/);
});
