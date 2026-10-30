import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolveCanonicalTier } from "../subscription-lifecycle.js";

const TIERS = Object.freeze({ FREE: "FREE", PRO: "PRO", ENTERPRISE: "ENTERPRISE", MSSP: "MSSP" });

for (const tier of Object.keys(TIERS)) {
  test("accepts only explicitly configured canonical tier " + tier, () => {
    assert.equal(resolveCanonicalTier(tier, TIERS), tier);
  });
}

for (const value of [undefined, null, "", "pro", "enterprise", "Mssp", "UNKNOWN",
  "__proto__", "constructor", "toString", "hasOwnProperty", "prototype", 0, 1, {}, [], false]) {
  test("rejects invalid entitlement tier " + String(value), () => {
    assert.equal(resolveCanonicalTier(value, TIERS), null);
  });
}

test("rejects a malformed or mismatched tier registry", () => {
  assert.equal(resolveCanonicalTier("PRO", null), null);
  assert.equal(resolveCanonicalTier("PRO", { PRO: 1 }), null);
  assert.equal(resolveCanonicalTier("PRO", { PRO: "MSSP" }), null);
  assert.equal(resolveCanonicalTier("PRO", Object.create({ PRO: "PRO" })), null);
});

test("gateway authorization paths never default a malformed tier to PRO", () => {
  const src = readFileSync(fileURLToPath(new URL("../index.js", import.meta.url)), "utf8");
  assert.doesNotMatch(src, /TIERS\[(?:record|payload)\.tier\]\s*\|\|\s*TIERS\.PRO/);
  assert.match(src, /if \(!verifiedJwtTier\) return \{ tier: TIERS\.FREE/);
  assert.match(src, /if \(!verifiedRecordTier\) \{/);
  assert.match(src, /const resolvedTier = resolveCanonicalTier\(domainRec\.tier, TIERS\)/);
  assert.match(src, /if \(!resolveCanonicalTier\(tier, TIERS\)\)/);
});
