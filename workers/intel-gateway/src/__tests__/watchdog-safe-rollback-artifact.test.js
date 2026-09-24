/**
 * The SAFE ROLLBACK TARGET artifact is pinned: overlay files match the
 * manifest, the manifest's base is pre-v3 main, and the overlay keeps the
 * v3 Durable Object class deployable. (Behavior: watchdog-rollback-matrix.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SR = path.resolve(HERE, "../../../../deploy/cyber-watchdog/safe-rollback");
const manifest = JSON.parse(readFileSync(path.join(SR, "manifest.json"), "utf8"));
const read = (rel) => readFileSync(path.join(SR, "overlay", rel), "utf8");

test("manifest pins base 6ac0385 and every overlay file hash", () => {
  assert.equal(manifest.name, "watchdog-v2-safe-rollback");
  assert.equal(manifest.base_sha, "6ac0385d658035ec53b98b5476dbc7af30887426");
  assert.match(manifest.artifact_digest, /^[0-9a-f]{64}$/);
  for (const [rel, want] of Object.entries(manifest.overlay_files_sha256)) {
    assert.equal(createHash("sha256").update(readFileSync(path.join(SR, "overlay", rel))).digest("hex"), want, rel);
  }
  assert.deepEqual(Object.keys(manifest.overlay_files_sha256).sort(), [
    "workers/intel-gateway/src/cyber-watchdog.js",
    "workers/intel-gateway/src/production-entry.js",
    "workers/intel-gateway/src/watchdog-ledger.js",
    "workers/intel-gateway/wrangler.toml",
  ]);
});

test("overlay keeps every Durable Object class, binding and migration that v3 created", () => {
  const entry = read("workers/intel-gateway/src/production-entry.js");
  assert.match(entry, /export class WatchdogScheduler/);
  assert.match(entry, /export \{ GumroadProvisioningLock, WatchdogLedger \} from '\.\/index\.js';/);
  const toml = read("workers/intel-gateway/wrangler.toml");
  const tags = [...toml.matchAll(/^tag\s*=\s*"([^"]+)"/gm)].map((m) => m[1]);
  assert.deepEqual(tags, ["v1-gumroad-provisioning-lock", "v2-watchdog-ledger", "v3-watchdog-scheduler"]);
  assert.equal((toml.match(/class_name = "WatchdogScheduler"/g) || []).length, 2, "default + production bindings");
  const ledger = read("workers/intel-gateway/src/watchdog-ledger.js");
  assert.match(ledger, /async alarm\(\) \{\}/);
});

test("overlay has no remaining outbound Watchdog request path", () => {
  const cw = read("workers/intel-gateway/src/cyber-watchdog.js");
  assert.doesNotMatch(cw, /fetchImpl\(/);
  assert.doesNotMatch(cw, /type: "record_delivery"/);
  assert.doesNotMatch(cw, /type: "set_destination"/);
});

test("the documented rollback target is the safe artifact, never raw 6ac0385", () => {
  const doc = readFileSync(path.resolve(HERE, "../../../../docs/CYBER_WATCHDOG_P3.md"), "utf8");
  assert.match(doc, /DO NOT deploy raw pre-v3 commit 6ac0385/);
  assert.match(doc, /watchdog-v2-safe-rollback/);
  assert.match(doc, new RegExp(manifest.artifact_digest));
});
