import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = readFileSync('scripts/demo-key-operator.mjs', 'utf8');

test('demo-key operator uses cryptographic 256-bit generation and file-backed KV writes', () => {
  assert.ok(source.includes('randomBytes(32)'));
  assert.ok(source.includes("createHash('sha256')"));
  assert.ok(source.includes("'--path', recordPath"));
  assert.ok(source.includes("'--ttl', String(ttl)"));
});

test('demo-key operator never prints the raw credential and verifies preflight', () => {
  assert.ok(source.includes('Raw credential  : NOT PRINTED'));
  assert.ok(source.includes('copyClipboard(key)'));
  assert.ok(source.includes('/api/v1/swarm/preflight'));
  assert.equal(/console\.log\([^\n]*raw_key/.test(source), false);
});

test('revoke fails closed through suspended tombstone before deleting key', () => {
  assert.ok(source.includes("subscription_status: 'suspended'"));
  assert.ok(source.includes("status: 'revoked'"));
  assert.ok(source.includes('if (!denied) throw new Error'));
  assert.ok(source.includes("'kv', 'key', 'delete'"));
  assert.ok(source.includes('cleanupState(pointer)'));
});

test('demo-key operator executes project-local Wrangler through process.execPath', () => {
  assert.ok(source.includes('spawnSync(process.execPath'));
  assert.ok(source.includes("'node_modules'"));
  assert.ok(source.includes("'wrangler'"));
  assert.ok(source.includes("'bin'"));
  assert.ok(source.includes("'wrangler.js'"));
  assert.ok(source.includes('existsSync(cli)'));

  assert.equal(
    source.includes(
      "const bin = process.platform === 'win32' ? 'npx.cmd' : 'npx';"
    ),
    false
  );

  assert.equal(
    source.includes("spawnSync(bin, ['wrangler', ...args]"),
    false
  );
});
