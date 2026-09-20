#!/usr/bin/env node

import { randomBytes, createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const BASE_URL = process.env.CDB_DEMO_BASE_URL || 'https://intel.cyberdudebivash.com';
const POINTER = join(tmpdir(), 'cdb-sentinel-demo-current.json');
const ENV = 'production';
const BINDING = 'API_KEYS_KV';

function arg(name, fallback = null) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')
    ? process.argv[i + 1]
    : fallback;
}

function command() {
  return process.argv[2] || 'help';
}

function wrangler(args, { capture = false } = {}) {
  const bin = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  const result = spawnSync(bin, ['wrangler', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    windowsHide: true,
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'ignore', 'ignore'],
  });

  if (result.error || result.status !== 0) {
    const detail = capture ? String(result.stderr || result.stdout || '').trim().slice(0, 600) : '';
    throw new Error(`wrangler failed (${result.status ?? 'spawn'}): ${detail || 'see local Wrangler authentication/configuration'}`);
  }
  return String(result.stdout || '');
}

function secureWrite(path, value) {
  writeFileSync(path, value, { encoding: 'utf8', mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* Windows ACL semantics differ */ }
}

function copyClipboard(text) {
  if (process.platform === 'win32') {
    const result = spawnSync('clip.exe', [], { input: text, encoding: 'utf8', windowsHide: true });
    if (result.status !== 0) throw new Error('Windows clipboard copy failed');
    return;
  }
  if (process.platform === 'darwin') {
    const result = spawnSync('pbcopy', [], { input: text, encoding: 'utf8' });
    if (result.status !== 0) throw new Error('macOS clipboard copy failed');
    return;
  }
  for (const candidate of [['wl-copy', []], ['xclip', ['-selection', 'clipboard']]]) {
    const result = spawnSync(candidate[0], candidate[1], { input: text, encoding: 'utf8' });
    if (result.status === 0) return;
  }
  throw new Error('No supported clipboard utility is available');
}

function clearClipboard() {
  try { copyClipboard('CDB_CLIPBOARD_CLEARED'); } catch { /* cleanup must not mask revoke */ }
}

function readPointer() {
  if (!existsSync(POINTER)) throw new Error('No current demo-key state pointer found. Run demo:key:create first.');
  const pointer = JSON.parse(readFileSync(POINTER, 'utf8'));
  if (!pointer?.state_path || !existsSync(pointer.state_path)) {
    throw new Error('Demo-key state pointer is stale or missing');
  }
  return pointer;
}

function readState() {
  const pointer = readPointer();
  return { pointer, state: JSON.parse(readFileSync(pointer.state_path, 'utf8')) };
}

function cleanupState(pointer) {
  try { if (pointer?.state_path) rmSync(pointer.state_path, { force: true }); } catch {}
  try { rmSync(POINTER, { force: true }); } catch {}
}

async function preflight(key) {
  const response = await fetch(`${BASE_URL}/api/v1/swarm/preflight`, {
    method: 'GET',
    headers: {
      'x-api-key': key,
      'x-request-id': `demo-key-${crypto.randomUUID()}`,
    },
    cache: 'no-store',
    signal: AbortSignal.timeout(20000),
  });
  let body = null;
  try { body = await response.json(); } catch {}
  return { response, body };
}

async function createDemoKey() {
  const hours = Number(arg('--hours', '4'));
  if (!Number.isFinite(hours) || hours <= 0 || hours > 24) {
    throw new Error('--hours must be >0 and <=24');
  }

  const now = new Date();
  const expires = new Date(now.getTime() + hours * 3600_000);
  const ttl = Math.floor((expires.getTime() - Date.now()) / 1000);
  if (ttl < 300) throw new Error('calculated TTL is too short');

  const randomHex = randomBytes(32).toString('hex');
  const key = `cdb_enterprise_demo_${randomHex}`;
  const keyHash = createHash('sha256').update(key, 'utf8').digest('hex');
  const demoId = `demo-${now.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}-${randomBytes(4).toString('hex')}`;
  const keyId = `key-${demoId}`;
  const fingerprint = keyHash.slice(0, 12);

  const record = {
    key_id: keyId,
    key_hash: keyHash,
    tier: 'ENTERPRISE',
    customer_id: demoId,
    name: 'CYBERDUDEBIVASH SWARM GLOBAL LIVE DEMO',
    source: 'operator_demo_key_cli',
    purpose: 'sentinel_apex_swarm_global_customer_demo',
    is_demo: true,
    created_at: now.toISOString(),
    expires_at: expires.toISOString(),
    subscription_status: 'active',
    status: 'active',
  };

  const work = mkdtempSync(join(tmpdir(), 'cdb-demo-key-'));
  const recordPath = join(work, 'record.json');
  const statePath = join(tmpdir(), `cdb-sentinel-demo-key-${fingerprint}.json`);
  let remoteCreated = false;

  try {
    secureWrite(recordPath, JSON.stringify(record));

    wrangler([
      'kv', 'key', 'put', key,
      '--path', recordPath,
      '--env', ENV,
      '--binding', BINDING,
      '--remote',
      '--ttl', String(ttl),
    ]);
    remoteCreated = true;

    const raw = wrangler([
      'kv', 'key', 'get', key,
      '--env', ENV,
      '--binding', BINDING,
      '--remote',
      '--text',
    ], { capture: true });

    const stored = JSON.parse(raw);
    if (
      stored.key_hash !== keyHash ||
      stored.tier !== 'ENTERPRISE' ||
      stored.subscription_status !== 'active' ||
      stored.customer_id !== demoId
    ) {
      throw new Error('remote API_KEYS_KV read-back integrity check failed');
    }

    let verified = null;
    for (let attempt = 1; attempt <= 12; attempt += 1) {
      const result = await preflight(key);
      if (
        result.response.status === 200 &&
        result.body?.eligible === true &&
        result.body?.entitlement?.tier === 'ENTERPRISE' &&
        result.body?.entitlement?.swarm_enabled === true &&
        result.body?.entitlement?.scope_granted === true
      ) {
        verified = result.body;
        break;
      }
      if ([401, 503].includes(result.response.status)) {
        await new Promise((resolve) => setTimeout(resolve, 5000));
        continue;
      }
      throw new Error(`canonical preflight rejected demo key: HTTP ${result.response.status} ${result.body?.reason || result.body?.error || ''}`);
    }

    if (!verified) throw new Error('canonical preflight did not observe the demo key before timeout');
    if (verified?.quota?.daily?.available !== true) throw new Error('daily quota telemetry unavailable');
    if (Number(verified?.quota?.daily?.remaining) < 32) throw new Error('insufficient quota reserve for certification + demo');

    const state = {
      schema: 'cdb.demo-key.operator.v1',
      raw_key: key,
      key_id: keyId,
      key_hash: keyHash,
      fingerprint,
      demo_id: demoId,
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
      state_path: statePath,
    };
    secureWrite(statePath, JSON.stringify(state));
    secureWrite(POINTER, JSON.stringify({ state_path: statePath, fingerprint }));

    copyClipboard(key);

    console.log('TEMP ENTERPRISE DEMO CREDENTIAL: READY');
    console.log('Tier            : ENTERPRISE');
    console.log('SWARM eligible  : true');
    console.log('Scope granted   : true');
    console.log(`Quota remaining : ${verified.quota.daily.remaining}`);
    console.log(`Expires         : ${expires.toISOString()}`);
    console.log(`Fingerprint     : ${fingerprint}`);
    console.log('Raw credential  : NOT PRINTED');
    console.log('Clipboard       : READY');
    console.log(`Local state     : ${statePath}`);
    console.log('Failsafe        : Cloudflare KV TTL enabled');
  } catch (error) {
    if (remoteCreated) {
      try {
        wrangler(['kv', 'key', 'delete', key, '--env', ENV, '--binding', BINDING, '--remote']);
      } catch {}
    }
    try { rmSync(statePath, { force: true }); } catch {}
    try { rmSync(POINTER, { force: true }); } catch {}
    clearClipboard();
    throw error;
  } finally {
    try { rmSync(work, { recursive: true, force: true }); } catch {}
  }
}

async function statusDemoKey() {
  const { state } = readState();
  const result = await preflight(state.raw_key);
  console.log(`Fingerprint     : ${state.fingerprint}`);
  console.log(`Expires         : ${state.expires_at}`);
  console.log(`HTTP            : ${result.response.status}`);
  console.log(`Eligible        : ${result.body?.eligible === true}`);
  console.log(`Tier            : ${result.body?.entitlement?.tier || '—'}`);
  console.log(`Quota remaining : ${result.body?.quota?.daily?.remaining ?? '—'}`);
}

async function copyDemoKey() {
  const { state } = readState();
  copyClipboard(state.raw_key);
  console.log(`Demo credential copied to clipboard. Fingerprint: ${state.fingerprint}`);
}

async function revokeDemoKey() {
  const { pointer, state } = readState();
  const now = new Date();

  const tombstone = {
    key_id: state.key_id,
    key_hash: state.key_hash,
    tier: 'ENTERPRISE',
    customer_id: state.demo_id,
    name: 'CYBERDUDEBIVASH SWARM GLOBAL LIVE DEMO',
    source: 'operator_demo_key_cli',
    purpose: 'sentinel_apex_swarm_global_customer_demo',
    is_demo: true,
    created_at: state.created_at,
    expires_at: state.expires_at,
    subscription_status: 'suspended',
    status: 'revoked',
    revoked_at: now.toISOString(),
    revoke_reason: 'demo_completed',
  };

  const work = mkdtempSync(join(tmpdir(), 'cdb-demo-revoke-'));
  const tombstonePath = join(work, 'revoked.json');

  try {
    secureWrite(tombstonePath, JSON.stringify(tombstone));
    wrangler([
      'kv', 'key', 'put', state.raw_key,
      '--path', tombstonePath,
      '--env', ENV,
      '--binding', BINDING,
      '--remote',
      '--ttl', '300',
    ]);

    let denied = false;
    for (let attempt = 1; attempt <= 12; attempt += 1) {
      const result = await preflight(state.raw_key);
      if ([401, 403].includes(result.response.status)) {
        denied = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
    if (!denied) throw new Error('revocation tombstone was not observed by canonical auth; key was NOT deleted');

    wrangler(['kv', 'key', 'delete', state.raw_key, '--env', ENV, '--binding', BINDING, '--remote']);
    cleanupState(pointer);
    clearClipboard();

    console.log('DEMO CREDENTIAL REVOKED: PASS');
    console.log(`Fingerprint: ${state.fingerprint}`);
    console.log('Canonical access denial observed before deletion.');
    console.log('Remote KV key deleted.');
    console.log('Local state deleted.');
    console.log('Clipboard cleared.');
  } finally {
    try { rmSync(work, { recursive: true, force: true }); } catch {}
  }
}

async function main() {
  switch (command()) {
    case 'create':
      await createDemoKey();
      break;
    case 'status':
      await statusDemoKey();
      break;
    case 'copy':
      await copyDemoKey();
      break;
    case 'revoke':
      await revokeDemoKey();
      break;
    default:
      console.log('Usage: node scripts/demo-key-operator.mjs <create|status|copy|revoke> [--hours 4]');
      console.log('The raw key is never printed. create/copy use the OS clipboard.');
      process.exitCode = command() === 'help' ? 0 : 2;
  }
}

main().catch((error) => {
  console.error(`DEMO KEY OPERATOR FAILED: ${error?.message || error}`);
  process.exitCode = 1;
});
