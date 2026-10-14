import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  PUBLIC_LATEST_PREMIUM_FIELDS,
  stripPublicLatestPremiumFields,
  hasPublicLatestPremiumFields,
} from '../public-latest-premium-boundary.js';

test('the Worker forbidden-field list includes every Python publication policy PREMIUM_FIELDS value', () => {
  const policy = readFileSync(new URL('../../../../scripts/public_api_sanitizer.py', import.meta.url), 'utf8');
  const declaration = policy.match(/PREMIUM_FIELDS:\s*frozenset\s*=\s*frozenset\(\[([\s\S]*?)\]\)/);
  assert.ok(declaration, 'cannot read authoritative Python premium field declaration');
  const names = [...declaration[1].matchAll(/^\s*"([^"]+)",?\s*(?:#.*)?$/gm)].map(match => match[1]);
  assert.ok(names.length > 25, 'cannot parse enough Python premium keys');
  assert.deepEqual([...new Set(PUBLIC_LATEST_PREMIUM_FIELDS)].sort(), [...new Set(names)].sort(),
    'the Worker field-denial list drifted from Python PREMIUM_FIELDS');
});

test('never exposes premium field names even when FREE masking inserts a locked AI teaser and null bundle', () => {
  const premium = Object.fromEntries(PUBLIC_LATEST_PREMIUM_FIELDS.map(name => [name, null]));
  const original = {
    id: 'intel--test', title: 'Fictional synthetic advisory', tlp: 'TLP:CLEAR',
    risk_score: 5, description: 'Public source description',
    _upgrade_url: '/upgrade.html?plan=pro', threat_urgency: { exploitation_status: 'NOT_VERIFIED' },
    ...premium,
    apex_ai: {
      predictive_risk: 5, ai_summary: 'Synthetic preview', actor_fingerprint: null,
      kill_chain: null, locked: true, upgrade: { plan: 'pro' },
    },
    stix_bundle: null,
  };
  const got = stripPublicLatestPremiumFields(original);
  assert.equal(got.id, original.id);
  assert.equal(got.description, original.description);
  assert.deepEqual(got.threat_urgency, original.threat_urgency);
  assert.equal(got._upgrade_url, original._upgrade_url);
  for (const name of PUBLIC_LATEST_PREMIUM_FIELDS) {
    assert.equal(Object.hasOwn(got, name), false, name);
  }
  assert.ok(Object.hasOwn(original, 'apex_ai'), 'source fixture must remain unchanged');
  assert.ok(Object.hasOwn(original, 'stix_bundle'), 'source fixture must remain unchanged');
  assert.equal(hasPublicLatestPremiumFields({ items: [got] }), false);
  assert.equal(hasPublicLatestPremiumFields({ items: [original] }), true);
});

test('detects old cached FREE response even when its only forbidden key is null', () => {
  assert.equal(hasPublicLatestPremiumFields({ items: [{ tlp: 'TLP:CLEAR', stix_bundle: null }] }), true);
  assert.equal(hasPublicLatestPremiumFields({ items: [{ tlp: 'TLP:CLEAR', apex_ai: { locked: true } }] }), true);
  assert.equal(hasPublicLatestPremiumFields({ items: [{ tlp: 'TLP:CLEAR' }] }), false);
  assert.equal(hasPublicLatestPremiumFields({ items: [] }), false);
  assert.equal(hasPublicLatestPremiumFields({ count: 1 }), true);
  assert.throws(() => stripPublicLatestPremiumFields(null), /PUBLIC_LATEST_ITEM_INVALID/);
  assert.throws(() => stripPublicLatestPremiumFields([]), /PUBLIC_LATEST_ITEM_INVALID/);
});

test('Worker FREE latest route and regional cache validator actually use the last-mile field boundary', () => {
  const worker = readFileSync(new URL('../index.js', import.meta.url), 'utf8');
  const routeStart = worker.indexOf('if (path === "/api/v1/intel/latest.json" || path === "/latest.json") {');
  const routeEnd = worker.indexOf('// --- /api/v1/intel/top10.json', routeStart);
  assert.ok(routeStart >= 0 && routeEnd > routeStart);
  const route = worker.slice(routeStart, routeEnd);
  assert.match(route, /stripPublicLatestPremiumFields\(applyTierGateV2\(i, "free", null\)\)/);
  assert.match(route, /if \(manifestFullAllowed\)/);
  assert.match(route, /"Cache-Control": "private, no-store"/);

  const cacheStart = worker.indexOf('async function cachedLiveFeedIsPublishable(response, pathname)');
  const cacheEnd = worker.indexOf('export default {', cacheStart);
  assert.ok(cacheStart >= 0 && cacheEnd > cacheStart);
  const cache = worker.slice(cacheStart, cacheEnd);
  assert.match(cache, /latest && hasPublicLatestPremiumFields\(feed\)/);
  assert.match(worker, /cachedLiveFeedIsPublishable\(cached, pathname\)/);
});
