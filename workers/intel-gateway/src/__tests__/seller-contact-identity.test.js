import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CANONICAL = 'contact@cyberdudebivash.in';
const RETIRED = ['enterprise@cyberdudebivash.com', 'enterprise@cyberdudebivash.in'];
const repoFile = path => readFileSync(fileURLToPath(new URL('../../../../' + path, import.meta.url)), 'utf8');

const SELLER_SURFACES = Object.freeze([
  'index.html',
  'upgrade.html',
  'user-test-kit.html',
  'contact-enterprise.html',
  'workers/intel-gateway/src/enterprise-endpoints.js',
  'api/enterprise.py',
  'scripts/demo_key_generator.py',
]);

test('all customer-facing seller and enterprise contact surfaces use the verified address', () => {
  for (const path of SELLER_SURFACES) {
    const content = repoFile(path);
    assert.ok(content.includes(CANONICAL), path + ': canonical contact missing');
    for (const old of RETIRED) {
      assert.ok(!content.includes(old), path + ': retired seller email remains');
    }
  }
});

test('checkout SELLER details link to the actual contact inbox, not an obsolete mailbox', () => {
  const html = repoFile('upgrade.html');
  const seller = html.slice(html.indexOf('<h2 class="side-title">Seller</h2>'));
  assert.ok(seller.startsWith('<h2 class="side-title">Seller</h2>'), 'seller section missing');
  assert.match(seller, /href="mailto:contact@cyberdudebivash\.in">contact@cyberdudebivash\.in<\/a>/);
  assert.ok(!/mailto:enterprise@cyberdudebivash\.(?:com|in)/.test(html));
});

test('beta customer invitation has matching visible customer contact link', () => {
  const html = repoFile('user-test-kit.html');
  assert.match(html, /href="mailto:contact@cyberdudebivash\.in"/);
  assert.ok(!html.includes('mailto:enterprise@'));
});

test('all six dashboard sales-kit inquiry CTAs use the approved customer contact', () => {
  const html = repoFile('index.html');
  const matches = [...html.matchAll(/href="mailto:contact@cyberdudebivash\\.in\\?subject=[^"]+"/g)];
  assert.ok(matches.length >= 6, 'dashboard sales-kit CTAs must use canonical contact');
  assert.ok(!html.includes('mailto:enterprise@cyberdudebivash.com'));
});
