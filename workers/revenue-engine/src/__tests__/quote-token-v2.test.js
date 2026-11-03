import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';
import { handleQuoteCreate } from '../enterprise-po.js';
import {
  issueQuoteToken, verifyQuoteToken, quoteV2Enabled,
  quoteSigningReady, quoteLegacyAllowed,
} from '../quote-token-v2.js';

const ID = 'qt_' + 'a'.repeat(20);
const OTHER_ID = 'qt_' + 'b'.repeat(20);
const ADMIN = 'TEST_ONLY_revenue_admin_secret_distinct_value';
const KEY = 'TEST_ONLY_quote_signer_distinct_32_bytes_or_longer';
const PORTAL_KEY = 'TEST_ONLY_portal_key_32_bytes_or_longer';
const legacy = () => ({ REVENUE_ADMIN_SECRET: ADMIN });
const v2 = (over = {}) => ({
  REVENUE_ADMIN_SECRET: ADMIN,
  REVENUE_PORTAL_HMAC_KEY: PORTAL_KEY,
  REVENUE_QUOTE_V2_ENABLED: 'true',
  REVENUE_QUOTE_HMAC_KEY: KEY,
  ...over,
});
const legacyValue = () => createHmac('sha256', ADMIN).update('quote:' + ID).digest('hex');

test('default legacy quote HMAC is byte-compatible; opt-in is never automatic', async () => {
  assert.equal(quoteV2Enabled(legacy()), false);
  assert.equal(quoteSigningReady(legacy()), true);
  assert.equal(await issueQuoteToken(legacy(), ID), legacyValue());
  assert.equal(await verifyQuoteToken(legacy(), ID, legacyValue()), true);
  assert.equal(await verifyQuoteToken({ ...legacy(), REVENUE_QUOTE_V2_ENABLED: 'off' }, ID, legacyValue()), true);
  assert.equal(await verifyQuoteToken({ ...legacy(), REVENUE_QUOTE_V2_ENABLED: 'false' }, ID, legacyValue()), true);
});

test('new quote capabilities use independent key, domain-separated ID, and reject wrong customer', async () => {
  const signed = await issueQuoteToken(v2(), ID);
  assert.match(signed, /^[0-9a-f]{64}$/);
  assert.notEqual(signed, legacyValue());
  assert.equal(await verifyQuoteToken(v2(), ID, signed), true);
  assert.equal(await verifyQuoteToken(v2(), OTHER_ID, signed), false);
  assert.equal(await verifyQuoteToken(v2({ REVENUE_QUOTE_HMAC_KEY: KEY + 'rotated' }), ID, signed), false);
  assert.equal(await verifyQuoteToken(v2(), ID, legacyValue()), false);
  assert.equal(await verifyQuoteToken(v2(), ID, signed.slice(0, -1) + '!'), false);
  assert.equal(await verifyQuoteToken(v2(), ID, ['not-a-token']), false);
  assert.equal(await verifyQuoteToken(v2(), '../../etc', signed), false);
});

test('quote v2 refuses absent, short, shared and misconfigured signing secrets', async () => {
  for (const extra of [
    { REVENUE_QUOTE_HMAC_KEY: undefined },
    { REVENUE_QUOTE_HMAC_KEY: 'short' },
    { REVENUE_QUOTE_HMAC_KEY: ADMIN },
    { REVENUE_QUOTE_HMAC_KEY: PORTAL_KEY },
    { REVENUE_QUOTE_V2_ENABLED: 'yes' },
  ]) {
    const config = v2(extra);
    assert.equal(quoteSigningReady(config), false);
    assert.equal(await issueQuoteToken(config, ID), null);
    assert.equal(await verifyQuoteToken(config, ID, legacyValue()), false);
  }
});

test('legacy grace must be explicitly tied to cutover and <= 90 days', async () => {
  const start = '2026-11-03T00:00:00Z';
  const end = '2026-11-13T00:00:00Z';
  const now = Date.parse('2026-11-05T00:00:00Z');
  const env = v2({
    REVENUE_QUOTE_LEGACY_CUTOVER_AT: start,
    REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL: end,
  });
  assert.equal(quoteLegacyAllowed(env, now), true);
  assert.equal(await verifyQuoteToken(env, ID, legacyValue(), now), true);
  assert.equal(quoteLegacyAllowed(env, Date.parse(end)), false);
  assert.equal(await verifyQuoteToken(env, ID, legacyValue(), Date.parse(end)), false);
  assert.equal(quoteLegacyAllowed(v2({ REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL: end }), now), false);
  assert.equal(quoteLegacyAllowed(v2({ REVENUE_QUOTE_LEGACY_CUTOVER_AT: start }), now), false);
  assert.equal(quoteLegacyAllowed(env, Date.parse('2026-11-02T00:00:00Z')), false);
  const tooLong = v2({
    REVENUE_QUOTE_LEGACY_CUTOVER_AT: start,
    REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL: '2027-04-03T00:00:00Z',
  });
  assert.equal(quoteLegacyAllowed(tooLong, now), false);
  assert.equal(quoteLegacyAllowed(tooLong, Date.parse('2027-02-03T00:00:00Z')), false,
    'an overlong grace must never become valid as time passes');
});

test('misconfigured opt-in cannot persist a quote or touch D1', async () => {
  let touched = false;
  const env = v2({
    REVENUE_QUOTE_HMAC_KEY: ADMIN,
    CRM_DB: { prepare() { touched = true; throw new Error('Unexpected DB access'); } },
  });
  const req = new Request('https://revenue.example.test/api/v2/billing/quotes', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'X-Admin-Secret': ADMIN },
    body: JSON.stringify({
      email: 'cfo@example.com', company_name: 'Example Security Pvt Ltd',
      billing_address: '123 Example Street Bengaluru 560001',
      billing_state: '29', tier: 'ENTERPRISE',
    }),
  });
  const response = await handleQuoteCreate(req, env, { waitUntil() {} }, 'rid');
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, 'quote_signing_unavailable');
  assert.equal(touched, false);
});
