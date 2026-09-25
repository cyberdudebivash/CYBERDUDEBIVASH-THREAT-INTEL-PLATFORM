#!/usr/bin/env node
/**
 * SENTINEL APEX -- upgrade.html Razorpay checkout (real browser).
 *
 * Owner commercial policy (2026-09-24): PRO / Enterprise / MSSP are recurring
 * services sold ONLY as Razorpay Subscriptions. Background: the page used to
 * fall back to one-time Orders when a plan had no live Razorpay Plan ID, and
 * that fallback referenced an undeclared `gstin` (fixed in #516), so buyers
 * saw "Network error". Now there is no fallback at all.
 *
 * Headless Chromium drives the shipped page with every network edge stubbed
 * (no real payment, no Razorpay call): checkout.razorpay.com is replaced by a
 * recorder, and the billing APIs answer fixtures.
 *
 * Checks:
 *   1. configured plan: Subscriptions modal opens with the subscription id;
 *      buyer GSTIN / state / name / address reach subscriptions/create;
 *      no one-time order is ever created
 *   2. plan not configured (503): no one-time order, no modal, an honest
 *      "not available, no payment was taken" message
 *   3. invalid GSTIN refused in the page, before any request
 *   4. a server-side field refusal is shown verbatim
 *   5. copy: no retracted claims (EMI/wallets on a subscription, 2-hour key,
 *      no-auto-renewal for Razorpay, SOC 2 / ISO 27001), and the refund
 *      guarantee is qualified and linked to the Refund Policy
 *   6. no page error on any path
 *   7. Gumroad: a configured membership is what the button sells ("renews");
 *      without one, the legacy access grant is labelled as a one-time grant
 *   8. checkout state machine after payment authorization:
 *      - backend confirms "active" + key -> ACTIVE with the activation actions
 *      - backend not yet active (timeout) -> ACTIVATION_PENDING: payment
 *        confirmed, never "failed", never "provisioned", pay button stays
 *        disabled, a late ondismiss does not re-enable it, recheck works
 *      - status endpoint unreachable -> ACTIVATION_PENDING, not a failure
 *      - ?checkout=success in the URL renders no success state
 *
 * Usage:
 *   PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH="$(npm root -g)" \
 *     node render-test/verify_upgrade_checkout.js [root]   (default: repo root; CI passes dist)
 *   UPGRADE_HTML=/path/to/other/upgrade.html ...   (serve another revision)
 *
 * Exit 0 = all checks passed, 1 = at least one failed.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { startStaticServer } = require('./lib/static-server');
const { chromium } = require('playwright');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const PORT = 8791;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const OVERRIDE = process.env.UPGRADE_HTML ? fs.readFileSync(process.env.UPGRADE_HTML, 'utf8') : null;

const RAZORPAY_STUB = `
  window.__rzp = { opened: [], options: null };
  window.Razorpay = function (options) {
    window.__rzp.options = options;
    this.on = function () {};
    this.open = function () { window.__rzp.opened.push(options); };
  };`;

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : '  -- ' + detail}`);
  if (!ok) failures++;
}

async function scenario(browser, { gstin, fill = {}, subStatus = 200, subBody, statusReplies, pollAttempts, afterPay }) {
  const page = await browser.newPage();
  const errors = [];
  const alerts = [];
  const subs = [];
  const orders = [];
  const statusCalls = [];
  const feedCalls = [];
  page.on('pageerror', (e) => errors.push(String(e && e.message || e)));
  page.on('dialog', async (d) => { alerts.push(d.message()); await d.dismiss(); });

  await page.route('**/*', async (route) => {
    const url = route.request().url();
    if (url.startsWith('https://checkout.razorpay.com/')) {
      return route.fulfill({ status: 200, contentType: 'application/javascript', body: RAZORPAY_STUB });
    }
    if (!url.startsWith(ORIGIN)) return route.abort();
    const p = new URL(url).pathname;
    if (p === '/upgrade.html' && OVERRIDE) return route.fulfill({ status: 200, contentType: 'text/html', body: OVERRIDE });
    if (p === '/api/v2/billing/subscriptions/create') {
      subs.push(JSON.parse(route.request().postData() || '{}'));
      const out = subBody || { subscription_id: 'sub_T1', key_id: 'rzp_test_key', tier: 'PRO', billing_cycle: 'monthly', status: 'created' };
      return route.fulfill({ status: subStatus, contentType: 'application/json', body: JSON.stringify(out) });
    }
    if (p === '/api/payment/razorpay/create-order') {
      orders.push(JSON.parse(route.request().postData() || '{}'));
      return route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: 'subscription_required' }) });
    }
    if (p === '/api/v2/billing/subscriptions/status' && statusReplies) {
      statusCalls.push(new URL(url).searchParams.toString());
      const r = statusReplies[Math.min(statusCalls.length - 1, statusReplies.length - 1)];
      if (r === 'network') return route.abort();
      return route.fulfill({ status: r.status || 200, contentType: 'application/json', body: JSON.stringify(r.body) });
    }
    if (p === '/api/feed') {
      feedCalls.push(route.request().headers()['x-api-key'] || '');
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{"items":[]}' });
    }
    if (p.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    return route.continue();
  });

  await page.goto(`${ORIGIN}/upgrade.html`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof window.Razorpay === 'function' && typeof window.initiateRazorpayCheckout === 'function', null, { timeout: 15000 });
  if (pollAttempts !== undefined) await page.evaluate((n) => { ACTIVATION_POLL_MAX_ATTEMPTS = n; }, pollAttempts);
  await page.evaluate(() => { if (typeof selectPlan === 'function') selectPlan('pro'); });
  await page.fill('#rzp-email', 'buyer@example.com');
  if (gstin !== undefined) await page.fill('#rzp-gstin', gstin);
  // Optional fields are filled only when the page has them, so an older
  // revision can be replayed (UPGRADE_HTML) and fail on behaviour instead.
  if (fill.state && await page.$('#rzp-billing-state')) await page.selectOption('#rzp-billing-state', fill.state);
  const countryVisible = await page.evaluate(() => { const r = document.getElementById('rzp-country-row'); return !!r && r.style.display !== 'none'; });
  // Set directly: the field is hidden unless "Outside India" is chosen, and a
  // value typed before switching back to an Indian state must not be sent.
  if (fill.country && await page.$('#rzp-billing-country')) {
    await page.evaluate((v) => { document.getElementById('rzp-billing-country').value = v.toUpperCase(); }, fill.country);
  }
  if (fill.name && await page.$('#rzp-billing-name')) await page.fill('#rzp-billing-name', fill.name);
  if (fill.address && await page.$('#rzp-billing-address')) await page.fill('#rzp-billing-address', fill.address);
  await page.evaluate(() => initiateRazorpayCheckout());
  await page.waitForTimeout(300);
  const rzp = await page.evaluate(() => window.__rzp);
  let post = null;
  if (afterPay) {
    await page.evaluate(() => window.__rzp.options.handler({ razorpay_payment_id: 'pay_T1', razorpay_signature: 'test_only_signature' }));
    post = await afterPay(page);
  }
  const text = await page.evaluate(() => document.body.innerText);
  await page.close();
  return { errors, alerts, subs, orders, rzp, text, countryVisible, statusCalls, feedCalls, post };
}

async function gumroadStates(browser) {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e && e.message || e)));
  await page.route('**/*', (route) => {
    const url = route.request().url();
    if (url.startsWith('https://checkout.razorpay.com/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: RAZORPAY_STUB });
    if (!url.startsWith(ORIGIN)) return route.abort();
    const p = new URL(url).pathname;
    if (p === '/upgrade.html' && OVERRIDE) return route.fulfill({ status: 200, contentType: 'text/html', body: OVERRIDE });
    if (p.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    return route.continue();
  });
  await page.goto(`${ORIGIN}/upgrade.html`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof window.updateGumroadPanel === 'function', null, { timeout: 15000 });
  const read = () => page.evaluate(() => {
    const b = document.getElementById('gbtn-pro');
    return { href: b.href, type: b.getAttribute('data-gumroad-sale-type'), label: b.textContent.trim(),
      price: document.getElementById('gprice-pro').textContent };
  });
  await page.evaluate(() => { selectPlan('pro'); if (isAnnual) toggleBilling(); });
  const grant = await read();
  const periodMonthly = await page.evaluate(() => document.getElementById('period-pro').textContent);
  await page.evaluate(() => { GUMROAD_MEMBERSHIP_URLS.pro.monthly = 'https://cyberdudebivash.gumroad.com/l/test-membership'; updateGumroadPanel(); });
  const membership = await read();
  await page.evaluate(() => toggleBilling());
  const annual = await read();
  const periodAnnual = await page.evaluate(() => document.getElementById('period-pro').textContent);
  await page.close();
  return { grant, membership, annual, periodMonthly, periodAnnual, errors };
}

(async () => {
  const server = await startStaticServer(ROOT, PORT, MIME);
  const browser = await chromium.launch();
  try {
    const ok = await scenario(browser, {
      gstin: '21arkpn8270g1zp', fill: { name: 'Acme Security Pvt Ltd', address: '12 MG Road, Bengaluru 560001' },
    });
    check('configured plan: subscriptions/create called once', ok.subs.length === 1, JSON.stringify(ok.subs));
    check('configured plan: Razorpay opened with the subscription id',
      ok.rzp.opened.length === 1 && ok.rzp.options && ok.rzp.options.subscription_id === 'sub_T1' && !ok.rzp.options.order_id);
    check('configured plan: no price or amount sent by the page', ok.subs[0] && !('amount' in ok.subs[0]) && !('price' in ok.subs[0]));
    check('configured plan: buyer GSTIN, name and address sent',
      ok.subs[0] && ok.subs[0].gstin === '21ARKPN8270G1ZP' && ok.subs[0].billing_name === 'Acme Security Pvt Ltd' &&
      ok.subs[0].billing_address === '12 MG Road, Bengaluru 560001', JSON.stringify(ok.subs[0]));
    check('configured plan: no one-time order', ok.orders.length === 0);
    check('configured plan: no page error', ok.errors.length === 0, ok.errors.join(' | '));

    const state = await scenario(browser, { fill: { state: '27', country: 'US' } });
    check('billing state sent when chosen', state.subs[0] && state.subs[0].billing_state === '27', JSON.stringify(state.subs[0]));
    check('a buyer in India sends no country (field hidden)', state.subs[0] && !('billing_country' in state.subs[0]) && !state.countryVisible,
      JSON.stringify(state.subs[0]));
    const abroad = await scenario(browser, { fill: { state: 'OUTSIDE_INDIA', country: 'sg' } });
    check('a buyer outside India sees and sends the country (export invoice)',
      abroad.countryVisible && abroad.subs[0] && abroad.subs[0].billing_state === 'OUTSIDE_INDIA' && abroad.subs[0].billing_country === 'SG',
      JSON.stringify(abroad.subs[0]));

    const missing = await scenario(browser, { subStatus: 503, subBody: { error: 'Razorpay plan not configured (RAZORPAY_PLAN_ID_PRO_MONTHLY)' } });
    check('plan not configured: NO one-time order fallback', missing.orders.length === 0, JSON.stringify(missing.orders));
    check('plan not configured: no modal', missing.rzp.opened.length === 0);
    check('plan not configured: honest message, no payment taken',
      missing.alerts.some((a) => /This billing cycle is temporarily unavailable\. No payment was taken\./.test(a)), JSON.stringify(missing.alerts));
    check('plan not configured: no page error', missing.errors.length === 0, missing.errors.join(' | '));

    const badGst = await scenario(browser, { gstin: '22AAAAA0000A1Z5' });
    check('invalid GSTIN: refused in the page', badGst.alerts.some((a) => /GSTIN/.test(a)), JSON.stringify(badGst.alerts));
    check('invalid GSTIN: no request, no modal', badGst.subs.length === 0 && badGst.orders.length === 0 && badGst.rzp.opened.length === 0);

    const refused = await scenario(browser, { gstin: 'DE123456789', subStatus: 400, subBody: { error: 'Billing address must be 10-250 characters.', field: 'billing_address' } });
    check('server field refusal shown verbatim', refused.alerts.includes('Billing address must be 10-250 characters.'), JSON.stringify(refused.alerts));
    check('server field refusal: no modal, no order', refused.rzp.opened.length === 0 && refused.orders.length === 0);

    // ── 8. state machine after payment authorization (fixtures are test-only) ──
    const snap = (page) => page.evaluate(() => ({
      state: document.body.getAttribute('data-checkout-state'),
      title: (document.getElementById('success-title') || {}).textContent || '',
      ref: (document.getElementById('success-review-id') || {}).textContent || '',
      text: (document.getElementById('success-state') || {}).innerText || '',
      visible: (document.getElementById('success-state') || { style: {} }).style.display === 'block',
      actions: (document.getElementById('activation-actions') || { style: {} }).style.display,
      payDisabled: !!(document.getElementById('rzp-pay-btn') || {}).disabled,
    }));
    const active = await scenario(browser, {
      statusReplies: [{ body: { status: 'created', tier: 'PRO' } }, { body: { status: 'active', tier: 'PRO', api_key: 'cdb_test_fixture_only' } }],
      afterPay: async (page) => {
        await page.waitForFunction(() => document.body.getAttribute('data-checkout-state') === 'ACTIVE', null, { timeout: 10000 });
        const a = await snap(page);
        await page.click('#activation-test-api');
        await page.waitForFunction(() => /key works/.test(document.getElementById('activation-test-result').textContent), null, { timeout: 5000 });
        return a;
      },
    });
    check('ACTIVE only after the backend confirmed status "active" with the key',
      active.post.state === 'ACTIVE' && active.statusCalls.length === 2 && active.post.ref === 'cdb_test_fixture_only', JSON.stringify(active.post));
    check('ACTIVE: status poll carries the payment proof', /payment_id=pay_T1/.test(active.statusCalls[0]) && /signature=test_only_signature/.test(active.statusCalls[0]));
    check('ACTIVE: activation actions shown (copy key, Test API, Watchdog, docs, Billing Center)',
      active.post.actions === 'flex' && /Copy API key/.test(active.post.text) && /Test API/.test(active.post.text) &&
      /Open Cyber Watchdog/.test(active.post.text) && /API docs/.test(active.post.text) && /Billing Center/.test(active.post.text), active.post.text);
    check('ACTIVE: Test API sends the new key to the API', active.feedCalls.length === 1 && active.feedCalls[0] === 'cdb_test_fixture_only');
    check('ACTIVE: no "instantly" claim, no page error', !/INSTANTLY/i.test(active.post.text) && active.errors.length === 0, active.errors.join(' | '));

    const pending = await scenario(browser, {
      pollAttempts: 1,
      statusReplies: [{ body: { status: 'created', tier: 'PRO' } }],
      afterPay: async (page) => {
        await page.waitForFunction(() => document.body.getAttribute('data-checkout-state') === 'ACTIVATION_PENDING', null, { timeout: 10000 });
        await page.evaluate(() => window.__rzp.options.modal.ondismiss());
        const first = await snap(page);
        await page.click('#activation-recheck-btn');
        await page.waitForTimeout(2600);
        const again = await snap(page);
        return { first, again };
      },
    });
    const pf = pending.post.first;
    check('timeout -> ACTIVATION_PENDING with "PAYMENT CONFIRMED — ACTIVATION IN PROGRESS"',
      pf.state === 'ACTIVATION_PENDING' && pf.visible && /PAYMENT CONFIRMED/.test(pf.title) && /ACTIVATION IN PROGRESS/.test(pf.title), JSON.stringify(pf));
    check('timeout: safe reference is the subscription id (no key, no payment signature)',
      pf.ref === 'sub_T1' && !/test_only_signature/.test(pf.text), pf.ref);
    check('timeout: never says the payment failed, never says access is provisioned',
      !/fail/i.test(pf.text) && !/provisioned|is active|API KEY PROVISIONED/i.test(pf.text) && !pending.alerts.some((a) => /fail/i.test(a)), pf.text);
    check('timeout: buyer told not to pay again; pay button stays disabled even after a late ondismiss',
      /do not pay again/i.test(pf.text) && pf.payDisabled && pf.actions === 'none', JSON.stringify(pf));
    check('timeout: "check again" re-polls the backend', pending.statusCalls.length >= 3 && pending.post.again.state === 'ACTIVATION_PENDING', String(pending.statusCalls.length));
    check('timeout: no page error', pending.errors.length === 0, pending.errors.join(' | '));

    const offline = await scenario(browser, {
      pollAttempts: 0, statusReplies: ['network'],
      afterPay: async (page) => {
        await page.waitForFunction(() => document.body.getAttribute('data-checkout-state') === 'ACTIVATION_PENDING', null, { timeout: 10000 });
        return snap(page);
      },
    });
    check('status endpoint unreachable -> ACTIVATION_PENDING, not a failure',
      offline.post.state === 'ACTIVATION_PENDING' && !/fail/i.test(offline.post.text) && offline.errors.length === 0, JSON.stringify(offline.post));

    const cancelled = await scenario(browser, {
      afterPay: null,
    });
    check('before payment: modal open, state CHECKOUT_OPEN', cancelled.rzp.opened.length === 1);

    {
      const page = await browser.newPage();
      await page.route('**/*', (route) => {
        const url = route.request().url();
        if (url.startsWith('https://checkout.razorpay.com/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: RAZORPAY_STUB });
        if (!url.startsWith(ORIGIN)) return route.abort();
        if (new URL(url).pathname === '/upgrade.html' && OVERRIDE) return route.fulfill({ status: 200, contentType: 'text/html', body: OVERRIDE });
        if (new URL(url).pathname.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
        return route.continue();
      });
      await page.goto(`${ORIGIN}/upgrade.html?checkout=success&plan=pro`, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(500);
      const shown = await page.evaluate(() => { const s = document.getElementById('success-state'); return !!s && s.style.display === 'block'; });
      await page.close();
      check('?checkout=success in the URL renders no success state', !shown);
    }

    const g = await gumroadStates(browser);
    check('gumroad: without a membership product the grant is labelled a one-time grant',
      g.grant.type === 'grant' && /pxyfcb/.test(g.grant.href) && /30-day grant, no auto-renew/.test(g.grant.price), JSON.stringify(g.grant));
    check('gumroad: a configured membership is what the button sells',
      g.membership.type === 'membership' && g.membership.href === 'https://cyberdudebivash.gumroad.com/l/test-membership' &&
      /renews monthly/.test(g.membership.price) && /SUBSCRIBE/.test(g.membership.label), JSON.stringify(g.membership));
    check('gumroad: annual without a yearly membership falls back to the labelled 12-month grant',
      g.annual.type === 'grant' && /12-month grant, no auto-renew/.test(g.annual.price), JSON.stringify(g.annual));
    check('plan card period follows the billing toggle', g.periodMonthly === 'per month' && g.periodAnnual === 'per year',
      g.periodMonthly + ' / ' + g.periodAnnual);
    check('gumroad: no page error', g.errors.length === 0, g.errors.join(' | '));

    const t = ok.text;
    check('copy: no EMI / wallets offered for a subscription', !/\bEMI\b|Wallets \(/.test(t));
    check('copy: no "API key within 2 hours" claim', !/within 2 ?h|in 2 hours/i.test(t));
    check('copy: no blanket "No Auto-Renewal" for Razorpay', !/No Auto-Renewal/i.test(t));
    check('copy: no SOC 2 / ISO 27001 claim', !/SOC 2|ISO 27001/.test(t));
    check('copy: guarantee qualified to eligible first purchases', /7-Day Money-Back Guarantee on eligible first purchases/i.test(t) && /No pro-rata refunds/i.test(t));
    check('copy: Razorpay renewal and cancellation stated', /renews automatically, cancel any time/i.test(t));
  } finally {
    await browser.close();
    server.close();
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll upgrade checkout checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
