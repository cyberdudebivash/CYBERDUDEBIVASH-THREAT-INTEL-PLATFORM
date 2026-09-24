#!/usr/bin/env node
/**
 * SENTINEL APEX -- upgrade.html Razorpay checkout (real browser).
 *
 * P0 (2026-09-24): initiateRazorpayOneTimeCheckout() referenced an
 * undeclared `gstin`, so whenever the Subscriptions path was unavailable
 * (no live Plan ID -> 503, by design) the one-time Orders fallback threw a
 * ReferenceError inside its try and the buyer saw "Network error" -- the
 * Razorpay modal never opened and no payment could be taken.
 *
 * Headless Chromium drives the shipped page with every network edge stubbed
 * (no real payment, no Razorpay call): checkout.razorpay.com is replaced by
 * a recorder, /api/v2/billing/subscriptions/create answers 503, and
 * /api/payment/razorpay/create-order answers a fixture order.
 *
 * Checks:
 *   1. one-time fallback opens Razorpay (PRO monthly, no tax id)
 *   2. a valid buyer GSTIN reaches create-order and the checkout notes
 *   3. an invalid GSTIN is refused in the page; no order is created
 *   4. a server-side GSTIN refusal is shown to the buyer verbatim
 *   5. no page error on any path
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

async function scenario(browser, { gstin, orderStatus = 200, orderBody }) {
  const page = await browser.newPage();
  const errors = [];
  const alerts = [];
  const orders = [];
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
      return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'Razorpay plan not configured (RAZORPAY_PLAN_PRO_MONTHLY)' }) });
    }
    if (p === '/api/payment/razorpay/create-order') {
      const body = JSON.parse(route.request().postData() || '{}');
      orders.push(body);
      const out = orderBody || { order_id: 'order_T1', amount: 410000, currency: 'INR', key_id: 'rzp_test_key', plan: 'Sentinel APEX PRO', tier: 'PRO', billing: body.billing };
      return route.fulfill({ status: orderStatus, contentType: 'application/json', body: JSON.stringify(out) });
    }
    if (p.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    return route.continue();
  });

  await page.goto(`${ORIGIN}/upgrade.html`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof window.Razorpay === 'function' && typeof window.initiateRazorpayCheckout === 'function', null, { timeout: 15000 });
  await page.evaluate(() => { if (typeof selectPlan === 'function') selectPlan('pro'); });
  await page.fill('#rzp-email', 'buyer@example.com');
  if (gstin !== undefined) await page.fill('#rzp-gstin', gstin);
  await page.evaluate(() => initiateRazorpayCheckout());
  await page.waitForTimeout(300);
  const rzp = await page.evaluate(() => window.__rzp);
  await page.close();
  return { errors, alerts, orders, rzp };
}

(async () => {
  const server = await startStaticServer(ROOT, PORT, MIME);
  const browser = await chromium.launch();
  try {
    const plain = await scenario(browser, {});
    check('one-time fallback: create-order called once', plain.orders.length === 1, JSON.stringify(plain.orders));
    check('one-time fallback: Razorpay modal opened', plain.rzp.opened.length === 1, 'alerts: ' + JSON.stringify(plain.alerts));
    check('one-time fallback: order id + INR passed to Razorpay',
      !!plain.rzp.options && plain.rzp.options.order_id === 'order_T1' && plain.rzp.options.currency === 'INR');
    check('one-time fallback: no tax id sent when the field is blank', plain.orders[0] && !plain.orders[0].gstin);
    check('one-time fallback: no page error', plain.errors.length === 0, plain.errors.join(' | '));

    const withGst = await scenario(browser, { gstin: '21arkpn8270g1zp' });
    check('valid GSTIN: sent to create-order, normalized', withGst.orders[0] && withGst.orders[0].gstin === '21ARKPN8270G1ZP', JSON.stringify(withGst.orders));
    check('valid GSTIN: carried in Razorpay checkout notes', !!withGst.rzp.options && withGst.rzp.options.notes && withGst.rzp.options.notes.gstin === '21ARKPN8270G1ZP');
    check('valid GSTIN: no page error', withGst.errors.length === 0, withGst.errors.join(' | '));

    const badGst = await scenario(browser, { gstin: '22AAAAA0000A1Z5' });
    check('invalid GSTIN: refused in the page', badGst.alerts.some((a) => /GSTIN/.test(a)), JSON.stringify(badGst.alerts));
    check('invalid GSTIN: no order created, no modal', badGst.orders.length === 0 && badGst.rzp.opened.length === 0);

    const serverRefuses = await scenario(browser, {
      gstin: 'DE123456789', orderStatus: 400, orderBody: { error: 'Tax id refused by server', field: 'gstin' },
    });
    check('server GSTIN refusal shown verbatim', serverRefuses.alerts.includes('Tax id refused by server'), JSON.stringify(serverRefuses.alerts));
    check('server GSTIN refusal: no modal', serverRefuses.rzp.opened.length === 0);
  } finally {
    await browser.close();
    server.close();
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll upgrade checkout checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
